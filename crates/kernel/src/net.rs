//! Sockets.
//!
//! Guest file descriptors are host socket descriptors. On Linux the calls would
//! be a straight passthrough, but `AF_UNIX` addresses must be rooted under the
//! guest rootfs on every host, so all address handling goes through [`to_host`]
//! and [`to_guest`]. On macOS those also translate the BSD differences:
//!
//! - **address families:** `AF_INET6` is 10 on Linux, 30 on macOS.
//! - **`sockaddr` header:** Linux leads with a 2-byte family; macOS with a
//!   length byte then a family byte. The payload that follows is identical.
//! - **socket type flags:** `SOCK_NONBLOCK`/`SOCK_CLOEXEC` are stripped from the
//!   `type` argument and applied with `fcntl`.
//! - **`setsockopt` names and `send`/`recv` flags:** mapped individually;
//!   `MSG_NOSIGNAL` becomes `SO_NOSIGPIPE` on the socket.
//! - **`SCM_RIGHTS`:** the control-message layout differs (`cmsg_len` is 64-bit
//!   on Linux, 32-bit on macOS), so file-descriptor passing is re-encoded.
//!
//! `AF_UNIX` paths are rooted under the rootfs; abstract-namespace names (a
//! leading NUL) are mapped to files under a per-host temporary directory, since
//! macOS has no abstract namespace.
//!
//! The calls that can block — `connect`, `accept`, `recvfrom`, `recvmsg`,
//! `sendto`, `sendmsg` — run outside the kernel lock via `blocking_syscall`.

use crate::host::{last_error, ret};
use crate::{guest, uaccess};
use fwe_abi::socket::*;
use fwe_abi::{err, errno};
use std::os::unix::ffi::OsStringExt;

const SOCKADDR_MAX: usize = 128;
/// Host `sun_path` capacity.
#[cfg(target_os = "linux")]
const UNIX_PATH_MAX: usize = 108;
#[cfg(not(target_os = "linux"))]
const UNIX_PATH_MAX: usize = 104;

/// Host value of `AF_UNIX`/`AF_INET`/`AF_INET6` (same on Linux, differ on mac).
fn host_af(domain: u64) -> Result<libc::c_int, i64> {
    Ok(match domain {
        AF_UNIX => libc::AF_UNIX,
        AF_INET => libc::AF_INET,
        AF_INET6 => libc::AF_INET6,
        _ => return Err(err(errno::EAFNOSUPPORT)),
    })
}

/// Map a guest `AF_UNIX` `sun_path` to a host filesystem path, following a
/// final symlink if `follow` (not for `bind`, which creates the name).
fn root_unix_path(raw: &[u8], follow: bool) -> Result<Vec<u8>, i64> {
    if raw.is_empty() {
        return Ok(Vec::new()); // unnamed / autobind
    }
    if raw[0] == 0 {
        // Abstract namespace: no macOS equivalent. Map the name to a stable
        // file under a per-host temp directory so peers rendezvous.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        raw[1..].hash(&mut h);
        // Each network namespace has its own abstract names.
        let dir = match crate::netns::current() {
            Some(net) => {
                use std::os::unix::ffi::OsStrExt;
                std::path::Path::new(std::ffi::OsStr::from_bytes(net.dir())).join("abstract")
            }
            None => std::env::temp_dir().join("fwe-abstract"),
        };
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!("{:016x}", h.finish()));
        return Ok(p.into_os_string().into_vec());
    }
    // Pathed: trim at the first NUL, then resolve as a file's path is, in
    // the guest's filesystem.
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let host = crate::fs::resolve_host(&raw[..end], follow).map_err(err)?;
    if !follow {
        // Linux's `bind` takes a name that exists, a symlink included, as
        // in use; macOS's would follow the symlink.
        let c = std::ffi::CString::new(host.clone()).map_err(|_| err(errno::EINVAL))?;
        // SAFETY: zeroed bytes are a valid `stat`; `lstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is NUL-terminated; `st` is a valid out-parameter.
        if unsafe { libc::lstat(c.as_ptr(), &mut st) } == 0 {
            return Err(err(errno::EADDRINUSE));
        }
    }
    Ok(host)
}

/// Reverse [`root_unix_path`] for addresses handed back to the guest: the
/// guest path of the host path, or the host path when it has none.
fn unroot_unix_path(host: &[u8]) -> Vec<u8> {
    crate::fs::guest_of_host(host).unwrap_or_else(|| host.to_vec())
}

/// Convert a guest `sockaddr` at `addr`/`len` into host layout in `out`,
/// returning the host length.
///
/// # Safety
/// `addr` must span `len` readable bytes.
unsafe fn to_host(
    addr: u64,
    len: u64,
    out: &mut [u8; SOCKADDR_MAX],
    follow: bool,
) -> Result<HostAddr, i64> {
    if addr == 0 || len < 2 {
        return Err(err(errno::EINVAL));
    }
    let src = uaccess::read_bytes(addr, (len as usize).min(SOCKADDR_MAX)).map_err(err)?;
    let len = match u16::from_ne_bytes([src[0], src[1]]) as u64 {
        AF_INET => inet_to_host(&src, out, 16)?,
        AF_INET6 => inet_to_host(&src, out, 28)?,
        AF_UNIX => return unix_to_host(&src, out, follow),
        _ => return Err(err(errno::EAFNOSUPPORT)),
    };
    Ok(HostAddr { len, dir: None, guest: Vec::new() })
}

/// A host socket address [`to_host`] made: its length, and for a Unix path
/// too long for the host's `sun_path`, the directory it is in (the
/// address then holds only the last name, see [`bind_or_connect`]).
struct HostAddr {
    len: libc::socklen_t,
    dir: Option<std::os::fd::OwnedFd>,
    /// For such a path, the guest's: what the host will not report back.
    guest: Vec<u8>,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Change the calling thread's working directory alone (`-1`: back to
    /// the process's).
    fn pthread_fchdir_np(fd: i32) -> i32;
}

/// `bind` (or `connect`, for `!bind`) socket `fd` to host address `hb`, as
/// [`to_host`] made it: for one relative to a directory, from that
/// directory as this thread's working directory, for the call.
fn bind_or_connect(fd: i32, hb: &[u8; SOCKADDR_MAX], a: &HostAddr, bind: bool) -> i32 {
    let p = hb.as_ptr() as *const libc::sockaddr;
    // SAFETY: `hb` holds a valid host sockaddr of `a.len` bytes.
    let call =
        || unsafe { if bind { libc::bind(fd, p, a.len) } else { libc::connect(fd, p, a.len) } };
    in_dir(a.dir.as_ref(), call)
}

/// Run `call` (a host call taking a relative path) from directory `dir`
/// as this thread's working directory, if one is given; its result and
/// `errno` are the call's.
fn in_dir(dir: Option<&std::os::fd::OwnedFd>, call: impl FnOnce() -> i32) -> i32 {
    let Some(dir) = dir else { return call() };
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: a live directory; the thread's own directory is undone
        // before returning, the call's errno kept.
        unsafe {
            if pthread_fchdir_np(dir.as_raw_fd()) != 0 {
                return -1;
            }
            let r = call();
            let e = crate::host::last_errno();
            pthread_fchdir_np(-1);
            *libc::__error() = e;
            r
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (dir, call);
        // SAFETY: setting this thread's errno.
        unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
        -1
    }
}

/// Run `call` with the host `AF_UNIX` address of host path `path` (one of
/// fwe's own sockets): one relative to the path's directory, from there,
/// if the whole path is too long for `sun_path`. The call's result, or
/// the Linux error making the address met.
pub fn at_unix_path(
    path: &[u8],
    call: impl FnOnce(*const libc::sockaddr, libc::socklen_t) -> i32,
) -> Result<i32, i32> {
    let (dir, name) = if path.len() + 1 > UNIX_PATH_MAX {
        let slash = path.iter().rposition(|&b| b == b'/').ok_or(errno::ENAMETOOLONG)?;
        let c = std::ffi::CString::new(&path[..slash.max(1)]).map_err(|_| errno::EINVAL)?;
        // SAFETY: a NUL-terminated path.
        let fd =
            unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        use std::os::fd::FromRawFd;
        // SAFETY: a fresh descriptor this owns.
        (Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }), &path[slash + 1..])
    } else {
        (None, path)
    };
    if name.is_empty() || name.len() + 1 > UNIX_PATH_MAX {
        return Err(errno::ENAMETOOLONG);
    }
    // SAFETY: zeroed bytes are a valid `sockaddr_un`.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, &b) in a.sun_path.iter_mut().zip(name) {
        *d = b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len() + 1) as libc::socklen_t;
    #[cfg(not(target_os = "linux"))]
    {
        a.sun_len = len as u8;
    }
    let p = (&a as *const libc::sockaddr_un).cast();
    Ok(in_dir(dir.as_ref(), || call(p, len)))
}

/// `src` is the guest's address; `total` is the family's size.
fn inet_to_host(
    src: &[u8],
    out: &mut [u8; SOCKADDR_MAX],
    total: usize,
) -> Result<libc::socklen_t, i64> {
    if src.len() < total {
        return Err(err(errno::EINVAL));
    }
    #[cfg(target_os = "linux")]
    {
        out[..total].copy_from_slice(&src[..total]);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let host_fam = if total == 16 { libc::AF_INET } else { libc::AF_INET6 } as u8;
        out[0] = total as u8;
        out[1] = host_fam;
        // The payload after the 2-byte header is identical.
        out[2..total].copy_from_slice(&src[2..total]);
    }
    Ok(total as libc::socklen_t)
}

/// `src` is the guest's address.
fn unix_to_host(src: &[u8], out: &mut [u8; SOCKADDR_MAX], follow: bool) -> Result<HostAddr, i64> {
    let raw = &src[2..];
    let mut host = root_unix_path(raw, follow)?;
    let mut dir = None;
    if host.len() + 1 > UNIX_PATH_MAX {
        // A guest path short enough for Linux, under a long host root: the
        // name relative to its directory.
        let slash = host.iter().rposition(|&b| b == b'/').ok_or(err(errno::ENAMETOOLONG))?;
        let name = host[slash + 1..].to_vec();
        if name.is_empty() || name.len() + 1 > UNIX_PATH_MAX {
            return Err(err(errno::ENAMETOOLONG));
        }
        let parent = if slash == 0 { b"/".to_vec() } else { host[..slash].to_vec() };
        let c = std::ffi::CString::new(parent).map_err(|_| err(errno::EINVAL))?;
        // SAFETY: a NUL-terminated path.
        let fd =
            unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(last_error());
        }
        use std::os::fd::FromRawFd;
        // SAFETY: a fresh descriptor this owns.
        dir = Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        host = name;
    }
    #[cfg(target_os = "linux")]
    {
        out[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    }
    #[cfg(not(target_os = "linux"))]
    {
        out[1] = libc::AF_UNIX as u8;
    }
    if host.is_empty() {
        #[cfg(not(target_os = "linux"))]
        {
            out[0] = 2;
        }
        return Ok(HostAddr { len: 2, dir, guest: Vec::new() });
    }
    out[2..2 + host.len()].copy_from_slice(&host);
    out[2 + host.len()] = 0;
    let total = 2 + host.len() + 1;
    #[cfg(not(target_os = "linux"))]
    {
        out[0] = total as u8;
    }
    let guest = if dir.is_some() {
        raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())].to_vec()
    } else {
        Vec::new()
    };
    Ok(HostAddr { len: total as libc::socklen_t, dir, guest })
}

/// Write a host `sockaddr` back to a guest buffer in Linux layout, honoring the
/// guest capacity; returns the full Linux length.
fn to_guest(
    host: &[u8; SOCKADDR_MAX],
    host_len: libc::socklen_t,
    dst: u64,
    dst_cap: u32,
) -> uaccess::Result<u32> {
    let total = host_len as usize;
    #[cfg(target_os = "linux")]
    let host_fam = u16::from_ne_bytes([host[0], host[1]]) as i32;
    #[cfg(not(target_os = "linux"))]
    let host_fam = host[1] as i32;

    let mut lb = [0u8; SOCKADDR_MAX];
    let linux_len: usize;
    if host_fam == libc::AF_UNIX {
        lb[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
        // Host path runs from offset 2 to the first NUL.
        let raw = &host[2..total.min(SOCKADDR_MAX)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        if end == 0 {
            linux_len = 2; // unnamed
        } else {
            let guest = unroot_unix_path(&raw[..end]);
            let n = guest.len().min(SOCKADDR_MAX - 3);
            lb[2..2 + n].copy_from_slice(&guest[..n]);
            lb[2 + n] = 0;
            linux_len = 2 + n + 1;
        }
    } else {
        let lfam: u16 = if host_fam == libc::AF_INET {
            AF_INET as u16
        } else if host_fam == libc::AF_INET6 {
            AF_INET6 as u16
        } else {
            0
        };
        lb[0..2].copy_from_slice(&lfam.to_ne_bytes());
        if total > 2 {
            lb[2..total].copy_from_slice(&host[2..total]);
        }
        linux_len = total;
    }
    if dst != 0 {
        let n = linux_len.min(dst_cap as usize);
        uaccess::write_from(dst, &lb[..n])?;
    }
    Ok(linux_len as u32)
}

/// Write a host `sockaddr` to the guest's `addr`, with its length in the
/// guest's `addrlen` word, which holds the buffer's capacity on entry.
fn name_to_guest(
    host: &[u8; SOCKADDR_MAX],
    host_len: libc::socklen_t,
    addr: u64,
    addrlen: u64,
) -> uaccess::Result<()> {
    let cap: u32 = uaccess::read(addrlen)?;
    let full = to_guest(host, host_len, addr, cap)?;
    uaccess::write(addrlen, full)
}

fn empty_sockaddr() -> [u8; SOCKADDR_MAX] {
    [0u8; SOCKADDR_MAX]
}

// --- socket setup ---------------------------------------------------------

fn apply_sock_flags(fd: i32, type_or_flags: u64) {
    // SAFETY: plain host calls on a fresh socket.
    unsafe {
        if type_or_flags & SOCK_NONBLOCK != 0 {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        if type_or_flags & SOCK_CLOEXEC != 0 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let on: i32 = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &on as *const _ as *const libc::c_void,
                4,
            );
        }
    }
}

/// A read's result `r` from descriptor `fd` (system call `nr`) as Linux
/// gives it: a Unix stream socket that is not connected fails a read with
/// `EINVAL` there (`ENOTCONN` on the host).
pub fn linux_read_error(nr: u64, fd: i32, r: i64) -> i64 {
    use fwe_abi::nr as n;
    let reads = matches!(
        nr,
        n::READ | n::READV | n::PREAD64 | n::PREADV | n::PREADV2 | n::RECVFROM | n::RECVMSG
    );
    if !reads || r != err(errno::ENOTCONN) {
        return r;
    }
    let opt = |o: i32| {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid out-parameters.
        let ok = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, o, (&mut v as *mut libc::c_int).cast(), &mut len)
        } == 0;
        ok.then_some(v)
    };
    // SAFETY: zeroed bytes are a valid `sockaddr_storage`.
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: a valid out-buffer of its length.
    let named = unsafe {
        libc::getsockname(fd, (&mut name as *mut libc::sockaddr_storage).cast(), &mut len)
    } == 0;
    let unix = named && name.ss_family as i32 == libc::AF_UNIX;
    if unix && opt(libc::SO_TYPE) == Some(libc::SOCK_STREAM) { err(errno::EINVAL) } else { r }
}

/// Linux's default socket buffer (`net.core.wmem_default` and
/// `rmem_default`).
const LINUX_BUFFER: i32 = 212_992;

/// Give a new Unix socket Linux's buffer sizes: the host's are a few KiB,
/// so a program that writes more before its peer reads (or sends a larger
/// datagram) would block (or fail) where on Linux it does not. A
/// `SOCK_SEQPACKET` one is sized as such ([`crate::seqpacket::make`]).
fn linux_buffers(fd: i32, dom: i32) {
    if dom != libc::AF_UNIX {
        return;
    }
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: a valid in-parameter on a fresh socket.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&LINUX_BUFFER as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
    }
}

/// `socket(domain, type, protocol)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn socket(domain: u64, type_: u64, protocol: u64) -> i64 {
    let dom = match host_af(domain) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let mut base = (type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC)) as i32;
    // macOS has no SOCK_SEQPACKET Unix sockets: a stream socket with its
    // messages framed (see `seqpacket`).
    let seqpacket = dom == libc::AF_UNIX && base == SOCK_SEQPACKET as i32;
    if seqpacket {
        base = libc::SOCK_STREAM;
    }
    // SAFETY: plain host call.
    let fd = unsafe { libc::socket(dom, base, protocol as i32) };
    if fd < 0 {
        return last_error();
    }
    apply_sock_flags(fd, type_);
    linux_buffers(fd, dom);
    if seqpacket {
        crate::seqpacket::make(fd);
    }
    fd as i64
}

/// `socketpair(domain, type, protocol, sv)`.
///
/// # Safety
/// `sv` must point to two writable `i32`s.
pub unsafe fn socketpair(domain: u64, type_: u64, protocol: u64, sv: u64) -> i64 {
    let dom = match host_af(domain) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let mut base = (type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC)) as i32;
    // macOS has no SOCK_SEQPACKET Unix sockets: a stream pair with its
    // messages framed (see `seqpacket`).
    let seqpacket = dom == libc::AF_UNIX && base == SOCK_SEQPACKET as i32;
    if seqpacket {
        base = libc::SOCK_STREAM;
    }
    let mut fds = [0i32; 2];
    // SAFETY: plain host call with a 2-element array.
    let r = unsafe { libc::socketpair(dom, base, protocol as i32, fds.as_mut_ptr()) };
    if r < 0 {
        return last_error();
    }
    apply_sock_flags(fds[0], type_);
    apply_sock_flags(fds[1], type_);
    linux_buffers(fds[0], dom);
    linux_buffers(fds[1], dom);
    if seqpacket {
        crate::seqpacket::make(fds[0]);
        crate::seqpacket::make(fds[1]);
    }
    if uaccess::write(sv, fds).is_err() {
        // SAFETY: closing the sockets just made.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return err(errno::EFAULT);
    }
    0
}

/// `bind(fd, addr, addrlen)`.
///
/// # Safety
/// `addr` must point to `addrlen` readable bytes.
/// `may_low`: the caller may bind a port below 1024
/// (`CAP_NET_BIND_SERVICE`), as a network namespace of fwe's asks.
pub unsafe fn bind(fd: u64, addr: u64, addrlen: u64, may_low: bool, umask: u32) -> i64 {
    let mut hb = empty_sockaddr();
    // SAFETY: the caller guarantees the sockaddr spans addrlen.
    let a = match unsafe { to_host(addr, addrlen, &mut hb, false) } {
        Ok(a) => a,
        Err(e) => return e,
    };
    let plan = match crate::netns::bind_prepare(fd as i32, &mut hb, may_low) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let r = ret(bind_or_connect(fd as i32, &hb, &a, true) as i64);
    if r == 0 && a.dir.is_some() {
        remember_name(fd as i32, true, &a.guest);
    }
    if r == 0
        && let Some(plan) = plan
    {
        crate::netns::bind_done(fd as i32, plan);
    }
    if r == 0 && family(&hb) == libc::AF_UNIX && a.len > 2 && hb[2] != 0 {
        // The node takes the socket's mode (its `fchmod`, or every bit),
        // less the umask, as on Linux.
        let mode = take_socket_mode(fd as i32).unwrap_or(0o777) & !umask;
        let end = hb[2..].iter().position(|&b| b == 0).map_or(hb.len(), |e| e + 2);
        if let Ok(name) = std::ffi::CString::new(&hb[2..end]) {
            use std::os::fd::AsRawFd;
            let dir = a.dir.as_ref().map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
            // Not through a link another thread may have put in its place.
            // SAFETY: a NUL-terminated name, relative to a live directory.
            unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0
                    && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
                {
                    libc::fchmodat(
                        dir,
                        name.as_ptr(),
                        mode as libc::mode_t,
                        libc::AT_SYMLINK_NOFOLLOW,
                    );
                }
            };
        }
    }
    r
}

/// The family of host socket address `hb`.
fn family(hb: &[u8]) -> i32 {
    #[cfg(target_os = "linux")]
    {
        u16::from_ne_bytes([hb[0], hb[1]]) as i32
    }
    #[cfg(not(target_os = "linux"))]
    {
        hb[1] as i32
    }
}

/// Modes given unbound sockets with `fchmod`, by descriptor and the
/// socket's inode: what a node bound for one is made with.
static SOCKET_MODES: std::sync::Mutex<Vec<(i32, u64, u32)>> = std::sync::Mutex::new(Vec::new());

fn inode(fd: i32) -> Option<u64> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino as u64)
}

/// `fchmod` of socket `fd` to `perm`: the mode a node bound for it gets
/// (the host has no mode for a socket itself).
pub fn set_socket_mode(fd: i32, perm: u32) {
    let Some(ino) = inode(fd) else { return };
    let mut m = SOCKET_MODES.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|&(f, _, _)| f != fd);
    m.push((fd, ino, perm & 0o7777));
}

fn take_socket_mode(fd: i32) -> Option<u32> {
    let ino = inode(fd)?;
    let mut m = SOCKET_MODES.lock().unwrap_or_else(|e| e.into_inner());
    let i = m.iter().position(|&(f, n, _)| f == fd && n == ino)?;
    Some(m.swap_remove(i).2)
}

/// `listen(fd, backlog)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn listen(fd: u64, backlog: u64) -> i64 {
    // SAFETY: plain host call.
    ret(unsafe { libc::listen(fd as i32, backlog as i32) } as i64)
}

/// `connect(fd, addr, addrlen)`.
///
/// # Safety
/// `addr` must point to `addrlen` readable bytes.
pub unsafe fn connect(fd: u64, addr: u64, addrlen: u64) -> i64 {
    if crate::netlink::is(fd as i32) {
        // The kernel (port 0) is the only peer there is.
        return 0;
    }
    let mut hb = empty_sockaddr();
    // SAFETY: the caller guarantees the sockaddr spans addrlen.
    let a = match unsafe { to_host(addr, addrlen, &mut hb, true) } {
        Ok(a) => a,
        Err(e) => return e,
    };
    if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
        return err(e);
    }
    let r = ret(bind_or_connect(fd as i32, &hb, &a, false) as i64);
    if r == 0 && a.dir.is_some() {
        remember_name(fd as i32, false, &a.guest);
    }
    r
}

/// Unix sockets bound (`local`) or connected to a path the host knows only
/// relative to its directory: by descriptor and inode, the guest's path,
/// which `getsockname` and `getpeername` report.
#[allow(clippy::type_complexity)]
static NAMES: std::sync::Mutex<Vec<(i32, u64, bool, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

fn remember_name(fd: i32, local: bool, guest: &[u8]) {
    let Some(ino) = inode(fd) else { return };
    let mut n = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    n.retain(|&(f, _, l, _)| !(f == fd && l == local));
    n.push((fd, ino, local, guest.to_vec()));
}

/// The guest path [`remember_name`] kept for `fd`, if it still names that
/// socket.
fn remembered_name(fd: i32, local: bool) -> Option<Vec<u8>> {
    let ino = inode(fd)?;
    let n = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    n.iter().find(|&&(f, i, l, _)| f == fd && i == ino && l == local).map(|e| e.3.clone())
}

/// `accept4(fd, addr, addrlen, flags)`; `accept` is this with `flags == 0`.
///
/// # Safety
/// `addr`/`addrlen`, if non-null, must be writable.
pub unsafe fn accept4(fd: u64, addr: u64, addrlen: u64, flags: u64) -> i64 {
    let mut hb = empty_sockaddr();
    let mut hl: libc::socklen_t = SOCKADDR_MAX as libc::socklen_t;
    let want = addr != 0;
    // SAFETY: valid out parameters or NULL.
    let r = unsafe {
        if want {
            libc::accept(fd as i32, hb.as_mut_ptr() as *mut libc::sockaddr, &mut hl)
        } else {
            libc::accept(fd as i32, std::ptr::null_mut(), std::ptr::null_mut())
        }
    };
    if r < 0 {
        return last_error();
    }
    crate::netns::to_guest(r, &mut hb, false);
    if crate::seqpacket::is(fd as i32) {
        // A connection of a SOCK_SEQPACKET listener is one too.
        crate::seqpacket::make(r);
    }
    if want && name_to_guest(&hb, hl, addr, addrlen).is_err() {
        // SAFETY: closing the connection just accepted.
        unsafe { libc::close(r) };
        return err(errno::EFAULT);
    }
    apply_sock_flags(r, flags);
    r as i64
}

/// `getsockname`/`getpeername`; `peer` selects which.
///
/// # Safety
/// `addr`/`addrlen` must be writable.
pub unsafe fn getname(fd: u64, addr: u64, addrlen: u64, peer: bool) -> i64 {
    let mut hb = empty_sockaddr();
    let mut hl: libc::socklen_t = SOCKADDR_MAX as libc::socklen_t;
    let a = hb.as_mut_ptr() as *mut libc::sockaddr;
    // SAFETY: valid out parameters.
    let r = unsafe {
        if peer {
            libc::getpeername(fd as i32, a, &mut hl)
        } else {
            libc::getsockname(fd as i32, a, &mut hl)
        }
    };
    if r < 0 {
        return last_error();
    }
    if let Some(path) = remembered_name(fd as i32, !peer) {
        // A Linux `sockaddr_un` with the guest's path, cut to the buffer.
        let mut name = (AF_UNIX as u16).to_ne_bytes().to_vec();
        name.extend_from_slice(&path);
        name.push(0);
        let cap: u32 = guest!(uaccess::read(addrlen));
        let n = (cap as usize).min(name.len());
        guest!(uaccess::write_from(addr, &name[..n]));
        guest!(uaccess::write(addrlen, name.len() as u32));
        return 0;
    }
    crate::netns::to_guest(fd as i32, &mut hb, !peer);
    guest!(name_to_guest(&hb, hl, addr, addrlen));
    0
}

// --- data transfer --------------------------------------------------------

/// Translate Linux `send`/`recv` flags to host flags.
fn msg_flags_to_host(flags: u64) -> i32 {
    #[cfg(target_os = "linux")]
    {
        // MSG_NOSIGNAL has no macOS equivalent; on Linux it is honored directly.
        flags as i32
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut h = 0;
        for &(l, hbit) in &[
            (MSG_OOB, libc::MSG_OOB),
            (MSG_PEEK, libc::MSG_PEEK),
            (MSG_DONTROUTE, libc::MSG_DONTROUTE),
            (MSG_TRUNC, libc::MSG_TRUNC),
            (MSG_DONTWAIT, libc::MSG_DONTWAIT),
            (MSG_EOR, libc::MSG_EOR),
            (MSG_WAITALL, libc::MSG_WAITALL),
        ] {
            if flags & l != 0 {
                h |= hbit;
            }
        }
        h
    }
}

fn msg_flags_from_host(flags: i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        flags
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut l = 0u64;
        for &(lbit, h) in &[
            (MSG_OOB, libc::MSG_OOB),
            (MSG_TRUNC, libc::MSG_TRUNC),
            (MSG_CTRUNC, libc::MSG_CTRUNC),
            (MSG_EOR, libc::MSG_EOR),
        ] {
            if flags & h != 0 {
                l |= lbit;
            }
        }
        l as i32
    }
}

/// `sendto(fd, buf, len, flags, addr, addrlen)`.
///
/// # Safety
/// `buf` spans `len` readable bytes; `addr`, if non-null, a `sockaddr`.
pub unsafe fn sendto(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
    if crate::netlink::is(fd as i32) {
        if crate::netlink::too_large(len) {
            return err(errno::EMSGSIZE);
        }
        let data = guest!(uaccess::read_bytes(buf, len as usize));
        return crate::netlink::send(fd as i32, &data);
    }
    let hflags = msg_flags_to_host(flags);
    let mut hb = empty_sockaddr();
    let (aptr, alen) = if addr != 0 && addrlen != 0 {
        // SAFETY: the caller guarantees the sockaddr spans addrlen.
        match unsafe { to_host(addr, addrlen, &mut hb, true) } {
            Ok(a) => {
                if a.dir.is_some() {
                    // No `sendto` takes a directory to name it from.
                    return err(errno::ENAMETOOLONG);
                }
                if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
                    return err(e);
                }
                (hb.as_ptr() as *const libc::sockaddr, a.len)
            }
            Err(e) => return e,
        }
    } else {
        (std::ptr::null(), 0)
    };
    if crate::seqpacket::is(fd as i32) {
        let v = guest!(uaccess::host_buffer(buf, len, false));
        return crate::seqpacket::send(fd as i32, &[v], (std::ptr::null_mut(), 0), hflags);
    }
    // SAFETY: valid buffer and optional host sockaddr.
    ret(unsafe {
        libc::sendto(fd as i32, buf as *const libc::c_void, len as usize, hflags, aptr, alen) as i64
    })
}

/// `recvfrom(fd, buf, len, flags, addr, addrlen)`.
///
/// # Safety
/// `buf` spans `len` writable bytes; `addr`/`addrlen`, if non-null, writable.
pub unsafe fn recvfrom(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
    let hflags = msg_flags_to_host(flags);
    if crate::netlink::is(fd as i32) {
        // The whole message's length, asked for with MSG_TRUNC (the host
        // takes the flag as an output only).
        let whole = (flags & MSG_TRUNC != 0).then(|| crate::netlink::next_len(fd as i32));
        // SAFETY: the caller guarantees the buffer.
        let r = unsafe { libc::recv(fd as i32, buf as *mut libc::c_void, len as usize, hflags) };
        if r < 0 {
            return last_error();
        }
        let r = whole.flatten().filter(|_| r >= 0).map_or(r, |w| w as isize);
        if addr != 0 && addrlen != 0 {
            let w = crate::netlink::write_name(addr, addrlen, 0);
            if w < 0 {
                return w;
            }
        }
        return r as i64;
    }
    if crate::seqpacket::is(fd as i32) {
        // A connected socket's peer, which Linux does not report here.
        if addr != 0 && addrlen != 0 {
            guest!(uaccess::write(addrlen, 0u32));
        }
        let v = guest!(uaccess::host_buffer(buf, len, true));
        return crate::seqpacket::recv(fd as i32, &[v], (std::ptr::null_mut(), 0), flags, hflags)
            .result;
    }
    if addr != 0 {
        let mut hb = empty_sockaddr();
        let mut hl: libc::socklen_t = SOCKADDR_MAX as libc::socklen_t;
        // SAFETY: valid buffer and out sockaddr.
        let r = unsafe {
            libc::recvfrom(
                fd as i32,
                buf as *mut libc::c_void,
                len as usize,
                hflags,
                hb.as_mut_ptr() as *mut libc::sockaddr,
                &mut hl,
            )
        };
        if r < 0 {
            return last_error();
        }
        crate::netns::to_guest(fd as i32, &mut hb, false);
        if addrlen != 0 {
            guest!(name_to_guest(&hb, hl, addr, addrlen));
        }
        r as i64
    } else {
        // SAFETY: valid buffer; no source address wanted.
        ret(unsafe {
            libc::recvfrom(
                fd as i32,
                buf as *mut libc::c_void,
                len as usize,
                hflags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) as i64
        })
    }
}

// --- options --------------------------------------------------------------

/// Map a Linux `(level, optname)` to the host pair.
fn opt_to_host(level: u64, optname: u64) -> Result<(i32, i32), i64> {
    #[cfg(target_os = "linux")]
    {
        Ok((level as i32, optname as i32))
    }
    #[cfg(not(target_os = "linux"))]
    {
        if level == SOL_SOCKET {
            let o = match optname {
                SO_REUSEADDR => libc::SO_REUSEADDR,
                SO_TYPE => libc::SO_TYPE,
                SO_ERROR => libc::SO_ERROR,
                SO_DONTROUTE => libc::SO_DONTROUTE,
                SO_BROADCAST => libc::SO_BROADCAST,
                SO_SNDBUF => libc::SO_SNDBUF,
                SO_RCVBUF => libc::SO_RCVBUF,
                SO_KEEPALIVE => libc::SO_KEEPALIVE,
                SO_OOBINLINE => libc::SO_OOBINLINE,
                SO_LINGER => libc::SO_LINGER,
                SO_REUSEPORT => libc::SO_REUSEPORT,
                SO_RCVTIMEO => libc::SO_RCVTIMEO,
                SO_SNDTIMEO => libc::SO_SNDTIMEO,
                SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
                _ => return Err(err(errno::ENOPROTOOPT)),
            };
            return Ok((libc::SOL_SOCKET, o));
        }
        if level == libc::IPPROTO_TCP as u64 {
            let o = if optname == 1 { libc::TCP_NODELAY } else { optname as i32 };
            return Ok((libc::IPPROTO_TCP, o));
        }
        Ok((level as i32, optname as i32))
    }
}

/// `setsockopt`.
///
/// # Safety
/// `optval` spans `optlen` readable bytes.
pub unsafe fn setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    let (hl, ho) = match opt_to_host(level, optname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller guarantees the option buffer.
    ret(unsafe {
        libc::setsockopt(
            fd as i32,
            hl,
            ho,
            optval as *const libc::c_void,
            optlen as libc::socklen_t,
        ) as i64
    })
}

/// `getsockopt`.
///
/// # Safety
/// `optval`/`optlen` must be writable.
pub unsafe fn getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    if level == SOL_SOCKET && optname == SO_PEERCRED {
        if !is_unix(fd as i32) || crate::netlink::is(fd as i32) {
            // No peer process: Linux's empty `ucred` (pid 0, ids -1).
            return write_ucred(optval, optlen, [0, u32::MAX, u32::MAX]);
        }
        return peercred(fd as i32, optval, optlen);
    }
    let (hl, ho) = match opt_to_host(level, optname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller guarantees the out buffers.
    let r = ret(unsafe {
        libc::getsockopt(
            fd as i32,
            hl,
            ho,
            optval as *mut libc::c_void,
            optlen as *mut libc::socklen_t,
        ) as i64
    });
    // The kind a socket fwe made stands in for.
    if r == 0
        && level == SOL_SOCKET
        && optname == SO_TYPE
        && crate::fdmarks::marked(fd as i32) == Some(crate::fdmarks::Mark::SeqPacket)
    {
        let _ = uaccess::write(optval, SOCK_SEQPACKET as i32);
    }
    if r == 0
        && level == SOL_SOCKET
        && optname == SO_TYPE
        && let Some(ty) =
            crate::netlink::sock_type(fd as i32).filter(|_| crate::netlink::is(fd as i32))
    {
        let _ = uaccess::write(optval, ty);
    }
    r
}

/// `SO_PEERCRED`: who is at the other end of Unix socket `fd`, as a
/// `struct ucred` (pid, uid, gid) into `optval`, of the length at `optlen`.
/// The pid is the peer's in the caller's pid namespace; its ids are the
/// host's, as the guest sees them.
fn peercred(fd: i32, optval: u64, optlen: u64) -> i64 {
    let Ok(len) = uaccess::read::<u32>(optlen) else { return err(errno::EFAULT) };
    let (pid, uid, gid) = match host_peercred(fd) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let pid = crate::pidns::to_guest(pid);
    let cred = [pid as u32, crate::host::uid_to_linux(uid), crate::host::gid_to_linux(gid)];
    let _ = len;
    write_ucred(optval, optlen, cred)
}

/// Write `struct ucred` `cred` to `optval`, its room at `optlen`.
fn write_ucred(optval: u64, optlen: u64, cred: [u32; 3]) -> i64 {
    let Ok(len) = uaccess::read::<u32>(optlen) else { return err(errno::EFAULT) };
    let mut bytes = Vec::with_capacity(12);
    for w in cred {
        bytes.extend_from_slice(&w.to_ne_bytes());
    }
    let n = (len as usize).min(bytes.len());
    if uaccess::write_from(optval, &bytes[..n]).is_err()
        || uaccess::write(optlen, n as u32).is_err()
    {
        return err(errno::EFAULT);
    }
    0
}

/// The host pid, uid and gid of the peer of Unix socket `fd`.
#[cfg(target_os = "macos")]
fn host_peercred(fd: i32) -> Result<(i32, u32, u32), i32> {
    const SOL_LOCAL: i32 = 0;
    const LOCAL_PEERCRED: i32 = 1;
    const LOCAL_PEERPID: i32 = 2;
    let fail = || Err(crate::host::errno_to_linux(crate::host::last_errno()));
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: valid out-parameters of the given length.
    if unsafe {
        libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, (&mut pid as *mut i32).cast(), &mut len)
    } != 0
    {
        return fail();
    }
    // SAFETY: zeroed bytes are a valid `xucred`, which the call fills.
    let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: as above.
    if unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            (&mut cred as *mut libc::xucred).cast(),
            &mut len,
        )
    } != 0
    {
        return fail();
    }
    let gid = if cred.cr_ngroups > 0 { cred.cr_groups[0] } else { 0 };
    Ok((pid, cred.cr_uid, gid))
}

#[cfg(not(target_os = "macos"))]
fn host_peercred(fd: i32) -> Result<(i32, u32, u32), i32> {
    // SAFETY: zeroed bytes are a valid `ucred`, which the call fills.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid out-parameters of the given length.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

/// `shutdown(fd, how)`. `how` matches on both.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn shutdown(fd: u64, how: u64) -> i64 {
    // SAFETY: plain host call.
    let r = ret(unsafe { libc::shutdown(fd as i32, how as i32) } as i64);
    if r == err(errno::ENOTCONN) && is_unix(fd as i32) {
        // macOS refuses once the peer has gone; Linux's Unix sockets shut
        // down whatever their peer.
        return 0;
    }
    r
}

/// Whether `fd` is a Unix socket.
fn is_unix(fd: i32) -> bool {
    let mut hb = empty_sockaddr();
    let mut hl: libc::socklen_t = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters.
    let r = unsafe { libc::getsockname(fd, hb.as_mut_ptr() as *mut libc::sockaddr, &mut hl) };
    // `sa_family` is the second byte on macOS (after `sa_len`), the first
    // two on Linux.
    #[cfg(target_os = "macos")]
    let family = i32::from(hb[1]);
    #[cfg(not(target_os = "macos"))]
    let family = i32::from(u16::from_ne_bytes([hb[0], hb[1]]));
    r == 0 && family == libc::AF_UNIX
}

// --- scatter/gather + ancillary -------------------------------------------

/// Guest `msghdr` fields (64-bit Linux layout): name, namelen, iov,
/// iovlen, control, controllen.
fn read_msghdr(msg: u64) -> uaccess::Result<(u64, u32, u64, u64, u64, u64)> {
    let w: [u64; 6] = uaccess::read(msg)?;
    Ok((w[0], w[1] as u32, w[2], w[3], w[4], w[5]))
}

/// `sendmsg(fd, msg, flags)`.
///
/// # Safety
/// `msg` must point to a valid `msghdr`.
pub unsafe fn sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let (name, namelen, iov, iovlen, control, controllen) = guest!(read_msghdr(msg));
    let mut hiov = guest!(uaccess::host_iovecs(iov, iovlen, false));
    if crate::netlink::is(fd as i32) {
        let total: usize = hiov.iter().map(|v| v.iov_len).sum();
        if crate::netlink::too_large(total as u64) {
            return err(errno::EMSGSIZE);
        }
        let mut data = Vec::new();
        for v in &hiov {
            // SAFETY: the iovecs are checked host buffers.
            data.extend_from_slice(unsafe {
                std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
            });
        }
        return crate::netlink::send(fd as i32, &data);
    }
    let mut hb = empty_sockaddr();
    let (name_ptr, name_len) = if name != 0 && namelen != 0 {
        // SAFETY: the caller guarantees the name spans namelen.
        match unsafe { to_host(name, namelen as u64, &mut hb, true) } {
            Ok(a) => {
                if a.dir.is_some() {
                    // No `sendto` takes a directory to name it from.
                    return err(errno::ENAMETOOLONG);
                }
                if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
                    return err(e);
                }
                (hb.as_mut_ptr() as *mut libc::c_void, a.len)
            }
            Err(e) => return e,
        }
    } else {
        (std::ptr::null_mut(), 0)
    };

    // Ancillary data: on Linux the guest layout is the host's, so it passes
    // through; on macOS re-encode SCM_RIGHTS.
    #[cfg(target_os = "linux")]
    let (ctl_ptr, ctl_len) = (control as *mut libc::c_void, controllen as _);
    #[cfg(not(target_os = "linux"))]
    let mut macbuf = [0u8; 256];
    #[cfg(not(target_os = "linux"))]
    let (ctl_ptr, ctl_len) = if controllen != 0 {
        match scm_linux_to_host(control, controllen as usize, &mut macbuf) {
            Ok(0) => (std::ptr::null_mut(), 0),
            Ok(n) => (macbuf.as_mut_ptr() as *mut libc::c_void, n as libc::socklen_t),
            Err(e) => return e,
        }
    } else {
        (std::ptr::null_mut(), 0)
    };

    let hmsg = libc::msghdr {
        msg_name: name_ptr,
        msg_namelen: name_len,
        msg_iov: hiov.as_mut_ptr(),
        msg_iovlen: hiov.len() as _,
        msg_control: ctl_ptr,
        msg_controllen: ctl_len,
        msg_flags: 0,
    };
    if crate::seqpacket::is(fd as i32) {
        return crate::seqpacket::send(
            fd as i32,
            &hiov,
            (hmsg.msg_control, hmsg.msg_controllen as usize),
            msg_flags_to_host(flags),
        );
    }
    // SAFETY: `hmsg` references guest iov and local name/control buffers.
    ret(unsafe { libc::sendmsg(fd as i32, &hmsg, msg_flags_to_host(flags)) } as i64)
}

/// `recvmsg(fd, msg, flags)`.
///
/// # Safety
/// `msg` must point to a valid `msghdr` with writable `iov`/`name`.
pub unsafe fn recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let (name, namelen, iov, iovlen, control, controllen) = guest!(read_msghdr(msg));
    let mut hiov = guest!(uaccess::host_iovecs(iov, iovlen, true));
    let want_name = name != 0 && namelen != 0;
    let mut hb = empty_sockaddr();

    #[cfg(target_os = "linux")]
    let (ctl_ptr, ctl_cap) = (control as *mut libc::c_void, controllen as _);
    #[cfg(not(target_os = "linux"))]
    let mut macbuf = [0u8; 256];
    #[cfg(not(target_os = "linux"))]
    let (ctl_ptr, ctl_cap) = if controllen != 0 {
        (macbuf.as_mut_ptr() as *mut libc::c_void, macbuf.len() as libc::socklen_t)
    } else {
        (std::ptr::null_mut(), 0)
    };

    let mut hmsg = libc::msghdr {
        msg_name: if want_name {
            hb.as_mut_ptr() as *mut libc::c_void
        } else {
            std::ptr::null_mut()
        },
        msg_namelen: if want_name { namelen.min(SOCKADDR_MAX as u32) } else { 0 },
        msg_iov: hiov.as_mut_ptr(),
        msg_iovlen: hiov.len() as _,
        msg_control: ctl_ptr,
        msg_controllen: ctl_cap,
        msg_flags: 0,
    };
    // A netlink message's whole length, asked for with MSG_TRUNC.
    let nl_whole = (crate::netlink::is(fd as i32) && flags & MSG_TRUNC != 0)
        .then(|| crate::netlink::next_len(fd as i32))
        .flatten();
    let r = if crate::seqpacket::is(fd as i32) {
        let got = crate::seqpacket::recv(
            fd as i32,
            &hiov,
            (hmsg.msg_control, hmsg.msg_controllen as usize),
            flags,
            msg_flags_to_host(flags),
        );
        if got.result < 0 {
            return got.result;
        }
        hmsg.msg_namelen = 0;
        hmsg.msg_controllen = got.controllen as _;
        hmsg.msg_flags = got.flags;
        got.result as isize
    } else {
        // SAFETY: `hmsg` references guest iov and local name/control buffers.
        let r = unsafe { libc::recvmsg(fd as i32, &mut hmsg, msg_flags_to_host(flags)) };
        if r < 0 {
            return last_error();
        }
        nl_whole.map_or(r, |w| w as isize)
    };
    if want_name && crate::netlink::is(fd as i32) {
        // From the kernel: port 0.
        let b = {
            let mut b = [0u8; 12];
            b[0..2].copy_from_slice(&(crate::netlink::AF_NETLINK as u16).to_ne_bytes());
            b
        };
        guest!(uaccess::write_from(name, &b[..(namelen as usize).min(12)]));
        guest!(uaccess::write(msg + 8, 12u32));
    } else if want_name {
        crate::netns::to_guest(fd as i32, &mut hb, false);
        let full = guest!(to_guest(&hb, hmsg.msg_namelen, name, namelen));
        guest!(uaccess::write(msg + 8, full));
    }

    // Ancillary data back to the guest.
    #[cfg(target_os = "linux")]
    {
        // Host wrote the guest's Linux-layout control buffer directly.
        guest!(uaccess::write(msg + 40, hmsg.msg_controllen as u64));
        guest!(uaccess::write(msg + 48, msg_flags_from_host(hmsg.msg_flags)));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (clen, ctrunc) = if controllen != 0 && hmsg.msg_controllen != 0 {
            guest!(scm_host_to_linux(
                &macbuf,
                hmsg.msg_controllen as usize,
                control,
                controllen as usize,
            ))
        } else {
            (0u64, false)
        };
        let mut lflags = msg_flags_from_host(hmsg.msg_flags);
        if ctrunc {
            lflags |= MSG_CTRUNC as i32;
        }
        guest!(uaccess::write(msg + 40, clen));
        guest!(uaccess::write(msg + 48, lflags));
    }
    r as i64
}

/// Re-encode a guest Linux `SCM_RIGHTS` control buffer into macOS layout in
/// `out`; returns the macOS control length (0 if no SCM_RIGHTS present).
#[cfg(not(target_os = "linux"))]
fn scm_linux_to_host(control: u64, len: usize, out: &mut [u8; 256]) -> Result<usize, i64> {
    // Linux cmsghdr: { u64 cmsg_len; i32 level; i32 type; } then data @16, 8-aligned.
    let ctl = uaccess::read_bytes(control, len.min(64 * 1024)).map_err(err)?;
    let len = ctl.len();
    let u64_at = |o: usize| u64::from_ne_bytes(ctl[o..o + 8].try_into().unwrap());
    let i32_at = |o: usize| i32::from_ne_bytes(ctl[o..o + 4].try_into().unwrap());
    let mut off = 0usize;
    while off + 16 <= len {
        let (clen, level, ctype) = (u64_at(off) as usize, i32_at(off + 8), i32_at(off + 12));
        if clen < 16 || off + clen > len {
            break;
        }
        if level == SOL_SOCKET as i32 && ctype == 1
        /* SCM_RIGHTS */
        {
            let nfds = (clen - 16) / 4;
            // macOS cmsghdr: { u32 cmsg_len; i32 level; i32 type; } data @12, 4-aligned.
            let maclen = 12 + nfds * 4;
            if maclen > out.len() {
                return Err(err(errno::EINVAL));
            }
            out[0..4].copy_from_slice(&(maclen as u32).to_ne_bytes());
            out[4..8].copy_from_slice(&(libc::SOL_SOCKET).to_ne_bytes());
            out[8..12].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
            for i in 0..nfds {
                let fd = i32_at(off + 16 + i * 4);
                out[12 + i * 4..16 + i * 4].copy_from_slice(&fd.to_ne_bytes());
            }
            return Ok(maclen);
        }
        off += (clen + 7) & !7; // CMSG_ALIGN to 8
    }
    Ok(0)
}

/// Re-encode macOS `SCM_RIGHTS` control data from `host` into the guest Linux
/// control buffer; returns `(linux_controllen, truncated)`.
///
/// `host` holds `host_len` bytes; `dst` is the guest's buffer of `dst_cap`
/// bytes.
#[cfg(not(target_os = "linux"))]
fn scm_host_to_linux(
    host: &[u8; 256],
    host_len: usize,
    dst: u64,
    dst_cap: usize,
) -> uaccess::Result<(u64, bool)> {
    let mut off = 0usize;
    while off + 12 <= host_len {
        let clen =
            u32::from_ne_bytes([host[off], host[off + 1], host[off + 2], host[off + 3]]) as usize;
        let level =
            i32::from_ne_bytes([host[off + 4], host[off + 5], host[off + 6], host[off + 7]]);
        let ctype =
            i32::from_ne_bytes([host[off + 8], host[off + 9], host[off + 10], host[off + 11]]);
        if clen < 12 || off + clen > host_len {
            break;
        }
        if level == libc::SOL_SOCKET && ctype == libc::SCM_RIGHTS {
            let nfds = (clen - 12) / 4;
            let linux_len = 16 + nfds * 4;
            if linux_len > dst_cap {
                return Ok((0, true));
            }
            let mut out = vec![0u8; linux_len];
            out[0..8].copy_from_slice(&(linux_len as u64).to_ne_bytes());
            out[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
            out[12..16].copy_from_slice(&1i32.to_ne_bytes()); // SCM_RIGHTS
            for i in 0..nfds {
                let fd = &host[off + 12 + i * 4..off + 16 + i * 4];
                out[16 + i * 4..20 + i * 4].copy_from_slice(fd);
                // A SOCK_SEQPACKET socket of fwe's is one here too.
                crate::seqpacket::adopt(i32::from_ne_bytes(fd.try_into().unwrap()));
            }
            uaccess::write_from(dst, &out)?;
            return Ok((linux_len as u64, false));
        }
        off += (clen + 3) & !3; // CMSG_ALIGN to 4 on macOS
    }
    Ok((0, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(fd: i64) {
        // SAFETY: plain host close of a socket we opened.
        unsafe { libc::close(fd as i32) };
    }

    fn sockaddr_in_v4(port: u16) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&[127, 0, 0, 1]);
        b
    }

    #[test]
    fn socketpair_round_trip() {
        let mut sv = [0i32; 2];
        let p = sv.as_mut_ptr() as u64;
        // SAFETY: `sv` holds two i32s.
        let r = unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, p) };
        assert_eq!(r, 0, "socketpair failed: {r}");
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::write(sv[0], b"ping".as_ptr() as *const _, 4) };
        assert_eq!(n, 4);
        let mut buf = [0u8; 8];
        // SAFETY: valid fd and buffer.
        let got = unsafe { libc::read(sv[1], buf.as_mut_ptr() as *mut _, buf.len()) };
        assert_eq!(got, 4);
        assert_eq!(&buf[..4], b"ping");
        close(sv[0] as i64);
        close(sv[1] as i64);
    }

    #[test]
    fn udp_v4_loopback() {
        // SAFETY: no pointers.
        let rx = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        assert!(rx >= 0, "socket rx: {rx}");
        // SAFETY: no pointers.
        let tx = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        assert!(tx >= 0);
        let addr = sockaddr_in_v4(0);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { bind(rx as u64, addr.as_ptr() as u64, 16, true, 0o022) }, 0);
        let mut got = [0u8; 16];
        let mut len: u32 = 16;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(rx as u64, got.as_mut_ptr() as u64, &mut len as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        let port = u16::from_be_bytes([got[2], got[3]]);
        assert_ne!(port, 0);
        let dst = sockaddr_in_v4(port);
        let payload = b"hello-udp";
        // SAFETY: valid buffer and sockaddr.
        let sent = unsafe {
            sendto(
                tx as u64,
                payload.as_ptr() as u64,
                payload.len() as u64,
                0,
                dst.as_ptr() as u64,
                16,
            )
        };
        assert_eq!(sent, payload.len() as i64, "sendto: {sent}");
        let mut buf = [0u8; 32];
        // SAFETY: valid buffer.
        let recvd = unsafe { recvfrom(rx as u64, buf.as_mut_ptr() as u64, 32, 0, 0, 0) };
        assert_eq!(recvd, payload.len() as i64);
        assert_eq!(&buf[..payload.len()], payload);
        close(rx);
        close(tx);
    }

    /// Validates the `sockaddr_in6` translation by binding `[::]:0` and reading
    /// it back; skips where IPv6 is unavailable.
    #[test]
    fn v6_sockaddr_round_trip() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
        if fd < 0 {
            eprintln!("skipping: AF_INET6 unavailable ({fd})");
            return;
        }
        let mut addr = [0u8; 28];
        addr[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
        // SAFETY: valid sockaddr_in6.
        let b = unsafe { bind(fd as u64, addr.as_ptr() as u64, 28, true, 0o022) };
        if b != 0 {
            eprintln!("skipping: IPv6 bind unavailable ({b})");
            close(fd);
            return;
        }
        let mut got = [0u8; 28];
        let mut len: u32 = 28;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(fd as u64, got.as_mut_ptr() as u64, &mut len as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        assert_eq!(u16::from_ne_bytes([got[0], got[1]]) as u64, AF_INET6);
        assert_eq!(len, 28);
        close(fd);
    }

    #[test]
    fn tcp_v4_loopback() {
        // SAFETY: no pointers.
        let srv = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(srv >= 0);
        let one: i32 = 1;
        // SAFETY: valid option buffer.
        unsafe {
            setsockopt(srv as u64, SOL_SOCKET, SO_REUSEADDR, &one as *const _ as u64, 4);
        }
        let addr = sockaddr_in_v4(0);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { bind(srv as u64, addr.as_ptr() as u64, 16, true, 0o022) }, 0);
        // SAFETY: no pointers.
        assert_eq!(unsafe { listen(srv as u64, 1) }, 0);
        let mut sa = [0u8; 16];
        let mut salen: u32 = 16;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(srv as u64, sa.as_mut_ptr() as u64, &mut salen as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        let port = u16::from_be_bytes([sa[2], sa[3]]);
        // SAFETY: no pointers.
        let cli = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(cli >= 0);
        let dst = sockaddr_in_v4(port);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { connect(cli as u64, dst.as_ptr() as u64, 16) }, 0);
        // SAFETY: no out address wanted.
        let acc = unsafe { accept4(srv as u64, 0, 0, 0) };
        assert!(acc >= 0, "accept: {acc}");
        let msg = b"tcp-hi";
        // SAFETY: valid buffer.
        let sent = unsafe { sendto(cli as u64, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0) };
        assert_eq!(sent, msg.len() as i64);
        let mut buf = [0u8; 16];
        // SAFETY: valid buffer.
        let got = unsafe { recvfrom(acc as u64, buf.as_mut_ptr() as u64, 16, 0, 0, 0) };
        assert_eq!(got, msg.len() as i64);
        assert_eq!(&buf[..msg.len()], msg);
        close(acc);
        close(cli);
        close(srv);
    }

    #[test]
    fn getsockopt_reports_type() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let mut ty: i32 = -1;
        let mut len: u32 = 4;
        // SAFETY: writable option and length buffers.
        let r = unsafe {
            getsockopt(
                fd as u64,
                SOL_SOCKET,
                SO_TYPE,
                &mut ty as *mut _ as u64,
                &mut len as *mut _ as u64,
            )
        };
        assert_eq!(r, 0, "getsockopt: {r}");
        assert_eq!(ty as u64, SOCK_STREAM);
        close(fd);
    }

    /// A guest `AF_UNIX` address for `path`, and its length.
    fn unix_addr(path: &[u8]) -> ([u8; 110], u64) {
        let mut addr = [0u8; 2 + 108];
        addr[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
        addr[2..2 + path.len()].copy_from_slice(path);
        (addr, 2 + path.len() as u64 + 1)
    }

    /// Pathed AF_UNIX: socket paths are resolved as file paths are, in the
    /// guest's filesystem: a relative one from the working directory, `..`
    /// kept inside the root, symlinks followed in the root (except by
    /// `bind`, which creates the name). A stream socket bound, connected,
    /// accepted and exchanging a message, and its name reported as the
    /// guest's path.
    #[test]
    fn unix_path_round_trip() {
        let dir = std::env::temp_dir().join(format!("fwe-unix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::os::unix::fs::symlink("/sub/s", dir.join("link")).unwrap();
        std::os::unix::fs::symlink("/sub/t", dir.join("dangling")).unwrap();
        let mut fs = crate::fs::Fs::new(Some(dir.as_os_str().as_encoded_bytes())).unwrap();
        fs.publish();
        fs.chdir(fwe_abi::fcntl::AT_FDCWD as i32, b"/sub").unwrap();

        // SAFETY: no pointers.
        let srv = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
        assert!(srv >= 0);
        // "s", from the working directory /sub.
        let (addr, alen) = unix_addr(b"s");
        // SAFETY: valid sockaddr.
        let b = unsafe { bind(srv as u64, addr.as_ptr() as u64, alen, true, 0o022) };
        assert_eq!(b, 0, "unix bind: {b}");
        assert!(dir.join("sub/s").exists());
        // SAFETY: no pointers.
        assert_eq!(unsafe { listen(srv as u64, 4) }, 0);
        let mut name = [0u8; 110];
        let mut len = name.len() as u32;
        // SAFETY: valid out pointers.
        let r = unsafe {
            getname(srv as u64, name.as_mut_ptr() as u64, &mut len as *mut u32 as u64, false)
        };
        assert_eq!(r, 0);
        assert_eq!(&name[2..len as usize], b"/sub/s\0");

        // The same socket by `..` past the root, and through a symlink.
        for path in [&b"/../../sub/s"[..], b"../link"] {
            // SAFETY: no pointers.
            let cli = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
            let (addr, alen) = unix_addr(path);
            // SAFETY: valid sockaddr.
            let c = unsafe { connect(cli as u64, addr.as_ptr() as u64, alen) };
            assert_eq!(c, 0, "unix connect {}: {c}", String::from_utf8_lossy(path));
            // SAFETY: no out address.
            let acc = unsafe { accept4(srv as u64, 0, 0, 0) };
            assert!(acc >= 0, "unix accept: {acc}");
            // SAFETY: valid buffer.
            let sent = unsafe { sendto(cli as u64, b"u!".as_ptr() as u64, 2, 0, 0, 0) };
            assert_eq!(sent, 2);
            let mut buf = [0u8; 4];
            // SAFETY: valid buffer.
            let got = unsafe { recvfrom(acc as u64, buf.as_mut_ptr() as u64, 4, 0, 0, 0) };
            assert_eq!(&buf[..got as usize], b"u!");
            close(acc);
            close(cli);
        }

        // `bind` does not follow a final symlink: the name is taken.
        // SAFETY: no pointers.
        let other = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
        let (addr, alen) = unix_addr(b"/dangling");
        // SAFETY: valid sockaddr.
        let b = unsafe { bind(other as u64, addr.as_ptr() as u64, alen, true, 0o022) };
        assert_eq!(b, -(errno::EADDRINUSE as i64));
        assert!(!dir.join("sub/t").exists());

        close(other);
        close(srv);
        crate::fs::unpublish();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SCM_RIGHTS: pass a file descriptor over a socketpair via sendmsg/recvmsg
    /// and confirm the received fd refers to the same file.
    #[test]
    fn scm_rights_fd_passing() {
        let mut sv = [0i32; 2];
        // SAFETY: valid array.
        assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64) }, 0);

        // A pipe whose read end we send across.
        let mut pipe = [0i32; 2];
        // SAFETY: valid array.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);

        // Build a Linux msghdr with a one-byte payload and an SCM_RIGHTS cmsg.
        let iovbuf = *b"x";
        let iov = libc::iovec { iov_base: iovbuf.as_ptr() as *mut _, iov_len: 1 };
        // Linux cmsg: u64 len; i32 level; i32 type; then one fd.
        let mut cbuf = [0u8; 16 + 4];
        cbuf[0..8].copy_from_slice(&(20u64).to_ne_bytes());
        cbuf[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
        cbuf[12..16].copy_from_slice(&(1i32).to_ne_bytes()); // SCM_RIGHTS
        cbuf[16..20].copy_from_slice(&pipe[0].to_ne_bytes());
        // Linux msghdr: name,namelen,iov,iovlen,control,controllen,flags.
        let mut mhdr = [0u8; 56];
        mhdr[16..24].copy_from_slice(&(&iov as *const _ as u64).to_ne_bytes());
        mhdr[24..32].copy_from_slice(&(1u64).to_ne_bytes());
        mhdr[32..40].copy_from_slice(&(cbuf.as_ptr() as u64).to_ne_bytes());
        mhdr[40..48].copy_from_slice(&(20u64).to_ne_bytes());
        // SAFETY: valid msghdr pointing at valid iov/control.
        let sent = unsafe { sendmsg(sv[0] as u64, mhdr.as_ptr() as u64, 0) };
        assert_eq!(sent, 1, "sendmsg: {sent}");

        // Receive with a control buffer.
        let mut rbuf = [0u8; 4];
        let riov = libc::iovec { iov_base: rbuf.as_mut_ptr() as *mut _, iov_len: 4 };
        let mut rc = [0u8; 64];
        let mut rhdr = [0u8; 56];
        rhdr[16..24].copy_from_slice(&(&riov as *const _ as u64).to_ne_bytes());
        rhdr[24..32].copy_from_slice(&(1u64).to_ne_bytes());
        rhdr[32..40].copy_from_slice(&(rc.as_mut_ptr() as u64).to_ne_bytes());
        rhdr[40..48].copy_from_slice(&(rc.len() as u64).to_ne_bytes());
        // SAFETY: valid msghdr with writable iov/control.
        let got = unsafe { recvmsg(sv[1] as u64, rhdr.as_mut_ptr() as u64, 0) };
        assert_eq!(got, 1, "recvmsg: {got}");
        assert_eq!(rbuf[0], b'x');

        // The control buffer should carry one SCM_RIGHTS fd (Linux layout).
        let clen = u64::from_ne_bytes(rhdr[40..48].try_into().unwrap()) as usize;
        assert!(clen >= 20, "controllen: {clen}");
        let newfd = i32::from_ne_bytes([rc[16], rc[17], rc[18], rc[19]]);
        assert!(newfd >= 0, "received fd: {newfd}");

        // Write through the original pipe write end; read via the received fd.
        // SAFETY: valid fds and buffers.
        unsafe {
            assert_eq!(libc::write(pipe[1], b"Z".as_ptr() as *const _, 1), 1);
            let mut one = [0u8; 1];
            assert_eq!(libc::read(newfd, one.as_mut_ptr() as *mut _, 1), 1);
            assert_eq!(one[0], b'Z');
            libc::close(newfd);
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}
