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
use crate::sockopt::Form;
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
        // file under a per-host temp directory so peers rendezvous, the
        // name kept beside it (`<file>.name`) to be reported back.
        let dir = abstract_dir();
        // Private to fwe's user, whatever the host's umask (fwe sets it to
        // 0, the guest's being its own to apply).
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir);
        }
        let p = abstract_file(&raw[1..]);
        let name = p.with_extension("name");
        if !name.exists() {
            let _ = std::fs::write(&name, &raw[1..]);
        }
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

/// Whether the caller may write to the Unix socket file host address `hb`
/// names (`a`'s), which connecting or sending to it needs: `EACCES` if the
/// mode fwe keeps for it denies its owner that, to a caller without
/// `CAP_DAC_OVERRIDE` ([`crate::modes`]; the host checks any other mode).
fn may_write_socket(hb: &[u8; SOCKADDR_MAX], a: &HostAddr) -> Result<(), i32> {
    if family(hb) != libc::AF_UNIX || hb[2] == 0 || crate::creds::dac_override() {
        return Ok(());
    }
    use std::os::fd::AsRawFd;
    let end = hb[2..].iter().position(|&b| b == 0).map_or(hb.len(), |e| e + 2);
    let Ok(name) = std::ffi::CString::new(&hb[2..end]) else { return Ok(()) };
    let dir = a.dir.as_ref().map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated name, relative to a live directory.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, 0) } != 0 || !crate::modes::marked(&st) {
        return Ok(());
    }
    let perm = crate::modes::guest_perm_at(dir, &name, &st);
    if crate::modes::owner_allows(perm, 2) { Ok(()) } else { Err(errno::EACCES) }
}

/// The file abstract name `name` (without its leading NUL) stands as.
fn abstract_file(name: &[u8]) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    abstract_dir().join(format!("{:016x}", h.finish()))
}

/// The host process that bound abstract name `name`, if one did (for a
/// Landlock domain that scopes abstract sockets).
pub fn abstract_owner(name: &[u8]) -> Option<i32> {
    let b = std::fs::read(abstract_file(name).with_extension("owner")).ok()?;
    Some(i32::from_ne_bytes(b.get(..4)?.try_into().ok()?))
}

/// Where abstract names' files are: each network namespace has its own.
fn abstract_dir() -> std::path::PathBuf {
    match crate::netns::current() {
        Some(net) => {
            use std::os::unix::ffi::OsStrExt;
            std::path::Path::new(std::ffi::OsStr::from_bytes(net.dir())).join("abstract")
        }
        None => std::env::temp_dir().join("fwe-abstract"),
    }
}

/// The abstract name (without its leading NUL) host path `host` stands
/// for, if it is one's file.
fn abstract_name(host: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(host));
    if path.parent()? != abstract_dir() {
        return None;
    }
    std::fs::read(path.with_extension("name")).ok()
}

/// Reverse [`root_unix_path`] for addresses handed back to the guest: an
/// abstract name (with its leading NUL), the guest path of the host path,
/// or the host path when it has neither.
fn unroot_unix_path(host: &[u8]) -> Vec<u8> {
    if let Some(name) = abstract_name(host) {
        return [&[0][..], &name].concat();
    }
    crate::fs::guest_of_host(host).unwrap_or_else(|| host.to_vec())
}

/// Whether the socket file at host path `hb`'s (an abstract name's) has no
/// socket behind it any longer: one of type `ty` connecting to it is
/// refused. Linux frees an abstract name with its socket; its file here
/// stays until the name is bound again.
fn abstract_stale(hb: &[u8; SOCKADDR_MAX], len: libc::socklen_t, ty: i32) -> bool {
    // SAFETY: plain host calls on a socket this owns.
    unsafe {
        let probe = libc::socket(libc::AF_UNIX, ty, 0);
        if probe < 0 {
            return false;
        }
        let r = libc::connect(probe, hb.as_ptr().cast(), len);
        let refused = r < 0 && crate::host::last_errno() == libc::ECONNREFUSED;
        libc::close(probe);
        refused
    }
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
    bytes_to_host(&src, out, follow)
}

/// [`to_host`] of a guest `sockaddr` read already.
fn bytes_to_host(src: &[u8], out: &mut [u8; SOCKADDR_MAX], follow: bool) -> Result<HostAddr, i64> {
    if src.len() < 2 {
        return Err(err(errno::EINVAL));
    }
    let len = match u16::from_ne_bytes([src[0], src[1]]) as u64 {
        AF_INET => inet_to_host(src, out, 16)?,
        AF_INET6 => inet_to_host(src, out, 28)?,
        AF_UNIX => return unix_to_host(src, out, follow),
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
/// A socket node `name` in directory `dir`, as `mknod` makes one: a Unix
/// socket bound there, from the directory, and closed, leaving the node.
pub fn make_socket_node(dir: i32, name: &std::ffi::CStr, perm: u32) -> Result<(), i32> {
    let bytes = name.to_bytes();
    if bytes.len() + 1 > UNIX_PATH_MAX {
        return Err(errno::ENAMETOOLONG);
    }
    // SAFETY: duplicating a live directory descriptor, owned below.
    let d = unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0) };
    if d < 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    use std::os::fd::FromRawFd;
    // SAFETY: the fresh duplicate.
    let d = unsafe { std::os::fd::OwnedFd::from_raw_fd(d) };
    let mut sa = empty_sockaddr();
    #[cfg(not(target_os = "linux"))]
    {
        sa[0] = (2 + bytes.len() + 1) as u8;
        sa[1] = libc::AF_UNIX as u8;
    }
    #[cfg(target_os = "linux")]
    sa[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
    sa[2..2 + bytes.len()].copy_from_slice(bytes);
    // SAFETY: a fresh socket of this function's, closed below.
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if s < 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    let len = (2 + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: a valid host sockaddr of `len` bytes.
    let r = in_dir(Some(&d), || unsafe { libc::bind(s, sa.as_ptr().cast(), len) });
    let e = crate::host::last_errno();
    // SAFETY: closing the socket made above; the node stays.
    unsafe { libc::close(s) };
    if r != 0 {
        return Err(crate::host::errno_to_linux(e));
    }
    // SAFETY: a NUL-terminated name in a live directory.
    unsafe { libc::fchmodat(dir, name.as_ptr(), perm as libc::mode_t, libc::AT_SYMLINK_NOFOLLOW) };
    Ok(())
}

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
    // An IPv6 address without its scope (RFC 2133's 24 bytes) has none.
    let mut padded = [0u8; 28];
    let src = if total == 28 && (24..28).contains(&src.len()) {
        padded[..src.len()].copy_from_slice(src);
        &padded[..]
    } else {
        src
    };
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
            // An abstract name is its bytes, a path ends in a NUL.
            if guest.first() == Some(&0) {
                linux_len = 2 + n;
            } else {
                lb[2 + n] = 0;
                linux_len = 2 + n + 1;
            }
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
    let cap = name_room(addr, addrlen)?;
    let full = to_guest(host, host_len, addr, cap)?;
    uaccess::write(addrlen, full)
}

/// The room a caller gives for a socket name at `addr`, of its length at
/// `addrlen`, checked as Linux checks it: a negative length is `EINVAL`, a
/// buffer with room that is not there `EFAULT`.
fn name_room(addr: u64, addrlen: u64) -> uaccess::Result<u32> {
    let cap: i32 = uaccess::read(addrlen)?;
    if cap < 0 {
        return Err(errno::EINVAL);
    }
    if addr == 0 && cap > 0 {
        return Err(errno::EFAULT);
    }
    Ok(cap as u32)
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

/// `SO_SNDBUF` or `SO_RCVBUF`, or their `FORCE` forms (32, 33; with
/// `CAP_NET_ADMIN`, `admin`), as Linux sets them: the size asked, held to
/// `net.core.wmem_max` or `rmem_max` (the forced one only to half the
/// largest `int`), doubled for the kernel's own bookkeeping, and at least
/// Linux's minimum. The host's buffer is given that size, or the largest
/// it takes below it, and reports it back.
fn buffer_size(fd: i32, optname: u64, optval: u64, optlen: u64, admin: bool) -> i64 {
    let send = optname == SO_SNDBUF || optname == 32;
    let force = optname == 32 || optname == 33;
    if force && !admin {
        return err(errno::EPERM);
    }
    if optlen < 4 {
        return err(errno::EINVAL);
    }
    let val: i32 = guest!(uaccess::read(optval));
    let max = |key: &[u8]| {
        crate::sysctl::number(key).map_or(LINUX_BUFFER as i64, |n| n.clamp(0, i32::MAX as i64))
    };
    let v = if force {
        i64::from(val).min(i64::from(i32::MAX / 2))
    } else {
        // Compared unsigned, as Linux compares it.
        let cap = if send { max(b"net/core/wmem_max") } else { max(b"net/core/rmem_max") };
        (val as u32 as i64).min(cap)
    };
    // SOCK_MIN_SNDBUF and SOCK_MIN_RCVBUF on arm64.
    let least: i32 = if send { 4608 } else { 2304 };
    let mut size = (v * 2).max(i64::from(least)).min(i64::from(i32::MAX)) as i32;
    let opt = if send { libc::SO_SNDBUF } else { libc::SO_RCVBUF };
    loop {
        // SAFETY: a valid in-parameter of its length.
        let r = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&raw const size).cast(), 4) };
        if r == 0 {
            return 0;
        }
        // Past what the host takes: the most it does.
        if crate::host::last_errno() != libc::ENOBUFS || size <= least {
            return last_error();
        }
        size /= 2;
    }
}

/// The host family of a socket of `domain`, `type_` and `protocol`, or
/// the error Linux refuses it with, checked in Linux's order: the family's
/// range, the type and its flags, the family, then the type and protocol
/// the family has (a raw IP socket names its protocol; a Unix socket's is
/// 0 or `PF_UNIX`).
fn check_socket(domain: u64, type_: u64, protocol: u64) -> Result<libc::c_int, i64> {
    // NPROTO and SOCK_MAX.
    if domain >= 46 {
        return Err(err(errno::EAFNOSUPPORT));
    }
    let base = type_ & SOCK_TYPE_MASK;
    if type_ & !(SOCK_TYPE_MASK | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 || base >= 11 {
        return Err(err(errno::EINVAL));
    }
    let dom = host_af(domain)?;
    let refused = match domain {
        AF_UNIX if protocol != 0 && protocol != AF_UNIX => Some(errno::EPROTONOSUPPORT),
        AF_UNIX => (!matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET))
            .then_some(errno::ESOCKTNOSUPPORT),
        // Past IPPROTO_MAX.
        _ if protocol >= 263 => Some(errno::EINVAL),
        // TCP; UDP, UDP-Lite and ping (ICMP or ICMPv6); raw, of a protocol.
        _ => match (base, protocol) {
            (SOCK_STREAM, 0 | 6) => None,
            (SOCK_DGRAM, 0 | 17 | 136) => None,
            (SOCK_DGRAM, 1) if domain == AF_INET => None,
            (SOCK_DGRAM, 58) if domain == AF_INET6 => None,
            (SOCK_RAW, 1..=255) => None,
            (SOCK_STREAM | SOCK_DGRAM | SOCK_RAW, _) => Some(errno::EPROTONOSUPPORT),
            _ => Some(errno::ESOCKTNOSUPPORT),
        },
    };
    match refused {
        Some(e) => Err(err(e)),
        None => Ok(dom),
    }
}

/// `socket(domain, type, protocol)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn socket(domain: u64, type_: u64, protocol: u64) -> i64 {
    let dom = match check_socket(domain, type_, protocol) {
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
    let dom = match check_socket(domain, type_, protocol) {
        Ok(d) => d,
        Err(e) => return e,
    };
    // Only Unix sockets come in pairs.
    if dom != libc::AF_UNIX {
        return err(errno::EOPNOTSUPP);
    }
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
    let src = match guest_sockaddr(fd as i32, addr, addrlen, true) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut hb = empty_sockaddr();
    let a = match bytes_to_host(&src, &mut hb, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // A port below `net.ipv4.ip_unprivileged_port_start` is the
    // privileged's (the host lets anyone have one on the wildcard address;
    // on a loopback one, `netns` maps it).
    if !may_low
        && matches!(family(&hb), libc::AF_INET | libc::AF_INET6)
        && (1..crate::sysctl::unprivileged_port_start())
            .contains(&u16::from_be_bytes([hb[2], hb[3]]))
    {
        return err(errno::EACCES);
    }
    let plan = match crate::netns::bind_prepare(fd as i32, &mut hb, may_low) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let mut r = ret(bind_or_connect(fd as i32, &hb, &a, true) as i64);
    if r == err(errno::EADDRINUSE) && family(&hb) == libc::AF_UNIX {
        let end = hb[2..].iter().position(|&b| b == 0).map_or(hb.len(), |e| e + 2);
        let ty = kind(fd as i32).map_or(libc::SOCK_STREAM, |k| k.1);
        if abstract_name(&hb[2..end]).is_some() && abstract_stale(&hb, a.len, ty) {
            use std::os::unix::ffi::OsStrExt;
            let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(&hb[2..end]));
            r = ret(bind_or_connect(fd as i32, &hb, &a, true) as i64);
        }
    }
    if r == 0 && a.dir.is_some() {
        remember_name(fd as i32, true, &a.guest);
    }
    // Who bound an abstract name, beside its file.
    if r == 0 && src[..2] == 1u16.to_ne_bytes() && src.get(2) == Some(&0) {
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let _ = std::fs::write(abstract_file(&src[3..]).with_extension("owner"), me.to_ne_bytes());
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
                    // The node is its maker's ([`crate::owners`]).
                    let a = crate::creds::access();
                    let _ = crate::owners::keep_at(dir, &name, (a.fsuid, a.fsgid));
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

/// `listen(fd, backlog)`. Linux queues one connection more than the
/// backlog (and takes any past `net.core.somaxconn`, or negative, as that),
/// the host no more than it: the host is given one more.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn listen(fd: u64, backlog: u64) -> i64 {
    const SOMAXCONN: i32 = 4096;
    let b = backlog as i32;
    let b = if (0..=SOMAXCONN).contains(&b) { b } else { SOMAXCONN };
    // SAFETY: plain host call.
    ret(unsafe { libc::listen(fd as i32, b + 1) } as i64)
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
    // AF_UNSPEC: the connection, or a datagram socket's peer, undone.
    if addr != 0 && addrlen >= 2 {
        let fam: u16 = guest!(uaccess::read(addr));
        if fam == 0
            && let Some(r) = disconnect(fd as i32)
        {
            return r;
        }
    }
    let src = match guest_sockaddr(fd as i32, addr, addrlen, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut hb = empty_sockaddr();
    let a = match bytes_to_host(&src, &mut hb, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
        return err(e);
    }
    if let Err(e) = may_write_socket(&hb, &a) {
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
        let cap = guest!(name_room(addr, addrlen));
        let n = (cap as usize).min(name.len());
        guest!(uaccess::write_from(addr, &name[..n]));
        guest!(uaccess::write(addrlen, name.len() as u32));
        return 0;
    }
    crate::netns::to_guest(fd as i32, &mut hb, !peer);
    v4_view(fd as i32, &mut hb, &mut hl);
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
    // What the receiving socket's filter lets in: none, the data dropped as
    // if sent, or the first part.
    let sent = len;
    let len = match crate::bpf::filter_send(fd as i32, len) {
        Some(0) => return sent as i64,
        Some(keep) => keep,
        None => len,
    };
    if crate::netlink::is(fd as i32) {
        if crate::netlink::too_large(len) {
            return err(errno::EMSGSIZE);
        }
        let data = guest!(uaccess::read_bytes(buf, len as usize));
        return crate::netlink::send(fd as i32, &data);
    }
    // The address is taken first, as Linux takes it: a length past a
    // `sockaddr_storage` or negative is refused, then its bytes read.
    if addr != 0 {
        let l = addrlen as i32;
        if !(0..=128).contains(&l) {
            return err(errno::EINVAL);
        }
        guest!(uaccess::read_bytes(addr, l as usize));
    }
    // TCP sends to its peer, whatever address it is given.
    let named = addr != 0 && addrlen != 0 && !ip_stream(fd as i32);
    let hflags = msg_flags_to_host(flags);
    let mut hb = empty_sockaddr();
    // A Unix path too long for the host is sent to from its directory.
    let mut dir = None;
    let (aptr, alen) = if named {
        // SAFETY: the caller guarantees the sockaddr spans addrlen.
        match unsafe { to_host(addr, addrlen, &mut hb, true) } {
            Ok(a) => {
                if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
                    return err(e);
                }
                dir = a.dir;
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
    let mut iov = [guest!(uaccess::host_buffer(buf, len, false))];
    let mut hmsg = libc::msghdr {
        msg_name: aptr as *mut libc::c_void,
        msg_namelen: alen,
        msg_iov: iov.as_mut_ptr(),
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    // ENAMETOOLONG where the host cannot send from a directory.
    let mut r = err(errno::ENAMETOOLONG);
    in_dir(dir.as_ref(), || {
        // SAFETY: `hmsg` references the guest buffer and the local name.
        r = unsafe { send_corked(fd as i32, &mut hmsg, flags, hflags) };
        0
    });
    r
}

/// Bytes `MSG_MORE` held back, by IP socket.
static CORKED: std::sync::Mutex<Option<std::collections::HashMap<i32, Vec<u8>>>> =
    std::sync::Mutex::new(None);

/// Whether any socket has bytes held back.
static ANY_CORKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether `fd` has bytes `MSG_MORE` held back.
pub fn corked(fd: i32) -> bool {
    ANY_CORKED.load(std::sync::atomic::Ordering::Relaxed)
        && CORKED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|m| m.contains_key(&fd))
}

/// The bytes held back for `fd`, taken.
fn take_corked(fd: i32) -> Option<Vec<u8>> {
    if !ANY_CORKED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    CORKED.lock().unwrap_or_else(|e| e.into_inner()).as_mut()?.remove(&fd)
}

/// The multicast groups TCP sockets joined: (socket, group and
/// interface as the host lays them out).
static MEMBERSHIPS: std::sync::Mutex<Vec<(i32, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

/// A multicast group joined or left on a TCP socket, which Linux allows
/// (no multicast reaches one) and the host refuses: kept by fwe. Joining
/// one joined is `EADDRINUSE`, leaving one not joined `EADDRNOTAVAIL`.
/// `None` for any other socket or option.
fn stream_membership(fd: i32, level: u64, name: u64, form: Form, host: &[u8]) -> Option<i64> {
    let group = match form {
        Form::Mreq | Form::GroupReq => host.to_vec(),
        // The group and interface, without the source.
        Form::MreqSource => [&host[..4], &host[8..12]].concat(),
        Form::GroupSourceReq => host[..132].to_vec(),
        _ => return None,
    };
    if !(level == 0 || level == 41) || !ip_stream(fd) {
        return None;
    }
    // IP_ADD_MEMBERSHIP, IP_ADD_SOURCE_MEMBERSHIP, MCAST_JOIN_GROUP,
    // MCAST_JOIN_SOURCE_GROUP; the leaves; the rest need the group joined.
    let join = matches!(name, 35 | 39 | 42 | 46);
    let leave = matches!(name, 36 | 40 | 45 | 47);
    let mut m = MEMBERSHIPS.lock().unwrap_or_else(|e| e.into_inner());
    let at = m.iter().position(|(f, g)| *f == fd && *g == group);
    Some(match (at, join, leave) {
        (Some(_), true, _) => err(errno::EADDRINUSE),
        (None, true, _) => {
            m.push((fd, group));
            0
        }
        (Some(i), _, true) => {
            m.remove(i);
            0
        }
        (Some(_), ..) => 0,
        (None, ..) => err(errno::EADDRNOTAVAIL),
    })
}

/// Socket `fd` was closed: what it held back goes out, as Linux sends it,
/// and the groups it joined are left.
pub fn closed(fd: i32) {
    MEMBERSHIPS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(f, _)| *f != fd);
    KEPT_VALUES.lock().unwrap_or_else(|e| e.into_inner()).retain(|k| k.0 != fd);
    V4_VIEW.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
    if let Some(held) = take_corked(fd) {
        // SAFETY: a local buffer of its length; the send does not wait.
        unsafe { libc::send(fd, held.as_ptr().cast(), held.len(), libc::MSG_DONTWAIT) };
    }
}

/// Send `msg` on `fd` with the guest's `flags` (the host's `hflags`), as
/// Linux's `MSG_MORE` has it, which the host has not: on a TCP or UDP
/// socket, data sent with it is held back, and goes with the next send
/// without it, as one segment or datagram.
///
/// # Safety
/// `msg` must reference valid buffers.
unsafe fn send_corked(fd: i32, msg: &mut libc::msghdr, flags: u64, hflags: i32) -> i64 {
    #[allow(clippy::unnecessary_cast)] // `msg_iovlen` is an `int` on macOS
    // SAFETY: the caller's guarantee.
    let iov = unsafe { std::slice::from_raw_parts(msg.msg_iov, msg.msg_iovlen as usize) };
    if flags & MSG_MORE != 0
        && matches!(
            kind(fd),
            Some((libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_DGRAM))
        )
    {
        let mut more = Vec::new();
        for v in iov {
            // SAFETY: the iovecs are checked host buffers.
            more.extend_from_slice(unsafe {
                std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
            });
        }
        let n = more.len() as i64;
        let mut m = CORKED.lock().unwrap_or_else(|e| e.into_inner());
        m.get_or_insert_with(Default::default).entry(fd).or_default().extend(more);
        ANY_CORKED.store(true, std::sync::atomic::Ordering::Relaxed);
        return n;
    }
    let Some(held) = take_corked(fd) else {
        // SAFETY: the caller's guarantee.
        return ret(unsafe { libc::sendmsg(fd, msg, hflags) } as i64);
    };
    let mut all = vec![libc::iovec { iov_base: held.as_ptr() as *mut _, iov_len: held.len() }];
    all.extend_from_slice(iov);
    msg.msg_iov = all.as_mut_ptr();
    msg.msg_iovlen = all.len() as _;
    // SAFETY: the caller's buffers, and the held bytes.
    let r = ret(unsafe { libc::sendmsg(fd, msg, hflags) } as i64);
    let h = held.len() as i64;
    if r < h {
        // What did not go is held still.
        let sent = r.max(0) as usize;
        let mut m = CORKED.lock().unwrap_or_else(|e| e.into_inner());
        m.get_or_insert_with(Default::default).insert(fd, held[sent..].to_vec());
        return if r < 0 { r } else { 0 };
    }
    r - h
}

/// `recvfrom(fd, buf, len, flags, addr, addrlen)`.
///
/// # Safety
/// `buf` spans `len` writable bytes; `addr`/`addrlen`, if non-null, writable.
pub unsafe fn recvfrom(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
    if let Some(e) = errqueue_empty(fd as i32, flags) {
        return e;
    }
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
/// Socket `fd`'s host family and type (`None` if it is not a socket).
fn kind(fd: i32) -> Option<(i32, i32)> {
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    let mut ty: i32 = 0;
    let mut tl = size_of::<i32>() as libc::socklen_t;
    // SAFETY: valid out-parameters of their lengths.
    let ok = unsafe {
        libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) == 0
            && libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&raw mut ty).cast(), &mut tl)
                == 0
    };
    ok.then(|| (family(&hb), ty))
}

/// Whether `fd` is a TCP socket (an IP stream socket).
fn ip_stream(fd: i32) -> bool {
    matches!(kind(fd), Some((libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM)))
}

/// A send's result as Linux gives it: a TCP socket that was never
/// connected has its pipe broken (`EPIPE`, and so `SIGPIPE`), where the
/// host says it is not connected.
pub fn linux_send_error(nr: u64, fd: i32, r: i64) -> i64 {
    use fwe_abi::nr as n;
    let sends = matches!(nr, n::WRITE | n::WRITEV | n::SENDTO | n::SENDMSG | n::SENDFILE);
    if sends && r == err(errno::ENOTCONN) && ip_stream(fd) {
        return err(errno::EPIPE);
    }
    // A full socket buffer the host calls out of buffers: Linux's `EAGAIN`
    // for a socket that does not wait.
    if sends && r == err(errno::ENOBUFS) {
        // SAFETY: F_GETFL only queries the descriptor.
        if unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0 {
            return err(errno::EAGAIN);
        }
    }
    r
}

/// The guest `sockaddr` at `addr` for a `bind` (`bind`) or `connect` of
/// socket `fd`, checked as Linux checks it against the socket's family: an
/// IPv4 socket's is a `sockaddr_in` (`EINVAL` shorter, `EAFNOSUPPORT` of
/// another family, but for `bind`'s `AF_UNSPEC` wildcard, an IPv4 one to
/// Linux); an IPv6 socket's a `sockaddr_in6` of 24 bytes at least, but for
/// an IPv4 peer of a datagram socket, which is its IPv4-mapped address; a
/// Unix socket's of `AF_UNIX` (`EINVAL`). For anything not a socket the
/// address is as given, for the host to refuse the call.
fn guest_sockaddr(fd: i32, addr: u64, addrlen: u64, bind: bool) -> Result<Vec<u8>, i64> {
    if addr == 0 || addrlen < 2 || addrlen > SOCKADDR_MAX as u64 {
        return Err(err(errno::EINVAL));
    }
    let mut src = uaccess::read_bytes(addr, addrlen as usize).map_err(err)?;
    let Some((fam, ty)) = kind(fd) else { return Ok(src) };
    let gf = u16::from_ne_bytes([src[0], src[1]]) as u64;
    match fam {
        libc::AF_INET => {
            if src.len() < 16 {
                return Err(err(errno::EINVAL));
            }
            if gf != AF_INET {
                if !(bind && gf == 0 && src[4..8] == [0; 4]) {
                    return Err(err(errno::EAFNOSUPPORT));
                }
                src[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            }
        }
        libc::AF_INET6 if gf == AF_INET && !bind && ty == libc::SOCK_DGRAM => {
            if src.len() < 16 {
                return Err(err(errno::EINVAL));
            }
            let mut m = vec![0u8; 28];
            m[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            m[2..4].copy_from_slice(&src[2..4]);
            m[18..20].copy_from_slice(&[0xff, 0xff]);
            m[20..24].copy_from_slice(&src[4..8]);
            src = m;
        }
        libc::AF_INET6 => {
            if src.len() < 24 {
                return Err(err(errno::EINVAL));
            }
            if gf != AF_INET6 {
                return Err(err(errno::EAFNOSUPPORT));
            }
        }
        libc::AF_UNIX if gf != AF_UNIX => return Err(err(errno::EINVAL)),
        _ => {}
    }
    Ok(src)
}

/// `connect` of socket `fd` to `AF_UNSPEC`, as Linux takes it: a datagram
/// socket's peer is forgotten (the host does so, and reports an error); a
/// TCP socket's connection is dropped and the socket is new again, which
/// the host has no call for: a new socket of the family takes its place,
/// the old one reset. `None` for a socket of another kind, whose call goes
/// on to be refused.
fn disconnect(fd: i32) -> Option<i64> {
    let (fam, ty) = kind(fd)?;
    if ty == libc::SOCK_DGRAM {
        let mut unspec = empty_sockaddr();
        // macOS's header starts with its length; Linux's family is 0 either way.
        unspec[0] = if cfg!(target_os = "linux") { 0 } else { 16 };
        // SAFETY: a valid host sockaddr of 16 bytes.
        unsafe { libc::connect(fd, unspec.as_ptr().cast(), 16) };
        return Some(0);
    }
    if ty != libc::SOCK_STREAM || !matches!(fam, libc::AF_INET | libc::AF_INET6) {
        return None;
    }
    // One IPv6 socket that `IPV6_ADDRFORM` made IPv4 is IPv4 from now on.
    let fam = if V4_VIEW.lock().unwrap_or_else(|e| e.into_inner()).contains(&fd) {
        libc::AF_INET
    } else {
        fam
    };
    // SAFETY: plain host calls; `new` is a fresh socket this owns until it
    // takes `fd`'s place.
    unsafe {
        let new = libc::socket(fam, libc::SOCK_STREAM, 0);
        if new < 0 {
            return Some(last_error());
        }
        apply_sock_flags(new, 0);
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(new, libc::F_SETFL, fl & libc::O_NONBLOCK | libc::fcntl(new, libc::F_GETFL));
        let fdfl = libc::fcntl(fd, libc::F_GETFD);
        // The connection is reset, as Linux's disconnect resets it.
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        );
        if libc::dup2(new, fd) < 0 {
            let e = last_error();
            libc::close(new);
            return Some(e);
        }
        libc::fcntl(fd, libc::F_SETFD, fdfl);
        libc::close(new);
    }
    V4_VIEW.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
    take_corked(fd);
    MEMBERSHIPS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(f, _)| *f != fd);
    Some(0)
}

/// Socket options Linux has and the host has not, which change nothing
/// fwe does: kept, and read back as set (`SO_NO_CHECK`, `SO_PRIORITY`,
/// `SO_PASSCRED`).
const KEPT: [u64; 3] = [11, 12, 16];

/// The values of [`KEPT`] options set: (socket, option, value).
static KEPT_VALUES: std::sync::Mutex<Vec<(i32, u64, i32)>> = std::sync::Mutex::new(Vec::new());

/// IPv6 sockets `IPV6_ADDRFORM` made IPv4: the host's socket stays IPv6,
/// its names are reported as the IPv4 ones they map.
static V4_VIEW: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// `IPV6_ADDRFORM` (`optval` `AF_INET`) of socket `fd`, as Linux allows
/// it: a TCP or UDP IPv6 socket whose peer is IPv4 (an IPv4-mapped address)
/// becomes an IPv4 socket.
fn addrform(fd: i32, optval: u64, optlen: u64) -> i64 {
    if optlen < 4 {
        return err(errno::EINVAL);
    }
    let val: i32 = guest!(uaccess::read(optval));
    if val as u64 != AF_INET {
        return err(errno::EINVAL);
    }
    let Some((libc::AF_INET6, ty)) = kind(fd) else {
        return err(errno::EINVAL);
    };
    if !matches!(ty, libc::SOCK_STREAM | libc::SOCK_DGRAM) {
        return err(errno::ENOPROTOOPT);
    }
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters of their lengths.
    if unsafe { libc::getpeername(fd, hb.as_mut_ptr().cast(), &mut hl) } != 0 {
        return if ty == libc::SOCK_STREAM {
            err(errno::ENOTCONN)
        } else {
            err(errno::EADDRNOTAVAIL)
        };
    }
    // The address, at 8 in either host's `sockaddr_in6`, IPv4-mapped.
    if hb[8..18] != [0; 10] || hb[18..20] != [0xff, 0xff] {
        return err(errno::EADDRNOTAVAIL);
    }
    V4_VIEW.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
    0
}

/// The host name `hb` (of `hl` bytes) of an IPv6 socket `IPV6_ADDRFORM`
/// made IPv4, as that: the IPv4 address its IPv4-mapped one stands for.
fn v4_view(fd: i32, hb: &mut [u8; SOCKADDR_MAX], hl: &mut libc::socklen_t) {
    if family(hb) != libc::AF_INET6
        || !V4_VIEW.lock().unwrap_or_else(|e| e.into_inner()).contains(&fd)
    {
        return;
    }
    let mut v4 = empty_sockaddr();
    #[cfg(target_os = "linux")]
    v4[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    #[cfg(not(target_os = "linux"))]
    {
        v4[0] = 16;
        v4[1] = libc::AF_INET as u8;
    }
    v4[2..4].copy_from_slice(&hb[2..4]);
    v4[4..8].copy_from_slice(&hb[20..24]);
    *hb = v4;
    *hl = 16;
}

/// The error Linux gives for an option at `level` of socket `fd` when the
/// socket has no layer of that level (a Unix socket has only its own
/// `SOL_SOCKET`; an IP socket its IP version's, its transport's, and a raw
/// one any): `EOPNOTSUPP` to get it, `ENOPROTOOPT` to set it on an IP
/// socket. `None` if the socket has the level, or is not a socket.
fn level_refused(fd: i32, level: u64, get: bool) -> Option<i64> {
    if level == SOL_SOCKET || crate::netlink::is(fd) {
        return None;
    }
    let (fam, ty) = kind(fd)?;
    let transport = match ty {
        libc::SOCK_STREAM => level == 6,
        libc::SOCK_DGRAM => level == 17 || level == 136,
        _ => true,
    };
    let has = match fam {
        libc::AF_INET => level == 0 || transport,
        libc::AF_INET6 => level == 0 || level == 41 || transport,
        libc::AF_UNIX => false,
        _ => return None,
    };
    if has {
        None
    } else if get || fam == libc::AF_UNIX {
        Some(err(errno::EOPNOTSUPP))
    } else {
        Some(err(errno::ENOPROTOOPT))
    }
}

/// The host's level and name for Linux socket option `optname` at
/// `level`, and its value's layout ([`crate::sockopt`]).
fn opt_to_host(level: u64, optname: u64) -> Result<(i32, i32, Form), i64> {
    #[cfg(target_os = "linux")]
    {
        Ok((level as i32, optname as i32, Form::Same))
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
                // SO_DEBUG, SO_RCVLOWAT
                1 => libc::SO_DEBUG,
                18 => libc::SO_RCVLOWAT,
                _ => return Err(err(errno::ENOPROTOOPT)),
            };
            return Ok((libc::SOL_SOCKET, o, Form::Same));
        }
        crate::sockopt::to_host(level, optname).map_err(err)
    }
}

/// `SO_ATTACH_BPF` and `SO_DETACH_BPF` (also `SO_DETACH_FILTER`).
const SO_ATTACH_BPF: u64 = 50;
const SO_DETACH_BPF: u64 = 27;

/// `setsockopt`.
///
/// # Safety
/// `optval` spans `optlen` readable bytes.
pub unsafe fn setsockopt(
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
    admin: bool,
) -> i64 {
    if (optlen as i32) < 0 {
        return err(errno::EINVAL);
    }
    if level == SOL_SOCKET && matches!(optname, SO_SNDBUF | SO_RCVBUF | 32 | 33) {
        return buffer_size(fd as i32, optname, optval, optlen, admin);
    }
    // IPPROTO_IPV6, IPV6_ADDRFORM
    if level == 41 && optname == 1 {
        return addrform(fd as i32, optval, optlen);
    }
    // An eBPF socket filter, attached or taken off ([`crate::bpf`]).
    if level == SOL_SOCKET && matches!(optname, SO_ATTACH_BPF | SO_DETACH_BPF) {
        let prog = if optname == SO_ATTACH_BPF {
            if optlen < 4 {
                return err(errno::EINVAL);
            }
            Some(guest!(uaccess::read::<i32>(optval)))
        } else {
            None
        };
        return match crate::bpf::attach_socket(fd as i32, prog) {
            Ok(()) => 0,
            Err(e) => err(e),
        };
    }
    if level == SOL_SOCKET && KEPT.contains(&optname) {
        if optlen < 4 {
            return err(errno::EINVAL);
        }
        let v: i32 = guest!(uaccess::read(optval));
        if let Err(e) = socket_fd(fd as i32) {
            return e;
        }
        let mut k = KEPT_VALUES.lock().unwrap_or_else(|e| e.into_inner());
        k.retain(|&(f, o, _)| (f, o) != (fd as i32, optname));
        k.push((fd as i32, optname, v));
        return 0;
    }
    if let Some(e) = level_refused(fd as i32, level, false) {
        return e;
    }
    let (hl, ho, form) = match opt_to_host(level, optname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if form != Form::Same {
        let val = guest!(uaccess::read_bytes(optval, optlen as usize));
        let host = guest!(crate::sockopt::value_to_host(form, &val));
        if let Some(r) = stream_membership(fd as i32, level, optname, form, &host) {
            return r;
        }
        // SAFETY: a local buffer of its length.
        return ret(unsafe {
            libc::setsockopt(fd as i32, hl, ho, host.as_ptr().cast(), host.len() as libc::socklen_t)
                as i64
        });
    }
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
    if let Some(e) = level_refused(fd as i32, level, true) {
        return e;
    }
    // The length is the caller's, checked as Linux checks it before the
    // host sees the buffer.
    let len: i32 = guest!(uaccess::read(optlen));
    if len < 0 {
        return err(errno::EINVAL);
    }
    if optval == 0 && len > 0 {
        return err(errno::EFAULT);
    }
    if level == SOL_SOCKET && (KEPT.contains(&optname) || matches!(optname, 38 | 39)) {
        let Some((fam, ty)) = kind(fd as i32) else {
            return socket_fd(fd as i32).err().unwrap_or(err(errno::ENOTSOCK));
        };
        let v = match optname {
            // SO_PROTOCOL: what the socket was made with, as Linux names it.
            38 => match (fam, ty) {
                (libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM) => 6,
                (libc::AF_INET | libc::AF_INET6, libc::SOCK_DGRAM) => 17,
                _ => 0,
            },
            // SO_DOMAIN
            39 => match fam {
                libc::AF_INET6 => AF_INET6 as i32,
                f => f,
            },
            _ => KEPT_VALUES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .find(|&&(f, o, _)| (f, o) == (fd as i32, optname))
                .map_or(0, |k| k.2),
        };
        let n = (len as usize).min(4);
        guest!(uaccess::write_from(optval, &v.to_ne_bytes()[..n]));
        guest!(uaccess::write(optlen, n as u32));
        return 0;
    }
    let (hl, ho, form) = match opt_to_host(level, optname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if form != Form::Same {
        let mut host = [0u8; 264];
        let mut hlen = host.len() as libc::socklen_t;
        // SAFETY: a local buffer of its length.
        let r = unsafe { libc::getsockopt(fd as i32, hl, ho, host.as_mut_ptr().cast(), &mut hlen) };
        if r < 0 {
            return last_error();
        }
        let linux = crate::sockopt::value_to_linux(form, &host[..hlen as usize], len as usize);
        let n = linux.len().min(len as usize);
        guest!(uaccess::write_from(optval, &linux[..n]));
        guest!(uaccess::write(optlen, n as u32));
        return 0;
    }
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

/// A message's buffers ([`uaccess::host_iovecs`]): more than `UIO_MAXIOV`
/// is too big a message (`EMSGSIZE`), as Linux has it.
fn msg_iovecs(iov: u64, count: u64, write: bool) -> uaccess::Result<Vec<libc::iovec>> {
    if count > 1024 {
        return Err(errno::EMSGSIZE);
    }
    uaccess::host_iovecs(iov, count, write)
}

/// A read of an IP socket's error queue (`MSG_ERRQUEUE`), which fwe never
/// fills (the host has none): empty, `EAGAIN`, as Linux reports one.
fn errqueue_empty(fd: i32, flags: u64) -> Option<i64> {
    if flags & MSG_ERRQUEUE == 0 {
        return None;
    }
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters of their lengths.
    let named = unsafe { libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) } == 0;
    (named && matches!(family(&hb), libc::AF_INET | libc::AF_INET6)).then(|| err(errno::EAGAIN))
}

/// Guest `msghdr` fields (64-bit Linux layout): name, namelen, iov,
/// iovlen, control, controllen.
/// A negative name length is refused (`EINVAL`), as Linux refuses it.
fn read_msghdr(msg: u64) -> uaccess::Result<(u64, u32, u64, u64, u64, u64)> {
    let w: [u64; 6] = uaccess::read(msg)?;
    if (w[1] as i32) < 0 {
        return Err(errno::EINVAL);
    }
    Ok((w[0], w[1] as u32, w[2], w[3], w[4], w[5]))
}

/// `MSG_CMSG_COMPAT`, which only the kernel's 32-bit entry points set:
/// refused from a 64-bit caller.
const MSG_CMSG_COMPAT: u64 = 0x8000_0000;

/// `sendmsg(fd, msg, flags)`.
///
/// # Safety
/// `msg` must point to a valid `msghdr`.
pub unsafe fn sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    if flags as u32 as u64 & MSG_CMSG_COMPAT != 0 {
        return err(errno::EINVAL);
    }
    // The descriptor is looked at before the message, as Linux looks
    // (the host looks at the message first).
    if let Err(e) = socket_fd(fd as i32) {
        return e;
    }
    let (name, namelen, iov, iovlen, control, controllen) = guest!(read_msghdr(msg));
    let mut hiov = guest!(msg_iovecs(iov, iovlen, false));
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
    // A Unix path too long for the host is sent to from its directory.
    let mut dir = None;
    let (name_ptr, name_len) = if name != 0 && namelen != 0 {
        // SAFETY: the caller guarantees the name spans namelen.
        match unsafe { to_host(name, namelen as u64, &mut hb, true) } {
            Ok(a) => {
                if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
                    return err(e);
                }
                dir = a.dir;
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
    let mut hmsg = hmsg;
    // ENAMETOOLONG where the host cannot send from a directory.
    let mut r = err(errno::ENAMETOOLONG);
    in_dir(dir.as_ref(), || {
        // SAFETY: `hmsg` references guest iov and local name/control buffers.
        r = unsafe { send_corked(fd as i32, &mut hmsg, flags, msg_flags_to_host(flags)) };
        0
    });
    r
}

/// A `struct mmsghdr`: a `msghdr` and the length sent or received.
const MMSGHDR: u64 = 64;

/// `sendmmsg(fd, msgvec, vlen, flags)`: [`sendmsg`] of each message in
/// turn (at most `UIO_MAXIOV`), each one's length written after it, until
/// one fails: how many went, or the error if none did.
///
/// # Safety
/// As for [`sendmsg`], for each message.
pub unsafe fn sendmmsg(fd: u64, vec: u64, vlen: u64, flags: u64) -> i64 {
    if let Err(e) = socket_fd(fd as i32) {
        return e;
    }
    let mut sent = 0;
    for i in 0..vlen.min(1024) {
        let at = vec + i * MMSGHDR;
        // SAFETY: the caller's guarantee.
        let r = unsafe { sendmsg(fd, at, flags) };
        if r < 0 {
            return if sent > 0 { sent } else { r };
        }
        if let Err(e) = uaccess::write(at + 56, r as u32) {
            return if sent > 0 { sent } else { err(e) };
        }
        sent += 1;
    }
    sent
}

/// `recvmmsg(fd, msgvec, vlen, flags, timeout)`: [`recvmsg`] into each
/// message in turn, each one's length written after it, until one fails
/// (how many came, or the error if none did), `MSG_WAITFORONE` stops
/// waiting after the first, or the timeout, looked at after each message
/// as Linux looks at it, has passed. The timeout is checked first
/// (`EFAULT`, `EINVAL`).
///
/// # Safety
/// As for [`recvmsg`], for each message.
pub unsafe fn recvmmsg(fd: u64, vec: u64, vlen: u64, flags: u64, timeout: u64) -> i64 {
    let deadline = if timeout != 0 {
        let ts: fwe_abi::Timespec = guest!(uaccess::read(timeout));
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return err(errno::EINVAL);
        }
        let d = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        Some(std::time::Instant::now() + d)
    } else {
        None
    };
    if let Err(e) = socket_fd(fd as i32) {
        return e;
    }
    let mut flags = flags;
    let mut got = 0;
    for i in 0..vlen.min(1024) {
        let at = vec + i * MMSGHDR;
        // SAFETY: the caller's guarantee.
        let r = unsafe { recvmsg(fd, at, flags & !MSG_WAITFORONE) };
        if r < 0 {
            return if got > 0 { got } else { r };
        }
        if let Err(e) = uaccess::write(at + 56, r as u32) {
            return if got > 0 { got } else { err(e) };
        }
        got += 1;
        if flags & MSG_WAITFORONE != 0 {
            flags |= MSG_DONTWAIT;
        }
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            break;
        }
        // Urgent data ends the batch.
        let msg_flags: i32 = uaccess::read(at + 48).unwrap_or(0);
        if msg_flags as u64 & MSG_OOB != 0 {
            break;
        }
    }
    got
}

/// `SIOCATMARK` of socket `fd` into the guest's `int` at `arg`: whether
/// reading is at the urgent mark, which only TCP has (`ENOTTY` for
/// another socket, as Linux answers).
pub fn at_mark(fd: i32, arg: u64) -> i64 {
    if !ip_stream(fd) {
        return err(errno::ENOTTY);
    }
    let mut at: i32 = 0;
    // macOS's SIOCATMARK, _IOR('s', 7, int).
    #[cfg(not(target_os = "linux"))]
    let req = 0x4004_7307;
    #[cfg(target_os = "linux")]
    let req = 0x8905;
    // SAFETY: a valid out-parameter.
    if unsafe { libc::ioctl(fd, req, &mut at) } < 0 {
        return last_error();
    }
    guest!(uaccess::write(arg, at));
    0
}

/// `fd` is a socket: `EBADF` if it is not open, `ENOTSOCK` if it is
/// something else.
fn socket_fd(fd: i32) -> Result<(), i64> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if fd < 0 || !crate::fdtable::guest_visible(fd) || unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(err(errno::EBADF));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(err(errno::ENOTSOCK));
    }
    Ok(())
}

/// `recvmsg(fd, msg, flags)`.
///
/// # Safety
/// `msg` must point to a valid `msghdr` with writable `iov`/`name`.
pub unsafe fn recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    if flags as u32 as u64 & MSG_CMSG_COMPAT != 0 {
        return err(errno::EINVAL);
    }
    // The descriptor is looked at before the message, as Linux looks
    // (the host looks at the message first).
    if let Err(e) = socket_fd(fd as i32) {
        return e;
    }
    let (name, namelen, iov, iovlen, control, controllen) = guest!(read_msghdr(msg));
    let mut hiov = guest!(msg_iovecs(iov, iovlen, true));
    if let Some(e) = errqueue_empty(fd as i32, flags) {
        return e;
    }
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

    /// A guest `struct mmsghdr` of one buffer: the `msghdr` (no name or
    /// control), then the length.
    fn mmsghdr(iov: &libc::iovec) -> [u64; 8] {
        [0, 0, iov as *const _ as u64, 1, 0, 0, 0, 0]
    }

    #[test]
    fn messages_go_and_come_in_batches_and_more_holds_one_back() {
        // SAFETY: no pointers.
        let (rx, tx) = unsafe { (socket(AF_INET, SOCK_DGRAM, 0), socket(AF_INET, SOCK_DGRAM, 0)) };
        assert!(rx >= 0 && tx >= 0);
        let any = sockaddr_in_v4(0);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { bind(rx as u64, any.as_ptr() as u64, 16, true, 0o022) }, 0);
        let mut got = [0u8; 16];
        let mut len: u32 = 16;
        // SAFETY: writable out sockaddr and length.
        unsafe { getname(rx as u64, got.as_mut_ptr() as u64, (&raw mut len) as u64, false) };
        let dst = sockaddr_in_v4(u16::from_be_bytes([got[2], got[3]]));
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { connect(tx as u64, dst.as_ptr() as u64, 16) }, 0);

        // Held back, then sent with the next send as one datagram.
        let more = b"held-";
        // SAFETY: valid buffer.
        let r = unsafe { sendto(tx as u64, more.as_ptr() as u64, 5, MSG_MORE, 0, 0) };
        assert_eq!(r, 5);
        // Two messages in one call.
        let (a, b) = (*b"one", *b"two");
        let iov = [
            libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: 3 },
            libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: 3 },
        ];
        let mut out = [mmsghdr(&iov[0]), mmsghdr(&iov[1])];
        // SAFETY: two valid messages.
        assert_eq!(unsafe { sendmmsg(tx as u64, out.as_mut_ptr() as u64, 2, 0) }, 2);
        assert_eq!(out[0][7] as u32, 3, "the length sent is written after each");

        let mut bufs = [[0u8; 16]; 3];
        let riov: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 16 })
            .collect();
        let mut msgs = [mmsghdr(&riov[0]), mmsghdr(&riov[1]), mmsghdr(&riov[2])];
        // SAFETY: three valid messages; no timeout.
        let n = unsafe { recvmmsg(rx as u64, msgs.as_mut_ptr() as u64, 2, 0, 0) };
        assert_eq!(n, 2);
        assert_eq!(&bufs[0][..8], b"held-one");
        assert_eq!(msgs[0][7] as u32, 8);
        assert_eq!(&bufs[1][..3], b"two");
        // Nothing more is there, and a non-blocking batch does not wait.
        // SAFETY: as above.
        let r = unsafe { recvmmsg(rx as u64, msgs[2..].as_mut_ptr() as u64, 1, MSG_DONTWAIT, 0) };
        assert_eq!(r, err(errno::EAGAIN));
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
            setsockopt(srv as u64, SOL_SOCKET, SO_REUSEADDR, &one as *const _ as u64, 4, true);
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
