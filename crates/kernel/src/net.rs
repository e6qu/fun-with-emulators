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
//! - **`setsockopt` names and `send`/`recv` flags:** mapped individually
//!   ([`crate::sockopt`]); an option the host lacks is kept by fwe (the
//!   UDP level's, `UDP_CORK` and `UDP_SEGMENT` acted on) or refused, never
//!   passed on under its Linux number; `MSG_NOSIGNAL` becomes
//!   `SO_NOSIGPIPE` on the socket.
//! - **control messages:** the layout differs (`cmsg_len` is 64-bit on
//!   Linux, 32-bit on macOS), so descriptors and credentials are
//!   re-encoded, and what fwe keeps of a descriptor goes with it
//!   ([`crate::scm`]).
//!
//! `AF_UNIX` paths are rooted under the rootfs; abstract-namespace names (a
//! leading NUL) are mapped to files under a per-host temporary directory, since
//! macOS has no abstract namespace. A Unix socket bound with its family
//! alone, or passing credentials and connecting or sending unbound, is
//! given an abstract name as Linux's autobind gives one; a Unix `SOCK_RAW`
//! socket is a datagram one, as Linux makes it.
//!
//! A ping socket (ICMP datagrams) receives on macOS with the IP header
//! first, which Linux's does not give: fwe marks one as it is made
//! ([`crate::fdmarks::Mark::Ping`]) and strips the header from what it
//! receives.
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
/// names (`a`'s), which connecting or sending to it needs: as `open`
/// checks, the caller's file-system ids against the node's guest owner
/// and mode ([`crate::owners`], [`crate::modes`]), `EACCES` where they
/// deny it. Without a root filesystem, the host's own nodes (root's, no
/// owner kept) are left to the host's checks.
fn may_write_socket(hb: &[u8; SOCKADDR_MAX], a: &HostAddr) -> Result<(), i32> {
    if family(hb) != libc::AF_UNIX || hb[2] == 0 {
        return Ok(());
    }
    let access = crate::creds::access();
    // `CAP_DAC_OVERRIDE` passes every node, but in a user namespace of
    // fwe's only a node mapped there ([`crate::creds::Access::permits`]).
    if access.dac_override && !access.scoped {
        return Ok(());
    }
    use std::os::fd::AsRawFd;
    let end = hb[2..].iter().position(|&b| b == 0).map_or(hb.len(), |e| e + 2);
    // An abstract name's file is fwe's, of no guest permissions.
    use std::os::unix::ffi::OsStrExt;
    if a.dir.is_none() && hb[2..end].starts_with(abstract_dir().as_os_str().as_bytes()) {
        return Ok(());
    }
    let Ok(name) = std::ffi::CString::new(&hb[2..end]) else { return Ok(()) };
    let dir = a.dir.as_ref().map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated name, relative to a live directory.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Ok(());
    }
    let perm = crate::modes::guest_perm_at(dir, &name, &st);
    let owner = crate::owners::of_at(dir, &name, &st);
    crate::modes::apply(&mut st, perm);
    crate::owners::apply(&mut st, owner);
    if owner == (0, 0) && crate::fs::root_is_host() {
        return Ok(());
    }
    if access.permits(&st, 2) { Ok(()) } else { Err(errno::EACCES) }
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
pub(crate) fn check_socket(domain: u64, type_: u64, protocol: u64) -> Result<libc::c_int, i64> {
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
    // A Unix `SOCK_RAW` socket is a datagram one, as Linux's `unix_create`
    // makes it.
    if dom == libc::AF_UNIX && base == SOCK_RAW as i32 {
        base = libc::SOCK_DGRAM;
    }
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
    #[cfg(target_os = "macos")]
    if dom == libc::AF_INET && base == libc::SOCK_DGRAM && protocol == 1 {
        crate::fdmarks::mark(fd, crate::fdmarks::Mark::Ping);
    }
    crate::netns::made(fd);
    fresh(fd);
    socket_made(fd, Some(own_ids()));
    fd as i64
}

/// A descriptor received from another process (`SCM_RIGHTS`,
/// `pidfd_getfd`): a socket standing in for a kind the host lacks is
/// marked as one here too.
pub fn adopt(fd: i32) {
    if kind(fd).is_some() {
        socket_made(fd, None);
    }
    // A SOCK_SEQPACKET socket of fwe's.
    crate::seqpacket::adopt(fd);
    // A ping socket, whose receives come with the IP header on macOS.
    #[cfg(target_os = "macos")]
    if kind(fd) == Some((libc::AF_INET, libc::SOCK_DGRAM))
        && crate::host::socket_protocol(fd) == Some(1)
    {
        crate::fdmarks::mark(fd, crate::fdmarks::Mark::Ping);
    }
}

/// The length of the IP header ICMP datagram `d` received on a macOS ping
/// socket starts with (0 if it has none: an IPv4 header's version and
/// length, in its first byte, say).
fn ip_header_len(d: &[u8]) -> usize {
    match d.first() {
        Some(&b) if b >> 4 == 4 && usize::from(b & 0xf) * 4 >= 20 => {
            (usize::from(b & 0xf) * 4).min(d.len())
        }
        _ => 0,
    }
}

/// A receive on ping socket `fd` into the host message `hmsg` (the host
/// flags `hflags`), as Linux delivers it: the ICMP message, without the IP
/// header macOS puts before it, cut to the buffers (`MSG_TRUNC` set when
/// it is), its whole length returned when the guest asked with `MSG_TRUNC`
/// (`whole`). Received whole into a buffer of fwe's, then copied to the
/// message's buffers (translated guest buffers: a fault there is `EFAULT`).
///
/// # Safety
/// `hmsg`'s name and control buffers must be valid for writing, and its
/// `msg_iov` must point to `msg_iovlen` iovecs.
unsafe fn ping_recvmsg(fd: i32, hmsg: &mut libc::msghdr, hflags: i32, whole: bool) -> i64 {
    // The largest IP datagram.
    let mut d = vec![0u8; 65536];
    let mut iov = libc::iovec { iov_base: d.as_mut_ptr().cast(), iov_len: d.len() };
    let (to, count) = (hmsg.msg_iov, hmsg.msg_iovlen);
    hmsg.msg_iov = &mut iov;
    hmsg.msg_iovlen = 1;
    // SAFETY: the caller's guarantee for name and control; a local buffer.
    let n = unsafe { libc::recvmsg(fd, hmsg, hflags & !libc::MSG_TRUNC) };
    hmsg.msg_iov = to;
    hmsg.msg_iovlen = count;
    if n < 0 {
        return last_error();
    }
    let got = &d[..n as usize];
    let icmp = &got[ip_header_len(got)..];
    #[allow(clippy::unnecessary_cast)] // `msg_iovlen` is an `int` on macOS
    // SAFETY: the caller's guarantee: `count` iovecs at `to`.
    let bufs = unsafe { std::slice::from_raw_parts(to, count as usize) };
    let mut done = 0;
    for b in bufs {
        let k = b.iov_len.min(icmp.len() - done);
        if let Err(e) = uaccess::write_host(b.iov_base as u64, &icmp[done..done + k]) {
            return err(e);
        }
        done += k;
    }
    if done < icmp.len() {
        hmsg.msg_flags |= libc::MSG_TRUNC;
    }
    if whole { icmp.len() as i64 } else { done as i64 }
}

/// `read` or `readv` of ping socket `fd` ([`crate::fdmarks::is_ping`])
/// into translated guest buffers `iov` ([`ping_recvmsg`]).
pub fn ping_read(fd: i32, iov: &[libc::iovec]) -> i64 {
    // SAFETY: an all-zero `msghdr` is valid: no name, no control.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = iov.as_ptr().cast_mut();
    m.msg_iovlen = iov.len() as _;
    // SAFETY: no name or control; the iovecs given.
    unsafe { ping_recvmsg(fd, &mut m, 0, false) }
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
    // A Unix `SOCK_RAW` socket is a datagram one, as Linux's `unix_create`
    // makes it.
    if dom == libc::AF_UNIX && base == SOCK_RAW as i32 {
        base = libc::SOCK_DGRAM;
    }
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
    crate::netns::made(fds[0]);
    crate::netns::made(fds[1]);
    fresh(fds[0]);
    fresh(fds[1]);
    socket_made(fds[0], Some(own_ids()));
    socket_made(fds[1], Some(own_ids()));
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
    // A Unix socket given its family alone takes a name of the kernel's
    // choosing, as Linux's `unix_bind` has it.
    if src.len() == 2 && src[..2] == (AF_UNIX as u16).to_ne_bytes() && is_unix(fd as i32) {
        return autobind(fd as i32);
    }
    bind_name(fd, src, may_low, umask)
}

/// Unix socket `fd` bound, unless it is bound already, to an abstract name
/// of five hexadecimal digits, as Linux's `unix_autobind` names one: from a
/// random start, the next free one; `ENOSPC` when none is.
fn autobind(fd: i32) -> i64 {
    if unix_bound(fd) {
        return 0;
    }
    let mut start = [0u8; 4];
    crate::host::fill_random(&mut start);
    let mut n = u32::from_ne_bytes(start) & 0xfffff;
    for _ in 0..=0xfffff {
        let mut src = (AF_UNIX as u16).to_ne_bytes().to_vec();
        src.push(0);
        src.extend_from_slice(autobind_name(n).as_bytes());
        let r = bind_name(fd as u64, src, false, 0);
        if r != err(errno::EADDRINUSE) {
            return r;
        }
        n = (n + 1) & 0xfffff;
    }
    err(errno::ENOSPC)
}

/// The abstract name (after its leading NUL) [`autobind`] gives for `n`.
fn autobind_name(n: u32) -> String {
    format!("{n:05x}")
}

/// Whether Unix socket `fd` has a name.
fn unix_bound(fd: i32) -> bool {
    let mut hb = empty_sockaddr();
    let mut hl: libc::socklen_t = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters.
    let r = unsafe { libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) };
    r == 0 && hl as usize > 2 && hb[2] != 0
}

/// A Unix socket that passes credentials (`SO_PASSCRED`) and has no name
/// is given one before it connects, or before a datagram one sends
/// (`datagram`), as Linux's `unix_stream_connect`, `unix_dgram_connect`
/// and `unix_dgram_sendmsg` give it, so that its peer can tell who sent.
fn autobind_to_pass_creds(fd: i32, datagram: bool) -> Result<(), i64> {
    if kept_value(fd, SO_PASSCRED) == 0 {
        return Ok(());
    }
    let unix = match kind(fd) {
        Some((libc::AF_UNIX, ty)) => !datagram || ty == libc::SOCK_DGRAM,
        _ => false,
    };
    if !unix || crate::netlink::is(fd) {
        return Ok(());
    }
    match autobind(fd) {
        r if r < 0 => Err(r),
        _ => Ok(()),
    }
}

/// [`bind`] of socket `fd` to Linux socket address `src`.
fn bind_name(fd: u64, src: Vec<u8>, may_low: bool, umask: u32) -> i64 {
    let mut hb = empty_sockaddr();
    let a = match bytes_to_host(&src, &mut hb, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // A port below `net.ipv4.ip_unprivileged_port_start` is the
    // privileged's (the host lets anyone have one on the wildcard address;
    // on a loopback one, `netns` maps it); a ping socket's is its ICMP
    // identifier, anyone's.
    if !may_low
        && !crate::fdmarks::is_ping(fd as i32)
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
        let me = crate::host::pid();
        let _ = std::fs::write(abstract_file(&src[3..]).with_extension("owner"), me.to_ne_bytes());
    }
    if r == 0
        && let Some(plan) = plan
    {
        crate::netns::bind_done(fd as i32, plan);
    }
    #[cfg(not(target_os = "linux"))]
    if r == 0 && kept_value(fd as i32, SO_PASSCRED) != 0 {
        passcred_bound(fd as i32, true);
    }
    if r == 0 && family(&hb) == libc::AF_UNIX && a.len > 2 && hb[2] != 0 {
        // The node takes the socket's mode (its `fchmod`, or every bit),
        // less the umask, as on Linux.
        let mode = socket_inode(fd as i32).map_or(0o777, |s| s.perm) & !umask;
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

/// What Linux keeps on a socket's own inode that the host keeps nowhere:
/// its owner and its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketInode {
    /// The file-system ids of the process that made it (initial-namespace
    /// ids), or none for one this process did not make (received).
    pub owner: Option<(u32, u32)>,
    /// Its permission bits: every one until an `fchmod`, which a node
    /// bound for it is made with (less the umask).
    pub perm: u32,
}

/// [`SocketInode`]s by the host socket's inode number, which every
/// descriptor of the socket shares; a socket made, accepted or received
/// with a number another had starts afresh.
pub(crate) static SOCKETS: std::sync::Mutex<Vec<(u64, SocketInode)>> =
    std::sync::Mutex::new(Vec::new());

fn inode(fd: i32) -> Option<u64> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino as u64)
}

/// Socket `fd` was made or accepted by this process, as its file-system
/// ids are now: its owner. A received one (`owner` none) has the host's.
fn socket_made(fd: i32, owner: Option<(u32, u32)>) {
    let Some(ino) = inode(fd) else { return };
    let mut m = SOCKETS.lock().unwrap_or_else(|e| e.into_inner());
    // Those of sockets gone: none is open here with its number now.
    if m.len() >= 64 && m.len().is_power_of_two() {
        let open: std::collections::HashSet<u64> =
            crate::fdtable::open_fds().into_iter().filter_map(inode).collect();
        m.retain(|(n, _)| open.contains(n));
    }
    m.retain(|&(n, _)| n != ino);
    m.push((ino, SocketInode { owner, perm: 0o777 }));
}

/// The owner and mode Linux would show for socket `fd`, if this process
/// knows them.
pub fn socket_inode(fd: i32) -> Option<SocketInode> {
    let ino = inode(fd)?;
    let m = SOCKETS.lock().unwrap_or_else(|e| e.into_inner());
    m.iter().find(|&&(n, _)| n == ino).map(|&(_, s)| s)
}

/// The caller's file-system ids, as a socket it makes is owned by.
fn own_ids() -> (u32, u32) {
    let a = crate::creds::access();
    (a.fsuid, a.fsgid)
}

/// `fchmod` of socket `fd` to `perm` (the host has no mode for a socket
/// itself).
pub fn set_socket_mode(fd: i32, perm: u32) {
    let Some(ino) = inode(fd) else { return };
    let mut m = SOCKETS.lock().unwrap_or_else(|e| e.into_inner());
    match m.iter_mut().find(|(n, _)| *n == ino) {
        Some((_, s)) => s.perm = perm & 0o7777,
        None => m.push((ino, SocketInode { owner: None, perm: perm & 0o7777 })),
    }
}

/// `listen(fd, backlog)`. Linux queues one connection more than the
/// backlog (and takes any past `net.core.somaxconn`, or negative, as that),
/// the host no more than it: the host is given one more.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn listen(fd: u64, backlog: u64) -> i64 {
    let max = crate::sysctl::somaxconn();
    let b = backlog as i32;
    let b = if (0..=max).contains(&b) { b } else { max };
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
    if let Err(e) = autobind_to_pass_creds(fd as i32, false) {
        return e;
    }
    if let Err(e) = crate::netns::connect_prepare(fd as i32, &mut hb) {
        return err(e);
    }
    if let Err(e) = may_write_socket(&hb, &a) {
        return err(e);
    }
    let r = connect_host(fd as i32, &hb, &a);
    if r == 0 && a.dir.is_some() {
        remember_name(fd as i32, false, &a.guest);
    }
    if r == 0 {
        crate::netns::used(fd as i32);
    }
    r
}

/// Sockets, by descriptor and inode, whose connection the host is still
/// making: their connect was interrupted (`EINTR`) or did not wait
/// (`EINPROGRESS`). Linux's socket is then `SS_CONNECTING`.
static CONNECTING: std::sync::Mutex<Vec<(i32, u64)>> = std::sync::Mutex::new(Vec::new());

/// Mark or unmark socket `fd` as [`CONNECTING`]; whether it was.
fn connecting(fd: i32, mark: bool) -> bool {
    let Some(ino) = inode(fd) else { return false };
    let mut c = CONNECTING.lock().unwrap_or_else(|e| e.into_inner());
    // Those of sockets gone: none is open here with its number now.
    if mark && c.len() >= 64 && c.len().is_power_of_two() {
        let open: std::collections::HashSet<u64> =
            crate::fdtable::open_fds().into_iter().filter_map(inode).collect();
        c.retain(|e| open.contains(&e.1));
    }
    let was = c.contains(&(fd, ino));
    c.retain(|&e| e.0 != fd);
    if mark {
        c.push((fd, ino));
    }
    was
}

/// The host's connect of `fd` to `hb`, as Linux's connect answers. The
/// host's connection goes on after an interrupted connect, as Linux's
/// does, and a connect is not to be made twice: a later connect of the
/// socket (the same call run again after a signal the guest does not see,
/// or after its handler) finishes the one under way, waiting for it if
/// the socket blocks, and returns its outcome, where the host would say
/// `EALREADY` or `EISCONN`. Once that is told, the socket is connected
/// (`EISCONN`), on Linux as on the host.
fn connect_host(fd: i32, hb: &[u8; SOCKADDR_MAX], a: &HostAddr) -> i64 {
    if bind_or_connect(fd, hb, a, false) == 0 {
        connecting(fd, false);
        return 0;
    }
    let e = crate::host::last_errno();
    match e {
        libc::EINTR | libc::EINPROGRESS => {
            connecting(fd, true);
            return err(crate::host::errno_to_linux(e));
        }
        libc::EALREADY | libc::EISCONN if connecting(fd, false) => {}
        _ => {
            // (A connection under way that failed is told so once.)
            connecting(fd, false);
            return err(crate::host::errno_to_linux(e));
        }
    }
    if e == libc::EALREADY {
        // SAFETY: plain host call on the guest's socket.
        if unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0 {
            connecting(fd, true);
            return err(errno::EALREADY);
        }
        let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut p, 1, -1) } < 0 {
            let e = crate::host::last_errno();
            connecting(fd, true);
            return err(crate::host::errno_to_linux(e));
        }
    }
    let mut so_error: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a valid out-parameter of its length.
    let r = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&raw mut so_error).cast(), &mut len)
    };
    if r != 0 {
        return crate::host::last_error();
    }
    if so_error != 0 { err(crate::host::errno_to_linux(so_error)) } else { 0 }
}

/// Unix sockets bound (`local`) or connected to a path the host knows only
/// relative to its directory: by descriptor and inode, the guest's path,
/// which `getsockname` and `getpeername` report.
#[allow(clippy::type_complexity)]
pub(crate) static NAMES: std::sync::Mutex<Vec<(i32, u64, bool, Vec<u8>)>> =
    std::sync::Mutex::new(Vec::new());

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
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return err(errno::EINVAL);
    }
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
    // A connection is in its listener's namespace.
    crate::fdmarks::pin_net(r, crate::netns::of(fd as i32));
    fresh(r);
    socket_made(r, Some(own_ids()));
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
    let filtered = if crate::bpf::filtering() {
        let data = guest!(uaccess::read_bytes(buf, len as usize));
        crate::bpf::filter_send(fd as i32, &data)
    } else {
        None
    };
    let len = match filtered {
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
    if let Err(e) = autobind_to_pass_creds(fd as i32, true) {
        return e;
    }
    // TCP fast open: connected first, then sent to the peer.
    if let Err(e) = fastopen(fd as i32, flags, addr, addrlen) {
        return e;
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
                // Sending to a Unix socket's node needs write permission on it.
                if let Err(e) = may_write_socket(&hb, &a) {
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
    // A datagram to a socket that asked for credentials carries them.
    #[cfg(not(target_os = "linux"))]
    let prepared = match send_control(fd as i32, 0, 0, named.then(|| &hb[..alen as usize])) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    #[cfg(not(target_os = "linux"))]
    let (ctl_ptr, ctl_len) = match &prepared {
        Some(p) => (p.buf.as_ptr() as *mut libc::c_void, p.buf.len() as _),
        None => (std::ptr::null_mut(), 0),
    };
    #[cfg(target_os = "linux")]
    let (ctl_ptr, ctl_len) = (std::ptr::null_mut(), 0);
    let mut hmsg = libc::msghdr {
        msg_name: aptr as *mut libc::c_void,
        msg_namelen: alen,
        msg_iov: iov.as_mut_ptr(),
        msg_iovlen: 1,
        msg_control: ctl_ptr,
        msg_controllen: ctl_len,
        msg_flags: 0,
    };
    // ENAMETOOLONG where the host cannot send from a directory.
    let mut r = err(errno::ENAMETOOLONG);
    in_dir(dir.as_ref(), || {
        // SAFETY: `hmsg` references the guest buffer and the local name.
        r = unsafe { send_corked(fd as i32, &mut hmsg, flags, hflags) };
        0
    });
    #[cfg(not(target_os = "linux"))]
    if r < 0
        && let Some(p) = prepared
    {
        p.unsent();
    }
    if r >= 0 {
        crate::netns::used(fd as i32);
    }
    r
}

/// Bytes `MSG_MORE` (or `UDP_CORK`) held back, by IP socket.
pub(crate) static CORKED: std::sync::Mutex<Option<std::collections::HashMap<i32, Held>>> =
    std::sync::Mutex::new(None);

/// What a socket holds back: the bytes, and for a datagram the host
/// address the first of them was sent to (empty for none), where they go.
#[derive(Default)]
pub(crate) struct Held {
    data: Vec<u8>,
    name: Vec<u8>,
}

/// Whether any socket has bytes held back.
static ANY_CORKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A send with `MSG_FASTOPEN` on TCP socket `fd`: connect to `addr`
/// (`addrlen` bytes) first, as Linux does when it sends the data with the
/// connection's opening (the host has no client fast open, so the data
/// follows the handshake). Whether it connected; `EISCONN` for a socket
/// connected already, `EINVAL` with no address, and the connection's
/// error (`EINPROGRESS` for a non-blocking socket, which sends nothing
/// then, as Linux sends nothing without a fast-open cookie).
fn fastopen(fd: i32, flags: u64, addr: u64, addrlen: u64) -> Result<bool, i64> {
    if flags & MSG_FASTOPEN == 0 || !ip_stream(fd) {
        return Ok(false);
    }
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters.
    if unsafe { libc::getpeername(fd, hb.as_mut_ptr().cast(), &mut hl) } == 0 {
        return Err(err(errno::EISCONN));
    }
    if addr == 0 || addrlen == 0 {
        return Err(err(errno::EINVAL));
    }
    // SAFETY: the caller guarantees the address spans its length.
    let r = unsafe { connect(fd as u64, addr, addrlen) };
    if r < 0 { Err(r) } else { Ok(true) }
}

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
fn take_corked(fd: i32) -> Option<Held> {
    if !ANY_CORKED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    CORKED.lock().unwrap_or_else(|e| e.into_inner()).as_mut()?.remove(&fd)
}

/// The multicast groups TCP sockets joined: (socket, group and
/// interface as the host lays them out).
pub(crate) static MEMBERSHIPS: crate::kept::Kept<Vec<(i32, Vec<u8>)>> =
    crate::kept::Kept::new(Vec::new());

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
    let mut m = MEMBERSHIPS.lock();
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
    #[cfg(not(target_os = "linux"))]
    if kept_value(fd, SO_PASSCRED) != 0 {
        passcred_bound(fd, false);
    }
    if let Some(mut m) = MEMBERSHIPS.if_used() {
        m.retain(|(f, _)| *f != fd);
    }
    if let Some(mut k) = KEPT_VALUES.if_used() {
        k.retain(|k| k.0 != fd);
    }
    if let Some(mut v) = V4_VIEW.if_used() {
        v.retain(|&f| f != fd);
    }
    flush_corked(fd);
}

/// A new socket is descriptor `fd` (made, accepted or received): what fwe
/// keeps per descriptor starts empty, whatever a socket that had the
/// number left (one closed out of fwe's sight).
pub(crate) fn fresh(fd: i32) {
    if let Some(mut m) = MEMBERSHIPS.if_used() {
        m.retain(|(f, _)| *f != fd);
    }
    if let Some(mut k) = KEPT_VALUES.if_used() {
        k.retain(|k| k.0 != fd);
    }
    if let Some(mut v) = V4_VIEW.if_used() {
        v.retain(|&f| f != fd);
    }
    take_corked(fd);
}

/// Send what socket `fd` held back, without waiting.
fn flush_corked(fd: i32) {
    let Some(held) = take_corked(fd) else { return };
    let (name, len) = if held.name.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (held.name.as_ptr().cast(), held.name.len() as libc::socklen_t)
    };
    // SAFETY: local buffers of their lengths; the send does not wait.
    unsafe {
        libc::sendto(fd, held.data.as_ptr().cast(), held.data.len(), libc::MSG_DONTWAIT, name, len)
    };
}

/// Whether `fd` is a UDP socket (an IP datagram one).
fn udp(fd: i32) -> bool {
    matches!(kind(fd), Some((libc::AF_INET | libc::AF_INET6, libc::SOCK_DGRAM)))
}

/// The value of option `optname` of the UDP level fwe keeps for `fd`.
fn udp_option(fd: i32, optname: u64) -> i32 {
    kept_value(fd, SOL_UDP << 32 | optname)
}

/// The value fwe keeps for `fd` under `key` ([`kept_key`]), 0 if none.
fn kept_value(fd: i32, key: u64) -> i32 {
    let kept = KEPT_VALUES.if_used();
    kept.and_then(|k| k.iter().find(|v| (v.0, v.1) == (fd, key)).map(|v| v.2)).unwrap_or(0)
}

/// The host path of Unix datagram socket `fd`'s own address (`peer`: its
/// peer's), if it has one.
#[cfg(not(target_os = "linux"))]
fn dgram_path(fd: i32, peer: bool) -> Option<Vec<u8>> {
    if kind(fd) != Some((libc::AF_UNIX, libc::SOCK_DGRAM)) {
        return None;
    }
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    let a = hb.as_mut_ptr().cast();
    // SAFETY: valid out-parameters of their lengths.
    let r = unsafe {
        if peer { libc::getpeername(fd, a, &mut hl) } else { libc::getsockname(fd, a, &mut hl) }
    };
    if r != 0 {
        return None;
    }
    host_unix_path(&hb[..hl as usize])
}

/// The path of host Unix address `hb` (macOS layout), if it has one.
#[cfg(not(target_os = "linux"))]
fn host_unix_path(hb: &[u8]) -> Option<Vec<u8>> {
    if hb.len() <= 2 || i32::from(hb[1]) != libc::AF_UNIX {
        return None;
    }
    let path = &hb[2..];
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    (end > 0).then(|| path[..end].to_vec())
}

/// Datagram socket `fd`, bound, asks for credentials (`on`) or no longer
/// does: senders that are fwe's are told by its address ([`crate::scm`]).
#[cfg(not(target_os = "linux"))]
fn passcred_bound(fd: i32, on: bool) {
    if let Some(path) = dgram_path(fd, false) {
        crate::scm::wants_creds(&path, on);
    }
}

/// The credentials a datagram from Unix socket `fd` to host address `to`
/// (its peer's when `None`) carries unasked: the sender's, when the
/// receiving socket asked for them ([`crate::scm::wants_creds`]).
#[cfg(not(target_os = "linux"))]
fn creds_for(fd: i32, to: Option<&[u8]>) -> Option<crate::scm::Creds> {
    if !crate::scm::any_wanted() {
        return None;
    }
    let path = match to {
        Some(hb) => host_unix_path(hb)?,
        None => dgram_path(fd, true)?,
    };
    crate::scm::creds_wanted(&path).then(crate::scm::own_creds)
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
    let ip = matches!(
        kind(fd),
        Some((libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_DGRAM))
    );
    let udp = ip && udp(fd);
    if ip && (flags & MSG_MORE != 0 || udp && udp_option(fd, UDP_CORK) != 0) {
        let mut more = Vec::new();
        for v in iov {
            // SAFETY: the iovecs are checked host buffers.
            more.extend_from_slice(unsafe {
                std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
            });
        }
        let n = more.len() as i64;
        let mut m = CORKED.lock().unwrap_or_else(|e| e.into_inner());
        let held = m.get_or_insert_with(Default::default).entry(fd).or_default();
        if held.name.is_empty() && !msg.msg_name.is_null() {
            // SAFETY: the caller's name buffer of its length.
            let name = unsafe {
                std::slice::from_raw_parts(msg.msg_name.cast::<u8>(), msg.msg_namelen as usize)
            };
            held.name = name.to_vec();
        }
        held.data.extend(more);
        ANY_CORKED.store(true, std::sync::atomic::Ordering::Relaxed);
        return n;
    }
    let held = take_corked(fd).unwrap_or_default();
    // A datagram held back goes where its first part was sent.
    if msg.msg_name.is_null() && !held.name.is_empty() {
        msg.msg_name = held.name.as_ptr() as *mut _;
        msg.msg_namelen = held.name.len() as _;
    }
    let segment = if udp { udp_option(fd, UDP_SEGMENT) as usize } else { 0 };
    let total = held.data.len() + iov.iter().map(|v| v.iov_len).sum::<usize>();
    if segment > 0 && total > segment {
        // SAFETY: the caller's buffers.
        return unsafe { send_segments(fd, msg, &held.data, iov, segment, hflags) };
    }
    if held.data.is_empty() {
        // SAFETY: the caller's guarantee.
        return ret(unsafe { libc::sendmsg(fd, msg, hflags) } as i64);
    }
    let mut all =
        vec![libc::iovec { iov_base: held.data.as_ptr() as *mut _, iov_len: held.data.len() }];
    all.extend_from_slice(iov);
    msg.msg_iov = all.as_mut_ptr();
    msg.msg_iovlen = all.len() as _;
    // SAFETY: the caller's buffers, and the held bytes.
    let r = ret(unsafe { libc::sendmsg(fd, msg, hflags) } as i64);
    let h = held.data.len() as i64;
    if r < h {
        // What did not go is held still.
        let sent = r.max(0) as usize;
        let mut m = CORKED.lock().unwrap_or_else(|e| e.into_inner());
        let rest = Held { data: held.data[sent..].to_vec(), name: held.name.clone() };
        m.get_or_insert_with(Default::default).insert(fd, rest);
        return if r < 0 { r } else { 0 };
    }
    r - h
}

/// A UDP send of `held` then `iov` with `UDP_SEGMENT` of `segment` bytes,
/// as Linux's segmentation offload sends it: a datagram of each `segment`
/// bytes and one of the rest, at most [`UDP_MAX_SEGMENTS`] (`EINVAL` past
/// them). Returns the guest's bytes sent, or the first datagram's error.
///
/// # Safety
/// `msg` names valid buffers, `iov` the guest's.
unsafe fn send_segments(
    fd: i32,
    msg: &mut libc::msghdr,
    held: &[u8],
    iov: &[libc::iovec],
    segment: usize,
    hflags: i32,
) -> i64 {
    let mut all = held.to_vec();
    for v in iov {
        // SAFETY: the iovecs are checked host buffers.
        all.extend_from_slice(unsafe { std::slice::from_raw_parts(v.iov_base.cast(), v.iov_len) });
    }
    if all.len().div_ceil(segment) > UDP_MAX_SEGMENTS {
        return err(errno::EINVAL);
    }
    for (i, part) in all.chunks(segment).enumerate() {
        let mut one = libc::iovec { iov_base: part.as_ptr() as *mut _, iov_len: part.len() };
        msg.msg_iov = &mut one;
        msg.msg_iovlen = 1;
        // SAFETY: a local buffer and the caller's name and control.
        let r = ret(unsafe { libc::sendmsg(fd, msg, hflags) } as i64);
        if r < 0 && i == 0 {
            return r;
        }
        // Control data (descriptors) goes with the first only.
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
    }
    (all.len() - held.len()) as i64
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
    if crate::fdmarks::is_ping(fd as i32) {
        let mut v = [guest!(uaccess::host_buffer(buf, len, true))];
        let mut hb = empty_sockaddr();
        // SAFETY: an all-zero `msghdr` is valid: no name, no control.
        let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
        m.msg_iov = v.as_mut_ptr();
        m.msg_iovlen = 1;
        if addr != 0 {
            m.msg_name = hb.as_mut_ptr().cast();
            m.msg_namelen = SOCKADDR_MAX as libc::socklen_t;
        }
        // SAFETY: a local name buffer and the translated guest buffer.
        let r = unsafe { ping_recvmsg(fd as i32, &mut m, hflags, flags & MSG_TRUNC != 0) };
        if r >= 0 && addr != 0 && addrlen != 0 {
            crate::netns::to_guest(fd as i32, &mut hb, false);
            guest!(name_to_guest(&hb, m.msg_namelen, addr, addrlen));
        }
        return r;
    }
    let whole = match datagram_whole(fd as i32, flags) {
        Ok(w) => w,
        Err(e) => return e,
    };
    let r = recvfrom_host(fd, buf, len, hflags, addr, addrlen);
    match whole {
        Some(w) if r >= 0 => w as i64,
        _ => r,
    }
}

/// The length of the datagram a receive with `MSG_TRUNC` on datagram
/// socket `fd` takes, which Linux returns (the host takes the flag as an
/// output only): waited for as the receive would wait, then measured
/// (`SO_NREAD`). `None` for another socket or without the flag.
fn datagram_whole(fd: i32, flags: u64) -> Result<Option<usize>, i64> {
    if flags & MSG_TRUNC == 0 || kind(fd).map(|k| k.1) != Some(libc::SOCK_DGRAM) {
        return Ok(None);
    }
    let wait = msg_flags_to_host(flags & (MSG_DONTWAIT | MSG_OOB)) | libc::MSG_PEEK;
    let mut b = 0u8;
    // A peek of a byte, which waits (one of none returns at once).
    // SAFETY: a one-byte local buffer.
    if unsafe { libc::recv(fd, (&mut b as *mut u8).cast(), 1, wait) } < 0 {
        return Err(last_error());
    }
    Ok(crate::netlink::next_len(fd))
}

/// Whether host address `hb` of `len` bytes, a received datagram's
/// sender's, is a Unix socket with no name, which Linux reports as no
/// address at all (a length of 0), not as the family alone.
fn unnamed_unix(hb: &[u8; SOCKADDR_MAX], len: libc::socklen_t) -> bool {
    let len = (len as usize).min(SOCKADDR_MAX);
    family(hb) == libc::AF_UNIX && hb[2..len.max(2)].first().is_none_or(|&b| b == 0)
}

/// [`recvfrom`] of a host socket: the bytes, the sender's address
/// translated back.
fn recvfrom_host(fd: u64, buf: u64, len: u64, hflags: i32, addr: u64, addrlen: u64) -> i64 {
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
            if unnamed_unix(&hb, hl) {
                guest!(uaccess::write(addrlen, 0u32));
            } else {
                guest!(name_to_guest(&hb, hl, addr, addrlen));
            }
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
    let fam = if V4_VIEW.lock().contains(&fd) { libc::AF_INET } else { fam };
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
    V4_VIEW.lock().retain(|&f| f != fd);
    take_corked(fd);
    MEMBERSHIPS.lock().retain(|(f, _)| *f != fd);
    Some(0)
}

/// Socket options Linux has and the host has not: kept, and read back as
/// set (`SO_NO_CHECK`, `SO_PRIORITY`, which change nothing fwe does;
/// `SO_PASSCRED`, which a receive acts on, see [`crate::scm`]).
const KEPT: [u64; 3] = [11, 12, 16];

/// Options of the IP levels Linux has and the host has not, kept as
/// [`KEPT`] is: `IP_RECVERR` and `IPV6_RECVERR`, which glibc's resolver
/// sets on its socket and gives up without. Linux's error queue holds the
/// ICMP errors a socket's datagrams met; the host keeps none, so it stays
/// empty, as on a network that returns no such errors.
const KEPT_IP: [(u64, u64); 3] = [(0, 11), (41, 25), (SOL_RAW, ICMP_FILTER)];

/// `SOL_RAW` and its `ICMP_FILTER`, which filters a raw ICMP socket's
/// types on Linux. The host has none, so it is kept as [`KEPT`] is, and
/// every type arrives (which `ping` copes with).
const SOL_RAW: u64 = 255;
const ICMP_FILTER: u64 = 1;

/// The UDP level's options (`SOL_UDP`, which `SOL_UDPLITE` shares). The
/// host has none of them (its `UDP_NOCKSUM` has `UDP_CORK`'s number), so
/// fwe keeps them: `UDP_CORK` holds sends back as `MSG_MORE` does until it
/// is cleared, which sends them as one datagram; `UDP_SEGMENT` cuts each
/// send into datagrams of its size, as segmentation offload does;
/// `UDP_GRO` joins nothing (Linux too delivers datagrams it did not join
/// one by one); the IPv6 checksum options leave checksums to the host.
const KEPT_UDP: [u64; 5] = [UDP_CORK, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_SEGMENT, UDP_GRO];

/// The key [`KEPT_VALUES`] holds option `optname` of `level` under, if it
/// is one fwe keeps.
fn kept_key(level: u64, optname: u64) -> Option<u64> {
    if level == SOL_SOCKET && KEPT.contains(&optname) {
        Some(optname)
    } else if matches!(level, SOL_UDP | SOL_UDPLITE) && KEPT_UDP.contains(&optname) {
        Some(SOL_UDP << 32 | optname)
    } else if KEPT_IP.contains(&(level, optname)) {
        Some(level << 32 | optname)
    } else {
        None
    }
}

/// The values of kept options set: (socket, [`kept_key`], value).
pub(crate) static KEPT_VALUES: crate::kept::Kept<Vec<(i32, u64, i32)>> =
    crate::kept::Kept::new(Vec::new());

/// IPv6 sockets `IPV6_ADDRFORM` made IPv4: the host's socket stays IPv6,
/// its names are reported as the IPv4 ones they map.
static V4_VIEW: crate::kept::Kept<Vec<i32>> = crate::kept::Kept::new(Vec::new());

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
    V4_VIEW.lock().push(fd);
    0
}

/// The host name `hb` (of `hl` bytes) of an IPv6 socket `IPV6_ADDRFORM`
/// made IPv4, as that: the IPv4 address its IPv4-mapped one stands for.
fn v4_view(fd: i32, hb: &mut [u8; SOCKADDR_MAX], hl: &mut libc::socklen_t) {
    if family(hb) != libc::AF_INET6 || !V4_VIEW.lock().contains(&fd) {
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
                // Seconds, as Linux's: the host's SO_LINGER is in clock
                // ticks.
                SO_LINGER => libc::SO_LINGER_SEC,
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
    let keep = |key: u64| {
        if optlen < 4 {
            return err(errno::EINVAL);
        }
        let v: i32 = guest!(uaccess::read(optval));
        if let Err(e) = socket_fd(fd as i32) {
            return e;
        }
        let mut k = KEPT_VALUES.lock();
        k.retain(|&(f, o, _)| (f, o) != (fd as i32, key));
        k.push((fd as i32, key, v));
        0
    };
    if level == SOL_SOCKET
        && let Some(key) = kept_key(level, optname)
    {
        // SO_PRIORITY past 6 is CAP_NET_ADMIN's to set.
        if optname == SO_PRIORITY && optlen >= 4 {
            let v: i32 = guest!(uaccess::read(optval));
            if !(0..=6).contains(&v) && !admin {
                return err(errno::EPERM);
            }
        }
        let r = keep(key);
        #[cfg(not(target_os = "linux"))]
        if r == 0 && optname == SO_PASSCRED {
            passcred_bound(fd as i32, kept_value(fd as i32, SO_PASSCRED) != 0);
        }
        return r;
    }
    if let Some(e) = level_refused(fd as i32, level, false) {
        return e;
    }
    if matches!(level, SOL_UDP | SOL_UDPLITE) && kept_key(level, optname).is_some() {
        if optlen < 4 {
            return err(errno::EINVAL);
        }
        let v: i32 = guest!(uaccess::read(optval));
        if optname == UDP_SEGMENT && !(0..=0xffff).contains(&v) {
            return err(errno::EINVAL);
        }
        let r = keep(SOL_UDP << 32 | optname);
        if r == 0 && optname == UDP_CORK && v == 0 {
            // Uncorked: what was held goes, as one datagram.
            flush_corked(fd as i32);
        }
        return r;
    }
    if let Some(key) = kept_key(level, optname) {
        return keep(key);
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
    let kept = kept_key(level, optname);
    if kept.is_some() || level == SOL_SOCKET && matches!(optname, 38 | 39) {
        let Some((fam, _)) = kind(fd as i32) else {
            return socket_fd(fd as i32).err().unwrap_or(err(errno::ENOTSOCK));
        };
        let v = match optname {
            // SO_PROTOCOL: what the socket was made with (TCP or UDP for
            // 0), as the host knows it; a netlink one's is NETLINK_ROUTE.
            38 if crate::netlink::is(fd as i32) => 0,
            38 => crate::host::socket_protocol(fd as i32).unwrap_or(0),
            // SO_DOMAIN
            39 => match fam {
                libc::AF_INET6 => AF_INET6 as i32,
                f => f,
            },
            _ => KEPT_VALUES
                .lock()
                .iter()
                .find(|&&(f, o, _)| Some((f, o)) == kept.map(|k| (fd as i32, k)))
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
    match peer_ucred(fd) {
        Ok(cred) => write_ucred(optval, optlen, cred),
        Err(e) => err(e),
    }
}

/// The `ucred` of the process at the other end of Unix socket `fd`, as the
/// caller sees it: its pid in the caller's pid namespace, its effective
/// user and group ids (fwe's for it, as `SO_PEERCRED` gives them) in the
/// caller's user namespace. A process fwe did not start has its host ids
/// as the guest sees them.
fn peer_ucred(fd: i32) -> Result<[u32; 3], i32> {
    let (pid, uid, gid) = host_peercred(fd)?;
    Ok(ucred_of(pid).unwrap_or([
        crate::pidns::to_guest(pid) as u32,
        crate::host::uid_to_linux(uid),
        crate::host::gid_to_linux(gid),
    ]))
}

/// The `ucred` of fwe's process `pid` (a host pid) as the caller sees it:
/// its effective ids, if fwe has a record of it.
fn ucred_of(pid: i32) -> Option<[u32; 3]> {
    let ids = crate::procreg::read(pid)?.ids;
    Some(guest_ucred(pid, ids[1], ids[5]))
}

/// Credentials as the caller sees them: the pid in its pid namespace, the
/// ids in its user namespace.
fn guest_ucred(host_pid: i32, uid: u32, gid: u32) -> [u32; 3] {
    [
        crate::pidns::to_guest(host_pid) as u32,
        crate::userns::to_ns(uid, false),
        crate::userns::to_ns(gid, true),
    ]
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

/// A read of a socket's error queue (`MSG_ERRQUEUE`), which fwe never
/// fills (the host has none): empty, `EAGAIN`, as Linux reports one, for
/// an IP or a Unix socket.
fn errqueue_empty(fd: i32, flags: u64) -> Option<i64> {
    if flags & MSG_ERRQUEUE == 0 {
        return None;
    }
    let mut hb = empty_sockaddr();
    let mut hl = SOCKADDR_MAX as libc::socklen_t;
    // SAFETY: valid out-parameters of their lengths.
    let named = unsafe { libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) } == 0;
    let fam = family(&hb);
    (named && matches!(fam, libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX))
        .then(|| err(errno::EAGAIN))
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
    if let Err(e) = autobind_to_pass_creds(fd as i32, true) {
        return e;
    }
    // TCP fast open: connected first, then sent to the peer.
    let (name, namelen) = match fastopen(fd as i32, flags, name, namelen as u64) {
        Ok(true) => (0, 0),
        Ok(false) => (name, namelen),
        Err(e) => return e,
    };
    // A socket whose peer filters what arrives: what it lets in is sent,
    // the rest dropped as if sent.
    let total: u64 = hiov.iter().map(|v| v.iov_len as u64).sum();
    let mut dropped = 0;
    if crate::bpf::filtering()
        && let Some(keep) = crate::bpf::filter_send(fd as i32, &crate::iovecs_bytes(&hiov))
    {
        if keep == 0 {
            return total as i64;
        }
        dropped = total - keep;
        hiov = crate::iovecs_part(&hiov, 0, keep);
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
                // Sending to a Unix socket's node needs write permission on it.
                if let Err(e) = may_write_socket(&hb, &a) {
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
    // through; on macOS it is re-encoded ([`crate::scm`]).
    #[cfg(target_os = "linux")]
    let (ctl_ptr, ctl_len) = (control as *mut libc::c_void, controllen as _);
    #[cfg(not(target_os = "linux"))]
    let to = (!name_ptr.is_null()).then(|| &hb[..name_len as usize]);
    #[cfg(not(target_os = "linux"))]
    let prepared = match send_control(fd as i32, control, controllen, to) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    #[cfg(not(target_os = "linux"))]
    let (ctl_ptr, ctl_len) = match &prepared {
        Some(p) if !p.buf.is_empty() => (p.buf.as_ptr() as *mut libc::c_void, p.buf.len() as _),
        _ => (std::ptr::null_mut(), 0),
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
    let r = if crate::seqpacket::is(fd as i32) {
        crate::seqpacket::send(
            fd as i32,
            &hiov,
            (hmsg.msg_control, hmsg.msg_controllen as usize),
            msg_flags_to_host(flags),
        )
    } else {
        let mut hmsg = hmsg;
        // ENAMETOOLONG where the host cannot send from a directory.
        let mut r = err(errno::ENAMETOOLONG);
        in_dir(dir.as_ref(), || {
            // SAFETY: `hmsg` references guest iov and local name/control buffers.
            r = unsafe { send_corked(fd as i32, &mut hmsg, flags, msg_flags_to_host(flags)) };
            0
        });
        r
    };
    #[cfg(not(target_os = "linux"))]
    if r < 0
        && let Some(p) = prepared
    {
        p.unsent();
    }
    if r >= 0 {
        crate::netns::used(fd as i32);
    }
    // What the filter dropped counts as sent.
    if r >= 0 && r as u64 + dropped == total { total as i64 } else { r }
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
    // Room for the most descriptors the host passes in one message.
    #[cfg(not(target_os = "linux"))]
    let mut macbuf = vec![0u8; if controllen != 0 { HOST_CONTROL } else { 0 }];
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
    let ping = crate::fdmarks::is_ping(fd as i32);
    // A netlink message's whole length, asked for with MSG_TRUNC.
    let nl_whole = if crate::netlink::is(fd as i32) {
        (flags & MSG_TRUNC != 0).then(|| crate::netlink::next_len(fd as i32)).flatten()
    } else if crate::seqpacket::is(fd as i32) || ping {
        None
    } else {
        match datagram_whole(fd as i32, flags) {
            Ok(w) => w,
            Err(e) => return e,
        }
    };
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
    } else if ping {
        // SAFETY: `hmsg` references guest iov and local name/control buffers.
        let r = unsafe {
            ping_recvmsg(fd as i32, &mut hmsg, msg_flags_to_host(flags), flags & MSG_TRUNC != 0)
        };
        if r < 0 {
            return r;
        }
        r as isize
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
    } else if want_name && unnamed_unix(&hb, hmsg.msg_namelen) {
        guest!(uaccess::write(msg + 8, 0u32));
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
        let cap = controllen as usize;
        let got = (hmsg.msg_controllen as usize).min(macbuf.len());
        // Credentials, asked for with `SO_PASSCRED`, come first: those the
        // sender gave, else the peer's (the kernel's, 0, for netlink).
        let passcred = kept_value(fd as i32, SO_PASSCRED) != 0;
        let room = cap.saturating_sub(if passcred { 32 } else { 0 });
        let inc = crate::scm::receive(
            &macbuf[..got],
            room.saturating_sub(CMSG_HDR) / 4,
            flags & MSG_PEEK != 0,
        );
        let creds = passcred.then(|| match inc.creds {
            Some(c) => guest_ucred(c.host_pid, c.uid, c.gid),
            None if crate::netlink::is(fd as i32) => [0, 0, 0],
            // No process to name (a datagram from a program fwe did not
            // start): the overflow ids, as Linux gives an id it cannot map.
            None => peer_ucred(fd as i32).unwrap_or([0, 65534, 65534]),
        });
        let (bytes, ctrunc) =
            crate::scm::linux_control(cap, creds, &inc.fds, flags & MSG_CMSG_CLOEXEC != 0);
        let mut lflags = msg_flags_from_host(hmsg.msg_flags);
        if ctrunc || inc.dropped {
            lflags |= MSG_CTRUNC as i32;
        }
        if uaccess::write_from(control, &bytes).is_err() {
            for &fd in &inc.fds {
                // SAFETY: descriptors received for this call, not delivered.
                unsafe { libc::close(fd) };
            }
            return err(errno::EFAULT);
        }
        guest!(uaccess::write(msg + 40, bytes.len() as u64));
        guest!(uaccess::write(msg + 48, lflags));
    }
    r as i64
}

/// The host control buffer a receive gives: the host's most descriptors
/// in one message (254), with room to spare.
#[cfg(not(target_os = "linux"))]
const HOST_CONTROL: usize = 12 + 4 * 256 + 64;

/// The host control data for the guest's control buffer of a send on
/// `fd` ([`crate::scm`]). A socket that is not a Unix one takes neither
/// descriptors nor credentials (`EINVAL`), and passes the rest over.
///
/// Credentials it gives are checked ([`crate::scm::check_creds`]); a
/// datagram to a socket that asked for them carries the sender's anyway,
/// as Linux attaches them (`to`: the host address it is sent to, if any).
#[cfg(not(target_os = "linux"))]
fn send_control(
    fd: i32,
    control: u64,
    len: u64,
    to: Option<&[u8]>,
) -> Result<Option<crate::scm::Prepared>, i32> {
    if len == 0 {
        return creds_for(fd, to).map_or(Ok(None), |c| crate::scm::prepare(&[], Some(c)).map(Some));
    }
    let ctl = uaccess::read_bytes(control, (len as usize).min(64 * 1024))?;
    if !is_unix(fd) {
        return match crate::scm::parse(&ctl) {
            Ok(o) if !o.fds.is_empty() || o.creds.is_some() => Err(errno::EINVAL),
            _ => Ok(None),
        };
    }
    let out = crate::scm::parse(&ctl)?;
    let creds = match out.creds {
        Some(c) => Some(crate::scm::check_creds(c)?),
        None => creds_for(fd, to),
    };
    if out.fds.is_empty() && creds.is_none() {
        return Ok(None);
    }
    crate::scm::prepare(&out.fds, creds).map(Some)
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

    /// `IP_RECVERR` and `IPV6_RECVERR`, which glibc's resolver sets on its
    /// UDP socket and gives up without, are accepted and read back as set.
    #[test]
    fn error_queue_options_are_kept() {
        for (family, level, opt) in [(AF_INET, 0u64, 11u64), (AF_INET6, 41, 25)] {
            // SAFETY: no pointers.
            let fd = unsafe { socket(family, SOCK_DGRAM, 0) };
            assert!(fd >= 0);
            let on: i32 = 1;
            // SAFETY: a readable option of its length.
            let r = unsafe { setsockopt(fd as u64, level, opt, &on as *const _ as u64, 4, false) };
            assert_eq!(r, 0, "setsockopt {level}/{opt}");
            let (mut v, mut len): (i32, u32) = (0, 4);
            // SAFETY: writable option and length buffers.
            let r = unsafe {
                getsockopt(
                    fd as u64,
                    level,
                    opt,
                    &mut v as *mut _ as u64,
                    &mut len as *mut _ as u64,
                )
            };
            assert_eq!((r, v, len), (0, 1, 4), "getsockopt {level}/{opt}");
            close(fd);
        }
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

#[cfg(test)]
pub(crate) mod scm_tests {
    use super::*;

    /// A connected Unix socket pair of `ty`.
    pub(crate) fn pair(ty: u64) -> [i32; 2] {
        let mut sv = [0i32; 2];
        // SAFETY: valid array.
        assert_eq!(unsafe { socketpair(AF_UNIX, ty, 0, sv.as_mut_ptr() as u64) }, 0);
        sv
    }

    /// Send one byte on `s` with `control` (Linux layout): the result.
    pub(crate) fn send_control(s: i32, control: &[u8]) -> i64 {
        let byte = *b"x";
        let iov = libc::iovec { iov_base: byte.as_ptr() as *mut _, iov_len: 1 };
        let mut mhdr = [0u64; 7];
        mhdr[2] = &iov as *const _ as u64;
        mhdr[3] = 1;
        mhdr[4] = control.as_ptr() as u64;
        mhdr[5] = control.len() as u64;
        // SAFETY: a valid msghdr pointing at a valid iovec and control.
        unsafe { sendmsg(s as u64, mhdr.as_ptr() as u64, 0) }
    }

    /// An `SCM_RIGHTS` message (Linux layout) of `fds`.
    pub(crate) fn rights(fds: &[i32]) -> Vec<u8> {
        let len = CMSG_HDR + 4 * fds.len();
        let mut c = vec![0u8; (len + 7) & !7];
        c[0..8].copy_from_slice(&(len as u64).to_ne_bytes());
        c[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
        c[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        for (i, fd) in fds.iter().enumerate() {
            c[16 + 4 * i..20 + 4 * i].copy_from_slice(&fd.to_ne_bytes());
        }
        c
    }

    /// Receive one message on `s` into a control buffer of `cap` bytes:
    /// the result, the control bytes written and the message flags.
    pub(crate) fn recv_control(s: i32, cap: usize, flags: u64) -> (i64, Vec<u8>, i32) {
        let mut byte = [0u8; 1];
        let iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
        let mut control = vec![0u8; cap];
        let mut mhdr = [0u64; 7];
        mhdr[2] = &iov as *const _ as u64;
        mhdr[3] = 1;
        mhdr[4] = control.as_mut_ptr() as u64;
        mhdr[5] = cap as u64;
        // SAFETY: a valid msghdr with a writable iovec and control.
        let r = unsafe { recvmsg(s as u64, mhdr.as_mut_ptr() as u64, flags) };
        control.truncate(mhdr[5] as usize);
        (r, control, mhdr[6] as i32)
    }

    /// The descriptors of the `SCM_RIGHTS` messages in `control`.
    pub(crate) fn fds_in(control: &[u8]) -> Vec<i32> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + CMSG_HDR <= control.len() {
            let len = u64::from_ne_bytes(control[at..at + 8].try_into().unwrap()) as usize;
            let ty = i32::from_ne_bytes(control[at + 12..at + 16].try_into().unwrap());
            if ty == SCM_RIGHTS {
                for o in (at + CMSG_HDR..(at + len).min(control.len())).step_by(4) {
                    out.push(i32::from_ne_bytes(control[o..o + 4].try_into().unwrap()));
                }
            }
            at += (len.max(CMSG_HDR) + 7) & !7;
        }
        out
    }

    pub(crate) fn cloexec(fd: i32) -> bool {
        // SAFETY: F_GETFD only queries.
        unsafe { libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
    }

    pub(crate) fn close_all(fds: &[i32]) {
        for &fd in fds {
            // SAFETY: descriptors of this test's.
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn cmsg_cloexec_marks_received_descriptors() {
        let _g = serial();
        let sv = pair(SOCK_STREAM);
        for (flags, want) in [(0, false), (MSG_CMSG_CLOEXEC, true)] {
            assert_eq!(send_control(sv[0], &rights(&[0, 1])), 1);
            let (r, control, _) = recv_control(sv[1], 64, flags);
            assert_eq!(r, 1);
            let fds = fds_in(&control);
            assert_eq!(fds.len(), 2);
            assert!(fds.iter().all(|&fd| cloexec(fd) == want), "flags {flags:#x}");
            close_all(&fds);
        }
        close_all(&sv);
    }

    /// The descriptor-passing tests, one at a time: they take descriptor
    /// numbers the host hands out and registries keyed by them.
    pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
        static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ONE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Pass `fds` from one end of a socket pair to the other: what came.
    fn pass(fds: &[i32]) -> Vec<i32> {
        let sv = pair(SOCK_STREAM);
        assert_eq!(send_control(sv[0], &rights(fds)), 1);
        let (r, control, flags) = recv_control(sv[1], 4096, 0);
        assert_eq!((r, flags & MSG_CTRUNC as i32), (1, 0));
        close_all(&sv);
        fds_in(&control)
    }

    #[test]
    fn the_most_descriptors_linux_passes_go_in_one_message() {
        let _g = serial();
        let fds = vec![0; SCM_MAX_FD];
        let got = pass(&fds);
        assert_eq!(got.len(), SCM_MAX_FD);
        close_all(&got);
        let sv = pair(SOCK_STREAM);
        assert_eq!(send_control(sv[0], &rights(&[0; SCM_MAX_FD + 1])), err(errno::EINVAL));
        close_all(&sv);
    }

    #[test]
    fn descriptors_that_do_not_fit_are_closed() {
        let _g = serial();
        let mut p = [0i32; 2];
        // SAFETY: a valid out-array.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let sv = pair(SOCK_STREAM);
        // Four of the pipe's write end; room for two.
        assert_eq!(send_control(sv[0], &rights(&[p[1]; 4])), 1);
        let (r, control, flags) = recv_control(sv[1], CMSG_HDR + 8, 0);
        assert_eq!(r, 1);
        assert_ne!(flags & MSG_CTRUNC as i32, 0);
        let got = fds_in(&control);
        assert_eq!(got.len(), 2);
        // Once those and the original are closed, no write end is left.
        close_all(&got);
        close_all(&[p[1]]);
        close_all(&sv);
        let mut b = 0u8;
        // SAFETY: a valid one-byte buffer; the read end does not block
        // once no writer is left.
        assert_eq!(unsafe { libc::read(p[0], (&mut b as *mut u8).cast(), 1) }, 0);
        close_all(&[p[0]]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_passed_eventfd_shares_its_count() {
        let _g = serial();
        // SAFETY: no pointers.
        let fd = unsafe { crate::specialfd::eventfd2(0, fwe_abi::eventfd::EFD_NONBLOCK) } as i32;
        let got = pass(&[fd]);
        assert_eq!(got.len(), 1);
        assert_eq!(crate::specialfd::anon_name(got[0]), Some("[eventfd]"));
        let seven = 7u64;
        // SAFETY: 8 readable bytes.
        let wrote = unsafe { crate::specialfd::try_write(fd, &seven as *const u64 as u64, 8) };
        assert_eq!(wrote, Some(8));
        let mut v = 0u64;
        // SAFETY: 8 writable bytes.
        let read = unsafe { crate::specialfd::try_read(got[0], &mut v as *mut u64 as u64, 8) };
        assert_eq!(read, Some(8));
        assert_eq!(v, 7);
        // SAFETY: as above: the original sees it read.
        let r = unsafe { crate::specialfd::try_read(fd, &mut v as *mut u64 as u64, 8) };
        assert_eq!(r, Some(err(errno::EAGAIN)));
        assert_eq!(crate::specialfd::try_close(got[0]), Some(0));
        assert_eq!(crate::specialfd::try_close(fd), Some(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_passed_timerfd_keeps_its_schedule() {
        let _g = serial();
        use fwe_abi::timerfd::TFD_NONBLOCK;
        // SAFETY: no pointers.
        let fd = unsafe { crate::specialfd::timerfd_create(1, TFD_NONBLOCK) } as i32;
        let spec: [i64; 4] = [0, 0, 0, 40_000_000];
        // SAFETY: a valid itimerspec.
        let r = unsafe { crate::specialfd::timerfd_settime(fd as u64, 0, spec.as_ptr() as u64, 0) };
        assert_eq!(r, 0);
        let got = pass(&[fd]);
        assert_eq!(crate::specialfd::anon_name(got[0]), Some("[timerfd]"));
        let mut cur = [0i64; 4];
        // SAFETY: a writable itimerspec.
        let r =
            unsafe { crate::specialfd::timerfd_gettime(got[0] as u64, cur.as_mut_ptr() as u64) };
        assert_eq!(r, 0);
        assert!(cur[3] > 0 && cur[3] <= 40_000_000, "{cur:?}");
        std::thread::sleep(std::time::Duration::from_millis(60));
        let mut v = 0u64;
        // SAFETY: 8 writable bytes.
        let r = unsafe { crate::specialfd::try_read(got[0], &mut v as *mut u64 as u64, 8) };
        assert_eq!((r, v), (Some(8), 1));
        crate::specialfd::try_close(got[0]);
        crate::specialfd::try_close(fd);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_passed_signalfd_is_one() {
        let _held = crate::thread::signals_held();
        let _g = serial();
        let fd = crate::signalfd::signalfd4(-1, 1 << 9, fwe_abi::fcntl::O_NONBLOCK);
        let got = pass(&[fd as i32]);
        assert!(crate::signalfd::is_signalfd(got[0]));
        crate::signalfd::try_close(got[0]);
        crate::signalfd::try_close(fd as i32);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_passed_netlink_socket_answers() {
        let _g = serial();
        let fd = crate::netlink::socket(3, 0, false) as i32;
        let got = pass(&[fd]);
        assert!(crate::netlink::is(got[0]));
        assert_eq!(crate::netlink::sock_type(got[0]), Some(3));
        crate::netlink::closed(got[0]);
        crate::fdmarks::closed(got[0]);
        crate::netlink::closed(fd);
        crate::fdmarks::closed(fd);
        close_all(&[got[0], fd]);
    }
}

#[cfg(test)]
mod udp_option_tests {
    use super::*;

    /// A bound UDP receiver and a sender: their descriptors and the
    /// receiver's address (Linux layout).
    fn udp_pair() -> (i32, i32, [u8; 16]) {
        let mut a = [0u8; 16];
        a[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        // SAFETY: no pointers.
        let (rx, tx) = unsafe { (socket(AF_INET, SOCK_DGRAM, 0), socket(AF_INET, SOCK_DGRAM, 0)) };
        // SAFETY: a valid sockaddr.
        assert_eq!(unsafe { bind(rx as u64, a.as_ptr() as u64, 16, true, 0o022) }, 0);
        let mut len: u32 = 16;
        // SAFETY: a writable sockaddr and length.
        let r =
            unsafe { getname(rx as u64, a.as_mut_ptr() as u64, &mut len as *mut _ as u64, false) };
        assert_eq!(r, 0);
        (rx as i32, tx as i32, a)
    }

    fn set(fd: i32, level: u64, name: u64, v: i32) -> i64 {
        // SAFETY: a 4-byte option value.
        unsafe { setsockopt(fd as u64, level, name, &v as *const i32 as u64, 4, false) }
    }

    fn get(fd: i32, level: u64, name: u64) -> Result<i32, i64> {
        let mut v = 0i32;
        let mut len = 4u32;
        // SAFETY: a 4-byte option buffer and its length.
        let r = unsafe {
            getsockopt(
                fd as u64,
                level,
                name,
                &mut v as *mut i32 as u64,
                &mut len as *mut u32 as u64,
            )
        };
        if r < 0 { Err(r) } else { Ok(v) }
    }

    fn send(tx: i32, data: &[u8], to: &[u8; 16]) -> i64 {
        // SAFETY: valid buffers.
        unsafe {
            sendto(tx as u64, data.as_ptr() as u64, data.len() as u64, 0, to.as_ptr() as u64, 16)
        }
    }

    /// The next datagram waiting on `rx`, if one is.
    fn next(rx: i32) -> Option<Vec<u8>> {
        let mut b = [0u8; 64];
        // SAFETY: a valid buffer.
        let n = unsafe { recvfrom(rx as u64, b.as_mut_ptr() as u64, 64, MSG_DONTWAIT, 0, 0) };
        (n >= 0).then(|| b[..n as usize].to_vec())
    }

    #[test]
    fn udp_cork_sends_one_datagram_when_cleared() {
        let (rx, tx, to) = udp_pair();
        assert_eq!(set(tx, SOL_UDP, UDP_CORK, 1), 0);
        assert_eq!(get(tx, SOL_UDP, UDP_CORK), Ok(1));
        assert_eq!(send(tx, b"ab", &to), 2);
        assert_eq!(send(tx, b"cd", &to), 2);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(next(rx), None);
        assert_eq!(set(tx, SOL_UDP, UDP_CORK, 0), 0);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(next(rx).as_deref(), Some(&b"abcd"[..]));
        closed(tx);
        // SAFETY: the sockets made above.
        unsafe { (libc::close(rx), libc::close(tx)) };
    }

    #[test]
    fn udp_segment_cuts_a_send_into_datagrams() {
        let (rx, tx, to) = udp_pair();
        assert_eq!(set(tx, SOL_UDP, UDP_SEGMENT, 4), 0);
        assert_eq!(send(tx, b"0123456789", &to), 10);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let got: Vec<Vec<u8>> = std::iter::from_fn(|| next(rx)).collect();
        assert_eq!(got, [b"0123".to_vec(), b"4567".to_vec(), b"89".to_vec()]);
        assert_eq!(set(tx, SOL_UDP, UDP_SEGMENT, 70_000), err(errno::EINVAL));
        closed(tx);
        // SAFETY: the sockets made above.
        unsafe { (libc::close(rx), libc::close(tx)) };
    }

    #[test]
    fn other_options_never_reach_the_host() {
        let (rx, tx, _) = udp_pair();
        // An option of the UDP level Linux has but fwe does not
        // (UDP_ENCAP), one it has not, and a level the socket has not.
        assert_eq!(set(tx, SOL_UDP, UDP_ENCAP, 1), err(errno::ENOPROTOOPT));
        assert_eq!(set(tx, SOL_UDP, 999, 1), err(errno::ENOPROTOOPT));
        assert_eq!(get(tx, SOL_UDP, 999), Err(err(errno::ENOPROTOOPT)));
        assert_eq!(set(tx, 6, 1, 1), err(errno::ENOPROTOOPT));
        assert_eq!(set(tx, SOL_UDP, UDP_GRO, 1), 0);
        assert_eq!(get(tx, SOL_UDPLITE, UDP_GRO), Ok(1));
        // SAFETY: the sockets made above.
        unsafe { (libc::close(rx), libc::close(tx)) };
    }
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod fastopen_tests {
    use super::*;

    /// `MSG_FASTOPEN` on an unconnected TCP socket connects and sends; on
    /// a connected one it is `EISCONN`.
    #[test]
    fn fast_open_connects_and_sends() {
        let mut a = [0u8; 16];
        a[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        // SAFETY: no pointers.
        let (srv, cli) = unsafe {
            (socket(AF_INET, SOCK_STREAM, 0) as i32, socket(AF_INET, SOCK_STREAM, 0) as i32)
        };
        // SAFETY: a valid sockaddr.
        assert_eq!(unsafe { bind(srv as u64, a.as_ptr() as u64, 16, true, 0o022) }, 0);
        let mut len: u32 = 16;
        // SAFETY: a writable sockaddr and length.
        let r =
            unsafe { getname(srv as u64, a.as_mut_ptr() as u64, &mut len as *mut _ as u64, false) };
        assert_eq!(r, 0);
        // SAFETY: no pointers.
        assert_eq!(unsafe { listen(srv as u64, 1) }, 0);
        let data = b"hello";
        let send = |addr: u64| {
            // SAFETY: valid buffers.
            unsafe { sendto(cli as u64, data.as_ptr() as u64, 5, MSG_FASTOPEN, addr, 16) }
        };
        assert_eq!(send(a.as_ptr() as u64), 5);
        // SAFETY: no out pointers.
        let conn = unsafe { accept4(srv as u64, 0, 0, 0) } as i32;
        let mut b = [0u8; 8];
        // SAFETY: a valid buffer.
        assert_eq!(unsafe { libc::read(conn, b.as_mut_ptr().cast(), 8) }, 5);
        assert_eq!(&b[..5], data);
        assert_eq!(send(a.as_ptr() as u64), err(errno::EISCONN));
        for fd in [srv, cli, conn] {
            // SAFETY: the sockets made above.
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn protocol(fd: i64) -> i32 {
        let mut v = -1i32;
        let mut len = 4u32;
        // SAFETY: a 4-byte option buffer and its length.
        let r = unsafe {
            getsockopt(
                fd as u64,
                SOL_SOCKET,
                38,
                &mut v as *mut i32 as u64,
                &mut len as *mut u32 as u64,
            )
        };
        assert_eq!(r, 0);
        v
    }

    /// `SO_PROTOCOL` is the protocol the socket was made with: ICMP for a
    /// ping socket, not 0.
    #[test]
    fn so_protocol_is_the_sockets() {
        // SAFETY: no pointers.
        let (tcp, udp, ping) = unsafe {
            (
                socket(AF_INET, SOCK_STREAM, 0),
                socket(AF_INET, SOCK_DGRAM, 0),
                socket(AF_INET, SOCK_DGRAM, 1),
            )
        };
        assert_eq!((protocol(tcp), protocol(udp)), (6, 17));
        if ping >= 0 {
            assert_eq!(protocol(ping), 1);
        }
        for fd in [tcp, udp, ping] {
            // SAFETY: the sockets made above.
            unsafe { libc::close(fd as i32) };
        }
    }

    /// A Unix socket's error queue is empty, as an IP socket's is.
    #[test]
    fn unix_error_queue_is_empty() {
        let mut sv = [0i32; 2];
        // SAFETY: a valid array.
        assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, sv.as_mut_ptr() as u64) }, 0);
        let mut b = [0u8; 4];
        // SAFETY: a valid buffer; the socket's queue holds nothing.
        let r = unsafe { recvfrom(sv[0] as u64, b.as_mut_ptr() as u64, 4, MSG_ERRQUEUE, 0, 0) };
        assert_eq!(r, err(errno::EAGAIN));
        // SAFETY: the sockets made above.
        unsafe { (libc::close(sv[0]), libc::close(sv[1])) };
    }

    /// The IP header before a received ICMP message is measured by its
    /// first byte; a message with none (an ICMP type) has none measured.
    #[test]
    fn ip_header_is_measured() {
        assert_eq!(ip_header_len(&[0x45; 28]), 20);
        assert_eq!(ip_header_len(&[0x46; 28]), 24);
        assert_eq!(ip_header_len(&[0, 0, 0, 0]), 0);
        assert_eq!(ip_header_len(&[8, 0, 0, 0]), 0);
        assert_eq!(ip_header_len(&[]), 0);
    }

    /// A ping socket's datagram is delivered as Linux delivers it, the
    /// ICMP message alone (a datagram socket marked as one stands in for
    /// macOS's, which gives the IP header first), cut to the buffer with
    /// `MSG_TRUNC` giving its whole length.
    #[cfg(target_os = "macos")]
    #[test]
    fn ping_replies_come_without_the_ip_header() {
        let mut sv = [0i32; 2];
        // SAFETY: a valid array.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };
        assert_eq!(r, 0);
        crate::fdmarks::mark(sv[1], crate::fdmarks::Mark::Ping);
        assert!(crate::fdmarks::is_ping(sv[1]));
        let mut d = vec![0x45u8; 20];
        d.extend_from_slice(&[0, 0, 0xab, 0xcd, 0x12, 0x34, 0, 1, b'h', b'i']);
        for _ in 0..3 {
            // SAFETY: a local buffer of its length.
            assert_eq!(unsafe { libc::send(sv[0], d.as_ptr().cast(), d.len(), 0) }, 30);
        }
        let mut b = [0u8; 64];
        // SAFETY: a valid buffer of its length.
        let r = unsafe { recvfrom(sv[1] as u64, b.as_mut_ptr() as u64, 64, 0, 0, 0) };
        assert_eq!(r, 10);
        assert_eq!(&b[..10], &d[20..]);
        // SAFETY: as above.
        let r = unsafe { recvfrom(sv[1] as u64, b.as_mut_ptr() as u64, 4, MSG_TRUNC, 0, 0) };
        assert_eq!((r, &b[..4]), (10, &d[20..24]));
        let iov = [libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 64 }];
        assert_eq!(ping_read(sv[1], &iov), 10);
        crate::fdmarks::closed(sv[1]);
        // SAFETY: the sockets made above.
        unsafe { (libc::close(sv[0]), libc::close(sv[1])) };
    }

    /// A Unix `SOCK_RAW` socket is a datagram one, as Linux makes it.
    #[test]
    fn unix_raw_is_a_datagram_socket() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_UNIX, SOCK_RAW, 0) };
        assert!(fd >= 0, "{fd}");
        let mut ty = -1i32;
        let mut len = 4u32;
        // SAFETY: a 4-byte option buffer and its length.
        let r = unsafe {
            getsockopt(
                fd as u64,
                SOL_SOCKET,
                3,
                &mut ty as *mut i32 as u64,
                &mut len as *mut u32 as u64,
            )
        };
        assert_eq!((r, ty), (0, SOCK_DGRAM as i32));
        // SAFETY: the socket made here.
        unsafe { libc::close(fd as i32) };
    }

    /// A Unix socket bound with its family alone is named as Linux's
    /// autobind names one, and binding it so again changes nothing.
    #[test]
    fn unix_autobind_names_five_hex_digits() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_UNIX, SOCK_DGRAM, 0) };
        let fam = (AF_UNIX as u16).to_ne_bytes();
        // SAFETY: a 2-byte address.
        assert_eq!(unsafe { bind(fd as u64, fam.as_ptr() as u64, 2, false, 0) }, 0);
        let name = |fd: i64| {
            let mut b = [0u8; 110];
            let mut len = b.len() as u32;
            // SAFETY: a buffer and its length.
            let r = unsafe {
                getname(fd as u64, b.as_mut_ptr() as u64, &mut len as *mut u32 as u64, false)
            };
            assert_eq!(r, 0);
            b[..len as usize].to_vec()
        };
        let first = name(fd);
        assert_eq!(first.len(), 8, "{first:?}");
        assert_eq!(&first[..3], &[fam[0], fam[1], 0]);
        assert!(
            first[3..].iter().all(u8::is_ascii_hexdigit)
                && first[3..] == *first[3..].to_ascii_lowercase()
        );
        // SAFETY: as above.
        assert_eq!(unsafe { bind(fd as u64, fam.as_ptr() as u64, 2, false, 0) }, 0);
        assert_eq!(name(fd), first);
        assert_eq!(autobind_name(0xabc), "00abc");
        // SAFETY: the socket made here.
        unsafe { libc::close(fd as i32) };
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod creds_tests {
    use super::scm_tests::{close_all, pair, recv_control, send_control};
    use super::*;

    fn set_passcred(fd: i32) {
        let one = 1i32;
        // SAFETY: a 4-byte option value.
        let r = unsafe {
            setsockopt(fd as u64, SOL_SOCKET, SO_PASSCRED, &one as *const i32 as u64, 4, false)
        };
        assert_eq!(r, 0);
    }

    /// The `SCM_CREDENTIALS` message (Linux layout) of `creds`.
    fn credentials(creds: [u32; 3]) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        c[0..8].copy_from_slice(&28u64.to_ne_bytes());
        c[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
        c[12..16].copy_from_slice(&crate::scm::SCM_CREDENTIALS.to_ne_bytes());
        for (i, w) in creds.iter().enumerate() {
            c[16 + 4 * i..20 + 4 * i].copy_from_slice(&w.to_ne_bytes());
        }
        c
    }

    /// The credentials the control data `c` starts with.
    fn creds_in(c: &[u8]) -> Option<[u32; 3]> {
        let ty = i32::from_ne_bytes(c.get(12..16)?.try_into().ok()?);
        if ty != crate::scm::SCM_CREDENTIALS {
            return None;
        }
        let w = |i: usize| u32::from_ne_bytes(c[16 + 4 * i..20 + 4 * i].try_into().unwrap());
        Some([w(0), w(1), w(2)])
    }

    /// A socket that asked for credentials receives its peer's, or those
    /// the sender gave when it may give them.
    #[test]
    fn credentials_come_when_asked() {
        let _g = super::scm_tests::serial();
        let sv = pair(SOCK_STREAM);
        let me = crate::pidns::to_guest(crate::host::pid()) as u32;
        assert_eq!(send_control(sv[0], &[]), 1);
        let (_, c, _) = recv_control(sv[1], 64, 0);
        assert_eq!(creds_in(&c), None);
        set_passcred(sv[1]);
        assert_eq!(send_control(sv[0], &[]), 1);
        let (_, c, _) = recv_control(sv[1], 64, 0);
        assert_eq!(creds_in(&c).map(|c| c[0]), Some(me));
        // Given: as given (the caller is root, as before any is published).
        let tgid = crate::thread::tgid() as u32;
        assert_eq!(send_control(sv[0], &credentials([tgid, 5, 6])), 1);
        let (_, c, _) = recv_control(sv[1], 64, 0);
        assert_eq!(creds_in(&c).map(|c| c[1..].to_vec()), Some(vec![5, 6]));
        // A pid no process has, or an id nothing maps.
        let bad = send_control(sv[0], &credentials([0x7fff_fff0, 0, 0]));
        assert_eq!(bad, err(errno::ESRCH));
        let bad = send_control(sv[0], &credentials([tgid, u32::MAX, 0]));
        assert_eq!(bad, err(errno::EINVAL));
        closed(sv[1]);
        close_all(&sv);
    }

    /// A datagram to a bound socket that asked for credentials carries the
    /// sender's.
    #[test]
    fn a_datagram_carries_credentials_when_asked() {
        let _g = super::scm_tests::serial();
        // An abstract name: a path would be rooted in whatever filesystem
        // view another test publishes meanwhile.
        let name = format!("fwe-passcred-{}", std::process::id());
        let mut a = [0u8; 110];
        a[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
        a[3..3 + name.len()].copy_from_slice(name.as_bytes());
        let alen = (3 + name.len()) as u64;
        // SAFETY: no pointers.
        let (rx, tx) = unsafe {
            (socket(AF_UNIX, SOCK_DGRAM, 0) as i32, socket(AF_UNIX, SOCK_DGRAM, 0) as i32)
        };
        // SAFETY: a valid address.
        assert_eq!(unsafe { bind(rx as u64, a.as_ptr() as u64, alen, true, 0o022) }, 0);
        set_passcred(rx);
        let byte = *b"x";
        // SAFETY: valid buffers.
        let r = unsafe { sendto(tx as u64, byte.as_ptr() as u64, 1, 0, a.as_ptr() as u64, alen) };
        assert_eq!(r, 1);
        let (_, c, _) = recv_control(rx, 64, 0);
        let me = crate::pidns::to_guest(crate::host::pid()) as u32;
        assert_eq!(creds_in(&c).map(|c| c[0]), Some(me));
        closed(rx);
        close_all(&[rx, tx]);
    }
}

#[cfg(test)]
mod kept_option_tests {
    use super::*;

    fn set(fd: i64, name: u64, val: &[i32], admin: bool) -> i64 {
        // SAFETY: an option value of its length.
        unsafe {
            setsockopt(
                fd as u64,
                SOL_SOCKET,
                name,
                val.as_ptr() as u64,
                4 * val.len() as u64,
                admin,
            )
        }
    }

    /// `SO_LINGER` is in seconds, as Linux's (the host's own is in ticks).
    #[test]
    fn linger_is_in_seconds() {
        // SAFETY: no pointers.
        let s = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert_eq!(set(s, SO_LINGER, &[1, 7], false), 0);
        let mut v = [0i32; 2];
        let mut len = 8u32;
        // SAFETY: an 8-byte buffer and its length.
        let r = unsafe {
            getsockopt(
                s as u64,
                SOL_SOCKET,
                SO_LINGER,
                v.as_mut_ptr() as u64,
                &mut len as *mut u32 as u64,
            )
        };
        assert_eq!((r, v[1] != 0, v[1]), (0, true, 7));
        closed(s as i32);
        // SAFETY: the socket made above.
        unsafe { libc::close(s as i32) };
    }

    /// A priority past 6 needs `CAP_NET_ADMIN`; `accept4` takes Linux's
    /// flags only.
    #[test]
    fn priority_and_accept_flags_are_checked() {
        // SAFETY: no pointers.
        let s = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        assert_eq!(set(s, SO_PRIORITY, &[7], false), err(errno::EPERM));
        assert_eq!(set(s, SO_PRIORITY, &[7], true), 0);
        assert_eq!(set(s, SO_PRIORITY, &[3], false), 0);
        // SAFETY: no out pointers.
        assert_eq!(unsafe { accept4(s as u64, 0, 0, 1) }, err(errno::EINVAL));
        closed(s as i32);
        // SAFETY: the socket made above.
        unsafe { libc::close(s as i32) };
    }

    /// `MSG_TRUNC` on a datagram socket returns the datagram's whole
    /// length, as Linux does.
    #[test]
    fn msg_trunc_gives_the_whole_datagram() {
        let mut sv = [0i32; 2];
        // SAFETY: a valid array.
        assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, sv.as_mut_ptr() as u64) }, 0);
        // SAFETY: a valid buffer.
        assert_eq!(unsafe { libc::send(sv[0], b"0123456789".as_ptr().cast(), 10, 0) }, 10);
        let mut b = [0u8; 4];
        // SAFETY: a valid 4-byte buffer.
        let peek =
            unsafe { recvfrom(sv[1] as u64, b.as_mut_ptr() as u64, 4, MSG_PEEK | MSG_TRUNC, 0, 0) };
        assert_eq!(peek, 10);
        // SAFETY: as above.
        let r = unsafe { recvfrom(sv[1] as u64, b.as_mut_ptr() as u64, 4, MSG_TRUNC, 0, 0) };
        assert_eq!((r, &b), (10, b"0123"));
        // SAFETY: the sockets made above.
        unsafe { (libc::close(sv[0]), libc::close(sv[1])) };
    }
}
