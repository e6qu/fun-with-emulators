//! `AF_NETLINK` sockets of the `NETLINK_ROUTE` family, in a network
//! namespace of fwe's: what a container runtime asks of its loopback
//! interface.
//!
//! The guest's descriptor is one end of a host datagram socket pair, so
//! receiving from it, `poll` and `epoll` are the host's own. A request
//! the guest sends is answered at once: fwe writes each reply message to
//! the other end, where the guest receives it, as the kernel queues
//! replies on the socket. The namespace has one interface, `lo` (index
//! 1), which `RTM_GETLINK` describes, `RTM_NEWLINK` brings up or down
//! (with `CAP_NET_ADMIN`), and whose addresses `RTM_GETADDR` lists once it
//! is up; any other request is answered with `EOPNOTSUPP`, as the kernel
//! answers one it has no handler for.
//!
//! In the initial network namespace, whose interfaces are the host's, fwe
//! describes the host's loopback as `lo`, always up, with its addresses:
//! bringing it up changes nothing, taking it down is refused (`EPERM`).
//! The host's other interfaces are not described. Such a socket also
//! carries what the kernel itself sends it: a message queue's
//! notification ([`crate::mqueue`]), for which [`bind_for_notify`] gives
//! the socket a host address another process can send to.

use crate::fdmarks::{self, Mark};
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::sync::Mutex;

pub const AF_NETLINK: u64 = 16;
const NETLINK_ROUTE: u64 = 0;
/// `SOL_NETLINK`, whose options are accepted and change nothing.
pub const SOL_NETLINK: u64 = 270;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x10000;
const ARPHRD_LOOPBACK: u16 = 772;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

/// The header every netlink message starts with.
const HEADER: usize = 16;

/// One netlink socket: the host end fwe answers through, the port it is
/// bound to, and the type the guest made it with.
pub(crate) struct Sock {
    peer: i32,
    port: u32,
    ty: i32,
    /// Its opener had `CAP_NET_ADMIN`, which changing a link needs.
    admin: bool,
    /// The network namespace it was made in, which it answers for (none:
    /// the initial one).
    net: Option<std::sync::Arc<crate::shared::Record<crate::ns::Net>>>,
    /// The host path the guest's end is bound to, once a message queue's
    /// notification is to come to it ([`bind_for_notify`]), and the host
    /// process that bound it (which alone removes it: a fork child that
    /// closes its copy leaves it).
    bound: Option<(Vec<u8>, i32)>,
}

/// The most a socket's queue holds, and the largest request: Linux's
/// default socket buffer.
const BUFFER: usize = 212_992;

/// `NLM_F_CAPPED`: an acknowledgement carries only the request's header.
const NLM_F_CAPPED: u16 = 0x100;

/// The sockets, by the inode of the guest's end (which its duplicates
/// share).
pub(crate) static SOCKS: Mutex<Option<HashMap<u64, Sock>>> = Mutex::new(None);

fn socks<R>(f: impl FnOnce(&mut HashMap<u64, Sock>) -> R) -> R {
    let mut g = SOCKS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

#[allow(clippy::unnecessary_cast)] // `ino_t` differs by host
fn inode(fd: i32) -> Option<u64> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino as u64)
}

/// Whether `fd` is one of fwe's netlink sockets.
pub fn is(fd: i32) -> bool {
    fdmarks::any_marks() && fdmarks::marked(fd) == Some(Mark::Netlink)
}

/// `socket(AF_NETLINK, type_, protocol)`: `type_` with its
/// `SOCK_NONBLOCK` and `SOCK_CLOEXEC`.
pub fn socket(type_: u64, protocol: u64, admin: bool) -> i64 {
    use fwe_abi::socket::{SOCK_CLOEXEC, SOCK_NONBLOCK};
    let net = crate::netns::current();
    let base = (type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC)) as i32;
    // SOCK_RAW and SOCK_DGRAM.
    if base != 3 && base != 2 {
        return err(errno::ESOCKTNOSUPPORT);
    }
    if protocol != NETLINK_ROUTE {
        return err(errno::EPROTONOSUPPORT);
    }
    let mut pair = [0i32; 2];
    // SAFETY: a valid out-array of two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, pair.as_mut_ptr()) } != 0 {
        return crate::host::last_error();
    }
    let peer = match crate::fdtable::reserve(pair[1]) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: closing the descriptor just made.
            unsafe { libc::close(pair[0]) };
            return err(e);
        }
    };
    let fd = pair[0];
    room(fd, peer);
    // SAFETY: plain host calls on the new descriptor.
    unsafe {
        if type_ & SOCK_CLOEXEC != 0 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        if type_ & SOCK_NONBLOCK != 0 {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
    }
    let Some(ino) = inode(fd) else { return err(errno::EBADF) };
    fdmarks::mark(fd, Mark::Netlink);
    socks(|m| m.insert(ino, Sock { peer, port: 0, ty: base, admin, net, bound: None }));
    fd as i64
}

/// Room for the replies a burst of requests queues on guest end `fd`, sent
/// from fwe's end `peer`, as on Linux (a host datagram socket holds 4 KiB,
/// and drops the rest).
fn room(fd: i32, peer: i32) {
    for (end, opt) in [(fd, libc::SO_RCVBUF), (peer, libc::SO_SNDBUF)] {
        let v = BUFFER as libc::c_int;
        // SAFETY: a valid option value.
        unsafe {
            libc::setsockopt(end, libc::SOL_SOCKET, opt, (&v as *const libc::c_int).cast(), 4)
        };
    }
}

/// Give netlink socket `fd` a host address another process can send to,
/// `path` (a path no other socket is given), unless it has one: the
/// address it has. A message queue's
/// notification for the socket is sent there ([`notify`]).
///
/// The guest's end of a host socket pair can have no address, so it is
/// replaced: a new datagram socket bound to `path` takes the descriptor
/// (its flags kept), and fwe's end is a new one connected to it.
pub fn bind_for_notify(fd: i32, path: &[u8]) -> Result<Vec<u8>, i32> {
    let ino = inode(fd).ok_or(errno::EBADF)?;
    if let Some((p, _)) = socks(|m| m.get(&ino).and_then(|s| s.bound.clone())) {
        return Ok(p);
    }
    let fresh = || {
        // SAFETY: plain host call.
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        if s < 0 { Err(crate::host::errno_to_linux(crate::host::last_errno())) } else { Ok(s) }
    };
    let close = |s: i32| {
        // SAFETY: a descriptor made here.
        unsafe { libc::close(s) };
    };
    let fail = || crate::host::errno_to_linux(crate::host::last_errno());
    let own = fresh()?;
    if let Ok(c) = std::ffi::CString::new(path) {
        // SAFETY: a NUL-terminated path in fwe's private directory.
        unsafe { libc::unlink(c.as_ptr()) };
    }
    // SAFETY: a valid address of the length given.
    let bound = crate::net::at_unix_path(path, |a, l| unsafe { libc::bind(own, a, l) });
    if bound != Ok(0) {
        close(own);
        return Err(bound.err().unwrap_or_else(fail));
    }
    let peer = match fresh() {
        Ok(p) => p,
        Err(e) => {
            close(own);
            return Err(e);
        }
    };
    // SAFETY: as above.
    let joined = crate::net::at_unix_path(path, |a, l| unsafe { libc::connect(peer, a, l) });
    let peer = match (joined, crate::fdtable::reserve(peer)) {
        (Ok(0), Ok(p)) => p,
        (_, r) => {
            close(own);
            if let Ok(p) = r {
                close(p);
            }
            return Err(errno::ENOBUFS);
        }
    };
    room(own, peer);
    // SAFETY: plain host calls on the guest's descriptor and the new one,
    // which takes its number.
    let moved = unsafe {
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        let fl_flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(own, libc::F_SETFL, fl_flags & libc::O_NONBLOCK);
        let r = libc::dup2(own, fd);
        libc::fcntl(fd, libc::F_SETFD, fd_flags & libc::FD_CLOEXEC);
        libc::close(own);
        r == fd
    };
    if !moved {
        close(peer);
        return Err(fail());
    }
    let new_ino = inode(fd).ok_or(errno::EBADF)?;
    fdmarks::mark(fd, Mark::Netlink);
    socks(|m| {
        if let Some(mut s) = m.remove(&ino) {
            close(s.peer);
            s.peer = peer;
            // SAFETY: getpid cannot fail.
            s.bound = Some((path.to_vec(), unsafe { libc::getpid() }));
            m.insert(new_ino, s);
        }
    });
    Ok(path.to_vec())
}

/// Send `cookie` to the netlink socket bound at host `path` (by
/// [`bind_for_notify`], in any process), as the kernel sends a message
/// queue's notification. Whether it was sent.
pub fn notify(path: &[u8], cookie: &[u8]) -> bool {
    // SAFETY: plain host call.
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return false;
    }
    // SAFETY: a valid buffer and address of the lengths given.
    let r = crate::net::at_unix_path(path, |a, l| unsafe {
        libc::sendto(s, cookie.as_ptr().cast(), cookie.len(), 0, a, l) as i32
    });
    // SAFETY: the descriptor made here.
    unsafe { libc::close(s) };
    r == Ok(cookie.len() as i32)
}

/// The socket's type, as the guest made it (`SO_TYPE`).
pub fn sock_type(fd: i32) -> Option<i32> {
    let ino = inode(fd)?;
    socks(|m| m.get(&ino).map(|s| s.ty))
}

/// A port nobody has: this process's pid for its first socket, then
/// numbers below zero, as Linux assigns them.
fn fresh_port(taken: &HashMap<u64, Sock>) -> u32 {
    let pid = crate::thread::tgid() as u32;
    if !taken.values().any(|s| s.port == pid) {
        return pid;
    }
    let mut p = u32::MAX;
    while taken.values().any(|s| s.port == p) {
        p -= 1;
    }
    p
}

/// `bind(fd, addr, len)`: a `sockaddr_nl`, its port 0 for one of fwe's
/// choosing.
pub fn bind(fd: i32, addr: u64, len: u64) -> i64 {
    if len < 12 {
        return err(errno::EINVAL);
    }
    let Ok(a) = crate::uaccess::read::<[u32; 3]>(addr) else { return err(errno::EFAULT) };
    if a[0] & 0xffff != AF_NETLINK as u32 {
        return err(errno::EINVAL);
    }
    let Some(ino) = inode(fd) else { return err(errno::EBADF) };
    socks(|m| {
        let port = if a[1] == 0 { fresh_port(m) } else { a[1] };
        if a[1] != 0 && m.iter().any(|(i, s)| *i != ino && s.port == port) {
            return err(errno::EADDRINUSE);
        }
        match m.get_mut(&ino) {
            // Bound already (explicitly, or by a send): Linux refuses.
            Some(s) if s.port != 0 && s.port != port => err(errno::EINVAL),
            Some(s) => {
                s.port = port;
                0
            }
            None => err(errno::EBADF),
        }
    })
}

/// `getsockname` (or `getpeername`, `peer`: the kernel, port 0) into the
/// `sockaddr_nl` at `addr`, its room at `len`.
pub fn getname(fd: i32, addr: u64, len: u64, peer: bool) -> i64 {
    let port = if peer { 0 } else { port_of(fd) };
    write_name(addr, len, port)
}

fn port_of(fd: i32) -> u32 {
    let Some(ino) = inode(fd) else { return 0 };
    socks(|m| {
        // Bound on first use, as Linux binds a socket that sends unbound.
        let fresh = fresh_port(m);
        m.get_mut(&ino).map_or(0, |s| {
            if s.port == 0 {
                s.port = fresh;
            }
            s.port
        })
    })
}

/// Write a `sockaddr_nl` of port `port` to `addr`, its room at `len` (a
/// guest `socklen_t`).
pub fn write_name(addr: u64, len: u64, port: u32) -> i64 {
    let Ok(room) = crate::uaccess::read::<u32>(len) else { return err(errno::EFAULT) };
    let mut b = [0u8; 12];
    b[0..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    b[4..8].copy_from_slice(&port.to_ne_bytes());
    let n = (room as usize).min(12);
    if crate::uaccess::write_from(addr, &b[..n]).is_err()
        || crate::uaccess::write(len, 12u32).is_err()
    {
        return err(errno::EFAULT);
    }
    0
}

/// The length of the next message waiting on `fd`, if one is (macOS's
/// `SO_NREAD` gives a datagram socket's first).
pub fn next_len(fd: i32) -> Option<usize> {
    #[cfg(target_os = "macos")]
    {
        let mut n: libc::c_int = 0;
        let mut l = 4 as libc::socklen_t;
        // SAFETY: valid out-parameters.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NREAD,
                (&mut n as *mut libc::c_int).cast(),
                &mut l,
            )
        };
        (r == 0 && n > 0).then_some(n as usize)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        None
    }
}

/// Whether a request of `len` bytes is too large for a socket (Linux's
/// `EMSGSIZE`): checked before anything is copied for it.
pub fn too_large(len: u64) -> bool {
    len > BUFFER as u64
}

/// Write the sockets into an exec state or fork snapshot (`exec`: the
/// host ends survive the host `execve` that re-executes fwe).
pub(crate) fn save(e: &mut crate::snapshot::Enc, exec: bool) {
    socks(|m| {
        e.u64(m.len() as u64);
        for (&ino, s) in m.iter() {
            if exec {
                // SAFETY: plain host call on fwe's own descriptor.
                unsafe { libc::fcntl(s.peer, libc::F_SETFD, 0) };
            }
            e.u64(ino);
            e.i32(s.peer);
            e.u32(s.port);
            e.i32(s.ty);
            e.bool(s.admin);
            e.bool(s.bound.is_some());
            let (path, by) = s.bound.clone().unwrap_or_default();
            e.bytes(&path);
            e.i32(by);
        }
    });
}

/// What [`save`] wrote, in the new process (in the namespace it runs in,
/// which an exec or fork keeps).
pub(crate) fn load(d: &mut crate::snapshot::Dec) {
    let n = d.count(34);
    let mut read = Vec::new();
    for _ in 0..n {
        let (ino, peer, port, ty, admin) = (d.u64(), d.i32(), d.u32(), d.i32(), d.bool());
        let (some, path, by) = (d.bool(), d.bytes(), d.i32());
        read.push((ino, peer, port, ty, admin, some.then_some((path, by))));
    }
    let net = crate::netns::current();
    socks(|m| {
        for (ino, peer, port, ty, admin, bound) in read {
            // SAFETY: plain host call on fwe's own descriptor.
            if unsafe { libc::fcntl(peer, libc::F_SETFD, libc::FD_CLOEXEC) } == 0 {
                m.insert(ino, Sock { peer, port, ty, admin, net: net.clone(), bound });
            }
        }
    });
}

/// `fd` is closed: its host end goes with the last of its descriptors.
pub fn closed(fd: i32) {
    if !is(fd) || fdmarks::shared_elsewhere(fd) {
        return;
    }
    let Some(ino) = inode(fd) else { return };
    if let Some(s) = socks(|m| m.remove(&ino)) {
        // SAFETY: the host end is fwe's own.
        unsafe { libc::close(s.peer) };
        // Its address (one no other socket is given) goes with it, in the
        // process that bound it.
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let path = s.bound.filter(|&(_, by)| by == me).map(|(p, _)| p);
        if let Some(c) = path.and_then(|p| std::ffi::CString::new(p).ok()) {
            // SAFETY: a NUL-terminated path in fwe's private directory.
            unsafe { libc::unlink(c.as_ptr()) };
        }
    }
}

/// A message: its header for `seq` and `port`, then `body`.
fn message(ty: u16, flags: u16, seq: u32, port: u32, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER + body.len());
    m.extend_from_slice(&((HEADER + body.len()) as u32).to_ne_bytes());
    m.extend_from_slice(&ty.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&port.to_ne_bytes());
    m.extend_from_slice(body);
    m
}

/// An attribute: its length and type, its value, padded to 4 bytes.
fn attr(out: &mut Vec<u8>, ty: u16, value: &[u8]) {
    out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The attributes of the message body `b` after its fixed part of `fixed`
/// bytes, as (type, value).
fn attrs(b: &[u8], fixed: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = fixed;
    while at + 4 <= b.len() {
        let len = u16::from_ne_bytes([b[at], b[at + 1]]) as usize;
        let ty = u16::from_ne_bytes([b[at + 2], b[at + 3]]) & 0x3fff;
        if len < 4 || at + len > b.len() {
            break;
        }
        out.push((ty, &b[at + 4..at + len]));
        at += (len + 3) & !3;
    }
    out
}

/// The `lo` interface's `RTM_NEWLINK` body: up or not.
fn link_body(up: bool) -> Vec<u8> {
    let flags = IFF_LOOPBACK | if up { IFF_UP | IFF_RUNNING | IFF_LOWER_UP } else { 0 };
    let mut b = Vec::new();
    b.push(0); // family
    b.push(0);
    b.extend_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
    b.extend_from_slice(&1i32.to_ne_bytes()); // index
    b.extend_from_slice(&flags.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes()); // change
    attr(&mut b, IFLA_IFNAME, b"lo\0");
    attr(&mut b, IFLA_MTU, &65536u32.to_ne_bytes());
    attr(&mut b, IFLA_TXQLEN, &1000u32.to_ne_bytes());
    // IF_OPER_UNKNOWN as Linux reports for an up loopback, else DOWN.
    attr(&mut b, IFLA_OPERSTATE, &[if up { 0 } else { 2 }]);
    attr(&mut b, IFLA_ADDRESS, &[0; 6]);
    attr(&mut b, IFLA_BROADCAST, &[0; 6]);
    b
}

/// The `RTM_NEWADDR` bodies of `lo`'s addresses of `family` (0 for
/// both).
fn addr_bodies(family: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // AF_INET: 127.0.0.1/8, host scope.
    if family == 0 || family == 2 {
        let mut b = vec![2, 8, 0x80, 254];
        b.extend_from_slice(&1u32.to_ne_bytes());
        attr(&mut b, IFA_ADDRESS, &[127, 0, 0, 1]);
        attr(&mut b, IFA_LOCAL, &[127, 0, 0, 1]);
        attr(&mut b, IFA_LABEL, b"lo\0");
        out.push(b);
    }
    // AF_INET6: ::1/128.
    if family == 0 || family == 10 {
        let mut b = vec![10, 128, 0x80, 254];
        b.extend_from_slice(&1u32.to_ne_bytes());
        let mut one = [0u8; 16];
        one[15] = 1;
        attr(&mut b, IFA_ADDRESS, &one);
        out.push(b);
    }
    out
}

/// A request the guest sent on `fd` (`data`, one or more messages):
/// answered on the socket. Returns the bytes taken, or the error.
pub fn send(fd: i32, data: &[u8]) -> i64 {
    if too_large(data.len() as u64) {
        return err(errno::EMSGSIZE);
    }
    let Some(ino) = inode(fd) else { return err(errno::EBADF) };
    let port = port_of(fd);
    let Some((peer, admin, net)) = socks(|m| m.get(&ino).map(|s| (s.peer, s.admin, s.net.clone())))
    else {
        return err(errno::EBADF);
    };
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let mut at = 0;
    while at + HEADER <= data.len() {
        let len = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap()) as usize;
        if len < HEADER || at + len > data.len() {
            break;
        }
        let ty = u16::from_ne_bytes([data[at + 4], data[at + 5]]);
        let flags = u16::from_ne_bytes([data[at + 6], data[at + 7]]);
        let seq = u32::from_ne_bytes(data[at + 8..at + 12].try_into().unwrap());
        let head = &data[at..at + HEADER];
        let body = &data[at + HEADER..at + len];
        // An acknowledgement (the request's header, capped) or an error
        // (the whole request), as Linux sends them.
        let whole = &data[at..at + len];
        let ack = |code: i32| {
            let mut b = (-code).to_ne_bytes().to_vec();
            let flags = if code == 0 {
                b.extend_from_slice(head);
                NLM_F_CAPPED
            } else {
                b.extend_from_slice(whole);
                0
            };
            message(NLMSG_ERROR, flags, seq, port, &b)
        };
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        // The initial namespace's loopback is the host's, always up.
        let up = net.as_ref().is_none_or(|n| n.get().lo_up);
        let result: Result<Vec<Vec<u8>>, i32> = match ty {
            RTM_GETLINK if flags & NLM_F_DUMP == NLM_F_DUMP => Ok(vec![
                message(RTM_NEWLINK, NLM_F_MULTI, seq, port, &link_body(up)),
                message(NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_ne_bytes()),
            ]),
            RTM_GETLINK => {
                if names_lo(body) {
                    Ok(vec![message(RTM_NEWLINK, 0, seq, port, &link_body(up))])
                } else {
                    Err(errno::ENODEV)
                }
            }
            RTM_NEWLINK if body.len() >= 16 => {
                let change = u32::from_ne_bytes(body[12..16].try_into().unwrap());
                let want = u32::from_ne_bytes(body[8..12].try_into().unwrap());
                if !names_lo(body) {
                    Err(errno::ENODEV)
                } else if !admin {
                    Err(errno::EPERM)
                } else if change & IFF_UP != 0 || change == 0 {
                    match &net {
                        Some(net) => net
                            .update(|n| {
                                n.lo_up = want & IFF_UP != 0;
                                Ok(())
                            })
                            .map(|()| Vec::new()),
                        // The host's stays up.
                        None if want & IFF_UP != 0 => Ok(Vec::new()),
                        None => Err(errno::EPERM),
                    }
                } else {
                    Ok(Vec::new())
                }
            }
            RTM_GETADDR => {
                let family = body.first().copied().unwrap_or(0);
                let mut out: Vec<Vec<u8>> = if up {
                    addr_bodies(family)
                        .iter()
                        .map(|b| message(RTM_NEWADDR, NLM_F_MULTI, seq, port, b))
                        .collect()
                } else {
                    Vec::new()
                };
                out.push(message(NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_ne_bytes()));
                Ok(out)
            }
            _ => Err(errno::EOPNOTSUPP),
        };
        match result {
            Ok(msgs) => {
                replies.extend(msgs);
                // A dump ends with its NLMSG_DONE, never an ACK.
                if flags & NLM_F_ACK != 0 && !dump {
                    replies.push(ack(0));
                }
            }
            Err(e) => replies.push(ack(e)),
        }
        at += (len + 3) & !3;
    }
    for r in replies {
        // SAFETY: a valid buffer; the host end is fwe's.
        unsafe { libc::send(peer, r.as_ptr().cast(), r.len(), 0) };
    }
    data.len() as i64
}

/// Whether an `ifinfomsg` request body names `lo`: its index 1, or the
/// name `lo` with no index.
fn names_lo(body: &[u8]) -> bool {
    if body.len() < 16 {
        return false;
    }
    let index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
    if index != 0 {
        return index == 1;
    }
    attrs(body, 16)
        .iter()
        .find(|(t, _)| *t == IFLA_IFNAME)
        .is_some_and(|(_, v)| v.split(|&b| b == 0).next() == Some(&b"lo"[..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lo_by_index_or_name() {
        let mut body = vec![0u8; 16];
        body[4..8].copy_from_slice(&1i32.to_ne_bytes());
        assert!(names_lo(&body));
        let mut body = vec![0u8; 16];
        attr(&mut body, IFLA_IFNAME, b"lo\0");
        assert!(names_lo(&body));
        let mut body = vec![0u8; 16];
        attr(&mut body, IFLA_IFNAME, b"eth0\0");
        assert!(!names_lo(&body));
    }

    #[test]
    fn link_message_parses_back() {
        let b = link_body(true);
        let a = attrs(&b, 16);
        assert!(a.iter().any(|(t, v)| *t == IFLA_IFNAME && *v == b"lo\0"));
        assert_eq!(u32::from_ne_bytes(b[8..12].try_into().unwrap()) & IFF_UP, IFF_UP);
    }
}
