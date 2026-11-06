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
//! has none: making such a socket fails with `EAFNOSUPPORT`.

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
struct Sock {
    peer: i32,
    port: u32,
    ty: i32,
    /// Its opener had `CAP_NET_ADMIN`, which changing a link needs.
    admin: bool,
}

/// The sockets, by the inode of the guest's end (which its duplicates
/// share).
static SOCKS: Mutex<Option<HashMap<u64, Sock>>> = Mutex::new(None);

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
    if crate::netns::current().is_none() {
        return err(errno::EAFNOSUPPORT);
    }
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
    socks(|m| m.insert(ino, Sock { peer, port: 0, ty: base, admin }));
    fd as i64
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

/// `fd` is closed: its host end goes with the last of its descriptors.
pub fn closed(fd: i32) {
    if !is(fd) || fdmarks::shared_elsewhere(fd) {
        return;
    }
    let Some(ino) = inode(fd) else { return };
    if let Some(s) = socks(|m| m.remove(&ino)) {
        // SAFETY: the host end is fwe's own.
        unsafe { libc::close(s.peer) };
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
    while out.len() % 4 != 0 {
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
    let Some(net) = crate::netns::current() else { return err(errno::EAFNOSUPPORT) };
    let Some(ino) = inode(fd) else { return err(errno::EBADF) };
    let port = port_of(fd);
    let Some((peer, admin)) = socks(|m| m.get(&ino).map(|s| (s.peer, s.admin))) else {
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
        // An error (or, asked for, an acknowledgement): the error, then
        // the request's header.
        let ack = |code: i32| {
            let mut b = (-code).to_ne_bytes().to_vec();
            b.extend_from_slice(head);
            message(NLMSG_ERROR, 0, seq, port, &b)
        };
        let up = net.get().lo_up;
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
                    net.update(|n| {
                        n.lo_up = want & IFF_UP != 0;
                        Ok(())
                    })
                    .map(|()| Vec::new())
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
                if flags & NLM_F_ACK != 0 {
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
