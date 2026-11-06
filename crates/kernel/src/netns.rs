//! Network namespaces of fwe's: a loopback interface, and a port space of
//! their own.
//!
//! A socket in such a namespace reaches only loopback addresses, and only
//! while `lo` is up: a bind to another address fails with `EADDRNOTAVAIL`,
//! a connection or a datagram to one with `ENETUNREACH`. Its ports are the
//! namespace's: a bind to a port is a bind to an ephemeral port of the
//! host's loopback, recorded in the namespace's table ([`crate::ns::Net`]),
//! and addresses are translated through it both ways, so two namespaces
//! can each have their own port 80 and neither is reachable from the host
//! or another namespace by its number. A bind to the wildcard address is a
//! bind to the host's loopback.
//!
//! The functions here act on host socket addresses (macOS layout: a length
//! and a family byte, the port, then the address), and do nothing outside
//! such a namespace.

use crate::ns::Net;
use crate::shared::Record;
use fwe_abi::errno;
use std::sync::{Arc, Mutex};

static CURRENT: Mutex<Option<Arc<Record<Net>>>> = Mutex::new(None);

/// The process's network namespace, if it is one of fwe's.
pub fn current() -> Option<Arc<Record<Net>>> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Make `net` the process's ([`crate::ns::Namespaces::net`]).
pub fn set_current(net: Option<Arc<Record<Net>>>) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = net;
}

/// TCP and UDP, the protocols ports are kept for.
const TCP: u8 = 6;
const UDP: u8 = 17;

fn proto(fd: i32) -> u8 {
    let mut ty: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid out-parameters.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if ty == libc::SOCK_DGRAM { UDP } else { TCP }
}

/// An inet address in host layout: its family, port and whether it is a
/// loopback or wildcard address.
struct Inet {
    v6: bool,
    port: u16,
    loopback: bool,
    any: bool,
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

fn parse(hb: &[u8]) -> Option<Inet> {
    let fam = family(hb);
    if fam == libc::AF_INET {
        let a = &hb[4..8];
        return Some(Inet {
            v6: false,
            port: u16::from_be_bytes([hb[2], hb[3]]),
            loopback: a[0] == 127,
            any: a == [0, 0, 0, 0],
        });
    }
    if fam == libc::AF_INET6 {
        let a = &hb[8..24];
        let mapped = a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff;
        let one = a[..15].iter().all(|&b| b == 0) && a[15] == 1;
        let loopback = one || mapped && a[12] == 127;
        return Some(Inet {
            v6: true,
            port: u16::from_be_bytes([hb[2], hb[3]]),
            loopback,
            any: a.iter().all(|&b| b == 0),
        });
    }
    None
}

fn set_port(hb: &mut [u8], port: u16) {
    hb[2..4].copy_from_slice(&port.to_be_bytes());
}

/// Make the address the host's loopback (`127.0.0.1` or `::1`).
fn set_loopback(hb: &mut [u8], v6: bool) {
    if v6 {
        hb[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    } else {
        hb[4..8].copy_from_slice(&[127, 0, 0, 1]);
    }
}

/// The host port the namespace's port `port` of `proto` is bound to.
fn host_port(net: &Record<Net>, proto: u8, port: u16) -> Option<u16> {
    net.get().ports.get(&(proto, port)).copied()
}

/// Whether host loopback port `host` of `proto` is still bound by someone
/// (a mapping to it is not stale).
fn in_use(proto: u8, v6: bool, host: u16) -> bool {
    let (fam, ty) = (
        if v6 { libc::AF_INET6 } else { libc::AF_INET },
        if proto == UDP { libc::SOCK_DGRAM } else { libc::SOCK_STREAM },
    );
    // SAFETY: plain host calls on a socket of our own, closed after.
    unsafe {
        let s = libc::socket(fam, ty, 0);
        if s < 0 {
            return true;
        }
        let mut hb = [0u8; 28];
        let len = if v6 { 28 } else { 16 };
        #[cfg(target_os = "linux")]
        hb[0..2].copy_from_slice(&(fam as u16).to_ne_bytes());
        #[cfg(not(target_os = "linux"))]
        {
            hb[0] = len as u8;
            hb[1] = fam as u8;
        }
        set_port(&mut hb, host);
        set_loopback(&mut hb, v6);
        let free = libc::bind(s, hb.as_ptr().cast(), len as libc::socklen_t) == 0;
        libc::close(s);
        !free
    }
}

/// What a `bind` in the namespace does once the host's bind is made:
/// record the namespace's port for the host's.
pub struct Plan {
    proto: u8,
    port: u16,
    any: bool,
}

/// Before `bind` of `fd` to the host address `hb` (an inet one): check the
/// address and make it a host loopback address with an ephemeral port, as
/// the namespace's port is to be. `may_low` says the caller may bind a
/// port below 1024.
pub fn bind_prepare(fd: i32, hb: &mut [u8], may_low: bool) -> Result<Option<Plan>, i32> {
    let Some(net) = current() else { return Ok(None) };
    let Some(a) = parse(hb) else { return Ok(None) };
    if !(a.loopback || a.any) || a.loopback && !net.get().lo_up {
        return Err(errno::EADDRNOTAVAIL);
    }
    let proto = proto(fd);
    if a.port != 0 {
        if a.port < crate::sysctl::unprivileged_port_start() && !may_low {
            return Err(errno::EACCES);
        }
        if let Some(h) = host_port(&net, proto, a.port)
            && in_use(proto, a.v6, h)
        {
            return Err(errno::EADDRINUSE);
        }
    }
    set_loopback(hb, a.v6);
    set_port(hb, 0);
    Ok(Some(Plan { proto, port: a.port, any: a.any }))
}

/// After the host's `bind` of `fd` (per `plan`) succeeded: record the
/// namespace's port for the host's.
pub fn bind_done(fd: i32, plan: Plan) {
    let Some(net) = current() else { return };
    let mut hb = [0u8; 128];
    let mut hl = hb.len() as libc::socklen_t;
    // SAFETY: valid out-parameters.
    if unsafe { libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) } != 0 {
        return;
    }
    let Some(a) = parse(&hb) else { return };
    // An ephemeral port is the host's own number.
    let port = if plan.port == 0 { a.port } else { plan.port };
    let _ = net.update(|n| {
        n.ports.insert((plan.proto, port), a.port);
        Ok(())
    });
    crate::fdmarks::mark(fd, crate::fdmarks::Mark::NetBound { port, any: plan.any });
}

/// Before `connect` of `fd`, or a datagram sent, to the host address `hb`:
/// only a loopback address, and the namespace's port is the host's it is
/// bound to (`ECONNREFUSED` for a stream to one nothing is bound to).
pub fn connect_prepare(fd: i32, hb: &mut [u8]) -> Result<(), i32> {
    let Some(net) = current() else { return Ok(()) };
    let Some(a) = parse(hb) else { return Ok(()) };
    if a.any {
        // Linux takes the wildcard as this host's loopback.
        set_loopback(hb, a.v6);
    } else if !a.loopback || !net.get().lo_up {
        return Err(errno::ENETUNREACH);
    }
    let proto = proto(fd);
    match host_port(&net, proto, a.port) {
        Some(h) => set_port(hb, h),
        // A stream to a port nobody bound here is refused; a datagram to a
        // socket's own host-chosen port (one never bound by number) goes
        // there.
        None if proto == TCP => return Err(errno::ECONNREFUSED),
        None => {}
    }
    Ok(())
}

/// A host address `hb` the guest is given back, as the namespace numbers
/// it: `local` for the socket's own (`getsockname`), else a peer's.
pub fn to_guest(fd: i32, hb: &mut [u8], local: bool) {
    let Some(net) = current() else { return };
    let Some(a) = parse(hb) else { return };
    if local && let Some(crate::fdmarks::Mark::NetBound { port, any }) = crate::fdmarks::marked(fd)
    {
        set_port(hb, port);
        if any {
            let zero = if a.v6 { 8..24 } else { 4..8 };
            hb[zero].iter_mut().for_each(|b| *b = 0);
        }
        return;
    }
    let proto = proto(fd);
    let found = net
        .get()
        .ports
        .iter()
        .find(|((p, _), h)| *p == proto && **h == a.port)
        .map(|((_, port), _)| *port);
    if let Some(port) = found {
        set_port(hb, port);
    }
}

/// `fd`, bound in the namespace, is closed: its port is free again unless
/// another descriptor of this process holds the socket.
pub fn closed(fd: i32, mark: Option<crate::fdmarks::Mark>) {
    let Some(net) = current() else { return };
    let Some(crate::fdmarks::Mark::NetBound { port, .. }) = mark else { return };
    let proto = proto(fd);
    let _ = net.update(|n| {
        n.ports.remove(&(proto, port));
        Ok(())
    });
}
