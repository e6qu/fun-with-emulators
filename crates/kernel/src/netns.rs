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
//! The host's own namespace keeps such a table for one thing the host
//! refuses there: a port below 1024 on a loopback address, for a caller
//! that may bind one (`CAP_NET_BIND_SERVICE`) when fwe does not run as
//! root. macOS lets anyone bind such a port on the wildcard address but
//! only root on a given one, where Linux lets the capability do both. The
//! socket is bound to an ephemeral port of the same address instead, and
//! the pair recorded ([`host_low_ports`]), so fwe's processes reach the
//! socket, and see it, by its number; a program that is not fwe's finds
//! nothing there.
//!
//! The functions here act on host socket addresses (macOS layout: a length
//! and a family byte, the port, then the address).

use crate::ns::Net;
use crate::shared::Record;
use fwe_abi::errno;
use std::sync::{Arc, Mutex};

static CURRENT: Mutex<Option<Arc<Record<Net>>>> = Mutex::new(None);

thread_local! {
    /// This thread's own network namespace, when it has its own
    /// ([`crate::threadfs`]): `Some(None)` for the initial one.
    static THREAD: std::cell::RefCell<Option<Option<Arc<Record<Net>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// The calling thread's network namespace, if it is one of fwe's.
pub fn current() -> Option<Arc<Record<Net>>> {
    if let Some(own) = THREAD.with(|t| t.borrow().clone()) {
        return own;
    }
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Make `net` this thread's own (`Some`), or the process's again (`None`).
pub fn set_thread(net: Option<Option<Arc<Record<Net>>>>) {
    THREAD.with(|t| *t.borrow_mut() = net);
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

/// Ports below this are root's on the host, on an address of its own.
const HOST_LOW: u16 = 1024;

/// The host namespace's low loopback ports, each by protocol (with
/// [`V6`] for IPv6) and number, and the host port behind it.
fn host_low_ports() -> Option<&'static Record<Net>> {
    static R: std::sync::OnceLock<Option<Record<Net>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Record::named("host-low-ports", 0, Net::default).ok()).as_ref()
}

/// Marks an IPv6 port's protocol in [`host_low_ports`]: `127.0.0.1` and
/// `::1` are each a port space.
const V6: u8 = 0x80;

/// Whether host port `port` of address `hb`, for `proto`, is still bound
/// by someone (a mapping to it is not stale).
fn in_use_at(proto: u8, hb: &[u8], port: u16) -> bool {
    let fam = family(hb);
    let ty = if proto & !V6 == UDP { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
    let len = if fam == libc::AF_INET6 { 28 } else { 16 };
    let mut a = [0u8; 28];
    a[..len].copy_from_slice(&hb[..len]);
    set_port(&mut a, port);
    // SAFETY: plain host calls on a socket of our own, closed after.
    unsafe {
        let s = libc::socket(fam, ty, 0);
        if s < 0 {
            return true;
        }
        let free = libc::bind(s, a.as_ptr().cast(), len as libc::socklen_t) == 0;
        libc::close(s);
        !free
    }
}

/// The key of a port of `fd` at `a` in [`host_low_ports`].
fn host_key(fd: i32, a: &Inet) -> u8 {
    proto(fd) | if a.v6 { V6 } else { 0 }
}

/// [`bind_prepare`] in the host's namespace.
fn host_bind_prepare(fd: i32, hb: &mut [u8], may_low: bool) -> Result<Option<Plan>, i32> {
    let Some(a) = parse(hb) else { return Ok(None) };
    // SAFETY: plain host call.
    let root = unsafe { libc::geteuid() } == 0;
    if a.port == 0 || a.port >= HOST_LOW || !a.loopback || a.any || !may_low || root {
        return Ok(None);
    }
    let Some(t) = host_low_ports() else { return Ok(None) };
    let key = host_key(fd, &a);
    if let Some(h) = host_port(t, key, a.port)
        && in_use_at(key, hb, h)
    {
        return Err(errno::EADDRINUSE);
    }
    set_port(hb, 0);
    Ok(Some(Plan { proto: key, port: a.port, any: false }))
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
    let Some(net) = current() else { return host_bind_prepare(fd, hb, may_low) };
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
    let net = current();
    let table: &Record<Net> = match (net.as_deref(), host_low_ports()) {
        (Some(n), _) => n,
        (None, Some(t)) => t,
        (None, None) => return,
    };
    let mut hb = [0u8; 128];
    let mut hl = hb.len() as libc::socklen_t;
    // SAFETY: valid out-parameters.
    if unsafe { libc::getsockname(fd, hb.as_mut_ptr().cast(), &mut hl) } != 0 {
        return;
    }
    let Some(a) = parse(&hb) else { return };
    // An ephemeral port is the host's own number.
    let port = if plan.port == 0 { a.port } else { plan.port };
    let _ = table.update(|n| {
        // (A mapping to the same host port is a stale one.)
        n.ports.retain(|&(p, _), h| p != plan.proto || *h != a.port);
        n.ports.insert((plan.proto, port), a.port);
        Ok(())
    });
    crate::fdmarks::mark(
        fd,
        crate::fdmarks::Mark::NetBound { port, any: plan.any, key: plan.proto },
    );
}

/// Before `connect` of `fd`, or a datagram sent, to the host address `hb`:
/// only a loopback address, and the namespace's port is the host's it is
/// bound to (`ECONNREFUSED` for a stream to one nothing is bound to).
pub fn connect_prepare(fd: i32, hb: &mut [u8]) -> Result<(), i32> {
    let Some(net) = current() else {
        // In the host's namespace, a low loopback port fwe mapped.
        if let Some(a) = parse(hb)
            && a.loopback
            && (1..HOST_LOW).contains(&a.port)
            && let Some(t) = host_low_ports()
        {
            let key = host_key(fd, &a);
            if let Some(h) = host_port(t, key, a.port)
                && in_use_at(key, hb, h)
            {
                set_port(hb, h);
            }
        }
        return Ok(());
    };
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
    let Some(a) = parse(hb) else { return };
    let Some(net) = current() else {
        // In the host's namespace, a low loopback port fwe mapped.
        if local
            && let Some(crate::fdmarks::Mark::NetBound { port, .. }) = crate::fdmarks::marked(fd)
        {
            set_port(hb, port);
        } else if !local
            && a.loopback
            && a.port >= HOST_LOW
            && let Some(t) = host_low_ports()
        {
            let key = host_key(fd, &a);
            let found = t
                .get()
                .ports
                .iter()
                .find(|((p, _), h)| *p == key && **h == a.port)
                .map(|(k, _)| k.1);
            if let Some(port) = found {
                set_port(hb, port);
            }
        }
        return;
    };
    if local
        && let Some(crate::fdmarks::Mark::NetBound { port, any, .. }) = crate::fdmarks::marked(fd)
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

/// A socket with `mark`, bound in the namespace (or to a low loopback port
/// of the host's that fwe mapped), is closed: its port is free again
/// unless another descriptor of this process holds the socket.
pub fn closed(mark: Option<crate::fdmarks::Mark>) {
    let Some(crate::fdmarks::Mark::NetBound { port, key, .. }) = mark else { return };
    let net = current();
    let table: &Record<Net> = match (net.as_deref(), host_low_ports()) {
        (Some(n), _) => n,
        (None, Some(t)) => t,
        (None, None) => return,
    };
    let _ = table.update(|n| {
        n.ports.remove(&(key, port));
        Ok(())
    });
}
