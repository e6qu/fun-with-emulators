//! `/proc/net` (`/proc/<pid>/net`): a network namespace's interfaces,
//! routes and sockets, as the files Linux writes show them.
//!
//! A namespace of fwe's has `lo` alone, up or down as it was set, and no
//! routes. The initial namespace's interfaces are the host's (`lo0` named
//! `lo`), with the host's counters, and its routes are those of each
//! interface's own network (no gateway). The sockets are those fwe's
//! processes in the namespace hold, as the host reports each
//! (`PROC_PIDFDSOCKETINFO`), with the namespace's port numbers; the
//! initial namespace shows fwe's processes' sockets, not the rest of the
//! Mac's.

use crate::ns::Net;
use crate::shared::Record;

/// The files of the directory.
pub const FILES: &[&[u8]] =
    &[b"dev", b"if_inet6", b"route", b"snmp", b"tcp", b"tcp6", b"udp", b"udp6", b"unix"];

/// One of a namespace's sockets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sock {
    /// `AF_INET`, `AF_INET6` or `AF_UNIX` (Linux's numbers).
    pub family: u64,
    /// `SOCK_STREAM`, `SOCK_DGRAM` or `SOCK_SEQPACKET`.
    pub kind: u64,
    /// The local and remote addresses (an IPv4 one in the first four
    /// bytes) and ports.
    pub local: ([u8; 16], u16),
    pub remote: ([u8; 16], u16),
    /// The TCP state, in Linux's numbers (1 established ... 10 listen).
    pub tcp_state: u8,
    /// Whether it is connected (`SS_ISCONNECTED`) or listening.
    pub connected: bool,
    pub listening: bool,
    /// Bytes waiting to be sent and to be read.
    pub tx_queue: u32,
    pub rx_queue: u32,
    /// Its owner's uid as the reader sees it, and its identity.
    pub uid: u32,
    pub inode: u64,
    /// A Unix socket's path, as the reader names it (`@name` for an
    /// abstract one).
    pub path: Vec<u8>,
}

/// A host path as the reader names it, if it can.
pub type GuestPath<'a> = &'a dyn Fn(&[u8]) -> Option<Vec<u8>>;

/// The file `name` of the namespace `net` (`None`: the initial one), for
/// a reader that names host paths with `guest`.
pub fn file(name: &[u8], net: Option<&Record<Net>>, guest: GuestPath) -> Option<Vec<u8>> {
    Some(match name {
        b"dev" => dev(net),
        b"if_inet6" => if_inet6(net),
        b"route" => route(net),
        b"snmp" => snmp(&sockets(net, guest)),
        b"tcp" | b"tcp6" | b"udp" | b"udp6" => inet(name, &sockets(net, guest)),
        b"unix" => unix(&sockets(net, guest)),
        _ => return None,
    })
}

/// A host interface: its Linux name, index, flags, IPv4 and IPv6
/// addresses (with prefix lengths) and counters (received bytes, packets,
/// errors, drops; sent bytes, packets, errors; collisions).
#[derive(Clone, Debug, Default)]
struct Iface {
    name: Vec<u8>,
    index: u32,
    up: bool,
    v4: Vec<([u8; 4], [u8; 4])>,
    v6: Vec<([u8; 16], u8)>,
    counters: [u64; 8],
}

/// The interfaces of namespace `net`.
fn ifaces(net: Option<&Record<Net>>) -> Vec<Iface> {
    match net {
        Some(n) => {
            let up = n.get().lo_up;
            let mut v6 = [0u8; 16];
            v6[15] = 1;
            vec![Iface {
                name: b"lo".to_vec(),
                index: 1,
                up,
                v4: if up { vec![([127, 0, 0, 1], [255, 0, 0, 0])] } else { Vec::new() },
                v6: if up { vec![(v6, 128)] } else { Vec::new() },
                counters: [0; 8],
            }]
        }
        None => host_ifaces(),
    }
}

#[cfg(target_os = "macos")]
fn host_ifaces() -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: a valid out-pointer; freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut at = list;
    while !at.is_null() {
        // SAFETY: a node of the list the host made, live until freed.
        let ifa = unsafe { &*at };
        at = ifa.ifa_next;
        // SAFETY: a NUL-terminated name.
        let host = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_bytes();
        let name = if host == b"lo0" { b"lo".to_vec() } else { host.to_vec() };
        let i = match out.iter().position(|i| i.name == name) {
            Some(i) => i,
            None => {
                // SAFETY: a NUL-terminated name.
                let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                out.push(Iface { name, index, ..Default::default() });
                out.len() - 1
            }
        };
        let iface = &mut out[i];
        iface.up |= ifa.ifa_flags & libc::IFF_UP as u32 != 0;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: a socket address of at least its header.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        match family {
            libc::AF_INET => {
                // SAFETY: an `AF_INET` address and mask.
                let (a, m) = unsafe {
                    let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let m = if ifa.ifa_netmask.is_null() {
                        0
                    } else {
                        (*(ifa.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr
                    };
                    (a.sin_addr.s_addr.to_ne_bytes(), m.to_ne_bytes())
                };
                iface.v4.push((a, m));
            }
            libc::AF_INET6 => {
                // SAFETY: an `AF_INET6` address and mask.
                let (a, prefix) = unsafe {
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr;
                    let m = if ifa.ifa_netmask.is_null() {
                        [0; 16]
                    } else {
                        (*(ifa.ifa_netmask as *const libc::sockaddr_in6)).sin6_addr.s6_addr
                    };
                    (a, m.iter().map(|b| b.count_ones()).sum::<u32>() as u8)
                };
                let mut a = a;
                // A link-local address carries its scope in its second word
                // on the host (KAME), which Linux's does not.
                if a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
                    a[2] = 0;
                    a[3] = 0;
                }
                iface.v6.push((a, prefix));
            }
            libc::AF_LINK if !ifa.ifa_data.is_null() => {
                // SAFETY: the link's counters, which `ifa_data` holds for it.
                let d = unsafe { &*(ifa.ifa_data as *const libc::if_data) };
                iface.counters = [
                    u64::from(d.ifi_ibytes),
                    u64::from(d.ifi_ipackets),
                    u64::from(d.ifi_ierrors),
                    u64::from(d.ifi_iqdrops),
                    u64::from(d.ifi_obytes),
                    u64::from(d.ifi_opackets),
                    u64::from(d.ifi_oerrors),
                    u64::from(d.ifi_collisions),
                ];
            }
            _ => {}
        }
    }
    // SAFETY: the list `getifaddrs` made.
    unsafe { libc::freeifaddrs(list) };
    out.sort_by_key(|i| i.index);
    out
}

#[cfg(not(target_os = "macos"))]
fn host_ifaces() -> Vec<Iface> {
    Vec::new()
}

fn dev(net: Option<&Record<Net>>) -> Vec<u8> {
    let mut out = b"Inter-|   Receive                                                |  Transmit\n \
          face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        .to_vec();
    for i in ifaces(net) {
        let [rb, rp, re, rd, tb, tp, te, coll] = i.counters;
        out.extend_from_slice(
            format!(
                "{:>6}: {rb:>7} {rp:>7} {re:>4} {rd:>4}    0     0          0         0 \
                 {tb:>8} {tp:>7} {te:>4}    0    0 {coll:>5}       0          0\n",
                String::from_utf8_lossy(&i.name)
            )
            .as_bytes(),
        );
    }
    out
}

fn if_inet6(net: Option<&Record<Net>>) -> Vec<u8> {
    let mut out = Vec::new();
    for i in ifaces(net) {
        for (a, prefix) in &i.v6 {
            let scope = if a.iter().take(15).all(|&b| b == 0) && a[15] == 1 {
                0x10
            } else if a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
                0x20
            } else {
                0
            };
            let hex: String = a.iter().map(|b| format!("{b:02x}")).collect();
            out.extend_from_slice(
                format!(
                    "{hex} {:02x} {prefix:02x} {scope:02x} 80 {:>8}\n",
                    i.index,
                    String::from_utf8_lossy(&i.name)
                )
                .as_bytes(),
            );
        }
    }
    out
}

fn route(net: Option<&Record<Net>>) -> Vec<u8> {
    let mut out =
        b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            .to_vec();
    // Linux keeps a loopback's routes in its local table, which this file
    // does not show.
    if net.is_some() {
        return out;
    }
    for i in ifaces(None).iter().filter(|i| i.up && i.name != b"lo") {
        for (a, m) in &i.v4 {
            let dest: [u8; 4] = std::array::from_fn(|k| a[k] & m[k]);
            out.extend_from_slice(
                format!(
                    "{}\t{:08X}\t00000000\t0001\t0\t0\t0\t{:08X}\t0\t0\t0\n",
                    String::from_utf8_lossy(&i.name),
                    u32::from_ne_bytes(dest),
                    u32::from_ne_bytes(*m)
                )
                .as_bytes(),
            );
        }
    }
    out
}

/// An address as `/proc/net/tcp` writes it: each 32-bit word of it in
/// memory order, as hex.
fn hex_addr(a: &[u8]) -> String {
    a.chunks(4)
        .map(|w| format!("{:08X}", u32::from_ne_bytes(w.try_into().unwrap_or([0; 4]))))
        .collect()
}

fn inet(name: &[u8], socks: &[Sock]) -> Vec<u8> {
    let (v6, tcp) = (name.ends_with(b"6"), name.starts_with(b"tcp"));
    let width = if v6 { 32 } else { 8 };
    let mut out = format!(
        "{:>4}  {:<w$} {:<w$} st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode{}\n",
        "sl",
        "local_address",
        "rem_address",
        if tcp { "" } else { " ref pointer drops" },
        w = width + 5
    )
    .into_bytes();
    let family = if v6 { fwe_abi::socket::AF_INET6 } else { fwe_abi::socket::AF_INET };
    let kind = if tcp { fwe_abi::socket::SOCK_STREAM } else { fwe_abi::socket::SOCK_DGRAM };
    for (sl, s) in socks.iter().filter(|s| s.family == family && s.kind == kind).enumerate() {
        let n = if v6 { 16 } else { 4 };
        let state = if tcp {
            s.tcp_state
        } else if s.connected {
            1
        } else {
            7
        };
        out.extend_from_slice(
            format!(
                "{sl:>4}: {}:{:04X} {}:{:04X} {state:02X} {:08X}:{:08X} 00:00000000 00000000 {:>5} {:>8} {}{}\n",
                hex_addr(&s.local.0[..n]),
                s.local.1,
                hex_addr(&s.remote.0[..n]),
                s.remote.1,
                s.tx_queue,
                s.rx_queue,
                s.uid,
                0,
                s.inode,
                if tcp { " 1 0000000000000000 100 0 0 10 0" } else { " 2 0000000000000000 0" }
            )
            .as_bytes(),
        );
    }
    out
}

fn unix(socks: &[Sock]) -> Vec<u8> {
    let mut out = b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec();
    for s in socks.iter().filter(|s| s.family == fwe_abi::socket::AF_UNIX) {
        // `__SO_ACCEPTCON` for a listener; connected (3) or not (1).
        let flags = if s.listening { 0x10000 } else { 0 };
        let st = if s.connected { 3 } else { 1 };
        let mut line = format!(
            "0000000000000000: 00000002 00000000 {flags:08X} {:04X} {st:02X} {}",
            s.kind, s.inode
        )
        .into_bytes();
        if !s.path.is_empty() {
            line.push(b' ');
            line.extend_from_slice(&s.path);
        }
        line.push(b'\n');
        out.extend_from_slice(&line);
    }
    out
}

fn snmp(socks: &[Sock]) -> Vec<u8> {
    let established = socks
        .iter()
        .filter(|s| s.kind == fwe_abi::socket::SOCK_STREAM && s.family != fwe_abi::socket::AF_UNIX)
        .filter(|s| matches!(s.tcp_state, 1 | 8))
        .count();
    format!(
        "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n\
         Ip: 2 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
         Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
         Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
         Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
         Tcp: 1 200 120000 -1 0 0 0 0 {established} 0 0 0 0 0 0\n\
         Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
         Udp: 0 0 0 0 0 0 0 0 0\n\
         UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
         UdpLite: 0 0 0 0 0 0 0 0 0\n"
    )
    .into_bytes()
}

/// The sockets fwe's processes in namespace `net` hold, each once.
fn sockets(net: Option<&Record<Net>>, guest: GuestPath) -> Vec<Sock> {
    let want = net.map(|n| n.dir().to_vec());
    let mut out: Vec<Sock> = Vec::new();
    let ports = net.map(|n| n.get().ports.clone()).unwrap_or_default();
    let abstract_dir = match net {
        Some(n) => [n.dir(), b"/abstract/"].concat(),
        None => {
            use std::os::unix::ffi::OsStrExt;
            let d = std::env::temp_dir().join("fwe-abstract");
            [d.as_os_str().as_bytes(), b"/"].concat()
        }
    };
    let fs_view = |p: &[u8]| -> Vec<u8> {
        if let Some(name) = p.strip_prefix(&abstract_dir[..]) {
            return [b"@", name].concat();
        }
        guest(p).unwrap_or_else(|| p.to_vec())
    };
    for (pid, r) in crate::procreg::all() {
        if crate::nsfd::dir_among(b"net", &r.ns) != want {
            continue;
        }
        let uid = crate::userns::to_ns(r.ids[1], false);
        for (fd, target) in crate::procpid::fds(pid) {
            let crate::procpid::FdTarget::Socket(inode) = target else { continue };
            if out.iter().any(|s| s.inode == inode) {
                continue;
            }
            let Some(mut s) = host_socket(pid, fd) else { continue };
            s.uid = uid;
            s.inode = inode;
            if s.family == fwe_abi::socket::AF_UNIX {
                s.path = fs_view(&s.path);
            } else if net.is_some() {
                // The namespace's port numbers, not the host's.
                let proto = if s.kind == fwe_abi::socket::SOCK_STREAM { 6 } else { 17 };
                for end in [&mut s.local, &mut s.remote] {
                    if let Some(((_, p), _)) =
                        ports.iter().find(|((pr, _), host)| *pr == proto && **host == end.1)
                    {
                        end.1 = *p;
                    }
                }
            }
            out.push(s);
        }
    }
    out
}

/// What the host reports of socket `fd` of host process `pid`.
#[cfg(target_os = "macos")]
fn host_socket(pid: i32, fd: i32) -> Option<Sock> {
    /// Offsets in `struct socket_fdinfo` (`sys/proc_info.h`), measured
    /// against the SDK's headers (checked by a test).
    const TYPE: usize = 176;
    const FAMILY: usize = 184;
    const OPTIONS: usize = 188;
    const STATE: usize = 192;
    const RCV_CC: usize = 208;
    const SND_CC: usize = 232;
    const KIND: usize = 256;
    const PROTO: usize = 264;
    const FPORT: usize = PROTO;
    const LPORT: usize = PROTO + 4;
    const VFLAG: usize = PROTO + 24;
    const FADDR: usize = PROTO + 32;
    const LADDR: usize = PROTO + 48;
    const TCP_STATE: usize = PROTO + 80;
    const UN_ADDR: usize = PROTO + 16;
    let b = crate::procpid::socket_info_of(pid, fd)?;
    let i32_at = |o: usize| i32::from_ne_bytes(b[o..o + 4].try_into().unwrap_or([0; 4]));
    let u16_at = |o: usize| u16::from_ne_bytes(b[o..o + 2].try_into().unwrap_or([0; 2]));
    let u32_at = |o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap_or([0; 4]));
    let mut s = Sock {
        kind: match i32_at(TYPE) {
            libc::SOCK_STREAM => fwe_abi::socket::SOCK_STREAM,
            libc::SOCK_DGRAM => fwe_abi::socket::SOCK_DGRAM,
            libc::SOCK_SEQPACKET => fwe_abi::socket::SOCK_SEQPACKET,
            _ => return None,
        },
        connected: u16_at(STATE) & 0x2 != 0,
        listening: u16_at(OPTIONS) & 0x2 != 0,
        rx_queue: u32_at(RCV_CC),
        tx_queue: u32_at(SND_CC),
        ..Default::default()
    };
    match i32_at(FAMILY) {
        libc::AF_UNIX => {
            s.family = fwe_abi::socket::AF_UNIX;
            // `sun_len`, `sun_family`, then the path.
            let path = &b[UN_ADDR + 2..(UN_ADDR + 106).min(b.len())];
            s.path = path[..path.iter().position(|&c| c == 0).unwrap_or(path.len())].to_vec();
        }
        f @ (libc::AF_INET | libc::AF_INET6) => {
            let kind = i32_at(KIND);
            // `INI_IPV4`: an IPv4 address in the last word.
            let v4 = b[VFLAG] & 1 != 0 && f == libc::AF_INET;
            s.family = if v4 { fwe_abi::socket::AF_INET } else { fwe_abi::socket::AF_INET6 };
            let addr = |o: usize| -> [u8; 16] {
                let mut a = [0u8; 16];
                if v4 {
                    a[..4].copy_from_slice(&b[o + 12..o + 16]);
                } else {
                    a.copy_from_slice(&b[o..o + 16]);
                }
                a
            };
            let port = |o: usize| u16::from_be(u32_at(o) as u16);
            s.local = (addr(LADDR), port(LPORT));
            s.remote = (addr(FADDR), port(FPORT));
            // `SOCKINFO_TCP`: the host's TCP state, in Linux's numbers.
            if kind == 2 {
                s.tcp_state = match i32_at(TCP_STATE) {
                    1 => 10,
                    2 => 2,
                    3 => 3,
                    4 => 1,
                    5 => 8,
                    6 => 4,
                    7 => 11,
                    8 => 9,
                    9 => 5,
                    10 => 6,
                    _ => 7,
                };
            }
        }
        _ => return None,
    }
    Some(s)
}

#[cfg(not(target_os = "macos"))]
fn host_socket(_: i32, _: i32) -> Option<Sock> {
    None
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// The host's report of a listening TCP socket and a bound Unix one is
    /// read where `socket_fdinfo` holds it.
    #[test]
    fn host_sockets_are_read_where_the_host_puts_them() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        use std::os::fd::AsRawFd;
        let s = host_socket(crate::host::pid(), l.as_raw_fd()).unwrap();
        assert_eq!(s.family, fwe_abi::socket::AF_INET);
        assert_eq!(s.kind, fwe_abi::socket::SOCK_STREAM);
        assert_eq!(s.local.1, port);
        assert_eq!(&s.local.0[..4], &[127, 0, 0, 1]);
        assert_eq!(s.tcp_state, 10);
        assert!(s.listening);
        let path = std::env::temp_dir().join(format!("fwe-procnet-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let u = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let s = host_socket(crate::host::pid(), u.as_raw_fd()).unwrap();
        assert_eq!(s.family, fwe_abi::socket::AF_UNIX);
        use std::os::unix::ffi::OsStrExt;
        assert!(path.as_os_str().as_bytes().ends_with(&s.path[s.path.len().saturating_sub(10)..]));
        let _ = std::fs::remove_file(&path);
        let text = inet(
            b"tcp",
            &[Sock {
                local: ([127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8080),
                kind: 1,
                family: 2,
                tcp_state: 10,
                inode: 7,
                ..Default::default()
            }],
        );
        let line = String::from_utf8(text).unwrap();
        assert!(
            line.lines().nth(1).unwrap().starts_with("   0: 0100007F:1F90 00000000:0000 0A "),
            "{line}"
        );
    }
}
