//! A network namespace's routes, as Linux's routing tables hold them: what
//! `RTM_GETROUTE` dumps and finds ([`crate::netlink`]) and `/proc/net/route`
//! and `ipv6_route` show ([`crate::procnet`]).
//!
//! Linux makes the routes of each address itself: an IPv4 address's own
//! (`local`, in the local table), its network's broadcast address's (below
//! a /31) and, on the loopback, its network's (`local`), and an IPv6
//! address's own (`local`), with `ff00::/8` (`multicast`) on an interface
//! with IPv6 that is not the loopback. Those are made the same way here,
//! from the namespace's interfaces. The main table holds, in the initial
//! namespace, the host's own routes ([`crate::host::routes`]): a route on
//! the link to the network of one of the interface's addresses as the
//! kernel's (`proto kernel`, with that address as its source), any other
//! as one set up at boot (`proto boot`); a namespace of fwe's has none
//! there, as on Linux, whose `lo` routes all are local.

use crate::host::{HostRoute, Interface};

/// `RTN_*`: what a route's destination is.
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;
pub const RTN_MULTICAST: u8 = 5;
/// `RT_TABLE_MAIN`, `RT_TABLE_LOCAL`.
pub const MAIN: u8 = 254;
pub const LOCAL: u8 = 255;
/// `RTPROT_KERNEL`, `RTPROT_BOOT`.
pub const KERNEL: u8 = 2;
pub const BOOT: u8 = 3;
/// `RT_SCOPE_UNIVERSE`, `RT_SCOPE_LINK`, `RT_SCOPE_HOST`.
pub const UNIVERSE: u8 = 0;
pub const LINK: u8 = 253;
pub const HOST: u8 = 254;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;

/// One route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// `AF_INET` (2) or `AF_INET6` (10).
    pub family: u8,
    pub kind: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub dst: Vec<u8>,
    pub prefix: u8,
    pub gateway: Option<Vec<u8>>,
    /// The interface's index.
    pub oif: u32,
    pub prefsrc: Option<Vec<u8>>,
    /// Its metric, if it has one (`RTA_PRIORITY`).
    pub metric: Option<u32>,
}

/// Whether `a` is in the network `net`/`prefix`.
fn within(a: &[u8], net: &[u8], prefix: u8) -> bool {
    a.len() == net.len()
        && a.iter().zip(net).enumerate().all(|(i, (x, y))| {
            let bits = (prefix as usize).saturating_sub(i * 8).min(8);
            let mask = if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
            x & mask == y & mask
        })
}

/// `a`'s network of `prefix` bits, and its last address (the broadcast).
fn network(a: &[u8], prefix: u8) -> (Vec<u8>, Vec<u8>) {
    let mut net = a.to_vec();
    let mut last = a.to_vec();
    for (i, (n, l)) in net.iter_mut().zip(last.iter_mut()).enumerate() {
        let bits = (prefix as usize).saturating_sub(i * 8).min(8);
        let mask = if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
        *n &= mask;
        *l |= !mask;
    }
    (net, last)
}

/// The routes of a namespace whose interfaces are `ifs`, with the host's
/// `host` in its main table, as Linux dumps them: IPv4's, then IPv6's,
/// each table's in turn, by destination.
pub fn table(ifs: &[Interface], host: &[HostRoute]) -> Vec<Route> {
    let mut out = Vec::new();
    let up = |f: &&Interface| f.flags & IFF_UP != 0;
    for f in ifs.iter().filter(up) {
        let loopback = f.flags & IFF_LOOPBACK != 0;
        let local = |family, dst: &[u8], prefix, src: &[u8], scope, metric| Route {
            family,
            kind: RTN_LOCAL,
            table: LOCAL,
            protocol: KERNEL,
            scope,
            dst: dst.to_vec(),
            prefix,
            gateway: None,
            oif: f.index,
            prefsrc: (family == 2).then(|| src.to_vec()),
            metric,
        };
        for a in f.addrs.iter().filter(|a| a.addr.len() == 4) {
            out.push(local(2, &a.addr, 32, &a.addr, HOST, None));
            let (net, last) = network(&a.addr, a.prefix);
            if loopback && a.prefix < 32 {
                out.push(local(2, &net, a.prefix, &a.addr, HOST, None));
            }
            if a.prefix < 31 {
                out.push(Route {
                    kind: RTN_BROADCAST,
                    scope: LINK,
                    ..local(2, &last, 32, &a.addr, LINK, None)
                });
            }
        }
        let v6: Vec<_> = f.addrs.iter().filter(|a| a.addr.len() == 16).collect();
        for a in &v6 {
            out.push(local(10, &a.addr, 128, &a.addr, UNIVERSE, Some(0)));
        }
        if !loopback && !v6.is_empty() {
            let mut ff = vec![0u8; 16];
            ff[0] = 0xff;
            out.push(Route { kind: RTN_MULTICAST, ..local(10, &ff, 8, &[], UNIVERSE, Some(256)) });
        }
    }
    for r in host {
        let Some(f) = ifs.iter().filter(up).find(|f| f.index == r.index) else { continue };
        let family = if r.family == 2 { 2 } else { 10 };
        let n = if family == 2 { 4 } else { 16 };
        // The network of one of its addresses, on the link: the kernel's.
        let src = f.addrs.iter().find(|a| {
            a.addr.len() == n
                && r.gateway.is_none()
                && a.prefix == r.prefix
                && within(&a.addr, &r.dst, r.prefix)
        });
        let v6 = family == 10;
        out.push(Route {
            family,
            kind: RTN_UNICAST,
            table: MAIN,
            protocol: if src.is_some() { KERNEL } else { BOOT },
            scope: if r.gateway.is_some() || v6 { UNIVERSE } else { LINK },
            dst: r.dst.clone(),
            prefix: r.prefix,
            gateway: r.gateway.clone(),
            oif: r.index,
            prefsrc: src.filter(|_| !v6).map(|a| a.addr.clone()),
            metric: if !v6 {
                None
            } else if src.is_some() || r.gateway.is_none() {
                Some(256)
            } else {
                Some(1024)
            },
        });
    }
    out.sort_by(|a, b| {
        (a.family, a.table, &a.dst, a.prefix).cmp(&(b.family, b.table, &b.dst, b.prefix))
    });
    out.dedup();
    out
}

/// The route the namespace's `routes` take to `addr` (`ip route get`): a
/// local one first, then the main table's longest prefix.
pub fn lookup<'a>(routes: &'a [Route], addr: &[u8]) -> Option<&'a Route> {
    let family = if addr.len() == 4 { 2 } else { 10 };
    let of = |table: u8| {
        routes
            .iter()
            .filter(|r| r.family == family && r.table == table)
            .filter(|r| matches!(r.kind, RTN_UNICAST | RTN_LOCAL) && within(addr, &r.dst, r.prefix))
            .max_by_key(|r| r.prefix)
    };
    of(LOCAL).or_else(|| of(MAIN))
}

/// Interface `index`'s first address of `addr`'s family, for a route's
/// source.
pub fn source(ifs: &[Interface], index: u32, addr: &[u8]) -> Option<Vec<u8>> {
    let f = ifs.iter().find(|f| f.index == index)?;
    f.addrs.iter().find(|a| a.addr.len() == addr.len()).map(|a| a.addr.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::IfAddr;

    fn lo() -> Interface {
        Interface {
            name: b"lo".to_vec(),
            index: 1,
            flags: IFF_UP | IFF_LOOPBACK,
            mtu: 65536,
            hw_type: 772,
            hw_addr: vec![0; 6],
            addrs: vec![
                IfAddr { addr: vec![127, 0, 0, 1], prefix: 8, broadcast: None },
                IfAddr { addr: [vec![0; 15], vec![1]].concat(), prefix: 128, broadcast: None },
            ],
        }
    }

    /// A namespace with `lo` up, as Linux 7.0 has its routes: local ones
    /// alone.
    #[test]
    fn a_namespaces_lo_has_its_local_routes() {
        let t = table(&[lo()], &[]);
        let short: Vec<_> =
            t.iter().map(|r| (r.kind, r.table, r.dst.clone(), r.prefix, r.scope)).collect();
        assert_eq!(
            short,
            vec![
                (RTN_LOCAL, LOCAL, vec![127, 0, 0, 0], 8, HOST),
                (RTN_LOCAL, LOCAL, vec![127, 0, 0, 1], 32, HOST),
                (RTN_BROADCAST, LOCAL, vec![127, 255, 255, 255], 32, LINK),
                (RTN_LOCAL, LOCAL, [vec![0; 15], vec![1]].concat(), 128, UNIVERSE),
            ]
        );
        assert_eq!(t[0].prefsrc, Some(vec![127, 0, 0, 1]));
        assert_eq!(t[3].metric, Some(0));
        let down = Interface { flags: IFF_LOOPBACK, ..lo() };
        assert!(table(&[down], &[]).is_empty());
        assert_eq!(lookup(&t, &[127, 0, 0, 1]).map(|r| r.kind), Some(RTN_LOCAL));
        assert_eq!(lookup(&t, &[8, 8, 8, 8]), None);
    }

    /// A host's network and default route, as Linux's main table holds
    /// them, and the address's local and broadcast routes.
    #[test]
    fn a_hosts_routes_fill_the_main_table() {
        let en = Interface {
            name: b"en0".to_vec(),
            index: 4,
            flags: IFF_UP,
            mtu: 1500,
            hw_type: 1,
            hw_addr: vec![0; 6],
            addrs: vec![IfAddr {
                addr: vec![10, 1, 0, 150],
                prefix: 20,
                broadcast: Some([10, 1, 15, 255]),
            }],
        };
        let host = [
            HostRoute {
                family: 2,
                dst: vec![0; 4],
                prefix: 0,
                gateway: Some(vec![10, 1, 0, 1]),
                index: 4,
            },
            HostRoute { family: 2, dst: vec![10, 1, 0, 0], prefix: 20, gateway: None, index: 4 },
        ];
        let t = table(&[lo(), en.clone()], &host);
        let main: Vec<_> = t.iter().filter(|r| r.table == MAIN).collect();
        assert_eq!(main.len(), 2);
        assert_eq!((main[0].prefix, main[0].protocol, main[0].scope), (0, BOOT, UNIVERSE));
        assert_eq!(main[0].gateway, Some(vec![10, 1, 0, 1]));
        assert_eq!((main[1].protocol, main[1].scope), (KERNEL, LINK));
        assert_eq!(main[1].prefsrc, Some(vec![10, 1, 0, 150]));
        assert!(t.iter().any(|r| r.kind == RTN_BROADCAST && r.dst == [10, 1, 15, 255]));
        assert_eq!(lookup(&t, &[8, 8, 8, 8]).map(|r| r.prefix), Some(0));
        assert_eq!(lookup(&t, &[10, 1, 3, 4]).map(|r| r.prefix), Some(20));
        assert_eq!(source(&[en], 4, &[8, 8, 8, 8]), Some(vec![10, 1, 0, 150]));
    }
}
