//! Multicast membership of TCP sockets, which macOS refuses and Linux
//! keeps (no multicast reaches a TCP socket, but its source filters are
//! kept and checked): fwe keeps them per socket ([`crate::sockstate`]), as
//! Linux's `igmp.c` and `mcast.c` do.
//!
//! Linux refuses `IP_ADD_MEMBERSHIP` and `IP_DROP_MEMBERSHIP` on a
//! connection-oriented socket (`EPROTO`, before their length is checked),
//! and the IPv6 ones (after it). The others act on a socket's groups, each
//! with a filter mode and a list of sources:
//!
//! - `MCAST_JOIN_GROUP` joins a group (exclude mode, no sources;
//!   `EADDRINUSE` if joined), `MCAST_LEAVE_GROUP` leaves it
//!   (`EADDRNOTAVAIL` if not joined);
//! - `IP_ADD_SOURCE_MEMBERSHIP`, `MCAST_JOIN_SOURCE_GROUP` join the group
//!   if not joined (include mode) and add the source;
//!   `IP_BLOCK_SOURCE`, `MCAST_BLOCK_SOURCE` add one to a joined group in
//!   exclude mode. A group not joined is `EINVAL`, one whose sources are
//!   of the other mode `EINVAL` (an empty one takes the mode), a source
//!   there already `EADDRNOTAVAIL`, one past the most (10 for IPv4, 64 for
//!   IPv6, the `igmp_max_msf` and `mld_max_msf` defaults) `ENOBUFS`;
//! - `IP_DROP_SOURCE_MEMBERSHIP`, `MCAST_LEAVE_SOURCE_GROUP`,
//!   `IP_UNBLOCK_SOURCE`, `MCAST_UNBLOCK_SOURCE` take a source away, as
//!   checked, `EADDRNOTAVAIL` for one not there; an include mode's last
//!   source taken leaves the group;
//! - `IP_MSFILTER`, `MCAST_MSFILTER` set a joined group's mode and sources
//!   (`EINVAL` for a group not joined); include mode with no sources
//!   leaves it.
//!
//! A group is the address and interface the call names: one named by an
//! interface address (`ip_mreq_source`, `ip_msfilter`) and one named by
//! an interface index (`group_req`) are kept apart.

use fwe_abi::{err, errno};

/// One group a socket joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Group {
    /// The group and interface, as the call named them ([`Named`]).
    pub key: Vec<u8>,
    /// Include mode (else exclude).
    pub include: bool,
    pub sources: Vec<Vec<u8>>,
}

/// What a membership option does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Join,
    Leave,
    /// A source added in include mode (`true`, joining the group first) or
    /// exclude mode.
    Add(bool),
    /// A source taken away, in include or exclude mode.
    Drop(bool),
    Filter,
}

/// An option's argument, read: its group and interface ([`Group::key`]),
/// the source, or the filter's mode and sources.
struct Named {
    key: Vec<u8>,
    source: Vec<u8>,
    include: bool,
    sources: Vec<Vec<u8>>,
}

/// The most bytes of an option's value read: a `group_filter` with the
/// most sources.
pub(crate) const MOST_VALUE: usize = 8 + STORAGE + 8 + 64 * STORAGE;

/// Whether option `name` of `level` is a multicast membership one.
pub(crate) fn is_membership(level: u64, name: u64) -> bool {
    match level {
        0 => (35..=48).contains(&name),
        41 => matches!(name, 20 | 21 | 42..=48),
        _ => false,
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
/// `struct sockaddr_storage`.
const STORAGE: usize = 128;

/// `setsockopt(fd, level, name, val)` of a multicast membership option on
/// a TCP socket (`ipv6`: an IPv6 one), as Linux answers it; `None` for an
/// option that is not one (or `val`'s bytes could not be read, `EFAULT`).
pub(crate) fn setsockopt(fd: i32, level: u64, name: u64, val: &[u8], ipv6: bool) -> Option<i64> {
    let at_ip = level == 0;
    let at_ipv6 = level == 41;
    let (op, form) = match (at_ip, at_ipv6, name) {
        // IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP: before the length.
        (true, _, 35 | 36) => return Some(err(errno::EPROTO)),
        // IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP: after it.
        (_, true, 20 | 21) => {
            return Some(err(if val.len() < 20 { errno::EINVAL } else { errno::EPROTO }));
        }
        (true, _, 39) => (Op::Add(true), Form::MreqSource),
        (true, _, 40) => (Op::Drop(true), Form::MreqSource),
        (true, _, 38) => (Op::Add(false), Form::MreqSource),
        (true, _, 37) => (Op::Drop(false), Form::MreqSource),
        (true, _, 41) => (Op::Filter, Form::MsFilter),
        (_, _, 42) if at_ip || at_ipv6 => (Op::Join, Form::GroupReq),
        (_, _, 45) if at_ip || at_ipv6 => (Op::Leave, Form::GroupReq),
        (_, _, 46) if at_ip || at_ipv6 => (Op::Add(true), Form::GroupSourceReq),
        (_, _, 47) if at_ip || at_ipv6 => (Op::Drop(true), Form::GroupSourceReq),
        (_, _, 43) if at_ip || at_ipv6 => (Op::Add(false), Form::GroupSourceReq),
        (_, _, 44) if at_ip || at_ipv6 => (Op::Drop(false), Form::GroupSourceReq),
        (_, _, 48) if at_ip || at_ipv6 => (Op::Filter, Form::GroupFilter),
        _ => return None,
    };
    // An IPv4 socket has no IPv6 level's groups.
    if at_ipv6 && !ipv6 {
        return None;
    }
    let max = if at_ipv6 { 64 } else { 10 };
    let named = match read(form, val, at_ipv6, max) {
        Ok(n) => n,
        Err(e) => return Some(err(e)),
    };
    // A group needs to be a multicast one, but for an IPv4 leave (which
    // finds none joined).
    let group = &named.key[named.key.len() - if at_ipv6 { 16 } else { 4 }..];
    if !multicast(group) && !(op == Op::Leave && at_ip) {
        return Some(err(errno::EINVAL));
    }
    Some(crate::sockstate::update(fd, |s| apply(&mut s.memberships, op, named, max)))
}

/// How an option's argument is laid out.
#[derive(Clone, Copy)]
enum Form {
    /// `ip_mreq_source`: group, interface address, source.
    MreqSource,
    /// `ip_msfilter`: group, interface address, mode, count, sources.
    MsFilter,
    /// `group_req`: interface index, group.
    GroupReq,
    /// `group_source_req`: interface index, group, source.
    GroupSourceReq,
    /// `group_filter`: interface index, group, mode, count, sources.
    GroupFilter,
}

/// The address of `sockaddr_storage` `s` of the level's family (`v6`), or
/// `wrong` for another family.
fn address(s: &[u8], v6: bool, wrong: i32) -> Result<Vec<u8>, i32> {
    let fam = u16::from_ne_bytes([s[0], s[1]]);
    match (v6, fam) {
        (false, AF_INET) => Ok(s[4..8].to_vec()),
        (true, AF_INET6) => Ok(s[8..24].to_vec()),
        _ => Err(wrong),
    }
}

/// Whether `a` is a multicast address.
fn multicast(a: &[u8]) -> bool {
    match a.len() {
        4 => a[0] >> 4 == 0xe,
        _ => a[0] == 0xff,
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Read `val` as `form` lays it out, checked as Linux checks it.
fn read(form: Form, val: &[u8], v6: bool, max: usize) -> Result<Named, i32> {
    let none =
        || Named { key: Vec::new(), source: Vec::new(), include: false, sources: Vec::new() };
    match form {
        Form::MreqSource => {
            if val.len() != 12 {
                return Err(errno::EINVAL);
            }
            // The interface address, then the group.
            let key = [&[0u8][..], &val[4..8], &val[..4]].concat();
            Ok(Named { key, source: val[8..12].to_vec(), ..none() })
        }
        Form::GroupReq | Form::GroupSourceReq => {
            let (len, sourced) = match form {
                Form::GroupReq => (8 + STORAGE, false),
                _ => (8 + 2 * STORAGE, true),
            };
            if val.len() < len {
                return Err(errno::EINVAL);
            }
            // A group of another family: `EINVAL` for an IPv4 join or
            // leave, `EADDRNOTAVAIL` for the rest.
            let wrong = if sourced || v6 { errno::EADDRNOTAVAIL } else { errno::EINVAL };
            let group = address(&val[8..8 + STORAGE], v6, wrong)?;
            let source =
                if sourced { address(&val[8 + STORAGE..len], v6, wrong)? } else { Vec::new() };
            let key = [&[1u8][..], &val[..4], &group].concat();
            Ok(Named { key, source, ..none() })
        }
        Form::MsFilter => {
            // `IP_MSFILTER_SIZE(n)`: 16 bytes and the sources.
            if val.len() < 16 {
                return Err(errno::EINVAL);
            }
            let n = u32_at(val, 12) as usize;
            if n > max {
                return Err(errno::ENOBUFS);
            }
            if 16 + 4 * n > val.len() {
                return Err(errno::EINVAL);
            }
            let key = [&[0u8][..], &val[4..8], &val[..4]].concat();
            if !multicast(&val[..4]) {
                return Err(errno::EINVAL);
            }
            let include = mode(u32_at(val, 8))?;
            let sources = (0..n).map(|i| val[16 + 4 * i..20 + 4 * i].to_vec()).collect();
            Ok(Named { key, include, sources, ..none() })
        }
        Form::GroupFilter => {
            // `GROUP_FILTER_SIZE(n)`: 144 bytes and the sources.
            let head = 8 + STORAGE + 8;
            if val.len() < head {
                return Err(errno::EINVAL);
            }
            let n = u32_at(val, 8 + STORAGE + 4) as usize;
            if n > max {
                return Err(errno::ENOBUFS);
            }
            if head + STORAGE * n > val.len() {
                return Err(errno::EINVAL);
            }
            let group = address(&val[8..8 + STORAGE], v6, errno::EADDRNOTAVAIL)?;
            if !multicast(&group) {
                return Err(errno::EINVAL);
            }
            let key = [&[1u8][..], &val[..4], &group].concat();
            let include = mode(u32_at(val, 8 + STORAGE))?;
            let at = |i: usize| &val[head + STORAGE * i..head + STORAGE * (i + 1)];
            let sources = (0..n)
                .map(|i| address(at(i), v6, errno::EADDRNOTAVAIL))
                .collect::<Result<_, _>>()?;
            Ok(Named { key, include, sources, ..none() })
        }
    }
}

/// A filter mode: `MCAST_INCLUDE` (1) or `MCAST_EXCLUDE` (0).
fn mode(m: u32) -> Result<bool, i32> {
    match m {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(errno::EINVAL),
    }
}

/// Apply `op` with `n` to a socket's `groups`: its result.
fn apply(groups: &mut Vec<Group>, op: Op, n: Named, max: usize) -> i64 {
    let at = groups.iter().position(|g| g.key == n.key);
    match (op, at) {
        (Op::Join, Some(_)) => err(errno::EADDRINUSE),
        (Op::Join, None) => {
            groups.push(Group { key: n.key, include: false, sources: Vec::new() });
            0
        }
        (Op::Leave, Some(i)) => {
            groups.remove(i);
            0
        }
        (Op::Leave, None) => err(errno::EADDRNOTAVAIL),
        (Op::Add(true), None) => {
            groups.push(Group { key: n.key.clone(), include: true, sources: Vec::new() });
            apply(groups, op, n, max)
        }
        (Op::Add(_) | Op::Drop(_) | Op::Filter, None) => err(errno::EINVAL),
        (Op::Add(include) | Op::Drop(include), Some(i)) => {
            let g = &mut groups[i];
            if g.include != include {
                if !g.sources.is_empty() {
                    return err(errno::EINVAL);
                }
                g.include = include;
            }
            let there = g.sources.iter().position(|s| *s == n.source);
            match (op, there) {
                (Op::Add(_), Some(_)) => err(errno::EADDRNOTAVAIL),
                (Op::Add(_), None) if g.sources.len() >= max => err(errno::ENOBUFS),
                (Op::Add(_), None) => {
                    g.sources.push(n.source);
                    0
                }
                (_, None) => err(errno::EADDRNOTAVAIL),
                (_, Some(_)) if include && g.sources.len() == 1 => {
                    groups.remove(i);
                    0
                }
                (_, Some(j)) => {
                    g.sources.remove(j);
                    0
                }
            }
        }
        (Op::Filter, Some(i)) => {
            if n.include && n.sources.is_empty() {
                groups.remove(i);
            } else {
                groups[i].include = n.include;
                groups[i].sources = n.sources;
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(n: u8) -> Named {
        Named { key: vec![7], source: vec![10, 0, 0, n], include: false, sources: Vec::new() }
    }

    #[test]
    fn include_sources_join_and_the_last_leaves() {
        let mut g = Vec::new();
        assert_eq!(apply(&mut g, Op::Add(true), src(1), 10), 0);
        assert_eq!(apply(&mut g, Op::Add(true), src(1), 10), err(errno::EADDRNOTAVAIL));
        // A blocked source needs exclude mode, which a group with sources
        // of the other mode refuses.
        assert_eq!(apply(&mut g, Op::Add(false), src(2), 10), err(errno::EINVAL));
        assert_eq!(apply(&mut g, Op::Drop(true), src(1), 10), 0);
        assert!(g.is_empty());
        assert_eq!(apply(&mut g, Op::Drop(true), src(1), 10), err(errno::EINVAL));
    }

    #[test]
    fn a_joined_group_blocks_sources_up_to_the_most() {
        let mut g = Vec::new();
        assert_eq!(apply(&mut g, Op::Join, src(0), 2), 0);
        assert_eq!(apply(&mut g, Op::Join, src(0), 2), err(errno::EADDRINUSE));
        assert_eq!(apply(&mut g, Op::Add(false), src(1), 2), 0);
        assert_eq!(apply(&mut g, Op::Add(false), src(2), 2), 0);
        assert_eq!(apply(&mut g, Op::Add(false), src(3), 2), err(errno::ENOBUFS));
        assert_eq!(apply(&mut g, Op::Drop(false), src(3), 2), err(errno::EADDRNOTAVAIL));
        assert_eq!(apply(&mut g, Op::Drop(false), src(1), 2), 0);
        assert_eq!(apply(&mut g, Op::Leave, src(0), 2), 0);
        assert_eq!(apply(&mut g, Op::Leave, src(0), 2), err(errno::EADDRNOTAVAIL));
    }
}
