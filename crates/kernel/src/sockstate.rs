//! What Linux keeps on a socket that the host has no place for, kept by
//! fwe for each socket: options the host lacks ([`State::kept`]), the
//! multicast groups a TCP socket joined, whether `IPV6_ADDRFORM` made an
//! IPv6 socket IPv4, and a Unix socket's peer as it was when the
//! connection was made (Linux's `sk_peer_cred`, which outlasts the peer).
//!
//! On Linux these are the socket's, so every descriptor of it shares them:
//! a `dup`, one inherited through `fork`, kept through `execve`, or passed
//! to another process with `SCM_RIGHTS`. The host's descriptor numbers
//! tell nothing of which socket they share, so fwe gives each socket a
//! number when it is made, accepted or received ([`fresh`]), maps each of
//! its descriptors to that number, and follows them: a `dup` maps one more
//! ([`duplicated`]), a `close` one fewer ([`closed`], which hands back the
//! state with the socket's last descriptor here), `execve` takes the table
//! along ([`save`], [`load`]), and a socket passed to another process
//! takes its state in the message's bundle ([`export`], [`import`]). Each
//! end knows the process that made or connected it ([`State::maker`]),
//! which a `fork` child or a process it was passed to is not. A
//! socket the first program was started with gets its number when fwe
//! first keeps something of it.

use crate::snapshot::{Dec, Enc};
use std::collections::BTreeMap;

/// What fwe keeps of one socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    /// Options set that the host has not: (key, value), the key as
    /// `net::kept_key` makes it.
    pub kept: Vec<(u64, i32)>,
    /// The multicast groups a TCP socket joined ([`crate::tcpmcast`]).
    pub memberships: Vec<crate::tcpmcast::Group>,
    /// An IPv6 socket `IPV6_ADDRFORM` made IPv4: its names are reported as
    /// the IPv4 ones they map.
    pub v4_view: bool,
    /// A Unix socket's peer when the connection was made.
    pub peer: Option<Peer>,
    /// The process that made this end of the socket, or connected it (its
    /// host pid): one that has it otherwise, a `fork` child or a process
    /// it was passed to, is not its maker, and names itself in what it
    /// sends where the receiver asks for credentials (`net::creds_for`).
    pub maker: Option<i32>,
    /// The peer socket's host identity, once looked up (`net::creds_for`).
    pub peer_id: Option<u64>,
    /// Whether the peer asks for credentials, as of a generation of what
    /// asks (`scm::generation`).
    pub peer_wants: Option<(u64, bool)>,
}

/// A Unix socket's peer process: its host pid and effective user and group
/// ids as the kernel holds them, and whether it is a process of the host's
/// (not fwe's: an X server, say), which reads no bundle (`scm::prepare`).
/// All are as they were when the connection was made: what the host gives
/// later is the last process to use the peer's socket (macOS's
/// `LOCAL_PEERPID` is the socket's `last_pid`), which can be any that had
/// it, gone since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub pid: i32,
    pub host: bool,
    pub uid: u32,
    pub gid: u32,
}

impl State {
    /// Whether nothing of it goes to another process ([`export`]): its
    /// maker and peer's identity are this process's view.
    #[cfg(not(target_os = "linux"))]
    fn is_default(&self) -> bool {
        State { maker: None, peer_id: None, peer_wants: None, ..self.clone() } == State::default()
    }

    fn encode(&self, e: &mut Enc) {
        e.u64(self.kept.len() as u64);
        for &(k, v) in &self.kept {
            e.u64(k);
            e.i32(v);
        }
        e.u64(self.memberships.len() as u64);
        for g in &self.memberships {
            e.bytes(&g.key);
            e.bool(g.include);
            e.u64(g.sources.len() as u64);
            for s in &g.sources {
                e.bytes(s);
            }
        }
        e.bool(self.v4_view);
        e.bool(self.peer.is_some());
        let p = self.peer.unwrap_or(Peer { pid: 0, host: false, uid: 0, gid: 0 });
        e.i32(p.pid);
        e.bool(p.host);
        e.u32(p.uid);
        e.u32(p.gid);
        e.bool(self.maker.is_some());
        e.i32(self.maker.unwrap_or(0));
    }

    fn decode(d: &mut Dec) -> State {
        let n = d.count(12);
        let kept = (0..n).map(|_| (d.u64(), d.i32())).collect();
        let n = d.count(17);
        let memberships = (0..n)
            .map(|_| {
                let (key, include) = (d.bytes(), d.bool());
                let k = d.count(8);
                crate::tcpmcast::Group {
                    key,
                    include,
                    sources: (0..k).map(|_| d.bytes()).collect(),
                }
            })
            .collect();
        let v4_view = d.bool();
        let some = d.bool();
        let peer = Peer { pid: d.i32(), host: d.bool(), uid: d.u32(), gid: d.u32() };
        let made = d.bool();
        let maker = d.i32();
        State {
            kept,
            memberships,
            v4_view,
            peer: some.then_some(peer),
            maker: made.then_some(maker),
            peer_id: None,
            peer_wants: None,
        }
    }
}

/// The sockets fwe keeps something of: their descriptors' numbers, and
/// each socket's state, with how many descriptors it has here, by the
/// number this process gave it.
#[derive(Default)]
pub(crate) struct Table {
    fds: BTreeMap<i32, u32>,
    socks: BTreeMap<u32, (State, u32)>,
    next: u32,
}

impl crate::kept::Table for Table {
    fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

impl Table {
    /// Unmap `fd`: the state of its socket if it was the last descriptor
    /// of it.
    fn unmap(&mut self, fd: i32) -> Option<State> {
        let n = self.fds.remove(&fd)?;
        let (_, count) = self.socks.get_mut(&n)?;
        *count -= 1;
        if *count > 0 {
            return None;
        }
        self.socks.remove(&n).map(|(s, _)| s)
    }

    /// Map `fd` (unmapped) to socket `n`.
    fn map(&mut self, fd: i32, n: u32) {
        if let Some((_, count)) = self.socks.get_mut(&n) {
            *count += 1;
            self.fds.insert(fd, n);
        }
    }

    /// Map `fd` (unmapped) to a socket of its own, with `state`: its
    /// number.
    fn map_new(&mut self, fd: i32, state: State) -> u32 {
        let n = self.next;
        self.next = self.next.wrapping_add(1);
        self.fds.insert(fd, n);
        self.socks.insert(n, (state, 1));
        n
    }
}

pub(crate) static TABLE: crate::kept::Kept<Table> =
    crate::kept::Kept::new(Table { fds: BTreeMap::new(), socks: BTreeMap::new(), next: 0 });

/// `f` of the state of socket `fd`, if fwe keeps any.
pub(crate) fn with<R>(fd: i32, f: impl FnOnce(&State) -> R) -> Option<R> {
    let t = TABLE.if_used()?;
    let n = t.fds.get(&fd)?;
    t.socks.get(n).map(|(s, _)| f(s))
}

/// Change the state of socket `fd` (a fresh one if fwe kept none of it).
pub(crate) fn update<R>(fd: i32, f: impl FnOnce(&mut State) -> R) -> R {
    let mut t = TABLE.lock();
    let n = match t.fds.get(&fd) {
        Some(&n) => n,
        None => t.map_new(fd, State::default()),
    };
    let Some((s, _)) = t.socks.get_mut(&n) else { unreachable!("a mapped socket has a state") };
    f(s)
}

/// Descriptor `fd` is a new socket (made, accepted or received), whatever
/// a socket that had the number left (one closed out of fwe's sight).
pub(crate) fn fresh(fd: i32) {
    let mut t = TABLE.lock();
    t.unmap(fd);
    t.map_new(fd, State::default());
}

/// Descriptor `fd` was closed: the state of its socket, if fwe kept any
/// and `fd` was its last descriptor here.
pub(crate) fn closed(fd: i32) -> Option<State> {
    TABLE.if_used()?.unmap(fd)
}

/// `new` is a duplicate of `old`.
pub(crate) fn duplicated(old: i32, new: i32) {
    let Some(mut t) = TABLE.if_used() else { return };
    t.unmap(new);
    if let Some(&n) = t.fds.get(&old) {
        t.map(new, n);
    }
}

/// The descriptors of sockets whose kept option `key` is set (non-zero),
/// one of each socket.
#[cfg(not(target_os = "linux"))]
pub(crate) fn with_kept(key: u64) -> Vec<i32> {
    let Some(t) = TABLE.if_used() else { return Vec::new() };
    t.socks
        .iter()
        .filter(|(_, (s, _))| s.kept.iter().any(|&(k, v)| k == key && v != 0))
        .filter_map(|(n, _)| t.fds.iter().find(|&(_, m)| m == n).map(|(&fd, _)| fd))
        .collect()
}

/// The table, for the process `execve` makes (or a VM fork child).
pub(crate) fn save(e: &mut Enc) {
    let t = TABLE.lock();
    e.u64(t.socks.len() as u64);
    for (n, (s, _)) in &t.socks {
        let fds: Vec<i32> = t.fds.iter().filter(|&(_, m)| m == n).map(|(&fd, _)| fd).collect();
        e.u64(fds.len() as u64);
        for fd in fds {
            e.i32(fd);
        }
        s.encode(e);
    }
}

/// What [`save`] wrote, in the new process: the sockets of descriptors
/// still open (those closed on exec are not).
pub(crate) fn load(d: &mut Dec) {
    let n = d.count(8);
    let mut t = TABLE.lock();
    for _ in 0..n {
        let k = d.count(4);
        let fds: Vec<i32> = (0..k).map(|_| d.i32()).collect();
        let state = State::decode(d);
        // SAFETY: F_GETFD only queries the descriptor.
        let open: Vec<i32> =
            fds.into_iter().filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).collect();
        let Some((&first, rest)) = open.split_first() else { continue };
        let m = t.map_new(first, state);
        for &fd in rest {
            t.map(fd, m);
        }
    }
}

/// The state socket `fd` takes to another process, if fwe keeps any.
#[cfg(not(target_os = "linux"))]
pub(crate) fn export(fd: i32) -> Option<Vec<u8>> {
    with(fd, |s| {
        (!s.is_default()).then(|| {
            let mut e = Enc::new();
            s.encode(&mut e);
            e.into_bytes()
        })
    })
    .flatten()
}

/// Received socket `fd` (fresh here) had the state `bytes` ([`export`]),
/// but for its maker and peer's identity: this process did not make it.
#[cfg(not(target_os = "linux"))]
pub(crate) fn import(fd: i32, bytes: &[u8]) {
    let mut d = Dec::new(bytes);
    let state = State { maker: None, peer_id: None, peer_wants: None, ..State::decode(&mut d) };
    if d.whole() {
        let mut t = TABLE.lock();
        t.unmap(fd);
        t.map_new(fd, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(t: &Table, fd: i32) -> Option<&State> {
        t.socks.get(t.fds.get(&fd)?).map(|(s, _)| s)
    }

    #[test]
    fn descriptors_of_one_socket_share_its_state_until_the_last_goes() {
        let mut t = Table::default();
        let n = t.map_new(3, State { v4_view: true, ..State::default() });
        t.map(7, n);
        assert_eq!(kept(&t, 7).map(|s| s.v4_view), Some(true));
        assert_eq!(t.unmap(3), None);
        assert_eq!(kept(&t, 7).map(|s| s.v4_view), Some(true));
        assert_eq!(t.unmap(7).map(|s| s.v4_view), Some(true));
        assert!(t.socks.is_empty() && t.fds.is_empty());
    }

    #[test]
    fn a_state_survives_its_encoding() {
        let s = State {
            kept: vec![(16, 1), (12, 5)],
            memberships: vec![crate::tcpmcast::Group {
                key: vec![1, 2],
                include: true,
                sources: vec![vec![10, 0, 0, 1]],
            }],
            v4_view: true,
            peer: Some(Peer { pid: 7, host: true, uid: 1000, gid: 100 }),
            maker: Some(9),
            peer_id: None,
            peer_wants: None,
        };
        let mut e = Enc::new();
        s.encode(&mut e);
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        assert_eq!(State::decode(&mut d), s);
        assert!(d.whole());
    }
}
