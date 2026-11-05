//! Pid namespaces: the pids a process and the ones it sees have inside one.
//!
//! In the initial namespace a guest's pid is its host process's. A
//! namespace fwe makes numbers its processes (and their threads) from 1, in
//! a shared record mapping each number to the host pid behind it, so any
//! process in the namespace can translate either way. A namespace inside
//! another is in that one's record too, as on Linux a process has a pid in
//! every namespace above its own.

use crate::shared::Data;
use crate::snapshot::{Dec, Enc};
use std::collections::BTreeMap;

/// The largest pid (`/proc/sys/kernel/pid_max`).
pub const PID_MAX: i32 = 4_194_304;

/// One pid namespace.
#[derive(Clone, Default, Debug)]
pub struct PidNs {
    /// The namespace this one is inside (its record's directory and
    /// identity), `None` for one inside the initial namespace.
    pub parent: Option<(Vec<u8>, u64)>,
    /// The next number to try.
    pub next: i32,
    /// Each number in use, and the host pid (of the process, or the
    /// thread's process) it stands for; a thread's has its tid.
    pub pids: BTreeMap<i32, Entry>,
}

/// What a number in a pid namespace stands for.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The host process.
    pub host: i32,
    /// The thread's number when this is a thread of that process (the
    /// process's own number is its main thread's).
    pub thread: bool,
}

impl Data for PidNs {
    fn encode(&self, e: &mut Enc) {
        match &self.parent {
            Some((dir, id)) => {
                e.bool(true);
                e.bytes(dir);
                e.u64(*id);
            }
            None => e.bool(false),
        }
        e.i32(self.next);
        e.u64(self.pids.len() as u64);
        for (n, entry) in &self.pids {
            e.i32(*n);
            e.i32(entry.host);
            e.bool(entry.thread);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let parent = if d.bool() { Some((d.bytes(), d.u64())) } else { None };
        let next = d.i32();
        let n = d.count(9);
        let pids = (0..n).map(|_| (d.i32(), Entry { host: d.i32(), thread: d.bool() })).collect();
        PidNs { parent, next, pids }
    }
}

impl PidNs {
    /// A new namespace inside `parent`.
    pub fn new(parent: Option<(Vec<u8>, u64)>) -> PidNs {
        PidNs { parent, next: 1, pids: BTreeMap::new() }
    }

    /// A free number, recorded for `entry`.
    pub fn alloc(&mut self, entry: Entry) -> Option<i32> {
        let start = self.next.max(1);
        let mut n = start;
        loop {
            if let std::collections::btree_map::Entry::Vacant(v) = self.pids.entry(n) {
                v.insert(entry);
                self.next = if n >= PID_MAX { 1 } else { n + 1 };
                return Some(n);
            }
            n = if n >= PID_MAX { 1 } else { n + 1 };
            if n == start {
                return None;
            }
        }
    }

    /// The number the process with host pid `host` has here.
    pub fn number_of(&self, host: i32) -> Option<i32> {
        self.pids.iter().find(|(_, e)| e.host == host && !e.thread).map(|(n, _)| *n)
    }

    /// The host pid number `n` stands for.
    pub fn host_of(&self, n: i32) -> Option<i32> {
        self.pids.get(&n).map(|e| e.host)
    }

    /// Forget every number of the host process `host` (it was reaped).
    pub fn release(&mut self, host: i32) {
        self.pids.retain(|_, e| e.host != host);
    }

    /// Forget the numbers of host processes that no longer exist.
    pub fn sweep(&mut self) {
        self.pids.retain(|_, e| {
            // SAFETY: a signal 0 only checks that the process exists.
            let alive = unsafe { libc::kill(e.host, 0) } == 0;
            alive || crate::host::last_errno() == libc::EPERM
        });
    }
}

/// The process's place in pid namespaces: its own namespace, then each one
/// above it, up to (not including) the initial one; empty in the initial
/// namespace.
pub type Chain = Vec<std::sync::Arc<crate::shared::Record<PidNs>>>;

static CURRENT: std::sync::Mutex<Option<std::sync::Arc<Chain>>> = std::sync::Mutex::new(None);

/// The chain the process is in now.
pub fn current() -> std::sync::Arc<Chain> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default()
}

/// Make `chain` the process's ([`crate::ns::Namespaces::pid`]).
pub fn set_current(chain: Chain) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::sync::Arc::new(chain));
}

/// The chain of namespaces from `ns` up: its record's parents, joined.
pub fn chain_from(ns: Option<std::sync::Arc<crate::shared::Record<PidNs>>>) -> Chain {
    let mut out = Vec::new();
    let mut at = ns;
    while let Some(r) = at {
        let parent = r.get().parent.clone();
        out.push(r);
        at = parent.and_then(|(dir, id)| {
            crate::shared::Record::join(&dir, id).ok().map(std::sync::Arc::new)
        });
    }
    out
}

/// Number a new process or thread in every namespace of `chain`, for the
/// host pid `host` (0 until known, see [`set_host`]). Returns the numbers,
/// the chain's first namespace's first.
pub fn alloc(chain: &Chain, host: i32, thread: bool) -> Result<Vec<i32>, i32> {
    let mut nums = Vec::with_capacity(chain.len());
    for r in chain.iter() {
        match r.update(|ns| ns.alloc(Entry { host, thread }).ok_or(fwe_abi::errno::EAGAIN)) {
            Ok(n) => nums.push(n),
            Err(e) => {
                // Undo the ones made.
                for (r, n) in chain.iter().zip(&nums) {
                    let _ = r.update(|ns| {
                        ns.pids.remove(n);
                        Ok(())
                    });
                }
                return Err(e);
            }
        }
    }
    Ok(nums)
}

/// Record the host pid behind the numbers [`alloc`] gave a process before
/// it existed.
pub fn set_host(chain: &Chain, nums: &[i32], host: i32) {
    for (r, n) in chain.iter().zip(nums) {
        let _ = r.update(|ns| {
            if let Some(e) = ns.pids.get_mut(n) {
                e.host = host;
            }
            Ok(())
        });
    }
}

/// The pid the process with host pid `host` has in the current
/// namespace, or 0 when it is outside it (as Linux reports a process the
/// observer cannot see).
pub fn to_guest(host: i32) -> i32 {
    match current().first() {
        None => host,
        Some(r) => r.get().number_of(host).unwrap_or(0),
    }
}

/// The host pid behind `pid` in the current namespace.
pub fn to_host(pid: i32) -> Option<i32> {
    match current().first() {
        None => Some(pid),
        Some(r) => r.get().host_of(pid).filter(|&h| h != 0),
    }
}

/// Whether the process is in a pid namespace of fwe's.
pub fn nested() -> bool {
    !current().is_empty()
}

/// Forget a reaped child's numbers, in every namespace of the chain.
pub fn reaped(host: i32) {
    for r in current().iter() {
        let _ = r.update(|ns| {
            ns.release(host);
            Ok(())
        });
    }
}

/// A pid argument (`0` for the caller) as the host pid it names, or
/// `ESRCH`.
pub fn host_arg(pid: i32) -> Result<i32, i32> {
    if pid <= 0 || !nested() {
        return Ok(pid);
    }
    to_host(pid).ok_or(fwe_abi::errno::ESRCH)
}

/// A host pid a call returns (an error passes through) as the guest's.
pub fn guest_ret(r: i64) -> i64 {
    if r > 0 && nested() { to_guest(r as i32) as i64 } else { r }
}

/// Take up the pid namespaces `ns` names, in a process that starts on
/// state another wrote (a re-executed fwe, a VM fork child): returns the
/// process's pid in its own namespace, `known` if the parent gave it, else
/// what the namespace's record holds for this host process.
pub fn adopt(ns: &crate::ns::Namespaces, known: i32) -> i32 {
    set_current(chain_from(ns.pid.clone()));
    // SAFETY: getpid cannot fail.
    let host = unsafe { libc::getpid() };
    if known > 0 {
        return known;
    }
    match current().first() {
        Some(r) => r.get().number_of(host).unwrap_or(host),
        None => host,
    }
}

/// Forget a thread's number in the current namespace (it exited).
pub fn release_thread(tid: i32) {
    if let Some(r) = current().first() {
        let _ = r.update(|ns| {
            if ns.pids.get(&tid).is_some_and(|e| e.thread) {
                ns.pids.remove(&tid);
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_from_one_and_maps_both_ways() {
        let mut ns = PidNs::new(None);
        assert_eq!(ns.alloc(Entry { host: 500, thread: false }), Some(1));
        assert_eq!(ns.alloc(Entry { host: 500, thread: true }), Some(2));
        assert_eq!(ns.alloc(Entry { host: 600, thread: false }), Some(3));
        assert_eq!(ns.number_of(600), Some(3));
        assert_eq!(ns.number_of(500), Some(1));
        assert_eq!(ns.host_of(2), Some(500));
        ns.release(500);
        assert_eq!(ns.host_of(1), None);
        assert_eq!(ns.alloc(Entry { host: 700, thread: false }), Some(4));
        let mut e = Enc::new();
        ns.encode(&mut e);
        let b = e.into_bytes();
        let back = PidNs::decode(&mut Dec::new(&b));
        assert_eq!(back.pids, ns.pids);
    }
}
