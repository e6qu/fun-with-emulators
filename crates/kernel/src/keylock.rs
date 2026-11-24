//! Locks between fwe's processes, one for each key (a pipe's or a socket's
//! identity), in a table of the process store's ([`crate::procstore::Area`]):
//! memory every fwe process maps, so taking one that no one holds is a
//! compare-and-swap, not a host call. A lock is held by a process (its host
//! pid; the threads of one take a mutex of their own first) and taken over
//! once its holder has ended, as a byte-range lock goes with its process.
//!
//! A slot is a key and its holder (0: free). Only takers of the same key
//! wait for each other. A key finds its slot under the table's making lock
//! ([`crate::procstore::lock_area`]), so two takers of one key agree on it;
//! a slot whose holder let go is free for any key.

use crate::procstore::Area;
use fwe_abi::errno;
use std::sync::atomic::{AtomicU64, Ordering};

/// The words of a slot: the key's two halves, then the holder.
const SLOT_WORDS: usize = 3;

/// The bytes of a table of `slots` slots, for its area.
pub(crate) const fn bytes(slots: usize) -> usize {
    slots * SLOT_WORDS * 8
}

/// How long a waiter naps before it looks again (a holder lets go without
/// a wake: it may have ended).
const NAP_NS: i64 = 200_000;

/// A key's lock, held until dropped; counted for this process's stops
/// ([`crate::procstore::Holding`]).
#[must_use = "dropped at once, it lets go at once"]
pub struct Held {
    holder: &'static AtomicU64,
    _holding: crate::procstore::Holding,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.holder.store(0, Ordering::Release);
    }
}

/// Whether host process `pid`, a lock's holder, has ended.
fn ended(pid: u64) -> bool {
    i32::try_from(pid)
        .ok()
        .and_then(crate::ids::HostPid::new)
        .is_some_and(|p| crate::host::probe(p) == crate::host::Probe::Gone)
}

/// Take the lock of `key` in `area`'s table, waiting for it if `wait`:
/// `EAGAIN` if another process holds it and not `wait`, `EINTR` if a
/// signal for the guest came while waiting. A table with every slot held
/// is waited on as a held lock is.
pub fn lock(area: Area, key: (u64, u64), wait: bool) -> Result<Held, i32> {
    let t = crate::procstore::area(area);
    let me = crate::host::pid().get() as u64;
    let slots = t.len() / SLOT_WORDS;
    let slot = |i: usize| &t[i * SLOT_WORDS..(i + 1) * SLOT_WORDS];
    let take = |h: u64, holder: &AtomicU64| {
        (h == 0 || ended(h))
            && holder.compare_exchange(h, me, Ordering::AcqRel, Ordering::Acquire).is_ok()
    };
    loop {
        let holding = crate::procstore::Holding::enter();
        // The key's slot, or a free one made the key's, under the making
        // lock.
        let found = {
            let _make = crate::procstore::lock_area(area);
            let found = (0..slots).find(|&i| {
                let s = slot(i);
                s[0].load(Ordering::Acquire) == key.0 && s[1].load(Ordering::Acquire) == key.1
            });
            match found {
                Some(i) => Some(i),
                None => {
                    let free =
                        (0..slots).find(|&i| take(slot(i)[2].load(Ordering::Acquire), &slot(i)[2]));
                    if let Some(i) = free {
                        slot(i)[0].store(key.0, Ordering::Release);
                        slot(i)[1].store(key.1, Ordering::Release);
                        return Ok(Held { holder: &slot(i)[2], _holding: holding });
                    }
                    None
                }
            }
        };
        if let Some(i) = found {
            let s = slot(i);
            if take(s[2].load(Ordering::Acquire), &s[2]) {
                // Still the key's (a slot let go may have been made
                // another's meanwhile).
                if s[0].load(Ordering::Acquire) == key.0 && s[1].load(Ordering::Acquire) == key.1 {
                    return Ok(Held { holder: &s[2], _holding: holding });
                }
                s[2].store(0, Ordering::Release);
                continue;
            }
        }
        if !wait {
            return Err(errno::EAGAIN);
        }
        if crate::thread::deliverable() != 0 {
            return Err(errno::EINTR);
        }
        // Not counted while it waits: a stop of this process need not wait
        // for another's lock.
        drop(holding);
        crate::thread::nap_ns(NAP_NS);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// A key's lock keeps others from it until let go; another key's is
    /// apart; a holder that has ended is taken over.
    #[test]
    fn a_key_is_held_by_one_and_taken_over_from_the_ended() {
        let area = Area::SeqPacketLocks;
        let key = (crate::shared::unique(), 7);
        let held = lock(area, key, false).expect("free");
        assert!(lock(area, (key.0, 8), false).is_ok());
        // The same process holds it: a second taker waits (here: refused).
        assert_eq!(lock(area, key, false).err(), Some(errno::EAGAIN));
        drop(held);
        let held = lock(area, key, false).expect("let go");
        // A holder that ended: a pid no process has.
        held.holder.store(i32::MAX as u64, Ordering::Release);
        std::mem::forget(held);
        let again = lock(area, key, false).expect("taken over");
        drop(again);
    }
}
