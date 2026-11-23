//! `EPOLLEXCLUSIVE` across processes: a write to a pipe that several epoll
//! sets wait on with it wakes one of them, as Linux's does, where every
//! host kqueue watching the pipe fires.
//!
//! A table in memory every fwe process maps ([`crate::procstore::area`])
//! holds a slot per pipe some set watches exclusively, by the pipe's host
//! identity: how many writes it has had, and how many of them a waiter
//! took. A write counts one more ([`wrote`]), once the writer's call
//! returns; a set whose wait such a write ended takes one ([`take`]), and
//! one that finds none left (taken by another set, or not counted yet: the
//! host wakes every set as the write is made) tries again for each write
//! counted from then on ([`wait_for_write`]). A set that finds the
//! pipe ready when it asks, without waiting, takes every write there is
//! ([`take_all`]): the readiness was there before it, for whoever asks. An
//! edge-triggered set sees a counted pipe readable anew when it was
//! written to, not when it holds more ([`crate::epoll`]).
//!
//! Only writes the guest makes with `write` and `writev` are counted.

use std::sync::atomic::{AtomicU64, Ordering};

/// Slots: pipes watched exclusively at once.
const SLOTS: usize = 127;
/// A slot: the pipe's identity (its two ends' host handles), writes,
/// writes taken.
const SLOT_WORDS: usize = 4;
/// The table's size: a count of slots in use, then the slots
/// ([`crate::procstore::Area::Exclusive`]).
pub(crate) const BYTES: usize = (1 + SLOTS * SLOT_WORDS) * 8;

/// The page: a count of slots in use, then the slots.
struct Table {
    words: &'static [AtomicU64],
}

static TABLE: std::sync::OnceLock<Option<Table>> = std::sync::OnceLock::new();

/// The shared table, in memory every fwe process maps.
fn table() -> Option<&'static Table> {
    // On Linux, epoll is the host's, which does this itself.
    if cfg!(target_os = "linux") {
        return None;
    }
    TABLE
        .get_or_init(|| {
            Some(Table { words: crate::procstore::area(crate::procstore::Area::Exclusive) })
        })
        .as_ref()
}

impl Table {
    fn in_use(&self) -> &AtomicU64 {
        &self.words[0]
    }
    fn slot(&self, i: usize) -> &[AtomicU64] {
        &self.words[1 + i * SLOT_WORDS..1 + (i + 1) * SLOT_WORDS]
    }
    /// The slot of the pipe with identity `(lo, hi)`, made if `make`.
    fn find(&self, (lo, hi): (u64, u64), make: bool) -> Option<&[AtomicU64]> {
        let used = (self.in_use().load(Ordering::Acquire) as usize).min(SLOTS);
        if let Some(s) = (0..used)
            .map(|i| self.slot(i))
            .find(|s| s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi)
        {
            return Some(s);
        }
        if !make {
            return None;
        }
        // A new slot, made under a lock so that two makers of the same
        // pipe's agree.
        let _lock = crate::procstore::lock_area(crate::procstore::Area::Exclusive);
        let used = (self.in_use().load(Ordering::Acquire) as usize).min(SLOTS);
        if let Some(s) = (0..used)
            .map(|i| self.slot(i))
            .find(|s| s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi)
        {
            return Some(s);
        }
        // A new slot, or when all are in use, one with no write left to
        // take (one freed, or a pipe long gone most likely), else each in
        // turn: writes no one took are left by pipes gone as well, and
        // fill the page for good otherwise. A pipe still watched whose
        // slot goes wakes every set again, as without a slot (Linux wakes
        // one or more).
        let s = if used < SLOTS {
            self.slot(used)
        } else {
            (0..SLOTS)
                .map(|i| self.slot(i))
                .find(|s| s[3].load(Ordering::Acquire) >= s[2].load(Ordering::Acquire))
                .unwrap_or_else(|| self.slot(NEXT_TAKEN.fetch_add(1, Ordering::Relaxed) % SLOTS))
        };
        s[0].store(lo, Ordering::Release);
        s[1].store(hi, Ordering::Release);
        s[2].store(0, Ordering::Release);
        s[3].store(0, Ordering::Release);
        if used < SLOTS {
            self.in_use().store(used as u64 + 1, Ordering::Release);
        }
        Some(s)
    }
}

/// Which slot this process takes next when every one holds writes no
/// one took.
static NEXT_TAKEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The identity of the pipe open as `fd`, if it is one: the same for both
/// of its ends (the host gives each end an inode of its own).
fn pipe_id(fd: i32) -> Option<(u64, u64)> {
    let (end, peer) = crate::splice::pipe_ends(fd)?;
    Some((end.min(peer), end.max(peer)))
}

/// A pipe the guest holds was made (by pipe2, eventfd or signalfd), one
/// end open as `fd`: a slot left by a pipe gone that had its identity (the
/// host reuses them) is freed, so that the new pipe counts no writes until
/// a set watches it exclusively. A freed slot has no identity a pipe has
/// and no write left to take, so it is made again first.
pub fn made(fd: i32) {
    if let Some(s) = slot_of(fd) {
        s[0].store(0, Ordering::Release);
        s[1].store(0, Ordering::Release);
        s[2].store(0, Ordering::Release);
        s[3].store(0, Ordering::Release);
    }
}

/// An epoll set watches the pipe open as `fd` exclusively: its writes are
/// counted from now on.
pub fn watch(fd: i32) {
    if let (Some(t), Some(id)) = (table(), pipe_id(fd)) {
        t.find(id, true);
    }
}

/// The guest wrote to `fd`: one more write for whoever watches it
/// exclusively, and those waiting for one are woken to try for it.
pub fn wrote(fd: i32) {
    let Some(t) = table() else { return };
    if t.in_use().load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some(s) = pipe_id(fd).and_then(|id| t.find(id, false)) {
        s[2].fetch_add(1, Ordering::AcqRel);
        crate::shared::wake_word(&s[2]);
    }
}

/// The slot of the pipe open as `fd`, if it is watched exclusively.
fn slot_of(fd: i32) -> Option<&'static [AtomicU64]> {
    let t = table()?;
    if t.in_use().load(Ordering::Acquire) == 0 {
        return None;
    }
    t.find(pipe_id(fd)?, false)
}

/// A wait on `fd` ended: whether this set takes a write, being the one it
/// woke (true too for a descriptor no slot counts).
pub fn take(fd: i32) -> bool {
    let Some(s) = slot_of(fd) else { return true };
    let mut taken = s[3].load(Ordering::Acquire);
    loop {
        if taken >= s[2].load(Ordering::Acquire) {
            return false;
        }
        match s[3].compare_exchange(taken, taken + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(now) => taken = now,
        }
    }
}

/// `fd` was ready when asked: every write so far is taken.
pub fn take_all(fd: i32) {
    if let Some(s) = slot_of(fd) {
        s[3].fetch_max(s[2].load(Ordering::Acquire), Ordering::AcqRel);
    }
}

/// The writes to `fd` so far, to wait for another with
/// [`wait_for_write`].
pub fn writes(fd: i32) -> Option<u64> {
    slot_of(fd).map(|s| s[2].load(Ordering::Acquire))
}

/// Wait up to `slice` for a write to `fd` after the `seen`th.
pub fn wait_for_write(fd: i32, seen: u64, slice: std::time::Duration) {
    match slot_of(fd) {
        Some(s) => crate::shared::wait_word_for(&s[2], seen, slice),
        None => std::thread::sleep(slice),
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    #[test]
    fn a_made_pipe_frees_a_slot_its_identity_had() {
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // A slot with no write left to take may go to another pipe when
        // all are in use (the table is the user's, shared by other tests):
        // until this one keeps its own.
        let kept = (0..20).any(|_| {
            super::watch(fds[0]);
            super::wrote(fds[1]);
            super::wrote(fds[1]);
            super::writes(fds[0]) == Some(2)
        });
        assert!(kept);
        // A new pipe with this identity (the host reuses them) counts
        // nothing left by the old one.
        super::made(fds[0]);
        assert_eq!(super::writes(fds[0]), None);
        // SAFETY: closing the descriptors made above.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
