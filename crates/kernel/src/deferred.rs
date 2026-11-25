//! One value kept apart from a structure under a lock: put there without
//! the lock, taken back the same way, or put into the structure by whoever
//! takes the lock next ([`Deferred::take`]). A mapping made and unmapped at
//! once, as an allocator's often is, so costs neither the mapping record's
//! lock nor the address space's.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU8, Ordering::*};

/// Nothing kept.
const EMPTY: u8 = 0;
/// A value kept, to read.
const FULL: u8 = 1;
/// A thread is writing or reading the value: no other can.
const BUSY: u8 = 2;

/// A value kept apart ([`Deferred::put`]), if any. Each thread that uses
/// the value owns it while the state is [`BUSY`], which only it set, so a
/// value is never read while written.
pub(crate) struct Deferred<T: Copy> {
    state: AtomicU8,
    value: UnsafeCell<T>,
}

// SAFETY: the value is accessed only by the thread that moved the state to
// `BUSY` (see the type's comment); `T: Copy + Send` values are moved
// between threads by copy.
unsafe impl<T: Copy + Send> Sync for Deferred<T> {}

impl<T: Copy> Deferred<T> {
    /// Nothing kept (`unused` fills the room until a value is).
    pub(crate) const fn new(unused: T) -> Deferred<T> {
        Deferred { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(unused) }
    }

    /// Keep `v` apart, if nothing is kept: false if something is (or a
    /// thread is using the room), and the caller puts `v` in itself.
    pub(crate) fn put(&self, v: T) -> bool {
        if self.state.compare_exchange(EMPTY, BUSY, Acquire, Relaxed).is_err() {
            return false;
        }
        // SAFETY: this thread set `BUSY`, so the value is its own.
        unsafe { *self.value.get() = v };
        self.state.store(FULL, Release);
        true
    }

    /// Take the value kept back if `wanted` says it is the one: whether it
    /// was (false if another was kept, none was, or another thread was
    /// putting it in its structure, where it then is).
    pub(crate) fn take_back(&self, wanted: impl FnOnce(&T) -> bool) -> bool {
        if self.state.load(Relaxed) != FULL
            || self.state.compare_exchange(FULL, BUSY, Acquire, Relaxed).is_err()
        {
            return false;
        }
        // SAFETY: this thread set `BUSY`, so the value is its own.
        let v = unsafe { *self.value.get() };
        let taken = wanted(&v);
        self.state.store(if taken { EMPTY } else { FULL }, Release);
        taken
    }

    /// The value kept, taken, for a holder of the structure's lock to put
    /// in: none if none was kept, or a thread was putting one there (its
    /// call not yet done).
    pub(crate) fn take(&self) -> Option<T> {
        if self.state.load(Relaxed) != FULL
            || self.state.compare_exchange(FULL, BUSY, Acquire, Relaxed).is_err()
        {
            return None;
        }
        // SAFETY: this thread set `BUSY`, so the value is its own.
        let v = unsafe { *self.value.get() };
        self.state.store(EMPTY, Release);
        Some(v)
    }

    /// Whether a value is kept (or being used): for a count that includes it.
    pub(crate) fn is_kept(&self) -> bool {
        self.state.load(Relaxed) != EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_kept_once_and_taken_once() {
        let d = Deferred::new(0u64);
        assert!(d.put(7));
        assert!(!d.put(8), "one kept already");
        assert!(d.is_kept());
        assert!(!d.take_back(|&v| v == 8), "not the one kept");
        assert!(d.take_back(|&v| v == 7));
        assert!(!d.is_kept());
        assert_eq!(d.take(), None);
        assert!(d.put(9));
        assert_eq!(d.take(), Some(9));
        assert!(!d.take_back(|_| true));
    }

    #[test]
    fn threads_racing_take_each_value_once() {
        let d = std::sync::Arc::new(Deferred::new(0u64));
        let taken = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut threads = Vec::new();
        for _ in 0..3 {
            let (d, taken) = (d.clone(), taken.clone());
            threads.push(std::thread::spawn(move || {
                for _ in 0..20_000 {
                    if let Some(v) = d.take() {
                        taken.fetch_add(v, Relaxed);
                    }
                }
            }));
        }
        let mut put = 0;
        for i in 1..=20_000u64 {
            if d.put(i) {
                put += i;
            }
            if d.take_back(|&v| v == i) {
                put -= i;
            }
        }
        for t in threads {
            t.join().unwrap();
        }
        if let Some(v) = d.take() {
            taken.fetch_add(v, Relaxed);
        }
        assert_eq!(taken.load(Relaxed), put, "every value kept was taken once");
    }
}
