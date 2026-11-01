//! A process-global futex: `FUTEX_WAIT` blocks and `FUTEX_WAKE` wakes, across
//! the host threads that run the guest's threads.
//!
//! The wait queues live here, outside the kernel lock, and operate only on
//! raw guest memory (the futex word) and their own synchronization. A backend
//! therefore runs a futex operation **without** holding the kernel lock, so a
//! waiting thread never blocks the threads that would wake it.

use fwe_abi::{Timespec, err, errno, futex};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// All wait queues, keyed by the guest address of the futex word. One global
/// condvar backs them; a woken waiter rechecks its own word and re-sleeps if
/// it was not the target (spurious wakeups are permitted for futexes).
struct Table {
    queues: Mutex<HashMap<u64, usize>>,
    cv: Condvar,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table { queues: Mutex::new(HashMap::new()), cv: Condvar::new() })
}

/// Read the futex word from guest memory.
///
/// # Safety
/// `uaddr` must point to a 4-byte-aligned readable guest word.
unsafe fn load(uaddr: u64) -> u32 {
    // SAFETY: the caller guarantees a readable aligned word.
    unsafe { (uaddr as *const u32).read() }
}

/// Run a `futex` operation. Returns the raw Linux result. Must be called
/// without the kernel lock held, because `FUTEX_WAIT` blocks.
///
/// # Safety
/// `uaddr` (and `timeout`, when non-null) must point to valid guest memory.
pub unsafe fn op(uaddr: u64, op: u64, val: u32, timeout: u64) -> i64 {
    if uaddr % 4 != 0 {
        return err(errno::EINVAL);
    }
    match op & futex::FUTEX_CMD_MASK {
        futex::FUTEX_WAIT => {
            // SAFETY: caller guarantees `timeout` is valid when non-null.
            let deadline = unsafe { wait_deadline(timeout) };
            // SAFETY: caller guarantees `uaddr` is valid.
            unsafe { wait(uaddr, val, deadline) }
        }
        futex::FUTEX_WAIT_BITSET => {
            // Treat the bitset variant as a plain wait (absolute timeout).
            // SAFETY: caller guarantees `timeout` is valid when non-null.
            let deadline = unsafe { wait_deadline_abs(timeout) };
            // SAFETY: caller guarantees `uaddr` is valid.
            unsafe { wait(uaddr, val, deadline) }
        }
        futex::FUTEX_WAKE | futex::FUTEX_WAKE_BITSET => wake(uaddr, val),
        _ => err(errno::ENOSYS),
    }
}

/// Parse a relative `FUTEX_WAIT` timeout into an absolute deadline.
///
/// # Safety
/// `timeout`, when non-null, must point to a guest `Timespec`.
unsafe fn wait_deadline(timeout: u64) -> Option<Instant> {
    if timeout == 0 {
        return None;
    }
    // SAFETY: the caller guarantees a valid pointer.
    let ts: Timespec = unsafe { (timeout as *const Timespec).read_unaligned() };
    Some(
        Instant::now()
            + Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32),
    )
}

/// A `FUTEX_WAIT_BITSET` absolute (CLOCK_MONOTONIC) timeout as a deadline.
///
/// # Safety
/// `timeout`, when non-null, must point to a guest `Timespec`.
unsafe fn wait_deadline_abs(timeout: u64) -> Option<Instant> {
    if timeout == 0 {
        return None;
    }
    // Approximate: treat the absolute time as a short relative wait from now
    // bounded by the value, since we cannot map another clock's epoch onto
    // Instant. A spurious early return is permitted for futexes.
    // SAFETY: the caller guarantees a valid pointer.
    let ts: Timespec = unsafe { (timeout as *const Timespec).read_unaligned() };
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let target = Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32);
    Some(Instant::now() + target.saturating_sub(now))
}

/// Block while the futex word still equals `val`.
///
/// # Safety
/// `uaddr` must point to a valid guest futex word.
unsafe fn wait(uaddr: u64, val: u32, deadline: Option<Instant>) -> i64 {
    let table = table();
    let mut queues = table.queues.lock().unwrap();
    // Re-check under the lock: if the value already differs, do not sleep.
    // SAFETY: caller guarantees `uaddr` is valid.
    if unsafe { load(uaddr) } != val {
        return err(errno::EAGAIN);
    }
    *queues.entry(uaddr).or_insert(0) += 1;
    loop {
        // SAFETY: caller guarantees `uaddr` is valid.
        if unsafe { load(uaddr) } != val {
            break;
        }
        let timed_out;
        (queues, timed_out) = match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    (queues, true)
                } else {
                    let (g, r) = table.cv.wait_timeout(queues, d - now).unwrap();
                    (g, r.timed_out())
                }
            }
            None => (table.cv.wait(queues).unwrap(), false),
        };
        // SAFETY: caller guarantees `uaddr` is valid.
        if timed_out && unsafe { load(uaddr) } == val {
            decrement(&mut queues, uaddr);
            return err(errno::ETIMEDOUT);
        }
    }
    decrement(&mut queues, uaddr);
    0
}

fn decrement(queues: &mut HashMap<u64, usize>, uaddr: u64) {
    if let Some(n) = queues.get_mut(&uaddr) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            queues.remove(&uaddr);
        }
    }
}

/// Wake up to `count` waiters on `uaddr`. Returns the number that may have
/// been waiting (an upper bound, as Linux allows).
fn wake(uaddr: u64, count: u32) -> i64 {
    let table = table();
    let queues = table.queues.lock().unwrap();
    let waiting = queues.get(&uaddr).copied().unwrap_or(0);
    // Wake everyone; each waiter rechecks its own word and re-sleeps if it was
    // not the target.
    table.cv.notify_all();
    (waiting.min(count as usize)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::futex::{FUTEX_WAIT, FUTEX_WAKE};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;

    #[test]
    fn wait_returns_eagain_on_mismatch() {
        let word = AtomicU32::new(5);
        let addr = &word as *const _ as u64;
        // SAFETY: `addr` points to our live word.
        let r = unsafe { op(addr, FUTEX_WAIT, 1, 0) };
        assert_eq!(r, err(errno::EAGAIN));
    }

    #[test]
    fn wake_unblocks_a_waiter() {
        // A heap word so both threads share the address.
        let word = Box::leak(Box::new(AtomicU32::new(0)));
        let addr = word as *const _ as u64;
        let waiter = thread::spawn(move || {
            // SAFETY: `addr` points to the leaked word, valid for the process.
            unsafe { op(addr, FUTEX_WAIT, 0, 0) }
        });
        // Give the waiter time to block, then change the value and wake it.
        thread::sleep(Duration::from_millis(50));
        word.store(1, Ordering::SeqCst);
        // SAFETY: same valid address.
        let woken = unsafe { op(addr, FUTEX_WAKE, 1, 0) };
        assert_eq!(waiter.join().unwrap(), 0);
        assert!(woken <= 1);
    }

    #[test]
    fn wait_times_out() {
        let word = AtomicU32::new(0);
        let addr = &word as *const _ as u64;
        let ts = Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
        // SAFETY: both pointers are to live locals.
        let r = unsafe { op(addr, FUTEX_WAIT, 0, &ts as *const _ as u64) };
        assert_eq!(r, err(errno::ETIMEDOUT));
    }
}
