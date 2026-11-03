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

/// Read the futex word from guest memory (an aligned single load).
fn load(uaddr: u64) -> crate::uaccess::Result<u32> {
    crate::uaccess::read(uaddr)
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
            let deadline = crate::guest!(wait_deadline(timeout));
            wait(uaddr, val, deadline)
        }
        futex::FUTEX_WAIT_BITSET => {
            // Treat the bitset variant as a plain wait. Its timeout is
            // absolute, on CLOCK_MONOTONIC unless FUTEX_CLOCK_REALTIME is set.
            let realtime = op & futex::FUTEX_CLOCK_REALTIME != 0;
            let deadline = crate::guest!(wait_deadline_abs(timeout, realtime));
            wait(uaddr, val, deadline)
        }
        futex::FUTEX_WAKE | futex::FUTEX_WAKE_BITSET => wake(uaddr, val),
        _ => err(errno::ENOSYS),
    }
}

/// Parse a relative `FUTEX_WAIT` timeout into an absolute deadline.
///
fn wait_deadline(timeout: u64) -> crate::uaccess::Result<Option<Instant>> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts: Timespec = crate::uaccess::read(timeout)?;
    Ok(Some(
        Instant::now()
            + Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32),
    ))
}

/// A `FUTEX_WAIT_BITSET` absolute timeout as a deadline. The value is on the
/// guest's CLOCK_MONOTONIC, or CLOCK_REALTIME when `realtime` is set; it is
/// read against the same host clock the guest's `clock_gettime` reports, and
/// the remaining time is carried over to an `Instant`.
fn wait_deadline_abs(timeout: u64, realtime: bool) -> crate::uaccess::Result<Option<Instant>> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts: Timespec = crate::uaccess::read(timeout)?;
    let clock = if realtime { libc::CLOCK_REALTIME } else { libc::CLOCK_MONOTONIC };
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `now` is a valid out-parameter.
    unsafe { libc::clock_gettime(clock, &mut now) };
    let now = Duration::new(now.tv_sec.max(0) as u64, now.tv_nsec.clamp(0, 999_999_999) as u32);
    let target = Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32);
    Ok(Some(Instant::now() + target.saturating_sub(now)))
}

/// Run `f` holding the wait-queue lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = table().queues.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// How often a blocked futex wait checks for a pending signal.
const SIGNAL_CHECK: Duration = Duration::from_millis(20);

/// Block while the futex word still equals `val`.
fn wait(uaddr: u64, val: u32, deadline: Option<Instant>) -> i64 {
    let table = table();
    let mut queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
    // Re-check under the lock: if the value already differs, do not sleep.
    match load(uaddr) {
        Ok(v) if v == val => {}
        Ok(_) => return err(errno::EAGAIN),
        Err(e) => return err(e),
    }
    *queues.entry(uaddr).or_insert(0) += 1;
    loop {
        if load(uaddr) != Ok(val) {
            break;
        }
        // A condition variable is not interrupted by host signals, so wait in
        // slices and check for a signal the guest should take, which ends the
        // wait with EINTR as on Linux.
        if crate::thread::deliverable() != 0 {
            decrement(&mut queues, uaddr);
            return err(errno::EINTR);
        }
        if crate::thread::pending() & crate::signalfd::watched() != 0 {
            // A signal for a signalfd landed on this thread; queue it there
            // (outside the wait-queue lock, which ranks below the signalfd
            // registry's) so the reader wakes.
            drop(queues);
            crate::signal::drain_to_signalfd();
            queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
            continue;
        }
        let now = Instant::now();
        let slice = match deadline {
            Some(d) if now >= d => {
                decrement(&mut queues, uaddr);
                return err(errno::ETIMEDOUT);
            }
            Some(d) => (d - now).min(SIGNAL_CHECK),
            None => SIGNAL_CHECK,
        };
        queues = table.cv.wait_timeout(queues, slice).unwrap_or_else(|e| e.into_inner()).0;
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
    let queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
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

    /// An absolute `FUTEX_WAIT_BITSET` deadline is on CLOCK_MONOTONIC (the
    /// guest's clock for it), not the realtime clock: a deadline a little in
    /// the future must actually be waited for, not reported expired at once.
    #[test]
    fn bitset_wait_honours_monotonic_deadline() {
        use fwe_abi::futex::{FUTEX_CLOCK_REALTIME, FUTEX_WAIT_BITSET};
        let word = AtomicU32::new(0);
        let addr = &word as *const _ as u64;
        for (clock, flags) in
            [(libc::CLOCK_MONOTONIC, 0), (libc::CLOCK_REALTIME, FUTEX_CLOCK_REALTIME)]
        {
            let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: `now` is a valid out-parameter.
            unsafe { libc::clock_gettime(clock, &mut now) };
            let mut ts = Timespec { tv_sec: now.tv_sec, tv_nsec: now.tv_nsec + 40_000_000 };
            if ts.tv_nsec >= 1_000_000_000 {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1_000_000_000;
            }
            let start = Instant::now();
            // SAFETY: both pointers are to live locals.
            let r = unsafe { op(addr, FUTEX_WAIT_BITSET | flags, 0, &ts as *const _ as u64) };
            assert_eq!(r, err(errno::ETIMEDOUT));
            assert!(start.elapsed() >= Duration::from_millis(30), "returned early");
        }
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
