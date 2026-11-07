//! Futexes: `FUTEX_WAIT` blocks and `FUTEX_WAKE` wakes.
//!
//! A private futex (`FUTEX_PRIVATE_FLAG`, what a process's own locks use)
//! is the process's: its wait queues live here, outside the kernel lock,
//! and operate only on raw guest memory (the futex word) and their own
//! synchronization. A shared one, as Linux keys it by the memory itself,
//! may be woken from another process that maps the same memory (a
//! process-shared lock, condition or semaphore, in `/dev/shm` or a
//! `MAP_SHARED` mapping): it waits on the host's own shared address waits
//! ([`shared`]), which key on the memory too. A backend runs a futex
//! operation **without** holding the kernel lock, so a waiting thread
//! never blocks the threads that would wake it.

use fwe_abi::{Timespec, err, errno, futex};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One waiter on a private futex: what it waits for, and whether a wake
/// has claimed it.
struct Waiter {
    bits: u32,
    woken: AtomicBool,
}

/// The private futexes' wait queues, keyed by the guest address of the
/// futex word, oldest waiter first. A wake takes its waiters off the queue
/// and marks them woken, as Linux does (it reports how many, and wakes
/// them whatever the word holds); one global condvar backs them, on which
/// each waiter looks for its own mark.
struct Table {
    queues: Mutex<HashMap<u64, VecDeque<Arc<Waiter>>>>,
    cv: Condvar,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table { queues: Mutex::new(HashMap::new()), cv: Condvar::new() })
}

/// Read the futex word from guest memory (an aligned single load).
pub(crate) fn load(uaddr: u64) -> crate::uaccess::Result<u32> {
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
    // SAFETY: the caller's guarantee, passed on; no second address.
    unsafe { op_full(uaddr, op, val, timeout, 0, u32::MAX) }
}

/// [`op`] with `futex`'s fifth and sixth arguments: `uaddr2` and `val3`
/// (the bitset of the bitset operations, the expected value of
/// `FUTEX_CMP_REQUEUE`). For the requeue operations `timeout` is the
/// number to move (`val2`).
///
/// # Safety
/// As for [`op`].
pub unsafe fn op_full(uaddr: u64, op: u64, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
    if uaddr % 4 != 0 {
        return err(errno::EINVAL);
    }
    let private = op & futex::FUTEX_PRIVATE_FLAG != 0;
    let cmd = op & futex::FUTEX_CMD_MASK;
    // Linux finds the word's memory for every operation, a wake's too:
    // `EFAULT` where there is none to read.
    if matches!(cmd, futex::FUTEX_WAKE | futex::FUTEX_WAKE_BITSET | futex::FUTEX_REQUEUE)
        && let Err(e) = load(uaddr)
    {
        return err(e);
    }
    if matches!(cmd, futex::FUTEX_REQUEUE | futex::FUTEX_CMP_REQUEUE)
        && let Err(e) = load(uaddr2)
    {
        return err(e);
    }
    match cmd {
        futex::FUTEX_WAIT => {
            let deadline = crate::guest!(wait_deadline(timeout));
            if private {
                wait_private(uaddr, val, deadline)
            } else {
                shared::wait(uaddr, val, deadline, u32::MAX)
            }
        }
        futex::FUTEX_WAIT_BITSET => {
            if val3 == 0 {
                return err(errno::EINVAL);
            }
            // Its timeout is absolute, on CLOCK_MONOTONIC unless
            // FUTEX_CLOCK_REALTIME is set.
            let realtime = op & futex::FUTEX_CLOCK_REALTIME != 0;
            let deadline = crate::guest!(wait_deadline_abs(timeout, realtime));
            if private {
                wait_private_bits(uaddr, val, deadline, val3)
            } else {
                shared::wait(uaddr, val, deadline, val3)
            }
        }
        futex::FUTEX_WAKE if private => wake_private(uaddr, val),
        futex::FUTEX_WAKE => shared::wake(uaddr, val, u32::MAX),
        futex::FUTEX_WAKE_BITSET if val3 == 0 => err(errno::EINVAL),
        futex::FUTEX_WAKE_BITSET if private => wake_private_bits(uaddr, val, val3),
        futex::FUTEX_WAKE_BITSET => shared::wake(uaddr, val, val3),
        futex::FUTEX_REQUEUE | futex::FUTEX_CMP_REQUEUE => {
            if uaddr2 % 4 != 0 || (val as i32) < 0 || (timeout as i32) < 0 {
                return err(errno::EINVAL);
            }
            let expect = (op & futex::FUTEX_CMD_MASK == futex::FUTEX_CMP_REQUEUE).then_some(val3);
            let moved = timeout as u32;
            if private {
                requeue_private(uaddr, val, moved, uaddr2, expect)
            } else {
                if let Some(v3) = expect {
                    match load(uaddr) {
                        Ok(v) if v == v3 => {}
                        Ok(_) => return err(errno::EAGAIN),
                        Err(e) => return err(e),
                    }
                }
                shared::requeue(uaddr, val, moved, uaddr2)
            }
        }
        _ => err(errno::ENOSYS),
    }
}

/// This process starts, or runs another program: no thread of it waits on
/// a shared futex ([`shared`]).
pub fn process_started() {
    #[cfg(target_os = "macos")]
    shared::process_started();
}

/// Wake up to `count` waiters on the word at `uaddr`, private or shared
/// (for what fwe itself wakes, as Linux wakes a thread's
/// `clear_child_tid` word as it ends, which C libraries wait on either
/// way).
pub fn wake_any(uaddr: u64, count: u32) -> i64 {
    let woken = wake_private(uaddr, count);
    if cfg!(not(target_os = "macos")) || woken >= count as i64 {
        return woken;
    }
    woken + shared::wake(uaddr, count - woken as u32, u32::MAX).max(0)
}

#[cfg(target_os = "macos")]
use crate::sharedfutex as shared;

/// Elsewhere every futex is the process's own.
#[cfg(not(target_os = "macos"))]
mod shared {
    use super::Instant;

    pub fn wait(uaddr: u64, val: u32, deadline: Option<Instant>, bits: u32) -> i64 {
        super::wait_private_bits(uaddr, val, deadline, bits)
    }

    pub fn wake(uaddr: u64, count: u32, bits: u32) -> i64 {
        super::wake_private_bits(uaddr, count, bits)
    }

    pub fn requeue(uaddr: u64, wake: u32, requeue: u32, uaddr2: u64) -> i64 {
        super::requeue_private(uaddr, wake, requeue, uaddr2, None)
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
pub(crate) const SIGNAL_CHECK: Duration = Duration::from_millis(20);

/// Block while the futex word still equals `val` (a private futex), until
/// a wake claims this waiter.
pub(crate) fn wait_private(uaddr: u64, val: u32, deadline: Option<Instant>) -> i64 {
    wait_private_bits(uaddr, val, deadline, u32::MAX)
}

/// [`wait_private`] for a wake for any of `bits` (`FUTEX_WAIT_BITSET`).
pub(crate) fn wait_private_bits(uaddr: u64, val: u32, deadline: Option<Instant>, bits: u32) -> i64 {
    let table = table();
    let mut queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
    // Compared under the lock a waker takes: a wake that follows a change
    // of the word either finds this waiter queued or the word changed.
    match load(uaddr) {
        Ok(v) if v == val => {}
        Ok(_) => return err(errno::EAGAIN),
        Err(e) => return err(e),
    }
    let me = Arc::new(Waiter { bits, woken: AtomicBool::new(false) });
    queues.entry(key(uaddr)).or_default().push_back(me.clone());
    loop {
        if me.woken.load(Ordering::SeqCst) {
            return 0;
        }
        // The word changed under it: a wake it was not counted in may be
        // on its way (a waiter may always wake spuriously, and its caller
        // looks at the word again), so it leaves rather than risk missing
        // one sent under another name for the word.
        if load(uaddr) != Ok(val) {
            leave(&mut queues, &me, 0);
            return 0;
        }
        // A condition variable is not interrupted by host signals, so wait in
        // slices and check for a signal the guest should take, which ends the
        // wait with EINTR as on Linux.
        if crate::thread::deliverable() != 0 {
            return leave(&mut queues, &me, errno::EINTR);
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
            Some(d) if now >= d => return leave(&mut queues, &me, errno::ETIMEDOUT),
            Some(d) => (d - now).min(SIGNAL_CHECK),
            None => SIGNAL_CHECK,
        };
        queues = table.cv.wait_timeout(queues, slice).unwrap_or_else(|e| e.into_inner()).0;
    }
}

type Queues = HashMap<u64, VecDeque<Arc<Waiter>>>;

/// A waiter giving up with `e`: off whichever queue it is on (a requeue
/// may have moved it), unless a wake claimed it first (then it was woken:
/// 0).
fn leave(queues: &mut Queues, me: &Arc<Waiter>, e: i32) -> i64 {
    if me.woken.load(Ordering::SeqCst) {
        return 0;
    }
    queues.retain(|_, q| {
        q.retain(|w| !Arc::ptr_eq(w, me));
        !q.is_empty()
    });
    err(e)
}

/// Take up to `count` waiters for any of `bits` off `uaddr`'s queue,
/// oldest first.
fn take(queues: &mut Queues, uaddr: u64, count: u32, bits: u32) -> Vec<Arc<Waiter>> {
    let mut out = Vec::new();
    if let Some(q) = queues.get_mut(&uaddr) {
        let mut i = 0;
        while i < q.len() && out.len() < count as usize {
            if q[i].bits & bits != 0 {
                out.extend(q.remove(i));
            } else {
                i += 1;
            }
        }
        if q.is_empty() {
            queues.remove(&uaddr);
        }
    }
    out
}

/// The queue a private futex at `uaddr` is on: its guest address (a
/// backend may give a call the address it translated, while fwe's own
/// wakes, of a thread's `clear_child_tid` word, use the guest's).
fn key(uaddr: u64) -> u64 {
    crate::uaccess::guest_of(uaddr)
}

/// A fork child has none of its parent's other threads: their waits are
/// not its own (a wake must not take them).
pub fn forked_child() {
    table().queues.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Mark `woken` woken and let them see it.
fn wake_all_of(table: &Table, woken: &[Arc<Waiter>]) {
    for w in woken {
        w.woken.store(true, Ordering::SeqCst);
    }
    if !woken.is_empty() {
        table.cv.notify_all();
    }
}

/// Wake up to `count` waiters on private futex `uaddr`: the number woken.
pub(crate) fn wake_private(uaddr: u64, count: u32) -> i64 {
    wake_private_bits(uaddr, count, u32::MAX)
}

/// [`wake_private`] of the waiters for any of `bits`
/// (`FUTEX_WAKE_BITSET`).
pub(crate) fn wake_private_bits(uaddr: u64, count: u32, bits: u32) -> i64 {
    let table = table();
    let mut queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
    let woken = take(&mut queues, key(uaddr), count, bits);
    wake_all_of(table, &woken);
    woken.len() as i64
}

/// `FUTEX_CMP_REQUEUE` of private futexes: wake up to `wake` waiters of
/// `uaddr`, move up to `requeue` of the rest to `uaddr2`: the number woken
/// and moved.
pub(crate) fn requeue_private(
    uaddr: u64,
    wake: u32,
    requeue: u32,
    uaddr2: u64,
    expect: Option<u32>,
) -> i64 {
    let table = table();
    let mut queues = table.queues.lock().unwrap_or_else(|e| e.into_inner());
    // `FUTEX_CMP_REQUEUE`'s comparison, under the lock a waiter queues
    // under, as Linux makes it: no waiter comes or goes in between.
    if let Some(v3) = expect {
        match load(uaddr) {
            Ok(v) if v == v3 => {}
            Ok(_) => return err(errno::EAGAIN),
            Err(e) => return err(e),
        }
    }
    let (uaddr, uaddr2) = (key(uaddr), key(uaddr2));
    let woken = take(&mut queues, uaddr, wake, u32::MAX);
    wake_all_of(table, &woken);
    let moved = take(&mut queues, uaddr, requeue, u32::MAX);
    let n = moved.len();
    queues.entry(uaddr2).or_default().extend(moved);
    (woken.len() + n) as i64
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
