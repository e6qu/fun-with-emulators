//! Futexes: `FUTEX_WAIT` blocks and `FUTEX_WAKE` wakes; `FUTEX_WAKE_OP`
//! also changes a second word atomically and wakes that one's waiters when
//! its old value meets a comparison; the requeues move waiters to another.
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One waiter on a private futex: what it waits for, whether a wake has
/// claimed it, and where its thread sleeps.
struct Waiter {
    bits: u32,
    woken: AtomicBool,
    park: Arc<Park>,
}

/// Where one wait's thread sleeps (for `futex_waitv`, its every futex's
/// waiter): a word of its own, which a wake sets and wakes the thread on,
/// and no other.
struct Park {
    /// 0 until a wake.
    word: AtomicU32,
    /// Its thread's wake pipe, written as it is woken while it naps close
    /// to its deadline ([`crate::thread::nap_ns`]), to end the nap at once;
    /// -1 for none.
    poke: i32,
    napping: AtomicBool,
}

impl Park {
    fn new() -> Arc<Park> {
        Arc::new(Park {
            word: AtomicU32::new(0),
            poke: crate::thread::poke_fd(),
            napping: AtomicBool::new(false),
        })
    }

    /// Sleep until woken, `most` at most (or a host signal).
    fn sleep(&self, most: Duration) {
        let ns = most.as_nanos().min(u64::MAX as u128) as u64;
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn __ulock_wait2(op: u32, a: *mut libc::c_void, v: u64, t: u64, v2: u64) -> i32;
            }
            // `UL_COMPARE_AND_WAIT | ULF_NO_ERRNO`: this process's own word.
            // SAFETY: waits on the park's word while it holds 0.
            unsafe { __ulock_wait2(1 | 0x0100_0000, self.word.as_ptr().cast(), 0, ns, 0) };
        }
        #[cfg(not(target_os = "macos"))]
        {
            let t = libc::timespec {
                tv_sec: (ns / 1_000_000_000) as libc::time_t,
                tv_nsec: (ns % 1_000_000_000) as libc::c_long,
            };
            // SAFETY: a private futex wait on the park's word while it is 0.
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.word.as_ptr(),
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    0,
                    &t,
                );
            }
        }
    }

    /// Mark it woken, and end its thread's nap if it naps. Called with the
    /// queues locked: a thread napping cannot have left its wait (nor
    /// ended) meanwhile, so its wake pipe is still its own.
    fn mark(&self) {
        self.word.store(1, Ordering::SeqCst);
        if self.napping.load(Ordering::SeqCst) && self.poke >= 0 {
            // SAFETY: one byte to the waiting thread's own non-blocking
            // pipe; a full pipe is woken already.
            unsafe { libc::write(self.poke, b"f".as_ptr().cast(), 1) };
        }
    }

    /// Wake its thread if it sleeps on its word, once [`Park::mark`]ed:
    /// with the queues let go, as the host's wake is a system call that
    /// may switch to the thread woken, and every futex call waits for the
    /// queues. (A thread that left its wait meanwhile is woken by none:
    /// the word is the park's, alive while it is held.)
    fn rouse(&self) {
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn __ulock_wake(op: u32, a: *mut libc::c_void, v: u64) -> i32;
            }
            // `UL_COMPARE_AND_WAIT | ULF_NO_ERRNO`.
            // SAFETY: wakes the thread waiting on the park's word.
            unsafe { __ulock_wake(1 | 0x0100_0000, self.word.as_ptr().cast(), 0) };
        }
        #[cfg(not(target_os = "macos"))]
        // SAFETY: a private futex wake on the park's word.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.word.as_ptr(),
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                1,
            );
        }
    }
}

/// The private futexes' wait queues, keyed by the guest address of the
/// futex word, oldest waiter first. A wake takes its waiters off the queue
/// and marks them woken, as Linux does (it reports how many, and wakes
/// them whatever the word holds), and wakes each one's thread alone.
struct Table {
    queues: Mutex<HashMap<u64, VecDeque<Arc<Waiter>>>>,
}

impl Table {
    /// The queues, locked ([`crate::shortlock`]: held for moments).
    fn lock(&self) -> std::sync::MutexGuard<'_, Queues> {
        crate::shortlock::lock(&self.queues)
    }
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table { queues: Mutex::new(HashMap::new()) })
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
    if !uaddr.is_multiple_of(4) {
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
    if !uaddr.is_multiple_of(4) {
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
        futex::FUTEX_WAKE if private => wake_private(uaddr, wake_count(val)),
        futex::FUTEX_WAKE => shared::wake(uaddr, wake_count(val), u32::MAX),
        futex::FUTEX_WAKE_BITSET if val3 == 0 => err(errno::EINVAL),
        futex::FUTEX_WAKE_BITSET if private => wake_private_bits(uaddr, wake_count(val), val3),
        futex::FUTEX_WAKE_BITSET => shared::wake(uaddr, wake_count(val), val3),
        futex::FUTEX_WAKE_OP => {
            if !uaddr2.is_multiple_of(4) {
                return err(errno::EINVAL);
            }
            // A shared futex's key is found in its memory.
            if !private && let Err(e) = load(uaddr) {
                return err(e);
            }
            let hit = match wake_op_apply(uaddr2, val3) {
                Ok(hit) => hit,
                Err(e) => return err(e),
            };
            let wake = |addr: u64, n: u32| {
                if private { wake_private(addr, n) } else { shared::wake(addr, n, u32::MAX) }
            };
            let mut woken = wake(uaddr, wake_count(val));
            if hit {
                woken += wake(uaddr2, wake_count(timeout as u32)).max(0);
            }
            woken
        }
        futex::FUTEX_REQUEUE | futex::FUTEX_CMP_REQUEUE => {
            if !uaddr2.is_multiple_of(4) || (val as i32) < 0 || (timeout as i32) < 0 {
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

/// How many waiters a wake of `n` wakes: Linux counts it as an `int` and
/// wakes one before it compares, so 0 or a negative count wakes one.
fn wake_count(n: u32) -> u32 {
    (n as i32).max(1) as u32
}

/// `FUTEX_WAKE_OP`'s operation `encoded` on the word at `uaddr2`, done
/// atomically as Linux's `futex_atomic_op_inuser`: the word set to the
/// result of the operation on it, then whether its old value meets the
/// comparison. An unknown operation changes nothing; an unknown
/// comparison comes after the change (`ENOSYS` either way).
fn wake_op_apply(uaddr2: u64, encoded: u32) -> Result<bool, i32> {
    use futex::*;
    let op = (encoded >> 28) & 7;
    let cmp = (encoded >> 24) & 15;
    // The arguments' 12 bits, sign-extended.
    let mut oparg = ((encoded << 8) as i32) >> 20;
    let cmparg = ((encoded << 20) as i32) >> 20;
    if encoded & (FUTEX_OP_OPARG_SHIFT << 28) != 0 {
        // Linux takes a shift past 31 modulo 32.
        oparg = 1i32.wrapping_shl((oparg & 31) as u32);
    }
    let apply = |old: u32| -> Option<u32> {
        let a = oparg as u32;
        Some(match op {
            FUTEX_OP_SET => a,
            FUTEX_OP_ADD => old.wrapping_add(a),
            FUTEX_OP_OR => old | a,
            FUTEX_OP_ANDN => old & !a,
            FUTEX_OP_XOR => old ^ a,
            _ => return None,
        })
    };
    let mut old = load(uaddr2)?;
    loop {
        let new = apply(old).ok_or(errno::ENOSYS)?;
        let seen = crate::uaccess::cmpxchg_u32(uaddr2, old, new)?;
        if seen == old {
            break;
        }
        old = seen;
    }
    let old = old as i32;
    match cmp {
        FUTEX_OP_CMP_EQ => Ok(old == cmparg),
        FUTEX_OP_CMP_NE => Ok(old != cmparg),
        FUTEX_OP_CMP_LT => Ok(old < cmparg),
        FUTEX_OP_CMP_LE => Ok(old <= cmparg),
        FUTEX_OP_CMP_GT => Ok(old > cmparg),
        FUTEX_OP_CMP_GE => Ok(old >= cmparg),
        _ => Err(errno::ENOSYS),
    }
}

/// `futex_waitv`'s most futexes.
const WAITV_MAX: u64 = 128;
/// `struct futex_waitv`'s flags: the word's size (only 32 bits), NUMA and
/// memory-policy keys (not offered), private.
const FUTEX2_SIZE_U32: u32 = 2;
const FUTEX2_SIZE_MASK: u32 = 3;
const FUTEX2_NUMA: u32 = 4;
const FUTEX2_MPOL: u32 = 8;
const FUTEX2_PRIVATE: u32 = 128;

/// A futex2 call's `flags` for one futex, checked as Linux checks them (a
/// 32-bit word only; no NUMA or memory-policy key: `EINVAL`): whether it
/// is private.
fn futex2_private(flags: u64) -> Result<bool, i32> {
    let known = u64::from(FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE);
    if flags & !known != 0
        || flags & u64::from(FUTEX2_SIZE_MASK) != u64::from(FUTEX2_SIZE_U32)
        || flags & u64::from(FUTEX2_NUMA | FUTEX2_MPOL) != 0
    {
        return Err(errno::EINVAL);
    }
    Ok(flags & u64::from(FUTEX2_PRIVATE) != 0)
}

/// The `futex` operation `cmd` for a futex2 call on a private futex or not.
fn futex2_op(cmd: u64, private: bool) -> u64 {
    if private { cmd | futex::FUTEX_PRIVATE_FLAG } else { cmd }
}

/// `futex_wake(uaddr, mask, nr, flags)`: wake up to `nr` waiters on the
/// futex whose bitset shares a bit with `mask`, as `FUTEX_WAKE_BITSET`.
///
/// # Safety
/// As for [`op`].
pub unsafe fn wake2(uaddr: u64, mask: u64, nr: u64, flags: u64) -> i64 {
    let private = match futex2_private(flags) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if mask == 0 || mask > u64::from(u32::MAX) {
        return err(errno::EINVAL);
    }
    // Strict, as Linux's: a count of 0 wakes none (the word found first).
    if nr as i32 == 0 {
        if !uaddr.is_multiple_of(4) {
            return err(errno::EINVAL);
        }
        return load(uaddr).map_or_else(err, |_| 0);
    }
    let nr = nr as u32;
    // SAFETY: the caller's guarantee, passed on.
    unsafe { op_full(uaddr, futex2_op(futex::FUTEX_WAKE_BITSET, private), nr, 0, 0, mask as u32) }
}

/// `futex_wait(uaddr, val, mask, flags, timeout, clockid)`: wait while the
/// futex holds `val`, until woken through `mask` or the absolute
/// `timeout` on `clockid`, as `FUTEX_WAIT_BITSET`.
///
/// # Safety
/// As for [`op`].
pub unsafe fn wait2(
    uaddr: u64,
    val: u64,
    mask: u64,
    flags: u64,
    timeout: u64,
    clockid: u64,
) -> i64 {
    let private = match futex2_private(flags) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if mask == 0 || mask > u64::from(u32::MAX) || val > u64::from(u32::MAX) {
        return err(errno::EINVAL);
    }
    let realtime = match clockid {
        fwe_abi::clock::CLOCK_MONOTONIC => false,
        fwe_abi::clock::CLOCK_REALTIME => true,
        _ => return err(errno::EINVAL),
    };
    let mut op = futex2_op(futex::FUTEX_WAIT_BITSET, private);
    if realtime {
        op |= futex::FUTEX_CLOCK_REALTIME;
    }
    // SAFETY: the caller's guarantee, passed on.
    unsafe { op_full(uaddr, op, val as u32, timeout, 0, mask as u32) }
}

/// `futex_requeue(waiters, flags, nr_wake, nr_requeue)`: on the first of
/// the two futexes `waiters` names (as `futex_waitv` does), still holding
/// its value, wake `nr_wake` waiters and move up to `nr_requeue` more to
/// the second, as `FUTEX_CMP_REQUEUE`. Both futexes are private or both
/// shared (fwe keeps the two kinds' waiters apart): `EINVAL` otherwise.
///
/// # Safety
/// The guest pointers are checked as they are read.
pub unsafe fn requeue2(waiters: u64, flags: u64, nr_wake: u64, nr_requeue: u64) -> i64 {
    if flags != 0 {
        return err(errno::EINVAL);
    }
    let raw = crate::guest!(crate::uaccess::read_bytes(waiters, 48));
    let mut futexes = [(0u64, 0u64, false); 2];
    for (i, w) in raw.as_chunks::<24>().0.iter().enumerate() {
        let val = u64::from_ne_bytes(w[0..8].try_into().unwrap());
        let uaddr = u64::from_ne_bytes(w[8..16].try_into().unwrap());
        let f = u32::from_ne_bytes(w[16..20].try_into().unwrap());
        let reserved = u32::from_ne_bytes(w[20..24].try_into().unwrap());
        let private = match futex2_private(u64::from(f)) {
            Ok(p) if reserved == 0 => p,
            _ => return err(errno::EINVAL),
        };
        futexes[i] = (uaddr, val, private);
    }
    let [(from, val, private), (to, _, to_private)] = futexes;
    if private != to_private || val > u64::from(u32::MAX) {
        return err(errno::EINVAL);
    }
    let op = futex2_op(futex::FUTEX_CMP_REQUEUE, private);
    let (wake, moved) = ((nr_wake as i32) as u32, (nr_requeue as i32) as u32);
    // SAFETY: the words are checked as they are read.
    unsafe { op_full(from, op, wake, u64::from(moved), to, val as u32) }
}

/// One futex `futex_waitv` waits on: in this process's queues, or in a
/// slot of the shared table ([`shared`]).
enum Held {
    Queued(Arc<Waiter>),
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Slot(usize),
}

impl Held {
    fn woken(&self) -> bool {
        match self {
            Held::Queued(w) => w.woken.load(Ordering::SeqCst),
            #[cfg(target_os = "macos")]
            Held::Slot(i) => shared::woken(*i),
            #[cfg(not(target_os = "macos"))]
            Held::Slot(_) => false,
        }
    }
}

/// `futex_waitv(waiters, nr, flags, timeout, clockid)`: wait on every
/// futex of `waiters` at once (while each word holds its value), until a
/// wake of any of them, whose index is the result, or the absolute
/// `timeout` on `clockid`. Must be called without the kernel lock held.
///
/// # Safety
/// The guest pointers are checked as they are read.
pub unsafe fn waitv(waiters: u64, nr: u64, flags: u64, timeout: u64, clockid: u64) -> i64 {
    // In Linux's order: the arguments, the timeout, then the futexes.
    if flags != 0 || nr == 0 || nr > WAITV_MAX || waiters == 0 {
        return err(errno::EINVAL);
    }
    let deadline = if timeout == 0 {
        None
    } else {
        // Linux's clock ids.
        let realtime = match clockid {
            fwe_abi::clock::CLOCK_MONOTONIC => false,
            fwe_abi::clock::CLOCK_REALTIME => true,
            _ => return err(errno::EINVAL),
        };
        crate::guest!(wait_deadline_abs(timeout, realtime))
    };
    let raw = crate::guest!(crate::uaccess::read_bytes(waiters, nr as usize * 24));
    let mut list: Vec<(u64, u32, bool)> = Vec::new();
    for w in raw.as_chunks::<24>().0.iter() {
        let val = u64::from_ne_bytes(w[0..8].try_into().unwrap());
        let uaddr = u64::from_ne_bytes(w[8..16].try_into().unwrap());
        let f = u32::from_ne_bytes(w[16..20].try_into().unwrap());
        let reserved = u32::from_ne_bytes(w[20..24].try_into().unwrap());
        let known = FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE;
        if f & !known != 0
            || reserved != 0
            || f & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32
            || f & (FUTEX2_NUMA | FUTEX2_MPOL) != 0
            || val > u64::from(u32::MAX)
            || uaddr % 4 != 0
        {
            return err(errno::EINVAL);
        }
        list.push((uaddr, val as u32, f & FUTEX2_PRIVATE != 0));
    }
    let table = table();
    let mut held: Vec<Held> = Vec::new();
    // Every one queued, then every word checked: a wake after a change of
    // a word finds its waiter, as for one futex.
    let done = |held: Vec<Held>, queues: &mut Queues, e: i32| -> i64 {
        let mut woken = None;
        for (i, h) in held.into_iter().enumerate() {
            let was = match h {
                Held::Queued(w) => leave(queues, &w, 0) == 0 && w.woken.load(Ordering::SeqCst),
                #[cfg(target_os = "macos")]
                Held::Slot(s) => shared::leave(s),
                #[cfg(not(target_os = "macos"))]
                Held::Slot(_) => false,
            };
            if was {
                woken = Some(i as i64);
            }
        }
        woken.unwrap_or(err(e))
    };
    let park = Park::new();
    let mut queues = table.lock();
    for &(uaddr, val, private) in &list {
        if let Err(e) = load(uaddr) {
            return done(held, &mut queues, e);
        }
        #[cfg(target_os = "macos")]
        if !private && let Some(slot) = shared::enter(uaddr) {
            match slot {
                Ok(i) => held.push(Held::Slot(i)),
                Err(e) => return done(held, &mut queues, e),
            }
            continue;
        }
        let _ = (private, val);
        let me =
            Arc::new(Waiter { bits: u32::MAX, woken: AtomicBool::new(false), park: park.clone() });
        queues.entry(key(uaddr)).or_default().push_back(me.clone());
        held.push(Held::Queued(me));
    }
    if list.iter().any(|&(uaddr, val, _)| load(uaddr) != Ok(val)) {
        return done(held, &mut queues, errno::EAGAIN);
    }
    // Shared slots are looked at between slices; a private wake wakes.
    let slice_most = if held.iter().any(|h| matches!(h, Held::Slot(_))) {
        Duration::from_millis(1)
    } else {
        SIGNAL_CHECK
    };
    loop {
        if held.iter().any(Held::woken) {
            return done(held, &mut queues, errno::EAGAIN);
        }
        if crate::thread::deliverable() != 0 {
            return done(held, &mut queues, errno::EINTR);
        }
        let now = Instant::now();
        let slice = match deadline {
            Some(d) if now >= d => return done(held, &mut queues, errno::ETIMEDOUT),
            Some(d) => (d - now).min(slice_most),
            None => slice_most,
        };
        if let Some(step) = deadline.and_then(|d| near(d, now)) {
            drop(queues);
            precise_sleep(step);
            queues = table.lock();
            continue;
        }
        drop(queues);
        park.sleep(slice);
        queues = table.lock();
    }
}

/// This process starts, or runs another program: no thread of it waits on
/// a shared futex ([`shared`]).
pub fn process_started() {
    #[cfg(target_os = "macos")]
    shared::process_started();
}

/// Release the futexes on thread `tid`'s robust list at `head` as the
/// thread ends, as Linux's `exit_robust_list` does: each word the thread
/// still owns is marked `FUTEX_OWNER_DIED` (its waiters bit kept) and a
/// waiter woken, so the next to lock it learns its owner died
/// (`EOWNERDEAD`). The entry being added or removed (`list_op_pending`)
/// last; the walk stops at a fault, the list's end, or 2048 entries.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn release_robust(head: u64, tid: i32) {
    use crate::uaccess::read;
    if head == 0 {
        return;
    }
    // The head: the first entry, the futex word's offset from an entry,
    // the pending entry; an entry's low bit marks a PI futex.
    let (Ok(first), Ok(offset), Ok(pending)) =
        (read::<u64>(head), read::<i64>(head + 8), read::<u64>(head + 16))
    else {
        return;
    };
    let (pending, pending_pi) = (pending & !1, pending & 1 != 0);
    let (mut entry, mut pi) = (first & !1, first & 1 != 0);
    let mut left = futex::ROBUST_LIST_LIMIT;
    while entry != head {
        let next = read::<u64>(entry);
        if entry != pending {
            owner_died(entry.wrapping_add_signed(offset), tid, pi, false);
        }
        let Ok(next) = next else { return };
        (entry, pi) = (next & !1, next & 1 != 0);
        left -= 1;
        if left == 0 {
            break;
        }
    }
    if pending != 0 {
        owner_died(pending.wrapping_add_signed(offset), tid, pending_pi, true);
    }
}

/// Linux's `handle_futex_death` for the word at `uaddr`.
fn owner_died(uaddr: u64, tid: i32, pi: bool, pending: bool) {
    use crate::uaccess::{cmpxchg_u32, read};
    let Ok(mut word) = read::<u32>(uaddr) else { return };
    loop {
        // A lock being taken when the thread ended, its word still 0: a
        // waiter may have been about to be woken for it.
        if pending && !pi && word == 0 {
            wake_any(uaddr, 1);
            return;
        }
        if word & futex::FUTEX_TID_MASK != tid as u32 {
            return;
        }
        let died = (word & futex::FUTEX_WAITERS) | futex::FUTEX_OWNER_DIED;
        match cmpxchg_u32(uaddr, word, died) {
            Ok(held) if held == word => break,
            Ok(held) => word = held,
            Err(_) => return,
        }
    }
    if !pi && word & futex::FUTEX_WAITERS != 0 {
        wake_any(uaddr, 1);
    }
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = table().lock();
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
    let mut queues = table.lock();
    // Compared under the lock a waker takes: a wake that follows a change
    // of the word either finds this waiter queued or the word changed.
    match load(uaddr) {
        Ok(v) if v == val => {}
        Ok(_) => return err(errno::EAGAIN),
        Err(e) => return err(e),
    }
    let park = Park::new();
    let me = Arc::new(Waiter { bits, woken: AtomicBool::new(false), park: park.clone() });
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
            queues = table.lock();
            continue;
        }
        let now = Instant::now();
        let slice = match deadline {
            Some(d) if now >= d => return leave(&mut queues, &me, errno::ETIMEDOUT),
            Some(d) => (d - now).min(SIGNAL_CHECK),
            None => SIGNAL_CHECK,
        };
        if let Some(d) = deadline.filter(|&d| near(d, now).is_some() && park.poke >= 0) {
            // Close to the deadline: on time, a wake ending it at once.
            park.napping.store(true, Ordering::SeqCst);
            drop(queues);
            crate::thread::nap_ns(d.saturating_duration_since(now).as_nanos() as i64);
            park.napping.store(false, Ordering::SeqCst);
            queues = table.lock();
            continue;
        }
        drop(queues);
        park.sleep(slice);
        queues = table.lock();
    }
}

/// How long to sleep on time before looking again, when deadline `d` is
/// close enough (from `now`) that the host's usual waits, which can end a
/// millisecond or more late, would miss it as Linux would not.
pub(crate) fn near(d: Instant, now: Instant) -> Option<Duration> {
    let left = d.saturating_duration_since(now);
    (left <= SIGNAL_CHECK).then(|| left.min(Duration::from_millis(1)))
}

/// Sleep for `d` on time ([`crate::thread::wait_ready_ns`]); a signal
/// ends it early, for the caller to see.
pub(crate) fn precise_sleep(d: Duration) {
    let _ = crate::thread::wait_ready_ns(&mut [], d.as_nanos().min(i64::MAX as u128) as i64);
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
    table().lock().clear();
}

/// Mark `woken` woken. Called with the queues locked ([`Park::mark`]);
/// their threads are woken once they are let go ([`rouse_all_of`]).
fn mark_all_of(woken: &[Arc<Waiter>]) {
    for w in woken {
        w.woken.store(true, Ordering::SeqCst);
        w.park.mark();
    }
}

/// Wake the threads of `woken`, marked woken ([`mark_all_of`]), with the
/// queues let go.
fn rouse_all_of(woken: &[Arc<Waiter>]) {
    for w in woken {
        w.park.rouse();
    }
}

/// Wake up to `count` waiters on private futex `uaddr`: the number woken.
pub(crate) fn wake_private(uaddr: u64, count: u32) -> i64 {
    wake_private_bits(uaddr, count, u32::MAX)
}

/// [`wake_private`] of the waiters for any of `bits`
/// (`FUTEX_WAKE_BITSET`).
/// Whether any of this process's private queues has a waiter.
#[cfg(target_os = "macos")]
pub(crate) fn any_private_waiting() -> bool {
    table().lock().values().any(|q| !q.is_empty())
}

pub(crate) fn wake_private_bits(uaddr: u64, count: u32, bits: u32) -> i64 {
    let table = table();
    let mut queues = table.lock();
    let woken = take(&mut queues, key(uaddr), count, bits);
    mark_all_of(&woken);
    drop(queues);
    rouse_all_of(&woken);
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
    let mut queues = table.lock();
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
    mark_all_of(&woken);
    let moved = take(&mut queues, uaddr, requeue, u32::MAX);
    let n = moved.len();
    queues.entry(uaddr2).or_default().extend(moved);
    drop(queues);
    rouse_all_of(&woken);
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

    /// `FUTEX_WAKE_OP`'s operation on the second word, and its comparison
    /// of the old value: each operation, a shift, the sign-extended
    /// arguments, and an unknown comparison (after the change).
    #[test]
    fn wake_op_changes_the_second_word() {
        use fwe_abi::futex::*;
        let enc = |op: u32, cmp: u32, oparg: i32, cmparg: i32| {
            op << 28 | cmp << 24 | (oparg as u32 & 0xfff) << 12 | (cmparg as u32 & 0xfff)
        };
        let word = AtomicU32::new(6);
        let addr = &word as *const _ as u64;
        let cases = [
            (enc(FUTEX_OP_SET, FUTEX_OP_CMP_EQ, 9, 6), 9, true),
            (enc(FUTEX_OP_ADD, FUTEX_OP_CMP_NE, 3, 9), 12, false),
            (enc(FUTEX_OP_OR, FUTEX_OP_CMP_GT, 1, 11), 13, true),
            (enc(FUTEX_OP_ANDN, FUTEX_OP_CMP_LE, 4, 13), 9, true),
            (enc(FUTEX_OP_XOR, FUTEX_OP_CMP_LT, 1, 9), 8, false),
            (enc(FUTEX_OP_OPARG_SHIFT | FUTEX_OP_OR, FUTEX_OP_CMP_GE, 4, 8), 24, true),
            (enc(FUTEX_OP_ADD, FUTEX_OP_CMP_LT, -24, -1), 0, false),
            (enc(FUTEX_OP_ADD, FUTEX_OP_CMP_GT, -1, -2), u32::MAX, true),
        ];
        for (encoded, after, hit) in cases {
            assert_eq!(wake_op_apply(addr, encoded), Ok(hit), "{encoded:#x}");
            assert_eq!(word.load(Ordering::SeqCst), after, "{encoded:#x}");
        }
        word.store(1, Ordering::SeqCst);
        assert_eq!(wake_op_apply(addr, enc(FUTEX_OP_SET, 9, 5, 0)), Err(errno::ENOSYS));
        assert_eq!(word.load(Ordering::SeqCst), 5);
        assert_eq!(wake_op_apply(addr, enc(6, FUTEX_OP_CMP_EQ, 7, 0)), Err(errno::ENOSYS));
        assert_eq!(word.load(Ordering::SeqCst), 5);
    }

    /// `FUTEX_WAKE_OP` wakes the first word's waiters, and the second's
    /// only when the comparison holds; an unaligned second word is
    /// `EINVAL`.
    #[test]
    fn wake_op_wakes_the_second_word_on_a_hit() {
        use fwe_abi::futex::*;
        let words: &'static [AtomicU32; 2] =
            Box::leak(Box::new([AtomicU32::new(0), AtomicU32::new(0)]));
        let (a, b) = (&words[0] as *const _ as u64, &words[1] as *const _ as u64);
        let wait_op = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
        let wake_op = FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG;
        // SAFETY: the leaked words live for the process.
        let waiter = thread::spawn(move || unsafe { op(b, wait_op, 0, 0) });
        thread::sleep(Duration::from_millis(50));
        // Old value 0 is not 1: the second word's waiter stays.
        let set_if_one = (FUTEX_OP_SET << 28) | (FUTEX_OP_CMP_EQ << 24) | (2 << 12) | 1;
        // SAFETY: as above.
        assert_eq!(unsafe { op_full(a, wake_op, 1, 1, b, set_if_one) }, 0);
        assert_eq!(words[1].load(Ordering::SeqCst), 2);
        // Old value 2: woken.
        let set_if_two = (FUTEX_OP_SET << 28) | (FUTEX_OP_CMP_EQ << 24) | (3 << 12) | 2;
        let mut woken = 0;
        for _ in 0..100 {
            // SAFETY: as above.
            woken = unsafe { op_full(a, wake_op, 1, 1, b, set_if_two) };
            if woken == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(woken, 1);
        assert_eq!(waiter.join().unwrap(), 0);
        // SAFETY: as above.
        assert_eq!(unsafe { op_full(a, wake_op, 1, 1, b + 1, 0) }, err(errno::EINVAL));
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

    /// A robust list's words: the ending thread's marked owner-dead (the
    /// waiters bit kept), another's left, the pending one released too.
    #[test]
    fn a_robust_list_is_released() {
        use fwe_abi::futex::{FUTEX_OWNER_DIED, FUTEX_WAITERS};
        // An entry: the next entry, then its futex word (offset 8).
        #[repr(C)]
        struct Entry {
            next: u64,
            word: u32,
        }
        let tid = 4242u32;
        let mut head = [0u64; 3];
        let mut a = Entry { next: 0, word: tid | FUTEX_WAITERS };
        let mut b = Entry { next: 0, word: 77 };
        let mut pending = Entry { next: 0, word: tid };
        head[0] = &a as *const Entry as u64;
        head[1] = 8;
        head[2] = &mut pending as *mut Entry as u64;
        let head_at = head.as_ptr() as u64;
        a.next = &b as *const Entry as u64;
        b.next = head_at;
        release_robust(head_at, tid as i32);
        assert_eq!(a.word, FUTEX_WAITERS | FUTEX_OWNER_DIED);
        assert_eq!(b.word, 77);
        assert_eq!(pending.word, FUTEX_OWNER_DIED);
    }
}
