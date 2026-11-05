//! Per-thread guest state and thread-id allocation.
//!
//! A guest thread is a host thread. State that Linux keeps per thread — the
//! thread id, `set_tid_address`'s clear-on-exit word, the robust-futex list,
//! the blocked-signal mask, the alternate signal stack and the signals
//! pending against the thread — lives in host thread-locals, not in the
//! shared [`crate::Kernel`].
//!
//! Pending signals are recorded with atomics only, because the backend's
//! host signal handler records them and may interrupt the thread anywhere.
//! Each thread's pending set is also registered by tid so another thread can
//! direct a signal at it.

use fwe_abi::{Stack, signal};
use std::cell::Cell;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The process (thread-group) id, shared by all threads. Set once at startup.
static TGID: AtomicI32 = AtomicI32::new(0);
/// Next thread id to hand out. Thread ids are unique within the process.
static NEXT_TID: AtomicI32 = AtomicI32::new(0);

thread_local! {
    static TID: Cell<i32> = const { Cell::new(0) };
    /// `set_tid_address`: futex word cleared and woken when the thread exits.
    static CLEAR_CHILD_TID: Cell<u64> = const { Cell::new(0) };
    static ROBUST_LIST: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    /// The name `prctl(PR_SET_NAME)` gave this thread, if any.
    static NAME: Cell<Option<[u8; fwe_abi::prctl::TASK_COMM_LEN]>> = const { Cell::new(None) };
    /// `prctl(PR_SET_PDEATHSIG)`: recorded, not delivered (see the limitations).
    static PDEATHSIG: Cell<u64> = const { Cell::new(0) };
}

/// This thread's name as `prctl(PR_SET_NAME)` set it, or `None`.
pub fn name() -> Option<[u8; fwe_abi::prctl::TASK_COMM_LEN]> {
    NAME.with(Cell::get)
}

pub fn set_name(name: [u8; fwe_abi::prctl::TASK_COMM_LEN]) {
    NAME.with(|n| n.set(Some(name)));
}

pub fn pdeathsig() -> u64 {
    PDEATHSIG.with(Cell::get)
}

pub fn set_pdeathsig(sig: u64) {
    PDEATHSIG.with(|s| s.set(sig));
}

/// Initialize the thread-group id and the main thread's id (both the host
/// pid, as Linux gives the main thread a tid equal to the pid).
///
/// Also used in a forked child, which starts as a single-threaded process
/// with no pending signals: the other threads' registrations are dropped.
pub fn init_main(pid: i32) {
    TGID.store(pid, Ordering::SeqCst);
    NEXT_TID.store(pid + 1, Ordering::SeqCst);
    TID.with(|t| t.set(pid));
    PROCESS.clear();
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    register_current();
}

/// The thread-group id (what `getpid` returns).
pub fn tgid() -> i32 {
    TGID.load(Ordering::SeqCst)
}

/// Allocate a fresh thread id for a new thread.
pub fn alloc_tid() -> i32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Record this host thread's guest thread id (called when a thread starts).
pub fn set_tid(tid: i32) {
    TID.with(|t| t.set(tid));
}

/// This thread's guest thread id (`gettid`).
pub fn tid() -> i32 {
    TID.with(Cell::get)
}

pub fn set_clear_child_tid(addr: u64) {
    CLEAR_CHILD_TID.with(|c| c.set(addr));
}

pub fn clear_child_tid() -> u64 {
    CLEAR_CHILD_TID.with(Cell::get)
}

pub fn set_robust_list(head: u64, len: u64) {
    ROBUST_LIST.with(|c| c.set((head, len)));
}

pub fn robust_list() -> (u64, u64) {
    ROBUST_LIST.with(Cell::get)
}

/// What a pending signal carries into the handler's `siginfo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    pub code: i32,
    pub pid: i32,
    pub uid: u32,
    /// Exit status or signal (`SIGCHLD`).
    pub status: i32,
}

#[derive(Default)]
struct SigSlot {
    code: AtomicI32,
    pid: AtomicI32,
    uid: AtomicU32,
    status: AtomicI32,
}

impl SigSlot {
    const fn new() -> SigSlot {
        SigSlot {
            code: AtomicI32::new(0),
            pid: AtomicI32::new(0),
            uid: AtomicU32::new(0),
            status: AtomicI32::new(0),
        }
    }
}

/// A set of pending signals (one per signal number, as for standard
/// signals) with the `siginfo` each was raised with.
pub struct Pending {
    bits: AtomicU64,
    info: [SigSlot; signal::NSIG as usize],
}

impl Pending {
    pub const fn new() -> Pending {
        Pending { bits: AtomicU64::new(0), info: [const { SigSlot::new() }; signal::NSIG as usize] }
    }

    /// Mark `sig` pending. Async-signal-safe.
    pub fn post(&self, sig: u64, info: SigInfo) {
        if !(1..=signal::NSIG).contains(&sig) {
            return;
        }
        let slot = &self.info[(sig - 1) as usize];
        slot.code.store(info.code, Ordering::Relaxed);
        slot.pid.store(info.pid, Ordering::Relaxed);
        slot.uid.store(info.uid, Ordering::Relaxed);
        slot.status.store(info.status, Ordering::Relaxed);
        self.bits.fetch_or(1 << (sig - 1), Ordering::Release);
    }

    fn take(&self, sig: u64) -> Option<SigInfo> {
        let bit = 1 << (sig - 1);
        if self.bits.fetch_and(!bit, Ordering::Acquire) & bit == 0 {
            return None;
        }
        let slot = &self.info[(sig - 1) as usize];
        Some(SigInfo {
            code: slot.code.load(Ordering::Relaxed),
            pid: slot.pid.load(Ordering::Relaxed),
            uid: slot.uid.load(Ordering::Relaxed),
            status: slot.status.load(Ordering::Relaxed),
        })
    }

    fn bits(&self) -> u64 {
        self.bits.load(Ordering::Acquire)
    }

    fn clear(&self) {
        self.bits.store(0, Ordering::Release);
    }
}

impl Default for Pending {
    fn default() -> Self {
        Pending::new()
    }
}

/// Signals pending against the whole process that the host could not carry
/// (those with no host equivalent, such as the real-time signals).
static PROCESS: Pending = Pending::new();

struct Registered {
    tid: i32,
    pending: Arc<Pending>,
    /// The host thread, or 0 while it is being created.
    host: libc::pthread_t,
}

/// Every live guest thread's pending set, by tid.
static THREADS: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

const UNBLOCKABLE: u64 = (1 << (signal::SIGKILL - 1)) | (1 << (signal::SIGSTOP - 1));

thread_local! {
    static MASK: Cell<u64> = const { Cell::new(0) };
    /// The mask `rt_sigsuspend` replaced, restored once the call ends.
    static SAVED_MASK: Cell<Option<u64>> = const { Cell::new(None) };
    static ALTSTACK: Cell<Stack> = const {
        Cell::new(Stack { ss_sp: 0, ss_flags: signal::SS_DISABLE, _pad: 0, ss_size: 0 })
    };
    /// This thread's registered pending set (owned by [`THREADS`]).
    static OWN: Cell<*const Pending> = const { Cell::new(std::ptr::null()) };
    /// A process signal landed here while this thread blocked it: the
    /// other threads are to be woken to take it ([`post_landed`]).
    static WAKE_OTHERS: Cell<bool> = const { Cell::new(false) };
}

/// Run `f` holding the thread registry lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Register the calling host thread as guest thread [`tid`], so signals can
/// be directed at it. Called when a guest thread starts.
pub fn register_current() {
    let pending = register(tid());
    adopt(&pending);
    // SAFETY: plain host call.
    set_host_thread(&pending, unsafe { libc::pthread_self() });
}

/// Register guest thread `tid` before its host thread exists, so a signal
/// sent to it the moment `clone` returns is kept for it. The new thread
/// [`adopt`]s the returned set; its creator calls [`set_host_thread`] once
/// the host thread exists.
pub fn register(tid: i32) -> Arc<Pending> {
    let pending = Arc::new(Pending::new());
    let entry = Registered { tid, pending: pending.clone(), host: 0 };
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).push(entry);
    pending
}

/// Make `pending` (from [`register`]) the calling thread's own set.
pub fn adopt(pending: &Arc<Pending>) {
    OWN.with(|o| o.set(Arc::as_ptr(pending)));
}

/// Record the host thread of the registration owning `pending`. Does
/// nothing if that thread has already exited.
pub fn set_host_thread(pending: &Arc<Pending>, host: libc::pthread_t) {
    let mut threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = threads.iter_mut().find(|r| Arc::ptr_eq(&r.pending, pending)) {
        r.host = host;
    }
}

/// Drop the registration owning `pending` (a thread that never started).
pub fn unregister(pending: &Arc<Pending>) {
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).retain(|r| !Arc::ptr_eq(&r.pending, pending));
}

/// Forget the calling thread's registration as it exits.
pub fn unregister_current() {
    let own = OWN.with(|o| o.replace(std::ptr::null()));
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).retain(|r| Arc::as_ptr(&r.pending) != own);
}

fn with_own<R>(f: impl FnOnce(&Pending) -> R) -> R {
    let p = OWN.with(Cell::get);
    if p.is_null() {
        f(&PROCESS)
    } else {
        // SAFETY: the pointer is cleared before the registry drops its Arc.
        f(unsafe { &*p })
    }
}

/// Record `sig` as pending against the calling thread. Async-signal-safe:
/// the backend calls it from its host signal handler.
pub fn post_self(sig: u64, info: SigInfo) {
    with_own(|p| p.post(sig, info));
}

/// Record a signal the host delivered to the calling thread, with its
/// sender. A signal this thread accepts is its own. One it blocks is the
/// process's, as Linux keeps a process signal for a thread that accepts it,
/// and the other threads are to be woken to take it, which
/// [`wake_others_if_asked`] does at a point where no lock is held. The
/// exception is `SIGPIPE` and `SIGXFSZ`, which the host directs at the
/// thread whose write caused them, as Linux does. (A signal another thread
/// directs at this one with `tgkill` never comes this way: it is posted to
/// this thread directly.) Async-signal-safe: the backend calls it from its
/// host signal handler.
pub fn post_landed(sig: u64, info: SigInfo) {
    let own = matches!(sig, signal::SIGPIPE | signal::SIGXFSZ);
    if own || (1..=signal::NSIG).contains(&sig) && mask() & (1 << (sig - 1)) == 0 {
        post_self(sig, info);
    } else {
        PROCESS.post(sig, info);
        WAKE_OTHERS.with(|w| w.set(true));
    }
}

/// Wake the other threads if a process signal landed on this one while it
/// blocked it ([`post_landed`]). Takes the thread registry lock: called
/// where this thread holds none of fwe's locks.
pub fn wake_others_if_asked(sig: libc::c_int) {
    if WAKE_OTHERS.with(|w| w.replace(false)) {
        wake_others(sig);
    }
}

/// Record `sig` as pending against the process; any thread that does not
/// block it takes it at its next system call.
pub fn post_process(sig: u64, info: SigInfo) {
    PROCESS.post(sig, info);
}

/// Record `sig` as pending against thread `tid` of this process. Returns
/// the host thread to wake, or `None` if there is no such thread.
pub fn post_thread(tid: i32, sig: u64, info: SigInfo) -> Option<libc::pthread_t> {
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    let r = threads.iter().find(|r| r.tid == tid)?;
    r.pending.post(sig, info);
    Some(r.host)
}

/// Send host signal `sig` to every other registered thread, to interrupt
/// what it is waiting in.
pub fn wake_others(sig: libc::c_int) {
    let me = tid();
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    for r in threads.iter().filter(|r| r.tid != me && r.host != 0) {
        // SAFETY: a registered thread is live until it unregisters, which
        // needs this lock.
        unsafe { libc::pthread_kill(r.host, sig) };
    }
}

/// The host thread running guest thread `tid` of this process: `Some(0)`
/// while it is still being created.
pub fn host_thread(tid: i32) -> Option<libc::pthread_t> {
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    threads.iter().find(|r| r.tid == tid).map(|r| r.host)
}

/// Signals pending against the calling thread or the process.
pub fn pending() -> u64 {
    with_own(Pending::bits) | PROCESS.bits()
}

/// Take pending signal `sig`, preferring the thread's own over the
/// process's.
pub fn take_pending(sig: u64) -> Option<SigInfo> {
    with_own(|p| p.take(sig)).or_else(|| PROCESS.take(sig))
}

/// Signals that are pending and not blocked by the calling thread.
pub fn deliverable() -> u64 {
    pending() & !mask()
}

/// The calling thread's blocked-signal mask.
pub fn mask() -> u64 {
    MASK.with(Cell::get)
}

/// Replace the calling thread's mask; `SIGKILL` and `SIGSTOP` cannot be
/// blocked.
pub fn set_mask(mask: u64) {
    MASK.with(|m| m.set(mask & !UNBLOCKABLE));
}

/// Remember the mask to restore when `rt_sigsuspend` ends.
pub fn save_mask(mask: u64) {
    SAVED_MASK.with(|m| m.set(Some(mask)));
}

/// The mask saved by `rt_sigsuspend`, if the call is still in progress.
pub fn take_saved_mask() -> Option<u64> {
    SAVED_MASK.with(Cell::take)
}

/// The calling thread's alternate signal stack.
pub fn altstack() -> Stack {
    ALTSTACK.with(Cell::get)
}

pub fn set_altstack(stack: Stack) {
    ALTSTACK.with(|a| a.set(stack));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_is_per_thread_and_carries_info() {
        register_current();
        let info = SigInfo { code: -6, pid: 7, uid: 8, status: 0 };
        post_self(signal::SIGUSR1, info);
        assert_eq!(pending() & (1 << (signal::SIGUSR1 - 1)), 1 << (signal::SIGUSR1 - 1));
        // Another thread does not see it.
        let other = std::thread::spawn(|| {
            register_current();
            let seen = pending() & (1 << (signal::SIGUSR1 - 1));
            unregister_current();
            seen
        })
        .join()
        .unwrap();
        assert_eq!(other, 0);
        assert_eq!(take_pending(signal::SIGUSR1), Some(info));
        assert_eq!(take_pending(signal::SIGUSR1), None);
        unregister_current();
    }

    #[test]
    fn mask_never_blocks_kill_or_stop() {
        set_mask(u64::MAX);
        assert_eq!(mask() & UNBLOCKABLE, 0);
        set_mask(0);
    }
}
