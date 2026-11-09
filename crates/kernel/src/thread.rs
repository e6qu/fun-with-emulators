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
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The process (thread-group) id, shared by all threads. Set once at startup.
static TGID: AtomicI32 = AtomicI32::new(0);
/// Next thread id to hand out. Thread ids are unique within the process.
static NEXT_TID: AtomicI32 = AtomicI32::new(TID_FIRST);

thread_local! {
    static TID: Cell<i32> = const { Cell::new(0) };
    /// `set_tid_address`: futex word cleared and woken when the thread exits.
    static CLEAR_CHILD_TID: Cell<u64> = const { Cell::new(0) };
    static ROBUST_LIST: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    /// The name `prctl(PR_SET_NAME)` gave this thread, if any.
    static NAME: Cell<Option<[u8; fwe_abi::prctl::TASK_COMM_LEN]>> = const { Cell::new(None) };
}

/// This thread's name as `prctl(PR_SET_NAME)` set it, or `None`.
pub fn name() -> Option<[u8; fwe_abi::prctl::TASK_COMM_LEN]> {
    NAME.with(Cell::get)
}

pub fn set_name(name: [u8; fwe_abi::prctl::TASK_COMM_LEN]) {
    NAME.with(|n| n.set(Some(name)));
}

/// Initialize the thread-group id and the main thread's id (both the host
/// pid, as Linux gives the main thread a tid equal to the pid).
///
/// Also used in a forked child, which starts as a single-threaded process
/// with no pending signals: the other threads' registrations are dropped.
///
/// A signal that came after the fork, before this (a sender may name the
/// child as soon as the parent's `fork` returns), is kept: the parent's,
/// which the child does not inherit, are dropped as the fork returns
/// ([`forked`]).
pub fn init_main(pid: i32) {
    TGID.store(pid, Ordering::SeqCst);
    // Without the shared counter: numbers past every host pid, this
    // process's own.
    NEXT_TID.store(TID_FIRST + (pid % 40) * 100_000, Ordering::SeqCst);
    TID.with(|t| t.set(pid));
    // An end status left by an earlier process of this number.
    // SAFETY: getpid cannot fail.
    crate::procreg::forget_end(unsafe { libc::getpid() });
    // The calling thread's own set goes with the registry: what landed in
    // it is moved to the process's, and a handler meanwhile posts there.
    let early: Vec<(u64, SigInfo)> =
        with_own(|p| (1..=signal::NSIG).filter_map(|s| p.take(s).map(|i| (s, i))).collect());
    OWN.with(|o| o.set(std::ptr::null()));
    for (s, i) in early {
        PROCESS.post(s, i);
    }
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    forget_wait_pipes();
    crate::pdeath::forked();
    crate::futex::forked_child();
    crate::signote::open_own();
    crate::sysvipc::forked_child();
    register_current();
}

/// Each waiting thread's wake pipe: the host thread, and the pipe's read
/// and write ends (in fwe's reserved range). A signal the host delivers
/// to a thread writes a byte to its pipe ([`poke_wait`]), and the waits
/// that block without bound until a descriptor is ready (`ppoll`, `epoll`)
/// watch the pipe beside the guest's descriptors ([`wait_ready`]): a
/// signal that lands after such a wait looked for pending signals, and
/// before the host wait began, still ends it. Kept without a lock: the
/// handler reads it.
static WAIT_PIPES: [(AtomicU64, AtomicI32, AtomicI32); 256] =
    [const { (AtomicU64::new(0), AtomicI32::new(-1), AtomicI32::new(-1)) }; 256];

fn self_id() -> u64 {
    // SAFETY: pthread_self cannot fail; async-signal-safe.
    unsafe { libc::pthread_self() as u64 }
}

/// The calling thread's wake pipe's read end, made on first use (none if
/// every slot is taken or no pipe can be made).
fn wait_pipe() -> Option<i32> {
    let me = self_id();
    if let Some((_, r, _)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
        return Some(r.load(Ordering::SeqCst)).filter(|&r| r >= 0);
    }
    let mut p = [-1i32; 2];
    // SAFETY: a valid out-array; the ends are made non-blocking and moved
    // to fwe's reserved range.
    unsafe {
        if libc::pipe(p.as_mut_ptr()) != 0 {
            return None;
        }
        for fd in p {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
    }
    let (Ok(r), Ok(w)) = (crate::fdtable::reserve(p[0]), crate::fdtable::reserve(p[1])) else {
        return None;
    };
    for (t, rs, ws) in &WAIT_PIPES {
        if t.compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            rs.store(r, Ordering::SeqCst);
            ws.store(w, Ordering::SeqCst);
            return Some(r);
        }
    }
    // SAFETY: the pipe made above, not kept.
    unsafe {
        libc::close(r);
        libc::close(w);
    }
    None
}

/// In a host signal handler: end the calling thread's wait, if it has a
/// wake pipe. Async-signal-safe.
pub fn poke_wait() {
    let me = self_id();
    if let Some((_, _, w)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
        let saved = crate::host::last_errno();
        // SAFETY: one byte to the thread's own pipe; a full pipe is woken
        // already.
        unsafe { libc::write(w.load(Ordering::SeqCst), b"w".as_ptr().cast(), 1) };
        crate::host::set_errno(saved);
    }
}

/// The calling thread's wake pipe goes, as it exits.
fn drop_wait_pipe() {
    let me = self_id();
    if let Some((t, r, w)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
        // SAFETY: the thread's own pipe, no longer used.
        unsafe {
            libc::close(r.swap(-1, Ordering::SeqCst));
            libc::close(w.swap(-1, Ordering::SeqCst));
        }
        t.store(0, Ordering::SeqCst);
    }
}

/// In a fork child: the parent's wake pipes are its own (the forking
/// thread's is shared with the parent), so they go; this thread makes its
/// own when it next waits.
fn forget_wait_pipes() {
    for (t, r, w) in &WAIT_PIPES {
        if t.swap(0, Ordering::SeqCst) != 0 {
            // SAFETY: inherited descriptors of fwe's, no longer used here.
            unsafe {
                libc::close(r.swap(-1, Ordering::SeqCst));
                libc::close(w.swap(-1, Ordering::SeqCst));
            }
        }
    }
}

/// `poll` of `fds` for up to `ms` milliseconds (-1: without bound), ended
/// as well by a signal for the guest (`EINTR`): one pending as the wait
/// starts, or one that lands during it, however soon. A signal the thread
/// blocks for a `signalfd` is moved onto it, so the wait sees that
/// descriptor ready. Returns how many of `fds` are ready.
pub fn wait_ready(fds: &mut [libc::pollfd], ms: i32) -> Result<i32, i32> {
    let Some(wake) = wait_pipe() else {
        // SAFETY: a valid array of `fds.len()` entries.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        return if n < 0 {
            Err(crate::host::errno_to_linux(crate::host::last_errno()))
        } else {
            Ok(n)
        };
    };
    let deadline =
        (ms >= 0).then(|| std::time::Instant::now() + std::time::Duration::from_millis(ms as u64));
    let mut all: Vec<libc::pollfd> = fds.to_vec();
    all.push(libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 });
    loop {
        // What woke it before is spent; a signal from now on writes again.
        let mut b = [0u8; 64];
        // SAFETY: the thread's own non-blocking pipe and a buffer of its length.
        while unsafe { libc::read(wake, b.as_mut_ptr().cast(), b.len()) } > 0 {}
        crate::signal::drain_to_signalfd();
        if deliverable() != 0 {
            return Err(fwe_abi::errno::EINTR);
        }
        let left = match deadline {
            None => -1,
            Some(d) => d.saturating_duration_since(std::time::Instant::now()).as_millis() as i32,
        };
        for p in &mut all {
            p.revents = 0;
        }
        // SAFETY: a valid array of `all.len()` entries.
        let n = unsafe { libc::poll(all.as_mut_ptr(), all.len() as libc::nfds_t, left) };
        if n < 0 && crate::host::last_errno() != libc::EINTR {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let woke = all[fds.len()].revents != 0;
        let ready = n.max(0) - i32::from(woke);
        if ready > 0 {
            for (f, a) in fds.iter_mut().zip(&all) {
                f.revents = a.revents;
            }
            return Ok(ready);
        }
        if n == 0 && deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Ok(0);
        }
    }
}

/// In a fork child, as the fork returns: the parent's pending signals,
/// which a child does not inherit, are dropped. Async-signal-safe.
pub fn forked() {
    PROCESS.clear();
    with_own(Pending::clear);
}

/// Linux's timer slack for a process that never set one, in nanoseconds.
pub const DEFAULT_SLACK: u64 = 50_000;

thread_local! {
    /// This thread's timer slack and its default (not the main thread's,
    /// which its process record holds, for `/proc/<pid>/timerslack_ns`).
    static SLACK: Cell<(u64, u64)> = const { Cell::new((DEFAULT_SLACK, DEFAULT_SLACK)) };
}

/// The timer slack of threads being created ([`register`]), until each
/// takes its own ([`set_tid`]).
static SLACK_HANDOFF: Mutex<Vec<(i32, u64)>> = Mutex::new(Vec::new());

/// This thread's timer slack (`PR_GET_TIMERSLACK`).
pub fn slack() -> u64 {
    if tid() == tgid() {
        // SAFETY: getpid cannot fail.
        crate::procreg::slack(unsafe { libc::getpid() }).0
    } else {
        SLACK.with(Cell::get).0
    }
}

/// Set this thread's timer slack (`PR_SET_TIMERSLACK`; 0 restores its
/// default).
pub fn set_slack(value: u64) {
    if tid() == tgid() {
        // SAFETY: getpid cannot fail.
        let _ = crate::procreg::set_slack(unsafe { libc::getpid() }, value);
    } else {
        SLACK.with(|s| {
            let (_, default) = s.get();
            s.set((if value == 0 { default } else { value }, default));
        });
    }
}

/// The thread-group id (what `getpid` returns).
pub fn tgid() -> i32 {
    TGID.load(Ordering::SeqCst)
}

/// The first thread id outside a pid namespace of fwe's: above every
/// host pid (macOS's end at 99999), so a thread's number never names
/// another process, and below Linux's largest `pid_max`, where the
/// numbers wrap.
const TID_FIRST: i32 = 100_000;
const TID_END: i32 = 4_194_304;

/// A thread id outside a pid namespace of fwe's: the next of a counter
/// every fwe process shares (a file beside the process records, taken in
/// turn with `flock`), so no two live threads have the same one.
fn shared_tid() -> Option<i32> {
    let dir = crate::procreg::records_dir()?;
    let path = std::ffi::CString::new([&dir[..], b"/tids"].concat()).ok()?;
    // SAFETY: a NUL-terminated path in fwe's private directory; a 4-byte
    // buffer; the descriptor is closed below.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd < 0 {
            return None;
        }
        libc::flock(fd, libc::LOCK_EX);
        let mut b = [0u8; 4];
        let n = match libc::pread(fd, b.as_mut_ptr().cast(), 4, 0) {
            4 => i32::from_ne_bytes(b),
            _ => TID_FIRST,
        };
        let n = if (TID_FIRST..TID_END).contains(&n) { n } else { TID_FIRST };
        let next = if n + 1 >= TID_END { TID_FIRST } else { n + 1 };
        libc::pwrite(fd, next.to_ne_bytes().as_ptr().cast(), 4, 0);
        libc::flock(fd, libc::LOCK_UN);
        libc::close(fd);
        Some(n)
    }
}

/// Allocate a fresh thread id for a new thread: in a pid namespace of
/// fwe's, a number from it (threads and processes share the numbers);
/// outside one, a number no host process has ([`shared_tid`]).
pub fn alloc_tid() -> i32 {
    if crate::pidns::nested() {
        // SAFETY: getpid cannot fail.
        let host = unsafe { libc::getpid() };
        if let Ok(nums) = crate::pidns::alloc(&crate::pidns::current(), host, true) {
            crate::pidns::remember_thread(nums[0], nums.clone());
            return nums[0];
        }
    }
    shared_tid().unwrap_or_else(|| NEXT_TID.fetch_add(1, Ordering::SeqCst))
}

/// Record this host thread's guest thread id (called when a thread starts).
pub fn set_tid(tid: i32) {
    TID.with(|t| t.set(tid));
    // A new thread: its creator's timer slack, as its own and its default.
    let mut handoff = SLACK_HANDOFF.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = handoff.iter().position(|&(t, _)| t == tid) {
        let (_, s) = handoff.swap_remove(i);
        SLACK.with(|c| c.set((s, s)));
    }
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
    /// The value a queued signal carries (`si_value`: `SI_QUEUE`,
    /// `SI_MESGQ`).
    pub value: u64,
    /// For a signal of I/O readiness (an owned descriptor's `F_SETSIG`
    /// signal): the descriptor, and the events (`si_band`).
    pub poll: Option<(i32, i64)>,
}

#[derive(Default)]
struct SigSlot {
    code: AtomicI32,
    pid: AtomicI32,
    uid: AtomicU32,
    status: AtomicI32,
    value: AtomicU64,
    /// `poll`'s descriptor (-1: none) and events.
    poll_fd: AtomicI32,
    band: AtomicI64,
}

impl SigSlot {
    const fn new() -> SigSlot {
        SigSlot {
            code: AtomicI32::new(0),
            pid: AtomicI32::new(0),
            uid: AtomicU32::new(0),
            status: AtomicI32::new(0),
            value: AtomicU64::new(0),
            poll_fd: AtomicI32::new(-1),
            band: AtomicI64::new(0),
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

    /// Mark `sig` pending. A standard signal already pending keeps the
    /// `siginfo` it was first raised with, as Linux drops a second instance
    /// of one (real-time signals, which Linux queues, keep the latest).
    /// The exception is an adopted process's `SIGCHLD`, which takes the
    /// place of its former parent's ([`crate::reaper::precedes`]): Linux
    /// sends it as the parent ends, before the parent's own. Async-signal-
    /// safe.
    pub fn post(&self, sig: u64, info: SigInfo) {
        if !(1..=signal::NSIG).contains(&sig) {
            return;
        }
        let slot = &self.info[(sig - 1) as usize];
        if sig == signal::SIGCHLD && crate::reaper::superseded(info.pid) {
            return;
        }
        if sig < signal::SIGRTMIN
            && self.bits.load(Ordering::Acquire) & (1 << (sig - 1)) != 0
            && !(sig == signal::SIGCHLD
                && crate::reaper::precedes(info.pid, slot.pid.load(Ordering::Relaxed)))
        {
            return;
        }
        slot.code.store(info.code, Ordering::Relaxed);
        slot.pid.store(info.pid, Ordering::Relaxed);
        slot.uid.store(info.uid, Ordering::Relaxed);
        slot.status.store(info.status, Ordering::Relaxed);
        slot.value.store(info.value, Ordering::Relaxed);
        let (fd, band) = info.poll.unwrap_or((-1, 0));
        slot.poll_fd.store(fd, Ordering::Relaxed);
        slot.band.store(band, Ordering::Relaxed);
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
            value: slot.value.load(Ordering::Relaxed),
            poll: match slot.poll_fd.load(Ordering::Relaxed) {
                -1 => None,
                fd => Some((fd, slot.band.load(Ordering::Relaxed))),
            },
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

/// The guest's threads, by tid, the main thread's (the process's) first.
pub fn tids() -> Vec<i32> {
    let me = tgid();
    let mut out = vec![me];
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    out.extend(threads.iter().map(|r| r.tid).filter(|&t| t != me));
    out
}

/// How many guest threads the process has.
pub fn live_threads() -> usize {
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).len().max(1)
}

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
    if tid != tgid() {
        let s = slack();
        SLACK_HANDOFF.lock().unwrap_or_else(|e| e.into_inner()).push((tid, s));
    }
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
    // Its process descriptors (`PIDFD_THREAD`) say it has ended.
    crate::pidfd::thread_gone(tid());
    drop_wait_pipe();
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
    use fwe_abi::wait::{CLD_DUMPED, CLD_EXITED, CLD_KILLED};
    // A child's end that Linux tells with its own exit signal (or none).
    let sig = match sig {
        signal::SIGCHLD if matches!(info.code, CLD_EXITED | CLD_KILLED | CLD_DUMPED) => {
            if crate::reaper::child_signal_landed(info.pid) {
                // Given already, by the `wait` that reaped it.
                return;
            }
            match crate::reaper::exit_signal(info.pid) {
                Some(0) => return,
                Some(s) => s,
                None => sig,
            }
        }
        _ => sig,
    };
    let unblocked = (1..=signal::NSIG).contains(&sig) && mask() & (1 << (sig - 1)) == 0;
    if unblocked && crate::signal::ignored() & (1 << (sig - 1)) != 0 {
        // Ignored, and not held: gone, as Linux drops it.
        return;
    }
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

/// Guest thread `tid`'s CPU time (user, system, in nanoseconds) and whether
/// it runs, as the host reports its thread: asked while the thread is
/// registered (one that ends unregisters first, so its host thread is
/// never asked about once it is gone). The calling thread's own too.
pub fn host_state(tid: i32) -> Option<(u64, u64, bool)> {
    if tid == self::tid() {
        // SAFETY: plain host call.
        return crate::host::thread_state(unsafe { libc::pthread_self() });
    }
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    let host = threads.iter().find(|r| r.tid == tid).map(|r| r.host)?;
    if host == 0 as libc::pthread_t {
        return None;
    }
    crate::host::thread_state(host)
}

/// Whether real-time signal `sig` may be queued: Linux refuses one
/// (`EAGAIN`) once as many signals are pending as `RLIMIT_SIGPENDING`
/// allows (those of this process are counted).
pub fn may_queue(sig: u64) -> bool {
    if sig < signal::SIGRTMIN {
        return true;
    }
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    let count = threads.iter().map(|r| r.pending.bits().count_ones()).sum::<u32>()
        + PROCESS.bits().count_ones();
    u64::from(count) < crate::rlimits::get(fwe_abi::resource::RLIMIT_SIGPENDING).0
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

    /// A thread's number is no host process's (macOS's pids end at
    /// 99999), and no two are given out alike.
    #[test]
    fn thread_ids_never_name_a_host_process() {
        let (a, b) = (alloc_tid(), alloc_tid());
        assert!((TID_FIRST..TID_END).contains(&a), "{a}");
        assert!((TID_FIRST..TID_END).contains(&b), "{b}");
        assert_ne!(a, b);
    }

    #[test]
    fn pending_is_per_thread_and_carries_info() {
        register_current();
        let info = SigInfo { code: -6, pid: 7, uid: 8, status: 0, value: 9, poll: None };
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
