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
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Arc, Mutex};

/// The process (thread-group) id, shared by all threads. Set once at startup.
static TGID: AtomicI32 = AtomicI32::new(0);

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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn init_main(pid: i32) {
    TGID.store(pid, Ordering::SeqCst);
    TID.with(|t| t.set(pid));
    // An end status and a thread list left by an earlier process of this
    // number.
    crate::procreg::forget_end(crate::host::pid());
    forget_published();
    // The calling thread's own set goes with the registry: what landed in
    // it is moved to the process's, and a handler meanwhile posts there.
    let early: Vec<(u64, SigInfo)> = with_own(|p| {
        (1..=signal::NSIG)
            .flat_map(|s| std::iter::from_fn(move || p.take(s)).map(move |i| (s, i)))
            .collect()
    });
    HOT.with(|h| h.own.set(std::ptr::null()));
    for (s, i) in early {
        PROCESS.post(s, i);
    }
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // The parent's threads are none of the child's.
    for d in &DIRECTED {
        d.tid.store(0, Ordering::Release);
        d.readers.store(0, Ordering::Release);
        d.pending.store(std::ptr::null_mut(), Ordering::Release);
    }
    forget_wait_pipes();
    crate::pdeath::forked();
    crate::futex::forked_child();
    crate::sysvipc::forked_child();
    crate::textbusy::forked_child();
    crate::reclocks::forked_child();
    crate::tmpfile::forked_child();
    crate::posixtimer::forked_child();
    crate::ptrace::forked_child();
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
static WAIT_PIPES: [(AtomicU64, AtomicI32, AtomicI32, AtomicI32); 256] =
    [const { (AtomicU64::new(0), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1)) };
        256];

fn self_id() -> u64 {
    // SAFETY: pthread_self cannot fail; async-signal-safe.
    unsafe { libc::pthread_self() as u64 }
}

/// The calling thread's wake pipe's read end and timer kqueue (-1 for
/// none, [`wait_timer`]), made on first use (none if every slot is taken or
/// no pipe can be made).
fn wait_pipe() -> Option<(i32, i32)> {
    let me = self_id();
    if let Some((_, r, _, tq)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
        let r = r.load(Ordering::SeqCst);
        return (r >= 0).then(|| (r, tq.load(Ordering::SeqCst)));
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
    let timer = wait_timer();
    for (t, rs, ws, tq) in &WAIT_PIPES {
        if t.compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            rs.store(r, Ordering::SeqCst);
            ws.store(w, Ordering::SeqCst);
            tq.store(timer, Ordering::SeqCst);
            return Some((r, timer));
        }
    }
    // SAFETY: the pipe and kqueue made above, not kept.
    unsafe {
        libc::close(r);
        libc::close(w);
        if timer >= 0 {
            libc::close(timer);
        }
    }
    None
}

/// In a host signal handler: end the calling thread's wait, if it has a
/// wake pipe. Async-signal-safe.
pub fn poke_wait() {
    let me = self_id();
    if let Some((_, _, w, _)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
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
    if let Some((t, r, w, tq)) = WAIT_PIPES.iter().find(|(t, ..)| t.load(Ordering::SeqCst) == me) {
        // SAFETY: the thread's own pipe and kqueue, no longer used.
        unsafe {
            libc::close(r.swap(-1, Ordering::SeqCst));
            libc::close(w.swap(-1, Ordering::SeqCst));
            let q = tq.swap(-1, Ordering::SeqCst);
            if q >= 0 {
                libc::close(q);
            }
        }
        t.store(0, Ordering::SeqCst);
    }
}

/// In a fork child: the parent's wake pipes are its own (the forking
/// thread's is shared with the parent), so they go; this thread makes its
/// own when it next waits. (Their timer kqueues the host did not pass on;
/// their numbers are only forgotten.)
fn forget_wait_pipes() {
    for (t, r, w, tq) in &WAIT_PIPES {
        if t.swap(0, Ordering::SeqCst) != 0 {
            // SAFETY: inherited descriptors of fwe's, no longer used here.
            unsafe {
                libc::close(r.swap(-1, Ordering::SeqCst));
                libc::close(w.swap(-1, Ordering::SeqCst));
            }
            tq.store(-1, Ordering::SeqCst);
        }
    }
}

/// `poll` of `fds` for up to `ms` milliseconds (-1: without bound); see
/// [`wait_ready_ns`].
pub fn wait_ready(fds: &mut [libc::pollfd], ms: i32) -> Result<i32, i32> {
    wait_ready_ns(fds, if ms < 0 { -1 } else { i64::from(ms) * 1_000_000 })
}

/// `poll` of `fds` for up to `ns` nanoseconds (-1: without bound), ended
/// as well by a signal for the guest (`EINTR`): one pending as the wait
/// starts, or one that lands during it, however soon. A signal the thread
/// blocks for a `signalfd` is moved onto it, so the wait sees that
/// descriptor ready. Returns how many of `fds` are ready.
///
/// The time is kept by a timer of the host's that wakes on time
/// ([`wait_timer`]): a `poll` timeout of its own, as the host's other
/// timers, can end a millisecond or more late (macOS coalesces timers),
/// where Linux wakes within its timer slack.
pub fn wait_ready_ns(fds: &mut [libc::pollfd], ns: i64) -> Result<i32, i32> {
    use std::time::{Duration, Instant};
    let deadline = (ns >= 0).then(|| Instant::now() + Duration::from_nanos(ns as u64));
    let Some((wake, timer)) = wait_pipe() else {
        let ms =
            if ns < 0 { -1 } else { (ns as u64).div_ceil(1_000_000).min(i32::MAX as u64) as i32 };
        // SAFETY: a valid array of `fds.len()` entries.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        return if n < 0 {
            Err(crate::host::errno_to_linux(crate::host::last_errno()))
        } else {
            Ok(n)
        };
    };
    // Nothing is ready until the host says so (whatever the caller's
    // `revents` held).
    for f in fds.iter_mut() {
        f.revents = 0;
    }
    let mut all: Vec<libc::pollfd> = fds.to_vec();
    all.push(libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 });
    // The timer only for a wait with a deadline: one an earlier wait left
    // fired (its event unread) keeps the kqueue readable until it is armed
    // again, which an unbounded wait never does.
    if timer >= 0 && deadline.is_some() {
        all.push(libc::pollfd { fd: timer, events: libc::POLLIN, revents: 0 });
    }
    loop {
        // What woke it before is spent; a signal from now on writes again.
        let mut b = [0u8; 64];
        // SAFETY: the thread's own non-blocking pipe and a buffer of its length.
        while unsafe { libc::read(wake, b.as_mut_ptr().cast(), b.len()) } > 0 {}
        // One that landed here for the process while this thread blocks
        // it: another thread that does not is woken to take it, as this
        // one waits on ([`post_landed`]).
        wake_others_if_asked(crate::host::WAKE_SIGNAL);
        crate::signal::drain_to_signalfd();
        if deliverable() != 0 {
            return Err(fwe_abi::errno::EINTR);
        }
        let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let poll_ms = match left {
            None => -1,
            Some(l) if l.is_zero() => 0,
            Some(l) if timer >= 0 => {
                arm_timer(timer, l);
                -1
            }
            Some(l) => l.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32,
        };
        for p in &mut all {
            p.revents = 0;
        }
        // SAFETY: a valid array of `all.len()` entries.
        let n = unsafe { libc::poll(all.as_mut_ptr(), all.len() as libc::nfds_t, poll_ms) };
        if n < 0 && crate::host::last_errno() != libc::EINTR {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let ready = all[..fds.len()].iter().filter(|p| p.revents != 0).count() as i32;
        if ready > 0 {
            for (f, a) in fds.iter_mut().zip(&all) {
                f.revents = a.revents;
            }
            return Ok(ready);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(0);
        }
    }
}

/// The write end of the calling thread's wake pipe, which another thread
/// writes to end this one's [`nap_ns`] (-1 if it has none).
pub fn poke_fd() -> i32 {
    if wait_pipe().is_none() {
        return -1;
    }
    let me = self_id();
    WAIT_PIPES
        .iter()
        .find(|(t, ..)| t.load(Ordering::SeqCst) == me)
        .map_or(-1, |(_, _, w, _)| w.load(Ordering::SeqCst))
}

/// Sleep for up to `ns` nanoseconds on time ([`wait_ready_ns`]), or until
/// the thread's wake pipe is written: a signal, or another thread writing
/// to [`poke_fd`]. What woke it is spent.
pub fn nap_ns(ns: i64) {
    let after = std::time::Duration::from_nanos(ns.max(0) as u64);
    let Some((wake, timer)) = wait_pipe() else {
        std::thread::sleep(after);
        return;
    };
    let mut all = [
        libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: timer, events: libc::POLLIN, revents: 0 },
    ];
    let (n, ms) = if timer >= 0 {
        arm_timer(timer, after);
        (2, -1)
    } else {
        (1, after.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32)
    };
    // SAFETY: a valid array of at least `n` entries.
    unsafe { libc::poll(all.as_mut_ptr(), n, ms) };
    let mut b = [0u8; 64];
    // SAFETY: the thread's own non-blocking pipe and a buffer of its length.
    while unsafe { libc::read(wake, b.as_mut_ptr().cast(), b.len()) } > 0 {}
    // As [`wait_ready_ns`]: one this thread blocks goes to another.
    wake_others_if_asked(crate::host::WAKE_SIGNAL);
}

/// Set the thread's timer kqueue `kq` to fire once, `after` from now, on
/// time (`NOTE_CRITICAL`), what it held before spent.
#[cfg(target_os = "macos")]
fn arm_timer(kq: i32, after: std::time::Duration) {
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: zeroed kevents are valid out-parameters; plain host calls on
    // the thread's own kqueue.
    unsafe {
        let mut spent: [libc::kevent; 4] = std::mem::zeroed();
        libc::kevent(kq, std::ptr::null(), 0, spent.as_mut_ptr(), 4, &zero);
        let ev = libc::kevent {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_NSECONDS | libc::NOTE_CRITICAL,
            data: after.as_nanos().min(i64::MAX as u128) as isize,
            udata: std::ptr::null_mut(),
        };
        libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
    }
}

#[cfg(not(target_os = "macos"))]
fn arm_timer(_: i32, _: std::time::Duration) {}

/// A kqueue for the calling thread's timed waits (-1 where the host has
/// none, or it cannot be made).
fn wait_timer() -> i32 {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: plain host call.
        crate::fdtable::reserve(unsafe { libc::kqueue() }).unwrap_or(-1)
    }
    #[cfg(not(target_os = "macos"))]
    {
        -1
    }
}

/// In a fork child, as the fork returns: the parent's pending signals,
/// which a child does not inherit, are dropped. Async-signal-safe.
pub fn forked() {
    PROCESS.clear();
    crate::procstore::not_busy();
    with_own(Pending::clear);
    // The parent's other threads' sets are not the child's. Only entries
    // ever taken are looked at, and only those in use written: a write to
    // each of the pool's pages would copy every one into the child.
    for q in used_pool() {
        if q.state.load(Ordering::Relaxed) != 0 {
            q.state.store(0, Ordering::Release);
        }
    }
    POOL_USED.store(0, Ordering::Relaxed);
    COUNT.store(0, Ordering::Relaxed);
    HELD.store(false, Ordering::Relaxed);
    crate::acct::forked_child();
    crate::aio::forget_all();
    // A restricted process's child is in its domain: it says so.
    crate::landlock::publish();
    // A new process starts with no robust list, as Linux's does.
    ROBUST_LIST.with(|c| c.set((0, 0)));
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
        crate::procreg::slack(crate::host::pid()).0
    } else {
        SLACK.with(Cell::get).0
    }
}

/// Set this thread's timer slack (`PR_SET_TIMERSLACK`; 0 restores its
/// default).
pub fn set_slack(value: u64) {
    if tid() == tgid() {
        let _ = crate::procreg::set_slack(crate::host::pid(), value);
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
/// turn with `flock`), so no two live threads have the same one. They are
/// taken [`TID_BLOCK`] at a time, the block marked this process's, and
/// given out from the block (a slot of the robust lists' file is a thread's
/// only once it is written after the process started).
fn shared_tid() -> i32 {
    let me = crate::host::pid();
    let mut block = TID_BLOCK_LEFT.lock().unwrap_or_else(|e| e.into_inner());
    // A fork child's block is its parent's.
    if block.0 == me && block.1 < block.2 {
        block.1 += 1;
        return block.1 - 1;
    }
    // Whose each block is, for another process to find it by
    // ([`owner_of_tid`]), beside the counter in the process store.
    let n = crate::procstore::take_tid_block(TID_FIRST, TID_END, TID_BLOCK);
    *block = (me, n + 1, n + TID_BLOCK);
    n
}

/// How many thread ids [`shared_tid`] takes at once: a change of the shared
/// counter for each block, not each thread.
const TID_BLOCK: i32 = 64;

/// The block of thread ids being given out: its process, the next, and
/// the end.
pub(crate) static TID_BLOCK_LEFT: Mutex<(i32, i32, i32)> = Mutex::new((0, 0, 0));

/// The host process thread `tid` (one of another process's) is in, if a
/// live one.
pub fn owner_of_tid(tid: i32) -> Option<i32> {
    if !(TID_FIRST..TID_END).contains(&tid) {
        return None;
    }
    let pid = crate::procstore::tid_block_owner(((tid - TID_FIRST) / TID_BLOCK) as usize);
    (pid > 0 && crate::host::process_exists(pid) && published_tids(pid).contains(&tid))
        .then_some(pid)
}

/// The threads (tids, the main thread's the process's pid) another
/// process published ([`publish_tids`]).
pub fn published_tids(pid: i32) -> Vec<i32> {
    let b = crate::procstore::get_of(crate::procstore::Kind::Threads, pid).unwrap_or_default();
    b.as_chunks::<4>().0.iter().map(|c| i32::from_ne_bytes(*c)).collect()
}

/// Whether this process published its threads ([`publish_tids`]), and
/// which process that was (a fork child's is its parent's).
pub(crate) static PUBLISHED: Mutex<i32> = Mutex::new(0);

/// The process is ending: its thread list is written no more.
static TIDS_ENDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Publish this process's threads, for another process to list
/// (`/proc/<pid>/task`) and name (a thread-directed signal, ptrace): from
/// when it first has more than its main thread, in its entry of the
/// process store ([`crate::procstore`]), which only it writes.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn publish_tids(tids: &[i32]) {
    if TIDS_ENDED.load(Ordering::SeqCst) {
        return;
    }
    let me = crate::host::pid();
    // Its threads take turns.
    let mut published = PUBLISHED.lock().unwrap_or_else(|e| e.into_inner());
    // A process that never had another thread has no list; one that had
    // keeps it, with the main thread alone in it again.
    if tids.len() <= 1 && *published != me {
        return;
    }
    *published = me;
    let b: Vec<u8> = tids.iter().flat_map(|t| t.to_ne_bytes()).collect();
    crate::procstore::put_own(crate::procstore::Kind::Threads, Some(&b));
}

/// This process starts (or is a fork's child): a list its pid's earlier
/// process left is not its own.
pub(crate) fn forget_published() {
    crate::procstore::put_own(crate::procstore::Kind::Threads, None);
    crate::procstore::put_own(crate::procstore::Kind::Robust, None);
    ROBUST.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Allocate a fresh thread id for a new thread: in a pid namespace of
/// fwe's, a number from it (threads and processes share the numbers);
/// outside one, a number no host process has ([`shared_tid`]).
pub fn alloc_tid() -> i32 {
    if crate::pidns::nested() {
        let host = crate::host::pid();
        if let Ok(nums) = crate::pidns::alloc(&crate::pidns::current(), host, true) {
            crate::pidns::remember_thread(nums[0], nums.clone());
            return nums[0];
        }
    }
    shared_tid()
}

/// Record this host thread's guest thread id (called when a thread starts).
pub fn set_tid(tid: i32) {
    TID.with(|t| t.set(tid));
    // A thread a tracer follows begins traced.
    crate::ptrace::thread_started(tid);
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

/// Record this thread's robust-futex list (`set_robust_list`): for its
/// process's other threads in its registry entry, for other processes in
/// the shared record ([`publish_robust`]).
pub fn set_robust_list(head: u64, len: u64) {
    ROBUST_LIST.with(|c| c.set((head, len)));
    let me = tid();
    let mut threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = threads.iter_mut().find(|r| r.tid == me) {
        r.robust = head;
    }
    drop(threads);
    let host = crate::host::pid();
    if me == tgid() {
        publish_robust(host, head);
    } else if !crate::pidns::nested() {
        publish_robust(me, head);
    }
}

pub fn robust_list() -> (u64, u64) {
    ROBUST_LIST.with(Cell::get)
}

/// This thread's robust-list head, taken as it ends (its futexes are
/// released once).
pub fn take_robust_list() -> u64 {
    ROBUST_LIST.with(|c| c.replace((0, 0))).0
}

/// The process's other threads' robust-list heads, with their tids, taken
/// as the process ends or runs another program.
pub fn take_others_robust() -> Vec<(i32, u64)> {
    let me = tid();
    let mut threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    threads
        .iter_mut()
        .filter(|r| r.tid != me && r.robust != 0)
        .map(|r| (r.tid, std::mem::take(&mut r.robust)))
        .collect()
}

/// Another thread of this process's robust-list head, if it is one.
pub fn robust_list_of(tid: i32) -> Option<u64> {
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    threads.iter().find(|r| r.tid == tid).map(|r| r.robust)
}

// Robust-list heads for other processes to read (`get_robust_list`): the
// process's entry of them in the process store ([`crate::procstore`]),
// which only it writes, as (id, head) pairs: the main thread's id its host
// pid, another's its thread number of fwe's ([`shared_tid`]).

/// The heads this process published, by id.
pub(crate) static ROBUST: Mutex<Vec<(i32, u64)>> = Mutex::new(Vec::new());

/// Record thread `id`'s (a host pid or a thread number) robust-list head
/// (0: none).
fn publish_robust(id: i32, head: u64) {
    let mut heads = ROBUST.lock().unwrap_or_else(|e| e.into_inner());
    let had = heads.iter().position(|&(i, _)| i == id);
    match (had, head) {
        (Some(i), 0) => {
            heads.swap_remove(i);
        }
        (Some(i), h) => heads[i].1 = h,
        (None, 0) => return,
        (None, h) => heads.push((id, h)),
    }
    let b: Vec<u8> = heads
        .iter()
        .flat_map(|&(i, h)| (i as u64).to_ne_bytes().into_iter().chain(h.to_ne_bytes()))
        .collect();
    crate::procstore::put_own(crate::procstore::Kind::Robust, Some(&b));
}

/// Another process's thread's robust-list head: `host` the main thread of
/// that host process, or `tid` one of its other threads (a number of
/// fwe's, of process `host`). `None` if it published none.
pub fn published_robust(host: i32, tid: Option<i32>) -> Option<u64> {
    let id = tid.unwrap_or(host);
    let b = crate::procstore::get_of(crate::procstore::Kind::Robust, host)?;
    b.as_chunks::<16>().0.iter().find_map(|c| {
        let i = u64::from_ne_bytes(c[..8].try_into().unwrap()) as i32;
        (i == id).then(|| u64::from_ne_bytes(c[8..].try_into().unwrap()))
    })
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

/// A real-time signal queued behind the one pending of its number, in
/// the process's [`POOL`].
struct Queued {
    /// 0: free; [`CLAIMED`] while it is written or read; else the order it
    /// was queued in, from 2 up.
    state: AtomicU64,
    /// The set it is queued in (its address).
    owner: AtomicUsize,
    sig: AtomicU64,
    info: SigSlot,
}

const CLAIMED: u64 = 1;

/// How many real-time signals the process queues behind the one pending
/// of each number, in all its sets: where `RLIMIT_SIGPENDING` is higher,
/// this is the process's limit.
pub const QUEUE_MAX: usize = 4096;

/// The real-time signals queued behind the one pending of each number, in
/// every set of the process. Shared, so a set may queue as many as the
/// process may.
static POOL: [Queued; QUEUE_MAX] = [const {
    Queued {
        state: AtomicU64::new(0),
        owner: AtomicUsize::new(0),
        sig: AtomicU64::new(0),
        info: SigSlot::new(),
    }
}; QUEUE_MAX];

/// The order the next queued signal takes.
static ORDER: AtomicU64 = AtomicU64::new(2);

/// How many entries of [`POOL`] are in use.
static POOL_USED: AtomicU64 = AtomicU64::new(0);

/// How many entries of [`POOL`] from its start were ever taken: none past
/// it was.
static POOL_HIGH: AtomicU64 = AtomicU64::new(0);

/// The entries of [`POOL`] ever taken: those past them hold nothing, and
/// are never read (a fork child would map in their pages to read them).
fn used_pool() -> &'static [Queued] {
    &POOL[..(POOL_HIGH.load(Ordering::Acquire) as usize).min(QUEUE_MAX)]
}

/// How many signals are pending in the process, in all its sets: each
/// number pending, and each queued behind it. What `RLIMIT_SIGPENDING`
/// bounds ([`may_queue`]).
static COUNT: AtomicU64 = AtomicU64::new(0);

/// The wake handler left signals another process queued in the mailbox,
/// the process being at its limit ([`admits`]): it takes them once one is
/// taken.
static HELD: AtomicBool = AtomicBool::new(false);

/// A slot of a [`Pending`] set holds no signal.
const EMPTY: u32 = 0;
/// A post is writing the slot's `siginfo` (its bit set before it is full).
const WRITING: u32 = 1;
/// The slot holds a pending signal, its bit set.
const FULL: u32 = 2;
/// A take is reading the slot's `siginfo`, with every host signal blocked
/// on its thread: no handler of that thread waits for it.
const TAKING: u32 = 3;

/// A set of pending signals with the `siginfo` each was raised with: one
/// of each standard signal, and the real-time signals queued, as Linux
/// queues them (one of each number in `info`, the rest behind it in the
/// process's [`POOL`], oldest first). The pool names a set by its
/// address, so a set never moves once it holds signals: it lives in a
/// static or an `Arc`.
///
/// Posts and takes come from many threads and signal handlers at once
/// (every thread takes from the process's set). Each slot's `state` hands
/// it between them: a post writes only a slot it claimed [`EMPTY`] (or,
/// replacing a `SIGCHLD`, [`FULL`]), and a take reads only a slot it
/// claimed full, so each signal is taken once, with the `siginfo` it was
/// posted with. `bits` mirrors the full slots, for a look without them.
pub struct Pending {
    bits: AtomicU64,
    state: [AtomicU32; signal::NSIG as usize],
    info: [SigSlot; signal::NSIG as usize],
}

/// Every host signal blocked on the calling thread for the life of the
/// value, its mask put back as it goes. Async-signal-safe.
struct AllBlocked(libc::sigset_t);

impl AllBlocked {
    fn new() -> AllBlocked {
        // SAFETY: zeroed bytes are a valid `sigset_t`, filled and passed as
        // the host asks; only this thread's mask changes.
        unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
            AllBlocked(old)
        }
    }
}

impl Drop for AllBlocked {
    fn drop(&mut self) {
        // SAFETY: the mask this thread had, as `new` read it.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

impl Pending {
    pub const fn new() -> Pending {
        Pending {
            bits: AtomicU64::new(0),
            state: [const { AtomicU32::new(EMPTY) }; signal::NSIG as usize],
            info: [const { SigSlot::new() }; signal::NSIG as usize],
        }
    }

    fn id(&self) -> usize {
        self as *const Pending as usize
    }

    /// Queue real-time `sig` with `info` behind the one pending: false
    /// when the pool is full. Async-signal-safe.
    fn enqueue(&self, sig: u64, info: &SigInfo) -> bool {
        for (i, q) in POOL.iter().enumerate() {
            if q.state.compare_exchange(0, CLAIMED, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                POOL_HIGH.fetch_max(i as u64 + 1, Ordering::AcqRel);
                q.owner.store(self.id(), Ordering::Relaxed);
                q.sig.store(sig, Ordering::Relaxed);
                store_slot(&q.info, info);
                POOL_USED.fetch_add(1, Ordering::Relaxed);
                COUNT.fetch_add(1, Ordering::Relaxed);
                let order = ORDER.fetch_add(1, Ordering::Relaxed);
                q.state.store(order, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// The oldest signal queued of number `sig`, taken off the queue.
    fn dequeue(&self, sig: u64) -> Option<SigInfo> {
        let me = self.id();
        loop {
            let oldest = used_pool()
                .iter()
                .filter_map(|q| {
                    let s = q.state.load(Ordering::Acquire);
                    (s > CLAIMED
                        && q.owner.load(Ordering::Relaxed) == me
                        && q.sig.load(Ordering::Relaxed) == sig)
                        .then_some((s, q))
                })
                .min_by_key(|&(s, _)| s);
            let (s, q) = oldest?;
            if q.state.compare_exchange(s, CLAIMED, Ordering::Acquire, Ordering::Relaxed).is_err() {
                continue;
            }
            let info = load_slot(&q.info);
            q.state.store(0, Ordering::Release);
            POOL_USED.fetch_sub(1, Ordering::Relaxed);
            uncount(1);
            return Some(info);
        }
    }

    /// Mark `bit` pending, counted if it was not.
    fn set_bit(&self, bit: u64) {
        if self.bits.fetch_or(bit, Ordering::Release) & bit == 0 {
            COUNT.fetch_add(1, Ordering::Relaxed);
        }
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
        if sig == signal::SIGCHLD && crate::reaper::superseded(info.pid) {
            return;
        }
        let i = (sig - 1) as usize;
        let (state, slot) = (&self.state[i], &self.info[i]);
        let realtime = sig >= signal::SIGRTMIN;
        loop {
            match state.load(Ordering::SeqCst) {
                EMPTY => {
                    if state
                        .compare_exchange(EMPTY, WRITING, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        // A real-time signal queued before the slot was
                        // emptied, and not yet brought in by the take that
                        // emptied it ([`Pending::promote`]), comes first:
                        // this one waits behind it.
                        match self.dequeue_if(realtime, sig) {
                            Some(older) => {
                                store_slot(slot, &older);
                                if info.code != signal::SI_USER || room(0) {
                                    self.enqueue(sig, &info);
                                }
                            }
                            None => store_slot(slot, &info),
                        }
                        // The bit before the state: no take empties a slot
                        // whose bit is still to be set.
                        self.set_bit(1 << i);
                        state.store(FULL, Ordering::SeqCst);
                        return;
                    }
                }
                // Being taken, by another thread (a take blocks its own
                // thread's handlers), which finishes without waiting: this
                // one is pending after it.
                TAKING => std::hint::spin_loop(),
                // Pending, or being written by another post (perhaps one
                // this handler interrupted): a standard signal is one with
                // it, as Linux keeps one of each; the exception is an
                // adopted process's `SIGCHLD`, which takes the place of
                // its former parent's.
                pending if !realtime => {
                    let replaces =
                        || crate::reaper::precedes(info.pid, slot.pid.load(Ordering::SeqCst));
                    if !(sig == signal::SIGCHLD && pending == FULL && replaces()) {
                        return;
                    }
                    if state
                        .compare_exchange(FULL, WRITING, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        // Still the one it replaces, now that it is claimed.
                        if replaces() {
                            store_slot(slot, &info);
                        }
                        state.store(FULL, Ordering::SeqCst);
                        return;
                    }
                }
                // A real-time signal pending, or being written: this one
                // waits behind it (a sender checked there was room,
                // [`may_queue`]). A `kill`'s, past `RLIMIT_SIGPENDING`, is
                // merged into the one pending, as Linux merges it.
                _ => {
                    if (info.code != signal::SI_USER || room(0)) && self.enqueue(sig, &info) {
                        self.promote(sig);
                    }
                    return;
                }
            }
        }
    }

    /// [`Pending::dequeue`], for a real-time signal only.
    fn dequeue_if(&self, realtime: bool, sig: u64) -> Option<SigInfo> {
        if realtime { self.dequeue(sig) } else { None }
    }

    /// Real-time `sig` was queued as the one pending of its number may
    /// have been taken, its slot emptied: the oldest queued takes the slot.
    /// Async-signal-safe.
    fn promote(&self, sig: u64) {
        let i = (sig - 1) as usize;
        let (state, slot) = (&self.state[i], &self.info[i]);
        // Pending still, or a post or take is there (a take brings the
        // oldest queued in as it ends).
        if state.compare_exchange(EMPTY, WRITING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }
        match self.dequeue(sig) {
            Some(next) => {
                store_slot(slot, &next);
                self.set_bit(1 << i);
                state.store(FULL, Ordering::SeqCst);
            }
            None => state.store(EMPTY, Ordering::SeqCst),
        }
    }

    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn take(&self, sig: u64) -> Option<SigInfo> {
        let i = (sig - 1) as usize;
        let bit = 1 << i;
        let (state, slot) = (&self.state[i], &self.info[i]);
        if self.bits.load(Ordering::SeqCst) & bit == 0 {
            return None;
        }
        // No handler of this thread runs while the slot is claimed: a post
        // to it would wait for this take.
        let _blocked = AllBlocked::new();
        // Not pending, or being written, or taken by another thread.
        if state.compare_exchange(FULL, TAKING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return None;
        }
        let mut info = load_slot(slot);
        // The next of a queued real-time signal takes its place.
        let next = if sig >= signal::SIGRTMIN { self.dequeue(sig) } else { None };
        if let Some(next) = next {
            store_slot(slot, &next);
            state.store(FULL, Ordering::SeqCst);
        } else {
            self.bits.fetch_and(!bit, Ordering::SeqCst);
            state.store(EMPTY, Ordering::SeqCst);
            uncount(1);
            // One queued as the slot was emptied.
            if sig >= signal::SIGRTMIN {
                self.promote(sig);
            }
        }
        // A POSIX timer's signal: its overrun as it is taken.
        if info.code == fwe_abi::signal::SI_TIMER {
            info.uid = crate::posixtimer::delivered(info.pid);
        }
        Some(info)
    }

    fn bits(&self) -> u64 {
        self.bits.load(Ordering::Acquire)
    }

    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn clear(&self) {
        uncount(u64::from(self.bits.swap(0, Ordering::AcqRel).count_ones()));
        // (In a fork child, a slot another thread of the parent held.)
        for state in &self.state {
            state.store(EMPTY, Ordering::SeqCst);
        }
        let me = self.id();
        for q in used_pool() {
            let s = q.state.load(Ordering::Acquire);
            if s > CLAIMED
                && q.owner.load(Ordering::Relaxed) == me
                && q.state.compare_exchange(s, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok()
            {
                POOL_USED.fetch_sub(1, Ordering::Relaxed);
                uncount(1);
            }
        }
    }
}

impl Drop for Pending {
    /// A thread's set goes with the thread, and the signals queued in it.
    fn drop(&mut self) {
        self.clear();
    }
}

/// `n` signals pending are taken: and if the wake handler left signals in
/// the mailbox for want of room, it is woken to take them now.
/// Async-signal-safe.
fn uncount(n: u64) {
    if n == 0 {
        return;
    }
    COUNT.fetch_sub(n, Ordering::Relaxed);
    if HELD.swap(false, Ordering::AcqRel) {
        // SAFETY: signalling this thread itself; the handler drains the
        // mailbox.
        unsafe { libc::pthread_kill(libc::pthread_self(), crate::host::WAKE_SIGNAL) };
    }
}

fn store_slot(slot: &SigSlot, info: &SigInfo) {
    slot.code.store(info.code, Ordering::Relaxed);
    slot.pid.store(info.pid, Ordering::Relaxed);
    slot.uid.store(info.uid, Ordering::Relaxed);
    slot.status.store(info.status, Ordering::Relaxed);
    slot.value.store(info.value, Ordering::Relaxed);
    let (fd, band) = info.poll.unwrap_or((-1, 0));
    slot.poll_fd.store(fd, Ordering::Relaxed);
    slot.band.store(band, Ordering::Relaxed);
}

fn load_slot(slot: &SigSlot) -> SigInfo {
    SigInfo {
        code: slot.code.load(Ordering::Relaxed),
        pid: slot.pid.load(Ordering::Relaxed),
        uid: slot.uid.load(Ordering::Relaxed),
        status: slot.status.load(Ordering::Relaxed),
        value: slot.value.load(Ordering::Relaxed),
        poll: match slot.poll_fd.load(Ordering::Relaxed) {
            -1 => None,
            fd => Some((fd, slot.band.load(Ordering::Relaxed))),
        },
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
    /// Its robust-futex list's head (`set_robust_list`).
    robust: u64,
    /// Its nice value (`setpriority` of its tid), for a thread other than
    /// the main one, whose nice value is the process's record's.
    nice: i32,
}

/// Every live guest thread's pending set, by tid.
static THREADS: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

/// The guest's threads, by tid, the main thread's (the process's) first.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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

/// The signal state every system call looks at, in one thread-local so
/// that a call looks it up once (each lookup is a call into the host's
/// dynamic linker).
struct Hot {
    mask: Cell<u64>,
    /// The mask `rt_sigsuspend` replaced, restored once the call ends.
    saved_mask: Cell<Option<u64>>,
    /// This thread's registered pending set (owned by [`THREADS`]).
    own: Cell<*const Pending>,
    /// A process signal landed here while this thread blocked it: the
    /// other threads are to be woken to take it ([`post_landed`]).
    wake_others: Cell<bool>,
}

thread_local! {
    static HOT: Hot = const {
        Hot {
            mask: Cell::new(0),
            saved_mask: Cell::new(None),
            own: Cell::new(std::ptr::null()),
            wake_others: Cell::new(false),
        }
    };
    static ALTSTACK: Cell<Stack> = const {
        Cell::new(Stack { ss_sp: 0, ss_flags: signal::SS_DISABLE, _pad: 0, ss_size: 0 })
    };
}

/// This host thread starts another guest thread ([`crate::thread_reused`]):
/// its state is a new thread's.
pub(crate) fn thread_reused() {
    TID.with(|t| t.set(0));
    CLEAR_CHILD_TID.with(|c| c.set(0));
    ROBUST_LIST.with(|r| r.set((0, 0)));
    NAME.with(|n| n.set(None));
    SLACK.with(|s| s.set((DEFAULT_SLACK, DEFAULT_SLACK)));
    HOT.with(|h| {
        h.mask.set(0);
        h.saved_mask.set(None);
        h.own.set(std::ptr::null());
        h.wake_others.set(false);
    });
    ALTSTACK.with(|a| a.set(Stack { ss_sp: 0, ss_flags: signal::SS_DISABLE, _pad: 0, ss_size: 0 }));
}

/// After a system call: wake the other threads if a signal for them landed
/// here, and the calling thread's pending signals, mask and saved mask
/// (see [`save_mask`]), in one look.
pub fn after_call(sig: libc::c_int) -> (u64, u64, Option<u64>) {
    let (wake, own, mask, saved) =
        HOT.with(|h| (h.wake_others.replace(false), h.own.get(), h.mask.get(), h.saved_mask.get()));
    if wake {
        wake_others(sig);
    }
    (own_bits(own) | PROCESS.bits(), mask, saved)
}

/// The calling thread's pending signals and mask, in one look.
pub fn state() -> (u64, u64) {
    let (own, mask) = HOT.with(|h| (h.own.get(), h.mask.get()));
    (own_bits(own) | PROCESS.bits(), mask)
}

/// The bits pending in `own` (the process's set when it is null).
fn own_bits(own: *const Pending) -> u64 {
    if own.is_null() {
        PROCESS.bits()
    } else {
        // SAFETY: the pointer is cleared before the registry drops its Arc.
        unsafe { &*own }.bits()
    }
}

/// Run `f` holding the thread registry lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn register(tid: i32) -> Arc<Pending> {
    if tid != tgid() {
        let s = slack();
        SLACK_HANDOFF.lock().unwrap_or_else(|e| e.into_inner()).push((tid, s));
    }
    if tid != tgid() {
        // Its filesystem view and namespaces are its creator's.
        crate::threadfs::started(tid);
    }
    // Its creator's nice value, as Linux's thread inherits it.
    let nice = if tid != tgid() { nice_of(self::tid()) } else { 0 };
    let pending = Arc::new(Pending::new());
    let entry = Registered { tid, pending: pending.clone(), host: 0, robust: 0, nice };
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).push(entry);
    directed_add(tid, Arc::as_ptr(&pending));
    publish_tids(&tids());
    pending
}

/// Thread `tid` of this process's nice value: the main thread's is the
/// process's, in its record ([`crate::procreg::nice`]).
pub fn nice_of(tid: i32) -> i32 {
    if tid == tgid() {
        return crate::procreg::nice(crate::host::pid());
    }
    let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    threads.iter().find(|r| r.tid == tid).map_or(0, |r| r.nice)
}

/// Set the nice value of thread `tid` of this process, other than the
/// main one: whether it is one.
pub fn set_nice_of(tid: i32, nice: i32) -> bool {
    let mut threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    threads.iter_mut().find(|r| r.tid == tid).map(|r| r.nice = nice).is_some()
}

/// Make `pending` (from [`register`]) the calling thread's own set.
pub fn adopt(pending: &Arc<Pending>) {
    HOT.with(|h| h.own.set(Arc::as_ptr(pending)));
    crate::threadfs::enter(tid());
}

/// Record the host thread of the registration owning `pending`. Does
/// nothing if that thread has already exited.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn set_host_thread(pending: &Arc<Pending>, host: libc::pthread_t) {
    let mut threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = threads.iter_mut().find(|r| Arc::ptr_eq(&r.pending, pending)) {
        r.host = host;
        directed_host(r.tid, host);
    }
}

/// Drop the registration owning `pending` (a thread that never started).
pub fn unregister(pending: &Arc<Pending>) {
    let gone: Vec<i32> = {
        let mut t = THREADS.lock().unwrap_or_else(|e| e.into_inner());
        let gone = t.iter().filter(|r| Arc::ptr_eq(&r.pending, pending)).map(|r| r.tid).collect();
        t.retain(|r| !Arc::ptr_eq(&r.pending, pending));
        gone
    };
    for tid in gone {
        directed_remove(tid);
        crate::threadfs::forget(tid);
    }
    publish_tids(&tids());
}

/// Forget the calling thread's registration as it exits.
pub fn unregister_current() {
    // Its process descriptors (`PIDFD_THREAD`) say it has ended.
    crate::pidfd::thread_gone(tid());
    drop_wait_pipe();
    let own = HOT.with(|h| h.own.replace(std::ptr::null()));
    directed_remove(tid());
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).retain(|r| Arc::as_ptr(&r.pending) != own);
    publish_tids(&tids());
    if tid() != tgid() {
        publish_robust(tid(), 0);
    }
}

/// As the process ends: its published threads go, and are written no
/// more.
pub fn process_ending() {
    TIDS_ENDED.store(true, Ordering::SeqCst);
    crate::procstore::put_own(crate::procstore::Kind::Threads, None);
    crate::procstore::put_own(crate::procstore::Kind::Robust, None);
}

// --- signals for a named thread, from a handler ------------------------------------
//
// A signal another process sends one thread of this one comes through the
// wake signal's handler ([`crate::signote`]), which must not take the
// registry's lock: each thread's pending set and host thread are also kept
// in a table it reads without one, an entry counting its readers so it is
// not taken away while one reads it.

const DIRECTED_SLOTS: usize = 512;

struct Directed {
    tid: AtomicI32,
    readers: AtomicU32,
    pending: std::sync::atomic::AtomicPtr<Pending>,
    host: std::sync::atomic::AtomicUsize,
}

static DIRECTED: [Directed; DIRECTED_SLOTS] = [const {
    Directed {
        tid: AtomicI32::new(0),
        readers: AtomicU32::new(0),
        pending: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        host: std::sync::atomic::AtomicUsize::new(0),
    }
}; DIRECTED_SLOTS];

fn directed_add(tid: i32, pending: *const Pending) {
    for d in &DIRECTED {
        if d.tid.load(Ordering::Acquire) == 0 && d.readers.load(Ordering::Acquire) == 0 {
            d.pending.store(pending as *mut Pending, Ordering::Release);
            d.host.store(0, Ordering::Release);
            if d.tid.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return;
            }
        }
    }
}

#[allow(clippy::unnecessary_cast)] // `pthread_t` is a pointer on macOS
fn directed_host(tid: i32, host: libc::pthread_t) {
    if let Some(d) = DIRECTED.iter().find(|d| d.tid.load(Ordering::Acquire) == tid) {
        d.host.store(host as usize, Ordering::Release);
    }
}

fn directed_remove(tid: i32) {
    if let Some(d) = DIRECTED.iter().find(|d| d.tid.load(Ordering::Acquire) == tid) {
        d.tid.store(0, Ordering::Release);
        // Until no handler reads it.
        while d.readers.load(Ordering::Acquire) != 0 {
            std::hint::spin_loop();
        }
        d.pending.store(std::ptr::null_mut(), Ordering::Release);
    }
}

/// Post `sig` for thread `tid` of this process and wake it: whether it was
/// there. Async-signal-safe.
#[allow(clippy::unnecessary_cast)] // `pthread_t` is a pointer on macOS
pub fn post_directed(tid: i32, sig: u64, info: SigInfo) -> bool {
    for d in &DIRECTED {
        if d.tid.load(Ordering::Acquire) != tid {
            continue;
        }
        d.readers.fetch_add(1, Ordering::AcqRel);
        let p = d.pending.load(Ordering::Acquire);
        let ok = d.tid.load(Ordering::Acquire) == tid && !p.is_null();
        if ok {
            // SAFETY: the set lives while its entry names it, and the entry
            // is not taken away while a reader is counted.
            unsafe { (*p).post(sig, info) };
            let host = d.host.load(Ordering::Acquire);
            // SAFETY: pthread_self cannot fail.
            if host != 0 && host != unsafe { libc::pthread_self() } as usize {
                // SAFETY: a registered thread, live while its entry is.
                unsafe { libc::pthread_kill(host as libc::pthread_t, crate::host::WAKE_SIGNAL) };
            }
        }
        d.readers.fetch_sub(1, Ordering::AcqRel);
        return ok;
    }
    false
}

fn with_own<R>(f: impl FnOnce(&Pending) -> R) -> R {
    let p = HOT.with(|h| h.own.get());
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
        HOT.with(|h| h.wake_others.set(true));
    }
}

/// Wake the other threads if a process signal landed on this one while it
/// blocked it ([`post_landed`]). Takes the thread registry lock: called
/// where this thread holds none of fwe's locks.
pub fn wake_others_if_asked(sig: libc::c_int) {
    if HOT.with(|h| h.wake_others.replace(false)) {
        wake_others(sig);
    }
}

/// Record `sig` as pending against the process; any thread that does not
/// block it takes it at its next system call.
pub fn post_process(sig: u64, info: SigInfo) {
    PROCESS.post(sig, info);
}

/// From a thread of fwe's own (the reaper's watcher, the parent-death
/// watcher): [`post_process`], and every guest thread woken. A wake sent
/// to the process would reach one thread the host picks, which may block
/// `sig` and wait on, leaving the one that takes it asleep.
pub fn post_process_waking(sig: u64, info: SigInfo) {
    if sig == signal::SIGCHLD && crate::trace::file().is_some() {
        crate::trace::note_to_file(&format!(
            "signal: SIGCHLD from {} posted (pending {:#x})",
            info.pid,
            PROCESS.bits()
        ));
    }
    post_process(sig, info);
    wake_others(crate::host::WAKE_SIGNAL);
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

/// Whether one more signal may be queued with `extra` more already on
/// their way: fewer are pending in the process, with its POSIX timers'
/// (each holds one, as Linux allocates it), than `RLIMIT_SIGPENDING`
/// allows and the pool holds. Linux counts those of the user's processes;
/// those of this process are counted here. Async-signal-safe.
fn room(extra: u64) -> bool {
    let used = COUNT.load(Ordering::Relaxed) + crate::posixtimer::count() as u64 + extra;
    used < crate::rlimits::sigpending()
        && POOL_USED.load(Ordering::Relaxed) + extra < QUEUE_MAX as u64
}

/// Whether signal `sig` sent with `si_code` `code` may be queued: Linux
/// refuses a real-time one (`EAGAIN`) past `RLIMIT_SIGPENDING`, unless a
/// `kill` sent it (`SI_USER`), which is merged into the one pending
/// instead; a standard signal is always taken, one of each number.
pub fn may_queue(sig: u64, code: i32) -> bool {
    sig < signal::SIGRTMIN || code == signal::SI_USER || room(0)
}

/// Whether a POSIX timer may be made: it holds a signal of the limit's
/// from the start, as Linux allocates it then.
pub fn may_add_timer() -> bool {
    room(0)
}

/// In the wake handler, for signal `sig` with `code` another process
/// queued in the mailbox, `taken` taken in this drain already: whether it
/// may be taken now ([`may_queue`]). One that may not stays in the
/// mailbox, and is taken once a signal pending is ([`uncount`]): the
/// sender found room in the mailbox, so it is not lost. Async-signal-safe.
pub fn admits(sig: u64, code: i32, taken: u64) -> bool {
    if sig < signal::SIGRTMIN || code == signal::SI_USER || room(taken) {
        return true;
    }
    HELD.store(true, Ordering::Release);
    false
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
    HOT.with(|h| h.mask.get())
}

/// Replace the calling thread's mask; `SIGKILL` and `SIGSTOP` cannot be
/// blocked.
pub fn set_mask(mask: u64) {
    HOT.with(|h| h.mask.set(mask & !UNBLOCKABLE));
}

/// Remember the mask to restore when `rt_sigsuspend` ends.
pub fn save_mask(mask: u64) {
    HOT.with(|h| h.saved_mask.set(Some(mask)));
}

/// The mask saved by `rt_sigsuspend`, if the call is still in progress.
pub fn take_saved_mask() -> Option<u64> {
    HOT.with(|h| h.saved_mask.take())
}

/// The calling thread's alternate signal stack.
pub fn altstack() -> Stack {
    ALTSTACK.with(Cell::get)
}

pub fn set_altstack(stack: Stack) {
    ALTSTACK.with(|a| a.set(stack));
}

/// Held by every unit test that touches the process's pending signals or
/// signal queues, which all of a test process's threads share.
#[cfg(test)]
pub(crate) fn signals_held() -> std::sync::MutexGuard<'static, ()> {
    static HELD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    HELD.lock().unwrap_or_else(|e| e.into_inner())
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
        let _held = crate::thread::signals_held();
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

    /// A set queues as many real-time signals as the process's pool
    /// holds, not a fixed few, and a set that goes frees what it queued.
    #[test]
    fn real_time_signals_queue_past_a_few() {
        let rt = signal::SIGRTMIN + 2;
        let p = Pending::new();
        for v in 0..300 {
            p.post(rt, valued(v));
        }
        let taken: Vec<u64> = std::iter::from_fn(|| p.take(rt)).map(|i| i.value).collect();
        assert_eq!(taken, (0..300).collect::<Vec<_>>());
        let q = Arc::new(Pending::new());
        for v in 0..10 {
            q.post(rt, valued(v));
        }
        let mine = |id: usize| {
            POOL.iter()
                .filter(|e| e.state.load(Ordering::Acquire) > CLAIMED)
                .filter(|e| e.owner.load(Ordering::Relaxed) == id)
                .count()
        };
        let id = q.id();
        assert_eq!(mine(id), 9);
        drop(q);
        assert_eq!(mine(id), 0);
    }

    fn valued(value: u64) -> SigInfo {
        SigInfo { code: signal::SI_QUEUE, value, ..SigInfo::default() }
    }

    /// Real-time signals queue, each with its own `siginfo`, oldest first;
    /// a standard one pending keeps its first.
    #[test]
    fn real_time_signals_queue() {
        let p = Pending::new();
        let rt = signal::SIGRTMIN + 1;
        for v in 1..=3 {
            p.post(rt, valued(v));
        }
        p.post(signal::SIGUSR1, valued(7));
        p.post(signal::SIGUSR1, valued(8));
        let taken: Vec<u64> = std::iter::from_fn(|| p.take(rt)).map(|i| i.value).collect();
        assert_eq!(taken, [1, 2, 3]);
        assert_eq!(p.bits() & (1 << (rt - 1)), 0);
        assert_eq!(p.take(signal::SIGUSR1).map(|i| i.value), Some(7));
        assert!(p.take(signal::SIGUSR1).is_none());
        p.post(rt, valued(9));
        p.post(rt, valued(10));
        p.clear();
        assert!(p.take(rt).is_none());
    }

    /// Threads taking from one set (the process's, which every thread
    /// takes from) while another posts: each signal posted is taken once,
    /// with its own `siginfo`, whatever the posts and takes interleave.
    #[test]
    fn concurrent_takes_take_each_signal_once() {
        let _held = signals_held();
        const POSTS: u64 = 20_000;
        let p = Pending::new();
        let bit = 1 << (signal::SIGUSR1 - 1);
        let done = AtomicBool::new(false);
        let mut taken: Vec<u64> = std::thread::scope(|s| {
            let takers: Vec<_> = (0..3)
                .map(|_| {
                    s.spawn(|| {
                        let mut got = Vec::new();
                        while !done.load(Ordering::SeqCst) || p.bits() & bit != 0 {
                            if let Some(i) = p.take(signal::SIGUSR1) {
                                got.push(i.value);
                            }
                        }
                        got
                    })
                })
                .collect();
            for v in 0..POSTS {
                // The next once the last is taken (or merged into a take):
                // each is then a signal of its own, none pending to merge with.
                while p.bits() & bit != 0 {
                    std::hint::spin_loop();
                }
                p.post(signal::SIGUSR1, valued(v));
            }
            done.store(true, Ordering::SeqCst);
            takers.into_iter().flat_map(|t| t.join().unwrap()).collect()
        });
        taken.sort_unstable();
        let twice = taken.windows(2).filter(|w| w[0] == w[1]).count();
        taken.dedup();
        assert_eq!((twice, taken.len() as u64), (0, POSTS), "taken twice, and how many taken");
    }

    /// Real-time signals posted while threads take them: each is taken
    /// once, and each thread takes them oldest first.
    #[test]
    fn concurrent_takes_of_queued_signals_keep_each_and_their_order() {
        let _held = signals_held();
        const POSTS: u64 = 20_000;
        let rt = signal::SIGRTMIN + 3;
        let p = Pending::new();
        let (done, count) = (AtomicBool::new(false), AtomicU64::new(0));
        let mut taken: Vec<u64> = std::thread::scope(|s| {
            let takers: Vec<_> = (0..3)
                .map(|_| {
                    s.spawn(|| {
                        let mut got = Vec::new();
                        while !done.load(Ordering::SeqCst) || p.bits() != 0 {
                            if let Some(i) = p.take(rt) {
                                got.push(i.value);
                                count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        got
                    })
                })
                .collect();
            for v in 0..POSTS {
                // A few queued at a time, well within the pool.
                while v - count.load(Ordering::SeqCst) > 64 {
                    std::hint::spin_loop();
                }
                p.post(rt, valued(v));
            }
            done.store(true, Ordering::SeqCst);
            takers
                .into_iter()
                .flat_map(|t| {
                    let got = t.join().unwrap();
                    assert!(got.windows(2).all(|w| w[0] < w[1]), "a thread took one out of order");
                    got
                })
                .collect()
        });
        taken.sort_unstable();
        let twice = taken.windows(2).filter(|w| w[0] == w[1]).count();
        taken.dedup();
        assert_eq!((twice, taken.len() as u64), (0, POSTS), "taken twice, and how many taken");
    }
}
