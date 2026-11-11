//! Orphans, and the reapers that adopt them.
//!
//! On Linux, a process whose parent ends is adopted by the nearest living
//! ancestor that is a child subreaper (`PR_SET_CHILD_SUBREAPER`), or else
//! by the init of the dying parent's pid namespace; the adopter is told of
//! its end with `SIGCHLD` and reaps it with `wait`. On macOS every orphan
//! goes to `launchd`, and only a parent can wait for a process, so fwe
//! keeps the adoption itself:
//!
//! - Each process's record ([`crate::procreg`]) holds its line of
//!   ancestors and the init its adoption stops at (its *bound*), and says
//!   whether it is a subreaper. A process whose parent has gone is the
//!   adopter's ([`adopter`]): its first living ancestor past the parent
//!   that is a subreaper or the bound, which also stops the search.
//! - A process that ends where a reaper might adopt it records how it
//!   ended ([`crate::procreg::Ended`]); one killed by `SIGKILL` cannot, and
//!   whoever finds it gone records it for it ([`crate::procreg::gone`]).
//!   Its parent's `wait` removes that record; once the parent has gone too,
//!   the adopter's `wait` takes it ([`take_adopted`]).
//! - A reaper (a subreaper, or a pid namespace's init) runs a watcher
//!   thread that follows its descendants on the host (`kqueue` process
//!   events), so it sees an adopted one end, stop or continue: it then
//!   raises `SIGCHLD` in the reaper, and wakes its threads waiting in
//!   `wait`, which report the stop or continue as Linux reports a
//!   child's ([`take_change`]).
//!
//! A child made with `CLONE_PARENT` is its creator's parent's, which is not
//! its parent on the host: its record says so (a *foster* child,
//! [`procreg::ProcRecord::foster`]), and it tells that parent as it starts
//! ([`foster_started`]). The parent then runs the watcher too, and its
//! `wait` takes the child as a reaper takes one it adopted.
//!
//! An adopter is found from the line of ancestors when it is asked for,
//! and a process that becomes a subreaper, or stops being one, notes the
//! orphans below it then ([`set_subreaper`]): those that had an adopter
//! already keep it, and those it adopted stay its own, as on Linux, where
//! an orphan is adopted when its parent ends.

use crate::procreg::{self, Ended, Proc};
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::SeqCst};

/// The host pid of this process.
fn me() -> i32 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() }
}

/// The processes that would adopt one with line of ancestors `lineage`
/// and bound `bound` were its parent gone: each ancestor past the parent,
/// up to and including the bound.
fn candidates(lineage: &[Proc], bound: Option<Proc>) -> impl Iterator<Item = Proc> + '_ {
    let at_bound = lineage.first().copied() == bound && bound.is_some();
    let mut done = at_bound;
    lineage.iter().skip(1).copied().take_while(move |p| {
        if done {
            return false;
        }
        done = Some(*p) == bound;
        true
    })
}

/// Whether candidate `p` adopts orphan `who`: it lives, and is the bound,
/// or a subreaper that did not find `who` adopted already when it became
/// one, or one that adopted it before it stopped being one.
fn adopts(p: Proc, bound: Option<Proc>, who: Proc) -> bool {
    procreg::alive(p)
        && (Some(p) == bound
            || procreg::read(p.0).is_some_and(|r| {
                r.subreaper && !r.declined.contains(&who) || r.kept.contains(&who)
            }))
}

/// Who adopts process `who`, with line of ancestors `lineage` and bound
/// `bound`, once its parent has gone: the host pid of its first living
/// ancestor past the parent that is a subreaper (for it) or the bound.
pub fn adopter(who: Proc, lineage: &[Proc], bound: Option<Proc>) -> Option<i32> {
    candidates(lineage, bound).find(|&p| adopts(p, bound, who)).map(|p| p.0)
}

/// Whether some reaper would adopt process `who`, with line of ancestors
/// `lineage` and bound `bound`, were its parent gone now: whether how it
/// ends is worth recording.
pub fn might_adopt(who: Proc, lineage: &[Proc], bound: Option<Proc>) -> bool {
    adopter(who, lineage, bound).is_some()
}

/// Whether how process `who` ends is to be recorded for someone other
/// than its host parent to take: a reaper might adopt it, or it is a
/// foster child (`foster`) of a living parent.
pub fn takes_end(who: Proc, lineage: &[Proc], bound: Option<Proc>, foster: bool) -> bool {
    foster && lineage.first().is_some_and(|&p| procreg::alive(p))
        || might_adopt(who, lineage, bound)
}

/// Whether a process with line `lineage`, foster or not (`foster`), is a
/// foster child of this process (by pid and start time: not of an earlier
/// process that had this pid).
fn fostered_here(lineage: &[Proc], foster: bool) -> bool {
    foster && lineage.first().is_some_and(|&p| Some(p) == own_proc())
}

/// This process as its pid and start time, kept once known.
fn own_proc() -> Option<Proc> {
    static PID: AtomicI32 = AtomicI32::new(0);
    static START: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let me = me();
    if PID.load(SeqCst) != me {
        let start = procreg::start_time(me)?;
        START.store(start, SeqCst);
        PID.store(me, SeqCst);
    }
    Some((me, START.load(SeqCst)))
}

/// This process has a foster child: its watcher is to run.
static FOSTERING: AtomicBool = AtomicBool::new(false);

/// This process was told it has a foster child (from the signal handler
/// that takes the note). Async-signal-safe.
pub fn fostered() {
    FOSTERING.store(true, SeqCst);
}

/// Whether this process has foster children, so its watcher is to run
/// (kept across `execve`, see [`set_fostering`]).
pub fn fostering() -> bool {
    FOSTERING.load(SeqCst)
}

/// [`fostering`], as a process that ran another program had it.
pub fn set_fostering(on: bool) {
    FOSTERING.store(on, SeqCst);
}

/// Whether the watcher is to be started: this process was told of a
/// foster child and its watcher does not run yet. A cheap check.
pub fn watcher_wanted() -> bool {
    FOSTERING.load(SeqCst) && !active()
}

/// This process, just made with `CLONE_PARENT` (a foster child, its line
/// `lineage`), tells its parent, whose watcher is to follow it.
pub fn foster_started(lineage: &[Proc]) {
    let Some(&(parent, _)) = lineage.first() else { return };
    if crate::signote::foster(parent).is_ok() {
        let _ = crate::host::kill_process(parent, crate::host::WAKE_SIGNAL);
    }
}

/// `PR_SET_CHILD_SUBREAPER`: make this process a subreaper (`on`), or
/// not. On Linux an orphan is adopted when its parent ends, by whoever is
/// its reaper then; so the orphans below this process that have an adopter
/// now keep it once this process becomes a subreaper, and those this
/// process adopted stay its own once it stops being one.
pub fn set_subreaper(on: bool) {
    busy(|| {
        let me = me();
        let Some(own) = procreg::read(me) else {
            procreg::set_own_subreaper(on, Vec::new(), Vec::new());
            return;
        };
        // Every orphan below this process, living or ended unreaped, who
        // adopts it now, and whether that is a reaper below this process
        // (which, when it ends, hands it on to the next reaper up, as on
        // Linux, so it is not declined).
        let below = |lineage: &[Proc], a: Option<i32>| {
            let mine = lineage.iter().position(|&(p, _)| p == me);
            a.is_some_and(|a| lineage.iter().position(|&(p, _)| p == a) < mine)
        };
        let mut orphans: Vec<(Proc, Option<i32>, bool)> = procreg::all()
            .into_iter()
            .filter(|(_, r)| r.lineage.iter().any(|&(p, _)| p == me) && orphaned(&r.lineage))
            .map(|(pid, r)| {
                let a = adopter((pid, r.start), &r.lineage, r.bound);
                ((pid, r.start), a, below(&r.lineage, a))
            })
            .collect();
        orphans.extend(
            procreg::all_ended()
                .into_iter()
                .filter(|e| e.lineage.iter().any(|&(p, _)| p == me) && orphaned(&e.lineage))
                .map(|e| {
                    let a = adopter((e.pid, e.start), &e.lineage, e.bound);
                    ((e.pid, e.start), a, below(&e.lineage, a))
                }),
        );
        let still = |p: &Proc| orphans.iter().any(|(o, ..)| o == p);
        let mut kept: Vec<Proc> = own.kept.iter().copied().filter(still).collect();
        let declined = if on {
            orphans.iter().filter(|(_, a, low)| *a != Some(me) && !low).map(|(o, ..)| *o).collect()
        } else {
            kept.extend(orphans.iter().filter(|(_, a, _)| *a == Some(me)).map(|(o, ..)| *o));
            Vec::new()
        };
        procreg::set_own_subreaper(on, declined, kept);
    });
}

/// Whether the parent at the head of `lineage` has gone.
fn orphaned(lineage: &[Proc]) -> bool {
    lineage.first().is_some_and(|&p| !procreg::alive(p))
}

/// The guest's parent of host process `pid`, as a host pid: its parent
/// while that lives, else the reaper that adopted it. `host_ppid` is the
/// host's answer, used for a process fwe has no line of ancestors for.
pub fn parent_of(pid: i32, host_ppid: i32) -> i32 {
    let Some(r) = procreg::read(pid) else { return host_ppid };
    match r.lineage.first() {
        Some(&p) if procreg::alive(p) => p.0,
        Some(_) => adopter((pid, r.start), &r.lineage, r.bound).unwrap_or(host_ppid),
        None => host_ppid,
    }
}

/// Whether someone may still reap ended process `e`: its parent, or a
/// reaper that adopts it.
pub fn reapable(e: &Ended) -> bool {
    e.lineage.first().is_some_and(|&p| procreg::alive(p))
        || might_adopt((e.pid, e.start), &e.lineage, e.bound)
}

/// Whether ended process `e` is this process's to reap as an adopter, or
/// as a foster child's parent.
fn adopted_ended(e: &Ended) -> bool {
    fostered_here(&e.lineage, e.foster)
        || orphaned(&e.lineage) && adopter((e.pid, e.start), &e.lineage, e.bound) == Some(me())
}

/// Whether living process `pid`, whose record is `r`, is one this process
/// adopted, or a foster child of its.
fn adopted_live(pid: i32, r: &procreg::ProcRecord) -> bool {
    let me = me();
    fostered_here(&r.lineage, r.foster)
        || r.lineage.first().is_some_and(|&(p, _)| p != me)
            && orphaned(&r.lineage)
            && adopter((pid, r.start), &r.lineage, r.bound) == Some(me)
}

/// Which children a `wait` is for, by host pid or process group.
#[derive(Clone, Copy, Debug)]
pub enum Select {
    Any,
    Pid(i32),
    Pgid(i32),
}

impl Select {
    fn matches(self, pid: i32, pgid: i32) -> bool {
        match self {
            Select::Any => true,
            Select::Pid(p) => p == pid,
            Select::Pgid(g) => g == pgid,
        }
    }
}

/// An adopted process that ended and that `sel` matches, its record taken
/// (it is reaped) unless `peek`.
pub fn take_adopted(sel: Select, peek: bool) -> Option<Ended> {
    if !active() {
        return None;
    }
    for e in procreg::all_ended() {
        if !sel.matches(e.pid, e.pgid) || !adopted_ended(&e) {
            continue;
        }
        if peek {
            return Some(e);
        }
        // Taken, and marked told, under the lock the watcher's `notify`
        // marks under: whichever marks it first raises its SIGCHLD, and only
        // it (a second would arrive with no report, from no one). The mark
        // goes with the watcher's next look, the record taken.
        let mut told = NOTIFIED.lock().unwrap_or_else(|e| e.into_inner());
        if procreg::take_adopted_end(&e) {
            let first = told.get_or_insert_with(HashSet::new).insert((e.pid, e.start));
            drop(told);
            crate::pidns::released(&e.numbers, e.pid);
            crate::pidfd::reaped(e.pid, e.status);
            if first && sigchld_taken() {
                // Reaped before the watcher saw it end: its SIGCHLD is
                // still owed, as Linux sends it before `wait` can return.
                raise(&e);
            }
            return Some(e);
        }
    }
    None
}

/// A reaper reaped `child`, a child of its own: what that child left
/// unreaped is now the reaper's, and owed its SIGCHLD before the `wait`
/// returns, as Linux hands a parent's zombies on as the parent ends. One
/// killed outright left no record of its end, which the watcher may not
/// have made yet: it is made here.
pub fn reaped_own_child(child: i32) {
    if active() {
        for (pid, r) in procreg::all() {
            if r.lineage.first().is_some_and(|&(p, _)| p == child) {
                procreg::gone(pid);
            }
        }
        notify();
    }
}

/// Whether a living process this one adopted matches `sel`. One found
/// ended with its record left (killed outright, which records nothing)
/// has its end recorded now, for the `wait` that looks next to take, as
/// the watcher would a moment later.
pub fn has_live_adopted(sel: Select) -> bool {
    if !active() {
        return false;
    }
    let mut live = false;
    for (pid, r) in procreg::all() {
        // SAFETY: plain host call.
        let pgid = unsafe { libc::getpgid(pid) };
        if !adopted_live(pid, &r) {
            continue;
        }
        if !procreg::alive((pid, r.start)) {
            procreg::gone(pid);
        } else if sel.matches(pid, pgid) {
            live = true;
        }
    }
    live
}

/// The stops and continues of adopted processes not yet reported to
/// `wait`: the latest of each, as an [`Ended`] whose status is the Linux
/// wait status of the stop or continue.
static CHANGES: Mutex<Vec<Ended>> = Mutex::new(Vec::new());

/// Whether Linux wait status `status` is a stop's.
fn is_stop(status: i32) -> bool {
    status & 0xff == 0x7f
}

/// The Linux wait status of a continue.
const CONTINUED: i32 = 0xffff;

/// A stop (`stopped`) or continue (`continued`) of an adopted process
/// that `sel` matches, not yet reported: taken, unless `peek`.
pub fn take_change(sel: Select, peek: bool, stopped: bool, continued: bool) -> Option<Ended> {
    if !active() {
        return None;
    }
    let mut c = CHANGES.lock().unwrap_or_else(|e| e.into_inner());
    let i = c.iter().position(|e| {
        sel.matches(e.pid, e.pgid)
            && (stopped && is_stop(e.status) || continued && e.status == CONTINUED)
    })?;
    Some(if peek { c[i].clone() } else { c.remove(i) })
}

/// Adopted process `pid` stopped (by Linux signal `sig`) or continued
/// (`None`): kept for `wait`, and told with `SIGCHLD` unless the guest
/// asked not to be (`SA_NOCLDSTOP`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn changed(pid: i32, r: &procreg::ProcRecord, sig: Option<i32>) {
    // SAFETY: plain host call.
    let pgid = unsafe { libc::getpgid(pid) };
    let e = Ended {
        pid,
        start: r.start,
        status: sig.map_or(CONTINUED, |s| (s << 8) | 0x7f),
        pgid,
        lineage: r.lineage.clone(),
        bound: r.bound,
        numbers: procreg::numbers_in(&r.ns, pid),
        foster: r.foster,
    };
    {
        let mut c = CHANGES.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|o| o.pid != pid);
        c.push(e.clone());
    }
    let sig = fwe_abi::signal::SIGCHLD;
    if !crate::host::signal_is_ignored(sig) && sigchld_taken() && !crate::host::sigchld_nocldstop()
    {
        raise(&e);
    }
}

/// The pid ended process `e` has in the caller's pid namespace.
pub fn guest_pid(e: &Ended) -> i32 {
    match crate::pidns::current().first() {
        None => e.pid,
        Some(ns) => e.number_in(ns.dir()).unwrap_or(0),
    }
}

/// A Linux wait status as the `si_code` and `si_status` of a `SIGCHLD`.
pub fn child_code(status: i32) -> (i32, i32) {
    use fwe_abi::wait::{CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED};
    if status == CONTINUED {
        return (CLD_CONTINUED, fwe_abi::signal::SIGCONT as i32);
    }
    if is_stop(status) {
        return (CLD_STOPPED, (status >> 8) & 0xff);
    }
    match status & 0x7f {
        0 => (CLD_EXITED, (status >> 8) & 0xff),
        sig if status & 0x80 != 0 => (CLD_DUMPED, sig),
        sig => (CLD_KILLED, sig),
    }
}

/// Whether this process's watcher runs: it is a reaper.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Whether this process is a reaper whose watcher runs.
pub fn active() -> bool {
    RUNNING.load(SeqCst)
}

/// The adopted processes whose end the watcher has raised `SIGCHLD` for.
static NOTIFIED: Mutex<Option<HashSet<(i32, u64)>>> = Mutex::new(None);

/// Host threads waiting in `wait`, which the watcher wakes.
static WAITERS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Held by the watcher while it acts on what it saw, and by a `wait` while
/// it looks at the records: a host `fork` takes it ([`hold`]), so neither
/// holds any of the locks it uses then (a shared record's, say), which a
/// child would inherit held by a thread it does not have.
static BUSY: Mutex<()> = Mutex::new(());

/// Run `f` (a host `fork`) with the reaper's locks held, released in both
/// processes (see [`crate::fork_locked`]).
pub fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _busy = BUSY.lock().unwrap_or_else(|e| e.into_inner());
    let _waiters = WAITERS.lock().unwrap_or_else(|e| e.into_inner());
    let _notified = NOTIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let _changes = CHANGES.lock().unwrap_or_else(|e| e.into_inner());
    let _inits = INITS.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Run `f`, which looks at or changes the records of processes, where a
/// host `fork` does not run meanwhile.
pub fn busy<R>(f: impl FnOnce() -> R) -> R {
    let _busy = BUSY.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// In a process that just forked: the watcher is the parent's (its thread
/// is not here), and so are its waiters.
pub fn forked_child() {
    RUNNING.store(false, SeqCst);
    // The parent's foster children are not this process's.
    FOSTERING.store(false, SeqCst);
    // The parent's children are not this process's.
    for (pid, _) in &EXIT_SIGNALS {
        pid.store(0, SeqCst);
    }
    WAITERS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    *NOTIFIED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    CHANGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // The parent's inits are not this process's children, and its kqueue
    // is not inherited.
    *INITS.lock().unwrap_or_else(|e| e.into_inner()) = Inits::default();
}

/// This process's children that are the inits of their pid namespaces,
/// with those namespaces' records, and the `kqueue` a thread waits on for
/// their ends.
#[derive(Default)]
struct Inits {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    kq: Option<i32>,
    children: std::collections::BTreeMap<i32, Vec<u8>>,
}

static INITS: Mutex<Inits> =
    Mutex::new(Inits { kq: None, children: std::collections::BTreeMap::new() });

/// Child `child` is the init of the pid namespace whose record is `ns`:
/// when it ends, however it ends, the namespace ends with it at once, as
/// on Linux (not only once this process reaps it).
pub fn init_child(child: i32, ns: Vec<u8>) {
    #[cfg(target_os = "macos")]
    {
        let mut inits = INITS.lock().unwrap_or_else(|e| e.into_inner());
        let kq = match inits.kq {
            Some(kq) => kq,
            None => {
                // SAFETY: plain host call.
                let Ok(kq) = crate::fdtable::reserve(unsafe { libc::kqueue() }) else { return };
                let spawned = std::thread::Builder::new()
                    .name("fwe-pidns".into())
                    .spawn(move || watch::inits(kq))
                    .is_ok();
                if !spawned {
                    // SAFETY: closing the kqueue just made.
                    unsafe { libc::close(kq) };
                    return;
                }
                inits.kq = Some(kq);
                kq
            }
        };
        let ev = libc::kevent {
            ident: child as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        inits.children.insert(child, ns.clone());
        // SAFETY: registering one change on our kqueue.
        let r = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if r < 0 {
            // Gone already.
            inits.children.remove(&child);
            drop(inits);
            ended_init(child, &ns);
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (child, ns);
}

/// Init `init` of the pid namespace whose record is `ns` has ended: every
/// other process in it is killed.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn ended_init(init: i32, ns: &[u8]) {
    busy(|| {
        if let Ok(r) = crate::shared::Record::<crate::pidns::PidNs>::join(ns, 0) {
            crate::pidns::zap(&r, init);
        }
    });
}

/// Whether a `wait` that must not block (`WNOHANG`) for child `child`
/// alone is to report nothing yet: it is a pid namespace's init that has
/// ended while the rest of its namespace has not (Linux reaps an init only
/// once its namespace is empty).
pub fn init_unreapable(child: i32) -> bool {
    let ns = INITS.lock().unwrap_or_else(|e| e.into_inner()).children.get(&child).cloned();
    let Some(ns) = ns else { return false };
    let ended = procreg::host_info(child).is_none_or(|(_, _, zombie)| zombie);
    busy(|| {
        ended
            && crate::shared::Record::<crate::pidns::PidNs>::join(&ns, 0)
                .is_ok_and(|r| crate::pidns::members_alive(&r, child))
    })
}

/// This process reaped child `child`: if it was a pid namespace's init,
/// its `wait` reports that only once the rest of the namespace has gone,
/// as on Linux, where an init is not reaped before its namespace is
/// empty.
pub fn reaped_child(child: i32) {
    let ns = INITS.lock().unwrap_or_else(|e| e.into_inner()).children.remove(&child);
    let Some(ns) = ns else { return };
    let Ok(r) = busy(|| crate::shared::Record::<crate::pidns::PidNs>::join(&ns, 0)) else {
        return;
    };
    busy(|| crate::pidns::zap(&r, child));
    // A process killed is gone in a moment; one that the host cannot end
    // is not waited for long.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while busy(|| crate::pidns::members_alive(&r, child)) && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Whether this process is a reaper: a subreaper, or its pid namespace's
/// init.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_reaper() -> bool {
    let init =
        crate::pidns::current().first().is_some_and(|ns| ns.get().number_of(me()) == Some(1));
    init || fostering() || procreg::own_subreaper()
}

/// Start the watcher if this process is a reaper and it has none yet.
/// Called as a process starts and whenever it may have become one.
/// The watcher follows processes with `kqueue`, which Linux hosts lack:
/// there fwe runs only the kernel's unit tests.
pub fn start_if_reaper() {
    #[cfg(target_os = "macos")]
    if !active() && is_reaper() && !RUNNING.swap(true, SeqCst) {
        // Made here, where the caller holds the kernel lock, so no guest
        // thread takes its number before it is moved out of their range.
        // SAFETY: plain host call.
        let kq = unsafe { libc::kqueue() };
        let started = crate::fdtable::reserve(kq).ok().is_some_and(|kq| {
            std::thread::Builder::new()
                .name("fwe-reaper".into())
                .spawn(move || watch::run(kq))
                .is_ok()
        });
        if !started {
            RUNNING.store(false, SeqCst);
        }
    }
}

/// A thread's wait in `wait4` or `waitid` while this process is a reaper:
/// registered for the watcher to wake, with every signal blocked while it
/// checks for a child to report, so none is missed before [`Waiter::sleep`].
pub struct Waiter {
    old: libc::sigset_t,
    me: usize,
}

impl Waiter {
    pub fn new() -> Waiter {
        // SAFETY: pthread_self cannot fail.
        let me = unsafe { libc::pthread_self() } as usize;
        WAITERS.lock().unwrap_or_else(|e| e.into_inner()).push(me);
        let mut all = crate::host::host_sigset(u64::MAX);
        let mut old = crate::host::empty_sigset();
        // SAFETY: plain host calls on valid signal sets.
        unsafe {
            libc::sigaddset(&mut all, crate::host::WAKE_SIGNAL);
            libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        }
        Waiter { old, me }
    }

    /// Wait until a signal arrives: the watcher's wake, or one for the
    /// guest.
    pub fn sleep(&self) {
        let wait = crate::host::host_mask_for(crate::thread::mask());
        // SAFETY: a valid signal set; returns after a host handler ran.
        unsafe { libc::sigsuspend(&wait) };
    }
}

impl Default for Waiter {
    fn default() -> Self {
        Waiter::new()
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // SAFETY: restoring the mask saved in `new`.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
        let mut w = WAITERS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = w.iter().position(|&t| t == self.me) {
            w.swap_remove(i);
        }
    }
}

/// Wake every thread waiting in `wait`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn wake_waiters() {
    let w = WAITERS.lock().unwrap_or_else(|e| e.into_inner());
    for &t in w.iter() {
        // SAFETY: a registered thread is live until it unregisters, which
        // needs this lock.
        unsafe { libc::pthread_kill(t as libc::pthread_t, crate::host::WAKE_SIGNAL) };
    }
}

/// The last adopted process the reaper reported, and its former parent
/// (host pids), for [`precedes`].
static REPORTED: AtomicI32 = AtomicI32::new(0);
static REPORTED_PARENT: AtomicI32 = AtomicI32::new(0);

/// Raise `SIGCHLD` for each adopted process that ended and was not yet
/// told of, as Linux does for a child (or a zombie) it hands a reaper
/// ([`raise`]). If the host reaps this process's children itself
/// (`SIGCHLD` ignored, or `SA_NOCLDWAIT`), they are reaped instead.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn notify() {
    let fresh: Vec<Ended> = {
        let mut n = NOTIFIED.lock().unwrap_or_else(|e| e.into_inner());
        let n = n.get_or_insert_with(HashSet::new);
        let ended: Vec<Ended> = procreg::all_ended().into_iter().filter(adopted_ended).collect();
        // Forget those reaped meanwhile.
        n.retain(|k| ended.iter().any(|e| (e.pid, e.start) == *k));
        ended.into_iter().filter(|e| n.insert((e.pid, e.start))).collect()
    };
    let sig = fwe_abi::signal::SIGCHLD;
    for e in fresh {
        crate::trace::note_to_file(&format!("reaper: {} ended, adopted", e.pid));
        if crate::host::children_reaped_by_host() && procreg::take_ended(&e) {
            crate::pidns::released(&e.numbers, e.pid);
        }
        // A SIGCHLD ignored is not sent at all (and one left at its
        // default would be dropped): only one the guest takes.
        if !crate::host::signal_is_ignored(sig) && sigchld_taken() {
            raise(&e);
        }
    }
}

/// Whether the guest takes `SIGCHLD`: a handler, or a signalfd.
fn sigchld_taken() -> bool {
    let bit = 1u64 << (fwe_abi::signal::SIGCHLD - 1);
    (crate::signal::caught() | crate::signalfd::watched()) & bit != 0
}

/// Whether the `SIGCHLD` of host process `pid` comes before one of host
/// process `pending`'s still pending: `pid` is an adopted process the
/// reaper reported, and `pending` the parent it was orphaned by, whose
/// end Linux reports after the orphan's (it hands its children on as it
/// ends). Async-signal-safe.
pub fn precedes(pid: i32, pending: i32) -> bool {
    pid != 0 && REPORTED.load(SeqCst) == pid && REPORTED_PARENT.load(SeqCst) == pending
}

/// Whether a `SIGCHLD` of host process `pid` is one Linux would not send
/// now: `pid` ended leaving an orphan the reaper has reported already, and
/// Linux sends a parent's `SIGCHLD` after its orphans' as it ends, so one
/// still pending absorbs it (a standard signal is not queued twice). Taken
/// once. Async-signal-safe.
pub fn superseded(pid: i32) -> bool {
    pid != 0
        && REPORTED.load(SeqCst) != 0
        && REPORTED_PARENT.compare_exchange(pid, 0, SeqCst, SeqCst).is_ok()
}

/// Raise the `SIGCHLD` for adopted process `e`'s end: pending for the
/// guest with the `siginfo` Linux gives a child's end, and a guest thread
/// woken to take it. It is not sent through the host: a `SIGCHLD` the host
/// holds or is delivering would absorb it (standard signals are not queued
/// twice), and the guest would hear of the orphan from neither.
fn raise(e: &Ended) {
    crate::trace::note_to_file(&format!("reaper: SIGCHLD for {} ({:#x})", e.pid, e.status));
    // An end is what Linux reports before the former parent's own.
    if !is_stop(e.status) && e.status != CONTINUED {
        REPORTED_PARENT.store(e.lineage.first().map_or(0, |p| p.0), SeqCst);
        REPORTED.store(e.pid, SeqCst);
    }
    let (code, status) = child_code(e.status);
    // SAFETY: getuid cannot fail.
    let uid = crate::host::uid_to_initial(unsafe { libc::getuid() });
    let info = crate::thread::SigInfo { code, pid: e.pid, uid, status, value: 0, poll: None };
    crate::thread::post_process(fwe_abi::signal::SIGCHLD, info);
    // One thread is woken to take it, as the host picks one for a signal
    // sent to the process: the wake carries nothing, so a wake the host
    // holds or merges loses nothing.
    // SAFETY: plain host call, to this process.
    unsafe { libc::kill(me(), crate::host::WAKE_SIGNAL) };
}

/// Host process `pid`'s children.
#[cfg(target_os = "macos")]
pub fn children(pid: i32) -> Vec<i32> {
    let mut buf = vec![0i32; 256];
    loop {
        let bytes = (buf.len() * std::mem::size_of::<i32>()) as libc::c_int;
        // SAFETY: a valid out-buffer of `bytes` bytes.
        let n = unsafe { libc::proc_listchildpids(pid, buf.as_mut_ptr().cast(), bytes) };
        if n < 0 {
            return Vec::new();
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            buf.retain(|&p| p > 0);
            return buf;
        }
        buf.resize(buf.len() * 2, 0);
    }
}

#[cfg(target_os = "macos")]
mod watch {
    use super::*;

    fn change(pid: i32, filter: i16, flags: u16, fflags: u32) -> libc::kevent {
        libc::kevent {
            ident: pid as usize,
            filter,
            flags,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        }
    }

    /// How long a signal sent to a followed process is given to stop or
    /// continue it, and how long it is looked for often.
    const SIGNAL_SETTLES: std::time::Duration = std::time::Duration::from_secs(5);
    const SIGNAL_SOON: std::time::Duration = std::time::Duration::from_millis(50);

    struct Watcher {
        kq: i32,
        watched: HashSet<i32>,
        /// Whether each followed process is stopped, as last seen: from
        /// when it is first followed, so a continue is seen as one even
        /// for a process stopped before it was adopted.
        stopped: std::collections::HashMap<i32, bool>,
    }

    impl Watcher {
        /// Follow `pid`, its children and theirs: its end, its forks, and
        /// the signals it is sent (which may stop or continue it).
        /// Returns whether one had already gone.
        fn follow(&mut self, pid: i32) -> bool {
            let mut gone = false;
            let mut todo = vec![pid];
            while let Some(p) = todo.pop() {
                if !self.watched.insert(p) {
                    continue;
                }
                crate::trace::note_to_file(&format!("reaper: follows {p}"));
                let ev = change(
                    p,
                    libc::EVFILT_PROC,
                    libc::EV_ADD | libc::EV_CLEAR,
                    libc::NOTE_EXIT | libc::NOTE_FORK | libc::NOTE_SIGNAL,
                );
                // SAFETY: registering one change on our kqueue.
                let r = unsafe {
                    libc::kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null())
                };
                if r < 0 {
                    // Gone before it could be followed.
                    self.watched.remove(&p);
                    procreg::gone(p);
                    gone = true;
                    continue;
                }
                self.stopped.insert(p, procreg::stopped_by(p).is_some());
                // Registered first, so a child it makes from now on is
                // reported by its fork.
                todo.extend(children(p));
            }
            gone
        }

        /// Follow every process whose record has `me` among its ancestors
        /// and that is not followed yet: one adopted before this watcher
        /// started (a reaper that started again with `execve`), or one
        /// whose parent ended before its fork was seen, so it was no
        /// longer that parent's child on the host.
        fn follow_recorded(&mut self, me: i32) {
            for (pid, r) in procreg::all() {
                if !self.watched.contains(&pid) && r.lineage.iter().any(|&(p, _)| p == me) {
                    self.follow(pid);
                }
            }
        }
    }

    /// The thread that waits for this process's children that are pid
    /// namespaces' inits to end ([`init_child`]).
    pub(super) fn inits(kq: i32) {
        // SAFETY: plain host calls on a valid signal set.
        unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
        }
        // SAFETY: a zeroed kevent is a valid out-parameter.
        let mut evs: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: valid out-buffer; blocks until an init ends.
            let n = unsafe {
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    evs.as_mut_ptr(),
                    evs.len() as i32,
                    std::ptr::null(),
                )
            };
            if n < 0 {
                if crate::host::last_errno() == libc::EINTR {
                    continue;
                }
                return;
            }
            for ev in &evs[..n as usize] {
                let pid = ev.ident as i32;
                let ns =
                    INITS.lock().unwrap_or_else(|e| e.into_inner()).children.get(&pid).cloned();
                if let Some(ns) = ns {
                    ended_init(pid, &ns);
                    if crate::host::children_reaped_by_host() {
                        // Reaped by the host: no `wait` will take it.
                        INITS.lock().unwrap_or_else(|e| e.into_inner()).children.remove(&pid);
                    }
                }
            }
        }
    }

    pub(super) fn run(kq: i32) {
        // Signals are for the guest's threads, never this one.
        // SAFETY: plain host calls on a valid signal set.
        unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
        }
        let me = me();
        let mut w = Watcher { kq, watched: HashSet::new(), stopped: Default::default() };
        // This process's forks, and the host's SIGCHLD (a child of its own
        // that ended, stopped or continued).
        let own = [
            change(me, libc::EVFILT_PROC, libc::EV_ADD | libc::EV_CLEAR, libc::NOTE_FORK),
            change(libc::SIGCHLD, libc::EVFILT_SIGNAL, libc::EV_ADD | libc::EV_CLEAR, 0),
        ];
        // SAFETY: registering changes on our kqueue.
        unsafe { libc::kevent(kq, own.as_ptr(), 2, std::ptr::null_mut(), 0, std::ptr::null()) };
        w.watched.insert(me);
        busy(|| {
            for c in children(me) {
                w.follow(c);
            }
            w.follow_recorded(me);
            notify();
            wake_waiters();
        });
        // SAFETY: a zeroed kevent is a valid out-parameter.
        let mut evs: [libc::kevent; 32] = unsafe { std::mem::zeroed() };
        // Processes whose end was reported while they were still on their
        // way out (not yet zombies): looked at again until they are, since
        // nothing else will be reported for them.
        let mut ending: HashSet<(i32, Option<u64>)> = HashSet::new();
        // Followed processes sent a signal, looked at until it has stopped
        // or continued them or [`SIGNAL_SETTLES`] has passed. The host
        // tells of a signal sent, not of the stop it makes, which takes
        // effect as the process gets to it: on a busy host, long after.
        let mut signalled: std::collections::HashMap<i32, std::time::Instant> = Default::default();
        let soon = libc::timespec { tv_sec: 0, tv_nsec: 5_000_000 };
        let later = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
        loop {
            let idle = ending.is_empty() && signalled.is_empty();
            // Often at first, where a stop usually is; less so after.
            let fresh =
                !ending.is_empty() || signalled.values().any(|sent| sent.elapsed() < SIGNAL_SOON);
            let timeout = if idle {
                std::ptr::null()
            } else if fresh {
                &soon as *const _
            } else {
                &later as *const _
            };
            // SAFETY: valid out-buffer; blocks until something happens (or
            // briefly, while an end is under way).
            let n = unsafe {
                libc::kevent(kq, std::ptr::null(), 0, evs.as_mut_ptr(), evs.len() as i32, timeout)
            };
            if n < 0 {
                if crate::host::last_errno() == libc::EINTR {
                    continue;
                }
                RUNNING.store(false, SeqCst);
                return;
            }
            busy(|| {
                for ev in &evs[..n as usize] {
                    if ev.filter != libc::EVFILT_PROC {
                        continue;
                    }
                    let pid = ev.ident as i32;
                    if ev.fflags & libc::NOTE_FORK != 0 {
                        for c in children(pid) {
                            w.follow(c);
                        }
                    }
                    if ev.fflags & libc::NOTE_EXIT != 0 && pid != me {
                        crate::trace::note_to_file(&format!("reaper: {pid} exits"));
                        w.watched.remove(&pid);
                        ending.insert((pid, procreg::start_time(pid)));
                        signalled.remove(&pid);
                        w.stopped.remove(&pid);
                        CHANGES.lock().unwrap_or_else(|e| e.into_inner()).retain(|e| e.pid != pid);
                    } else if ev.fflags & libc::NOTE_SIGNAL != 0 && pid != me {
                        signalled.insert(pid, std::time::Instant::now());
                    }
                }
                // Those of them that stopped or continued.
                signalled.retain(|&pid, sent| {
                    let sig = procreg::stopped_by(pid);
                    let was = w.stopped.get(&pid).copied().unwrap_or(false);
                    if sig.is_some() != was {
                        w.stopped.insert(pid, sig.is_some());
                        // Reported if it is an adopted one; a child of a
                        // living parent is that parent's to hear of.
                        if let Some(r) = procreg::read(pid).filter(|r| adopted_live(pid, r)) {
                            changed(pid, &r, sig.map(|s| crate::host::signal_to_linux(s) as i32));
                        }
                        return false;
                    }
                    sent.elapsed() < SIGNAL_SETTLES
                });
                // Those that have ended by now: a zombie, or gone.
                ending.retain(|&(pid, start)| {
                    // (A pid given to another process since is done too.)
                    let done = procreg::host_info(pid)
                        .is_none_or(|(now, _, zombie)| zombie || Some(now) != start);
                    if done {
                        // Its record is gone unless it was killed outright.
                        procreg::gone(pid);
                    }
                    !done
                });
                w.follow_recorded(me);
                notify();
                wake_waiters();
            });
        }
    }
}

/// The children of this process whose end Linux signals with another
/// signal than `SIGCHLD` (`clone`'s exit signal; 0 for none), as (host
/// pid, signal): the host's `SIGCHLD` for one's end stands for it
/// ([`exit_signal`]). Read in signal handlers, so kept without a lock.
static EXIT_SIGNALS: [(std::sync::atomic::AtomicI32, std::sync::atomic::AtomicU64); 64] =
    [const { (std::sync::atomic::AtomicI32::new(0), std::sync::atomic::AtomicU64::new(0)) }; 64];

/// Child `child` (host pid) was made with exit signal `sig`.
pub fn set_exit_signal(child: i32, sig: u64) {
    use std::sync::atomic::Ordering::SeqCst;
    if sig == fwe_abi::signal::SIGCHLD || exit_signal(child).is_some() {
        return;
    }
    for (pid, s) in &EXIT_SIGNALS {
        if pid.compare_exchange(0, -1, SeqCst, SeqCst).is_ok() {
            s.store(sig, SeqCst);
            pid.store(child, SeqCst);
            return;
        }
    }
}

/// The signal child `child`'s end is told with, if not `SIGCHLD` (0: none).
/// Async-signal-safe.
pub fn exit_signal(child: i32) -> Option<u64> {
    use std::sync::atomic::Ordering::SeqCst;
    if child <= 0 {
        return None;
    }
    EXIT_SIGNALS.iter().find(|(pid, _)| pid.load(SeqCst) == child).map(|(_, s)| s.load(SeqCst))
}

/// Child `child` was reaped: its exit signal goes.
pub fn forget_exit_signal(child: i32) {
    use std::sync::atomic::Ordering::SeqCst;
    for (pid, _) in &EXIT_SIGNALS {
        let _ = pid.compare_exchange(child, 0, SeqCst, SeqCst);
    }
}

/// A child's `SIGCHLD`, which Linux sends before `wait` can report the
/// child, may come from the host after `wait` returned (macOS wakes the
/// waiter first), and interrupt the guest's next call. So a `wait` that
/// reaps a child whose `SIGCHLD` has not landed yet gives it then
/// ([`reaped_child_signal`]), and the host's, when it comes, is dropped
/// ([`child_signal_landed`]). The pids are kept in two small rings, without
/// a lock: the host's signal lands in a handler.
static GIVEN: [AtomicI32; 64] = [const { AtomicI32::new(0) }; 64];
static LANDED: [AtomicI32; 64] = [const { AtomicI32::new(0) }; 64];
static GIVEN_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static LANDED_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn ring_take(ring: &[AtomicI32; 64], pid: i32) -> bool {
    ring.iter().any(|s| s.compare_exchange(pid, 0, SeqCst, SeqCst).is_ok())
}

fn ring_put(ring: &[AtomicI32; 64], at: &std::sync::atomic::AtomicUsize, pid: i32) {
    ring[at.fetch_add(1, SeqCst) % ring.len()].store(pid, SeqCst);
}

/// The host's `SIGCHLD` for child `pid`'s end landed: whether it is to be
/// dropped, its `wait` having given it already. Async-signal-safe.
pub fn child_signal_landed(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if ring_take(&GIVEN, pid) {
        return true;
    }
    ring_put(&LANDED, &LANDED_AT, pid);
    false
}

/// A `wait` reaped child `pid`, which ended so (`info`): its `SIGCHLD`
/// given now unless it has landed, for the guest to take as `wait`
/// returns.
pub fn reaped_child_signal(pid: i32, info: crate::thread::SigInfo) {
    // Its own exit signal, if not SIGCHLD (none: nothing to give).
    let sig = match exit_signal(pid) {
        Some(0) => return,
        Some(s) => s,
        None => fwe_abi::signal::SIGCHLD,
    };
    let bit = 1 << (sig - 1);
    let taken = (crate::signal::caught() | crate::signalfd::watched()) & bit != 0;
    if pid <= 0 {
        return;
    }
    if !taken {
        // Neither caught nor watched: Linux discarded it as the child
        // ended unless the thread blocked it then, so the host's landing
        // later (once the guest may block it) is dropped, unless blocked
        // now, when it stays pending as Linux's would.
        if crate::thread::mask() & bit == 0 {
            ring_put(&GIVEN, &GIVEN_AT, pid);
            if ring_take(&LANDED, pid) {
                ring_take(&GIVEN, pid);
            }
        }
        return;
    }
    // Marked given first: the host's landing from now on is dropped.
    ring_put(&GIVEN, &GIVEN_AT, pid);
    if ring_take(&LANDED, pid) {
        // It had landed: nothing owed.
        ring_take(&GIVEN, pid);
        return;
    }
    crate::thread::post_process(sig, info);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_stop_at_the_bound() {
        let line = [(10, 1), (20, 2), (30, 3), (40, 4)];
        let all: Vec<Proc> = candidates(&line, None).collect();
        assert_eq!(all, [(20, 2), (30, 3), (40, 4)]);
        let bounded: Vec<Proc> = candidates(&line, Some((30, 3))).collect();
        assert_eq!(bounded, [(20, 2), (30, 3)]);
        // A parent that is the bound (a namespace's init) leaves no one.
        assert_eq!(candidates(&line, Some((10, 1))).count(), 0);
    }

    #[test]
    fn wait_status_as_child_code() {
        use fwe_abi::wait::{CLD_DUMPED, CLD_EXITED, CLD_KILLED};
        assert_eq!(child_code(7 << 8), (CLD_EXITED, 7));
        assert_eq!(child_code(9), (CLD_KILLED, 9));
        assert_eq!(child_code(11 | 0x80), (CLD_DUMPED, 11));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lists_children() {
        let mut child = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let found = children(me()).contains(&(child.id() as i32));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(found);
    }
}
