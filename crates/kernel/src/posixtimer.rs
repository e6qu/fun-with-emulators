//! POSIX interval timers (`timer_create`, `timer_settime`,
//! `timer_gettime`, `timer_getoverrun`, `timer_delete`), a process's own.
//!
//! A thread of fwe's sleeps until the next timer is due on its clock and
//! raises the timer's signal (`SI_TIMER`, with the timer's id and value)
//! for the process, or for one thread (`SIGEV_THREAD_ID`); a
//! `SIGEV_NONE` timer only keeps time. As Linux's, a periodic timer is
//! set going again when its signal is taken, not before: the intervals
//! that passed meanwhile are its overrun (`si_overrun`,
//! `timer_getoverrun`, at most `INT_MAX`), so a timer of tiny intervals
//! whose signal waits costs nothing. A timer of CPU time (the process's or
//! a thread's) is looked at again when as much time has passed as it had
//! left, at most every 10 ms. A fork child has none of its parent's
//! timers, and `execve` deletes them.
//!
//! What a taken signal needs ([`delivered`]) is kept in atomics: a signal
//! may be taken in a host signal handler.

use crate::uaccess;
use fwe_abi::{err, errno};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

/// Timers a process may have.
const MAX: usize = 1024;
const NS: u64 = 1_000_000_000;

/// A timer's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Clock {
    /// A host clock.
    Host(libc::clockid_t),
    /// A host thread's CPU time.
    Thread(libc::pthread_t),
    /// Another process's CPU time: Linux's clock id for it.
    Cpu(u64),
}

impl Clock {
    /// Encoded in a word, for [`Slot::clock`].
    #[allow(clippy::unnecessary_cast)] // `pthread_t` is a pointer on macOS
    fn encode(self) -> u64 {
        match self {
            Clock::Host(id) => id as u64,
            Clock::Thread(t) => 1 << 62 | t as usize as u64 & ((1 << 62) - 1),
            Clock::Cpu(id) => 2 << 62 | id & 0xffff_ffff,
        }
    }

    #[allow(clippy::unnecessary_cast)] // `pthread_t` is a pointer on macOS
    fn decode(w: u64) -> Clock {
        match w >> 62 {
            0 => Clock::Host(w as libc::clockid_t),
            1 => Clock::Thread((w & ((1 << 62) - 1)) as usize as libc::pthread_t),
            _ => Clock::Cpu(w & 0xffff_ffff | 0xffff_ffff_0000_0000),
        }
    }

    /// Now, in nanoseconds.
    fn now(self) -> Option<u64> {
        match self {
            Clock::Host(id) => {
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                // SAFETY: a valid out-parameter.
                (unsafe { libc::clock_gettime(id, &mut ts) } == 0)
                    .then(|| ts.tv_sec.max(0) as u64 * NS + ts.tv_nsec as u64)
            }
            Clock::Thread(t) => crate::host::thread_cpu_ns(t).map(|(u, s)| u + s),
            Clock::Cpu(id) => crate::syscalls::cpu_clock_ns(id)?.ok(),
        }
    }

    fn is_cpu(self) -> bool {
        !matches!(self, Clock::Host(id) if id != libc::CLOCK_PROCESS_CPUTIME_ID)
    }
}

/// What a taken signal needs of a timer.
struct Slot {
    used: AtomicBool,
    clock: AtomicU64,
    /// When it is next due, on its clock (0: disarmed), and its interval.
    due: AtomicU64,
    interval: AtomicU64,
    /// Its signal is raised and not yet taken.
    pending: AtomicBool,
    /// The overrun of the last signal taken.
    last: AtomicI32,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            used: AtomicBool::new(false),
            clock: AtomicU64::new(0),
            due: AtomicU64::new(0),
            interval: AtomicU64::new(0),
            pending: AtomicBool::new(false),
            last: AtomicI32::new(0),
        }
    }
}

static SLOTS: [Slot; MAX] = [const { Slot::new() }; MAX];

/// How a timer tells of its expiry.
#[derive(Clone, Copy, Debug)]
struct Notify {
    /// `SIGEV_SIGNAL`, `SIGEV_NONE` or `SIGEV_THREAD_ID` (`SIGEV_THREAD`
    /// is a signal to the process, which the C library acts on).
    how: i32,
    signo: u64,
    value: u64,
    tid: i32,
}

/// Each timer's notification, by id.
static NOTIFY: Mutex<Vec<Option<Notify>>> = Mutex::new(Vec::new());

/// The timer thread's wake pipe (read, write; -1: no thread yet).
static WAKE_R: AtomicI32 = AtomicI32::new(-1);
static WAKE_W: AtomicI32 = AtomicI32::new(-1);

fn notify() -> std::sync::MutexGuard<'static, Vec<Option<Notify>>> {
    NOTIFY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wake the timer thread to look again. Async-signal-safe.
fn wake() {
    let w = WAKE_W.load(Ordering::Acquire);
    if w >= 0 {
        // SAFETY: a byte from a valid buffer to fwe's pipe; a full pipe
        // already wakes the thread.
        unsafe { libc::write(w, [1u8].as_ptr().cast(), 1) };
    }
}

/// The timer thread, started with the first timer.
fn start_thread() {
    if WAKE_R.load(Ordering::Acquire) >= 0 {
        return;
    }
    let mut p = [-1i32; 2];
    // SAFETY: a valid out-array.
    if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
        return;
    }
    let (Ok(r), Ok(w)) = (crate::fdtable::reserve(p[0]), crate::fdtable::reserve(p[1])) else {
        return;
    };
    // SAFETY: fwe's own pipe, made non-blocking.
    unsafe {
        libc::fcntl(r, libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(w, libc::F_SETFL, libc::O_NONBLOCK);
    }
    WAKE_R.store(r, Ordering::Release);
    WAKE_W.store(w, Ordering::Release);
    let _ = std::thread::Builder::new().name("fwe-timers".into()).spawn(move || run(r));
}

/// The timer thread: raise what is due, then sleep until the next one.
fn run(r: i32) {
    // Host signals are the guest threads' to take.
    // SAFETY: a full set, applied to this thread only.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
    loop {
        if WAKE_R.load(Ordering::Acquire) != r {
            return;
        }
        let wait = tick();
        match wait {
            // Soon: sleep it out (the pipe's wait counts milliseconds).
            Some(ns) if ns < 2_000_000 => {
                let ts = libc::timespec { tv_sec: 0, tv_nsec: ns as libc::c_long };
                // SAFETY: a valid request; no remainder wanted.
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            }
            _ => {
                let ms = wait.map_or(-1, |ns| (ns / 1_000_000).min(i32::MAX as u64) as i32);
                let mut p = libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 };
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(&mut p, 1, ms) };
                let mut buf = [0u8; 64];
                // SAFETY: draining fwe's own non-blocking pipe into a buffer.
                while unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
            }
        }
    }
}

/// Raise the signals of the timers that are due: how long until the next
/// one may be, if any is armed.
fn tick() -> Option<u64> {
    let notes = notify().clone();
    let mut wait: Option<u64> = None;
    for (id, n) in notes.iter().enumerate() {
        let Some(n) = n else { continue };
        let s = &SLOTS[id];
        let due = s.due.load(Ordering::Acquire);
        if !s.used.load(Ordering::Acquire)
            || due == 0
            || n.how == fwe_abi::mqueue::SIGEV_NONE
            || s.pending.load(Ordering::Acquire)
        {
            continue;
        }
        let clock = Clock::decode(s.clock.load(Ordering::Acquire));
        let Some(now) = clock.now() else { continue };
        if now < due {
            let left = due - now;
            let left = if clock.is_cpu() { left.min(10_000_000) } else { left };
            wait = Some(wait.map_or(left, |w| w.min(left)));
            continue;
        }
        // Due: a one-shot timer is spent; a periodic one waits for its
        // signal to be taken ([`delivered`]).
        s.pending.store(true, Ordering::Release);
        if s.interval.load(Ordering::Acquire) == 0 {
            s.due.store(0, Ordering::Release);
        }
        raise(id, n);
    }
    wait
}

/// Raise timer `id`'s signal, as `n` says.
fn raise(id: usize, n: &Notify) {
    let info = crate::thread::SigInfo {
        code: fwe_abi::signal::SI_TIMER,
        pid: id as i32,
        uid: 0,
        status: 0,
        value: n.value,
        poll: None,
    };
    if n.how == fwe_abi::mqueue::SIGEV_THREAD_ID {
        if let Some(host) = crate::thread::post_thread(n.tid, n.signo, info)
            && host != 0 as libc::pthread_t
        {
            // SAFETY: a registered thread of this process.
            unsafe { libc::pthread_kill(host, crate::host::WAKE_SIGNAL) };
        }
    } else {
        crate::thread::post_process(n.signo, info);
        crate::thread::wake_others(crate::host::WAKE_SIGNAL);
    }
}

/// Timer `id`'s signal was taken: its overrun, the intervals that passed
/// since it was due, and a periodic timer is due again after them.
/// Async-signal-safe.
pub fn delivered(id: i32) -> u32 {
    let Some(s) = usize::try_from(id).ok().and_then(|i| SLOTS.get(i)) else { return 0 };
    if !s.used.load(Ordering::Acquire) || !s.pending.swap(false, Ordering::AcqRel) {
        return s.last.load(Ordering::Acquire).max(0) as u32;
    }
    let (due, interval) = (s.due.load(Ordering::Acquire), s.interval.load(Ordering::Acquire));
    let mut overrun = 0u64;
    if interval > 0 && due != 0 {
        let now = Clock::decode(s.clock.load(Ordering::Acquire)).now().unwrap_or(due);
        let missed = now.saturating_sub(due) / interval;
        overrun = missed;
        let next = due.saturating_add(missed.saturating_add(1).saturating_mul(interval));
        s.due.store(next.max(1), Ordering::Release);
    }
    let overrun = overrun.min(i32::MAX as u64) as i32;
    s.last.store(overrun, Ordering::Release);
    wake();
    overrun as u32
}

/// In a fork child: none of the parent's timers, and no timer thread.
pub fn forked_child() {
    for s in &SLOTS {
        s.used.store(false, Ordering::Release);
        s.due.store(0, Ordering::Release);
        s.pending.store(false, Ordering::Release);
    }
    notify().clear();
    for fd in [WAKE_R.swap(-1, Ordering::AcqRel), WAKE_W.swap(-1, Ordering::AcqRel)] {
        if fd >= 0 {
            // SAFETY: fwe's inherited pipe end, no longer used here.
            unsafe { libc::close(fd) };
        }
    }
}

/// At `execve`: the timers are deleted (the thread, idle, stays).
pub fn exec() {
    for s in &SLOTS {
        s.used.store(false, Ordering::Release);
        s.due.store(0, Ordering::Release);
        s.pending.store(false, Ordering::Release);
    }
    notify().clear();
}

fn to_ns(t: fwe_abi::Timespec) -> Result<u64, i32> {
    if t.tv_sec < 0 || !(0..NS as i64).contains(&t.tv_nsec) {
        return Err(errno::EINVAL);
    }
    Ok((t.tv_sec as u64).saturating_mul(NS).saturating_add(t.tv_nsec as u64))
}

fn to_timespec(ns: u64) -> fwe_abi::Timespec {
    fwe_abi::Timespec { tv_sec: (ns / NS) as i64, tv_nsec: (ns % NS) as i64 }
}

/// Timer `id`'s slot, if it is one.
fn slot(id: u64) -> Result<&'static Slot, i32> {
    let s = usize::try_from(id as i32).ok().and_then(|i| SLOTS.get(i)).ok_or(errno::EINVAL)?;
    if s.used.load(Ordering::Acquire) { Ok(s) } else { Err(errno::EINVAL) }
}

/// What is left of timer `s` until it is next due, and its interval.
fn current(s: &Slot) -> fwe_abi::Itimerspec {
    let (due, interval) = (s.due.load(Ordering::Acquire), s.interval.load(Ordering::Acquire));
    let now = Clock::decode(s.clock.load(Ordering::Acquire)).now().unwrap_or(0);
    let left = if due == 0 {
        0
    } else if now < due {
        due - now
    } else if interval > 0 {
        // Past due: the next of its intervals.
        interval - (now - due) % interval
    } else {
        0
    };
    fwe_abi::Itimerspec { it_interval: to_timespec(interval), it_value: to_timespec(left) }
}

impl<P: crate::Platform> crate::Kernel<P> {
    /// `timer_create(clock, sevp, timerid)`.
    pub(crate) fn sys_timer_create(&mut self, clock: u64, sevp: u64, timerid: u64) -> i64 {
        use fwe_abi::clock as c;
        use fwe_abi::mqueue::{SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID};
        let which = clock as i32;
        let clk = if which < 0 {
            // A process's or thread's CPU-time clock.
            match crate::syscalls::cpu_clock_ns(clock) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return err(e),
                None => return err(errno::EINVAL),
            }
            let who = !(which >> 3);
            if which & 4 != 0 {
                let tid = if who == 0 { crate::thread::tid() } else { who };
                match self.thread_of(tid) {
                    Some(t) => Clock::Thread(t),
                    None => return err(errno::EINVAL),
                }
            } else if who == 0 || who == crate::thread::tgid() {
                Clock::Host(libc::CLOCK_PROCESS_CPUTIME_ID)
            } else {
                Clock::Cpu(clock)
            }
        } else {
            match clock {
                c::CLOCK_REALTIME | c::CLOCK_TAI => Clock::Host(libc::CLOCK_REALTIME),
                c::CLOCK_MONOTONIC | c::CLOCK_BOOTTIME => Clock::Host(libc::CLOCK_MONOTONIC),
                c::CLOCK_REALTIME_ALARM | c::CLOCK_BOOTTIME_ALARM => {
                    if !self.creds.has(crate::caps::CAP_WAKE_ALARM) {
                        return err(errno::EPERM);
                    }
                    let host = if clock == c::CLOCK_REALTIME_ALARM {
                        libc::CLOCK_REALTIME
                    } else {
                        libc::CLOCK_MONOTONIC
                    };
                    Clock::Host(host)
                }
                c::CLOCK_PROCESS_CPUTIME_ID => Clock::Host(libc::CLOCK_PROCESS_CPUTIME_ID),
                // SAFETY: pthread_self cannot fail.
                c::CLOCK_THREAD_CPUTIME_ID => Clock::Thread(unsafe { libc::pthread_self() }),
                // Clocks without timers.
                c::CLOCK_MONOTONIC_RAW | c::CLOCK_REALTIME_COARSE | c::CLOCK_MONOTONIC_COARSE => {
                    return err(errno::EOPNOTSUPP);
                }
                _ => return err(errno::EINVAL),
            }
        };
        let mut n =
            Notify { how: SIGEV_SIGNAL, signo: fwe_abi::signal::SIGALRM, value: u64::MAX, tid: 0 };
        if sevp != 0 {
            let ev: [u8; 64] = crate::guest!(uaccess::read(sevp));
            let word = |at: usize| i32::from_ne_bytes(ev[at..at + 4].try_into().unwrap());
            n.value = u64::from_ne_bytes(ev[0..8].try_into().unwrap());
            n.signo = word(8) as u32 as u64;
            n.how = word(12);
            n.tid = word(16);
            match n.how {
                SIGEV_NONE => {}
                SIGEV_SIGNAL | SIGEV_THREAD | SIGEV_THREAD_ID => {
                    if n.how == SIGEV_THREAD_ID && !crate::thread::tids().contains(&n.tid) {
                        return err(errno::EINVAL);
                    }
                    if !(1..=fwe_abi::signal::NSIG).contains(&n.signo) {
                        return err(errno::EINVAL);
                    }
                    if n.how == SIGEV_THREAD {
                        n.how = SIGEV_SIGNAL;
                    }
                }
                _ => return err(errno::EINVAL),
            }
        }
        // The lowest free id.
        let mut notes = notify();
        let Some(id) = (0..MAX).find(|&i| !SLOTS[i].used.load(Ordering::Acquire)) else {
            return err(errno::EAGAIN);
        };
        if sevp == 0 {
            n.value = id as u64;
        }
        if crate::uaccess::write(timerid, id as i32).is_err() {
            return err(errno::EFAULT);
        }
        if notes.len() <= id {
            notes.resize(id + 1, None);
        }
        notes[id] = Some(n);
        let s = &SLOTS[id];
        s.clock.store(clk.encode(), Ordering::Release);
        s.due.store(0, Ordering::Release);
        s.interval.store(0, Ordering::Release);
        s.pending.store(false, Ordering::Release);
        s.last.store(0, Ordering::Release);
        s.used.store(true, Ordering::Release);
        drop(notes);
        if n.how != SIGEV_NONE {
            start_thread();
        }
        0
    }

    /// The host thread of guest thread `tid` of this process.
    fn thread_of(&self, tid: i32) -> Option<libc::pthread_t> {
        if tid == crate::thread::tid() {
            // SAFETY: pthread_self cannot fail.
            return Some(unsafe { libc::pthread_self() });
        }
        crate::thread::host_thread(tid).filter(|&h| h != 0 as libc::pthread_t)
    }

    /// `timer_settime(id, flags, new, old)`.
    pub(crate) fn sys_timer_settime(&mut self, id: u64, flags: u64, new: u64, old: u64) -> i64 {
        const TIMER_ABSTIME: u64 = 1;
        // In Linux's order: the new setting (`EINVAL` for none, `EFAULT`),
        // its times, then the timer.
        if new == 0 {
            return err(errno::EINVAL);
        }
        let spec: fwe_abi::Itimerspec = crate::guest!(uaccess::read(new));
        let (value, interval) = match (to_ns(spec.it_value), to_ns(spec.it_interval)) {
            (Ok(v), Ok(i)) => (v, i),
            _ => return err(errno::EINVAL),
        };
        let s = match slot(id) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        if old != 0 {
            crate::guest!(uaccess::write(old, current(s)));
        }
        let due = if value == 0 {
            0
        } else if flags & TIMER_ABSTIME != 0 {
            value.max(1)
        } else {
            let now = Clock::decode(s.clock.load(Ordering::Acquire)).now().unwrap_or(0);
            now.saturating_add(value)
        };
        s.pending.store(false, Ordering::Release);
        s.interval.store(if due == 0 { 0 } else { interval }, Ordering::Release);
        s.due.store(due, Ordering::Release);
        wake();
        0
    }

    /// `timer_gettime(id, curr)`.
    pub(crate) fn sys_timer_gettime(&mut self, id: u64, curr: u64) -> i64 {
        let s = match slot(id) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        crate::guest!(uaccess::write(curr, current(s)));
        0
    }

    /// `timer_getoverrun(id)`.
    pub(crate) fn sys_timer_getoverrun(&mut self, id: u64) -> i64 {
        match slot(id) {
            Ok(s) => i64::from(s.last.load(Ordering::Acquire)),
            Err(e) => err(e),
        }
    }

    /// `timer_delete(id)`.
    pub(crate) fn sys_timer_delete(&mut self, id: u64) -> i64 {
        let s = match slot(id) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let mut notes = notify();
        s.used.store(false, Ordering::Release);
        s.due.store(0, Ordering::Release);
        s.pending.store(false, Ordering::Release);
        if let Some(n) = notes.get_mut(id as usize) {
            *n = None;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clocks_survive_their_encoding() {
        for c in [
            Clock::Host(libc::CLOCK_REALTIME),
            Clock::Host(libc::CLOCK_MONOTONIC),
            Clock::Thread(12345usize as libc::pthread_t),
            Clock::Cpu(!(42u64 << 3) & 0xffff_ffff | 0xffff_ffff_0000_0000),
        ] {
            assert_eq!(Clock::decode(c.encode()), c);
        }
    }

    #[test]
    fn a_timer_past_due_is_left_its_next_interval() {
        let s = Slot::new();
        s.clock.store(Clock::Host(libc::CLOCK_MONOTONIC).encode(), Ordering::Release);
        s.used.store(true, Ordering::Release);
        s.interval.store(NS, Ordering::Release);
        s.due.store(1, Ordering::Release);
        let c = current(&s);
        assert_eq!(c.it_interval.tv_sec, 1);
        assert!(c.it_value.tv_sec == 0 && c.it_value.tv_nsec > 0 || c.it_value.tv_sec == 1);
    }
}
