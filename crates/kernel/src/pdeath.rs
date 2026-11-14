//! The parent-death signal (`prctl(PR_SET_PDEATHSIG)`): the signal a
//! process is sent when its parent ends.
//!
//! macOS has no such thing, so once one is set a thread of fwe's waits for
//! the parent's end (`kqueue`'s `EVFILT_PROC` with `NOTE_EXIT` on the
//! host's parent, the process that made this one) and then sends the
//! signal to this process: through the host for a signal it has (a
//! `SIGKILL` as the kill relay, so a VM process tears its VM down first),
//! or recorded for one it lacks. A parent that had ended already when the
//! signal was set sends none, as on Linux. A fork child starts without one
//! ([`forked`]); an `execve` keeps it ([`save`], [`restore`]).
//!
//! Linux sends it when the parent *thread* that made the child ends; here
//! it is sent when the parent process ends.
//!
//! The same watch keeps the parent's pid for `getppid` ([`parent`]): while
//! the parent lives it is the answer, with no call to the host. A process
//! that asks for its parent often ([`asked`]) starts the watch for that
//! alone.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

/// The signal set (0: none).
static SIG: AtomicU64 = AtomicU64::new(0);
/// Whether the watching thread runs (or ran, until the parent ended).
static WATCHING: AtomicBool = AtomicBool::new(false);

/// This process's host pid and its host parent's, while the watch sees the
/// parent live (0: not known).
static KNOWN: AtomicU64 = AtomicU64::new(0);

/// How often this process asked for its parent ([`asked`]), with its pid.
static ASKS: AtomicU64 = AtomicU64::new(0);

/// `PR_SET_PDEATHSIG`: `sig` is sent when the parent ends (0: nothing).
pub fn set(sig: u64) {
    SIG.store(sig, SeqCst);
    if sig != 0 {
        start();
    }
}

/// Watch the parent from now on, before the caller goes on: a parent that
/// ends right after (as the child tells it to) is seen.
fn start() {
    if WATCHING.swap(true, SeqCst) {
        return;
    }
    let Some((kq, parent)) = watch_parent() else { return };
    let me = crate::host::pid();
    KNOWN.store((me as u64) << 32 | parent as u32 as u64, SeqCst);
    let started = crate::host::with_signals_blocked(|| {
        std::thread::Builder::new().name("fwe-pdeath".into()).spawn(move || wait(kq))
    });
    if started.is_err() {
        KNOWN.store(0, SeqCst);
        // SAFETY: the kqueue made above, of no one else's.
        unsafe { libc::close(kq) };
        WATCHING.store(false, SeqCst);
    }
}

/// This process's host parent, while the watch knows it lives.
pub fn parent() -> Option<i32> {
    let v = KNOWN.load(SeqCst);
    ((v >> 32) as i32 == crate::host::pid() && v != 0).then_some(v as u32 as i32)
}

/// This process asked the host for its parent: from the 32nd time, the
/// parent is watched and the answer kept ([`parent`]).
pub fn asked() {
    let me = crate::host::pid() as u64;
    let v = ASKS.load(SeqCst);
    let n = if v >> 32 == me { (v & 0xffff_ffff) + 1 } else { 1 };
    ASKS.store(me << 32 | n.min(1 << 20), SeqCst);
    if n == 32 {
        start();
    }
}

/// `PR_GET_PDEATHSIG`.
pub fn get() -> u64 {
    SIG.load(SeqCst)
}

/// In a fork child: it has no parent-death signal (and no watching
/// thread).
pub fn forked() {
    SIG.store(0, SeqCst);
    KNOWN.store(0, SeqCst);
    WATCHING.store(false, SeqCst);
}

/// The signal, into a process fwe re-executes.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    e.u64(SIG.load(SeqCst));
}

/// What [`save`] wrote: the signal, and its watch again.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    set(d.u64());
}

/// A kqueue watching this process's host parent for its end, made by the
/// calling thread, and the parent; none if the parent has ended already
/// (an adopted orphan's host parent is `launchd`), which sends nothing, as
/// on Linux.
#[cfg(target_os = "macos")]
fn watch_parent() -> Option<(i32, i32)> {
    // SAFETY: getppid cannot fail.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return None;
    }
    // SAFETY: plain host calls on a kqueue of fwe's own, in its reserved
    // range, where the guest's closing of its descriptors (as a program
    // does before an `execve`) does not reach it.
    unsafe {
        let kq = crate::fdtable::reserve(libc::kqueue()).ok()?;
        let ev = libc::kevent {
            ident: parent as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // Still the parent once watched: one that ended between is not.
        if libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) != 0
            || libc::getppid() != parent
        {
            libc::close(kq);
            return None;
        }
        Some((kq, parent))
    }
}

#[cfg(not(target_os = "macos"))]
fn watch_parent() -> Option<(i32, i32)> {
    None
}

/// On a thread of fwe's: wait on kqueue `kq` ([`watch_parent`]) for the
/// parent's end, then send the signal.
#[cfg(target_os = "macos")]
fn wait(kq: i32) {
    // Signals are for the guest's threads, never this one: it starts with
    // them all blocked ([`crate::host::with_signals_blocked`]).
    // SAFETY: plain host calls on the kqueue the thread was given, which it
    // closes.
    unsafe {
        let mut out: libc::kevent = std::mem::zeroed();
        let n = loop {
            let n = libc::kevent(kq, std::ptr::null(), 0, &mut out, 1, std::ptr::null());
            if n >= 0 || crate::host::last_errno() != libc::EINTR {
                break n;
            }
        };
        libc::close(kq);
        // The parent is the host's to say again.
        KNOWN.store(0, SeqCst);
        // Only the parent's end sends it, never a failed wait.
        if n != 1 || out.fflags & libc::NOTE_EXIT == 0 {
            return;
        }
    }
    deliver(SIG.load(SeqCst));
}

#[cfg(not(target_os = "macos"))]
fn wait(_: i32) {}

/// Send `sig` (a Linux signal) to this process, as the parent's end does.
#[cfg(target_os = "macos")]
fn deliver(sig: u64) {
    if sig == 0 {
        return;
    }
    let me = crate::host::pid();
    match crate::host::signal_to_host(sig) {
        Some(h) => {
            crate::host::kill_process(me, h);
        }
        None => {
            // SAFETY: getuid cannot fail.
            let uid = unsafe { libc::getuid() };
            let info = crate::thread::SigInfo {
                code: fwe_abi::signal::SI_KERNEL,
                uid,
                ..Default::default()
            };
            crate::thread::post_process_waking(sig, info);
        }
    }
}
