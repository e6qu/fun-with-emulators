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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

/// The signal set (0: none).
static SIG: AtomicU64 = AtomicU64::new(0);
/// Whether the watching thread runs.
static WATCHING: AtomicBool = AtomicBool::new(false);

/// `PR_SET_PDEATHSIG`: `sig` is sent when the parent ends (0: nothing).
pub fn set(sig: u64) {
    SIG.store(sig, SeqCst);
    if sig != 0 && !WATCHING.swap(true, SeqCst) {
        // SAFETY: getppid cannot fail.
        let parent = unsafe { libc::getppid() };
        let started =
            std::thread::Builder::new().name("fwe-pdeath".into()).spawn(move || watch(parent));
        if started.is_err() {
            WATCHING.store(false, SeqCst);
        }
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

/// The watching thread: wait for host process `parent` to end, then send
/// the signal.
#[cfg(target_os = "macos")]
fn watch(parent: i32) {
    // Signals are for the guest's threads, never this one.
    // SAFETY: plain host calls on a valid signal set.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
    // An adopted orphan's host parent is `launchd`: its parent has ended.
    if parent <= 1 {
        return;
    }
    // SAFETY: plain host calls on a kqueue of this thread's own.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            return;
        }
        let ev = libc::kevent {
            ident: parent as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // A parent already gone sends nothing.
        if libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) != 0 {
            libc::close(kq);
            return;
        }
        let mut out: libc::kevent = std::mem::zeroed();
        while libc::kevent(kq, std::ptr::null(), 0, &mut out, 1, std::ptr::null()) < 0
            && crate::host::last_errno() == libc::EINTR
        {}
        libc::close(kq);
    }
    deliver(SIG.load(SeqCst));
}

#[cfg(not(target_os = "macos"))]
fn watch(_: i32) {}

/// Send `sig` (a Linux signal) to this process, as the parent's end does.
fn deliver(sig: u64) {
    if sig == 0 {
        return;
    }
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
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
            crate::thread::post_process(sig, info);
            crate::host::kill_process(me, crate::host::WAKE_SIGNAL);
        }
    }
}
