//! fwe's own host children, which are not the guest's.
//!
//! A guest's process is a host process, and its children are the host's
//! children of it: a guest's `wait` is the host's, and the host's
//! `SIGCHLD` is the guest's. A process fwe starts for itself while the
//! guest runs (the GPU helper's launcher, [`crate::virgl`]) is a child of
//! the same host process for as long as it lives, which is not long. It is
//! recorded here before it may end ([`OwnChild::record`]); a guest's wait
//! that reaps it, or sees it without reaping it, goes on as if it had not
//! happened ([`taken`], [`reap_seen`]), and the `SIGCHLD` its end raises is
//! not the guest's ([`is_own`]).
//!
//! The record is a few slots of atomics, read in signal handlers: a slot
//! holds a live child's pid, or its negation once a guest's wait reaped it
//! (so its record's end does not wait for the pid again, which may by then
//! be another process's).

use std::sync::atomic::{AtomicI32, Ordering::SeqCst};

/// The slots: as many of fwe's own children as may live at once.
const SLOTS: usize = 8;
static OWN: [AtomicI32; SLOTS] = [const { AtomicI32::new(0) }; SLOTS];

/// A child of fwe's own, recorded until it is reaped: dropping it waits
/// for its end and reaps it, unless a guest's wait reaped it already.
#[must_use = "a child of fwe's own is reaped when its record is dropped"]
pub struct OwnChild(crate::ids::HostPid);

impl OwnChild {
    /// Record `pid`, a child just started, as fwe's own: `None` if every
    /// slot is taken (the child is then not recorded, and the caller must
    /// end it at once and not let it be seen).
    pub fn record(pid: crate::ids::HostPid) -> Option<OwnChild> {
        OWN.iter()
            .any(|s| s.compare_exchange(0, pid.get(), SeqCst, SeqCst).is_ok())
            .then_some(OwnChild(pid))
    }
}

impl Drop for OwnChild {
    fn drop(&mut self) {
        let pid = self.0.get();
        let Some(slot) = OWN.iter().find(|s| matches!(s.load(SeqCst), p if p == pid || p == -pid))
        else {
            return;
        };
        if slot.load(SeqCst) == pid {
            let mut status = 0;
            // SAFETY: plain host call on a child of this process, not yet
            // reaped (or reaped by the host, if the guest ignores SIGCHLD:
            // ECHILD).
            while unsafe { libc::waitpid(pid, &mut status, 0) } < 0
                && crate::host::last_errno().is(libc::EINTR)
            {}
        }
        slot.store(0, SeqCst);
    }
}

/// Whether host process `pid` is a live child of fwe's own (one no wait
/// has reaped). Async-signal-safe.
pub fn is_own(pid: i32) -> bool {
    pid > 0 && OWN.iter().any(|s| s.load(SeqCst) == pid)
}

/// A host wait made for the guest reaped `pid`: whether it was a child of
/// fwe's own, which the wait must then not report. Its record then knows
/// it reaped. Async-signal-safe.
pub fn taken(pid: i32) -> bool {
    pid > 0 && OWN.iter().any(|s| s.compare_exchange(pid, -pid, SeqCst, SeqCst).is_ok())
}

/// A host wait made for the guest saw `pid` without reaping it (`WNOWAIT`):
/// whether it was a child of fwe's own, which is then reaped, so no wait
/// sees it again. Async-signal-safe.
pub fn reap_seen(pid: i32) -> bool {
    if !is_own(pid) {
        return false;
    }
    let mut status = 0;
    // SAFETY: plain host call on a child of this process, which the wait
    // saw has ended.
    if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
        taken(pid);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that ends at once.
    fn child() -> crate::ids::HostPid {
        // SAFETY: the child only ends.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: as above.
            unsafe { libc::_exit(0) };
        }
        crate::ids::HostPid::new(pid).expect("a child")
    }

    #[test]
    fn a_record_reaps_its_child_as_it_goes() {
        let pid = child();
        let own = OwnChild::record(pid).expect("a slot");
        assert!(is_own(pid.get()));
        drop(own);
        assert!(!is_own(pid.get()));
        let mut status = 0;
        // SAFETY: plain host call: the child is gone, reaped.
        assert_eq!(unsafe { libc::waitpid(pid.get(), &mut status, libc::WNOHANG) }, -1);
    }

    #[test]
    fn a_child_a_wait_took_is_not_waited_for_again() {
        let pid = child();
        let own = OwnChild::record(pid).expect("a slot");
        let mut status = 0;
        // SAFETY: plain host call on the child just made.
        assert_eq!(unsafe { libc::waitpid(pid.get(), &mut status, 0) }, pid.get());
        assert!(taken(pid.get()));
        // Taken: no longer a live child of fwe's, and its record's end does
        // not wait for the pid again.
        assert!(!is_own(pid.get()));
        assert!(!taken(pid.get()));
        drop(own);
        assert!(OWN.iter().all(|s| s.load(SeqCst) != -pid.get()));
    }

    #[test]
    fn a_child_seen_without_reaping_is_reaped() {
        let pid = child();
        let own = OwnChild::record(pid).expect("a slot");
        // SAFETY: an all-zero siginfo_t is a valid out-parameter.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: plain host call: waits for the child to end, not reaping.
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid.get() as libc::id_t,
                &mut si,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(r, 0);
        assert!(reap_seen(pid.get()));
        assert!(!is_own(pid.get()));
        drop(own);
        assert!(!reap_seen(pid.get()));
    }
}
