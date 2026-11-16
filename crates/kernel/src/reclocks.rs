//! Whether the process holds POSIX record locks (`F_SETLK`).
//!
//! Record locks are the host's, and macOS, as Linux, drops all of a
//! process's locks on a file when the process closes any descriptor of
//! it. Linux does so only for the guest's own closes; fwe must never close
//! a descriptor of a guest's file it opened for its own ends. Most of fwe
//! reaches guest files without a descriptor (by path or from their
//! directory: [`crate::host::at_path`]); the few places that open one
//! first to see what it is (the one-call opens of [`crate::fs::Direct`])
//! look before they open once the process has taken a record lock
//! ([`held`]), which few programs do.

use std::sync::atomic::{AtomicBool, Ordering};

static HELD: AtomicBool = AtomicBool::new(false);

/// The process took a record lock (one other than an unlock).
pub fn taken() {
    if !HELD.load(Ordering::Relaxed) {
        HELD.store(true, Ordering::Relaxed);
    }
}

/// Whether the process may hold a record lock: it has taken one since it
/// began (a fork child holds none of its parent's).
pub fn held() -> bool {
    HELD.load(Ordering::Relaxed)
}

/// In a fork child: it holds no record lock.
pub fn forked_child() {
    HELD.store(false, Ordering::Relaxed);
}
