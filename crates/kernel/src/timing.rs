//! Phase timings of a start, an `execve` and a `fork`, for finding where
//! their time goes: with `FWE_TIMING` set, each mark writes to standard
//! error how long since the previous one and since the process began.
//! Off (the default), a mark costs one relaxed load.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

static ON: AtomicBool = AtomicBool::new(false);
static START: OnceLock<Instant> = OnceLock::new();
/// Nanoseconds since [`START`] at the last mark.
static LAST: AtomicU64 = AtomicU64::new(0);

/// Take `FWE_TIMING` from the environment; the process's time counts from
/// here.
pub fn init() {
    let start = *START.get_or_init(Instant::now);
    let _ = start;
    ON.store(std::env::var_os("FWE_TIMING").is_some(), Relaxed);
}

/// Mark the end of phase `name`.
#[inline]
pub fn mark(name: &str) {
    if ON.load(Relaxed) {
        write_mark(name);
    }
}

#[cold]
fn write_mark(name: &str) {
    let Some(start) = START.get() else { return };
    let now = start.elapsed().as_nanos() as u64;
    let last = LAST.swap(now, Relaxed);
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let line = format!(
        "[fwe {pid}] timing: {name} +{}us ({}us)\n",
        now.saturating_sub(last) / 1000,
        now / 1000
    );
    // SAFETY: a buffer of its length.
    unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
}
