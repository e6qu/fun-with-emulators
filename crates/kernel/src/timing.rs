//! Phase timings of a start, an `execve` and a `fork`, for finding where
//! their time goes: with `FWE_TIMING` set, each mark writes to standard
//! error how long since the previous one and since the process began. A
//! `backend:` mark names the backend each program starts in, native or the
//! VM (the benchmarks count them).
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
    let pid = crate::host::pid();
    let line = format!(
        "[fwe {pid}] timing: {name} +{}us ({}us)\n",
        now.saturating_sub(last) / 1000,
        now / 1000
    );
    // SAFETY: a buffer of its length.
    unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
}

/// Whether `FWE_TIMING` is set: for a mark whose name costs work to make.
pub fn on() -> bool {
    ON.load(Relaxed)
}

/// The guest's system calls by number, and the nanoseconds they took, and
/// the host signals fwe handled by number: for `FWE_TIMING`'s mark as a
/// process ends ([`calls_and_signals`]). Counted only with it on.
static CALLS: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
static CALL_NS: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
static SIGNALS: [AtomicU64; 32] = [const { AtomicU64::new(0) }; 32];

/// The start of a system call's run, if [`on`].
#[inline]
pub fn call_began() -> Option<Instant> {
    on().then(Instant::now)
}

/// System call `nr`, begun at `began` ([`call_began`]), done.
#[inline]
pub fn call_done(nr: u64, began: Option<Instant>) {
    if let Some(b) = began {
        let i = (nr as usize).min(CALLS.len() - 1);
        CALLS[i].fetch_add(1, Relaxed);
        CALL_NS[i].fetch_add(b.elapsed().as_nanos() as u64, Relaxed);
    }
}

/// Host signal `sig` taken by fwe's handlers.
#[inline]
pub fn signal(sig: i32) {
    if on() {
        SIGNALS[(sig as usize).min(SIGNALS.len() - 1)].fetch_add(1, Relaxed);
    }
}

/// The calls that took longest (number, count, milliseconds) and the
/// signals taken (number, count), as text.
pub fn calls_and_signals() -> String {
    let mut calls: Vec<(usize, u64, u64)> = (0..CALLS.len())
        .map(|i| (i, CALLS[i].load(Relaxed), CALL_NS[i].load(Relaxed)))
        .filter(|c| c.1 > 0)
        .collect();
    calls.sort_by_key(|c| std::cmp::Reverse(c.2));
    let total: u64 = calls.iter().map(|c| c.1).sum();
    let calls: Vec<String> = calls
        .iter()
        .take(12)
        .map(|(i, n, ns)| format!("{i}: {n} ({} ms)", ns / 1_000_000))
        .collect();
    let signals: Vec<String> = (0..SIGNALS.len())
        .map(|i| (i, SIGNALS[i].load(Relaxed)))
        .filter(|s| s.1 > 0)
        .map(|(i, n)| format!("{i}: {n}"))
        .collect();
    format!(
        "{total} system calls, by number, the longest: {}; host signals by number: {}",
        calls.join(", "),
        signals.join(", ")
    )
}
