//! Phase timings of a start, an `execve` and a `fork`, for finding where
//! their time goes: with `FWE_TIMING` set, each mark writes to standard
//! error how long since the previous one and since the process began,
//! and how many page faults the process took since the previous one. A
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
/// The process's page faults (reclaims included) at the last mark.
static LAST_FAULTS: AtomicU64 = AtomicU64::new(0);

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
    let faults = faults();
    // (A fork's child counts its own from 0.)
    let since = LAST_FAULTS.swap(faults, Relaxed);
    let since = if since > faults { faults } else { faults - since };
    let pid = crate::host::pid();
    // Made on the stack: a mark allocates nothing, so it writes no page
    // the step it ends would not (the faults it counts are the step's).
    let mut line = [0u8; 4096];
    let mut at = std::io::Cursor::new(&mut line[..]);
    use std::io::Write;
    let _ = writeln!(
        at,
        "[fwe {pid}] timing: {name} +{}us ({}us) +{since} faults",
        now.saturating_sub(last) / 1000,
        now / 1000
    );
    let len = at.position() as usize;
    // SAFETY: a buffer of at least `len` bytes.
    unsafe { libc::write(2, line.as_ptr().cast(), len) };
}

/// The page faults this process has taken: those the kernel resolved
/// without reading anything (a copy on write, a page zeroed) and the rest.
fn faults() -> u64 {
    // SAFETY: zeroed bytes are a valid `rusage`; `getrusage` fills it.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
        return 0;
    }
    (u.ru_minflt + u.ru_majflt) as u64
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

/// What a host `SIGTRAP` was for, counted by [`trapped`].
#[derive(Clone, Copy)]
pub enum Trap {
    /// A translation's way out by its own trap.
    WayOut,
    /// The exit gate's trap: on at code not translated, or a signal to
    /// deliver.
    ExitGate,
    /// The system-call gate's trap after the call ran (a signal to
    /// deliver).
    GateRan,
    /// The system-call gate's trap with the call not run.
    Gate,
    /// A system call's own trap, or a `brk` that is not fwe's.
    Call,
}

const TRAP_NAMES: [&str; 5] = [
    "ways out",
    "exit gate",
    "gate after its call",
    "gate before its call",
    "system calls and others",
];

static TRAPS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// A host `SIGTRAP` taken for `what`, if [`on`].
#[inline]
pub fn trapped(what: Trap) {
    if on() {
        TRAPS[what as usize].fetch_add(1, Relaxed);
    }
}

/// The calls that took longest (number, count, milliseconds), the signals
/// taken (number, count) and what the traps among them were for, as text.
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
    let traps: Vec<String> = (0..TRAPS.len())
        .map(|i| (TRAP_NAMES[i], TRAPS[i].load(Relaxed)))
        .filter(|t| t.1 > 0)
        .map(|(name, n)| format!("{name} {n}"))
        .collect();
    format!(
        "{total} system calls, by number, the longest: {}; host signals by number: {}; traps: {}",
        calls.join(", "),
        signals.join(", "),
        traps.join(", ")
    )
}
