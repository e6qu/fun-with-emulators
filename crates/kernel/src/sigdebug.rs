//! A trace of how `SIGCHLD` reports travel, for chasing a race on a busy
//! host: with `FWE_DEBUG_SIGCHLD` set, each step is written to standard
//! error as it happens. Async-signal-safe (a fixed buffer, one `write`).

use std::sync::atomic::{AtomicU8, Ordering::Relaxed};

/// 0 unknown, 1 off, 2 on.
static STATE: AtomicU8 = AtomicU8::new(0);

/// Look at the environment once, as the process starts (not from a
/// handler).
pub fn init() {
    let on = std::env::var_os("FWE_DEBUG_SIGCHLD").is_some();
    STATE.store(if on { 2 } else { 1 }, Relaxed);
}

/// Write `what` and the numbers `n`, if tracing.
pub fn event(what: &str, n: &[i64]) {
    if STATE.load(Relaxed) != 2 {
        return;
    }
    let mut buf = [0u8; 256];
    let mut at = 0;
    let mut put = |b: &[u8], at: &mut usize| {
        let k = b.len().min(buf.len() - *at);
        buf[*at..*at + k].copy_from_slice(&b[..k]);
        *at += k;
    };
    put(b"[sigchld ", &mut at);
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() } as i64;
    for v in std::iter::once(me) {
        put(&digits(v).0[..digits(v).1], &mut at);
    }
    put(b"] ", &mut at);
    put(what.as_bytes(), &mut at);
    for &v in n {
        put(b" ", &mut at);
        let (d, l) = digits(v);
        put(&d[..l], &mut at);
    }
    put(b"\n", &mut at);
    let saved = crate::host::last_errno();
    // SAFETY: writing a buffer of `at` bytes to standard error.
    unsafe { libc::write(2, buf.as_ptr().cast(), at) };
    crate::host::set_errno(saved);
}

fn digits(v: i64) -> ([u8; 24], usize) {
    let mut out = [0u8; 24];
    let mut tmp = [0u8; 24];
    let neg = v < 0;
    let mut n = v.unsigned_abs();
    let mut len = 0;
    loop {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut at = 0;
    if neg {
        out[0] = b'-';
        at = 1;
    }
    for i in (0..len).rev() {
        out[at] = tmp[i];
        at += 1;
    }
    (out, at)
}
