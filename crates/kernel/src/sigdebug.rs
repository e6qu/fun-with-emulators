//! A trace of how `SIGCHLD` reports travel, for chasing a race on a busy
//! host: with `FWE_DEBUG_SIGCHLD` set, each step is written as it happens,
//! to standard error (`1`) or appended to the file it names (a path).
//! Async-signal-safe (a fixed buffer, one `write`).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};

/// 0 unknown, 1 off, 2 on.
static STATE: AtomicU8 = AtomicU8::new(0);
/// The file to append to, NUL-terminated (none: standard error).
static FILE: OnceLock<Vec<u8>> = OnceLock::new();

/// Trace to the file at `path` (`--debug-sigchld`, which fwe passes on to
/// the programs it runs).
pub fn to_file(path: &[u8]) {
    let _ = FILE.set([path, b"\0"].concat());
    STATE.store(2, Relaxed);
}

/// The file traced to, as given (to pass on).
pub fn file() -> Option<&'static [u8]> {
    FILE.get().map(|p| &p[..p.len() - 1])
}

/// Look at the environment once, as the process starts (not from a
/// handler), unless an option said already.
pub fn init() {
    use std::os::unix::ffi::OsStrExt;
    if STATE.load(Relaxed) != 0 {
        return;
    }
    let v = std::env::var_os("FWE_DEBUG_SIGCHLD");
    if let Some(v) = &v
        && v.as_bytes() != b"1"
    {
        let _ = FILE.set([v.as_bytes(), b"\0"].concat());
    }
    STATE.store(if v.is_some() { 2 } else { 1 }, Relaxed);
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
    match FILE.get() {
        // SAFETY: a NUL-terminated path; a buffer of `at` bytes.
        Some(path) => unsafe {
            let fd = libc::open(
                path.as_ptr().cast(),
                libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            );
            if fd >= 0 {
                libc::write(fd, buf.as_ptr().cast(), at);
                libc::close(fd);
            }
        },
        // SAFETY: writing a buffer of `at` bytes to standard error.
        None => unsafe {
            libc::write(2, buf.as_ptr().cast(), at);
        },
    }
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
