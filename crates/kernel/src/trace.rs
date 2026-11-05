//! strace-style tracing of guest system calls.

use fwe_abi::{errno_name, syscall_name};
use std::fmt::Write as _;

/// Writes one line per system call to the host's standard error when enabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tracer {
    pub enabled: bool,
    /// Only the calls that fail, and the notes (`--strace=failures`): cheap
    /// enough to leave the timing of a run much as it is.
    pub failures_only: bool,
}

impl Tracer {
    pub fn syscall(&self, nr: u64, args: &[u64; 6], result: i64) {
        if !self.enabled || self.failures_only && !(-4095..0).contains(&result) {
            return;
        }
        let mut line = String::with_capacity(128);
        match syscall_name(nr) {
            Some(name) => line.push_str(name),
            None => {
                let _ = write!(line, "syscall_{nr}");
            }
        }
        line.push('(');
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                line.push_str(", ");
            }
            let _ = write!(line, "{a:#x}");
        }
        line.push_str(") = ");
        if (-4095..0).contains(&result) {
            let e = (-result) as i32;
            let _ = write!(line, "-1 {} ({e})", errno_name(e).unwrap_or("E?"));
        } else {
            let _ = write!(line, "{result:#x}");
        }
        self.write_line(&line);
    }

    pub fn note(&self, message: &str) {
        if self.enabled {
            self.write_line(message);
        }
    }

    fn write_line(&self, line: &str) {
        let mut out = String::with_capacity(line.len() + 8);
        out.push_str("[fwe] ");
        out.push_str(line);
        out.push('\n');
        // Written with a single host write so lines from the guest and the
        // tracer do not interleave mid-line.
        // SAFETY: `out` is a valid buffer of `out.len()` bytes.
        unsafe { libc::write(2, out.as_ptr().cast(), out.len()) };
    }
}
