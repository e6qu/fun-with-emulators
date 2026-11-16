//! strace-style tracing of guest system calls.

use fwe_abi::{errno_name, syscall_name};
use std::fmt::Write as _;
use std::sync::OnceLock;

/// The file every process of the run traces to (`--strace-file`), and fwe's
/// descriptor of it in this process.
static FILE: OnceLock<(Vec<u8>, i32)> = OnceLock::new();

/// Trace to the file at host path `path`, appended to, each line naming
/// the process, instead of to standard error: so a run of many processes
/// (whose standard error another may hold) is traced whole. Called once
/// the guest's descriptor range is placed ([`crate::fdtable::init`]).
pub fn to_file(path: &[u8]) -> Result<(), String> {
    let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
    // SAFETY: a NUL-terminated path.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let fd = crate::fdtable::reserve(fd).map_err(|e| format!("errno {e}"))?;
    let _ = FILE.set((path.to_vec(), fd));
    Ok(())
}

/// Note `message` in the trace file, when the run traces to one: what fwe's
/// own threads (the reaper's watcher) see and do, which no system call
/// shows. Nothing without a trace file.
pub fn note_to_file(message: &str) {
    if FILE.get().is_some() {
        Tracer { enabled: true, failures_only: false }.write_line(message);
    }
}

/// The file traced to, which a process fwe starts is told of.
pub fn file() -> Option<&'static [u8]> {
    FILE.get().map(|(p, _)| p.as_slice())
}

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
        let strings = string_args(nr);
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                line.push_str(", ");
            }
            // A path or name, as the guest wrote it.
            match crate::uaccess::read_cstr(*a, 256)
                .ok()
                .filter(|_| *a != 0 && strings & (1 << i) != 0)
            {
                Some(text) => {
                    let _ = write!(line, "{:?}", String::from_utf8_lossy(&text));
                }
                None => {
                    let _ = write!(line, "{a:#x}");
                }
            }
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
        let mut out = String::with_capacity(line.len() + 16);
        let fd = match FILE.get() {
            Some((_, fd)) => {
                let _ = write!(out, "[fwe {}] ", crate::host::pid());
                *fd
            }
            None => {
                out.push_str("[fwe] ");
                2
            }
        };
        out.push_str(line);
        out.push('\n');
        // Written with a single host write so lines from the guest and the
        // tracer do not interleave mid-line.
        // SAFETY: `out` is a valid buffer of `out.len()` bytes.
        unsafe { libc::write(fd, out.as_ptr().cast(), out.len()) };
    }
}

/// Which arguments of system call `nr` are strings: a bit for each.
fn string_args(nr: u64) -> u8 {
    use fwe_abi::nr as n;
    match nr {
        n::OPENAT | n::OPENAT2 | n::FACCESSAT | n::FACCESSAT2 | n::NEWFSTATAT | n::STATX => 0b10,
        n::READLINKAT | n::MKDIRAT | n::MKNODAT | n::UNLINKAT | n::FCHMODAT | n::FCHOWNAT => 0b10,
        n::UTIMENSAT | n::EXECVEAT | n::OPEN_TREE | n::INOTIFY_ADD_WATCH => 0b10,
        n::SYMLINKAT => 0b101,
        n::LINKAT | n::RENAMEAT | n::RENAMEAT2 => 0b1010,
        n::EXECVE | n::CHDIR | n::CHROOT | n::STATFS | n::TRUNCATE | n::UMOUNT2 => 0b1,
        n::MEMFD_CREATE => 0b1,
        n::MOUNT => 0b111,
        n::PIVOT_ROOT => 0b11,
        n::SETXATTR
        | n::LSETXATTR
        | n::GETXATTR
        | n::LGETXATTR
        | n::REMOVEXATTR
        | n::LREMOVEXATTR => 0b11,
        n::FSETXATTR | n::FGETXATTR | n::FREMOVEXATTR => 0b10,
        _ => 0,
    }
}
