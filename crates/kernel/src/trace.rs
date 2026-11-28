//! strace-style tracing of guest system calls.

use fwe_abi::{errno_name, syscall_name};
use std::fmt::Write as _;
use std::sync::OnceLock;

/// The file every process of the run traces to (`--strace-file`), and fwe's
/// descriptor of it in this process.
static FILE: OnceLock<(Vec<u8>, i32)> = OnceLock::new();

/// Trace to the file at host path `path`, appended to, each line naming
/// the process, instead of to standard error: so a run of many processes
/// (whose standard error another might hold) is traced whole. Called once
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
/// Every call is traced (not only the failures): what calls fwe makes
/// without the kernel, which holds the tracer, look at ([`calls_traced`]).
static ALL_CALLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The run traces every call, as `tracer` says.
pub fn traces(tracer: Tracer) {
    ALL_CALLS.store(tracer.enabled && !tracer.failures_only, std::sync::atomic::Ordering::Relaxed);
}

/// Whether every call is traced, to a file.
pub fn calls_traced() -> bool {
    ALL_CALLS.load(std::sync::atomic::Ordering::Relaxed) && FILE.get().is_some()
}

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
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn syscall(&self, nr: u64, args: &[u64; 6], result: i64) {
        if !self.enabled || self.failures_only && !(-4095..0).contains(&result) {
            return;
        }
        let mut line = call_line(nr, args);
        if (-4095..0).contains(&result) {
            let e = (-result) as i32;
            let _ = write!(line, "-1 {} ({e})", errno_name(e).unwrap_or("E?"));
        } else {
            let _ = write!(line, "{result:#x}");
        }
        returned(&mut line, nr, args, result);
        self.write_line(&line);
    }

    /// A call that was not made, and why (`seccomp's SIGSYS`): `= ?`, as
    /// it returns nothing of its own.
    pub fn not_made(&self, nr: u64, args: &[u64; 6], why: &str) {
        if self.enabled && !self.failures_only {
            let mut line = call_line(nr, args);
            let _ = write!(line, "? ({why})");
            self.write_line(&line);
        }
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
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                let mut tid = 0u64;
                // SAFETY: probe: out pointers to locals.
                unsafe {
                    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
                    libc::pthread_threadid_np(0, &mut tid);
                }
                let us = ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000;
                let _ = write!(out, "[fwe {} {tid} @{us}] ", crate::host::pid());
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

/// A call's name and arguments, up to its ` = `.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn call_line(nr: u64, args: &[u64; 6]) -> String {
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
        // A path or name, as the guest wrote it: read only where the call
        // takes one (another argument is a number, or a pointer to bytes
        // that are no string).
        let text = (*a != 0 && strings & (1 << i) != 0)
            .then(|| crate::uaccess::read_cstr(*a, 256).ok())
            .flatten();
        match text {
            Some(text) => {
                let _ = write!(line, "{:?}", String::from_utf8_lossy(&text));
            }
            None => {
                let _ = write!(line, "{a:#x}");
            }
        }
    }
    line.push_str(") = ");
    line
}

/// What a call gave back or was given in memory that says what happened:
/// a `ppoll`'s returned events (each descriptor's, up to 16), a Unix
/// socket's address in `connect` and `bind` (`@` for an abstract name),
/// and the descriptors a `sendmsg` sent or a `recvmsg` received
/// (`SCM_RIGHTS`), each memfd and other file of fwe's store marked.
fn returned(line: &mut String, nr: u64, args: &[u64; 6], result: i64) {
    use fwe_abi::nr as n;
    match nr {
        n::PPOLL if result > 0 => {
            let count = args[1].min(16) as usize;
            let Ok(fds) = crate::uaccess::read_bytes(args[0], count * 8) else { return };
            line.push_str(" [");
            for (i, p) in fds.as_chunks::<8>().0.iter().enumerate() {
                let fd = i32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
                let revents = u16::from_ne_bytes([p[6], p[7]]);
                let _ = write!(line, "{}{fd}:{revents:#x}", if i > 0 { " " } else { "" });
            }
            line.push(']');
        }
        n::SENDMSG | n::RECVMSG if result >= 0 => passed_fds(line, args[1]),
        n::CONNECT | n::BIND => {
            let len = args[2].min(110) as usize;
            let Ok(addr) = crate::uaccess::read_bytes(args[1], len) else { return };
            if len > 2 && u16::from_ne_bytes([addr[0], addr[1]]) == 1 {
                let path = &addr[2..];
                let (at, name) = match path.split_first() {
                    Some((0, rest)) => ("@", rest),
                    _ => ("", &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())]),
                };
                let _ = write!(line, " [{at}{}]", String::from_utf8_lossy(name));
            }
        }
        _ => {}
    }
}

/// The descriptors of the `SCM_RIGHTS` messages of `msghdr` `msg`, as
/// ` [fds 3 4(memfd) 5(store)]`.
fn passed_fds(line: &mut String, msg: u64) {
    // `struct msghdr`: its control buffer at 32 and length at 40.
    let Ok(hdr) = crate::uaccess::read::<[u64; 6]>(msg) else { return };
    let (control, len) = (hdr[4], hdr[5].min(4096) as usize);
    if control == 0 || len < 16 {
        return;
    }
    let Ok(buf) = crate::uaccess::read_bytes(control, len) else { return };
    let mut fds = Vec::new();
    let mut at = 0;
    // Each `struct cmsghdr`: its length (8 bytes), level and type, then
    // its data, the next at an 8-byte boundary.
    while at + 16 <= buf.len() {
        let clen = u64::from_ne_bytes(buf[at..at + 8].try_into().expect("eight bytes")) as usize;
        let level = i32::from_ne_bytes(buf[at + 8..at + 12].try_into().expect("four bytes"));
        let kind = i32::from_ne_bytes(buf[at + 12..at + 16].try_into().expect("four bytes"));
        if clen < 16 || at + clen > buf.len() {
            break;
        }
        if level == fwe_abi::socket::SOL_SOCKET as i32 && kind == 1 {
            for c in buf[at + 16..at + clen].as_chunks::<4>().0 {
                fds.push(i32::from_ne_bytes(*c));
            }
        }
        at += clen.next_multiple_of(8);
    }
    if fds.is_empty() {
        return;
    }
    line.push_str(" [fds");
    for fd in fds {
        let kind = if crate::memfd::name(fd).is_some() {
            "(memfd)"
        } else if crate::filestore::desc::of(fd).is_some() {
            "(store)"
        } else {
            ""
        };
        let _ = write!(line, " {fd}{kind}");
    }
    line.push(']');
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
