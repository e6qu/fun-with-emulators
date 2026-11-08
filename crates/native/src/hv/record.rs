//! The flight recorder (`--hv-record DEST`, or `FWE_HV_RECORD=DEST` for the
//! first process): a line per framework call that changes the VM's state —
//! made, mapped, unmapped, a vCPU made or destroyed, the VM destroyed —
//! written before the call and after it, plus the process's
//! start, its `execve` and fork children, and a heartbeat with the count of
//! `hv_vcpu_run` calls every half second.
//!
//! It is for runs on real hardware, where a kernel crash can follow the
//! backend's use of the framework (see the safety rules in
//! `docs/hypervisor.md`): the record shows what every VM process was doing
//! up to the crash. A watchdog reset loses what the system had not yet
//! written, so each line is written synchronously: to a file (`file:PATH`),
//! with `F_FULLFSYNC` so it is on the disk before the call it announces
//! (a vCPU's destruction, which every thread records at once as a process
//! ends, is synced by the VM's destruction after it), or
//! as a UDP datagram to another machine (`udp:HOST:PORT`), which a reset
//! cannot take back. Several destinations are separated by commas; the
//! setting is passed on to every fwe a guest's `execve`, `fork` or `vfork`
//! starts.
//!
//! A line is `fwe-hv <wall-clock seconds>.<µs> pid <pid> tid <tid> <what>`;
//! a call is `> name args` before and `< name = rc` after. Everything here
//! is async-signal-safe: teardown and the framework calls it makes can run
//! in a signal handler.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

/// Where the record goes: descriptors, and whether each is a file.
struct Sinks {
    spec: String,
    fds: Vec<(i32, bool)>,
}

static SINKS: OnceLock<Sinks> = OnceLock::new();
/// `hv_vcpu_run` calls so far, for the heartbeat.
static RUNS: AtomicU64 = AtomicU64::new(0);

/// Start recording to `spec` (`file:PATH` and/or `udp:HOST:PORT`, comma
/// separated). Called at startup.
pub fn start(spec: &str) -> Result<(), String> {
    // fwe's own descriptors live above the guest's range, which this sets:
    // the guest must never see, reuse or close the record's.
    fwe_kernel::fdtable::init();
    let mut fds = Vec::new();
    // What is passed on, with each host resolved once, here.
    let mut resolved = Vec::new();
    for part in spec.split(',').filter(|p| !p.is_empty()) {
        let fd = if let Some(path) = part.strip_prefix("file:") {
            let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
            // SAFETY: opening a file by a NUL-terminated path.
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC,
                    0o644,
                )
            };
            if fd < 0 {
                return Err(format!("{path}: {}", std::io::Error::last_os_error()));
            }
            resolved.push(part.to_string());
            (fd, true)
        } else if let Some(addr) = part.strip_prefix("udp:") {
            use std::net::ToSocketAddrs;
            let to = addr
                .to_socket_addrs()
                .map_err(|e| format!("{addr}: {e}"))?
                .find(|a| a.is_ipv4())
                .ok_or_else(|| format!("{addr}: no IPv4 address"))?;
            let std::net::SocketAddr::V4(v4) = to else { unreachable!() };
            resolved.push(format!("udp:{v4}"));
            // SAFETY: a UDP socket connected to `v4`, from a filled-in
            // address record.
            let fd = unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                if fd < 0 {
                    return Err(format!("socket: {}", std::io::Error::last_os_error()));
                }
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
                sa.sin_family = libc::AF_INET as u8;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                if libc::connect(fd, (&sa as *const libc::sockaddr_in).cast(), sa.sin_len as u32)
                    != 0
                {
                    return Err(format!("{addr}: {}", std::io::Error::last_os_error()));
                }
                fd
            };
            (fd, false)
        } else {
            return Err(format!("{part}: a destination is file:PATH or udp:HOST:PORT"));
        };
        let kept = fwe_kernel::fdtable::reserve(fd.0)
            .map_err(|_| format!("{part}: no descriptor left for it"))?;
        fds.push((kept, fd.1));
    }
    let _ = SINKS.set(Sinks { spec: resolved.join(","), fds });
    std::thread::Builder::new()
        .name("fwe-hv-record".into())
        .spawn(|| {
            // No signal for the guest may land here: the backend relies on
            // the host delivering them only to vCPU threads.
            // SAFETY: blocking every signal on this thread only.
            unsafe {
                let mut all: libc::sigset_t = std::mem::zeroed();
                libc::sigfillset(&mut all);
                libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
            }
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let mut l = Line::new();
                l.s("heartbeat runs ").dec(RUNS.load(SeqCst));
                l.emit();
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The recorder is on.
#[inline]
pub fn active() -> bool {
    SINKS.get().is_some()
}

/// Its destinations, to pass on to the processes fwe starts.
pub fn spec() -> Option<&'static str> {
    SINKS.get().map(|s| s.spec.as_str())
}

/// Its descriptors, which a fork child must not be given (it opens its own).
pub fn own_fds() -> Vec<i32> {
    SINKS.get().map(|s| s.fds.iter().map(|&(fd, _)| fd).collect()).unwrap_or_default()
}

/// Count an `hv_vcpu_run`.
#[inline]
pub fn count_run() {
    if active() {
        RUNS.fetch_add(1, SeqCst);
    }
}

/// A line of the record, built without allocating.
pub struct Line {
    buf: [u8; 400],
    n: usize,
}

impl Default for Line {
    fn default() -> Line {
        Line::new()
    }
}

impl Line {
    /// A line stamped with the time, the process and the thread.
    pub fn new() -> Line {
        let mut l = Line { buf: [0; 400], n: 0 };
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: plain host calls.
        let (pid, tid) = unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            let mut tid = 0u64;
            libc::pthread_threadid_np(0, &mut tid);
            (libc::getpid(), tid)
        };
        l.s("fwe-hv ").dec(ts.tv_sec as u64).s(".");
        let us = (ts.tv_nsec / 1000) as u64;
        for d in [100_000, 10_000, 1000, 100, 10, 1] {
            l.byte(b'0' + (us / d % 10) as u8);
        }
        l.s(" pid ").dec(pid as u64).s(" tid ").dec(tid).s(" ");
        l
    }

    fn byte(&mut self, b: u8) -> &mut Line {
        if self.n < self.buf.len() - 1 {
            self.buf[self.n] = b;
            self.n += 1;
        }
        self
    }

    pub fn s(&mut self, s: &str) -> &mut Line {
        for &b in s.as_bytes() {
            self.byte(b);
        }
        self
    }

    pub fn bytes(&mut self, s: &[u8]) -> &mut Line {
        for &b in s {
            self.byte(if b.is_ascii_graphic() || b == b' ' { b } else { b'?' });
        }
        self
    }

    pub fn dec(&mut self, mut v: u64) -> &mut Line {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &b in &d[i..] {
            self.byte(b);
        }
        self
    }

    pub fn hex(&mut self, v: u64) -> &mut Line {
        self.s("0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = (v >> (i * 4)) & 0xf;
            if nib != 0 || started || i == 0 {
                started = true;
                self.byte(b"0123456789abcdef"[nib as usize]);
            }
        }
        self
    }

    /// Write the line to every destination, synchronously.
    pub fn emit(&mut self) {
        self.send(true);
    }

    /// Write the line without waiting for the disk: for what many threads
    /// record at once while a process ends, which must not hold up its
    /// teardown. The next synced line (the VM's destruction) puts it on the
    /// disk too; a datagram goes at once either way.
    pub fn emit_unsynced(&mut self) {
        self.send(false);
    }

    fn send(&mut self, sync: bool) {
        let Some(sinks) = SINKS.get() else { return };
        self.buf[self.n] = b'\n';
        let len = self.n + 1;
        for &(fd, file) in &sinks.fds {
            // SAFETY: writing our buffer to our descriptor; F_FULLFSYNC
            // puts it on the disk itself, past the drive's cache.
            unsafe {
                libc::write(fd, self.buf.as_ptr().cast(), len);
                if file && sync {
                    libc::fcntl(fd, libc::F_FULLFSYNC);
                }
            }
        }
    }
}

/// Record an event of the process (`what` and a detail).
pub fn event(what: &str, detail: &[u8]) {
    if active() {
        Line::new().s(what).s(" ").bytes(detail).emit();
    }
}

/// Record the start of framework call `name` with `args`; `sync` as for
/// [`Line::emit`] or [`Line::emit_unsynced`].
pub fn begin(name: &str, args: &[u64], sync: bool) {
    if !active() {
        return;
    }
    let mut l = Line::new();
    l.s("> ").s(name);
    for &a in args {
        l.s(" ").hex(a);
    }
    l.send(sync);
}

/// Record the end of framework call `name`, which returned `rc`.
pub fn end(name: &str, rc: i32, sync: bool) {
    if active() {
        Line::new().s("< ").s(name).s(" = ").hex(rc as u32 as u64).send(sync);
    }
}
