//! `signalfd`: read pending signals through a file descriptor.
//!
//! The host has no `signalfd`, so it is emulated here: each signalfd is a pipe
//! (for readiness, so it is pollable by `epoll`) plus a queue of
//! `signalfd_siginfo` records and the set of signals it watches. The host
//! never blocks a watched signal, so it always reaches the backend's handler
//! and is recorded pending; a pending signal that the thread blocks and some
//! signalfd watches is then moved onto that signalfd
//! ([`crate::signal::drain_to_signalfd`]), and `read` returns the queued
//! records.

use fwe_abi::{err, errno};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Size of `struct signalfd_siginfo`.
pub const SIGINFO_SIZE: usize = 128;

struct SignalFd {
    rfd: i32,
    wfd: i32,
    mask: u64,
    queue: VecDeque<[u8; SIGINFO_SIZE]>,
}

static REG: Mutex<Option<HashMap<i32, SignalFd>>> = Mutex::new(None);
/// The union of every signalfd's mask, readable without the lock.
static WATCHED: AtomicU64 = AtomicU64::new(0);

fn with<R>(f: impl FnOnce(&mut HashMap<i32, SignalFd>) -> R) -> R {
    let mut g = REG.lock().unwrap_or_else(|e| e.into_inner());
    let reg = g.get_or_insert_with(HashMap::new);
    let r = f(reg);
    WATCHED.store(reg.values().fold(0, |m, s| m | s.mask), Ordering::Release);
    r
}

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = REG.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Write the registry into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    with(|m| {
        crate::snapshot::fd_map(e, m, |e, s| {
            e.i32(s.rfd);
            e.i32(s.wfd);
            e.u64(s.mask);
            crate::snapshot::queue(e, &s.queue);
        })
    })
}

/// Rebuild the registry in a fork child (its pipes are inherited).
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let reg = crate::snapshot::read_fd_map(d, |d| SignalFd {
        rfd: d.i32(),
        wfd: d.i32(),
        mask: d.u64(),
        queue: crate::snapshot::read_queue(d),
    });
    with(|m| *m = reg);
}

/// Whether `fd` is a signalfd.
pub fn is_signalfd(fd: i32) -> bool {
    with(|m| m.contains_key(&fd))
}

/// The signals some signalfd watches (a Linux set).
pub fn watched() -> u64 {
    WATCHED.load(Ordering::Acquire)
}

/// Build a `signalfd_siginfo` for signal `sig` with its code, sender (as
/// the guest sees it), status and value.
pub fn siginfo_full(
    sig: u32,
    code: i32,
    pid: i32,
    uid: u32,
    status: i32,
    value: u64,
) -> [u8; SIGINFO_SIZE] {
    let mut b = [0u8; SIGINFO_SIZE];
    b[0..4].copy_from_slice(&sig.to_ne_bytes()); // ssi_signo
    b[8..12].copy_from_slice(&code.to_ne_bytes()); // ssi_code
    b[12..16].copy_from_slice(&pid.to_ne_bytes()); // ssi_pid
    b[16..20].copy_from_slice(&uid.to_ne_bytes()); // ssi_uid
    b[40..44].copy_from_slice(&status.to_ne_bytes()); // ssi_status
    b[44..48].copy_from_slice(&(value as u32).to_ne_bytes()); // ssi_int
    b[48..56].copy_from_slice(&value.to_ne_bytes()); // ssi_ptr
    b
}

/// `signalfd4(fd, mask, flags)`. `fd == -1` creates a new descriptor; otherwise
/// `fd` is an existing signalfd whose mask is replaced. `mask` is the Linux
/// signal set (bit `sig-1`).
pub fn signalfd4(fd: i32, mask: u64, flags: u64) -> i64 {
    use fwe_abi::fcntl;
    if flags & !(fcntl::O_CLOEXEC | fcntl::O_NONBLOCK) != 0 {
        return err(errno::EINVAL);
    }
    if fd != -1 {
        return with(|m| match m.get_mut(&fd) {
            Some(s) => {
                s.mask = mask;
                fd as i64
            }
            // An open descriptor of another kind (`EINVAL`), or none.
            // SAFETY: F_GETFD only queries the descriptor.
            None if fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 => err(errno::EINVAL),
            None => err(errno::EBADF),
        });
    }
    let mut fds = [0i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return crate::host::last_error();
    }
    // The write end is fwe's: out of the guest's reach.
    let wfd = match crate::fdtable::reserve(fds[1]) {
        Ok(w) => w,
        Err(e) => {
            // SAFETY: closing the read end made above.
            unsafe { libc::close(fds[0]) };
            return fwe_abi::err(e);
        }
    };
    let rfd = fds[0];
    if flags & fcntl::O_CLOEXEC != 0 {
        // SAFETY: plain host call on a fresh descriptor.
        unsafe { libc::fcntl(rfd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    if flags & fcntl::O_NONBLOCK != 0 {
        // As `F_GETFL` shows it, and `F_SETFL` changes it.
        // SAFETY: plain host call on a fresh descriptor.
        unsafe { libc::fcntl(rfd, libc::F_SETFL, libc::O_NONBLOCK) };
    }
    let s = SignalFd { rfd, wfd, mask, queue: VecDeque::new() };
    with(|m| m.insert(rfd, s));
    rfd as i64
}

/// Queue `info` on every signalfd that watches signal `sig` (bit `sig-1`).
/// Returns true if at least one took it.
pub fn deliver(sig: u64, info: [u8; SIGINFO_SIZE]) -> bool {
    if sig == 0 || sig > 64 {
        return false;
    }
    let bit = 1u64 << (sig - 1);
    with(|m| {
        let mut took = false;
        for s in m.values_mut() {
            if s.mask & bit != 0 {
                let was_empty = s.queue.is_empty();
                s.queue.push_back(info);
                if was_empty {
                    let b = [0u8];
                    // SAFETY: the pipe holds at most one readiness byte.
                    unsafe { libc::write(s.wfd, b.as_ptr() as *const _, 1) };
                }
                took = true;
            }
        }
        took
    })
}

/// Handle `read` on a signalfd. `Some` if `fd` is one of ours.
///
/// # Safety
/// `buf` must span `len` writable bytes.
pub unsafe fn try_read(fd: i32, buf: u64, len: u64) -> Option<i64> {
    let rfd = with(|m| m.get(&fd).map(|s| s.rfd))?;
    if (len as usize) < SIGINFO_SIZE {
        return Some(err(errno::EINVAL));
    }
    let max = (len as usize) / SIGINFO_SIZE;
    loop {
        let got = with(|m| {
            let s = m.get_mut(&fd)?;
            if s.queue.is_empty() {
                return None;
            }
            let mut n = 0;
            while n < max {
                let Some(rec) = s.queue.pop_front() else { break };
                if crate::uaccess::write_from(buf + (n * SIGINFO_SIZE) as u64, &rec).is_err() {
                    // Keep the record for a later read.
                    s.queue.push_front(rec);
                    if n == 0 {
                        return Some(err(errno::EFAULT));
                    }
                    break;
                }
                n += 1;
            }
            if s.queue.is_empty() {
                let mut b = 0u8;
                // SAFETY: a readiness byte is present when the queue drains.
                unsafe { libc::read(s.rfd, &mut b as *mut _ as *mut _, 1) };
            }
            Some((n * SIGINFO_SIZE) as i64)
        });
        match got {
            Some(r) => return Some(r),
            None => {
                // A signal that interrupted the wait below is pending against
                // this thread; queue it if it is one of ours.
                crate::signal::drain_to_signalfd();
                if with(|m| m.get(&fd).is_some_and(|s| !s.queue.is_empty())) {
                    continue;
                }
                // As `signalfd4` or `F_SETFL` last set it.
                // SAFETY: F_GETFL only queries the descriptor.
                if unsafe { libc::fcntl(rfd, libc::F_GETFL) } & libc::O_NONBLOCK != 0 {
                    return Some(err(errno::EAGAIN));
                }
                let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
                // SAFETY: a valid single-element pollfd; wait indefinitely.
                if unsafe { libc::poll(&mut pfd, 1, -1) } < 0
                    && crate::host::last_errno() == libc::EINTR
                    && crate::thread::deliverable() != 0
                {
                    // A signal the guest handles: let it run.
                    return Some(err(errno::EINTR));
                }
            }
        }
    }
}

/// Release a signalfd on `close`. `Some(0)` if it was ours.
pub fn try_close(fd: i32) -> Option<i64> {
    let s = with(|m| m.remove(&fd))?;
    // SAFETY: both ends were opened by this module.
    unsafe {
        libc::close(s.rfd);
        libc::close(s.wfd);
    }
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_one(fd: i32) -> Option<[u8; SIGINFO_SIZE]> {
        let mut buf = [0u8; SIGINFO_SIZE];
        // SAFETY: `buf` is SIGINFO_SIZE writable bytes.
        let r = unsafe { try_read(fd, buf.as_mut_ptr() as u64, SIGINFO_SIZE as u64) }?;
        if r == SIGINFO_SIZE as i64 { Some(buf) } else { None }
    }

    fn empty_read(fd: i32) -> Option<i64> {
        let mut buf = [0u8; SIGINFO_SIZE];
        // SAFETY: `buf` is SIGINFO_SIZE writable bytes.
        unsafe { try_read(fd, buf.as_mut_ptr() as u64, SIGINFO_SIZE as u64) }
    }

    #[test]
    fn queued_signal_reads_back() {
        // Watch SIGUSR1 (10) and SIGTERM (15), non-blocking.
        let mask = (1u64 << (10 - 1)) | (1u64 << (15 - 1));
        let fd = signalfd4(-1, mask, fwe_abi::fcntl::O_NONBLOCK) as i32;
        assert!(fd >= 0);

        // Empty: EAGAIN.
        assert_eq!(empty_read(fd), Some(err(errno::EAGAIN)));

        // An unwatched signal is not taken.
        assert!(!deliver(9, siginfo_full(9, 0, 1, 0, 0, 0)));
        // A watched one is.
        assert!(deliver(15, siginfo_full(15, -3, 42, 0, 7, 0x1234)));
        let rec = read_one(fd).expect("one record");
        let word = |at: usize| u32::from_ne_bytes(rec[at..at + 4].try_into().unwrap());
        // `ssi_signo`, `ssi_pid`, `ssi_status`, `ssi_int` and `ssi_ptr`.
        assert_eq!((word(0), word(12), word(40), word(44)), (15, 42, 7, 0x1234));
        assert_eq!(u64::from_ne_bytes(rec[48..56].try_into().unwrap()), 0x1234);

        // Drained again.
        assert_eq!(empty_read(fd), Some(err(errno::EAGAIN)));
        assert_eq!(try_close(fd), Some(0));
    }

    #[test]
    fn short_buffer_is_einval() {
        let fd = signalfd4(-1, 1, fwe_abi::fcntl::O_NONBLOCK) as i32;
        let mut b = [0u8; 8];
        // SAFETY: buffer too small for a siginfo.
        assert_eq!(unsafe { try_read(fd, b.as_mut_ptr() as u64, 8) }, Some(err(errno::EINVAL)));
        try_close(fd);
    }
}
