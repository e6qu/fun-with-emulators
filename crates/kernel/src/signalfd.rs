//! `signalfd`: read pending signals through a file descriptor.
//!
//! The guest's signals are virtual — the kernel tracks them itself rather than
//! as host signals — so `signalfd` cannot be delegated to the host on either
//! platform. It is emulated here: each signalfd is a pipe (for readiness, so it
//! is pollable by `epoll`) plus a queue of `signalfd_siginfo` records and the
//! set of signals it watches. When the guest raises a signal that is blocked
//! and some signalfd watches it, [`deliver`] queues a record instead of leaving
//! it pending, and `read` returns the queued records.

use fwe_abi::{err, errno};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Size of `struct signalfd_siginfo`.
pub const SIGINFO_SIZE: usize = 128;

struct SignalFd {
    rfd: i32,
    wfd: i32,
    mask: u64,
    nonblock: bool,
    queue: VecDeque<[u8; SIGINFO_SIZE]>,
}

static REG: Mutex<Option<HashMap<i32, SignalFd>>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut HashMap<i32, SignalFd>) -> R) -> R {
    let mut g = REG.lock().unwrap();
    f(g.get_or_insert_with(HashMap::new))
}

/// Build a minimal `signalfd_siginfo` for signal `sig`.
pub fn siginfo(sig: u32, pid: u32, status: i32) -> [u8; SIGINFO_SIZE] {
    let mut b = [0u8; SIGINFO_SIZE];
    b[0..4].copy_from_slice(&sig.to_ne_bytes()); // ssi_signo
    b[12..16].copy_from_slice(&pid.to_ne_bytes()); // ssi_pid
    b[48..52].copy_from_slice(&status.to_ne_bytes()); // ssi_status
    b
}

/// `signalfd4(fd, mask, flags)`. `fd == -1` creates a new descriptor; otherwise
/// `fd` is an existing signalfd whose mask is replaced. `mask` is the Linux
/// signal set (bit `sig-1`).
pub fn signalfd4(fd: i32, mask: u64, flags: u64) -> i64 {
    use fwe_abi::fcntl;
    if fd >= 0 {
        return with(|m| match m.get_mut(&fd) {
            Some(s) => {
                s.mask = mask;
                fd as i64
            }
            None => err(errno::EINVAL),
        });
    }
    let mut fds = [0i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return crate::host::last_error();
    }
    let (rfd, wfd) = (fds[0], fds[1]);
    // SAFETY: plain host calls on fresh descriptors.
    unsafe {
        if flags & fcntl::O_CLOEXEC != 0 {
            libc::fcntl(rfd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        libc::fcntl(wfd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let s = SignalFd {
        rfd,
        wfd,
        mask,
        nonblock: flags & fcntl::O_NONBLOCK != 0,
        queue: VecDeque::new(),
    };
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
    let (rfd, nonblock) = with(|m| m.get(&fd).map(|s| (s.rfd, s.nonblock)))?;
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
                // SAFETY: the caller guarantees `max * SIGINFO_SIZE` writable bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        rec.as_ptr(),
                        (buf + (n * SIGINFO_SIZE) as u64) as *mut u8,
                        SIGINFO_SIZE,
                    );
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
                if nonblock {
                    return Some(err(errno::EAGAIN));
                }
                let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
                // SAFETY: a valid single-element pollfd; wait indefinitely.
                unsafe { libc::poll(&mut pfd, 1, -1) };
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
        assert!(!deliver(9, siginfo(9, 1, 0)));
        // A watched one is.
        assert!(deliver(15, siginfo(15, 42, 0)));
        let rec = read_one(fd).expect("one record");
        assert_eq!(u32::from_ne_bytes(rec[0..4].try_into().unwrap()), 15);
        assert_eq!(u32::from_ne_bytes(rec[12..16].try_into().unwrap()), 42);

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
