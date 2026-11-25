//! `signalfd`: read pending signals through a file descriptor.
//!
//! The host has no `signalfd`, so it is emulated here: each signalfd is a pipe
//! (for readiness, so it is pollable by `epoll`) and the set of signals it
//! watches. The host never blocks a watched signal, so it always reaches the
//! backend's handler and is recorded pending; a pending signal that the
//! thread blocks and some signalfd watches is then moved onto the process's
//! queue of `signalfd_siginfo` records
//! ([`crate::signal::drain_to_signalfd`]), where it stays pending once, as on
//! Linux: a standard signal is queued once however often it is sent, and a
//! record is taken by the first `read` of any signalfd that watches it. A
//! signalfd's pipe holds a byte exactly while the queue holds a record it
//! watches.

use crate::signal::bit;
use fwe_abi::{err, errno};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

/// Size of `struct signalfd_siginfo`.
pub const SIGINFO_SIZE: usize = 128;

/// The first real-time signal: signals below it are standard ones, pending
/// at most once.
const SIGRTMIN: u32 = 32;

struct SignalFd {
    rfd: i32,
    wfd: i32,
    mask: u64,
    /// Whether its pipe holds the readiness byte.
    ready: bool,
}

/// The signalfds, and the signals moved onto them, in the order they came.
#[derive(Default)]
struct Reg {
    fds: HashMap<i32, SignalFd>,
    queue: VecDeque<[u8; SIGINFO_SIZE]>,
}

impl crate::kept::Table for Reg {
    fn is_empty(&self) -> bool {
        self.fds.is_empty() && self.queue.is_empty()
    }
}

impl Reg {
    /// Give each signalfd its readiness byte while the queue holds a
    /// record it watches, and take it away otherwise.
    fn settle(&mut self) {
        let pending = self.queue.iter().fold(0u64, |m, r| m | bit(u64::from(signo(r))));
        for s in self.fds.values_mut() {
            let want = s.mask & pending != 0;
            if want && !s.ready {
                let b = [0u8];
                // SAFETY: the pipe holds at most one readiness byte.
                unsafe { libc::write(s.wfd, b.as_ptr().cast(), 1) };
            } else if !want && s.ready {
                let mut b = 0u8;
                // SAFETY: the readiness byte is there to take.
                unsafe { libc::read(s.rfd, (&mut b as *mut u8).cast(), 1) };
            }
            s.ready = want;
        }
    }
}

/// The signal a record is of.
fn signo(r: &[u8; SIGINFO_SIZE]) -> u32 {
    u32::from_ne_bytes(r[0..4].try_into().unwrap())
}

static REG: crate::kept::Kept<Option<Reg>> = crate::kept::Kept::new(None);
/// The union of every signalfd's mask, readable without the lock.
static WATCHED: AtomicU64 = AtomicU64::new(0);

fn with<R>(f: impl FnOnce(&mut Reg) -> R) -> R {
    let mut g = REG.lock();
    let reg = g.get_or_insert_with(Reg::default);
    let r = f(reg);
    WATCHED.store(reg.fds.values().fold(0, |m, s| m | s.mask), Ordering::Release);
    r
}

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = REG.lock();
    f()
}

/// Write the registry into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    let mut g = REG.lock();
    let reg = g.get_or_insert_with(Reg::default);
    crate::snapshot::fd_map(e, &reg.fds, |e, s| {
        e.i32(s.rfd);
        e.i32(s.wfd);
        e.u64(s.mask);
        e.bool(s.ready);
    });
    crate::snapshot::queue(e, &reg.queue);
}

/// Rebuild the registry in a fork child (its pipes are inherited).
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let fds = crate::snapshot::read_fd_map(d, |d| SignalFd {
        rfd: d.i32(),
        wfd: d.i32(),
        mask: d.u64(),
        ready: d.bool(),
    });
    let queue = crate::snapshot::read_queue(d);
    with(|m| *m = Reg { fds, queue });
}

/// Whether `fd` is a signalfd.
pub fn is_signalfd(fd: i32) -> bool {
    with(|m| m.fds.contains_key(&fd))
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
        return with(|m| match m.fds.get_mut(&fd) {
            Some(s) => {
                s.mask = mask;
                m.settle();
                fd as i64
            }
            // An open descriptor of another kind (`EINVAL`), or none.
            // SAFETY: F_GETFD only queries the descriptor.
            None if fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 => err(errno::EINVAL),
            None => err(errno::EBADF),
        });
    }
    match make(mask, flags & fcntl::O_CLOEXEC != 0, flags & fcntl::O_NONBLOCK != 0) {
        Ok(rfd) => rfd as i64,
        Err(e) => err(e),
    }
}

/// A new signalfd watching `mask`: its readiness pipe's read end, which
/// the guest holds (its write end is fwe's).
fn make(mask: u64, cloexec: bool, nonblock: bool) -> Result<i32, i32> {
    let mut fds = [0i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    // The write end is fwe's: out of the guest's reach.
    let wfd = match crate::fdtable::reserve(fds[1]) {
        Ok(w) => w,
        Err(e) => {
            // SAFETY: closing the read end made above.
            unsafe { libc::close(fds[0]) };
            return Err(e);
        }
    };
    let rfd = fds[0];
    crate::exclusive::made(rfd);
    if cloexec {
        // SAFETY: plain host call on a fresh descriptor.
        unsafe { libc::fcntl(rfd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    if nonblock {
        // As `F_GETFL` shows it, and `F_SETFL` changes it.
        // SAFETY: plain host call on a fresh descriptor.
        unsafe { libc::fcntl(rfd, libc::F_SETFL, libc::O_NONBLOCK) };
    }
    with(|m| {
        m.fds.insert(rfd, SignalFd { rfd, wfd, mask, ready: false });
        m.settle();
    });
    Ok(rfd)
}

/// What signalfd `fd` takes to another process it is passed to
/// ([`crate::scm`]): its mask and whether it blocks. A signalfd reads its
/// reader's signals, so the receiver makes its own.
#[cfg(not(target_os = "linux"))]
pub(crate) fn export(fd: i32) -> Option<crate::scm::Export> {
    let mask = with(|m| m.fds.get(&fd).map(|s| s.mask))?;
    let mut e = crate::snapshot::Enc::new();
    e.u64(mask);
    // SAFETY: F_GETFL only queries the descriptor.
    e.bool(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0);
    Some(crate::scm::Export {
        kind: crate::scm::kind::SIGNALFD,
        state: e.into_bytes(),
        companions: Vec::new(),
        placeholder: true,
    })
}

/// Make received descriptor `fd` a signalfd as an [`export`] described:
/// whether it was.
#[cfg(not(target_os = "linux"))]
pub(crate) fn import(fd: i32, d: &mut crate::snapshot::Dec) -> bool {
    let (mask, nonblock) = (d.u64(), d.bool());
    let Ok(rfd) = make(mask, false, nonblock) else { return false };
    let s = with(|m| m.fds.remove(&rfd));
    if !crate::scm::replace(fd, rfd) {
        if let Some(s) = s {
            // SAFETY: the write end made above.
            unsafe { libc::close(s.wfd) };
        }
        return false;
    }
    if let Some(mut s) = s {
        s.rfd = fd;
        with(|m| m.fds.insert(fd, s));
    }
    true
}

/// Queue `info` for signal `sig` (1 to 64) on the process's signalfds, if
/// any watches it: a standard signal already queued is not queued again.
/// Returns whether one watches it.
pub fn deliver(sig: u64, info: [u8; SIGINFO_SIZE]) -> bool {
    let sig = sig as u32;
    if bit(u64::from(sig)) == 0 {
        return false;
    }
    with(|m| {
        if !m.fds.values().any(|s| s.mask & bit(u64::from(sig)) != 0) {
            return false;
        }
        if sig >= SIGRTMIN || !m.queue.iter().any(|r| signo(r) == sig) {
            m.queue.push_back(info);
        }
        m.settle();
        true
    })
}

/// Handle `read` on a signalfd. `Some` if `fd` is one of ours.
///
/// # Safety
/// `buf` MUST span `len` writable bytes.
pub unsafe fn try_read(fd: i32, buf: u64, len: u64) -> Option<i64> {
    let rfd = with(|m| m.fds.get(&fd).map(|s| s.rfd))?;
    if (len as usize) < SIGINFO_SIZE {
        return Some(err(errno::EINVAL));
    }
    let max = (len as usize) / SIGINFO_SIZE;
    loop {
        let got = with(|m| {
            let mask = m.fds.get(&fd)?.mask;
            let mut n = 0;
            let mut at = 0;
            while n < max && at < m.queue.len() {
                if bit(u64::from(signo(&m.queue[at]))) & mask == 0 {
                    at += 1;
                    continue;
                }
                let rec = m.queue[at];
                if crate::uaccess::write_from(buf + (n * SIGINFO_SIZE) as u64, &rec).is_err() {
                    // Kept for a later read.
                    if n == 0 {
                        return Some(err(errno::EFAULT));
                    }
                    break;
                }
                m.queue.remove(at);
                n += 1;
            }
            if n == 0 {
                return None;
            }
            m.settle();
            Some((n * SIGINFO_SIZE) as i64)
        });
        match got {
            Some(r) => return Some(r),
            None => {
                // A signal that interrupted the wait below is pending against
                // this thread; queue it if it is one of ours.
                crate::signal::drain_to_signalfd();
                let ready = with(|m| {
                    let mask = m.fds.get(&fd).map_or(0, |s| s.mask);
                    m.queue.iter().any(|r| bit(u64::from(signo(r))) & mask != 0)
                });
                if ready {
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
                    && crate::host::last_errno().is(libc::EINTR)
                    && crate::thread::deliverable() != 0
                {
                    // A signal the guest handles: let it run.
                    return Some(err(errno::EINTR));
                }
            }
        }
    }
}

/// Release a signalfd on `close`. `Some(0)` if it was ours. The records
/// no signalfd left watches go with it.
pub fn try_close(fd: i32) -> Option<i64> {
    let s = {
        let mut g = REG.if_used()?;
        let reg = g.as_mut()?;
        let s = reg.fds.remove(&fd)?;
        let watched = reg.fds.values().fold(0, |m, s| m | s.mask);
        reg.queue.retain(|r| bit(u64::from(signo(r))) & watched != 0);
        WATCHED.store(watched, Ordering::Release);
        s
    };
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
        let _held = crate::thread::signals_held();
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

    /// A signal two signalfds watch is read once, by whichever reads
    /// first; a standard signal sent twice before it is read is pending
    /// once, a real-time one twice.
    #[test]
    fn a_signal_is_taken_once() {
        let _held = crate::thread::signals_held();
        // SIGUSR2 (12) and SIGRTMIN+5 (37).
        let mask = (1u64 << 11) | (1u64 << 36);
        let a = signalfd4(-1, mask, fwe_abi::fcntl::O_NONBLOCK) as i32;
        let b = signalfd4(-1, mask, fwe_abi::fcntl::O_NONBLOCK) as i32;
        assert!(deliver(12, siginfo_full(12, 0, 1, 0, 0, 0)));
        assert!(deliver(12, siginfo_full(12, 0, 1, 0, 0, 0)));
        assert!(read_one(b).is_some());
        assert_eq!(empty_read(a), Some(err(errno::EAGAIN)));
        assert_eq!(empty_read(b), Some(err(errno::EAGAIN)));
        assert!(deliver(37, siginfo_full(37, 0, 1, 0, 0, 0)));
        assert!(deliver(37, siginfo_full(37, 0, 1, 0, 0, 0)));
        assert!(read_one(a).is_some());
        assert!(read_one(b).is_some());
        assert_eq!(empty_read(a), Some(err(errno::EAGAIN)));
        assert_eq!(try_close(a), Some(0));
        assert_eq!(try_close(b), Some(0));
    }

    #[test]
    fn short_buffer_is_einval() {
        let _held = crate::thread::signals_held();
        let fd = signalfd4(-1, 1, fwe_abi::fcntl::O_NONBLOCK) as i32;
        let mut b = [0u8; 8];
        // SAFETY: buffer too small for a siginfo.
        assert_eq!(unsafe { try_read(fd, b.as_mut_ptr() as u64, 8) }, Some(err(errno::EINVAL)));
        try_close(fd);
    }
}
