//! Whole writes to a pipe: Linux writes up to `PIPE_BUF` (4096) bytes to a
//! pipe in one piece, never interleaved with another writer's; the host
//! does so only up to its own `PIPE_BUF` (512), and splits a larger write
//! that waits for room. Writers of such a write to the same pipe, in every
//! fwe process, take turns: an `flock` on one of a few lock files in fwe's
//! private directory, chosen by the pipe's identity (the host lets go of a
//! lock whose holder ends). A write that does not wait (`O_NONBLOCK`) is
//! written whole or not at all (`EAGAIN`), as Linux's is.

/// Linux's `PIPE_BUF`, and the host's.
const LINUX_PIPE_BUF: u64 = 4096;
const HOST_PIPE_BUF: u64 = 512;

/// Lock files: pipes whose identities share one take turns with each
/// other too, briefly.
const LOCKS: usize = 64;

/// This process's descriptors of the lock files, and the process they
/// were opened in (a fork child's are its parent's open files, whose
/// `flock` the two would share, so it opens its own).
static OPEN: std::sync::Mutex<(i32, Vec<i32>)> = std::sync::Mutex::new((0, Vec::new()));

/// The descriptor of lock file `i`, opened if this process has none.
fn lock_fd(i: usize) -> Option<i32> {
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    if open.0 != me {
        // A parent's descriptors stay open (they are the parent's too);
        // this process makes its own.
        *open = (me, vec![-1; LOCKS]);
    }
    if open.1[i] < 0 {
        let mut path = crate::fs::shm::user_dir().ok()?;
        path.extend_from_slice(format!("/pipe-{i}.lock").as_bytes());
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe {
            libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        open.1[i] = crate::fdtable::reserve(fd).ok()?;
    }
    Some(open.1[i])
}

/// A write of `len` bytes to `fd` by `write(offset, count)`, if it is a
/// pipe and a write Linux makes whole that the host may not: whole, the
/// pipe's other writers waiting. `None` for any other write.
pub fn whole_write(fd: i32, len: u64, mut write: impl FnMut(u64, u64) -> i64) -> Option<i64> {
    if len <= HOST_PIPE_BUF || len > LINUX_PIPE_BUF {
        return None;
    }
    let (end, peer) = crate::splice::pipe_ends(fd)?;
    let i =
        (crate::shared::hash(&[end.min(peer).to_ne_bytes(), end.max(peer).to_ne_bytes()].concat())
            % LOCKS as u64) as usize;
    let lock = lock_fd(i)?;
    // SAFETY: F_GETFL only queries the descriptor.
    let nonblock = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0;
    // SAFETY: an `flock` of fwe's own descriptor; a signal ends the wait.
    while unsafe { libc::flock(lock, libc::LOCK_EX) } != 0 {
        if crate::thread::deliverable() != 0 {
            return Some(fwe_abi::err(fwe_abi::errno::EINTR));
        }
    }
    let r = (|| {
        // Not waiting: all of it fits now, or none is written.
        if nonblock && crate::splice::room(fd) < len {
            let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            // SAFETY: one valid pollfd; no wait.
            let hung_up = unsafe { libc::poll(&mut p, 1, 0) } == 1
                && p.revents & (libc::POLLHUP | libc::POLLERR) != 0;
            if !hung_up {
                return fwe_abi::err(fwe_abi::errno::EAGAIN);
            }
        }
        let mut done = 0;
        while done < len {
            let r = write(done, len - done);
            if r <= 0 {
                return if done > 0 { done as i64 } else { r };
            }
            done += r as u64;
        }
        done as i64
    })();
    // SAFETY: as above.
    unsafe { libc::flock(lock, libc::LOCK_UN) };
    Some(r)
}
