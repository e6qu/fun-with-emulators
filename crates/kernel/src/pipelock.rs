//! Whole writes to a pipe: Linux writes up to `PIPE_BUF` (4096) bytes to a
//! pipe in one piece, never interleaved with another writer's; the host
//! does so only up to its own `PIPE_BUF` (512), and splits a larger write
//! that waits for room. Writers of such a write to the same pipe, in every
//! fwe process, take turns: a lock of that pipe's own in a page every fwe
//! process maps, held by a process (taken over once its holder has ended).
//! Only writers of that pipe wait for it, so a process that reads one pipe
//! and writes another (a pipeline's middle) never waits on a writer of the
//! first. A write that does not wait (`O_NONBLOCK`) is written whole or
//! not at all (`EAGAIN`), as Linux's is.

/// Linux's `PIPE_BUF`, and the host's.
const LINUX_PIPE_BUF: u64 = 4096;
const HOST_PIPE_BUF: u64 = 512;

/// Locks: pipes being written to so at once ([`crate::keylock`]).
const SLOTS: usize = 256;
/// The table's size ([`crate::procstore::Area::PipeLocks`]).
pub(crate) const BYTES: usize = crate::keylock::bytes(SLOTS);

/// A write of `len` bytes to `fd` by `write(offset, count)`, if it is a
/// pipe and a write Linux makes whole that the host may not: whole, the
/// pipe's other writers waiting. `None` for any other write.
pub fn whole_write(fd: i32, len: u64, mut write: impl FnMut(u64, u64) -> i64) -> Option<i64> {
    if len <= HOST_PIPE_BUF || len > LINUX_PIPE_BUF {
        return None;
    }
    let (end, peer) = crate::splice::pipe_ends(fd)?;
    let held = match crate::keylock::lock(
        crate::procstore::Area::PipeLocks,
        (end.min(peer), end.max(peer)),
        true,
    ) {
        Ok(h) => h,
        Err(e) => return Some(fwe_abi::err(e)),
    };
    // SAFETY: F_GETFL only queries the descriptor.
    let nonblock = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0;
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
    drop(held);
    Some(r)
}
