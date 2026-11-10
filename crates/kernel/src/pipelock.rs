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

use std::sync::atomic::{AtomicU64, Ordering};

/// Linux's `PIPE_BUF`, and the host's.
const LINUX_PIPE_BUF: u64 = 4096;
const HOST_PIPE_BUF: u64 = 512;

/// Locks: pipes being written to so at once. A slot is the pipe's
/// identity (its ends' host handles) and the pid holding it (0: free).
const SLOTS: usize = 256;
const SLOT_WORDS: usize = 3;

static TABLE: std::sync::OnceLock<Option<&'static [AtomicU64]>> = std::sync::OnceLock::new();

/// The shared page, mapped on first use.
fn table() -> Option<&'static [AtomicU64]> {
    *TABLE.get_or_init(|| {
        let mut path = crate::fs::shm::user_dir().ok()?;
        path.extend_from_slice(b"/pipe-locks");
        let c = std::ffi::CString::new(path).ok()?;
        let len = SLOTS * SLOT_WORDS * 8;
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe {
            libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: plain host calls on the descriptor just opened; a file
        // shorter than the table is grown with zeros.
        let map = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) == 0 && (st.st_size as usize) < len {
                libc::ftruncate(fd, len as libc::off_t);
            }
            let m = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            m
        };
        if map == libc::MAP_FAILED {
            return None;
        }
        // SAFETY: the mapping is `len` bytes, page-aligned, shared and never
        // unmapped; every access is atomic.
        Some(unsafe { std::slice::from_raw_parts(map as *const AtomicU64, len / 8) })
    })
}

/// The lock that makes a pipe's slot, held only while it is looked for
/// or made (never while waiting for a pipe).
struct MakeLock(i32);

impl MakeLock {
    fn take() -> Option<MakeLock> {
        let mut path = crate::fs::shm::user_dir().ok()?;
        path.extend_from_slice(b"/pipe-locks.lock");
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: a NUL-terminated path; the lock goes with the descriptor.
        let fd = unsafe {
            libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: plain host call on the descriptor just opened.
        crate::shared::lock_exclusive(fd);
        Some(MakeLock(fd))
    }
}

impl Drop for MakeLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor `take` opened; closing it lets go.
        unsafe { libc::close(self.0) };
    }
}

/// Whether host process `pid`, a lock's holder, has ended.
fn ended(pid: u64) -> bool {
    // SAFETY: signal 0 only asks whether the process exists.
    pid != 0
        && unsafe { libc::kill(pid as i32, 0) } != 0
        && crate::host::last_errno() == libc::ESRCH
}

/// Take the lock of the pipe with identity `(lo, hi)`: its slot, or `None`
/// if the table has no room (the write then goes as the host makes it), or
/// `Err` for a signal for the guest while waiting.
fn lock(t: &'static [AtomicU64], (lo, hi): (u64, u64)) -> Result<Option<usize>, i32> {
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() } as u64;
    let slot = |i: usize| &t[i * SLOT_WORDS..(i + 1) * SLOT_WORDS];
    // The pipe's slot, made if it has none: under the making lock, so two
    // writers of a pipe agree on one.
    let i = {
        let _make = MakeLock::take();
        let found = (0..SLOTS).find(|&i| {
            let s = slot(i);
            s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi
        });
        match found {
            Some(i) => i,
            None => {
                // A free slot (or one whose holder has ended), taken now.
                let Some(i) = (0..SLOTS).find(|&i| {
                    let h = slot(i)[2].load(Ordering::Acquire);
                    (h == 0 || ended(h))
                        && slot(i)[2]
                            .compare_exchange(h, me, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                }) else {
                    return Ok(None);
                };
                slot(i)[0].store(lo, Ordering::Release);
                slot(i)[1].store(hi, Ordering::Release);
                return Ok(Some(i));
            }
        }
    };
    let s = slot(i);
    loop {
        let h = s[2].load(Ordering::Acquire);
        if (h == 0 || ended(h))
            && s[2].compare_exchange(h, me, Ordering::AcqRel, Ordering::Acquire).is_ok()
        {
            // Still this pipe's (a slot freed may be made another's).
            if s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi {
                return Ok(Some(i));
            }
            s[2].store(0, Ordering::Release);
            return lock(t, (lo, hi));
        }
        if crate::thread::deliverable() != 0 {
            return Err(fwe_abi::errno::EINTR);
        }
        crate::thread::nap_ns(200_000);
    }
}

/// A write of `len` bytes to `fd` by `write(offset, count)`, if it is a
/// pipe and a write Linux makes whole that the host may not: whole, the
/// pipe's other writers waiting. `None` for any other write.
pub fn whole_write(fd: i32, len: u64, mut write: impl FnMut(u64, u64) -> i64) -> Option<i64> {
    if len <= HOST_PIPE_BUF || len > LINUX_PIPE_BUF {
        return None;
    }
    let (end, peer) = crate::splice::pipe_ends(fd)?;
    let t = table()?;
    let i = match lock(t, (end.min(peer), end.max(peer))) {
        Ok(Some(i)) => i,
        Ok(None) => return None,
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
    t[i * SLOT_WORDS + 2].store(0, Ordering::Release);
    Some(r)
}
