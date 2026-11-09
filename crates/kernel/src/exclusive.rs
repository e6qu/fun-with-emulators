//! `EPOLLEXCLUSIVE` across processes: a write to a pipe that several epoll
//! sets wait on with it wakes one of them, as Linux's does, where every
//! host kqueue watching the pipe fires.
//!
//! A page every fwe process maps (in fwe's private directory) holds a slot
//! per pipe some set watches exclusively, by the pipe's host identity:
//! how many writes it has had, and how many of them a waiter took. A write
//! counts one more ([`wrote`]); a set whose wait such a write ended takes
//! one ([`take`]), and one that finds none left was not the one woken: it
//! waits again ([`wait_for_write`]). A set that finds the pipe ready when
//! it asks, without waiting, takes every write there is ([`take_all`]):
//! the readiness was there before it, for whoever asks. An edge-triggered
//! set sees a counted pipe readable anew when it was written to, not when
//! it holds more ([`crate::epoll`]).
//!
//! Only writes the guest makes with `write` and `writev` are counted.

use std::sync::atomic::{AtomicU64, Ordering};

/// Slots: pipes watched exclusively at once.
const SLOTS: usize = 127;
/// A slot: the pipe's identity (its two ends' host handles), writes,
/// writes taken.
const SLOT_WORDS: usize = 4;

/// The page: a count of slots in use, then the slots.
struct Table {
    words: &'static [AtomicU64],
}

static TABLE: std::sync::OnceLock<Option<Table>> = std::sync::OnceLock::new();

/// The shared page, mapped on first use.
fn table() -> Option<&'static Table> {
    // On Linux, epoll is the host's, which does this itself.
    if cfg!(target_os = "linux") {
        return None;
    }
    TABLE
        .get_or_init(|| {
            let mut path = crate::fs::shm::user_dir().ok()?;
            path.extend_from_slice(b"/epoll-exclusive");
            let c = std::ffi::CString::new(path).ok()?;
            let len = (1 + SLOTS * SLOT_WORDS) * 8;
            // SAFETY: a NUL-terminated path in fwe's private directory.
            let fd = unsafe {
                libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
            };
            if fd < 0 {
                return None;
            }
            // SAFETY: plain host calls on the descriptor just opened. A
            // file shorter than the page is grown with zeros; one of that
            // size already is left as it is.
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
            // SAFETY: the mapping is `len` bytes, page-aligned, shared and
            // never unmapped; every access is atomic.
            let words = unsafe { std::slice::from_raw_parts(map as *const AtomicU64, len / 8) };
            Some(Table { words })
        })
        .as_ref()
}

impl Table {
    fn in_use(&self) -> &AtomicU64 {
        &self.words[0]
    }
    fn slot(&self, i: usize) -> &[AtomicU64] {
        &self.words[1 + i * SLOT_WORDS..1 + (i + 1) * SLOT_WORDS]
    }
    /// The slot of the pipe with identity `(lo, hi)`, made if `make`.
    fn find(&self, (lo, hi): (u64, u64), make: bool) -> Option<&[AtomicU64]> {
        let used = (self.in_use().load(Ordering::Acquire) as usize).min(SLOTS);
        if let Some(s) = (0..used)
            .map(|i| self.slot(i))
            .find(|s| s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi)
        {
            return Some(s);
        }
        if !make {
            return None;
        }
        // A new slot, made under a lock so that two makers of the same
        // pipe's agree.
        let _lock = Lock::take()?;
        let used = (self.in_use().load(Ordering::Acquire) as usize).min(SLOTS);
        if let Some(s) = (0..used)
            .map(|i| self.slot(i))
            .find(|s| s[0].load(Ordering::Acquire) == lo && s[1].load(Ordering::Acquire) == hi)
        {
            return Some(s);
        }
        // A new slot, or when all are in use, one with no write left to
        // take (a pipe long gone, most likely; one still watched wakes
        // every set again, as without a slot).
        let s = if used < SLOTS {
            self.slot(used)
        } else {
            (0..SLOTS)
                .map(|i| self.slot(i))
                .find(|s| s[3].load(Ordering::Acquire) >= s[2].load(Ordering::Acquire))?
        };
        s[0].store(lo, Ordering::Release);
        s[1].store(hi, Ordering::Release);
        s[2].store(0, Ordering::Release);
        s[3].store(0, Ordering::Release);
        if used < SLOTS {
            self.in_use().store(used as u64 + 1, Ordering::Release);
        }
        Some(s)
    }
}

/// The lock that makes slots.
struct Lock(i32);

impl Lock {
    fn take() -> Option<Lock> {
        let mut path = crate::fs::shm::user_dir().ok()?;
        path.extend_from_slice(b"/epoll-exclusive.lock");
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: a NUL-terminated path; the lock goes with the descriptor.
        let fd = unsafe {
            libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: plain host call on the descriptor just opened.
        unsafe { libc::flock(fd, libc::LOCK_EX) };
        Some(Lock(fd))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the descriptor `take` opened; closing it drops the lock.
        unsafe { libc::close(self.0) };
    }
}

/// The identity of the pipe open as `fd`, if it is one: the same for both
/// of its ends (the host gives each end an inode of its own).
fn pipe_id(fd: i32) -> Option<(u64, u64)> {
    let (end, peer) = crate::splice::pipe_ends(fd)?;
    Some((end.min(peer), end.max(peer)))
}

/// The guest made a pipe, one end open as `fd`: a slot left by a pipe
/// gone that had its identity (the host reuses them) starts again.
pub fn made(fd: i32) {
    if let Some(s) = slot_of(fd) {
        s[2].store(0, Ordering::Release);
        s[3].store(0, Ordering::Release);
    }
}

/// An epoll set watches the pipe open as `fd` exclusively: its writes are
/// counted from now on.
pub fn watch(fd: i32) {
    if let (Some(t), Some(id)) = (table(), pipe_id(fd)) {
        t.find(id, true);
    }
}

/// The guest wrote to `fd`: one more write for whoever watches it
/// exclusively, and those waiting for one are woken to try for it.
pub fn wrote(fd: i32) {
    let Some(t) = table() else { return };
    if t.in_use().load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some(s) = pipe_id(fd).and_then(|id| t.find(id, false)) {
        s[2].fetch_add(1, Ordering::AcqRel);
        crate::shared::wake_word(&s[2]);
    }
}

/// The slot of the pipe open as `fd`, if it is watched exclusively.
fn slot_of(fd: i32) -> Option<&'static [AtomicU64]> {
    let t = table()?;
    if t.in_use().load(Ordering::Acquire) == 0 {
        return None;
    }
    t.find(pipe_id(fd)?, false)
}

/// A wait on `fd` ended: whether this set takes a write, being the one it
/// woke (true too for a descriptor no slot counts).
pub fn take(fd: i32) -> bool {
    let Some(s) = slot_of(fd) else { return true };
    let mut taken = s[3].load(Ordering::Acquire);
    loop {
        if taken >= s[2].load(Ordering::Acquire) {
            return false;
        }
        match s[3].compare_exchange(taken, taken + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(now) => taken = now,
        }
    }
}

/// `fd` was ready when asked: every write so far is taken.
pub fn take_all(fd: i32) {
    if let Some(s) = slot_of(fd) {
        s[3].fetch_max(s[2].load(Ordering::Acquire), Ordering::AcqRel);
    }
}

/// The writes to `fd` so far, to wait for another with
/// [`wait_for_write`].
pub fn writes(fd: i32) -> Option<u64> {
    slot_of(fd).map(|s| s[2].load(Ordering::Acquire))
}

/// Wait up to `slice` for a write to `fd` after the `seen`th.
pub fn wait_for_write(fd: i32, seen: u64, slice: std::time::Duration) {
    match slot_of(fd) {
        Some(s) => crate::shared::wait_word_for(&s[2], seen, slice),
        None => std::thread::sleep(slice),
    }
}
