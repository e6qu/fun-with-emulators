//! What Linux keeps on an open file that the host has no place for: whether
//! its owner (`F_SETOWN_EX`) is a thread, the signal it sends
//! (`F_SETSIG`), whether its open made the file (`F_CREATED_QUERY`), and a
//! pipe's capacity (`F_SETPIPE_SZ`). Leases are [`crate::leases`]'.
//!
//! The host signals an owner with `SIGIO` as Linux does, but knows no other
//! signal and no pipe sizes: a `SIGIO` the host raises for a descriptor
//! with a signal chosen is that signal ([`io_signal`]); a pipe's size is
//! recorded, read back as set, and checked as Linux checks it. A pipe given
//! less than the host's capacity holds no more than that: this process's
//! writes to it are cut to the room Linux's pipe would have
//! ([`capped_write`]), and it is not writable while full ([`pipe_full`]).
//! The room is reckoned as Linux reckons it, in buffers of a page that a
//! write fills and a read frees only once it has read all of one: the
//! process keeps the buffers its writes made, and how many bytes the host
//! pipe holds tells how far reads have taken them.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// What is kept of one descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    /// The thread `F_SETOWN_EX` made the owner (`F_OWNER_TID`), if one
    /// was (the host's owner is then its process).
    pub owner_tid: Option<i32>,
    /// The signal `F_SETSIG` set (0: `SIGIO`).
    pub sig: u32,
    /// The open that made it made the file (`O_CREAT` of one not there).
    pub created: bool,
}

static STATES: Mutex<BTreeMap<i32, State>> = Mutex::new(BTreeMap::new());

/// Pipes' capacities, by the host pipe's identity (device and inode).
static PIPES: Mutex<Option<HashMap<(u64, u64), u64>>> = Mutex::new(None);

/// A pipe's capacity until one is set: what the host's pipe holds (Linux's
/// 16 pages are more, with 16 KiB pages, than a host pipe can take).
pub fn default_pipe_size() -> u64 {
    65_536
}

/// The largest capacity a caller without `CAP_SYS_RESOURCE` may give a pipe
/// (`fs.pipe-max-size`).
pub fn pipe_max_size() -> u64 {
    crate::sysctl::number(b"fs/pipe-max-size").map_or(1_048_576, |n| n.max(0) as u64)
}

/// The capacity a new pipe starts with, made by a caller with `CAP_SYS_RESOURCE`
/// (`privileged`) or without, in the guest's pages of `page` bytes: the
/// default, or no more pages than `fs.pipe-max-size` holds for one without.
pub fn new_pipe_size(privileged: bool, page: u64) -> u64 {
    let max = pipe_max_size();
    let default = default_pipe_size();
    if privileged || max >= default { default } else { (max / page).max(1) * page }
}

/// Descriptor `fd`'s state.
pub fn get(fd: i32) -> State {
    STATES.lock().unwrap_or_else(|e| e.into_inner()).get(&fd).copied().unwrap_or_default()
}

/// The descriptor whose `F_SETSIG` signal stands for a host `SIGIO`: one
/// set to signal (`O_ASYNC`) with a signal chosen, and the owner thread
/// (`F_SETOWN_EX`'s) if one is.
pub fn io_signal() -> Option<(i32, u32, Option<i32>)> {
    let states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    states.iter().find_map(|(&fd, s)| {
        // SAFETY: F_GETFL only queries the descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        (s.sig != 0 && fl >= 0 && fl & libc::O_ASYNC != 0).then_some((fd, s.sig, s.owner_tid))
    })
}

/// Whether any of this process's descriptors is set to signal (`O_ASYNC`).
pub fn any_async() -> bool {
    crate::fdtable::open_fds().into_iter().any(|fd| {
        // SAFETY: F_GETFL only queries the descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        fl >= 0 && fl & libc::O_ASYNC != 0
    })
}

/// Change descriptor `fd`'s state.
pub fn update(fd: i32, f: impl FnOnce(&mut State)) {
    let mut states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = states.get(&fd).copied().unwrap_or_default();
    f(&mut s);
    if s == State::default() {
        states.remove(&fd);
    } else {
        states.insert(fd, s);
    }
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    STATES.lock().unwrap_or_else(|e| e.into_inner()).remove(&fd);
    crate::leases::closed(fd);
}

/// `new` is a duplicate of `old`: the same open file.
pub fn duplicated(old: i32, new: i32) {
    let mut states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    match states.get(&old).copied() {
        Some(s) => states.insert(new, s),
        None => states.remove(&new),
    };
}

/// The write ends of pipes this process made, by their host identity: the
/// read end's identity, which the pipe's capacity is kept under (the host
/// gives a pipe's two ends two identities; a FIFO's share the file's).
static WRITE_ENDS: Mutex<Option<HashMap<PipeId, PipeId>>> = Mutex::new(None);

/// A pipe end's host identity: device and inode.
type PipeId = (u64, u64);

/// A pipe was made: its read end's identity `read`, its write end's
/// `write`.
pub fn pipe_made(read: (u64, u64), write: (u64, u64)) {
    let mut ends = WRITE_ENDS.lock().unwrap_or_else(|e| e.into_inner());
    ends.get_or_insert_with(HashMap::new).insert(write, read);
}

/// The identity a pipe's capacity is kept under, of either end's `id`.
fn pipe_key(id: (u64, u64)) -> (u64, u64) {
    let ends = WRITE_ENDS.lock().unwrap_or_else(|e| e.into_inner());
    ends.as_ref().and_then(|e| e.get(&id)).copied().unwrap_or(id)
}

/// The capacity of the pipe with host identity `id` (either end's).
pub fn pipe_size(id: (u64, u64)) -> u64 {
    let key = pipe_key(id);
    let pipes = PIPES.lock().unwrap_or_else(|e| e.into_inner());
    pipes.as_ref().and_then(|p| p.get(&key)).copied().unwrap_or_else(default_pipe_size)
}

/// The pipe with host identity `id` (either end's) has capacity `size` now.
pub fn set_pipe_size(id: (u64, u64), size: u64) {
    let key = pipe_key(id);
    if size < default_pipe_size() {
        CAPPED.store(true, Ordering::Relaxed);
    }
    let mut pipes = PIPES.lock().unwrap_or_else(|e| e.into_inner());
    pipes.get_or_insert_with(HashMap::new).insert(key, size);
}

/// Whether any pipe was given less than the host's capacity (until one is,
/// writes and polls need not look).
static CAPPED: AtomicBool = AtomicBool::new(false);

/// The page buffers of pipes with less than the host's capacity that this
/// process wrote, by the pipe's identity: each buffer's end in its page
/// (where a write may add to it) and the bytes in it not yet read.
static BUFFERS: Mutex<Option<HashMap<PipeId, Buffers>>> = Mutex::new(None);

/// One pipe's buffers, oldest first: (end in its page, unread bytes).
#[derive(Debug, Default)]
struct Buffers(VecDeque<(u64, u64)>);

impl Buffers {
    /// Brought up to date with the host pipe holding `held` bytes: what
    /// was read is gone, oldest first, a buffer freed once all of it is;
    /// bytes this process did not write (another's writes) taken as
    /// full pages of their own.
    fn sync(&mut self, held: u64, page: u64) {
        let ours: u64 = self.0.iter().map(|b| b.1).sum();
        if held > ours {
            self.0.clear();
            let mut left = held;
            while left > 0 {
                let n = left.min(page);
                self.0.push_back((n, n));
                left -= n;
            }
            return;
        }
        let mut read = ours - held;
        while read > 0 {
            let Some(front) = self.0.front_mut() else { break };
            if front.1 <= read {
                read -= front.1;
                self.0.pop_front();
            } else {
                front.1 -= read;
                read = 0;
            }
        }
    }

    /// Of a write of `len` bytes, the part that a pipe of `slots` page
    /// buffers takes now: the tail of the write shorter than a page added
    /// to the last buffer if it fits there whole, and whole new buffers
    /// for as many free ones as there are.
    fn room(&self, len: u64, page: u64, slots: u64) -> u64 {
        let merged = self.merged(len, page);
        let free = slots.saturating_sub(self.0.len() as u64);
        merged + (len - merged).min(free * page)
    }

    /// What of a write of `len` bytes goes into the last buffer.
    fn merged(&self, len: u64, page: u64) -> u64 {
        let tail = len % page;
        match self.0.back() {
            Some(&(end, _)) if tail > 0 && end + tail <= page => tail,
            _ => 0,
        }
    }

    /// `n` bytes of a write of `len` were written.
    fn wrote(&mut self, len: u64, n: u64, page: u64) {
        let merged = self.merged(len, page).min(n);
        if let Some(last) = self.0.back_mut() {
            last.0 += merged;
            last.1 += merged;
        }
        let mut left = n - merged;
        while left > 0 {
            let k = left.min(page);
            self.0.push_back((k, k));
            left -= k;
        }
    }
}

/// The pipe at `fd` if it has less than the host's capacity: its identity,
/// capacity, and the bytes it holds.
fn capped(fd: i32) -> Option<(PipeId, u64, u64)> {
    if !CAPPED.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return None;
    }
    let id = (st.st_dev as u64, st.st_ino);
    let size = pipe_size(id);
    (size < default_pipe_size()).then(|| (pipe_key(id), size, st.st_size.max(0) as u64))
}

/// Run `f` on the buffers of the capped pipe at `fd`, brought up to date
/// (`None` if the pipe is not capped).
fn with_buffers<T>(fd: i32, f: impl FnOnce(&mut Buffers, u64, u64) -> T) -> Option<T> {
    let (key, size, held) = capped(fd)?;
    let page = crate::maps::page_size();
    let mut all = BUFFERS.lock().unwrap_or_else(|e| e.into_inner());
    let b = all.get_or_insert_with(HashMap::new).entry(key).or_default();
    b.sync(held, page);
    Some(f(b, page, (size / page).max(1)))
}

/// Whether `fd` is a pipe with less than the host's capacity that is full:
/// not writable, as Linux reports it.
pub fn pipe_full(fd: i32) -> bool {
    with_buffers(fd, |b, _, slots| b.0.len() as u64 >= slots).unwrap_or(false)
}

/// A write of `len` bytes to `fd`, if it is a pipe with less than the
/// host's capacity: as much as the pipe has room for at a time, written by
/// `write(offset, count)` (a host write of `count` bytes from `offset` into
/// the data), until all is written, or as much as fits without waiting for
/// a non-blocking descriptor (`EAGAIN` if nothing does), as Linux writes to
/// a pipe. A signal for the guest ends a wait (`EINTR` if nothing was
/// written); readers gone, the host write fails as Linux's does (`EPIPE`).
pub fn capped_write(fd: i32, len: u64, mut write: impl FnMut(u64, u64) -> i64) -> Option<i64> {
    if len == 0 || capped(fd).is_none() {
        return None;
    }
    // SAFETY: F_GETFL only queries the descriptor.
    let nonblock = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0;
    let mut done = 0;
    loop {
        let left = len - done;
        let room = with_buffers(fd, |b, page, slots| b.room(left, page, slots)).unwrap_or(left);
        let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        // SAFETY: one valid pollfd; no wait.
        let hung_up = room == 0
            && unsafe { libc::poll(&mut p, 1, 0) } == 1
            && p.revents & (libc::POLLHUP | libc::POLLERR) != 0;
        if room > 0 || hung_up {
            let r = write(done, if hung_up { left } else { room });
            if r < 0 {
                return Some(if done > 0 { done as i64 } else { r });
            }
            with_buffers(fd, |b, page, _| b.wrote(left, r as u64, page));
            done += r as u64;
            if done == len {
                return Some(done as i64);
            }
            continue;
        }
        if nonblock || crate::thread::deliverable() != 0 {
            let e = if nonblock { fwe_abi::errno::EAGAIN } else { fwe_abi::errno::EINTR };
            return Some(if done > 0 { done as i64 } else { fwe_abi::err(e) });
        }
        crate::thread::nap_ns(1_000_000);
    }
}

/// A capacity asked for, as Linux rounds it in the guest's pages of `page`
/// bytes: at least a page, and a power of two pages (`None` past what any
/// pipe may have).
pub fn round_pipe_size(size: u64, page: u64) -> Option<u64> {
    if size > 1 << 31 {
        return None;
    }
    Some(size.div_ceil(page).max(1).next_power_of_two() * page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_sizes_round_as_linux_rounds_them() {
        for p in [4096, 16384] {
            assert_eq!(round_pipe_size(0, p), Some(p));
            assert_eq!(round_pipe_size(p + 1, p), Some(2 * p));
            assert_eq!(round_pipe_size(3 * p, p), Some(4 * p));
            assert_eq!(round_pipe_size(u64::MAX, p), None);
        }
    }

    #[test]
    fn pipe_buffers_fill_and_free_as_linux_does() {
        let page = 16384;
        let mut b = Buffers::default();
        // A one-page pipe takes one page, then nothing.
        assert_eq!(b.room(page, page, 1), page);
        b.wrote(page, page, page);
        assert_eq!(b.room(page, page, 1), 0);
        // Half read: the buffer is not freed, and has no room after it.
        b.sync(page / 2, page);
        assert_eq!(b.room(1, page, 1), 0);
        // All read: free again.
        b.sync(0, page);
        assert_eq!(b.room(page, page, 1), page);
        // Small writes share a buffer while they fit in it whole.
        b.wrote(100, 100, page);
        assert_eq!(b.room(100, page, 1), 100);
        b.wrote(100, 100, page);
        assert_eq!(b.room(page - 200, page, 1), page - 200);
        assert_eq!(b.room(page - 199, page, 1), 0);
        // Of a longer write, its tail joins the last buffer, the rest takes
        // new ones.
        assert_eq!(b.room(page + 100, page, 2), page + 100);
        // Bytes another process wrote fill pages of their own.
        b.sync(3 * page, page);
        assert_eq!(b.room(1, page, 4), 1);
        assert_eq!(b.room(page, page, 4), page);
    }

    #[test]
    fn state_follows_duplicates_and_closes() {
        let fd = 1_000_001;
        update(fd, |s| s.sig = 10);
        duplicated(fd, fd + 1);
        assert_eq!(get(fd + 1).sig, 10);
        closed(fd);
        assert_eq!(get(fd), State::default());
        update(fd + 1, |s| s.sig = 0);
        assert_eq!(get(fd + 1), State::default());
    }
}
