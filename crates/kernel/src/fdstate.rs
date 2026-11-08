//! What Linux keeps on an open file that the host has no place for: whether
//! its owner (`F_SETOWN_EX`) is a thread, the signal it sends
//! (`F_SETSIG`), whether its open made the file (`F_CREATED_QUERY`), and a
//! pipe's capacity (`F_SETPIPE_SZ`). Leases are [`crate::leases`]'.
//!
//! The host signals an owner with `SIGIO` as Linux does, but knows no other
//! signal and no pipe sizes: a `SIGIO` the host raises for a descriptor
//! with a signal chosen is that signal ([`io_signal`]); a pipe's size is
//! recorded, read back as set, and checked as Linux checks it, and the pipe
//! holds what the host's does, whatever size it was given.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

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
    let mut pipes = PIPES.lock().unwrap_or_else(|e| e.into_inner());
    pipes.get_or_insert_with(HashMap::new).insert(key, size);
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
