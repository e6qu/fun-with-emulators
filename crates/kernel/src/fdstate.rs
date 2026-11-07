//! What Linux keeps on an open file that the host has no place for: whether
//! its owner (`F_SETOWN_EX`) is a thread, the signal it sends
//! (`F_SETSIG`), its lease (`F_SETLEASE`), and a pipe's capacity
//! (`F_SETPIPE_SZ`).
//!
//! The host signals an owner with `SIGIO` as Linux does, but knows no other
//! signal, no leases and no pipe sizes: these are recorded, read back as
//! set, and checked as Linux checks them. A lease is never broken (the host
//! cannot say when another process opens the file), and a pipe holds what
//! the host's does, whatever size it was given.

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
    /// The lease held (`F_RDLCK` or `F_WRLCK`), if any.
    pub lease: Option<i16>,
}

static STATES: Mutex<BTreeMap<i32, State>> = Mutex::new(BTreeMap::new());

/// Pipes' capacities, by the host pipe's identity (device and inode).
static PIPES: Mutex<Option<HashMap<(u64, u64), u64>>> = Mutex::new(None);

/// A pipe's capacity until one is set (Linux's 16 pages).
pub const DEFAULT_PIPE_SIZE: u64 = 65_536;

/// Descriptor `fd`'s state.
pub fn get(fd: i32) -> State {
    STATES.lock().unwrap_or_else(|e| e.into_inner()).get(&fd).copied().unwrap_or_default()
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
}

/// `new` is a duplicate of `old`: the same open file.
pub fn duplicated(old: i32, new: i32) {
    let mut states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    match states.get(&old).copied() {
        Some(s) => states.insert(new, s),
        None => states.remove(&new),
    };
}

/// The capacity of the pipe with host identity `id`.
pub fn pipe_size(id: (u64, u64)) -> u64 {
    let pipes = PIPES.lock().unwrap_or_else(|e| e.into_inner());
    pipes.as_ref().and_then(|p| p.get(&id)).copied().unwrap_or(DEFAULT_PIPE_SIZE)
}

/// The pipe with host identity `id` has capacity `size` now.
pub fn set_pipe_size(id: (u64, u64), size: u64) {
    let mut pipes = PIPES.lock().unwrap_or_else(|e| e.into_inner());
    pipes.get_or_insert_with(HashMap::new).insert(id, size);
}

/// A capacity asked for, as Linux rounds it: at least a page, and a power
/// of two pages (`None` past what any pipe may have).
pub fn round_pipe_size(size: u64) -> Option<u64> {
    const PAGE: u64 = 4096;
    if size > 1 << 31 {
        return None;
    }
    Some(size.max(PAGE).next_power_of_two())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_sizes_round_as_linux_rounds_them() {
        assert_eq!(round_pipe_size(0), Some(4096));
        assert_eq!(round_pipe_size(4097), Some(8192));
        assert_eq!(round_pipe_size(65536), Some(65536));
        assert_eq!(round_pipe_size(u64::MAX), None);
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
