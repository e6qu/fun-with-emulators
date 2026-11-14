//! Where the process records ([`crate::procreg`]) are kept: memory every
//! fwe process of the user maps, a file in fwe's private directory. A
//! record read or written is memory read or written, where a file of its
//! own each cost the host a file's making, opening and removal (tens of
//! microseconds each, more than the rest of a `fork`).
//!
//! - **Entries**, one for each host pid: a lock, a sequence number (odd
//!   while the record changes), where the record's bytes are and how many,
//!   and the Linux wait status the process left as it ended of a signal.
//!   A bit for each pid with a record lets a listing skip the rest.
//! - **Blocks** of 4 KiB hold the bytes, chained, taken from and given back
//!   to a bitmap of free ones.
//! - **Ended accounts** (how a process ended, for its reaper): a table of
//!   their own, each taken whole by one reaper.
//!
//! A reader takes no lock: it reads the sequence number, the bytes and the
//! number again, and reads again if a change came between. A writer holds
//! the entry's lock ([`lock`]), writes the new bytes into blocks of its
//! own, makes them the record's, and only then frees the old ones. The
//! lock names its holder's pid: one left by a process that died holding
//! it is taken over.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};

/// Host pids with an entry: those below this (macOS's end at 99999).
const PIDS: usize = 1 << 17;
/// Ended accounts kept at once.
const ENDED: usize = 4096;
/// A block's size, and how many there are (records of 256 MiB at most).
const BLOCK: usize = 4096;
const BLOCKS: usize = 1 << 16;
/// A block's room for bytes, past its link to the next.
const ROOM: usize = BLOCK - 4;

#[repr(C)]
struct Entry {
    /// The pid of the process holding the lock, or 0.
    lock: AtomicU32,
    seq: AtomicU32,
    /// The first block (from 1; 0 for no record) and the record's length.
    head: AtomicU32,
    len: AtomicU32,
    /// How the process ended of a signal ([`set_end`]), with [`END_SET`].
    end: AtomicU32,
    _pad: AtomicU32,
}

const END_SET: u32 = 1 << 31;

#[repr(C)]
struct Ended {
    /// [`FREE`], [`FILLING`], [`FULL`] or [`TAKING`], and a generation
    /// above, bumped by every change.
    state: AtomicU32,
    pid: AtomicU32,
    start: AtomicU64,
    head: AtomicU32,
    len: AtomicU32,
}

const FREE: u32 = 0;
const FILLING: u32 = 1;
const FULL: u32 = 2;
const TAKING: u32 = 3;

fn st(state: u32) -> u32 {
    state & 0xff
}

fn next(state: u32, st: u32) -> u32 {
    (state.wrapping_add(0x100) & !0xff) | st
}

/// The store's layout: where each part starts in the file.
const ENTRIES_AT: usize = 64;
const USED_AT: usize = ENTRIES_AT + PIDS * size_of::<Entry>();
const ENDED_AT: usize = USED_AT + PIDS / 8;
const FREE_HINT_AT: usize = ENDED_AT + ENDED * size_of::<Ended>();
const TAKEN_AT: usize = FREE_HINT_AT + 64;
const BLOCKS_AT: usize = (TAKEN_AT + BLOCKS / 8).div_ceil(BLOCK) * BLOCK;
const SIZE: usize = BLOCKS_AT + BLOCKS * BLOCK;

/// The store, mapped once per process.
struct Store {
    base: usize,
}

static STORE: OnceLock<Option<Store>> = OnceLock::new();

fn map() -> Option<Store> {
    let mut path = crate::fs::shm::user_dir().ok()?;
    path.extend_from_slice(format!("/v{}-processes", crate::shared::FORMAT).as_bytes());
    let path = std::ffi::CString::new(path).ok()?;
    // SAFETY: plain host calls; the file is fwe's own, and the mapping is
    // kept for the process's life.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd < 0 {
            return None;
        }
        // Zeroes (nothing recorded, every block free) the first time, the
        // same size after; the host keeps only the pages written.
        let sized = libc::ftruncate(fd, SIZE as libc::off_t) == 0;
        let p = libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        (sized && p != libc::MAP_FAILED).then_some(Store { base: p as usize })
    }
}

fn store() -> Option<&'static Store> {
    STORE.get_or_init(map).as_ref()
}

/// Map the store now, so that [`end_status`] (from a signal handler) finds
/// it mapped.
pub fn init() {
    store();
}

impl Store {
    fn at<T>(&self, offset: usize) -> &T {
        // SAFETY: an offset inside the mapping, of a value of atomics only
        // (every bit pattern valid), the mapping kept for the process's life.
        unsafe { &*((self.base + offset) as *const T) }
    }

    fn entry(&self, pid: i32) -> Option<&Entry> {
        let i = usize::try_from(pid).ok().filter(|&i| i > 0 && i < PIDS)?;
        Some(self.at(ENTRIES_AT + i * size_of::<Entry>()))
    }

    fn used(&self, word: usize) -> &AtomicU64 {
        self.at(USED_AT + word * 8)
    }

    fn ended(&self, i: usize) -> &Ended {
        self.at(ENDED_AT + i * size_of::<Ended>())
    }

    fn taken(&self, word: usize) -> &AtomicU64 {
        self.at(TAKEN_AT + word * 8)
    }

    /// The lowest word of the block bitmap that may have a free block.
    fn free_hint(&self) -> &AtomicU32 {
        self.at(FREE_HINT_AT)
    }

    /// Block `b` (from 1): its link to the next (0 for none) and its room.
    fn block(&self, b: u32) -> (&AtomicU32, *mut u8) {
        let at = BLOCKS_AT + (b as usize - 1) * BLOCK;
        (self.at(at), (self.base + at + 4) as *mut u8)
    }

    /// Take a free block, as `pid`'s.
    fn take_block(&self) -> Option<u32> {
        let words = BLOCKS / 64;
        let from = (self.free_hint().load(SeqCst) as usize).min(words);
        for w in (from..words).chain(0..from) {
            let word = self.taken(w);
            let mut cur = word.load(SeqCst);
            while cur != u64::MAX {
                let bit = (!cur).trailing_zeros();
                match word.compare_exchange(cur, cur | 1 << bit, SeqCst, SeqCst) {
                    Ok(_) => {
                        self.free_hint().fetch_max(w as u32, SeqCst);
                        return Some((w * 64) as u32 + bit + 1);
                    }
                    Err(now) => cur = now,
                }
            }
        }
        None
    }

    fn free_chain(&self, mut b: u32, mut len: usize) {
        // As many blocks as the bytes took, at most (a chain is never
        // followed further than its length says).
        loop {
            if b == 0 || b as usize > BLOCKS {
                return;
            }
            let (link, _) = self.block(b);
            let nxt = link.load(SeqCst);
            let w = (b as usize - 1) / 64;
            self.taken(w).fetch_and(!(1 << ((b - 1) % 64)), SeqCst);
            self.free_hint().fetch_min(w as u32, SeqCst);
            if len <= ROOM {
                return;
            }
            len -= ROOM;
            b = nxt;
        }
    }

    /// Write `bytes` into new blocks: the first, or `None` if there is no
    /// room (what was taken given back).
    fn write_chain(&self, bytes: &[u8]) -> Option<u32> {
        let mut chunks: Vec<&[u8]> = bytes.chunks(ROOM).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let mut blocks = Vec::with_capacity(chunks.len());
        for _ in &chunks {
            match self.take_block() {
                Some(b) => blocks.push(b),
                None => {
                    for &b in &blocks {
                        self.free_chain(b, 0);
                    }
                    return None;
                }
            }
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let (link, room) = self.block(blocks[i]);
            link.store(blocks.get(i + 1).copied().unwrap_or(0), SeqCst);
            // SAFETY: a block this writer took, `ROOM` bytes from `room`.
            unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), room, chunk.len()) };
        }
        Some(blocks[0])
    }

    /// The `len` bytes of the chain from block `b`, as they read now (the
    /// caller checks they were not changed meanwhile); `None` if the chain
    /// is not whole.
    fn read_chain(&self, mut b: u32, len: usize) -> Option<Vec<u8>> {
        if len > BLOCKS * ROOM {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(len);
        while out.len() < len {
            if b == 0 || b as usize > BLOCKS {
                return None;
            }
            let (link, room) = self.block(b);
            let n = (len - out.len()).min(ROOM);
            let at = out.len();
            // SAFETY: `n` bytes of a block's room into spare capacity of
            // `out`, then counted.
            unsafe {
                std::ptr::copy_nonoverlapping(room, out.as_mut_ptr().add(at), n);
                out.set_len(at + n);
            }
            b = link.load(SeqCst);
        }
        Some(out)
    }
}

/// The record bytes of host pid `pid`, if it has a record.
pub fn get(pid: i32) -> Option<Vec<u8>> {
    let s = store()?;
    let e = s.entry(pid)?;
    for round in 0..10_000 {
        let seq = e.seq.load(SeqCst);
        if seq % 2 == 0 {
            let (head, len) = (e.head.load(SeqCst), e.len.load(SeqCst) as usize);
            let bytes = if head == 0 { Some(None) } else { s.read_chain(head, len).map(Some) };
            if e.seq.load(SeqCst) == seq
                && let Some(bytes) = bytes
            {
                return bytes;
            }
        }
        if round > 16 {
            std::thread::yield_now();
        }
    }
    None
}

/// Which version of host pid `pid`'s record there is: it changes with
/// every write ([`put`], [`remove`]).
pub fn version(pid: i32) -> Option<u32> {
    Some(store()?.entry(pid)?.seq.load(SeqCst))
}

/// A held record lock ([`lock`]), let go when dropped.
pub struct Held {
    entry: &'static Entry,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.entry.lock.store(0, SeqCst);
        wake(&self.entry.lock);
    }
}

/// Hold host pid `pid`'s record lock while the result lives. A lock its
/// holder left as it died is taken over.
pub fn lock(pid: i32) -> Option<Held> {
    let entry = store()?.entry(pid)?;
    let me = crate::host::pid() as u32;
    loop {
        match entry.lock.compare_exchange(0, me, SeqCst, SeqCst) {
            Ok(_) => return Some(Held { entry }),
            Err(holder) => {
                // Gone, or a zombie (it died holding the lock): taken over.
                let live = crate::procreg::host_info(holder as i32).is_some_and(|(_, _, z)| !z);
                if !live && entry.lock.compare_exchange(holder, me, SeqCst, SeqCst).is_ok() {
                    return Some(Held { entry });
                }
                // Woken as it is let go; a while at most, to look at the
                // holder again.
                wait(&entry.lock, holder, 10_000_000);
            }
        }
    }
}

/// Write `bytes` as host pid `pid`'s record, under its lock (`_held`).
pub fn put(_held: &Held, pid: i32, bytes: &[u8]) {
    let Some(s) = store() else { return };
    let Some(e) = s.entry(pid) else { return };
    let Some(head) = s.write_chain(bytes) else { return };
    let (old, old_len) = replace(e, head, bytes.len() as u32);
    s.used(pid as usize / 64).fetch_or(1 << (pid as usize % 64), SeqCst);
    s.free_chain(old, old_len as usize);
}

/// Forget host pid `pid`'s record, under its lock (`_held`).
pub fn remove(_held: &Held, pid: i32) {
    let Some(s) = store() else { return };
    let Some(e) = s.entry(pid) else { return };
    let (old, old_len) = replace(e, 0, 0);
    s.used(pid as usize / 64).fetch_and(!(1 << (pid as usize % 64)), SeqCst);
    s.free_chain(old, old_len as usize);
}

/// Make the chain from `head` of `len` bytes entry `e`'s record: the old
/// chain and its length.
fn replace(e: &Entry, head: u32, len: u32) -> (u32, u32) {
    e.seq.fetch_add(1, SeqCst);
    let old = (e.head.swap(head, SeqCst), e.len.swap(len, SeqCst));
    e.seq.fetch_add(1, SeqCst);
    old
}

/// Every host pid with a record.
pub fn pids() -> Vec<i32> {
    let Some(s) = store() else { return Vec::new() };
    let mut out = Vec::new();
    for w in 0..PIDS / 64 {
        let mut bits = s.used(w).load(SeqCst);
        while bits != 0 {
            let b = bits.trailing_zeros();
            out.push((w * 64) as i32 + b as i32);
            bits &= bits - 1;
        }
    }
    out
}

/// Record that host process `pid` ends of a signal, with Linux wait status
/// `status`.
pub fn set_end(pid: i32, status: i32) {
    if let Some(e) = store().and_then(|s| s.entry(pid)) {
        e.end.store((status as u32 & !END_SET) | END_SET, SeqCst);
    }
}

/// The status [`set_end`] recorded for host pid `pid`. Async-signal-safe
/// once the store is mapped ([`init`]).
pub fn end_status(pid: i32) -> Option<i32> {
    let s = STORE.get()?.as_ref()?;
    let v = s.entry(pid)?.end.load(SeqCst);
    (v & END_SET != 0).then_some((v & !END_SET) as i32)
}

/// Forget the status [`set_end`] recorded for host pid `pid`.
pub fn forget_end(pid: i32) {
    if let Some(e) = store().and_then(|s| s.entry(pid)) {
        e.end.store(0, SeqCst);
    }
}

/// Keep an ended account of host process `pid` that started at `start`,
/// in place of one kept of it already.
pub fn put_ended(pid: i32, start: u64, bytes: &[u8]) {
    let Some(s) = store() else { return };
    take_ended(pid, start);
    let Some(head) = s.write_chain(bytes) else { return };
    for i in 0..ENDED {
        let slot = s.ended(i);
        let cur = slot.state.load(SeqCst);
        if st(cur) != FREE
            || slot.state.compare_exchange(cur, next(cur, FILLING), SeqCst, SeqCst).is_err()
        {
            continue;
        }
        slot.pid.store(pid as u32, SeqCst);
        slot.start.store(start, SeqCst);
        slot.head.store(head, SeqCst);
        slot.len.store(bytes.len() as u32, SeqCst);
        slot.state.store(next(cur, FULL), SeqCst);
        return;
    }
    s.free_chain(head, bytes.len());
}

/// The ended accounts kept of processes whose host pid `wanted` picks.
pub fn ended(wanted: impl Fn(i32) -> bool) -> Vec<Vec<u8>> {
    let Some(s) = store() else { return Vec::new() };
    let mut out = Vec::new();
    for i in 0..ENDED {
        let slot = s.ended(i);
        let cur = slot.state.load(SeqCst);
        if st(cur) != FULL || !wanted(slot.pid.load(SeqCst) as i32) {
            continue;
        }
        let (head, len) = (slot.head.load(SeqCst), slot.len.load(SeqCst) as usize);
        let bytes = s.read_chain(head, len);
        // Still the account it was as it was read.
        if slot.state.load(SeqCst) == cur
            && let Some(bytes) = bytes
        {
            out.push(bytes);
        }
    }
    out
}

/// Take the ended account of host process `pid` that started at `start`:
/// whether this caller took it (one caller does).
pub fn take_ended(pid: i32, start: u64) -> bool {
    let Some(s) = store() else { return false };
    for i in 0..ENDED {
        let slot = s.ended(i);
        let cur = slot.state.load(SeqCst);
        if st(cur) != FULL
            || slot.pid.load(SeqCst) != pid as u32
            || slot.start.load(SeqCst) != start
            || slot.state.compare_exchange(cur, next(cur, TAKING), SeqCst, SeqCst).is_err()
        {
            continue;
        }
        let (head, len) = (slot.head.load(SeqCst), slot.len.load(SeqCst) as usize);
        s.free_chain(head, len);
        slot.state.store(next(next(cur, TAKING), FREE), SeqCst);
        return true;
    }
    false
}

/// Whether an ended account of host process `pid` that started at `start`
/// is kept.
pub fn has_ended(pid: i32, start: u64) -> bool {
    let Some(s) = store() else { return false };
    (0..ENDED).any(|i| {
        let slot = s.ended(i);
        st(slot.state.load(SeqCst)) == FULL
            && slot.pid.load(SeqCst) == pid as u32
            && slot.start.load(SeqCst) == start
    })
}

/// Wait while `word` is `value`, `timeout_ns` at most, for another process
/// to change it and [`wake`] it.
fn wait(word: &AtomicU32, value: u32, timeout_ns: u64) {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn __ulock_wait2(op: u32, a: *mut libc::c_void, v: u64, t: u64, v2: u64) -> i32;
        }
        // `UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO`.
        // SAFETY: waits on a word of the shared mapping while it holds `value`.
        unsafe {
            __ulock_wait2(3 | 0x0100_0000, word.as_ptr().cast(), value.into(), timeout_ns, 0)
        };
    }
    #[cfg(not(target_os = "macos"))]
    {
        let t = libc::timespec {
            tv_sec: (timeout_ns / 1_000_000_000) as libc::time_t,
            tv_nsec: (timeout_ns % 1_000_000_000) as libc::c_long,
        };
        // SAFETY: a futex wait on a word of the shared mapping.
        unsafe {
            libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAIT, value, &t);
        }
    }
}

/// Wake whoever [`wait`]s on `word`.
fn wake(word: &AtomicU32) {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn __ulock_wake(op: u32, a: *mut libc::c_void, v: u64) -> i32;
        }
        // `UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL | ULF_NO_ERRNO`.
        // SAFETY: wakes waiters on a word of the shared mapping.
        unsafe { __ulock_wake(3 | 0x0000_0100 | 0x0100_0000, word.as_ptr().cast(), 0) };
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: a futex wake on a word of the shared mapping.
        unsafe { libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAKE, i32::MAX) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record written is read back whole, across blocks, replaced and
    /// removed, its blocks given back; an ended account is taken once.
    #[test]
    fn records_are_kept_replaced_and_removed() {
        // A pid no process here has: the test's own and above.
        let pid = (std::process::id() as i32 % 1000) + 99_000;
        let held = lock(pid).unwrap();
        let big: Vec<u8> = (0..3 * ROOM + 17).map(|i| i as u8).collect();
        put(&held, pid, &big);
        assert_eq!(get(pid), Some(big.clone()));
        assert!(pids().contains(&pid));
        let v = version(pid);
        put(&held, pid, b"small");
        assert_eq!(get(pid).as_deref(), Some(&b"small"[..]));
        assert_ne!(version(pid), v);
        remove(&held, pid);
        assert_eq!(get(pid), None);
        assert!(!pids().contains(&pid));
        drop(held);

        put_ended(pid, 7, b"how it ended");
        assert!(has_ended(pid, 7));
        assert_eq!(ended(|p| p == pid), vec![b"how it ended".to_vec()]);
        assert!(take_ended(pid, 7));
        assert!(!take_ended(pid, 7));
        assert!(ended(|p| p == pid).is_empty());

        set_end(pid, 9);
        assert_eq!(end_status(pid), Some(9));
        forget_end(pid);
        assert_eq!(end_status(pid), None);
    }
}
