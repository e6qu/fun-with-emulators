//! Where the process records ([`crate::procreg`]) are kept: memory every
//! fwe process of the user maps, a POSIX shared memory object ([`name`]). A
//! record read or written is memory read or written, where a file of its
//! own each cost the host a file's making, opening and removal (tens of
//! microseconds each, more than the rest of a `fork`).
//!
//! - **Entries**, one for each host pid: a lock, a sequence number (odd
//!   while the record changes), where the record's bytes are and how many,
//!   and the Linux wait status the process left as it ended of a signal;
//!   one of each kind (its record, thread list, mappings...), a pid's side
//!   by side. A bit for each pid with a record lets a listing skip the
//!   rest.
//! - **Blocks** of 4 KiB hold the bytes, chained, taken from and given back
//!   to a bitmap of free ones.
//! - **Ended accounts** (how a process ended, for its reaper): a table of
//!   their own, each taken whole by one reaper, and a count of them.
//! - **Thread numbers** outside a pid namespace ([`crate::thread`]): a
//!   counter blocks of them are taken from, and each block's process.
//! - **Signal mailboxes** ([`crate::signote`]): a pool of them, each given
//!   to a pid as it is first sent a signal through one, and taken back
//!   with its record, or once its process is gone.
//! - **Busy marks**, one for each host pid: its main thread is in fwe's
//!   own work, which the host may make it wait for ([`Busy`]).
//! - **Entry marks**, one for each host pid: the start of the process
//!   whose main thread has gone into the program ([`entered`]).
//! - **Tasks**, one word for each host pid: its real user, as its record
//!   says, and its threads, as it counts them ([`user_tasks`]).
//! - **Named records** ([`named`]): the state of Linux's kernel every
//!   process shares ([`crate::shared::Record`]: namespaces, mount tables,
//!   System V IPC...), each in a slot found by its name, its bytes in
//!   blocks.
//!
//! A reader takes no lock: it reads the sequence number, the bytes and the
//! number again, and reads again if a change came between. A writer holds
//! the entry's lock ([`lock`]), writes the new bytes into blocks of its
//! own, makes them the record's, and only then frees the old ones. The
//! lock names its holder's pid: one left by a process that died holding
//! it is taken over.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};

pub mod named;

/// Host pids with an entry: those below this (macOS's end at 99999).
const PIDS: usize = 1 << 17;
/// What an entry holds: a process record, or a process's thread list
/// ([`crate::thread`]).
#[derive(Clone, Copy)]
pub enum Kind {
    Record = 0,
    Threads = 1,
    /// Its threads' robust-futex list heads ([`crate::thread`]).
    Robust = 2,
    /// Its mappings, for `/proc/<pid>/maps` ([`crate::maps`]).
    Maps = 3,
    /// Its mount namespace, root, working directory and resource limits,
    /// for `/proc/<pid>/{cwd,root,mountinfo,limits}` ([`crate::fs::Fs::share`]).
    View = 4,
}
const KINDS: usize = 5;
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
    /// Its signal mailbox ([`mailbox`]), from 1 (0: none).
    mailbox: AtomicU32,
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

/// Counts every fwe process shares ([`count`]), first in the store.
#[derive(Clone, Copy)]
pub enum Count {
    /// Pid namespaces with accounting on ([`crate::acct`]); never fewer
    /// than have it.
    Accounting = 0,
    /// Leases held ([`crate::leases`]).
    Leases = 1,
    /// Memfds ever sealed against writing ([`crate::memfd`]).
    WriteSeals = 2,
    /// Whether the registry of watched files is made
    /// ([`crate::inotify::registry`]): 1 once it is.
    Watches = 3,
    /// Whether the record of keys is made ([`crate::keys`]): 1 once it
    /// is, so a fork of a program that never used a key looks no further.
    Keys = 4,
}

/// Room for the counts.
const COUNTS: usize = 8;

/// The store's layout: where each part starts in the object.
const COUNTS_AT: usize = 0;
/// The CPU's features as `AT_HWCAP` and `AT_HWCAP2` report them
/// ([`hwcap`]), then whether they are set, past the counts.
const HWCAP_AT: usize = COUNTS_AT + COUNTS * 8;
/// The user's temporary directory as the host named it ([`user_temp`]):
/// its length, then its bytes.
const USER_TEMP_AT: usize = HWCAP_AT + 32;
const USER_TEMP_MAX: usize = 1024;
const ENTRIES_AT: usize = USER_TEMP_AT + 8 + USER_TEMP_MAX;
const USED_AT: usize = ENTRIES_AT + KINDS * PIDS * size_of::<Entry>();
/// The pids whose record their process writes itself as it starts, and
/// has not yet ([`mark_unwritten`]).
const UNWRITTEN_AT: usize = USED_AT + PIDS / 8;
/// Each pid's busy mark ([`Busy`]).
const BUSY_AT: usize = UNWRITTEN_AT + PIDS / 8;
/// Each pid's entry mark ([`entered`]).
const ENTERED_AT: usize = BUSY_AT + PIDS * 4;
/// Each pid's tasks ([`user_tasks`]).
const TASKS_AT: usize = ENTERED_AT + PIDS * 8;
const ENDED_AT: usize = TASKS_AT + PIDS * 8;
const FREE_HINT_AT: usize = ENDED_AT + ENDED * size_of::<Ended>();
/// How many ended accounts are kept or being kept or taken
/// ([`Store::ended_kept`]), in the free hint's line.
const ENDED_KEPT_AT: usize = FREE_HINT_AT + 8;
/// Thread-number blocks: the next block's first number, then each
/// block's process.
pub const TID_BLOCKS: usize = 1 << 16;
const TID_NEXT_AT: usize = FREE_HINT_AT + 64;
const TID_OWNERS_AT: usize = TID_NEXT_AT + 64;
/// Signal mailboxes: how many, each's words (its process, then what
/// [`crate::signote`] lays out), and which are given out.
const MAILBOXES: usize = 4096;
pub const MAILBOX_WORDS: usize = 1290;
const MAILBOX_TAKEN_AT: usize = TID_OWNERS_AT + TID_BLOCKS * 4;
const MAILBOXES_AT: usize = MAILBOX_TAKEN_AT + MAILBOXES / 8;
/// Cells of three shared words, each named by a tag ([`cell`]).
const CELLS: usize = 1024;
const CELLS_AT: usize = MAILBOXES_AT + MAILBOXES * MAILBOX_WORDS * 8;
/// Pages of shared words, each named by a tag and kept for a process
/// ([`page`]): the lock under which one is made, then each's tag and
/// process, then the pages.
const PAGES: usize = 1024;
pub const PAGE_WORDS: usize = 512;
const PAGES_LOCK_AT: usize = CELLS_AT + CELLS * 32;
const PAGE_TAGS_AT: usize = PAGES_LOCK_AT + 64;
const PAGES_AT: usize = (PAGE_TAGS_AT + PAGES * 16).div_ceil(PAGE_WORDS * 8) * PAGE_WORDS * 8;
/// Named records ([`named`]): the lock under which one is made or
/// removed, the count their identities are taken from, then their slots.
const NAMED_LOCK_AT: usize = PAGES_AT + PAGES * PAGE_WORDS * 8;
const NAMED_NEXT_AT: usize = NAMED_LOCK_AT + 64;
const NAMED_AT: usize = NAMED_NEXT_AT + 64;
const TAKEN_AT: usize = NAMED_AT + named::SLOTS * size_of::<named::Named>();
const BLOCKS_AT: usize = (TAKEN_AT + BLOCKS / 8).div_ceil(BLOCK) * BLOCK;
const SIZE: usize = BLOCKS_AT + BLOCKS * BLOCK;

/// The store, mapped once per process.
struct Store {
    base: usize,
}

static STORE: OnceLock<Store> = OnceLock::new();

/// The store's name: a POSIX shared memory object of the user's (memory
/// only: a file's dirty pages would be written back to its disk as each
/// process holding them ends, milliseconds on a virtual machine's).
fn name() -> String {
    // Its size too: an object's size is set once, so a layout of another
    // size is another object. (macOS allows names of 31 bytes.)
    format!("/fwe{}v{}p{:x}", crate::host::euid(), crate::shared::FORMAT, SIZE)
}

fn map() -> Result<Store, String> {
    let name = name();
    let c = std::ffi::CString::new(name.clone()).map_err(|e| e.to_string())?;
    let err = |what: &str| format!("{what} {name}: {}", std::io::Error::last_os_error());
    // SAFETY: plain host calls; the object is the user's own (checked), and
    // the mapping is kept for the process's life.
    unsafe {
        let fd = libc::shm_open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600 as libc::c_uint);
        if fd < 0 {
            return Err(err("opening"));
        }
        // Zeroes (nothing recorded, every block free) the first time; the
        // host gives memory only to the pages written. Its size is set once
        // (macOS refuses to change it after, so a failure here is one made
        // already, which the size below checks).
        libc::ftruncate(fd, SIZE as libc::off_t);
        let Some(st) = sized(fd) else {
            libc::close(fd);
            return Err(err("looking at"));
        };
        if st.st_uid != crate::host::euid() || st.st_mode & 0o077 != 0 {
            libc::close(fd);
            return Err(format!(
                "{name} is not the user's own (owner {}, mode {:o})",
                st.st_uid, st.st_mode
            ));
        }
        if (st.st_size as usize) < SIZE {
            libc::close(fd);
            return Err(format!("{name} is {} bytes, not {SIZE}", st.st_size));
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        if p == libc::MAP_FAILED {
            return Err(err("mapping"));
        }
        Ok(Store { base: p as usize })
    }
}

/// The metadata of the shared memory object open as `fd`, once it has a
/// size: another process making it at once sizes it, and its size is 0
/// until that process's `ftruncate` is done (this one's is refused
/// meanwhile). `None` if it cannot be looked at.
fn sized(fd: i32) -> Option<libc::stat> {
    // SAFETY: zeroed bytes are a valid `stat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    for _ in 0..1000 {
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return None;
        }
        if st.st_size != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Some(st)
}

/// The store, mapped on first use. fwe cannot run without it (no process
/// would know another): a failure to map it ends the process, saying why.
fn store() -> &'static Store {
    STORE.get_or_init(|| map().unwrap_or_else(|e| fatal(&format!("the process records: {e}"))))
}

/// The store from a signal handler, which cannot map it: mapped by then
/// ([`init`], as every process starts), else `None`.
fn mapped() -> Option<&'static Store> {
    STORE.get()
}

/// End the process: the store cannot do what it must.
fn fatal(why: &str) -> ! {
    eprintln!("fwe: {why}");
    std::process::exit(1)
}

/// Map the store now, before a signal handler may need it.
pub fn init() {
    store();
    // A process before this one with the pid may have ended busy.
    not_busy();
}

/// While one lives, the calling thread, if it is its process's main
/// thread, is in fwe's own work (a shared record read or written under
/// its lock), which the host may make it wait for, as a Linux thread
/// doing its kernel's work is not asleep in a wait of the guest's:
/// `/proc` shows it running ([`busy`]), where a program waiting for it
/// to sleep (in a semaphore wait it is on its way to, say) would take a
/// host wait of fwe's for that.
pub struct Busy(bool);

impl Busy {
    pub fn new() -> Busy {
        let main = crate::thread::tid() == crate::thread::tgid();
        if main && let Some(w) = busy_word(crate::host::pid()) {
            w.fetch_add(1, SeqCst);
        }
        Busy(main)
    }
}

impl Default for Busy {
    fn default() -> Busy {
        Busy::new()
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        if self.0
            && let Some(w) = busy_word(crate::host::pid())
        {
            // (Not below zero: a fork child starts with none.)
            let mut n = w.load(SeqCst);
            while n > 0 {
                match w.compare_exchange(n, n - 1, SeqCst, SeqCst) {
                    Ok(_) => break,
                    Err(now) => n = now,
                }
            }
        }
    }
}

fn busy_word(pid: i32) -> Option<&'static AtomicU32> {
    let i = usize::try_from(pid).ok().filter(|&i| i > 0 && i < PIDS)?;
    Some(store().at(BUSY_AT + i * 4))
}

/// Whether host pid `pid`'s main thread is in fwe's own work ([`Busy`]).
pub fn busy(pid: i32) -> bool {
    busy_word(pid).is_some_and(|w| w.load(SeqCst) != 0)
}

/// This process's main thread goes into the program: its first
/// instruction, or a fork's return in the child. A host wait it is shown in
/// before then is fwe's or the host's work of making it (a fork child
/// waits for its parent), which Linux shows running: a program waiting
/// for its child to sleep in a wait it is on its way to would take that
/// for it ([`has_entered`]). The mark is the process's start, which no
/// later process with the pid has.
pub fn entered() {
    let pid = crate::host::pid();
    if let Some(w) = entered_word(pid)
        && let Some(start) = crate::procreg::own_start()
    {
        w.store(start, SeqCst);
    }
}

/// Whether host process `pid`, which started at `start` (microseconds,
/// as the host says), is one of fwe's (it has a record, or writes its own)
/// that has not yet gone into the program ([`entered`]).
pub fn not_yet_entered(pid: i32, start: u64) -> bool {
    (version(pid).is_some() || unwritten(pid))
        && !entered_word(pid).is_some_and(|w| w.load(SeqCst) == start)
}

fn entered_word(pid: i32) -> Option<&'static AtomicU64> {
    let i = usize::try_from(pid).ok().filter(|&i| i > 0 && i < PIDS)?;
    Some(store().at(ENTERED_AT + i * 8))
}

/// Host pid `pid`'s tasks words: its real user + 1 (0: not said), and
/// its threads (0, before it says, counts as 1).
fn tasks_words(pid: i32) -> Option<[&'static AtomicU32; 2]> {
    let i = usize::try_from(pid).ok().filter(|&i| i > 0 && i < PIDS)?;
    Some([store().at(TASKS_AT + i * 8), store().at(TASKS_AT + i * 8 + 4)])
}

/// Host process `pid`'s record says its real user is `uid` (an initial
/// namespace id).
pub fn set_task_user(pid: i32, uid: u32) {
    if let Some([user, _]) = tasks_words(pid) {
        user.store(uid.wrapping_add(1), SeqCst);
    }
}

/// This process has `n` threads.
pub fn set_own_threads(n: u32) {
    if let Some([_, threads]) = tasks_words(crate::host::pid()) {
        threads.store(n, SeqCst);
    }
}

/// The tasks (threads, in every process) of user `uid` (an initial
/// namespace id) by the tasks words of the pids `pids`, without a record
/// read or a host call: what `RLIMIT_NPROC` counts.
pub fn user_tasks(uid: u32, pids: impl IntoIterator<Item = i32>) -> u64 {
    pids.into_iter()
        .filter_map(tasks_words)
        .filter(|[user, _]| user.load(SeqCst) == uid.wrapping_add(1))
        .map(|[_, threads]| u64::from(threads.load(SeqCst).max(1)))
        .sum()
}

/// This process's main thread is in none of fwe's work: it starts, or is
/// a fork child (the parent's marks are not its own).
pub fn not_busy() {
    if let Some(w) = busy_word(crate::host::pid()) {
        w.store(0, SeqCst);
    }
}

/// The count `c`.
pub fn count(c: Count) -> &'static AtomicU64 {
    store().at(COUNTS_AT + c as usize * 8)
}

/// The user's temporary directory, as a process asked the host for it
/// ([`set_user_temp`]): asking costs milliseconds (a daemon answers).
pub fn user_temp() -> Option<Vec<u8>> {
    let s = store();
    let len: &AtomicU64 = s.at(USER_TEMP_AT);
    let n = len.load(SeqCst) as usize;
    if n == 0 || n > USER_TEMP_MAX {
        return None;
    }
    let words = n.div_ceil(8);
    let bytes: Vec<u8> = (0..words)
        .flat_map(|i| s.at::<AtomicU64>(USER_TEMP_AT + 8 + i * 8).load(SeqCst).to_le_bytes())
        .take(n)
        .collect();
    Some(bytes)
}

/// Keep `dir` as the user's temporary directory ([`user_temp`]); its
/// length is written last, so a reader finds all of it or none.
pub fn set_user_temp(dir: &[u8]) {
    if dir.is_empty() || dir.len() > USER_TEMP_MAX {
        return;
    }
    let s = store();
    for (i, chunk) in dir.chunks(8).enumerate() {
        let mut w = [0u8; 8];
        w[..chunk.len()].copy_from_slice(chunk);
        s.at::<AtomicU64>(USER_TEMP_AT + 8 + i * 8).store(u64::from_le_bytes(w), SeqCst);
    }
    s.at::<AtomicU64>(USER_TEMP_AT).store(dir.len() as u64, SeqCst);
}

/// The CPU's features as a process found them ([`set_hwcap`]): asking the
/// host costs a call for each.
pub fn hwcap() -> Option<(u64, u64)> {
    let s = store();
    (s.at::<AtomicU64>(HWCAP_AT + 16).load(SeqCst) != 0).then(|| {
        (s.at::<AtomicU64>(HWCAP_AT).load(SeqCst), s.at::<AtomicU64>(HWCAP_AT + 8).load(SeqCst))
    })
}

/// Keep the CPU's features for [`hwcap`]; marked set last, so a reader
/// finds both words or none.
pub fn set_hwcap(hwcap: u64, hwcap2: u64) {
    let s = store();
    s.at::<AtomicU64>(HWCAP_AT).store(hwcap, SeqCst);
    s.at::<AtomicU64>(HWCAP_AT + 8).store(hwcap2, SeqCst);
    s.at::<AtomicU64>(HWCAP_AT + 16).store(1, SeqCst);
}

impl Store {
    fn at<T>(&self, offset: usize) -> &T {
        // SAFETY: an offset inside the mapping, of a value of atomics only
        // (every bit pattern valid), the mapping kept for the process's life.
        unsafe { &*((self.base + offset) as *const T) }
    }

    fn entry(&self, pid: i32) -> Option<&Entry> {
        self.entry_of(Kind::Record, pid)
    }

    /// A pid's entries side by side, one of each kind: a process just
    /// forked, which writes several of its own, finds them on one page.
    fn entry_of(&self, kind: Kind, pid: i32) -> Option<&Entry> {
        let i = usize::try_from(pid).ok().filter(|&i| i > 0 && i < PIDS)?;
        Some(self.at(ENTRIES_AT + (i * KINDS + kind as usize) * size_of::<Entry>()))
    }

    fn unwritten(&self, word: usize) -> &AtomicU64 {
        self.at(UNWRITTEN_AT + word * 8)
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

    /// How many ended-account slots are not free: counted up before one is
    /// filled and down once it is free again, so that none is in use while
    /// it reads 0, and a look for an account, most often when there is
    /// none (a parent reaping its child), reads one word, not the table.
    fn ended_kept(&self) -> &AtomicU32 {
        self.at(ENDED_KEPT_AT)
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

    /// Write `bytes` into new blocks: the first. With no room (256 MiB of
    /// records), the process ends saying so.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn write_chain(&self, bytes: &[u8]) -> u32 {
        self.write_chain_ends(bytes).0
    }

    /// [`Store::write_chain`], and the chain's last block.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn write_chain_ends(&self, bytes: &[u8]) -> (u32, u32) {
        let mut chunks: Vec<&[u8]> = bytes.chunks(ROOM).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let mut blocks = Vec::with_capacity(chunks.len());
        for _ in &chunks {
            match self.take_block() {
                Some(b) => blocks.push(b),
                None => fatal("the process records' memory is full"),
            }
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let (link, room) = self.block(blocks[i]);
            link.store(blocks.get(i + 1).copied().unwrap_or(0), SeqCst);
            // SAFETY: a block this writer took, `ROOM` bytes from `room`.
            unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), room, chunk.len()) };
        }
        (blocks[0], blocks[blocks.len() - 1])
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

/// Take the next block of `size` thread numbers from `first` (up to
/// `end`, then from `first` again) for this process: its first number.
pub fn take_tid_block(first: i32, end: i32, size: i32) -> i32 {
    let s = store();
    let next: &AtomicU32 = s.at(TID_NEXT_AT);
    let mut cur = next.load(SeqCst);
    let n = loop {
        let n = cur as i32;
        let n = if (first..=end - size).contains(&n) { n } else { first };
        let after = if n + size >= end { first } else { n + size };
        match next.compare_exchange(cur, after as u32, SeqCst, SeqCst) {
            Ok(_) => break n,
            Err(now) => cur = now,
        }
    };
    let block = ((n - first) / size) as usize;
    if block < TID_BLOCKS {
        let owner: &AtomicU32 = s.at(TID_OWNERS_AT + block * 4);
        owner.store(crate::host::pid() as u32, SeqCst);
    }
    n
}

/// The process that took thread-number block `block` last (0: none).
pub fn tid_block_owner(block: usize) -> i32 {
    let s = store();
    if block >= TID_BLOCKS {
        return 0;
    }
    let owner: &AtomicU32 = s.at(TID_OWNERS_AT + block * 4);
    owner.load(SeqCst) as i32
}

/// A word of shared memory.
pub type Word = AtomicU64;

/// Host pid `pid`'s signal mailbox (its words after its owner's), given
/// one now if it has none and `make`. Without `make`, async-signal-safe
/// once the store is mapped ([`init`]).
pub fn mailbox(pid: i32, make: bool) -> Option<&'static [AtomicU64]> {
    let s = if make { store() } else { mapped()? };
    let e = s.entry(pid)?;
    let words = |i: u32| -> &'static [AtomicU64] {
        let at = MAILBOXES_AT + (i as usize - 1) * MAILBOX_WORDS * 8;
        // SAFETY: mailbox `i`'s words, inside the mapping, kept for the
        // process's life; atomics only.
        unsafe { std::slice::from_raw_parts((s.base + at) as *const AtomicU64, MAILBOX_WORDS) }
    };
    let i = e.mailbox.load(SeqCst);
    if i != 0 {
        return Some(&words(i)[1..]);
    }
    if !make {
        return None;
    }
    for round in 0..2 {
        if let Some(i) = s.take_mailbox() {
            words(i)[0].store(pid as u64, SeqCst);
            return match e.mailbox.compare_exchange(0, i, SeqCst, SeqCst) {
                Ok(_) => Some(&words(i)[1..]),
                Err(theirs) => {
                    // Another sender gave it one first.
                    s.give_back_mailbox(i, words(i));
                    Some(&words(theirs)[1..])
                }
            };
        }
        if round == 0 {
            // None free: those of processes gone are taken back.
            for i in 1..=MAILBOXES as u32 {
                let owner = words(i)[0].load(SeqCst) as i32;
                if owner > 0 && !crate::host::process_exists(owner) {
                    forget_mailbox(owner);
                }
            }
        }
    }
    fatal(&format!("the signal mailboxes are full ({MAILBOXES} processes have one)"))
}

/// The three shared words of the cell tagged `tag` (not 0): the one
/// tagged so, or with `make` a free one, zeroed, tagged now (`None` if
/// none is free).
pub fn cell(tag: u64, make: bool) -> Option<&'static [Word; 3]> {
    let s = store();
    let tag = tag | 1;
    let at = |i: usize| -> &'static [Word; 4] { s.at(CELLS_AT + i * 32) };
    if let Some(i) = (0..CELLS).find(|&i| at(i)[0].load(SeqCst) == tag) {
        return Some(at(i)[1..].try_into().unwrap());
    }
    if !make {
        return None;
    }
    for i in 0..CELLS {
        let c = at(i);
        if c[0].load(SeqCst) == 0 && c[0].compare_exchange(0, u64::MAX, SeqCst, SeqCst).is_ok() {
            for w in &c[1..] {
                w.store(0, SeqCst);
            }
            c[0].store(tag, SeqCst);
            return Some(c[1..].try_into().unwrap());
        }
    }
    None
}

/// The cell tagged `tag` is free again.
pub fn free_cell(tag: u64) {
    let s = store();
    for i in 0..CELLS {
        let c: &[Word; 4] = s.at(CELLS_AT + i * 32);
        let _ = c[0].compare_exchange(tag | 1, 0, SeqCst, SeqCst);
    }
}

/// The page tagged `tag` (not 0), or with `make` (`Some(owner)`) a new
/// one, zeroed, kept until [`free_page`], or until host process `owner`
/// is gone and the pages run short (`None`: none so tagged).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn page(tag: u64, make: Option<i32>) -> Option<&'static [Word; PAGE_WORDS]> {
    let s = store();
    let tags = |i: usize| -> &'static [Word; 2] { s.at(PAGE_TAGS_AT + i * 16) };
    let words = |i: usize| -> &'static [Word; PAGE_WORDS] { s.at(PAGES_AT + i * PAGE_WORDS * 8) };
    let find = || (0..PAGES).find(|&i| tags(i)[0].load(SeqCst) == tag);
    if let Some(i) = find() {
        return Some(words(i));
    }
    let owner = make?;
    let _held = hold(s.at(PAGES_LOCK_AT));
    // Made meanwhile by another process.
    if let Some(i) = find() {
        return Some(words(i));
    }
    // Free first, then those of processes gone.
    for gone in [false, true] {
        let free = (0..PAGES).find(|&i| {
            let [t, o] = tags(i);
            t.load(SeqCst) == 0 || gone && !crate::host::process_exists(o.load(SeqCst) as i32)
        });
        if let Some(i) = free {
            for w in words(i) {
                w.store(0, SeqCst);
            }
            tags(i)[1].store(owner as u64, SeqCst);
            tags(i)[0].store(tag, SeqCst);
            return Some(words(i));
        }
    }
    fatal(&format!("the shared pages are full ({PAGES} are kept)"))
}

/// The page tagged `tag` is free again.
pub fn free_page(tag: u64) {
    let s = store();
    for i in 0..PAGES {
        let t: &Word = s.at(PAGE_TAGS_AT + i * 16);
        let _ = t.compare_exchange(tag, 0, SeqCst, SeqCst);
    }
}

/// Host pid `pid`'s mailbox goes (its record went, or its process).
pub fn forget_mailbox(pid: i32) {
    let s = store();
    let Some(e) = s.entry(pid) else { return };
    let i = e.mailbox.swap(0, SeqCst);
    if i != 0 {
        let at = MAILBOXES_AT + (i as usize - 1) * MAILBOX_WORDS * 8;
        // SAFETY: as in [`mailbox`].
        let w =
            unsafe { std::slice::from_raw_parts((s.base + at) as *const AtomicU64, MAILBOX_WORDS) };
        s.give_back_mailbox(i, w);
    }
}

impl Store {
    fn take_mailbox(&self) -> Option<u32> {
        for w in 0..MAILBOXES / 64 {
            let word: &AtomicU64 = self.at(MAILBOX_TAKEN_AT + w * 8);
            let mut cur = word.load(SeqCst);
            while cur != u64::MAX {
                let bit = (!cur).trailing_zeros();
                match word.compare_exchange(cur, cur | 1 << bit, SeqCst, SeqCst) {
                    Ok(_) => return Some((w * 64) as u32 + bit + 1),
                    Err(now) => cur = now,
                }
            }
        }
        None
    }

    /// Mailbox `i` (its words `w`), emptied, is free again.
    fn give_back_mailbox(&self, i: u32, w: &[AtomicU64]) {
        for x in w {
            x.store(0, SeqCst);
        }
        let b = i as usize - 1;
        let word: &AtomicU64 = self.at(MAILBOX_TAKEN_AT + b / 64 * 8);
        word.fetch_and(!(1 << (b % 64)), SeqCst);
    }
}

/// The record bytes of host pid `pid`, if it has a record.
pub fn get(pid: i32) -> Option<Vec<u8>> {
    get_of(Kind::Record, pid)
}

/// What host pid `pid`'s entry of `kind` holds, if anything.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn get_of(kind: Kind, pid: i32) -> Option<Vec<u8>> {
    let s = store();
    let e = s.entry_of(kind, pid)?;
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
    Some(store().entry(pid)?.seq.load(SeqCst))
}

/// A held record lock ([`lock`]), let go when dropped.
pub struct Held {
    word: &'static AtomicU32,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.word.store(0, SeqCst);
        wake(self.word);
    }
}

/// Hold host pid `pid`'s record lock while the result lives.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn lock(pid: i32) -> Option<Held> {
    Some(hold(&store().entry(pid)?.lock))
}

/// Hold the lock `word` (its holder's host pid, 0: free) while the result
/// lives. A lock its holder left as it died is taken over.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn hold(word: &'static AtomicU32) -> Held {
    let me = crate::host::pid() as u32;
    loop {
        match word.compare_exchange(0, me, SeqCst, SeqCst) {
            Ok(_) => return Held { word },
            Err(holder) => {
                // Gone, or a zombie (it died holding the lock): taken over.
                let live = crate::procreg::host_info(holder as i32).is_some_and(|(_, _, z)| !z);
                if !live && word.compare_exchange(holder, me, SeqCst, SeqCst).is_ok() {
                    return Held { word };
                }
                // Woken as it is let go; a while at most, to look at the
                // holder again.
                wait(word, holder, 10_000_000);
            }
        }
    }
}

/// Write `bytes` as host pid `pid`'s record, under its lock (`_held`).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn put(_held: &Held, pid: i32, bytes: &[u8]) {
    let s = store();
    let Some(e) = s.entry(pid) else { return };
    let head = s.write_chain(bytes);
    let (old, old_len) = replace(e, head, bytes.len() as u32);
    s.used(pid as usize / 64).fetch_or(1 << (pid as usize % 64), SeqCst);
    s.unwritten(pid as usize / 64).fetch_and(!(1 << (pid as usize % 64)), SeqCst);
    s.free_chain(old, old_len as usize);
}

/// Host pid `pid`, just forked, writes its record itself as it starts:
/// until it has, every process's listing ([`pids`]) has it, and a read of
/// it waits ([`crate::procreg::read`]), as on Linux a child is there once
/// `fork` returns.
pub fn mark_unwritten(pid: i32) {
    if (1..PIDS as i32).contains(&pid) {
        store().unwritten(pid as usize / 64).fetch_or(1 << (pid as usize % 64), SeqCst);
    }
}

/// Whether host pid `pid` is to write its record and has not yet.
pub fn unwritten(pid: i32) -> bool {
    (1..PIDS as i32).contains(&pid)
        && store().unwritten(pid as usize / 64).load(SeqCst) & (1 << (pid as usize % 64)) != 0
}

/// Host pid `pid` will write no record (it is gone).
pub fn forget_unwritten(pid: i32) {
    if (1..PIDS as i32).contains(&pid) {
        store().unwritten(pid as usize / 64).fetch_and(!(1 << (pid as usize % 64)), SeqCst);
    }
}

/// Forget host pid `pid`'s record, under its lock (`_held`), and every
/// other entry of the process (its thread list, mappings, view...): it is
/// gone, and they would hold their blocks until another process had its
/// pid.
pub fn remove(_held: &Held, pid: i32) {
    let s = store();
    let Some(e) = s.entry(pid) else { return };
    let (old, old_len) = replace(e, 0, 0);
    s.used(pid as usize / 64).fetch_and(!(1 << (pid as usize % 64)), SeqCst);
    s.free_chain(old, old_len as usize);
    if let Some(words) = tasks_words(pid) {
        for w in words {
            w.store(0, SeqCst);
        }
    }
    for kind in [Kind::Threads, Kind::Robust, Kind::Maps, Kind::View] {
        if let Some(e) = s.entry_of(kind, pid) {
            let (old, old_len) = replace(e, 0, 0);
            s.free_chain(old, old_len as usize);
        }
    }
}

/// Write `bytes` as this process's entry of `kind` (one it alone writes,
/// its threads taking turns): `None` for none.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn put_own(kind: Kind, bytes: Option<&[u8]>) {
    put_of(kind, crate::host::pid(), bytes);
}

/// In a parent, its child `pid`, just forked and waiting to go on (so
/// writing nothing itself): its entry of `kind` holds `bytes`.
pub fn put_for(kind: Kind, pid: i32, bytes: &[u8]) {
    put_of(kind, pid, Some(bytes));
}

#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn put_of(kind: Kind, pid: i32, bytes: Option<&[u8]>) {
    let s = store();
    let Some(e) = s.entry_of(kind, pid) else { return };
    let (head, len) = match bytes {
        Some(b) => (s.write_chain(b), b.len() as u32),
        None => (0, 0),
    };
    let (old, old_len) = replace(e, head, len);
    s.free_chain(old, old_len as usize);
}

/// Make the chain from `head` of `len` bytes entry `e`'s record, under its
/// lock: the old chain and its length. The sequence number is set, not
/// counted on, so one left odd by a writer that died between its two
/// changes is put right.
fn replace(e: &Entry, head: u32, len: u32) -> (u32, u32) {
    let odd = e.seq.load(SeqCst) | 1;
    e.seq.store(odd, SeqCst);
    let old = (e.head.swap(head, SeqCst), e.len.swap(len, SeqCst));
    e.seq.store(odd.wrapping_add(1), SeqCst);
    old
}

/// Every host pid with a record, or to write one ([`mark_unwritten`]).
pub fn pids() -> Vec<i32> {
    let s = store();
    let mut out = Vec::new();
    for w in 0..PIDS / 64 {
        let mut bits = s.used(w).load(SeqCst) | s.unwritten(w).load(SeqCst);
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
    if let Some(e) = store().entry(pid) {
        e.end.store((status as u32 & !END_SET) | END_SET, SeqCst);
    }
}

/// The status [`set_end`] recorded for host pid `pid`. Async-signal-safe
/// once the store is mapped ([`init`]).
pub fn end_status(pid: i32) -> Option<i32> {
    let s = mapped()?;
    let v = s.entry(pid)?.end.load(SeqCst);
    (v & END_SET != 0).then_some((v & !END_SET) as i32)
}

/// Forget the status [`set_end`] recorded for host pid `pid`.
pub fn forget_end(pid: i32) {
    if let Some(e) = store().entry(pid) {
        e.end.store(0, SeqCst);
    }
}

/// Keep an ended account of host process `pid` that started at `start`,
/// in place of one kept of it already.
pub fn put_ended(pid: i32, start: u64, bytes: &[u8]) {
    let s = store();
    take_ended(pid, start);
    let head = s.write_chain(bytes);
    for i in 0..ENDED {
        let slot = s.ended(i);
        let cur = slot.state.load(SeqCst);
        if st(cur) != FREE {
            continue;
        }
        s.ended_kept().fetch_add(1, SeqCst);
        if slot.state.compare_exchange(cur, next(cur, FILLING), SeqCst, SeqCst).is_err() {
            s.ended_kept().fetch_sub(1, SeqCst);
            continue;
        }
        slot.pid.store(pid as u32, SeqCst);
        slot.start.store(start, SeqCst);
        slot.head.store(head, SeqCst);
        slot.len.store(bytes.len() as u32, SeqCst);
        slot.state.store(next(cur, FULL), SeqCst);
        return;
    }
    fatal(&format!("the table of ended processes is full ({ENDED} not reaped)"));
}

/// The ended accounts kept of processes whose host pid `wanted` picks.
pub fn ended(wanted: impl Fn(i32) -> bool) -> Vec<Vec<u8>> {
    let s = store();
    let mut out = Vec::new();
    if s.ended_kept().load(SeqCst) == 0 {
        return out;
    }
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
    let s = store();
    if s.ended_kept().load(SeqCst) == 0 {
        return false;
    }
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
        s.ended_kept().fetch_sub(1, SeqCst);
        return true;
    }
    false
}

/// Whether an ended account of host process `pid` that started at `start`
/// is kept.
pub fn has_ended(pid: i32, start: u64) -> bool {
    let s = store();
    s.ended_kept().load(SeqCst) != 0
        && (0..ENDED).any(|i| {
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

/// [`wait`] on a 64-bit word: while its low half reads `value`'s (every
/// change of the words this waits on changes it).
fn wait64(word: &AtomicU64, value: u64, timeout_ns: u64) {
    // SAFETY: the word's low half, at its address (little-endian), an
    // atomic of its own size inside it.
    let low = unsafe { &*(word.as_ptr() as *const AtomicU32) };
    wait(low, value as u32, timeout_ns);
}

/// Wake whoever [`wait64`]s on `word`.
fn wake_all64(word: &AtomicU64) {
    // SAFETY: as in [`wait64`].
    let low = unsafe { &*(word.as_ptr() as *const AtomicU32) };
    wake(low);
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

    /// A store another process is making is waited for until it has its
    /// size.
    #[test]
    fn a_store_being_sized_elsewhere_is_waited_for() {
        let name = std::ffi::CString::new(format!("/fwe-t{}", std::process::id())).unwrap();
        // SAFETY: plain host calls on an object of the test's own.
        unsafe {
            let fd = libc::shm_open(name.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600);
            assert!(fd >= 0);
            let other = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                libc::ftruncate(fd, 1 << 20);
            });
            let st = sized(fd).unwrap();
            other.join().unwrap();
            assert_eq!(st.st_size, 1 << 20);
            libc::close(fd);
            libc::shm_unlink(name.as_ptr());
        }
    }

    /// A pid forgotten (its process gone) keeps no entry of any kind, so
    /// no block of the store stays taken for it.
    #[test]
    fn a_forgotten_pid_keeps_no_entry_of_any_kind() {
        let me = crate::host::pid();
        let s = store();
        let kinds = [Kind::Threads, Kind::Robust, Kind::Maps, Kind::View];
        let saved: Vec<Option<Vec<u8>>> = kinds.iter().map(|&k| get_of(k, me)).collect();
        for &k in &kinds {
            put_own(k, Some(&[1u8; 5000]));
        }
        let held = lock(me).unwrap();
        let record = get_of(Kind::Record, me);
        remove(&held, me);
        for &k in &kinds {
            let e = s.entry_of(k, me).unwrap();
            assert_eq!((e.head.load(SeqCst), e.len.load(SeqCst)), (0, 0));
        }
        // This process's own entries as they were.
        if let Some(r) = record {
            put(&held, me, &r);
        }
        drop(held);
        for (&k, b) in kinds.iter().zip(saved) {
            put_own(k, b.as_deref());
        }
    }

    /// A page made is found by its tag, zeroed, until it is freed.
    #[test]
    fn pages_are_found_by_tag_until_freed() {
        let tag = 7 << 32 | u64::from(std::process::id());
        let me = crate::host::pid();
        assert!(page(tag, None).is_none());
        let p = page(tag, Some(me)).unwrap();
        assert!(p.iter().all(|w| w.load(SeqCst) == 0));
        p[3].store(42, SeqCst);
        assert_eq!(page(tag, None).unwrap()[3].load(SeqCst), 42);
        assert_eq!(page(tag, Some(me)).unwrap()[3].load(SeqCst), 42);
        free_page(tag);
        assert!(page(tag, None).is_none());
        assert_eq!(page(tag, Some(me)).unwrap()[3].load(SeqCst), 0);
        free_page(tag);
    }

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
