//! Named records: the state of Linux's kernel that every fwe process
//! shares ([`crate::shared::Record`]), in the store's memory as a kernel
//! keeps it in its own.
//!
//! A record is a slot found by its name (open addressing over the slots,
//! by the name's hash), holding:
//!
//! - a **lock** naming its holder's pid (one left by a process that died
//!   holding it is taken over), with a bit its waiters set so that its
//!   holder wakes them as it lets go, and makes no host call otherwise;
//! - a **generation**, counted by every change, which processes wait on
//!   for a change, with a bit a waiter sets before it sleeps: a change
//!   wakes waiters only when it finds the bit set, and clears it (one that
//!   died waiting costs one wake, not every one after);
//! - its **data** written whole, and the generation it is at;
//! - a **journal** of the changes since, each appended to it as it is
//!   made: a change costs what it holds, not what the record does;
//! - a **note** of a few bytes beside them (a namespace's owner);
//! - its identity (the number `/proc/<pid>/ns` shows) and when it was made.
//!
//! A reader takes no lock: it copies the bytes it wants and reads the
//! slot's sequence number again, which a writer makes odd while it puts
//! other bytes in their place, and copies again if a change came between.
//! An append to the journal changes no byte a reader may be reading (the
//! journal's length, set last, says how far its bytes go), so needs no
//! sequence number.

use super::{BLOCKS, NAMED_AT, NAMED_LOCK_AT, NAMED_NEXT_AT, ROOM, Store, hold, store, wait, wake};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};

/// How many records there can be.
pub(super) const SLOTS: usize = 1 << 14;

#[repr(C)]
pub(super) struct Named {
    /// [`FREE`], [`MAKING`], [`LIVE`] or [`DEAD`].
    state: AtomicU32,
    /// The holder's host pid (0: free), with [`WAITED`].
    lock: AtomicU32,
    /// Odd while a writer replaces the data or the journal.
    seq: AtomicU32,
    /// Unused.
    spare: AtomicU32,
    /// The generation, shifted up past [`WAITING`].
    generation: AtomicU64,
    id: AtomicU64,
    /// The name's hash (never 0).
    hash: AtomicU64,
    /// When it was made, in seconds since 1970.
    made: AtomicU64,
    /// The generation the data written whole is at.
    data_at: AtomicU64,
    name_head: AtomicU32,
    name_len: AtomicU32,
    data_head: AtomicU32,
    data_len: AtomicU32,
    journal_head: AtomicU32,
    journal_len: AtomicU32,
    /// The journal's last block, which an append fills first.
    journal_tail: AtomicU32,
    /// Counted each time the journal starts again (the data written whole).
    journal_epoch: AtomicU32,
    note_head: AtomicU32,
    note_len: AtomicU32,
}

/// A slot no record has had since the store was made: a search for a name
/// ends at one.
const FREE: u32 = 0;
/// Being made, under the slots' lock.
const MAKING: u32 = 1;
const LIVE: u32 = 2;
/// One a record had: free again, but a search goes on past it.
const DEAD: u32 = 3;

/// The lock bit of a holder's waiters.
const WAITED: u32 = 1 << 31;

/// The generation word's bit of a process waiting for it to change.
const WAITING: u64 = 1;

/// Whether host process `pid` lives (a zombie died holding what it held).
fn holder_live(pid: u32) -> bool {
    crate::ids::HostPid::new(pid as i32)
        .and_then(crate::procreg::host_info)
        .is_some_and(|(_, _, zombie)| !zombie)
}

/// The base of the identities records are given: past those of Linux's
/// initial namespaces, as Linux numbers its own.
const IDS: u64 = 4026532000;

impl Store {
    fn named(&self, i: usize) -> &Named {
        self.at(NAMED_AT + i * size_of::<Named>())
    }

    /// The bytes `start..end` of the chain from block `b`, as they read now
    /// (the caller checks they were not changed meanwhile); `None` if the
    /// chain is not whole.
    fn read_range(&self, mut b: u32, start: usize, end: usize) -> Option<Vec<u8>> {
        if end < start || end > BLOCKS * ROOM {
            return None;
        }
        if end == start {
            return Some(Vec::new());
        }
        for _ in 0..start / ROOM {
            if b == 0 || b as usize > BLOCKS {
                return None;
            }
            b = self.block(b).0.load(SeqCst);
        }
        let mut out: Vec<u8> = Vec::with_capacity(end - start);
        let mut at = start % ROOM;
        while out.len() < end - start {
            if b == 0 || b as usize > BLOCKS {
                return None;
            }
            let (link, room) = self.block(b);
            let n = (end - start - out.len()).min(ROOM - at);
            let len = out.len();
            // SAFETY: `n` bytes of a block's room, from `at` (with `at + n`
            // at most `ROOM`), into spare capacity of `out`, then counted.
            unsafe {
                std::ptr::copy_nonoverlapping(room.add(at), out.as_mut_ptr().add(len), n);
                out.set_len(len + n);
            }
            at = 0;
            b = link.load(SeqCst);
        }
        Some(out)
    }
}

/// A named record's slot.
#[derive(Clone, Copy)]
pub struct Slot {
    n: &'static Named,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slot({})", self.n.id.load(SeqCst))
    }
}

fn hash_of(name: &[u8]) -> u64 {
    crate::shared::hash(name) | 1
}

/// Whether slot `n`, live, is the record named `name` (hashed `h`).
fn is(s: &Store, n: &Named, name: &[u8], h: u64) -> bool {
    n.state.load(SeqCst) == LIVE
        && n.hash.load(SeqCst) == h
        && n.name_len.load(SeqCst) as usize == name.len()
        && s.read_chain(n.name_head.load(SeqCst), name.len()).is_some_and(|b| b == name)
        // (Removed while it was read.)
        && n.state.load(SeqCst) == LIVE
}

/// The record named `name`, if there is one.
pub fn find(name: &[u8]) -> Option<Slot> {
    let s = store();
    let h = hash_of(name);
    for k in 0..SLOTS {
        let n = s.named((h as usize).wrapping_add(k) % SLOTS);
        match n.state.load(SeqCst) {
            FREE => return None,
            LIVE if is(s, n, name, h) => return Some(Slot { n }),
            _ => {}
        }
    }
    None
}

/// The record named `name`, made now (with no data: [`Slot::has_data`])
/// if there is none. With no slot free ([`SLOTS`] records), the process
/// ends saying so.
pub fn find_or_make(name: &[u8]) -> Slot {
    if let Some(slot) = find(name) {
        return slot;
    }
    let s = store();
    let _held = hold(s.at(NAMED_LOCK_AT));
    // Made meanwhile by another process.
    if let Some(slot) = find(name) {
        return slot;
    }
    let h = hash_of(name);
    for k in 0..SLOTS {
        let n = s.named((h as usize).wrapping_add(k) % SLOTS);
        if !matches!(n.state.load(SeqCst), FREE | DEAD) {
            continue;
        }
        n.state.store(MAKING, SeqCst);
        for w in [&n.lock, &n.seq, &n.spare, &n.journal_len, &n.journal_tail, &n.note_len] {
            w.store(0, SeqCst);
        }
        for w in [&n.data_head, &n.data_len, &n.journal_head, &n.note_head] {
            w.store(0, SeqCst);
        }
        n.generation.store(0, SeqCst);
        n.data_at.store(0, SeqCst);
        n.journal_epoch.fetch_add(1, SeqCst);
        let next: &AtomicU64 = s.at(NAMED_NEXT_AT);
        n.id.store(IDS + next.fetch_add(1, SeqCst) + 1, SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        n.made.store(now, SeqCst);
        n.name_head.store(s.write_chain(name), SeqCst);
        n.name_len.store(name.len() as u32, SeqCst);
        n.hash.store(h, SeqCst);
        n.state.store(LIVE, SeqCst);
        return Slot { n };
    }
    super::fatal(format_args!("the shared records are full ({SLOTS} are kept)"))
}

/// Every record: its name, and when it was made (seconds since 1970).
pub fn all() -> Vec<(Vec<u8>, u64)> {
    let s = store();
    (0..SLOTS)
        .filter_map(|i| {
            let n = s.named(i);
            if n.state.load(SeqCst) != LIVE {
                return None;
            }
            let name = s.read_chain(n.name_head.load(SeqCst), n.name_len.load(SeqCst) as usize)?;
            (n.state.load(SeqCst) == LIVE).then(|| (name, n.made.load(SeqCst)))
        })
        .collect()
}

/// Remove the record named `name`, if there is one: no process holds it
/// any more ([`crate::shared::collect`]).
pub fn remove(name: &[u8]) {
    let s = store();
    let _held = hold(s.at(NAMED_LOCK_AT));
    let Some(Slot { n }) = find(name) else { return };
    n.state.store(DEAD, SeqCst);
    for (head, len) in [
        (&n.name_head, &n.name_len),
        (&n.data_head, &n.data_len),
        (&n.journal_head, &n.journal_len),
        (&n.note_head, &n.note_len),
    ] {
        let (b, l) = (head.swap(0, SeqCst), len.swap(0, SeqCst));
        if b != 0 {
            s.free_chain(b, l as usize);
        }
    }
}

/// What a read of a record ([`Slot::read`]) found.
pub struct Read {
    /// The generation as the read began: the bytes hold every change up to
    /// it (and maybe some after).
    pub generation: u64,
    /// The data written whole and the generation it is at, if asked for.
    pub data: Option<(u64, Vec<u8>)>,
    /// The journal's bytes from `start`, which the journal's `epoch` has.
    pub journal: Vec<u8>,
    pub start: u32,
    pub epoch: u32,
}

/// The record's lock, held ([`Slot::lock`]), let go when dropped.
pub struct Held {
    n: &'static Named,
    _holding: super::Holding,
}

impl Drop for Held {
    fn drop(&mut self) {
        let_go(self.n);
    }
}

/// Let `n`'s lock go, its waiters woken.
fn let_go(n: &Named) {
    if n.lock.swap(0, SeqCst) & WAITED != 0 {
        wake(&n.lock);
    }
}

impl Slot {
    /// The generation, counted by every change.
    pub fn generation(&self) -> u64 {
        self.n.generation.load(SeqCst) >> 1
    }

    /// Under the lock: the generation moves to `at`, and those waiting for
    /// it to change are woken.
    pub fn advance(&self, _held: &Held, at: u64) {
        if self.n.generation.swap(at << 1, SeqCst) & WAITING != 0 {
            super::wake_all64(&self.n.generation);
        }
    }

    /// Sleep up to `slice_ns` while the generation is `seen`.
    pub fn wait(&self, seen: u64, slice_ns: u64) {
        let word = &self.n.generation;
        let cur = word.load(SeqCst);
        if cur >> 1 != seen {
            return;
        }
        if cur & WAITING == 0 && word.compare_exchange(cur, cur | WAITING, SeqCst, SeqCst).is_err()
        {
            return;
        }
        super::wait64(word, cur | WAITING, slice_ns);
    }

    /// The record's identity.
    pub fn id(&self) -> u64 {
        self.n.id.load(SeqCst)
    }

    /// Whether its data has been written.
    pub fn has_data(&self) -> bool {
        self.n.data_head.load(SeqCst) != 0
    }

    /// The bytes of its data written whole and of its journal.
    pub fn sizes(&self) -> (usize, usize) {
        (self.n.data_len.load(SeqCst) as usize, self.n.journal_len.load(SeqCst) as usize)
    }

    /// Hold the record's lock. One its holder left as it died is taken
    /// over (and a change it left half made, put right as far as its
    /// sequence number goes: the bytes it had not yet put in place are
    /// lost with it).
    pub fn lock(&self) -> Held {
        let me = crate::host::pid().get() as u32;
        let word = &self.n.lock;
        let mut spins = 0;
        loop {
            let holding = super::Holding::enter();
            let cur = match word.compare_exchange(0, me, SeqCst, SeqCst) {
                Ok(_) => return Held { n: self.n, _holding: holding },
                Err(cur) => cur,
            };
            // A short wait for a holder at work, before a host wait.
            if spins < 100 {
                spins += 1;
                std::hint::spin_loop();
                continue;
            }
            if cur & WAITED == 0
                && word.compare_exchange(cur, cur | WAITED, SeqCst, SeqCst).is_err()
            {
                continue;
            }
            // Not counted while it waits (a stop of this process need not
            // wait for another's lock). Woken as it is let go; a while at
            // most, to look at the holder again: still held by the same, it
            // may have died.
            drop(holding);
            wait(word, cur | WAITED, 10_000_000);
            if word.load(SeqCst) == cur | WAITED && !holder_live(cur & !WAITED) {
                self.take_over(cur | WAITED, me);
            }
        }
    }

    /// Take the lock, `held` by a process that died holding it, for `me`.
    fn take_over(&self, held: u32, me: u32) {
        if self.n.lock.compare_exchange(held, me | WAITED, SeqCst, SeqCst).is_ok() {
            let seq = self.n.seq.load(SeqCst);
            if !seq.is_multiple_of(2) {
                self.n.seq.store(seq.wrapping_add(1), SeqCst);
            }
            // Let go at once: the waiters (this one among them) take it in
            // turn.
            let_go(self.n);
        }
    }

    /// Read the record: from journal `epoch`'s byte `start` on when given
    /// and the journal has not started again since, else its data and its
    /// whole journal. `None` if it cannot be read whole (a writer that died
    /// as it changed it).
    pub fn read(&self, from: Option<(u32, u32)>) -> Option<Read> {
        let s = store();
        let n = self.n;
        for round in 0..100_000u32 {
            let seq = n.seq.load(SeqCst);
            if seq.is_multiple_of(2) {
                let generation = n.generation.load(SeqCst) >> 1;
                let epoch = n.journal_epoch.load(SeqCst);
                let (head, len) = (n.journal_head.load(SeqCst), n.journal_len.load(SeqCst));
                let after = from.filter(|&(e, o)| e == epoch && o <= len);
                let (data, start) = match after {
                    Some((_, o)) => (Some(None), o),
                    None => {
                        let at = n.data_at.load(SeqCst);
                        let (h, l) = (n.data_head.load(SeqCst), n.data_len.load(SeqCst));
                        if h == 0 {
                            // No data written yet.
                            return None;
                        }
                        (s.read_chain(h, l as usize).map(|b| Some((at, b))), 0)
                    }
                };
                let journal = s.read_range(head, start as usize, len as usize);
                if n.seq.load(SeqCst) == seq
                    && let (Some(journal), Some(data)) = (journal, data)
                {
                    return Some(Read { generation, data, journal, start, epoch });
                }
            }
            if round > 16 {
                std::thread::yield_now();
            }
            if round > 1000 && !seq.is_multiple_of(2) {
                // Left odd by a writer that died as it changed it: put
                // right as its lock is taken over.
                drop(self.lock());
            }
        }
        None
    }

    /// Under the lock: `bytes` are the data, at generation `at`, and the
    /// journal starts again: its epoch.
    pub fn write_whole(&self, _held: &Held, at: u64, bytes: &[u8]) -> u32 {
        let s = store();
        let n = self.n;
        let head = s.write_chain(bytes);
        let odd = n.seq.load(SeqCst) | 1;
        n.seq.store(odd, SeqCst);
        let data = (n.data_head.swap(head, SeqCst), n.data_len.swap(bytes.len() as u32, SeqCst));
        n.data_at.store(at, SeqCst);
        let journal = (n.journal_head.swap(0, SeqCst), n.journal_len.swap(0, SeqCst));
        n.journal_tail.store(0, SeqCst);
        let epoch = n.journal_epoch.fetch_add(1, SeqCst).wrapping_add(1);
        n.seq.store(odd.wrapping_add(1), SeqCst);
        for (b, l) in [data, journal] {
            if b != 0 {
                s.free_chain(b, l as usize);
            }
        }
        epoch
    }

    /// Under the lock: `bytes` appended to the journal. The journal's epoch
    /// and its length now.
    pub fn append(&self, _held: &Held, bytes: &[u8]) -> (u32, u32) {
        let s = store();
        let n = self.n;
        let len = n.journal_len.load(SeqCst) as usize;
        let epoch = n.journal_epoch.load(SeqCst);
        if n.journal_head.load(SeqCst) == 0 {
            let (first, last) = s.write_chain_ends(bytes);
            n.journal_tail.store(last, SeqCst);
            n.journal_head.store(first, SeqCst);
            n.journal_len.store(bytes.len() as u32, SeqCst);
            return (epoch, bytes.len() as u32);
        }
        // The last block's room first: past the journal's length, which no
        // reader reads.
        let tail = n.journal_tail.load(SeqCst);
        let used = len % ROOM;
        let fits = if used == 0 { 0 } else { (ROOM - used).min(bytes.len()) };
        let (link, room) = s.block(tail);
        // SAFETY: `fits` bytes into the last block's room past its `used`
        // ones, within `ROOM`; a block of this record's, under its lock.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), room.add(used), fits) };
        if fits < bytes.len() {
            let (first, last) = s.write_chain_ends(&bytes[fits..]);
            link.store(first, SeqCst);
            n.journal_tail.store(last, SeqCst);
        }
        n.journal_len.store((len + bytes.len()) as u32, SeqCst);
        (epoch, (len + bytes.len()) as u32)
    }

    /// The note, if one was set.
    pub fn note(&self) -> Option<Vec<u8>> {
        let s = store();
        let n = self.n;
        for _ in 0..100_000 {
            let seq = n.seq.load(SeqCst);
            if seq.is_multiple_of(2) {
                let (h, l) = (n.note_head.load(SeqCst), n.note_len.load(SeqCst));
                let bytes = if h == 0 { Some(None) } else { s.read_chain(h, l as usize).map(Some) };
                if n.seq.load(SeqCst) == seq
                    && let Some(bytes) = bytes
                {
                    return bytes;
                }
            }
            std::thread::yield_now();
        }
        None
    }

    /// Under the lock: the note is `bytes`.
    pub fn set_note(&self, _held: &Held, bytes: &[u8]) {
        let s = store();
        let n = self.n;
        let head = s.write_chain(bytes);
        let odd = n.seq.load(SeqCst) | 1;
        n.seq.store(odd, SeqCst);
        let old = (n.note_head.swap(head, SeqCst), n.note_len.swap(bytes.len() as u32, SeqCst));
        n.seq.store(odd.wrapping_add(1), SeqCst);
        if old.0 != 0 {
            s.free_chain(old.0, old.1 as usize);
        }
    }
}
