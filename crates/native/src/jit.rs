//! Code a program makes executable at run time, run by translation.
//!
//! A JIT compiler writes code into memory and runs it, and keeps data in
//! the same pages: headers, constants, addresses. It reads that memory
//! back, patches it and copies it. So fwe never changes it, and never lets
//! the host run it: the program's memory stays exactly as the program
//! wrote it. Instead, when the program jumps there, the instruction fetch
//! faults, and the block of code at that address is translated into fwe's
//! code cache and run from there, following the program's control flow:
//! only code that runs is ever decoded, so nothing has to tell code from
//! data.
//!
//! A translated block holds the program's instructions as they are, except
//! those whose meaning depends on where they are or that macOS does not
//! let a program run unchanged:
//!
//! - `adr`, `adrp` and literal loads compute from the program's address;
//! - a use of `x18`, a system call and a thread-pointer access are
//!   expanded as [`crate::rewrite`]'s stubs do, inline;
//! - a branch out of the block goes on at the translation of the
//!   program's target. A direct branch traps the first time, and is then
//!   linked, a branch straight to the target's translation. A call leaves
//!   the program's own return address in `x30`, so the stack holds only
//!   the program's addresses, as its unwinders and stack walkers expect.
//!   An indirect branch or return looks its target up in a table of
//!   translations by program address ([`TABLE`]), saving `x16` and `x17`
//!   for it; the translation checks the target is its own (an entry can be
//!   taken over or dropped as a lookup reads it) and restores them. A
//!   dropped entry leads to a retry stub, back to fwe. A target that is
//!   not the program's run-time code (a library's, prepared in place) has
//!   0 for its translation: the lookup restores `x16` and `x17` and makes
//!   the program's own branch through its register, so no register
//!   changes (code may count on that beyond the procedure call standard:
//!   HotSpot calls its atomic stubs saying they clobber only `x8`, `x9`
//!   and `x30`). Through `x18`, which has no register to branch through,
//!   fwe's trap makes it.
//!
//! What the program can observe stays its own: a fault or signal in a
//! translation is delivered at the program's instruction, with its
//! registers ([`to_guest`]); a page a translation was made from is kept
//! from being written, through its own mapping and any other of the same
//! file's page, and a write to it (the program's, or the host's for it)
//! drops its translations, so code the program changes is translated anew.
//!
//! The code cache is made of chunks, each one memory mapped twice: fwe
//! writes translations through a writable view while threads run others
//! from an executable one. A chunk is no larger than a branch reaches, so
//! blocks in one chunk are linked to each other. A full chunk is followed
//! by a new one, or, where at least half of the cache is translations
//! dropped since, the cache is emptied ([`flush`]): every other thread is
//! stopped, the blocks a thread may be in or return into are retired, and
//! the rest of the room is reused.

use crate::rewrite::{self, Site};
use fwe_kernel::Regs;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// `brk #0x4a54` ("JT"): a translated block's way out to fwe.
pub const EXIT_IMM: u32 = 0x4a54;
pub const EXIT: u32 = 0xd420_0000 | (EXIT_IMM << 5);
/// `udf #0`: an instruction no translation can stand for (an
/// authenticated branch fwe does not offer); it faults as `SIGILL` at the
/// program's instruction.
const UDF: u32 = 0;
/// Most instructions a block holds before it ends and goes on to the next.
const BLOCK_INSNS: usize = 64;
/// The most chunks the code cache has (8 GiB of translations).
const MAX_CHUNKS: usize = 64;

/// The chunks' executable views, for [`in_cache`] to read without the
/// translator's lock: the first [`CHUNK_COUNT`] are set.
static CHUNK_RX: [AtomicU64; MAX_CHUNKS] = [const { AtomicU64::new(0) }; MAX_CHUNKS];
static CHUNK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Whether `pc` is in fwe's code cache, cheaply (every system call asks).
pub fn in_cache(pc: u64) -> bool {
    let n = CHUNK_COUNT.load(Ordering::Acquire) as usize;
    let size = chunk_size();
    CHUNK_RX[..n].iter().any(|c| pc.wrapping_sub(c.load(Ordering::Relaxed)) < size)
}

/// The largest code cache chunk: what a branch reaches, so blocks in one
/// chunk can be linked to each other.
const MAX_CHUNK: u64 = 128 << 20;
/// A chunk's size: [`MAX_CHUNK`], or less where `FWE_JIT_CHUNK` (bytes)
/// says, so tests can fill the cache.
static CHUNK_SIZE: AtomicU64 = AtomicU64::new(MAX_CHUNK);

fn chunk_size() -> u64 {
    CHUNK_SIZE.load(Ordering::Relaxed)
}

/// Read `FWE_JIT_CHUNK`, before any code runs by translation.
pub fn configure() {
    install();
    let Some(v) = std::env::var_os("FWE_JIT_CHUNK") else { return };
    let size: u64 = v
        .to_str()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u64| (64 << 10..=MAX_CHUNK).contains(&n) && n.is_multiple_of(page_size()))
        .unwrap_or_else(|| {
            panic!("FWE_JIT_CHUNK: {v:?} is no size in bytes, a multiple of the page size, from 64 KiB to 128 MiB")
        });
    CHUNK_SIZE.store(size, Ordering::Relaxed);
}

/// Have writes the host makes for the program release pages kept from
/// writes first ([`host_writes`]).
fn install() {
    fwe_kernel::mm::on_host_writes(host_writes);
}
/// Room left in a chunk below which the next block goes in a new one: the
/// most a block's translation takes.
const BLOCK_ROOM: u64 = 4 * 64 * 24;
/// The table of translations by program address: at an address an `orr`
/// can encode (one bit), 2^20 entries of (program address, translation).
pub const TABLE: u64 = 1 << 45;
const TABLE_BITS: u32 = 20;
const TABLE_SIZE: u64 = 16 << TABLE_BITS;

// Encodings of the lookup sequence and the stubs.
/// `stp x16, x17, [sp, #-16]!`
const SAVE: u32 = 0xa9bf_47f0;
/// `ldp x16, x17, [sp], #16`
const RESTORE: u32 = 0xa8c1_47f0;
/// `ubfx x17, x16, #2, #20`: the table index.
const INDEX: u32 = 0xd342_5611;
/// `lsl x17, x17, #4`: by the entry's size.
const SCALE: u32 = 0xd37c_ee31;
/// `orr x17, x17, #TABLE`
const BASE: u32 = 0xb253_0231;
/// `ldar x17, [x17]`: the entry's key, before its value.
const KEY: u32 = 0xc8df_fe31;
/// `eor x17, x17, x16`
const CHECK: u32 = 0xca10_0231;
/// `cbnz x17, #off`
const MISS: u32 = 0xb500_0011;
/// `ldr x17, [x17, #8]`: the entry's translation.
const VALUE: u32 = 0xf940_0631;
/// `br x17`
const GO: u32 = 0xd61f_0220;
/// `isb`.
const ISB: u32 = 0xd503_3fdf;
/// `cbz x17, <outside>`: a table entry for a target not translated.
const OUTSIDE: u32 = 0xb400_0011;

/// Where a block's way out leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// To this program address.
    Jump(u64),
    /// To the address in register `n` (`x18`: the program's), `x30`
    /// becoming `link` first for a call.
    Reg { n: u32, link: Option<u64> },
    /// A lookup that came to the wrong block (its entry was taken over or
    /// dropped as it read it), or to the retry stub: on to the address in
    /// `x16`, the program's `x16` and `x17` on the stack.
    Retry,
}

/// What one word of a translation stands for: how a thread stopped there
/// is as the program at one of its instructions.
#[derive(Debug, Clone, Copy)]
enum Word {
    /// The program's instruction at this address, or the start of its
    /// expansion: the program's state is as at it.
    At(u64),
    /// Inside an expansion of the program's instruction at `g` that
    /// started at `start`, before the instruction ran: undone (the
    /// registers it saved restored, `sp` as it was), it is as at `g`.
    Undo { g: u64, start: u64 },
    /// Inside an expansion after the instruction ran: finished (its
    /// remaining words run here), it is as at the next instruction.
    Finish { g: u64 },
    /// Inside the lookup of the branch at `g`, `x16` and `x17` saved:
    /// before it is committed, as at `g`; once committed (`x30` being set
    /// for a call, or the branch taken), as at its target, which `x16`
    /// holds.
    Lookup { g: u64, link: Option<u64>, committed: bool },
    /// A way out, as at the branch at `g`.
    Out { g: u64, exit: Exit },
    /// The retry stub: a lookup that read an entry as it was dropped.
    Retry,
}

/// A translated block.
struct Block {
    /// The program address it translates.
    g: u64,
    /// Its translation's address in the executable view: its first word
    /// restores `x16` and `x17` (entered from a lookup); a direct branch
    /// enters at the next.
    t: u64,
    /// What each word of the translation stands for.
    words: Vec<Word>,
    /// The branches linked straight to it, to undo if it goes.
    linked: Vec<u64>,
    /// Its translation's size in bytes.
    len: u64,
    /// Where a direct branch enters it: past the check and restore a
    /// lookup enters through.
    body: u64,
    /// Kept when the cache was emptied, as a thread may still be in it or
    /// return into it: found by no lookup, and its ways out not linked.
    retired: bool,
}

/// The code cache: chunks, each one memory mapped twice.
struct Cache {
    chunks: Vec<Chunk>,
    /// The chunk new translations go in.
    current: usize,
    /// The retry stub (a dropped entry's value), at the first chunk's start.
    stub: u64,
    /// Bytes of translations in use, and of those dropped (written over,
    /// unmapped) or retired, whose room is had back by emptying the cache.
    live: u64,
    garbage: u64,
    /// Times the cache was emptied.
    flushes: u64,
}

/// A chunk of the code cache: its writable view and its executable one.
struct Chunk {
    rw: u64,
    rx: u64,
    used: u64,
    /// Holds retired translations: nothing new goes in it.
    retired: bool,
}

/// Bytes at the first chunk's start that hold the stub.
const STUB_ROOM: u64 = 8;

pub struct State {
    /// Program memory whose code runs by translation: start -> end.
    regions: BTreeMap<u64, u64>,
    /// Translations by program address.
    by_g: BTreeMap<u64, usize>,
    /// Translations by their address in the cache: start -> block index.
    by_t: BTreeMap<u64, usize>,
    blocks: Vec<Block>,
    /// The program's pages kept from being written (written, they get
    /// their protections back and their translations go).
    guarded: std::collections::BTreeSet<u64>,
    /// Pages -> how many times their guard was lifted. A write that faulted
    /// on a guard another thread lifted before this one's fault was handled
    /// finds the page unguarded: it is tried again while the page's guard
    /// changes between its tries ([`written`]).
    lifted: BTreeMap<u64, u64>,
    /// Host threads -> the address and the page's lift count of the write
    /// each last tried again with its page unguarded.
    retried: BTreeMap<u64, (u64, u64)>,
    /// Program pages -> the blocks made from them.
    pages: BTreeMap<u64, Vec<usize>>,
    /// Program addresses the table says are code not
    /// translated.
    outside: std::collections::BTreeSet<u64>,
    /// Pages translated from that map a file shared (a memfd a JIT maps
    /// twice, writable and executable): the file's page (device, inode,
    /// offset) -> those pages.
    objects: BTreeMap<(u64, u64, u64), std::collections::BTreeSet<u64>>,
    /// Pages of other mappings of those files' pages -> the pages
    /// translated from that they also map. Kept from writes: a write
    /// through one drops their translations.
    aliases: BTreeMap<u64, std::collections::BTreeSet<u64>>,
    /// Code not translated -> the block that branches to it from the
    /// cache where a direct branch does not reach ([`veneer`]).
    veneers: BTreeMap<u64, usize>,
    /// Where calls made from translations return: a return there from
    /// code followed into is followed back ([`exit`]).
    returns: std::collections::BTreeSet<u64>,
    /// Call sites of code not translated that called into translated code
    /// and were linked to it, or tried ([`link_call_site`]).
    call_sites: std::collections::BTreeSet<u64>,
    cache: Option<Cache>,
}

static STATE: Mutex<State> = Mutex::new(State {
    regions: BTreeMap::new(),
    by_g: BTreeMap::new(),
    by_t: BTreeMap::new(),
    blocks: Vec::new(),
    guarded: std::collections::BTreeSet::new(),
    lifted: BTreeMap::new(),
    retried: BTreeMap::new(),
    pages: BTreeMap::new(),
    outside: std::collections::BTreeSet::new(),
    objects: BTreeMap::new(),
    aliases: BTreeMap::new(),
    veneers: BTreeMap::new(),
    returns: std::collections::BTreeSet::new(),
    call_sites: std::collections::BTreeSet::new(),
    cache: None,
});

/// For `FWE_TIMING`: blocks translated, ways out taken through fwe (a
/// branch's first time, a lookup's miss), fetches of the program's code
/// gone on at a translation, and pages whose translations a write dropped.
static TRANSLATED: AtomicU64 = AtomicU64::new(0);
static EXITS: AtomicU64 = AtomicU64::new(0);
static ENTERED: AtomicU64 = AtomicU64::new(0);
/// Of [`EXITS`]: direct branches to code not translated, and indirect
/// ones (and lookup misses) to it; of [`ENTERED`]: returns (to `x30`).
static EXITS_DIRECT_OUT: AtomicU64 = AtomicU64::new(0);
static EXITS_INDIRECT_OUT: AtomicU64 = AtomicU64::new(0);
static ENTERED_RETURNS: AtomicU64 = AtomicU64::new(0);
/// Of [`ENTERED`]: calls (`blr`) from code not translated, counted only
/// for `FWE_TIMING` (it reads the caller's code).
static ENTERED_CALLS: AtomicU64 = AtomicU64::new(0);
/// Call sites of code not translated linked to translations.
static CALL_SITES_LINKED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static FLUSHES: AtomicU64 = AtomicU64::new(0);

/// What [`TRANSLATED`] and the others counted, if any code ran by
/// translation.
pub fn counts() -> Option<String> {
    let t = TRANSLATED.load(Ordering::Relaxed);
    (t > 0).then(|| {
        format!(
            "JIT code: {t} blocks translated, {} exits through fwe ({} direct and {} \
             indirect to code not translated), {} entries by fetch ({} returns, {} calls from code not translated, {} call sites linked), \
             {} pages' translations dropped by writes, the code cache emptied {} times",
            EXITS.load(Ordering::Relaxed),
            EXITS_DIRECT_OUT.load(Ordering::Relaxed),
            EXITS_INDIRECT_OUT.load(Ordering::Relaxed),
            ENTERED.load(Ordering::Relaxed),
            ENTERED_RETURNS.load(Ordering::Relaxed),
            ENTERED_CALLS.load(Ordering::Relaxed),
            CALL_SITES_LINKED.load(Ordering::Relaxed),
            DROPPED.load(Ordering::Relaxed),
            FLUSHES.load(Ordering::Relaxed)
        )
    })
}

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn page_size() -> u64 {
    fwe_kernel::mm::host_page_size()
}

/// The table entry for program address `g`.
fn entry(g: u64) -> &'static [AtomicU64; 2] {
    let at = TABLE | (((g >> 2) & ((1 << TABLE_BITS) - 1)) << 4);
    // SAFETY: an entry of the table, mapped for the process's life once the
    // code cache exists; entries are only ever accessed atomically.
    unsafe { &*(at as *const [AtomicU64; 2]) }
}

/// Make `g`'s entry say translation `t`: the value first, then the key, so
/// a lookup that finds the key finds the value with it.
fn publish(g: u64, t: u64) {
    let e = entry(g);
    e[0].store(0, Ordering::Release);
    e[1].store(t, Ordering::Release);
    e[0].store(g, Ordering::Release);
}

/// Clear `g`'s entry if it says `t`.
fn unpublish(g: u64, t: u64) {
    let e = entry(g);
    if e[0].load(Ordering::Acquire) == g && e[1].load(Ordering::Acquire) == t {
        // A lookup that read the key before this reads the retry stub, not
        // a translation that may go.
        e[1].store(RETRY.load(Ordering::Relaxed), Ordering::Release);
        e[0].store(0, Ordering::Release);
    }
}

/// The retry stub's address ([`new_cache`]).
static RETRY: AtomicU64 = AtomicU64::new(0);

impl State {
    fn in_region(&self, addr: u64) -> bool {
        self.regions.range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
    }

    /// Write `w` at `at` in the cache (its executable address).
    fn patch(&self, at: u64, w: u32) {
        let c = self.cache.as_ref().expect("a code cache");
        let k =
            c.chunks.iter().find(|k| (k.rx..k.rx + chunk_size()).contains(&at)).expect("a chunk");
        // SAFETY: a word of the cache, through its writable view.
        unsafe { ((at - k.rx + k.rw) as *mut u32).write_volatile(w) };
        // SAFETY: the word, in the executable view.
        unsafe { crate::prepare::flush_icache(at, 4) };
    }

    /// Drop the translations made from `[addr, addr + len)`, and give the
    /// pages kept from writes there their protections back.
    fn drop_range(&mut self, addr: u64, len: u64) {
        let start = addr & !(page_size() - 1);
        let end = addr.saturating_add(len);
        // The pages in the range that are kept from writes or translated
        // from (not every page of it: a range may be a reservation of
        // terabytes).
        let guarded: Vec<u64> = self.guarded.range(start..end).copied().collect();
        for p in guarded {
            self.guarded.remove(&p);
            lift(p);
            *self.lifted.entry(p).or_default() += 1;
        }
        // Other mappings of translated pages: the code they map may change
        // through them now, so its translations go too.
        let aliases: Vec<u64> = self.aliases.range(start..end).map(|(&q, _)| q).collect();
        for q in aliases {
            for p in self.aliases.remove(&q).unwrap_or_default() {
                self.drop_range(p, page_size());
            }
        }
        let pages: Vec<u64> = self.pages.range(start..end).map(|(&p, _)| p).collect();
        for p in pages {
            self.objects.retain(|_, ps| {
                ps.remove(&p);
                !ps.is_empty()
            });
            for i in self.pages.remove(&p).unwrap_or_default() {
                let (g, t) = (self.blocks[i].g, self.blocks[i].t);
                if self.by_g.get(&g) == Some(&i) {
                    self.by_g.remove(&g);
                    unpublish(g, t);
                    let len = self.blocks[i].len;
                    if let Some(c) = self.cache.as_mut() {
                        c.live -= len;
                        c.garbage += len;
                    }
                    // Branches linked to it trap again.
                    for at in std::mem::take(&mut self.blocks[i].linked) {
                        self.patch(at, EXIT);
                    }
                }
            }
        }
    }
}

/// Page `p`, kept from writes, gets the protections the program's mapping
/// has now: what it had, or what a call that just changed it (`mmap`,
/// `mprotect`) gave it. A page no longer mapped is left alone.
fn lift(p: u64) {
    let now = fwe_kernel::maps::record().areas_in(p, p + page_size()).first().map(|a| a.value.prot);
    if let Some(prot) = now {
        // SAFETY: a page of the program's memory.
        unsafe { libc::mprotect(p as *mut libc::c_void, page_size() as usize, host_prot(prot)) };
    }
}

/// `[addr, addr + len)` holds code the program made executable after it
/// mapped it: it runs by translation from now on.
pub fn code(addr: u64, len: u64) {
    let mut s = state();
    s.drop_range(addr, len);
    remove(&mut s.regions, addr, len);
    s.regions.insert(addr, addr + len);
    // Lookups that took its addresses for code not translated go again.
    if s.cache.is_some() {
        let gone: Vec<u64> = s.outside.range(addr..addr.saturating_add(len)).copied().collect();
        for g in gone {
            s.outside.remove(&g);
            unpublish(g, 0);
        }
    }
}

/// `[addr, addr + len)` no longer holds such code, or changed beyond what
/// fwe kept watch over (unmapped, mapped anew, its protections changed):
/// its translations are dropped. Whether any of it held such code.
pub fn changed(addr: u64, len: u64) -> bool {
    let mut s = state();
    let end = addr.saturating_add(len);
    let held = s.regions.range(..end).any(|(_, &e)| e > addr);
    s.drop_range(addr, len);
    remove(&mut s.regions, addr, len);
    let gone: Vec<u64> = s.lifted.range(addr & !(page_size() - 1)..end).map(|(&p, _)| p).collect();
    for p in gone {
        s.lifted.remove(&p);
    }
    held
}

/// A new program in this process (`execve`): nothing of the old one's.
pub fn reset() {
    let mut s = state();
    let regions: Vec<(u64, u64)> = s.regions.iter().map(|(&a, &e)| (a, e)).collect();
    for (a, e) in regions {
        s.drop_range(a, e - a);
    }
    s.regions.clear();
    if s.cache.is_some() {
        let entries: Vec<(u64, u64)> = s
            .by_g
            .iter()
            .map(|(&g, &i)| (g, s.blocks[i].t))
            .chain(s.outside.iter().map(|&g| (g, 0)))
            .collect();
        for (g, t) in entries {
            unpublish(g, t);
        }
    }
    s.by_g.clear();
    s.outside.clear();
    s.lifted.clear();
    s.retried.clear();
    s.objects.clear();
    s.aliases.clear();
    s.veneers.clear();
    s.returns.clear();
    s.call_sites.clear();
}

/// Held across a `fork`, so that the child's copy of the translations is
/// whole (no other thread is midway through making one).
pub fn hold() -> std::sync::MutexGuard<'static, State> {
    state()
}

/// In a fork child, with [`hold`]'s guard: the code cache's two views are
/// copies of their own now, so the executable one is mapped anew from the
/// writable one, which the child's translations are written to.
pub fn forked(s: &mut State) {
    let Some(c) = s.cache.as_ref() else { return };
    for k in &c.chunks {
        let mut rx = k.rx;
        let (mut cur, mut max) = (0, 0);
        // SAFETY: fwe's own code cache in this process: a chunk's
        // executable view replaced by a second mapping of its writable one,
        // at the same place.
        unsafe {
            let task = mach::mach_task_self_;
            assert_eq!(
                mach::mach_vm_remap(
                    task,
                    &mut rx,
                    chunk_size(),
                    0,
                    mach::VM_FLAGS_FIXED_OVERWRITE,
                    task,
                    k.rw,
                    0,
                    &mut cur,
                    &mut max,
                    mach::VM_INHERIT_COPY,
                ),
                0
            );
            assert_eq!(rx, k.rx);
            assert_eq!(
                mach::mach_vm_protect(task, rx, chunk_size(), 0, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
        }
    }
}

fn remove(set: &mut BTreeMap<u64, u64>, addr: u64, len: u64) {
    let end = addr.saturating_add(len);
    let hit: Vec<(u64, u64)> =
        set.range(..end).filter(|&(_, &e)| e > addr).map(|(&s, &e)| (s, e)).collect();
    for (s, e) in hit {
        set.remove(&s);
        if s < addr {
            set.insert(s, addr);
        }
        if e > end {
            set.insert(end, e);
        }
    }
}

/// A fetch from the program's memory at `pc` (the thread's `x30` being
/// `lr`, which tells a return): the translation to run instead, if `pc`
/// holds code that runs by translation.
pub fn enter(pc: u64, lr: u64) -> Option<u64> {
    let mut s = state();
    if !s.in_region(pc) {
        return None;
    }
    // Code not translated yet that it cannot read (its page's protections
    // taken away without fwe) is no code to run: the fetch's fault is the
    // program's. (Read as the host copies, which reports a hole rather
    // than fault with the lock held.)
    if !s.by_g.contains_key(&pc) && crate::trap::read_host::<u32>(pc).is_none() {
        return None;
    }
    ENTERED.fetch_add(1, Ordering::Relaxed);
    if lr == pc {
        ENTERED_RETURNS.fetch_add(1, Ordering::Relaxed);
    } else if fwe_kernel::timing::on()
        && !s.in_region(lr.wrapping_sub(4))
        && crate::trap::read_host::<u32>(lr.wrapping_sub(4))
            .is_some_and(|w| w & 0xffff_fc1f == 0xd63f_0000)
    {
        ENTERED_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    let i = translation(&mut s, pc);
    let into = body(&s, i);
    // Called from code fwe prepared in place (`blr xN` before `lr`): that
    // site looks its targets up from now on, as a translation does.
    let site = lr.wrapping_sub(4);
    if lr != pc && !s.call_sites.contains(&site) && !s.in_region(site) && followable(site) {
        // (Read as the host copies: `lr` may be anything.)
        if let Some(w) = crate::trap::read_host::<u32>(site)
            && w & 0xffff_fc1f == 0xd63f_0000
            && !matches!((w >> 5) & 0x1f, 18 | 30)
        {
            link_call_site(&mut s, site, (w >> 5) & 0x1f);
        }
    }
    Some(into)
}

/// Give call site `site` (`blr xN`, in code fwe prepared in place) a stub
/// within reach that looks the target up in the table, as a translation's
/// lookup does, and goes to its translation, or makes the call as it was
/// (target not translated, or not yet): every register as the call would
/// leave it. The site becomes `bl` to it, made with every other thread
/// stopped.
fn link_call_site(s: &mut State, site: u64, n: u32) {
    s.call_sites.insert(site);
    let mut words = vec![
        SAVE,
        0xaa00_03f0 | (n << 16), // mov x16, xN
        INDEX,
        SCALE,
        BASE,
        KEY,
        CHECK,
        MISS,
        INDEX,
        SCALE,
        BASE,
        VALUE,
        OUTSIDE,
        GO,
        RESTORE,
        0xd61f_0000 | (n << 5), // br xN
    ];
    // Both to the restore and the call as it was.
    words[7] |= 7 << 5;
    words[12] |= 2 << 5;
    let _stopped = crate::quiesce::stop_others(&mut |_| {});
    let Some(stub) = crate::prepare::call_stub(site, &words) else { return };
    let Some(b) = rewrite::branch(site, stub) else { return };
    let page = site & !(page_size() - 1);
    let prot = fwe_kernel::mm::host_prot_at(page);
    // Writable a moment, not executable meanwhile (the host allows no page
    // both at once).
    let writable = (prot & !libc::PROT_EXEC) | libc::PROT_READ | libc::PROT_WRITE;
    // SAFETY: a page of the program's code, no other thread running; it
    // gets its protections back.
    unsafe {
        if libc::mprotect(page as *mut libc::c_void, page_size() as usize, writable) != 0 {
            return;
        }
        (site as *mut u32).write(b | 0x8000_0000); // bl
        libc::mprotect(page as *mut libc::c_void, page_size() as usize, prot);
        crate::prepare::flush_icache(site, 4);
    }
    CALL_SITES_LINKED.fetch_add(1, Ordering::Relaxed);
}

/// A write to the program's memory at `addr` that faulted: if the page was
/// kept from writes because code was translated from it, the translations
/// go and it is writable again (the write is to be tried again).
///
/// Threads that write a guarded page at once all fault; the first one
/// handled lifts the guard, and the others find the page unguarded. Their
/// writes are tried again: once, and again only while the page's guard has
/// changed since, so a write that faults for another reason is not tried
/// forever.
pub fn written(addr: u64) -> bool {
    let mut s = state();
    let page = addr & !(page_size() - 1);
    // SAFETY: no preconditions.
    let thread = unsafe { libc::pthread_self() } as u64;
    if s.guarded.contains(&page) {
        s.retried.remove(&thread);
        DROPPED.fetch_add(1, Ordering::Relaxed);
        s.drop_range(page, page_size());
        return true;
    }
    let Some(&lifts) = s.lifted.get(&page) else { return false };
    if !s.in_region(addr) || s.retried.get(&thread) == Some(&(addr, lifts)) {
        s.retried.remove(&thread);
        return false;
    }
    s.retried.insert(thread, (addr, lifts));
    true
}

/// The host is about to write program memory `[addr, addr + len)` for the
/// program (a `read` into it): pages there kept from writes are written as
/// by the program itself ([`written`]), their translations dropped.
pub fn host_writes(addr: u64, len: u64) {
    let mut s = state();
    let start = addr & !(page_size() - 1);
    let kept: Vec<u64> = s.guarded.range(start..addr.saturating_add(len)).copied().collect();
    for p in kept {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        s.drop_range(p, page_size());
    }
}

/// The way out of a block at `regs.pc` (its trap): `regs` go on at the
/// translation of where it leads, or at the address itself where that is
/// not code run by translation; a direct branch is linked there. `false`
/// if `pc` is no way out of fwe's.
pub fn exit(regs: &mut Regs) -> bool {
    let mut s = state();
    let at = regs.pc;
    let exit = match word_at(&s, at) {
        Some(Word::Out { exit, .. }) => exit,
        // The retry stub: an entry dropped as a lookup read it.
        Some(Word::Retry) => Exit::Retry,
        _ => return false,
    };
    EXITS.fetch_add(1, Ordering::Relaxed);
    // A retired block's ways out are not linked: its room is had back once
    // nothing is in it, and a link from it would outlive it.
    let from_retired = block_at(&s, at).is_some_and(|i| s.blocks[i].retired);
    let flushes = s.cache.as_ref().map_or(0, |c| c.flushes);
    let (to, link_here) = match exit {
        Exit::Jump(to) => (to, true),
        Exit::Reg { n, link } => {
            let to = regs.x[n as usize];
            if let Some(link) = link {
                regs.x[30] = link;
            }
            (to, false)
        }
        Exit::Retry => {
            let to = regs.x[16];
            let sp = regs.sp;
            // SAFETY: the stack the lookup saved the program's `x16` and
            // `x17` on.
            let saved = |off: u64| unsafe { ((sp + off) as *const u64).read() };
            (regs.x[16], regs.x[17]) = (saved(0), saved(8));
            regs.sp += 16;
            (to, false)
        }
    };
    // Code fwe prepared in place (a library's, the program's own) that a
    // translation calls or branches to is followed: translated too, so
    // what it calls and where it returns stay in translations. A return
    // is followed only to where a translated call returns; to a caller
    // not translated, it goes back to code that runs as it is.
    let follow = !s.in_region(to)
        && match exit {
            Exit::Reg { n: 30, link: None } => s.returns.contains(&to),
            _ => true,
        }
        && followable(to);
    if !s.in_region(to) && !follow {
        if link_here {
            EXITS_DIRECT_OUT.fetch_add(1, Ordering::Relaxed);
        } else {
            EXITS_INDIRECT_OUT.fetch_add(1, Ordering::Relaxed);
        }
        // Code not translated: its lookups branch to it themselves.
        publish(to, 0);
        s.outside.insert(to);
        // A direct branch to it is linked: straight there where it
        // reaches, else through a veneer.
        if link_here && !from_retired && s.cache.as_ref().is_some_and(|c| c.flushes == flushes) {
            if let Some(b) = rewrite::branch(at, to) {
                s.patch(at, b);
            } else {
                let i = veneer(&mut s, to);
                let same = s.cache.as_ref().is_some_and(|c| c.flushes == flushes);
                if same && let Some(b) = rewrite::branch(at, s.blocks[i].t) {
                    s.patch(at, b);
                    s.blocks[i].linked.push(at);
                }
            }
        }
        regs.pc = to;
        return true;
    }
    let i = translation(&mut s, to);
    let into = body(&s, i);
    // Linked where the target is in reach (in the same chunk), unless the
    // cache was emptied meanwhile (`at` may be reused).
    let same = s.cache.as_ref().is_some_and(|c| c.flushes == flushes);
    if link_here
        && same
        && !from_retired
        && let Some(b) = rewrite::branch(at, into)
    {
        s.patch(at, b);
        s.blocks[i].linked.push(at);
    }
    regs.pc = into;
    true
}

/// The program's address of the instruction a word of a translation at
/// `pc` stands for, if `pc` is in one: a system call made from a
/// translation is the program's `svc`'s, for the kernel (which restarts it
/// there, writes a signal frame from it, and shows it to a tracer).
pub fn guest_pc(pc: u64) -> Option<u64> {
    match word_at(&state(), pc)? {
        Word::At(g)
        | Word::Out { g, .. }
        | Word::Undo { g, .. }
        | Word::Finish { g }
        | Word::Lookup { g, .. } => Some(g),
        Word::Retry => None,
    }
}

/// `regs` stopped in fwe's code cache (a fault, a signal): as the
/// program's state at the instruction it stands for. `false` if `regs.pc`
/// is not in the cache.
pub fn to_guest(regs: &mut Regs) -> bool {
    let s = state();
    let Some(w) = word_at(&s, regs.pc) else { return false };
    let sp = regs.sp;
    // SAFETY: the stack below which fwe's code saved registers.
    let stack = |off: u64| unsafe { (sp.wrapping_add(off) as *const u64).read() };
    match w {
        Word::Out { exit: Exit::Retry, .. } => {
            let to = regs.x[16];
            (regs.x[16], regs.x[17]) = (stack(0), stack(8));
            regs.sp += 16;
            regs.pc = to;
        }
        Word::At(g) | Word::Out { g, .. } => regs.pc = g,
        Word::Undo { g, start } => {
            undo(regs, start);
            regs.pc = g;
        }
        Word::Finish { g } => {
            finish(regs, |at| matches!(word_at(&s, at), Some(Word::Finish { g: o }) if o == g));
            regs.pc = g + 4;
        }
        Word::Lookup { g, link, committed } => {
            let to = regs.x[16];
            (regs.x[16], regs.x[17]) = (stack(0), stack(8));
            regs.sp += 16;
            if committed {
                if let Some(link) = link {
                    regs.x[30] = link;
                }
                regs.pc = to;
            } else {
                regs.pc = g;
            }
        }
        Word::Retry => {
            // `x16` holds the target; the program's `x16` and `x17` are on
            // the stack.
            let to = regs.x[16];
            (regs.x[16], regs.x[17]) = (stack(0), stack(8));
            regs.sp += 16;
            regs.pc = to;
        }
    }
    true
}

fn word_at(s: &State, pc: u64) -> Option<Word> {
    let c = s.cache.as_ref()?;
    if pc == c.stub {
        return Some(Word::Retry);
    }
    let i = block_at(s, pc)?;
    s.blocks[i].words.get(((pc - s.blocks[i].t) / 4) as usize).copied()
}

/// The block whose translation holds `pc`.
fn block_at(s: &State, pc: u64) -> Option<usize> {
    let (&t, &i) = s.by_t.range(..=pc).next_back()?;
    (pc < t + s.blocks[i].len).then_some(i)
}

/// Undo an expansion's words from `start` up to `regs.pc`: each register
/// it saved and has not restored is read back, and `sp` is as before.
fn undo(regs: &mut Regs, start: u64) {
    // What the expansion saved below `sp`, frame by frame: the registers
    // and their offsets in the frame, and its size.
    let mut saved: Vec<(Vec<(u32, u64)>, u64)> = Vec::new();
    let mut at = start;
    while at < regs.pc {
        // SAFETY: a word of fwe's code cache, readable.
        let w = unsafe { (at as *const u32).read() };
        if w & !0x1f == rewrite::PUSH {
            saved.push((vec![(w & 0x1f, 0)], 16));
        } else if w & !0x7c1f == rewrite::PUSH_PAIR {
            saved.push((vec![(w & 0x1f, 0), ((w >> 10) & 0x1f, 8)], 16));
        } else if w == rewrite::SYSCALL_STUB_ENTRY {
            saved.push((vec![(30, 0), (0, 8)], 32));
        } else if w & 0xffc0_03ff == rewrite::SUB_SP {
            // A frame made at once, filled by the stores below.
            saved.push((Vec::new(), u64::from((w >> 10) & 0xfff)));
        } else if w & !0x7c1f == rewrite::STP_SP {
            let frame = &mut saved.last_mut().expect("a frame stored into").0;
            frame.extend([(w & 0x1f, 0), ((w >> 10) & 0x1f, 8)]);
        } else if w & 0xffc0_03e0 == rewrite::STR_UIMM | 31 << 5 {
            let frame = &mut saved.last_mut().expect("a frame stored into").0;
            frame.push((w & 0x1f, u64::from((w >> 10) & 0xfff) * 8));
        } else if w & !0x1f == rewrite::POP || w & !0x7c1f == rewrite::POP_PAIR {
            saved.pop();
        }
        at += 4;
    }
    for (regs_saved, size) in saved.iter().rev() {
        for &(r, off) in regs_saved {
            // SAFETY: the stack the expansion saved registers on.
            regs.x[r as usize] = unsafe { ((regs.sp + off) as *const u64).read() };
        }
        regs.sp += size;
    }
}

/// Finish an expansion from `regs.pc`, its instruction having run: its
/// remaining words (those `ours` says are) store `x18` back, restore saved
/// registers and move `sp`; they are carried out here, up to its way on (a
/// branch, or the next instruction's translation).
fn finish(regs: &mut Regs, ours: impl Fn(u64) -> bool) {
    while ours(regs.pc) {
        // SAFETY: a word of fwe's code cache, readable.
        let w = unsafe { (regs.pc as *const u32).read() };
        if !step(regs, w) {
            return;
        }
        regs.pc += 4;
    }
}

/// Carry out word `w` of an expansion's ending on `regs`, if it is one of
/// the words they hold; `false` for any other (its way on).
fn step(regs: &mut Regs, w: u32) -> bool {
    // A base register: 31 is `sp`.
    let base = |regs: &Regs, n: u32| if n == 31 { regs.sp } else { regs.x[n as usize] };
    // SAFETY: the stack the expansion saved registers on, or the thread's
    // own TSD slots.
    let read = |a: u64| unsafe { (a as *const u64).read() };
    let (t, n) = (w & 0x1f, (w >> 5) & 0x1f);
    if w & !0x1f == rewrite::POP {
        regs.x[t as usize] = read(regs.sp);
        regs.sp += 16;
    } else if w & !0x7c1f == rewrite::POP_PAIR {
        regs.x[t as usize] = read(regs.sp);
        regs.x[((w >> 10) & 0x1f) as usize] = read(regs.sp + 8);
        regs.sp += 16;
    } else if w == rewrite::POP32_X30 {
        regs.x[30] = read(regs.sp);
        regs.sp += 32;
    } else if w & 0xffc0_0000 == rewrite::STR_UIMM {
        // `str xT, [xN, #imm]`: storing `x18`'s new value in its slot, or
        // the thread pointer's in its own.
        let imm = u64::from((w >> 10) & 0xfff) * 8;
        let value = regs.x[t as usize];
        // SAFETY: the thread's own TSD slot, or the stack the expansion
        // saved registers on.
        unsafe { ((base(regs, n) + imm) as *mut u64).write(value) };
        // `regs` carry the guest's `x18` (written back to its slot as the
        // thread goes on): it is the new value too.
        if n != 31 && imm == u64::from(crate::x18_slot()) {
            regs.x[18] = value;
        }
    } else if w & 0xffc0_0000 == rewrite::LDR_UIMM {
        let imm = u64::from((w >> 10) & 0xfff) * 8;
        regs.x[t as usize] = read(base(regs, n) + imm);
    } else if w & !0x7c1f == rewrite::LDP_SP {
        regs.x[t as usize] = read(regs.sp);
        regs.x[((w >> 10) & 0x1f) as usize] = read(regs.sp + 8);
    } else if w & 0xffc0_03ff == rewrite::ADD_SP {
        regs.sp += u64::from((w >> 10) & 0xfff);
    } else if w & 0xffc0_03ff == rewrite::SUB_SP {
        regs.sp -= u64::from((w >> 10) & 0xfff);
    } else if w & !0x03e0 == rewrite::MOV_TO_SP {
        regs.sp = regs.x[n as usize];
    } else if w & 0xffe0_ffe0 == rewrite::MOV {
        regs.x[t as usize] = regs.x[((w >> 16) & 0x1f) as usize];
    } else if w & 0xffe0_fc00 == rewrite::ADD_REG {
        let m = ((w >> 16) & 0x1f) as usize;
        regs.x[t as usize] = regs.x[n as usize].wrapping_add(regs.x[m]);
    } else if w & 0xffe0_0c00 == rewrite::LDUR {
        let imm = i64::from(((w >> 12) & 0x1ff) as i32) << 55 >> 55;
        regs.x[t as usize] = read(base(regs, n).wrapping_add_signed(imm));
    } else {
        return false;
    }
    true
}

/// Where a direct branch enters block `i`: past the word that restores
/// what a lookup saved.
fn body(s: &State, i: usize) -> u64 {
    s.blocks[i].body
}

/// The translation of program address `g`, made if there is none.
fn translation(s: &mut State, g: u64) -> usize {
    if let Some(&i) = s.by_g.get(&g) {
        // Its table entry may have gone to another address since (they
        // share entries): it is its own again.
        publish(g, s.blocks[i].t);
        return i;
    }
    if s.cache.is_none() {
        s.cache = Some(new_cache());
    }
    // The page is kept from writes before it is read: a write after this
    // faults and drops the translation, one before it is in what is read.
    // (Room is made first: emptying the cache lifts every guard.)
    let page = g & !(page_size() - 1);
    let at = cache_next(s);
    guard(s, page);
    let followed = !s.in_region(g);
    let (words, info, entry, calls) = translate(g, at, followed);
    // Where its calls return is followed too, from code not translated
    // (a library's function the call went to): no longer branched to as
    // code not translated.
    for r in calls {
        if s.returns.insert(r) && s.outside.remove(&r) {
            unpublish(r, 0);
        }
    }
    let t = emit(s, &words);
    let len = 4 * words.len() as u64;
    s.cache.as_mut().expect("a code cache").live += len;
    let i = s.blocks.len();
    s.pages.entry(page).or_default().push(i);
    s.blocks.push(Block {
        g,
        t,
        words: info,
        linked: Vec::new(),
        len,
        body: t + 4 * entry as u64,
        retired: false,
    });
    s.by_g.insert(g, i);
    s.by_t.insert(t, i);
    publish(g, t);
    TRANSLATED.fetch_add(1, Ordering::Relaxed);
    i
}

/// Keep program page `p` from being written while translations of it are
/// in use, through its own mapping and any other of the same file's page:
/// a write faults ([`written`]).
fn guard(s: &mut State, p: u64) {
    if !s.pages.contains_key(&p) {
        // Its first translation: the other mappings of what it maps.
        let rec = fwe_kernel::maps::record();
        if let Some(k) = shared_page(&rec, p) {
            let others: Vec<u64> =
                rec.areas().iter().filter_map(|a| alias_in(a, k)).filter(|&q| q != p).collect();
            drop(rec);
            s.objects.entry(k).or_default().insert(p);
            for q in others {
                s.aliases.entry(q).or_default().insert(p);
                keep(s, q);
            }
        }
    }
    keep(s, p);
}

/// The file page (device, inode, offset) program page `p` maps, if it
/// maps a file shared (which another mapping may map too).
fn shared_page(rec: &fwe_kernel::maps::Held, p: u64) -> Option<(u64, u64, u64)> {
    let a = rec.areas_in(p, p + page_size()).into_iter().next()?;
    let o = &a.value.object;
    (a.value.shared && o.ino != 0 && matches!(o.name, fwe_kernel::maps::Name::Path(_)))
        .then_some((o.dev, o.ino, o.offset))
}

/// The page of mapping `a` that maps file page `k`, if it does.
fn alias_in(
    a: &fwe_kernel::vmas::Piece<fwe_kernel::maps::Area>,
    k: (u64, u64, u64),
) -> Option<u64> {
    let o = &a.value.object;
    let len = a.end - a.start;
    (a.value.shared && (o.dev, o.ino) == (k.0, k.1) && (o.offset..o.offset + len).contains(&k.2))
        .then(|| a.start + (k.2 - o.offset))
}

/// `[addr, addr + len)` was just mapped, or given other protections:
/// pages of it that map a file's page code was translated from are kept
/// from writes, as that code's other mappings are ([`guard`]).
pub fn mapped(addr: u64, len: u64) {
    // (Its lock before the record's, as everywhere.)
    let mut s = state();
    if s.objects.is_empty() {
        return;
    }
    let rec = fwe_kernel::maps::record();
    let mut found = Vec::new();
    for a in rec.areas_in(addr, addr.saturating_add(len)) {
        let o = &a.value.object;
        if !a.value.shared || o.ino == 0 {
            continue;
        }
        let span = (o.dev, o.ino, o.offset)..(o.dev, o.ino, o.offset + (a.end - a.start));
        for (&k, ps) in s.objects.range(span) {
            let q = a.start + (k.2 - o.offset);
            found.extend(ps.iter().filter(|&&p| p != q).map(|&p| (q, p)));
        }
    }
    drop(rec);
    for (q, p) in found {
        s.aliases.entry(q).or_default().insert(p);
        keep(&mut s, q);
    }
}

/// Keep program page `p` from being written, if it may be.
fn keep(s: &mut State, p: u64) {
    if s.guarded.contains(&p) {
        return;
    }
    let prot = fwe_kernel::maps::record()
        .areas_in(p, p + page_size())
        .first()
        .map_or(libc::PROT_READ, |a| host_prot(a.value.prot));
    if prot & libc::PROT_WRITE == 0 {
        return;
    }
    // SAFETY: a page of the program's memory; it stays readable.
    unsafe {
        libc::mprotect(p as *mut libc::c_void, page_size() as usize, prot & !libc::PROT_WRITE)
    };
    s.guarded.insert(p);
    fwe_kernel::mm::keeping_pages();
}

/// The host protections of the program's memory with Linux protections
/// `prot`, code that runs by translation never executable.
fn host_prot(prot: u64) -> libc::c_int {
    let mut p = libc::PROT_NONE;
    // Code is read by fwe to be translated: executable is readable.
    if prot & (fwe_abi::mman::PROT_READ | fwe_abi::mman::PROT_EXEC) != 0 {
        p |= libc::PROT_READ;
    }
    if prot & fwe_abi::mman::PROT_WRITE != 0 {
        p |= libc::PROT_WRITE;
    }
    p
}

mod mach {
    unsafe extern "C" {
        pub static mach_task_self_: u32;
        pub fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: i32) -> i32;
        pub fn mach_vm_remap(
            task: u32,
            target: *mut u64,
            size: u64,
            mask: u64,
            flags: i32,
            src_task: u32,
            src: u64,
            copy: i32,
            cur: *mut i32,
            max: *mut i32,
            inherit: u32,
        ) -> i32;
        pub fn mach_vm_protect(task: u32, addr: u64, size: u64, set_max: i32, prot: i32) -> i32;
        pub fn mach_vm_read_overwrite(
            task: u32,
            addr: u64,
            size: u64,
            data: u64,
            out: *mut u64,
        ) -> i32;
    }
    pub const VM_FLAGS_FIXED: i32 = 0;
    pub const VM_FLAGS_ANYWHERE: i32 = 1;
    pub const VM_FLAGS_FIXED_OVERWRITE: i32 = 0x4000;
    pub const VM_INHERIT_COPY: u32 = 1;
}

/// A new chunk of the code cache: one memory, mapped a second time, the
/// second view executable and not writable.
fn new_chunk() -> Chunk {
    let (mut rw, mut rx) = (0u64, 0u64);
    let (mut cur, mut max) = (0, 0);
    // SAFETY: fresh memory in this task, mapped twice.
    unsafe {
        let task = mach::mach_task_self_;
        assert_eq!(mach::mach_vm_allocate(task, &mut rw, chunk_size(), mach::VM_FLAGS_ANYWHERE), 0);
        assert_eq!(
            mach::mach_vm_remap(
                task,
                &mut rx,
                chunk_size(),
                0,
                mach::VM_FLAGS_ANYWHERE,
                task,
                rw,
                0,
                &mut cur,
                &mut max,
                mach::VM_INHERIT_COPY,
            ),
            0
        );
        assert_eq!(
            mach::mach_vm_protect(task, rx, chunk_size(), 0, libc::PROT_READ | libc::PROT_EXEC),
            0
        );
    }
    let n = CHUNK_COUNT.load(Ordering::Relaxed) as usize;
    assert!(n < MAX_CHUNKS, "fwe's code cache is full");
    CHUNK_RX[n].store(rx, Ordering::Relaxed);
    CHUNK_COUNT.store(n as u64 + 1, Ordering::Release);
    Chunk { rw, rx, used: 0, retired: false }
}

/// The code cache, its retry stub, and the table.
fn new_cache() -> Cache {
    let mut table = TABLE;
    // SAFETY: fresh memory in this task, at the table's fixed place.
    unsafe {
        assert_eq!(
            mach::mach_vm_allocate(
                mach::mach_task_self_,
                &mut table,
                TABLE_SIZE,
                mach::VM_FLAGS_FIXED
            ),
            0,
            "fwe's translation table's place ({TABLE:#x}) is taken"
        );
    }
    let mut c =
        Cache { chunks: vec![new_chunk()], current: 0, stub: 0, live: 0, garbage: 0, flushes: 0 };
    // The retry stub, a dropped entry's value: fwe's trap.
    c.stub = write(&mut c, &[EXIT]);
    c.chunks[0].used = STUB_ROOM;
    RETRY.store(c.stub, Ordering::Relaxed);
    c
}

/// Where the next block goes: in the current chunk while it has room for
/// the largest block; else, the cache is emptied where at least half of it
/// is dropped translations, and the block goes in a chunk with room, or a
/// new one.
/// The block that branches from the cache to `to`, code not translated
/// that a direct branch from the cache does not reach: `to` loaded into
/// `x16`, then `br x16`, as a linker's veneer does (AAPCS64 lets one
/// clobber `x16` and `x17` on a direct branch to other code). A block, so
/// emptying the cache keeps it while a thread is in it, and unlinks the
/// branches to it when it goes.
fn veneer(s: &mut State, to: u64) -> usize {
    if let Some(&i) = s.veneers.get(&to) {
        return i;
    }
    cache_next(s);
    let mut words = Vec::new();
    materialize(16, to, &mut words);
    words.push(0xd61f_0200); // br x16
    let t = emit(s, &words);
    let len = 4 * words.len() as u64;
    s.cache.as_mut().expect("a code cache").live += len;
    let i = s.blocks.len();
    // A thread stopped in it goes on at `to`, its x16 the veneer's.
    s.blocks.push(Block {
        g: to,
        t,
        words: vec![Word::At(to); words.len()],
        linked: Vec::new(),
        len,
        body: t,
        retired: false,
    });
    s.by_t.insert(t, i);
    s.veneers.insert(to, i);
    i
}

/// Whether program address `to` holds code fwe prepared in place that a
/// translation may follow into: in an executable mapping of the program's,
/// and not a stub of fwe's.
fn followable(to: u64) -> bool {
    !in_cache(to)
        && crate::prepare::stub_region(to).is_none()
        && fwe_kernel::maps::record()
            .areas_in(to, to + 4)
            .first()
            .is_some_and(|a| a.value.prot & fwe_abi::mman::PROT_EXEC != 0)
}

fn cache_next(s: &mut State) -> u64 {
    let room = |k: &Chunk| !k.retired && k.used + BLOCK_ROOM <= chunk_size();
    let c = s.cache.as_ref().expect("a code cache");
    if !room(&c.chunks[c.current]) {
        if c.garbage >= c.live {
            flush(s);
        }
        let c = s.cache.as_mut().expect("a code cache");
        match c.chunks.iter().position(room) {
            Some(k) => c.current = k,
            None => {
                c.chunks.push(new_chunk());
                c.current = c.chunks.len() - 1;
            }
        }
    }
    let c = s.cache.as_ref().expect("a code cache");
    let k = &c.chunks[c.current];
    k.rx + k.used
}

/// Words a flush reads of memory at a time.
const SCAN_PIECE: usize = 2048;
/// How far above a stopped thread's `sp` a flush looks: past the deepest
/// stack fwe's code runs on (a signal stack, a gate stack).
const SCAN_STACK: u64 = 2 << 20;

/// Empty the code cache (every other thread stopped), but for the blocks a
/// thread may be in or return into: any whose translation a thread's
/// registers, the stack it is on, or a gate block (a call's way back)
/// points into. Those are retired, their ways out unlinked; the room of
/// every other block is had back, and their code translated again as it
/// runs.
fn flush(s: &mut State) {
    let mut pinned = vec![false; s.blocks.len()];
    let gates = crate::gate::blocks();
    let mut buf = vec![0u64; SCAN_PIECE];
    let stopped = {
        let st: &State = s;
        let mut mark = |v: u64| {
            if in_cache(v)
                && let Some(i) = block_at(st, v)
            {
                pinned[i] = true;
            }
        };
        let stopped = crate::quiesce::stop_others(&mut |regs| {
            for &r in &regs[..33] {
                mark(r);
            }
            scan(regs[31], SCAN_STACK, &mut buf, &mut mark);
        });
        for &b in &gates {
            scan(b, std::mem::size_of::<crate::gate::Block>() as u64, &mut buf, &mut mark);
        }
        stopped
    };
    let old = std::mem::take(&mut s.blocks);
    let in_pinned = |s: &State, at: u64| {
        s.by_t.range(..=at).next_back().is_some_and(|(&t, &i)| at < t + old[i].len && pinned[i])
    };
    for (&g, &i) in &s.by_g {
        unpublish(g, old[i].t);
    }
    // No branch from a retired block leads into the room had back.
    for b in &old {
        for &at in &b.linked {
            if in_pinned(s, at) {
                s.patch(at, EXIT);
            }
        }
    }
    let mut kept = 0;
    s.by_t.clear();
    s.by_g.clear();
    s.pages.clear();
    for (i, b) in old.into_iter().enumerate() {
        if pinned[i] {
            kept += b.len;
            s.by_t.insert(b.t, s.blocks.len());
            s.blocks.push(Block { linked: Vec::new(), retired: true, ..b });
        }
    }
    // Nothing is translated from the program's pages now.
    s.objects.clear();
    s.veneers.clear();
    s.aliases.clear();
    let pages = std::mem::take(&mut s.guarded);
    for p in pages {
        lift(p);
        *s.lifted.entry(p).or_default() += 1;
    }
    let size = chunk_size();
    let blocks = &s.blocks;
    let c = s.cache.as_mut().expect("a code cache");
    for (n, k) in c.chunks.iter_mut().enumerate() {
        k.retired = blocks.iter().any(|b| (k.rx..k.rx + size).contains(&b.t));
        if !k.retired {
            k.used = if n == 0 { STUB_ROOM } else { 0 };
        }
    }
    c.live = 0;
    c.garbage = kept;
    c.flushes += 1;
    FLUSHES.fetch_add(1, Ordering::Relaxed);
    drop(stopped);
}

/// Pass each 8-byte word of `[from, from + len)` that can be read to
/// `mark`, reading through the host's copy of this task's memory (which
/// reports a hole rather than fault) a piece at a time; stops at the first
/// piece that cannot be read. Takes no lock and allocates nothing.
fn scan(from: u64, len: u64, buf: &mut [u64], mark: &mut impl FnMut(u64)) {
    let piece = 8 * buf.len() as u64;
    let end = from.saturating_add(len);
    let mut at = from & !7;
    while at < end {
        let n = ((at / piece + 1) * piece).min(end) - at;
        let mut out = 0u64;
        // SAFETY: copying `n` bytes (at most `piece`) into `buf`.
        let r = unsafe {
            mach::mach_vm_read_overwrite(
                mach::mach_task_self_,
                at,
                n,
                buf.as_mut_ptr() as u64,
                &mut out,
            )
        };
        if r != 0 || out != n {
            return;
        }
        for &w in &buf[..(n / 8) as usize] {
            mark(w);
        }
        at += n;
    }
}

/// Write `words` at the current chunk's next free place (8-byte aligned,
/// as a system call's stub needs for its literal): their executable
/// address.
fn write(c: &mut Cache, words: &[u32]) -> u64 {
    let k = &mut c.chunks[c.current];
    let len = 4 * words.len() as u64;
    assert!(k.used + len <= chunk_size(), "a block larger than the room kept for one");
    let off = k.used;
    for (i, &w) in words.iter().enumerate() {
        // SAFETY: inside the chunk's writable view.
        unsafe { ((k.rw + off + 4 * i as u64) as *mut u32).write(w) };
    }
    k.used = (off + len + 7) & !7;
    // SAFETY: the words just written, in the executable view.
    unsafe { crate::prepare::flush_icache(k.rx + off, len) };
    k.rx + off
}

fn emit(s: &mut State, words: &[u32]) -> u64 {
    write(s.cache.as_mut().expect("a code cache"), words)
}

/// The program's instruction at `g`, read from its memory.
fn read(g: u64) -> u32 {
    // SAFETY: the program's code, mapped readable (it runs by translation).
    unsafe { (g as *const u32).read() }
}

/// Translate the block at program address `g`, to be placed at `t`: its
/// words, and what each stands for. A block ends at its page's end, so it
/// is made from that page alone.
fn translate(g: u64, t: u64, followed: bool) -> (Vec<u32>, Vec<Word>, usize, Vec<u64>) {
    // Entered from a lookup with the target in `x16`, the program's `x16`
    // and `x17` on the stack: the target is checked to be this block's (a
    // lookup can read an entry another thread is taking over), then they
    // are restored. A direct branch enters past them.
    let entered = Word::Lookup { g, link: None, committed: true };
    let mut out: Vec<u32> = Vec::new();
    materialize(17, g, &mut out);
    out.push(CHECK);
    let wrong_at = out.len();
    out.push(MISS);
    out.push(RESTORE);
    let mut info: Vec<Word> = vec![entered; out.len()];
    let entry = out.len();
    let calls = body_of(g, t, followed, &mut out, &mut info);
    // The wrong block's way out.
    let wrong = out.len();
    out[wrong_at] |= ((wrong - wrong_at) as u32) << 5;
    out.push(EXIT);
    info.push(Word::Out { g, exit: Exit::Retry });
    (out, info, entry, calls)
}

/// The instructions of the block at program address `g`, translated onto
/// `out` (the block placed at `t`); `followed`, code fwe prepared in place
/// (a library's), read as the program wrote it. Where its calls return.
fn body_of(g: u64, t: u64, followed: bool, out: &mut Vec<u32>, info: &mut Vec<Word>) -> Vec<u64> {
    let page = page_size();
    let mut pc = g;
    let mut calls = Vec::new();
    for _ in 0..BLOCK_INSNS {
        let w = if followed { crate::prepare::original(pc, read(pc)) } else { read(pc) };
        // `bl`, `blr`
        if w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000 {
            calls.push(pc + 4);
        }
        let ended = one(w, pc, t, out, info);
        pc += 4;
        // Ends at a branch out, or at the page's end (the next page may not
        // be the program's code).
        if ended {
            return calls;
        }
        if pc & (page - 1) == 0 {
            break;
        }
    }
    out.push(EXIT);
    info.push(Word::Out { g: pc, exit: Exit::Jump(pc) });
    calls
}

/// Translate the program's instruction `w` at `pc` into `out`, the block
/// placed at `t`, recording what each word stands for. Whether it ends the
/// block.
fn one(w: u32, pc: u64, t: u64, out: &mut Vec<u32>, info: &mut Vec<Word>) -> bool {
    let here = |out: &Vec<u32>| t + 4 * out.len() as u64;
    let imm26 = || pc.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
    let imm19 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x7_ffff) << 13) as i32 >> 11));
    let imm14 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x3fff) << 18) as i32 >> 16));
    let jump = |out: &mut Vec<u32>, info: &mut Vec<Word>, to: u64| {
        out.push(EXIT);
        info.push(Word::Out { g: pc, exit: Exit::Jump(to) });
    };
    // b
    if w & 0xfc00_0000 == 0x1400_0000 {
        jump(out, info, imm26());
        return true;
    }
    // bl: the program's return address in x30, then on.
    if w & 0xfc00_0000 == 0x9400_0000 {
        let at = out.len();
        materialize(30, pc + 4, out);
        info.extend((at..out.len()).map(|_| Word::At(pc)));
        jump(out, info, imm26());
        return true;
    }
    // b.cond (and bc.cond): to the taken way out two words on.
    if w & 0xff00_0000 == 0x5400_0000 {
        out.push((w & !(0x7_ffff << 5)) | (2 << 5));
        info.push(Word::At(pc));
        jump(out, info, pc + 4);
        jump(out, info, imm19());
        return true;
    }
    // cbz/cbnz, tbz/tbnz
    let family = (w >> 25) & 0x3f;
    if family == 0b011010 || family == 0b011011 {
        let taken = if family == 0b011010 { imm19() } else { imm14() };
        let field = if family == 0b011010 { 0x7_ffff << 5 } else { 0x3fff << 5 };
        if w & 0x1f == 18 {
            // Of x18: its value from its slot into x16 (x16 and x17 saved
            // below sp, as a lookup saves them), tested there; each way
            // restores them and goes on, linked as any branch is.
            let before = Word::Lookup { g: pc, link: None, committed: false };
            out.push(SAVE);
            info.push(Word::At(pc));
            let slot = crate::x18_slot();
            out.extend([
                rewrite::MRS_TPIDRRO | 16,
                rewrite::AND_NOT7 | (16 << 5) | 16,
                rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 16,
                (w & !field & !0x1f) | (3 << 5) | 16,
                RESTORE,
            ]);
            info.extend([before; 5]);
            jump(out, info, pc + 4);
            out.push(RESTORE);
            info.push(before);
            jump(out, info, taken);
            return true;
        }
        out.push((w & !field) | (2 << 5));
        info.push(Word::At(pc));
        jump(out, info, pc + 4);
        jump(out, info, taken);
        return true;
    }
    // br, blr, ret
    match w & 0xffff_fc1f {
        0xd61f_0000 | 0xd65f_0000 => {
            lookup(pc, (w >> 5) & 0x1f, None, out, info);
            return true;
        }
        0xd63f_0000 => {
            lookup(pc, (w >> 5) & 0x1f, Some(pc + 4), out, info);
            return true;
        }
        _ => {}
    }
    if (w >> 25) & 0x7f == 0b110_1011 {
        // Another branch through a register (authenticated): no stand-in.
        out.push(UDF);
        info.push(Word::At(pc));
        return true;
    }
    // adr, adrp
    if w & 0x1f00_0000 == 0x1000_0000 {
        let imm = (((w >> 5) & 0x7_ffff) << 2) | ((w >> 29) & 3);
        let imm = i64::from(((imm << 11) as i32) >> 11);
        let v = if w >> 31 == 1 {
            (pc & !0xfff).wrapping_add_signed(imm << 12)
        } else {
            pc.wrapping_add_signed(imm)
        };
        if w & 0x1f == 18 {
            expansion(Site::X18 { insn: w }, pc, here(out), out, info);
        } else {
            let at = out.len();
            materialize(w & 0x1f, v, out);
            info.extend((at..out.len()).map(|_| Word::At(pc)));
        }
        return false;
    }
    // Literal loads.
    if w & 0x3b00_0000 == 0x1800_0000 {
        let addr = imm19();
        let (v, opc, rt) = ((w >> 26) & 1, w >> 30, w & 0x1f);
        let at = out.len();
        match (v, opc) {
            (0, 3) => {} // prfm: a hint, dropped
            (0, _) if rt == 18 => {
                expansion(Site::X18 { insn: w }, pc, here(out), out, info);
                return false;
            }
            (0, _) => {
                materialize(rt, addr, out);
                let load = match opc {
                    0 => 0xb940_0000,
                    1 => 0xf940_0000,
                    _ => 0xb980_0000,
                };
                out.push(load | (rt << 5) | rt);
            }
            (_, _) => {
                // A vector register: the address in x16, saved around it.
                let start = here(out);
                out.push(rewrite::PUSH | 16);
                info.push(Word::At(pc));
                let m = out.len();
                materialize(16, addr, out);
                info.extend((m..out.len()).map(|_| Word::Undo { g: pc, start }));
                let load = match opc {
                    0 => 0xbd40_0000,
                    1 => 0xfd40_0000,
                    _ => 0x3dc0_0000,
                };
                out.push(load | (16 << 5) | rt);
                info.push(Word::Undo { g: pc, start });
                out.push(rewrite::POP | 16);
                info.push(Word::Finish { g: pc });
                return false;
            }
        }
        info.extend((at..out.len()).map(|_| Word::At(pc)));
        return false;
    }
    // `isb`: from here the program runs what it wrote to code before it
    // (the architecture's rule for self-modifying code). The block ends:
    // its way out goes on at the next instruction's translation, made again
    // if a write dropped it (and unlinked the way there).
    if w == ISB {
        out.push(w);
        info.push(Word::At(pc));
        jump(out, info, pc + 4);
        return true;
    }
    // A system call (Linux ignores `svc`'s immediate).
    if w & 0xffe0_001f == 0xd400_0001 {
        let gate = crate::syscall_gate();
        if gate == 0 {
            out.push(rewrite::TRAP);
            info.push(Word::At(pc));
        } else {
            // The stub's literal is 8-byte aligned.
            if here(out) % 8 != 0 {
                out.push(rewrite::NOP);
                info.push(Word::At(pc));
            }
            let stub_at = here(out);
            let words = rewrite::stub(Site::Syscall { gate }, 0, 0, stub_at, stub_at + 32);
            for (k, &sw) in words.iter().enumerate() {
                out.push(sw);
                // Before the call returns: undone (the call not made);
                // after: finished.
                info.push(match k {
                    0 => Word::At(pc),
                    1..=2 => Word::Undo { g: pc, start: stub_at },
                    _ => Word::Finish { g: pc },
                });
            }
        }
        return false;
    }
    // The thread pointer.
    if w & !rewrite::RT_MASK == rewrite::MRS_TPIDR {
        let rt = w & rewrite::RT_MASK;
        if rt != 31 {
            expansion(Site::ReadThreadPointer { rt }, pc, here(out), out, info);
        }
        return false;
    }
    if w & !rewrite::RT_MASK == rewrite::MSR_TPIDR {
        expansion(Site::WriteThreadPointer { rt: w & rewrite::RT_MASK }, pc, here(out), out, info);
        return false;
    }
    // x18
    if rewrite::x18_site(w) {
        expansion(Site::X18 { insn: w }, pc, here(out), out, info);
        return false;
    }
    if crate::decode::names_x18(w) {
        // A form fwe has no stand-in for.
        out.push(UDF);
        info.push(Word::At(pc));
        return true;
    }
    out.push(w);
    info.push(Word::At(pc));
    false
}

/// An indirect branch through `x<n>` at `pc`, a call if `link` (the
/// return address): its target looked up in the table, `x16` and `x17`
/// saved for it; a miss traps.
fn lookup(pc: u64, n: u32, link: Option<u64>, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    let before = Word::Lookup { g: pc, link, committed: false };
    out.push(SAVE);
    info.push(Word::At(pc));
    // x16: the target.
    match n {
        16 => out.push(0xf940_03f0), // ldr x16, [sp]
        17 => out.push(0xf940_07f0), // ldr x16, [sp, #8]
        18 => {
            let slot = crate::x18_slot();
            out.extend([
                rewrite::MRS_TPIDRRO | 16,
                rewrite::AND_NOT7 | (16 << 5) | 16,
                rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 16,
            ]);
        }
        _ => out.push(0xaa00_03f0 | (n << 16)), // mov x16, xN
    }
    while info.len() < out.len() {
        info.push(before);
    }
    out.extend([INDEX, SCALE, BASE, KEY, CHECK]);
    let miss_at = out.len();
    out.push(MISS); // its offset filled in below
    out.extend([INDEX, SCALE, BASE, VALUE]);
    while info.len() < out.len() {
        info.push(before);
    }
    let committed = Word::Lookup { g: pc, link, committed: true };
    // A target fwe does not translate has no translation in the table (0):
    // the branch is made as the program made it, every register its own.
    let outside_at = out.len();
    out.push(OUTSIDE);
    info.push(committed);
    if let Some(link) = link {
        let at = out.len();
        materialize(30, link, out);
        info.extend((at..out.len()).map(|_| committed));
    }
    out.push(GO);
    info.push(committed);
    // Not translated: x16 and x17 back, x30 the program's return address
    // for a call, and the program's own branch through its register (whose
    // value is the target). Through x18, which has no register to branch
    // through, or a call through x30, whose target the return address
    // would replace, fwe's trap takes it.
    let trapped = n == 18 || (n == 30 && link.is_some());
    let outside = out.len();
    if !trapped {
        out[outside_at] |= ((outside - outside_at) as u32) << 5;
        if let Some(link) = link {
            let at = out.len();
            materialize(30, link, out);
            info.extend((at..out.len()).map(|_| committed));
        }
        out.push(RESTORE);
        info.push(committed);
        // `ret xN` returns as it did; a call (its x30 set above) or a branch
        // is `br xN`.
        let ret = link.is_none() && n == 30;
        out.push(if ret { 0xd65f_0000 } else { 0xd61f_0000 } | (n << 5));
        info.push(Word::At(pc));
    }
    // The miss: x16 and x17 back, then fwe's trap.
    let miss = out.len();
    out[miss_at] |= ((miss - miss_at) as u32) << 5;
    if trapped {
        out[outside_at] |= ((miss - outside_at) as u32) << 5;
    }
    out.push(RESTORE);
    info.push(before);
    out.push(EXIT);
    info.push(Word::Out { g: pc, exit: Exit::Reg { n, link } });
}

/// Load the value `v` into `x<rd>` with `movz`/`movk`.
fn materialize(rd: u32, v: u64, out: &mut Vec<u32>) {
    out.push(rewrite::MOVZ | ((v & 0xffff) as u32) << 5 | rd);
    for hw in 1..4u32 {
        let part = ((v >> (16 * hw)) & 0xffff) as u32;
        if part != 0 {
            out.push(rewrite::MOVK | (hw << 21) | (part << 5) | rd);
        }
    }
}

/// The expansion of site `site` for the program's instruction at `pc`, as
/// [`rewrite::stub_body`] makes it, placed at `start`: it runs on into the
/// next instruction's translation.
fn expansion(site: Site, pc: u64, start: u64, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    let (tp, x18) = (crate::thread_pointer_slot(), crate::x18_slot());
    let words = rewrite::stub_body(site, tp, x18, pc);
    // Where the instruction itself is: undone before, finished after.
    let main = match site {
        Site::X18 { insn } => rewrite::x18_special_main(insn).or_else(|| {
            (crate::decode::x18_adr(insn).is_none() && !crate::decode::x18_ldr_literal(insn))
                .then(|| rewrite::x18_stub_main(insn))
        }),
        _ => None,
    };
    for (k, &sw) in words.iter().enumerate() {
        out.push(sw);
        info.push(match main {
            _ if k == 0 => Word::At(pc),
            Some(m) if k > m => Word::Finish { g: pc },
            _ => Word::Undo { g: pc, start },
        });
    }
}
