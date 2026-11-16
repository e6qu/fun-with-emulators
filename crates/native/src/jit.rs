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
//!   for it; the translation's first word restores them. Code that is not
//!   the program's run-time code (a library's, prepared in place) is
//!   entered through one stub, which leaves the target's address in
//!   `x16`: the arm64 procedure call standard lets a call or return
//!   clobber `x16` and `x17`, for veneers like this.
//!
//! What the program can observe stays its own: a fault or signal in a
//! translation is delivered at the program's instruction, with its
//! registers ([`to_guest`]); a page a translation was made from is kept
//! from being written, and a write to it drops its translations, so code
//! the program changes is translated anew.
//!
//! The code cache is made of chunks, each one memory mapped twice: fwe
//! writes translations through a writable view while threads run others
//! from an executable one. A chunk is no larger than a branch reaches, so
//! blocks in one chunk are linked to each other; a full chunk is followed
//! by a new one.

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
    CHUNK_RX[..n].iter().any(|c| pc.wrapping_sub(c.load(Ordering::Relaxed)) < CACHE_SIZE)
}

/// A code cache chunk's size: what a branch reaches, so blocks in one chunk
/// can be linked to each other. A full chunk is followed by another.
const CACHE_SIZE: u64 = 128 << 20;
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

/// Where a block's way out leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// To this program address.
    Jump(u64),
    /// To the address in register `n` (`x18`: the program's), `x30`
    /// becoming `link` first for a call.
    Reg { n: u32, link: Option<u64> },
    /// A `cbz`/`cbnz`/`tbz`/`tbnz` of `x18`: `insn` decides between its
    /// target and the next instruction, by the program's `x18`.
    TestX18 { insn: u32, taken: u64, next: u64 },
}

/// What one word of a translation stands for: how a thread stopped there
/// is as the program at one of its instructions.
#[derive(Debug, Clone, Copy)]
enum Word {
    /// The program's instruction at this address, or the start of its
    /// expansion: the program's state is as at it.
    At(u64),
    /// A block's first word, entered from a lookup: `x16` and `x17` still
    /// saved on the stack.
    Entry(u64),
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
    /// The stub into code not translated, at its `k`th word.
    Static(u8),
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
}

/// The code cache: chunks, each one memory mapped twice.
struct Cache {
    chunks: Vec<Chunk>,
    /// The stub into code not translated.
    stub: u64,
}

/// A chunk of the code cache: its writable view and its executable one.
struct Chunk {
    rw: u64,
    rx: u64,
    used: u64,
}

pub struct State {
    /// Program memory whose code runs by translation: start -> end.
    regions: BTreeMap<u64, u64>,
    /// Translations by program address.
    by_g: BTreeMap<u64, usize>,
    /// Translations by their address in the cache: start -> block index.
    by_t: BTreeMap<u64, usize>,
    blocks: Vec<Block>,
    /// The program's pages kept from being written, with the protections
    /// they had (written, they get them back and their translations go).
    guarded: BTreeMap<u64, libc::c_int>,
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
    /// Program addresses the table sends through the stub into code not
    /// translated.
    outside: std::collections::BTreeSet<u64>,
    cache: Option<Cache>,
}

static STATE: Mutex<State> = Mutex::new(State {
    regions: BTreeMap::new(),
    by_g: BTreeMap::new(),
    by_t: BTreeMap::new(),
    blocks: Vec::new(),
    guarded: BTreeMap::new(),
    lifted: BTreeMap::new(),
    retried: BTreeMap::new(),
    pages: BTreeMap::new(),
    outside: std::collections::BTreeSet::new(),
    cache: None,
});

/// For `FWE_TIMING`: blocks translated, ways out taken through fwe (a
/// branch's first time, a lookup's miss), fetches of the program's code
/// gone on at a translation, and pages whose translations a write dropped.
static TRANSLATED: AtomicU64 = AtomicU64::new(0);
static EXITS: AtomicU64 = AtomicU64::new(0);
static ENTERED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// What [`TRANSLATED`] and the others counted, if any code ran by
/// translation.
pub fn counts() -> Option<String> {
    let t = TRANSLATED.load(Ordering::Relaxed);
    (t > 0).then(|| {
        format!(
            "JIT code: {t} blocks translated, {} exits through fwe, {} entries by fetch, \
             {} pages' translations dropped by writes",
            EXITS.load(Ordering::Relaxed),
            ENTERED.load(Ordering::Relaxed),
            DROPPED.load(Ordering::Relaxed)
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
        e[0].store(0, Ordering::Release);
    }
}

impl State {
    fn in_region(&self, addr: u64) -> bool {
        self.regions.range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
    }

    /// Write `w` at `at` in the cache (its executable address).
    fn patch(&self, at: u64, w: u32) {
        let c = self.cache.as_ref().expect("a code cache");
        let k = c.chunks.iter().find(|k| (k.rx..k.rx + CACHE_SIZE).contains(&at)).expect("a chunk");
        // SAFETY: a word of the cache, through its writable view.
        unsafe { ((at - k.rx + k.rw) as *mut u32).write_volatile(w) };
        // SAFETY: the word, in the executable view.
        unsafe { crate::prepare::flush_icache(at, 4) };
    }

    /// Drop the translations made from `[addr, addr + len)`, and give the
    /// pages kept from writes there their protections back.
    fn drop_range(&mut self, addr: u64, len: u64) {
        let page = page_size();
        let mut p = addr & !(page - 1);
        while p < addr.saturating_add(len) {
            if let Some(prot) = self.guarded.remove(&p) {
                // SAFETY: a page of the program's memory fwe kept from
                // writes; it gets the protections it had back.
                unsafe { libc::mprotect(p as *mut libc::c_void, page as usize, prot) };
                *self.lifted.entry(p).or_default() += 1;
            }
            for i in self.pages.remove(&p).unwrap_or_default() {
                let (g, t) = (self.blocks[i].g, self.blocks[i].t);
                if self.by_g.get(&g) == Some(&i) {
                    self.by_g.remove(&g);
                    unpublish(g, t);
                    // Branches linked to it trap again.
                    for at in std::mem::take(&mut self.blocks[i].linked) {
                        self.patch(at, EXIT);
                    }
                }
            }
            p += page;
        }
    }
}

/// `[addr, addr + len)` holds code the program made executable after it
/// mapped it: it runs by translation from now on.
pub fn code(addr: u64, len: u64) {
    let mut s = state();
    s.drop_range(addr, len);
    remove(&mut s.regions, addr, len);
    s.regions.insert(addr, addr + len);
    // Lookups that sent its addresses to code not translated go again.
    if let Some(stub) = s.cache.as_ref().map(|c| c.stub) {
        let gone: Vec<u64> = s.outside.range(addr..addr.saturating_add(len)).copied().collect();
        for g in gone {
            s.outside.remove(&g);
            unpublish(g, stub);
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
    if let Some(stub) = s.cache.as_ref().map(|c| c.stub) {
        let entries: Vec<(u64, u64)> = s
            .by_g
            .iter()
            .map(|(&g, &i)| (g, s.blocks[i].t))
            .chain(s.outside.iter().map(|&g| (g, stub)))
            .collect();
        for (g, t) in entries {
            unpublish(g, t);
        }
    }
    s.by_g.clear();
    s.outside.clear();
    s.lifted.clear();
    s.retried.clear();
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
                    CACHE_SIZE,
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
                mach::mach_vm_protect(task, rx, CACHE_SIZE, 0, libc::PROT_READ | libc::PROT_EXEC),
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

/// A fetch from the program's memory at `pc`: the translation to run
/// instead, if `pc` holds code that runs by translation.
pub fn enter(pc: u64) -> Option<u64> {
    let mut s = state();
    if !s.in_region(pc) {
        return None;
    }
    ENTERED.fetch_add(1, Ordering::Relaxed);
    let i = translation(&mut s, pc);
    Some(body(&s, i))
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
    if s.guarded.contains_key(&page) {
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

/// The way out of a block at `regs.pc` (its trap): `regs` go on at the
/// translation of where it leads, or at the address itself where that is
/// not code run by translation; a direct branch is linked there. `false`
/// if `pc` is no way out of fwe's.
pub fn exit(regs: &mut Regs) -> bool {
    let mut s = state();
    let at = regs.pc;
    let Some(Word::Out { exit, .. }) = word_at(&s, at) else { return false };
    EXITS.fetch_add(1, Ordering::Relaxed);
    let (to, link_here) = match exit {
        Exit::Jump(to) => (to, true),
        Exit::Reg { n, link } => {
            let to = regs.x[n as usize];
            if let Some(link) = link {
                regs.x[30] = link;
            }
            (to, false)
        }
        Exit::TestX18 { insn, taken, next } => {
            (if test_taken(insn, regs.x[18]) { taken } else { next }, false)
        }
    };
    if !s.in_region(to) {
        // Code not translated: its lookups go through the stub.
        if let Some(stub) = s.cache.as_ref().map(|c| c.stub) {
            publish(to, stub);
            s.outside.insert(to);
        }
        regs.pc = to;
        return true;
    }
    let i = translation(&mut s, to);
    let into = body(&s, i);
    // Linked where the target is in reach (in the same chunk).
    if link_here && let Some(b) = rewrite::branch(at, into) {
        s.patch(at, b);
        s.blocks[i].linked.push(at);
    }
    regs.pc = into;
    true
}

/// Whether a `cbz`/`cbnz`/`tbz`/`tbnz` of a register holding `v` branches.
fn test_taken(insn: u32, v: u64) -> bool {
    let nz = (insn >> 24) & 1 == 1;
    if (insn >> 25) & 0x3f == 0b011010 {
        let v = if insn >> 31 == 1 { v } else { v & 0xffff_ffff };
        (v != 0) == nz
    } else {
        let bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f);
        ((v >> bit) & 1 == 1) == nz
    }
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
        Word::Entry(g) => Some(g),
        Word::Static(_) => None,
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
        Word::At(g) | Word::Out { g, .. } => regs.pc = g,
        Word::Entry(g) => {
            (regs.x[16], regs.x[17]) = (stack(0), stack(8));
            regs.sp += 16;
            regs.pc = g;
        }
        Word::Undo { g, start } => {
            undo(regs, start);
            regs.pc = g;
        }
        Word::Finish { g } => {
            finish(regs);
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
        Word::Static(k) => {
            // `x16` holds the target; its own value is on the stack (below
            // `sp` once the stub has moved it back).
            let to = regs.x[16];
            match k {
                0 => {
                    (regs.x[16], regs.x[17]) = (stack(0), stack(8));
                    regs.sp += 16;
                }
                1 => {
                    regs.x[16] = stack(0);
                    regs.sp += 16;
                }
                _ => regs.x[16] = stack(0u64.wrapping_sub(16)),
            }
            regs.pc = to;
        }
    }
    true
}

fn word_at(s: &State, pc: u64) -> Option<Word> {
    let c = s.cache.as_ref()?;
    if (c.stub..c.stub + 12).contains(&pc) {
        return Some(Word::Static(((pc - c.stub) / 4) as u8));
    }
    let (&t, &i) = s.by_t.range(..=pc).next_back()?;
    s.blocks[i].words.get(((pc - t) / 4) as usize).copied()
}

/// Undo an expansion's words from `start` up to `regs.pc`: each register
/// it saved and has not restored is read back, and `sp` is as before.
fn undo(regs: &mut Regs, start: u64) {
    let mut saved: Vec<(Vec<u32>, u64)> = Vec::new();
    let mut at = start;
    while at < regs.pc {
        // SAFETY: a word of fwe's code cache, readable.
        let w = unsafe { (at as *const u32).read() };
        if w & !0x1f == rewrite::PUSH {
            saved.push((vec![w & 0x1f], 16));
        } else if w & !0x7c1f == rewrite::PUSH_PAIR {
            saved.push((vec![w & 0x1f, (w >> 10) & 0x1f], 16));
        } else if w == rewrite::SYSCALL_STUB_ENTRY {
            saved.push((vec![30, 0], 32));
        } else if w & !0x1f == rewrite::POP || w & !0x7c1f == rewrite::POP_PAIR {
            saved.pop();
        }
        at += 4;
    }
    for (regs_saved, size) in saved.iter().rev() {
        for (k, &r) in regs_saved.iter().enumerate() {
            // SAFETY: the stack the expansion saved registers on.
            regs.x[r as usize] = unsafe { ((regs.sp + 8 * k as u64) as *const u64).read() };
        }
        regs.sp += size;
    }
}

/// Finish an expansion from `regs.pc`, its instruction having run: its
/// remaining words store `x18` back and restore saved registers; they are
/// carried out here, up to its way on (a branch, or the next instruction's
/// translation).
fn finish(regs: &mut Regs) {
    loop {
        // SAFETY: a word of fwe's code cache, readable.
        let w = unsafe { (regs.pc as *const u32).read() };
        if w & !0x1f == rewrite::POP {
            // SAFETY: the stack the expansion saved the register on.
            regs.x[(w & 0x1f) as usize] = unsafe { (regs.sp as *const u64).read() };
            regs.sp += 16;
        } else if w == rewrite::POP32_X30 {
            // SAFETY: as above.
            regs.x[30] = unsafe { (regs.sp as *const u64).read() };
            regs.sp += 32;
        } else if w & 0xffc0_0000 == rewrite::STR_UIMM {
            // `str xT, [xN, #imm]`: storing `x18`'s new value in its slot.
            let (t, n, imm) = (w & 0x1f, (w >> 5) & 0x1f, ((w >> 10) & 0xfff) as u64 * 8);
            // SAFETY: the thread's own TSD slot the expansion stores to.
            unsafe { ((regs.x[n as usize] + imm) as *mut u64).write(regs.x[t as usize]) };
        } else {
            // A branch on, or the next instruction's translation.
            return;
        }
        regs.pc += 4;
    }
}

/// Where a direct branch enters block `i`: past the word that restores
/// what a lookup saved.
fn body(s: &State, i: usize) -> u64 {
    s.blocks[i].t + 4
}

/// The translation of program address `g`, made if there is none.
fn translation(s: &mut State, g: u64) -> usize {
    if let Some(&i) = s.by_g.get(&g) {
        return i;
    }
    if s.cache.is_none() {
        s.cache = Some(new_cache());
    }
    // The page is kept from writes before it is read: a write after this
    // faults and drops the translation, one before it is in what is read.
    let page = g & !(page_size() - 1);
    guard(s, page);
    let at = cache_next(s);
    let (words, info) = translate(g, at);
    let t = emit(s, &words);
    let i = s.blocks.len();
    s.pages.entry(page).or_default().push(i);
    s.blocks.push(Block { g, t, words: info, linked: Vec::new() });
    s.by_g.insert(g, i);
    s.by_t.insert(t, i);
    publish(g, t);
    TRANSLATED.fetch_add(1, Ordering::Relaxed);
    i
}

/// Keep program page `p` from being written while translations of it are
/// in use: a write faults ([`written`]).
fn guard(s: &mut State, p: u64) {
    if s.guarded.contains_key(&p) {
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
    s.guarded.insert(p, prot);
}

/// The host protections of the program's memory with Linux protections
/// `prot`, code that runs by translation never executable.
fn host_prot(prot: u64) -> libc::c_int {
    let mut p = libc::PROT_NONE;
    if prot & fwe_abi::mman::PROT_READ != 0 {
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
        assert_eq!(mach::mach_vm_allocate(task, &mut rw, CACHE_SIZE, mach::VM_FLAGS_ANYWHERE), 0);
        assert_eq!(
            mach::mach_vm_remap(
                task,
                &mut rx,
                CACHE_SIZE,
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
            mach::mach_vm_protect(task, rx, CACHE_SIZE, 0, libc::PROT_READ | libc::PROT_EXEC),
            0
        );
    }
    let n = CHUNK_COUNT.load(Ordering::Relaxed) as usize;
    assert!(n < MAX_CHUNKS, "fwe's code cache is full");
    CHUNK_RX[n].store(rx, Ordering::Relaxed);
    CHUNK_COUNT.store(n as u64 + 1, Ordering::Release);
    Chunk { rw, rx, used: 0 }
}

/// The code cache, its stub into code not translated, and the table.
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
    let mut c = Cache { chunks: vec![new_chunk()], stub: 0 };
    // `ldr x17, [sp, #8]; add sp, sp, #16; br x16`
    c.stub = write(&mut c, &[0xf940_07f1, 0x9100_43ff, 0xd61f_0200]);
    c
}

/// Where the next block goes: in the last chunk, or a new one where that
/// lacks room for the largest block.
fn cache_next(s: &mut State) -> u64 {
    let c = s.cache.as_mut().expect("a code cache");
    if c.chunks.last().is_none_or(|k| k.used + BLOCK_ROOM > CACHE_SIZE) {
        c.chunks.push(new_chunk());
    }
    let k = c.chunks.last().expect("a chunk");
    k.rx + k.used
}

/// Write `words` at the last chunk's next free place (8-byte aligned, as
/// a system call's stub needs for its literal): their executable address.
fn write(c: &mut Cache, words: &[u32]) -> u64 {
    let k = c.chunks.last_mut().expect("a chunk");
    let len = 4 * words.len() as u64;
    assert!(k.used + len <= CACHE_SIZE, "a block larger than the room kept for one");
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
fn translate(g: u64, t: u64) -> (Vec<u32>, Vec<Word>) {
    let mut out: Vec<u32> = vec![RESTORE];
    let mut info: Vec<Word> = vec![Word::Entry(g)];
    let page = page_size();
    let mut pc = g;
    for _ in 0..BLOCK_INSNS {
        let w = read(pc);
        let ended = one(w, pc, t, &mut out, &mut info);
        pc += 4;
        // Ends at a branch out, or at the page's end (the next page may not
        // be the program's code).
        if ended {
            return (out, info);
        }
        if pc & (page - 1) == 0 {
            break;
        }
    }
    out.push(EXIT);
    info.push(Word::Out { g: pc, exit: Exit::Jump(pc) });
    (out, info)
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
        if w & 0x1f == 18 {
            out.push(EXIT);
            info.push(Word::Out { g: pc, exit: Exit::TestX18 { insn: w, taken, next: pc + 4 } });
            return true;
        }
        let field = if family == 0b011010 { 0x7_ffff << 5 } else { 0x3fff << 5 };
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
    if let Some(link) = link {
        let at = out.len();
        materialize(30, link, out);
        info.extend((at..out.len()).map(|_| committed));
    }
    out.push(GO);
    info.push(committed);
    // The miss: x16 and x17 back, then fwe's trap.
    let miss = out.len();
    out[miss_at] |= ((miss - miss_at) as u32) << 5;
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
        Site::X18 { insn }
            if crate::decode::x18_adr(insn).is_none()
                && !crate::decode::x18_ldr_literal(insn)
                && !crate::decode::x18_casp(insn)
                && !crate::decode::x18_sp_writeback(insn)
                && !crate::decode::x18_writes_sp(insn) =>
        {
            Some(rewrite::x18_stub_main(insn))
        }
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
