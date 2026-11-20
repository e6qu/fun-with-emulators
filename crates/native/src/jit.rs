//! Code a program makes executable at run time, run by translation
//! (described for readers in `docs/jit.md`).
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
//!   linked, a branch straight to the target's translation; a block goes
//!   on past a conditional branch, whose taken way is linked in the branch
//!   itself where it reaches, or goes to the block's own words for its
//!   target where it holds them. A call leaves the program's own return
//!   address in `x30`, so the stack holds only the program's addresses,
//!   as its unwinders and stack walkers expect. An indirect branch or
//!   return looks its target up in a table of translations by program
//!   address ([`TABLE`]), saving `x16` and `x17` for it: one 16-byte load
//!   reads an entry's address and translation together (single-copy
//!   atomic, as the table's writes are), so a match is the target's
//!   translation. Through `x16` or `x17`, which hold the target as it is
//!   looked up, the address and translation are read apart, and the
//!   translation's check (that the target is its own: an entry can be
//!   taken over as a lookup reads it) comes first. A target that is not
//!   the program's run-time code (a library's, prepared in place) has 0
//!   for its translation: the lookup restores `x16` and `x17` and makes
//!   the program's own branch through its register, so no register
//!   changes (code may count on that beyond the procedure call standard:
//!   HotSpot calls its atomic stubs saying they clobber only `x8`, `x9`
//!   and `x30`). Through `x18`, which has no register to branch through,
//!   fwe's trap makes it.
//!
//! A translation entered with `x16` and `x17` saved keeps them in two
//! slots of the thread's (reached through `tpidrro_el0`, as `x18`'s is)
//! until an instruction names them or needs fwe's stack ([`keeps_saved`]),
//! and a way out or lookup saves them again only if they were restored:
//! code that never names them (an interpreter's dispatch, a recursion
//! moving `sp` at each call) runs its lookups and calls with no save or
//! restore between them. A block is entered with the program's own
//! registers past its restore, or at a copy of its words up to there
//! ([`translate`]).

//! What the program can observe stays its own: a fault or signal in a
//! translation is delivered at the program's instruction, with its
//! registers ([`to_guest`]).
//!
//! Code the program changes is translated anew. The program says where:
//! arm64 has the instruction cache kept apart from data writes (the
//! `CTR_EL0` fwe gives says so, as Apple's processors' does under Linux),
//! so a program that writes code invalidates each cache line it wrote
//! (`ic ivau`) before it runs it, as `__clear_cache` does. fwe takes that
//! instruction ([`crate::rewrite`]'s stub, or a translation's) for the
//! word that the line changed, and drops the blocks made from it, through
//! any mapping of the same memory ([`flushed`]). The rest of the page is
//! the program's to write as it likes: a JIT keeps its data beside its
//! code. Memory mapped, unmapped, given other protections or discarded
//! drops its translations too, as does a write fwe makes into code (a
//! debugger's breakpoint); a write that `read` makes into memory is the
//! program's, as on Linux, which syncs no instruction cache for it.
//!
//! A block is translated with the translator's lock let go, from one
//! look at the program's words, and placed with it taken again if they
//! are still as it saw them ([`translation`]): threads that make blocks
//! at once wait on each other only to place them.
//!
//! The code cache is made of chunks, each one memory mapped twice: fwe
//! writes translations through a writable view while threads run others
//! from an executable one. A chunk is no larger than a branch reaches, so
//! blocks in one chunk are linked to each other. A block's words are made
//! in two parts ([`crate::asm`]), its hot words and its cold ones, laid
//! apart in a segment of its chunk ([`Chunk`]). A full chunk is followed
//! by a new one, or, where at least half of the cache is translations
//! dropped since, the cache is emptied ([`flush`]): every other thread is
//! stopped, the blocks a thread may be in or return into are retired, and
//! the rest of the room is reused.

mod kept;

use crate::asm::{Asm, Field, Label, Pos, STUB, Sec};
use crate::jitcount;
use crate::rewrite::{self, Site};
use fwe_kernel::Regs;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// `brk #0x4a54` ("JT"): the wrong block entered, into fwe by its trap.
pub const EXIT_IMM: u32 = 0x4a54;
pub const EXIT: u32 = 0xd420_0000 | (EXIT_IMM << 5);
/// `udf #0`: an instruction no translation can stand for (an
/// authenticated branch fwe does not offer); it faults as `SIGILL` at the
/// program's instruction.
const UDF: u32 = 0;
/// `adr x16, #0`: a way out's first word, the program's `x16` and `x17`
/// saved, until it is linked.
const OUT: u32 = 0x1000_0010;
/// The bytes at the start of each chunk that its ways out branch to on
/// into the exit gate ([`exit_stub`]).
const EXIT_STUB: u64 = 16;

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

/// Whether `pc` may be where [`to_guest`] finds the program's state: in
/// fwe's code cache, or in a stub region once a call stub was made
/// ([`link_call_site`]). Not for fwe's own code (it may take locks).
pub fn stands_for_program(pc: u64) -> bool {
    in_cache(pc)
        || (CALL_SITES_LINKED.load(Ordering::Relaxed) > 0
            && crate::prepare::stub_region(pc).is_some())
}

/// Whether `pc` is in a chunk's exit stub ([`exit_stub`]).
fn in_exit_stub(pc: u64) -> bool {
    let n = CHUNK_COUNT.load(Ordering::Acquire) as usize;
    CHUNK_RX[..n].iter().any(|c| pc.wrapping_sub(c.load(Ordering::Relaxed)) < EXIT_STUB)
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
    fwe_kernel::procmem::on_code_written(code_written);
    reserve_table();
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

/// Whether this process holds the translation table.
static TABLE_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Take the translation table's place, as fwe starts, before the program
/// maps anything: a mapping the program asks for there with a hint goes
/// elsewhere. (Its pages are the host's only as they are first written.)
fn reserve_table() {
    if TABLE_HELD.swap(true, Ordering::SeqCst) {
        return;
    }
    for at in [TABLE, RETS] {
        let mut table = at;
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
                "fwe's translation table's place ({at:#x}) is taken"
            );
        }
    }
}

/// The table of translations by program address: at an address an `orr`
/// can encode (one bit), 2^20 entries of (program address, translation).
/// An address's entry is the one its bits pick, or the other of the pair
/// of entries that one is in ([`OTHER`]): two addresses whose entry is the
/// same, both run often, would each push the other out at every turn, a
/// way into fwe each time.
pub const TABLE: u64 = 1 << 45;
/// The table of returns, laid out as [`TABLE`]: a call's return address,
/// and the way back into the translation of the call (the words after
/// its `bl`, where the block goes on), where a return goes with `ret`. The
/// processor predicts a return to where the last `bl` would have come
/// back to: found here, it is right, where a `br` to the address the
/// table of translations gives would be guessed from the branches before
/// it (a return to one of many callers, as a tree walk's, missed most
/// times).
pub const RETS: u64 = TABLE | 1 << 44;
const TABLE_BITS: u32 = 20;
const TABLE_SIZE: u64 = 16 << TABLE_BITS;

// Encodings of the lookup sequence and the stubs.
/// `stp x16, x17, [sp, #-16]`: a save's first word ([`save_words`]).
const SAVE: u32 = 0xa93f_47f0;
/// Words of a save of the program's `x16` and `x17`, and of their restore.
const SAVE_WORDS: usize = 6;
const RESTORE_WORDS: usize = 4;

/// A save of the program's `x16` and `x17` into their slots of the
/// thread's area ([`crate::parked_slots`]), with no register free: both
/// below `sp` first (`sp` unmoved; a thread stopped inside has them there,
/// [`Word::Stashed`]), then the area's address into `x17` and each into
/// its slot, `x17`'s through `x16`.
fn save_words() -> [u32; SAVE_WORDS] {
    let (s16, s17) = crate::parked_slots();
    [
        SAVE,
        rewrite::MRS_TPIDRRO | 17,
        rewrite::AND_NOT7 | (17 << 5) | 17,
        rewrite::STR_UIMM | ((s16 / 8) << 10) | (17 << 5) | 16,
        0xf85f_83f0, // ldur x16, [sp, #-8]
        rewrite::STR_UIMM | ((s17 / 8) << 10) | (17 << 5) | 16,
    ]
}

/// The program's `x16` and `x17` taken back from their slots, the area's
/// address in `x16` until the last word.
fn restore_words() -> [u32; RESTORE_WORDS] {
    let (s16, s17) = crate::parked_slots();
    [
        rewrite::MRS_TPIDRRO | 16,
        rewrite::AND_NOT7 | (16 << 5) | 16,
        rewrite::LDR_UIMM | ((s17 / 8) << 10) | (16 << 5) | 17,
        rewrite::LDR_UIMM | ((s16 / 8) << 10) | (16 << 5) | 16,
    ]
}

/// The program's `x16` and `x17` as their slots hold them, on this thread.
fn parked() -> (u64, u64) {
    let (s16, s17) = crate::parked_slots();
    let area: u64;
    // SAFETY: reading this thread's TSD base, which the host keeps in
    // `tpidrro_el0` (its low bits the processor's number).
    unsafe { std::arch::asm!("mrs {}, tpidrro_el0", out(reg) area, options(nomem, nostack)) };
    let area = area & !7;
    // SAFETY: this thread's own TSD slots.
    unsafe {
        (
            ((area + u64::from(s16)) as *const u64).read(),
            ((area + u64::from(s17)) as *const u64).read(),
        )
    }
}

/// [`save_words`] into `a`'s section `s`, its first word as `first` (the
/// program's state as at `g`, or a way out), the rest [`Word::Stashed`].
fn push_save(a: &mut Asm<Word>, s: Sec, first: Word, g: u64) -> Pos {
    let w = save_words();
    let at = a.push(s, w[0], first);
    a.extend(s, w[1..].iter().copied(), Word::Stashed(g));
    at
}

/// [`restore_words`] into `a`'s section `s`, each as `w`.
fn push_restore(a: &mut Asm<Word>, s: Sec, w: Word) {
    a.extend(s, restore_words(), w);
}
/// `ubfx x17, x16, #2, #20`: the table index.
const INDEX: u32 = 0xd342_5611;
/// `lsl x17, x17, #4`: by the entry's size.
const SCALE: u32 = 0xd37c_ee31;
/// `orr x17, x17, #TABLE`
const BASE: u32 = 0xb253_0231;
/// `orr x17, x17, #RETS`
const RETS_BASE: u32 = 0xb254_0631;
/// `ret x17`
const RET_X17: u32 = 0xd65f_0220;
/// `bl` (its offset added)
const BL: u32 = 0x9400_0000;
/// `b` (its offset added)
const B: u32 = 0x1400_0000;
/// The sections of a block's words ([`Asm`]): what runs each time it runs,
/// and what runs only out of the common case.
const H: Sec = Sec::Hot;
const C: Sec = Sec::Cold;
/// `eor x17, x17, #16`: an entry's address to the other's of its pair.
const OTHER: u32 = 0xd27c_0231;
/// `ldar x17, [x17]`: the entry's key, before its value.
const KEY: u32 = 0xc8df_fe31;
/// `ldp x16, x17, [x17]`: the entry's key and value at once.
const ENTRY: u32 = 0xa940_4630;
/// `cbnz x16, #off`
const MISS_X16: u32 = 0xb500_0010;
/// `sub x17, x17, #CHECK_WORDS * 4`: from a translation's saved entry
/// back to its check.
const TO_CHECK: u32 = 0xd100_0231 | ((4 * CHECK_WORDS as u32) << 10);
/// Words of a translation's check that the target in `x16` is its own
/// (its address in `x17`, padded to 4 words, `eor`, `cbnz`), before its
/// saved entry.
const CHECK_WORDS: usize = 6;
/// `nop`
const NOP: u32 = 0xd503_201f;
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

/// `ubfx x17, x<n>, #2, #20`: the table index of the address in `x<n>`.
const fn index_of(n: u32) -> u32 {
    0xd342_5411 | (n << 5)
}

/// `eor x16, x16, x<n>`: an entry's key against the target in `x<n>`.
const fn key_against(n: u32) -> u32 {
    0xca00_0210 | (n << 16)
}

/// Where a block's way out leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// To this program address.
    Jump(u64),
    /// To the address in register `n` (`x18`: the program's), `x30`
    /// becoming `link` first for a call.
    Reg { n: u32, link: Option<u64> },
    /// A lookup that came to the wrong block (its entry was taken over as
    /// it read it): on to the address in `x16`, the program's `x16` and
    /// `x17` on the stack.
    Retry,
    /// Into the call at this program address, made in another block's
    /// words ([`State::calls_made`]): linked there as the block is placed;
    /// through fwe once those words are dropped, then linked to the
    /// call's own translation.
    Join(u64),
}

/// What an expansion ([`Word::Undo`], [`Word::Finish`]) stands for: its
/// letter in [`write_map`]'s maps.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum Of {
    /// An instruction naming `x18`.
    X18 = b'8',
    /// A read or write of the thread pointer.
    ThreadPointer = b't',
    /// A literal load into a vector register.
    Load = b'e',
    /// A cache flush.
    Flush = b'i',
    /// A system call.
    Syscall = b'c',
}

/// What one word of a translation stands for: how a thread stopped there
/// is as the program at one of its instructions.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Word {
    /// The program's instruction at this address, or the start of its
    /// expansion: the program's state is as at it.
    At(u64),
    /// Inside an expansion of the program's instruction at `g` that
    /// started at `start`, before the instruction ran: undone (the
    /// registers it saved restored, `sp` as it was), it is as at `g`.
    Undo { g: u64, start: u64, of: Of },
    /// Inside an expansion after the instruction ran: finished (its
    /// remaining words run here), it is as at the next instruction.
    /// (`of` in both: what the expansion stands for, for [`write_map`].)
    Finish { g: u64, of: Of },
    /// Inside the lookup of the branch at `g`, `x16` and `x17` saved:
    /// before it is committed (`to` none), as at `g`; once committed
    /// (`x30` being set for a call, or the branch taken), as at its
    /// target, which `x<to>` holds.
    Lookup { g: u64, link: Option<u64>, to: Option<u8> },
    /// The program's instruction at `g` (or the start of its stand-in), its
    /// `x16` and `x17` saved in their slots ([`crate::parked_slots`]).
    Saved(u64),
    /// Inside a save of the program's `x16` and `x17` ([`save_words`]) as
    /// at `g`: both below `sp`, at `[sp, #-16]` and `[sp, #-8]`.
    Stashed(u64),
    /// As [`Word::Saved`], the program's `x18` held in `x17` (its slot not
    /// written yet).
    SavedX18(u64),
    /// A way out, as at the branch at `g`; `saved`, with the program's
    /// `x16` and `x17` in their slots (and for [`Exit::Retry`], as at the
    /// target in `x16`), and `x18`, with its `x18` (back in its slot) in
    /// `x17` too, the thread's area in `x16`; the taken way of the
    /// conditional branch `cond` words before it (0: none).
    Out { g: u64, exit: Exit, saved: bool, x18: bool, cond: u16 },
}

/// A [`Word`] as a placed block keeps it, in 16 bytes rather than 40: its
/// program address as instructions past the block's (`g`), an expansion's
/// start as words past the block's translation, a call's return address
/// as the one after `g` ([`Block::word`] makes the word again).
#[derive(Clone, Copy)]
enum Packed {
    At(u16),
    Saved(u16),
    SavedX18(u16),
    Stashed(u16),
    Undo {
        g: u16,
        start: u32,
        of: Of,
    },
    Finish {
        g: u16,
        of: Of,
    },
    Lookup {
        g: u16,
        call: bool,
        to: Option<u8>,
    },
    /// `exit`: 0 [`Exit::Jump`] to `to`, 1 [`Exit::Retry`], 2 [`Exit::Join`]
    /// (into the call at `g`), 3 + 2n (+ 1 for a call) [`Exit::Reg`].
    Out {
        to: u64,
        g: u16,
        cond: u16,
        exit: u8,
        saved: bool,
        x18: bool,
    },
}

const _: () = assert!(std::mem::size_of::<Packed>() == 16);

impl Packed {
    /// Word `w` of a block at program address `g0` translated at `t` (an
    /// expansion's start as made, at 0, or placed: `t` subtracted).
    fn of(w: Word, g0: u64, t: u64) -> Packed {
        let off = |g: u64| -> u16 {
            let k = g.wrapping_sub(g0) / 4;
            u16::try_from(k).unwrap_or_else(|_| panic!("word of {g:#x} in a block at {g0:#x}"))
        };
        let next = |g: u64, link: Option<u64>| -> bool {
            assert!(link.is_none_or(|l| l == g + 4), "a call at {g:#x} returning to {link:x?}");
            link.is_some()
        };
        match w {
            Word::At(g) => Packed::At(off(g)),
            Word::Saved(g) => Packed::Saved(off(g)),
            Word::SavedX18(g) => Packed::SavedX18(off(g)),
            Word::Stashed(g) => Packed::Stashed(off(g)),
            Word::Undo { g, start, of } => Packed::Undo {
                g: off(g),
                start: u32::try_from((start - t) / 4).expect("an expansion in its block"),
                of,
            },
            Word::Finish { g, of } => Packed::Finish { g: off(g), of },
            Word::Lookup { g, link, to } => Packed::Lookup { g: off(g), call: next(g, link), to },
            Word::Out { g, exit, saved, x18, cond } => {
                let (exit, to) = match exit {
                    Exit::Jump(to) => (0, to),
                    Exit::Retry => (1, 0),
                    Exit::Join(at) => {
                        assert_eq!(at, g, "a join at {g:#x} into {at:#x}");
                        (2, 0)
                    }
                    Exit::Reg { n, link } => (3 + 2 * n as u8 + u8::from(next(g, link)), 0),
                };
                Packed::Out { to, g: off(g), cond, exit, saved, x18 }
            }
        }
    }

    /// Its 16 bytes as a kept record holds them ([`kept`]): a tag, then
    /// its fields in turn, little-endian.
    fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        let mut put = |at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
        match self {
            Packed::At(k) => put(0, &[0, k as u8, (k >> 8) as u8]),
            Packed::Saved(k) => put(0, &[1, k as u8, (k >> 8) as u8]),
            Packed::SavedX18(k) => put(0, &[2, k as u8, (k >> 8) as u8]),
            Packed::Stashed(k) => put(0, &[7, k as u8, (k >> 8) as u8]),
            Packed::Undo { g, start, of } => {
                put(0, &[3]);
                put(1, &g.to_le_bytes());
                put(3, &start.to_le_bytes());
                put(7, &[of as u8]);
            }
            Packed::Finish { g, of } => {
                put(0, &[4]);
                put(1, &g.to_le_bytes());
                put(3, &[of as u8]);
            }
            Packed::Lookup { g, call, to } => {
                put(0, &[5]);
                put(1, &g.to_le_bytes());
                put(3, &[u8::from(call), to.unwrap_or(0xff)]);
            }
            Packed::Out { to, g, cond, exit, saved, x18 } => {
                put(0, &[6]);
                put(1, &to.to_le_bytes());
                put(9, &g.to_le_bytes());
                put(11, &cond.to_le_bytes());
                put(13, &[exit, u8::from(saved), u8::from(x18)]);
            }
        }
        b
    }

    /// [`Packed::to_bytes`]'s word again, if `b` is one.
    fn from_bytes(b: &[u8]) -> Option<Packed> {
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let of = |v: u8| {
            [Of::X18, Of::ThreadPointer, Of::Load, Of::Flush, Of::Syscall]
                .into_iter()
                .find(|&o| o as u8 == v)
        };
        if b.len() != 16 {
            return None;
        }
        Some(match b[0] {
            0 => Packed::At(u16_at(1)),
            1 => Packed::Saved(u16_at(1)),
            2 => Packed::SavedX18(u16_at(1)),
            7 => Packed::Stashed(u16_at(1)),
            3 => Packed::Undo {
                g: u16_at(1),
                start: u32::from_le_bytes(b[3..7].try_into().ok()?),
                of: of(b[7])?,
            },
            4 => Packed::Finish { g: u16_at(1), of: of(b[3])? },
            5 => {
                Packed::Lookup { g: u16_at(1), call: b[3] == 1, to: (b[4] != 0xff).then_some(b[4]) }
            }
            6 => Packed::Out {
                to: u64::from_le_bytes(b[1..9].try_into().ok()?),
                g: u16_at(9),
                cond: u16_at(11),
                exit: b[13],
                saved: b[14] == 1,
                x18: b[15] == 1,
            },
            _ => return None,
        })
    }

    /// The word again, in a block at program address `g0` placed at `t`.
    fn word(self, g0: u64, t: u64) -> Word {
        let at = |k: u16| g0 + 4 * u64::from(k);
        match self {
            Packed::At(k) => Word::At(at(k)),
            Packed::Saved(k) => Word::Saved(at(k)),
            Packed::SavedX18(k) => Word::SavedX18(at(k)),
            Packed::Stashed(k) => Word::Stashed(at(k)),
            Packed::Undo { g, start, of } => {
                Word::Undo { g: at(g), start: t + 4 * u64::from(start), of }
            }
            Packed::Finish { g, of } => Word::Finish { g: at(g), of },
            Packed::Lookup { g, call, to } => {
                Word::Lookup { g: at(g), link: call.then(|| at(g) + 4), to }
            }
            Packed::Out { to, g, cond, exit, saved, x18 } => {
                let g = at(g);
                let exit = match exit {
                    0 => Exit::Jump(to),
                    1 => Exit::Retry,
                    2 => Exit::Join(g),
                    e => Exit::Reg {
                        n: u32::from((e - 3) / 2),
                        link: ((e - 3) % 2 == 1).then_some(g + 4),
                    },
                };
                Word::Out { g, exit, saved, x18, cond }
            }
        }
    }
}

/// A translated block.
struct Block {
    /// The program address it translates.
    g: u64,
    /// Its translation's address in the executable view: its first words
    /// check that a lookup read apart from the table reached the block it
    /// looked for ([`CHECK_WORDS`], [`TO_CHECK`]); the entries follow.
    t: u64,
    /// What each word of the translation stands for: its hot words', then
    /// its cold ones' ([`crate::asm`]).
    words: Vec<Packed>,
    /// The branches linked straight to it, to undo if it goes.
    linked: Vec<u64>,
    /// Its hot words' size in bytes, from `t`.
    len: u64,
    /// Its cold words' address and size in bytes (0 if none): what runs
    /// only out of the common case, apart from the hot words of the blocks
    /// laid together ([`Chunk`]).
    cold: u64,
    cold_len: u64,
    /// Where a lookup or a direct branch enters it with the program's
    /// `x16` and `x17` saved: past its check (its saved entry).
    body: u64,
    /// Where it is entered with the program's own registers: past its
    /// first word where that takes them back, else its start, which saves
    /// them.
    unsaved: u64,
    /// Where it is entered with them saved and its `x18` in `x17` (the
    /// thread's area in `x16`), past the words that load them, if it starts
    /// with them; else 0.
    x18: u64,
    /// Kept when the cache was emptied, as a thread may still be in it or
    /// return into it: found by no lookup, and its ways out not linked.
    retired: bool,
    /// The program's words it was made from, from `g` on, and whether it
    /// was followed into (code not run by translation): dropped by a flush
    /// of them, it is taken back while they are the same ([`revive`]).
    source: Vec<u32>,
    followed: bool,
    /// Its calls' pads ([`RETS`]): where each returns, and the address
    /// of the words that go on there.
    pads: Vec<(u64, u64)>,
    /// The calls it makes for every block ([`State::calls_made`]): each
    /// one's program address and the address of its words.
    calls_made: Vec<(u64, u64)>,
    /// What the translator's counts know of it ([`jitcount`]).
    notes: Notes,
}

/// What [`jitcount`] counts of a block: whether it was made ahead of the
/// program ([`ahead`]), whether its entry with the program's own `x16`
/// and `x17` is a second pass of its words and whether that entry was
/// used, and its counters, if blocks count their runs.
#[derive(Default)]
struct Notes {
    ahead: bool,
    second: bool,
    used: std::cell::Cell<bool>,
    counters: Option<u64>,
}

impl Block {
    /// Its entry with the program's own `x16` and `x17`, noted as used.
    fn unsaved_entry(&self) -> u64 {
        if self.notes.second && !self.notes.used.replace(true) {
            jitcount::SECOND_USED.fetch_add(1, Ordering::Relaxed);
        }
        self.unsaved
    }

    /// What its word `k` stands for.
    fn word(&self, k: usize) -> Option<Word> {
        self.words.get(k).map(|p| p.word(self.g, self.t))
    }

    /// The index of its word at cache address `at`, if it holds one there.
    fn index(&self, at: u64) -> Option<usize> {
        if at.wrapping_sub(self.t) < self.len {
            Some(((at - self.t) / 4) as usize)
        } else if at.wrapping_sub(self.cold) < self.cold_len {
            Some(((self.len + at - self.cold) / 4) as usize)
        } else {
            None
        }
    }

    /// The cache address of its word `k`.
    fn addr(&self, k: usize) -> u64 {
        let off = 4 * k as u64;
        if off < self.len { self.t + off } else { self.cold + off - self.len }
    }

    /// Its size in the cache, hot and cold, in bytes.
    fn size(&self) -> u64 {
        self.len + self.cold_len
    }

    /// What its word at cache address `at` stands for.
    fn word_at(&self, at: u64) -> Option<Word> {
        self.word(self.index(at)?)
    }

    /// What each of its words stands for.
    fn all_words(&self) -> impl Iterator<Item = Word> + '_ {
        self.words.iter().map(|p| p.word(self.g, self.t))
    }

    /// Its direct ways out ([`Exit::Jump`]): where each is, its target,
    /// and whether it is a conditional branch's taken way.
    fn jumps(&self) -> impl Iterator<Item = (u64, u64, bool)> + '_ {
        self.words.iter().enumerate().filter_map(|(k, p)| match *p {
            Packed::Out { to, exit: 0, cond, .. } => Some((self.addr(k), to, cond != 0)),
            _ => None,
        })
    }

    /// Its direct ways out ([`Block::jumps`]) by what leads there: their
    /// targets, and whether an unconditional branch of the program's
    /// (`b`) does, and whether ahead within the words a block made at its
    /// own address could read ([`snapshot`]), from the target's page.
    fn leads(&self) -> impl Iterator<Item = (u64, jitcount::Lead)> + '_ {
        self.words.iter().filter_map(|p| match *p {
            Packed::Out { to, g, cond: 0, exit: 0, .. } => {
                let at = self.g + 4 * u64::from(g);
                let branch = self.source.get(usize::from(g)).is_some_and(|&w| {
                    w & 0xfc00_0000 == 0x1400_0000
                        && at.wrapping_add_signed(i64::from((w << 6) as i32 >> 4)) == to
                });
                let page = !(page_size() - 1);
                let ahead = to > at && to < self.g + 4 * (BLOCK_INSNS + 16) as u64;
                Some((
                    to,
                    match (branch, at & page == to & page) {
                        (true, true) if ahead => jitcount::Lead::Ahead,
                        (true, true) => jitcount::Lead::Branch,
                        (true, false) => jitcount::Lead::BranchAway,
                        _ => jitcount::Lead::Other,
                    },
                ))
            }
            Packed::Out { to, exit: 0, .. } => Some((to, jitcount::Lead::Other)),
            _ => None,
        })
    }

    /// Whether the program's words it was made from are still there.
    fn unchanged(&self) -> bool {
        self.source.iter().zip((self.g..).step_by(4)).all(|(&w, at)| read(at) == w)
    }
}

/// The code cache: chunks, each one memory mapped twice.
struct Cache {
    chunks: Vec<Chunk>,
    /// The chunk new translations go in.
    current: usize,
    /// Bytes of translations in use, and of those dropped (flushed,
    /// unmapped) or retired, whose room is had back by emptying the cache.
    live: u64,
    garbage: u64,
    /// Times the cache was emptied.
    flushes: u64,
}

/// A map by program address, looked up and never walked in order: a way
/// out takes the translator's lock to look up and add to these, and a
/// tree's insert and walk cost several times a hash's.
type AddrMap<V> = HashMap<u64, V, BuildHasherDefault<AddrHash>>;

/// A program address's hash: its bits mixed by a multiply, the high half
/// folded into the low, which pick the bucket.
#[derive(Default)]
struct AddrHash(u64);

impl Hasher for AddrHash {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(self.0 ^ u64::from(b));
        }
    }

    fn write_u64(&mut self, v: u64) {
        let h = (self.0 ^ v).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = h ^ (h >> 32);
    }
}

/// A chunk of the code cache: its writable view and its executable one,
/// filled a segment at a time ([`segment`]), the blocks' hot words from
/// the segment's start up and their cold ones from its end down: the hot
/// words of blocks made one after another lie together, each block's cold
/// words in reach of its conditional branches.
struct Chunk {
    rw: u64,
    rx: u64,
    /// The current segment's next free byte for hot words, its lowest cold
    /// one, and its end (offsets in the chunk).
    hot: u64,
    cold: u64,
    end: u64,
    /// Holds retired translations: nothing new goes in it.
    retired: bool,
}

impl Chunk {
    /// Where a block of `hot` and `cold` bytes goes in it: its parts'
    /// offsets and the end of the segment they are in; in the current
    /// segment if they fit, else in the next. Each part 8-byte aligned, as
    /// a system call's stub needs for its literal.
    fn fit(&self, hot: u64, cold: u64) -> Option<(u64, u64, u64)> {
        let place = |start: u64, top: u64, end: u64| {
            let c = (top - cold) & !7;
            (start + hot <= c).then_some((start, c, end))
        };
        place(self.hot, self.cold, self.end).or_else(|| {
            (self.end < chunk_size()).then(|| {
                let end = (self.end + segment()).min(chunk_size());
                place(self.end, end, end)
            })?
        })
    }

    /// Emptied: its first segment, past the exit stub, from the start.
    fn empty(&mut self) {
        self.hot = EXIT_STUB;
        self.end = segment();
        self.cold = self.end;
    }
}

/// The most a segment of a chunk holds ([`Chunk`]): what a conditional
/// branch reaches, from a block's hot words to its cold ones.
const MAX_SEGMENT: u64 = 1 << 20;

/// A segment's size: a quarter of a chunk, at most [`MAX_SEGMENT`].
fn segment() -> u64 {
    (chunk_size() / 4).min(MAX_SEGMENT)
}

pub struct State {
    /// Program memory whose code runs by translation: start -> end.
    regions: BTreeMap<u64, u64>,
    /// Translations by program address.
    by_g: AddrMap<usize>,
    /// Translations by their address in the cache: the start of each part
    /// (hot words, cold words) -> block index.
    by_t: BTreeMap<u64, usize>,
    blocks: Vec<Block>,
    /// Program pages -> the blocks made from them.
    pages: BTreeMap<u64, Vec<usize>>,
    /// Program addresses the table says are code not
    /// translated.
    outside: std::collections::BTreeSet<u64>,
    /// Pages translated from that map a file shared (a memfd a JIT maps
    /// twice, writable and executable): the file's page (device, inode,
    /// offset) -> those pages.
    objects: BTreeMap<(u64, u64, u64), std::collections::BTreeSet<u64>>,
    /// [`State::objects`] the other way: page -> its file page.
    object_of: BTreeMap<u64, (u64, u64, u64)>,
    /// Pages of other mappings of those files' pages -> the pages
    /// translated from that they also map: a flush through one drops
    /// their translations ([`flushed`]).
    aliases: BTreeMap<u64, std::collections::BTreeSet<u64>>,
    /// Code not translated, and whether from a way out with the
    /// program's `x16` and `x17` saved -> the block that branches to it
    /// from the cache ([`veneer`]).
    veneers: BTreeMap<(u64, bool), usize>,
    /// Each call (`bl`, `blr`) made in a block's words: its program
    /// address, the block, and the address of its words (entered with the
    /// program's `x16` and `x17` saved). Another block that comes to it
    /// goes on there ([`Exit::Join`]): a call has one `bl`, and its return
    /// one way back ([`RETS`]) the processor predicts.
    calls_made: BTreeMap<u64, (usize, u64)>,
    /// Where calls made from translations return: a return there from
    /// code followed into is followed back ([`exit`]).
    returns: std::collections::BTreeSet<u64>,
    /// Sites of code not translated that called or branched into
    /// translated code, and whether they were linked to it
    /// ([`link_call_site`]).
    call_sites: BTreeMap<u64, bool>,
    /// The stubs those sites call: each one's address -> its site and its
    /// words ([`call_stub_to_guest`]).
    call_stubs: BTreeMap<u64, (u64, Vec<u32>)>,
    /// Program addresses not translated yet -> the direct ways out of
    /// translations that lead there (and their blocks), linked as the
    /// target is translated ([`link_waiting`]) rather than each through
    /// fwe's trap.
    waiting: AddrMap<Waiting>,
    /// Program addresses -> the block made there that a flush of its
    /// words dropped, taken back when the address is to be translated
    /// again if its words were not changed ([`revive`]).
    dormant: BTreeMap<u64, usize>,
    cache: Option<Cache>,
    /// Words of the cache [`State::patch`] changed whose instruction cache
    /// lines are not invalidated yet ([`State::sync_patched`]).
    patched: std::cell::RefCell<Vec<u64>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    regions: BTreeMap::new(),
    by_g: AddrMap::with_hasher(BuildHasherDefault::new()),
    by_t: BTreeMap::new(),
    blocks: Vec::new(),
    pages: BTreeMap::new(),
    outside: std::collections::BTreeSet::new(),
    objects: BTreeMap::new(),
    object_of: BTreeMap::new(),
    aliases: BTreeMap::new(),
    veneers: BTreeMap::new(),
    calls_made: BTreeMap::new(),
    returns: std::collections::BTreeSet::new(),
    call_sites: BTreeMap::new(),
    call_stubs: BTreeMap::new(),
    waiting: AddrMap::with_hasher(BuildHasherDefault::new()),
    dormant: BTreeMap::new(),
    cache: None,
    patched: std::cell::RefCell::new(Vec::new()),
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
/// Of [`EXITS`]: to a block made already, by a direct branch (and of
/// those, ones left unlinked) and by an indirect one (and of those, ones
/// whose table entry another address held).
static EXITS_KNOWN_DIRECT: AtomicU64 = AtomicU64::new(0);
static EXITS_KNOWN_UNLINKED: AtomicU64 = AtomicU64::new(0);
static EXITS_KNOWN_INDIRECT: AtomicU64 = AtomicU64::new(0);
static EXITS_KNOWN_TAKEN: AtomicU64 = AtomicU64::new(0);
static ENTERED_RETURNS: AtomicU64 = AtomicU64::new(0);
/// Of [`ENTERED`]: calls (`blr`) from code not translated, branches (`br`)
/// from code such a call (`bl`) led to, and the others (not linked to
/// their site) whose return is followed.
static ENTERED_CALLS: AtomicU64 = AtomicU64::new(0);
static ENTERED_BRANCHES: AtomicU64 = AtomicU64::new(0);
static ENTERED_FOLLOWED: AtomicU64 = AtomicU64::new(0);
/// Sites of code not translated linked to translations.
static CALL_SITES_LINKED: AtomicU64 = AtomicU64::new(0);
/// For `FWE_TIMING`: entries by fetch by their target and `x30`, each
/// with how many there were and the registers that held the target.
static ENTRY_SPOTS: std::sync::Mutex<BTreeMap<(u64, u64), (u64, u32)>> =
    std::sync::Mutex::new(BTreeMap::new());
/// Time spent translating blocks, and in [`exit`] (with its lock), in
/// nanoseconds.
static TRANSLATE_NS: AtomicU64 = AtomicU64::new(0);
static EXIT_NS: AtomicU64 = AtomicU64::new(0);
/// Cache lines the program flushed, the blocks those flushes kept (their
/// words unchanged) and dropped, and blocks taken back ([`revive`]).
static LINES_FLUSHED: AtomicU64 = AtomicU64::new(0);
static KEPT: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static REVIVED: AtomicU64 = AtomicU64::new(0);
/// Times the code cache was emptied.
static FLUSHES: AtomicU64 = AtomicU64::new(0);

/// With `FWE_JIT_MAP` naming a directory, write there (`jit-<pid>.map`)
/// what the code cache holds as the process ends, for a profile of where
/// time in translations goes (the benchmarks' samples): a line per block's
/// hot words and another for its cold ones, each with its address in the
/// cache, its size in bytes, the block's program address, a letter per
/// word for what it stands for (`a` the program's instruction, `s` one
/// with its `x16` and `x17` saved, `x` one with its `x18` held in `x17`
/// too, `v` and `r` their save and restore, inside an expansion its
/// [`Of`], `l` a lookup, `L` one committed, `o` a way out) and its words
/// in hexadecimal; then, for the hot words, how many of the program's
/// words the block was made from and the last of them, and for the cold
/// ones `cold`.
pub fn write_map() {
    let Some(dir) = std::env::var_os("FWE_JIT_MAP") else { return };
    let s = state();
    let mut text = String::new();
    for b in &s.blocks {
        // SAFETY: a word of the block's translation, in the cache.
        let insn = |k: usize| unsafe { (b.addr(k) as *const u32).read() };
        // The words of each restore, a run of them.
        let restore = restore_words();
        let mut restoring = vec![false; b.words.len()];
        for k in 0..b.words.len().saturating_sub(RESTORE_WORDS - 1) {
            if (0..RESTORE_WORDS).all(|j| insn(k + j) == restore[j]) {
                restoring[k..k + RESTORE_WORDS].fill(true);
            }
        }
        let kinds: String = b
            .all_words()
            .enumerate()
            .map(|(k, w)| match w {
                Word::Undo { of, .. } | Word::Finish { of, .. } => of as u8 as char,
                Word::Stashed(_) => 'v',
                _ if insn(k) == SAVE => 'v',
                _ if restoring[k] => 'r',
                Word::At(_) => 'a',
                Word::Saved(_) => 's',
                Word::SavedX18(_) => 'x',
                Word::Lookup { to: None, .. } => 'l',
                Word::Lookup { .. } => 'L',
                Word::Out { .. } => 'o',
            })
            .collect();
        let words: String = (0..b.words.len()).map(|k| format!("{:08x}", insn(k))).collect();
        let hot = (b.len / 4) as usize;
        // The program's words it was made from: how many, and the last
        // (what ended it).
        let last = b.source.last().copied().unwrap_or(0);
        text.push_str(&format!(
            "{:x} {} {:x} {} {} {}:{last:08x}\n",
            b.t,
            b.len,
            b.g,
            &kinds[..hot],
            &words[..8 * hot],
            b.source.len()
        ));
        if b.cold_len > 0 {
            text.push_str(&format!(
                "{:x} {} {:x} {} {} cold\n",
                b.cold,
                b.cold_len,
                b.g,
                &kinds[hot..],
                &words[8 * hot..]
            ));
        }
    }
    let path = std::path::Path::new(&dir).join(format!("jit-{}.map", std::process::id()));
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("fwe: {}: {e}", path.display());
    }
}

/// What [`TRANSLATED`] and the others counted, if any code ran by
/// translation.
pub fn counts() -> Option<String> {
    let t = TRANSLATED.load(Ordering::Relaxed);
    let counted = (t > 0).then(|| {
        let s = state();
        let blocks: Vec<jitcount::Counted> = s
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| jitcount::Counted {
                g: b.g,
                origin: if b.followed { jitcount::FILE } else { jitcount::GENERATED },
                ahead: b.notes.ahead,
                counters: b.notes.counters,
                live: s.by_g.get(&b.g) == Some(&i),
                words: b.source.len(),
                leads: b.leads().collect(),
            })
            .collect();
        jitcount::report(&blocks, |a| !s.in_region(a) && followable(a))
    });
    (t > 0).then(|| {
        format!(
            "JIT code: {t} blocks translated, {} exits through fwe ({} direct and {} \
             indirect to code not translated; to blocks made already: {} direct, {} of them left unlinked, \
             {} indirect, {} of them with their entry another's), {} entries by fetch ({} returns, {} calls from code not translated, {} branches from code a call led to, {} sites linked, {} whose return is followed), \
             {} cache lines flushed ({} blocks kept unchanged, {} dropped, {} taken back), the code cache emptied {} times; \
             {} ms translating, {} ms in ways out, {} waits for the lock ({} ms), held {} ms in ways out, {} in flushes, {} in entries, {} in the gate, {} else",
            EXITS.load(Ordering::Relaxed),
            EXITS_DIRECT_OUT.load(Ordering::Relaxed),
            EXITS_INDIRECT_OUT.load(Ordering::Relaxed),
            EXITS_KNOWN_DIRECT.load(Ordering::Relaxed),
            EXITS_KNOWN_UNLINKED.load(Ordering::Relaxed),
            EXITS_KNOWN_INDIRECT.load(Ordering::Relaxed),
            EXITS_KNOWN_TAKEN.load(Ordering::Relaxed),
            ENTERED.load(Ordering::Relaxed),
            ENTERED_RETURNS.load(Ordering::Relaxed),
            ENTERED_CALLS.load(Ordering::Relaxed),
            ENTERED_BRANCHES.load(Ordering::Relaxed),
            CALL_SITES_LINKED.load(Ordering::Relaxed),
            ENTERED_FOLLOWED.load(Ordering::Relaxed),
            LINES_FLUSHED.load(Ordering::Relaxed),
            KEPT.load(Ordering::Relaxed),
            DROPPED.load(Ordering::Relaxed),
            REVIVED.load(Ordering::Relaxed),
            FLUSHES.load(Ordering::Relaxed),
            TRANSLATE_NS.load(Ordering::Relaxed) / 1_000_000,
            EXIT_NS.load(Ordering::Relaxed) / 1_000_000,
            LOCK_WAITS.load(Ordering::Relaxed),
            LOCK_WAIT_NS.load(Ordering::Relaxed) / 1_000_000,
            HOLD_NS[HOLD_EXIT].load(Ordering::Relaxed) / 1_000_000,
            HOLD_NS[HOLD_FLUSH].load(Ordering::Relaxed) / 1_000_000,
            HOLD_NS[HOLD_ENTER].load(Ordering::Relaxed) / 1_000_000,
            HOLD_NS[HOLD_GATE].load(Ordering::Relaxed) / 1_000_000,
            HOLD_NS[HOLD_OTHER].load(Ordering::Relaxed) / 1_000_000
        ) + &entry_spots()
            + "; "
            + counted.as_deref().unwrap_or_default()
    })
}

/// The entries by fetch taken most often ([`ENTRY_SPOTS`]): the target,
/// `x30`, the word before `x30` (a call's) and the registers holding the
/// target.
fn entry_spots() -> String {
    let spots = ENTRY_SPOTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut top: Vec<((u64, u64), (u64, u32))> = spots.iter().map(|(&k, &v)| (k, v)).collect();
    top.sort_by_key(|&(_, (n, _))| std::cmp::Reverse(n));
    let said: Vec<String> = top
        .iter()
        .take(8)
        .map(|&((pc, lr), (n, held))| {
            let at = lr.wrapping_sub(4);
            let w = crate::trap::read_host::<u32>(at);
            let before = w.map_or("?".into(), |w| format!("{w:08x}"));
            // A call's target's first words (as they are now).
            let to = w.filter(|w| w & 0xfc00_0000 == 0x9400_0000).map(|w| {
                let to = at.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
                let words: Vec<String> = (0..8)
                    .map_while(|k| crate::trap::read_host::<u32>(to + 4 * k))
                    .map(|w| format!("{w:08x}"))
                    .collect();
                format!(" (to {to:#x}: {})", words.join(" "))
            });
            let regs: Vec<String> =
                (0..31).filter(|r| held & 1 << r != 0).map(|r| format!("x{r}")).collect();
            format!(
                "{n} to {pc:#x} with x30 {lr:#x} after {before}{} in {}",
                to.unwrap_or_default(),
                regs.join(" ")
            )
        })
        .collect();
    if said.is_empty() {
        String::new()
    } else {
        format!("; entries by fetch at {} places, most often: {}", spots.len(), said.join(", "))
    }
}

/// The state, locked, for a caller of kind `site` ([`HOLD_NS`]).
fn state_at(site: usize) -> Held {
    Held { s: Some(lock_state()), site, since: Clock::now() }
}

fn state() -> Held {
    state_at(HOLD_OTHER)
}

/// [`STATE`] locked, and how long it is held counted by the kind of its
/// holder.
struct Held {
    /// The lock (none only while [`Held::unlocked`] runs its work).
    s: Option<std::sync::MutexGuard<'static, State>>,
    site: usize,
    since: Clock,
}

impl Held {
    /// `work` done with the lock let go, and taken again after: the state
    /// may have changed meanwhile.
    /// (Words patched meanwhile are synced by the next holder: a way out
    /// seen unlinked a while longer only goes through fwe, which finds it
    /// linked; unlinks, of the program's flushes and of emptying the
    /// cache, are synced before their holders let go.)
    fn unlocked<R>(&mut self, work: impl FnOnce() -> R) -> R {
        self.since.add_to(&HOLD_NS[self.site]);
        self.s = None;
        let r = work();
        self.s = Some(lock_state());
        self.since = Clock::now();
        r
    }
}

impl std::ops::Deref for Held {
    type Target = State;
    fn deref(&self) -> &State {
        self.s.as_ref().expect("the translator's lock held")
    }
}

impl std::ops::DerefMut for Held {
    fn deref_mut(&mut self) -> &mut State {
        self.s.as_mut().expect("the translator's lock held")
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(s) = &self.s {
            s.sync_patched();
        }
        self.since.add_to(&HOLD_NS[self.site]);
    }
}

/// The time now, read only for `FWE_TIMING` (which says what the JIT's
/// counters add up): a read costs as much as some of the work it times.
#[derive(Clone, Copy)]
struct Clock(Option<std::time::Instant>);

impl Clock {
    fn now() -> Self {
        Clock(fwe_kernel::timing::on().then(std::time::Instant::now))
    }

    /// The nanoseconds since it was read, added to `to`.
    fn add_to(self, to: &AtomicU64) {
        if let Some(t) = self.0 {
            to.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
}

/// How long [`STATE`] was held, by its holders' kinds: ways out, the
/// program's flushes, entries by fetch, the exit gate's look at where it
/// goes, and the rest.
const HOLD_EXIT: usize = 0;
const HOLD_FLUSH: usize = 1;
const HOLD_ENTER: usize = 2;
const HOLD_GATE: usize = 3;
const HOLD_OTHER: usize = 4;
static HOLD_NS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

fn lock_state() -> std::sync::MutexGuard<'static, State> {
    match STATE.try_lock() {
        Ok(s) => s,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            // Held by another thread: how often, and how long it waits
            // (held for moments, [`fwe_kernel::shortlock`]).
            let began = Clock::now();
            let s = fwe_kernel::shortlock::lock(&STATE);
            LOCK_WAITS.fetch_add(1, Ordering::Relaxed);
            began.add_to(&LOCK_WAIT_NS);
            s
        }
    }
}

/// The times a thread found [`STATE`] held by another, and how long they
/// waited for it, in nanoseconds.
static LOCK_WAITS: AtomicU64 = AtomicU64::new(0);
static LOCK_WAIT_NS: AtomicU64 = AtomicU64::new(0);

fn page_size() -> u64 {
    fwe_kernel::mm::host_page_size()
}

/// The table entry program address `g`'s bits pick: its key (an
/// address) and value (a translation's lookup entry, or 0), 16 bytes
/// aligned. `g` is there or in the other entry of the pair ([`OTHER`]).
fn entry(g: u64) -> u64 {
    entry_in(TABLE, g)
}

/// [`entry`] in `table` ([`TABLE`] or [`RETS`]).
fn entry_in(table: u64, g: u64) -> u64 {
    table | (((g >> 2) & ((1 << TABLE_BITS) - 1)) << 4)
}

/// Entry `e` as it is: key and value read at once (a 16-byte aligned
/// `ldp` is single-copy atomic: FEAT_LSE2, which every Apple processor
/// has).
fn read_entry(e: u64) -> (u64, u64) {
    let (k, v): (u64, u64);
    // SAFETY: an entry of the table, mapped for the process's life once the
    // code cache exists, 16 bytes aligned.
    unsafe {
        std::arch::asm!("ldp {k}, {v}, [{e}]", e = in(reg) e, k = out(reg) k,
            v = out(reg) v, options(nostack, readonly, preserves_flags));
    }
    (k, v)
}

/// Make entry `e` say `(key, value)` at once, after everything written
/// before (the translation it leads to).
fn write_entry(e: u64, key: u64, value: u64) {
    // SAFETY: as [`read_entry`]; a lookup reads the pair with one `ldp`.
    unsafe {
        std::arch::asm!("dmb ish", "stp {k}, {v}, [{e}]", e = in(reg) e, k = in(reg) key,
            v = in(reg) value, options(nostack, preserves_flags));
    }
}

/// The entry of `table` that holds `g`, if one of its pair does.
fn holding(table: u64, g: u64) -> Option<u64> {
    let e = entry_in(table, g);
    [e, e ^ 16].into_iter().find(|&e| read_entry(e).0 == g)
}

/// The value of an entry for the translation at `t`: its saved entry; 0
/// (`t` 0) for code not translated.
fn looked_up(t: u64) -> u64 {
    if t == 0 { 0 } else { t + 4 * CHECK_WORDS as u64 }
}

/// Make `g`'s entry say translation `t` (0: code not translated): the
/// one that holds it, else the one its bits pick, whose address moves to
/// the other of the pair (a lookup looks there first: the address wanted
/// last stays where it is found soonest). Under [`STATE`]'s lock: one
/// writer, and a lookup reads an entry whole, so it finds either address
/// in one of them as they move.
fn publish(g: u64, t: u64) {
    publish_in(TABLE, g, looked_up(t));
}

/// Clear `g`'s entry if it says translation `t`.
fn unpublish(g: u64, t: u64) {
    unpublish_in(TABLE, g, looked_up(t));
}

/// [`publish`] in `table`: `g`'s entry says `value`.
fn publish_in(table: u64, g: u64, value: u64) {
    let first = entry_in(table, g);
    let e = match holding(table, g) {
        Some(e) => e,
        None => {
            let (k, v) = read_entry(first);
            if k != 0 {
                write_entry(first ^ 16, k, v);
            }
            first
        }
    };
    write_entry(e, g, value);
}

/// [`unpublish`] in `table`: `g`'s entry cleared if it says `value`.
fn unpublish_in(table: u64, g: u64, value: u64) {
    if let Some(e) = holding(table, g)
        && read_entry(e).1 == value
    {
        write_entry(e, 0, 0);
    }
}

/// Block `b`'s calls' ways back as returns find them ([`RETS`]): each
/// return address, and the words after the call's `bl`.
fn pads(b: &Block) -> impl Iterator<Item = (u64, u64)> + '_ {
    b.pads.iter().copied()
}

/// Block `b` found by lookups: its program address's translation, and
/// its calls' pads by their return addresses.
fn publish_block(b: &Block) {
    publish(b.g, b.t);
    for (g, h) in pads(b) {
        publish_in(RETS, g, h);
    }
}

/// Block `b` found by no lookup ([`publish_block`] undone).
fn unpublish_block(b: &Block) {
    unpublish(b.g, b.t);
    for (g, h) in pads(b) {
        unpublish_in(RETS, g, h);
    }
}

impl State {
    fn in_region(&self, addr: u64) -> bool {
        self.regions.range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
    }

    /// Write `w` at `at` in the cache (its executable address). Its
    /// instruction cache line is invalidated with the others patched
    /// before the lock is let go or new words are written
    /// ([`State::sync_patched`]): a patch turns one way on into another
    /// (a way out into a branch to a translation, or back), each right
    /// meanwhile.
    fn patch(&self, at: u64, w: u32) {
        let c = self.cache.as_ref().expect("a code cache");
        let k =
            c.chunks.iter().find(|k| (k.rx..k.rx + chunk_size()).contains(&at)).expect("a chunk");
        // SAFETY: a word of the cache, through its writable view.
        unsafe { ((at - k.rx + k.rw) as *mut u32).write_volatile(w) };
        self.patched.borrow_mut().push(at);
    }

    /// The instruction cache lines of the words [`State::patch`] changed,
    /// and of those [`emit`] wrote, invalidated: each cleaned to the point
    /// of unification, then each invalidated, with one barrier between and
    /// after, as `sys_icache_invalidate` does for a range (and a barrier
    /// every 20 lines, as it does on the cores that need one).
    fn sync_patched(&self) {
        let mut patched = self.patched.borrow_mut();
        if patched.is_empty() {
            return;
        }
        // SAFETY: cache maintenance of words of the cache, mapped (in the
        // executable view); it changes no memory.
        unsafe {
            for &at in patched.iter() {
                std::arch::asm!("dc cvau, {0}", in(reg) at, options(nostack, preserves_flags));
            }
            std::arch::asm!("dsb ish", options(nostack, preserves_flags));
            for (k, &at) in patched.iter().enumerate() {
                if k > 0 && k % 20 == 0 {
                    std::arch::asm!("dsb ish", options(nostack, preserves_flags));
                }
                std::arch::asm!("ic ivau, {0}", in(reg) at, options(nostack, preserves_flags));
            }
            std::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
        patched.clear();
    }

    /// Link way out `at` (a direct one, not linked yet) of block `from` to
    /// `into`, a translation's entry as the way out has the program's `x16`
    /// and `x17`: a branch there, and the conditional branch it is the
    /// taken way of straight there too where that reaches. Whether it
    /// reaches.
    fn link(&self, from: usize, at: u64, into: u64) -> bool {
        let Some(b) = rewrite::branch(at, into) else { return false };
        self.patch(at, b);
        if let Some(c) = conditional(&self.blocks[from], at) {
            // SAFETY: a word of fwe's code cache, readable.
            if let Some(w) = retarget(unsafe { (c as *const u32).read() }, c, into) {
                self.patch(c, w);
            }
        }
        true
    }

    /// Undo [`State::link`] of way out `at` in block `from`: its first
    /// word as it was made, into the exit gate again (no trap), and its
    /// conditional branch leads to it.
    fn unlink(&self, from: &Block, at: u64) {
        let Some(Word::Out { saved, .. }) = from.word_at(at) else {
            panic!("a link at {at:#x}, no way out");
        };
        self.patch(at, if saved { OUT } else { SAVE });
        if let Some(c) = conditional(from, at) {
            // SAFETY: a word of fwe's code cache, readable.
            let w = retarget(unsafe { (c as *const u32).read() }, c, at);
            // In one segment with it ([`Chunk`]).
            self.patch(
                c,
                w.unwrap_or_else(|| panic!("way out {at:#x} out of reach of its branch {c:#x}")),
            );
        }
    }

    /// Drop the translations made from `[addr, addr + len)`, and forget
    /// them: the memory was unmapped, mapped anew, its protections changed
    /// or its pages discarded.
    fn drop_range(&mut self, addr: u64, len: u64) {
        kept::remapped(addr, len);
        let start = addr & !(page_size() - 1);
        let end = addr.saturating_add(len);
        let gone: Vec<u64> = self.dormant.range(start..end).map(|(&g, _)| g).collect();
        for g in gone {
            self.dormant.remove(&g);
        }
        // Other mappings of translated pages there map something else now.
        // (The pages in the range translated from, not every page of it:
        // a range may be a reservation of terabytes.)
        let aliases: Vec<u64> = self.aliases.range(start..end).map(|(&q, _)| q).collect();
        for q in aliases {
            self.aliases.remove(&q);
        }
        let pages: Vec<u64> = self.pages.range(start..end).map(|(&p, _)| p).collect();
        for p in pages {
            if let Some(k) = self.object_of.remove(&p)
                && let Some(ps) = self.objects.get_mut(&k)
            {
                ps.remove(&p);
                if ps.is_empty() {
                    self.objects.remove(&k);
                }
            }
            for i in self.pages.remove(&p).unwrap_or_default() {
                self.drop_block(i, false);
            }
        }
    }

    /// Drop block `i`'s translation, if it is its address's (the caller
    /// takes it off its page's list). `flushed`: kept to take back
    /// ([`revive`]).
    fn drop_block(&mut self, i: usize, flushed: bool) {
        let g = self.blocks[i].g;
        if self.by_g.get(&g) != Some(&i) {
            return;
        }
        self.by_g.remove(&g);
        unpublish_block(&self.blocks[i]);
        for &(p, ..) in &self.blocks[i].calls_made {
            if self.calls_made.get(&p).is_some_and(|&(j, ..)| j == i) {
                self.calls_made.remove(&p);
            }
        }
        if flushed {
            self.dormant.insert(g, i);
        }
        let len = self.blocks[i].size();
        if let Some(c) = self.cache.as_mut() {
            c.live -= len;
            c.garbage += len;
        }
        // Branches linked to it lead into fwe again, and wait for it to
        // be translated anew.
        for at in std::mem::take(&mut self.blocks[i].linked) {
            let Some(f) = block_at(self, at) else { continue };
            self.unlink(&self.blocks[f], at);
            if self.by_g.get(&self.blocks[f].g) == Some(&f) {
                wait(&mut self.waiting, g, (at, f));
            }
        }
    }
}

/// `[addr, addr + len)` holds code the program made executable after it
/// mapped it: it runs by translation from now on.
pub fn code(addr: u64, len: u64) {
    let mut s = state();
    ANY_CODE.store(true, Ordering::Release);
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

/// `[addr, addr + len)` is about to be replaced by fresh pages, mapped as
/// it was (`MADV_DONTNEED`): its translations go, but it still holds code
/// to translate.
pub fn discarded(addr: u64, len: u64) {
    state().drop_range(addr, len);
}

/// The program invalidated the instruction cache line at `addr` (`ic
/// ivau`), as it does after writing code there: the blocks made from the
/// line, through this mapping or another of the same memory, whose words
/// it changed go. Each is kept, and taken back if its words turn out as
/// they were ([`revive`]).
pub fn flushed(addr: u64) {
    LINES_FLUSHED.fetch_add(1, Ordering::Relaxed);
    jitcount::flushed(addr);
    if TRANSLATED.load(Ordering::Relaxed) == 0 {
        return;
    }
    let line = 4 << (crate::hwcap::CTR_EL0 & 15);
    let mut s = state_at(HOLD_FLUSH);
    drop_lines(&mut s, addr & !(line - 1), line);
}

/// fwe wrote the program's code at `[addr, addr + len)` itself (a
/// debugger's breakpoint, through `ptrace` or `/proc/pid/mem`): as Linux
/// syncs the instruction cache there, the blocks made from it go.
fn code_written(addr: u64, len: u64) {
    // SAFETY: memory fwe just wrote, mapped.
    unsafe { crate::prepare::flush_icache(addr, len) };
    if TRANSLATED.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut s = state();
    let (mut at, end) = (addr, addr.saturating_add(len));
    while at < end {
        let next = ((at & !(page_size() - 1)) + page_size()).min(end);
        drop_lines(&mut s, at, next - at);
        at = next;
    }
}

/// Drop the blocks made from `[addr, addr + len)` (within a page) whose
/// words changed, kept to take back, through this mapping and any other
/// of the same file's page.
fn drop_lines(s: &mut State, addr: u64, len: u64) {
    let ps = page_size();
    let page = addr & !(ps - 1);
    let (off, end) = (addr - page, (addr - page + len).min(ps));
    // (Most lines a JIT flushes are on a page of its own mapping alone,
    // and hold no block yet: code it just wrote.)
    if !s.aliases.contains_key(&page) && !s.object_of.contains_key(&page) {
        drop_on(s, page, off, end);
        return;
    }
    let mut pages = vec![page];
    pages.extend(s.aliases.get(&page).into_iter().flatten().copied());
    if let Some(ps) = s.object_of.get(&page).and_then(|k| s.objects.get(k)) {
        pages.extend(ps.iter().copied());
    }
    pages.sort_unstable();
    pages.dedup();
    for p in pages {
        drop_on(s, p, off, end);
    }
}

/// Drop the blocks made from `[p + off, p + end)`, on page `p`, whose
/// words changed, kept to take back. A block whose words are the same
/// stays: a JIT flushes lines whose instructions it left alone (a word
/// of data beside them changed, code written next to them).
fn drop_on(s: &mut State, p: u64, off: u64, end: u64) {
    let Some(blocks) = s.pages.get(&p) else { return };
    let on = |i: usize| {
        let b = &s.blocks[i];
        p + off < b.g + 4 * b.source.len() as u64 && p + end > b.g
    };
    let on_line = blocks.iter().filter(|&&i| on(i)).count();
    if on_line == 0 {
        return;
    }
    let (hit, kept): (Vec<usize>, Vec<usize>) =
        blocks.iter().partition(|&&i| on(i) && !s.blocks[i].unchanged());
    KEPT.fetch_add((on_line - hit.len()) as u64, Ordering::Relaxed);
    if hit.is_empty() {
        return;
    }
    s.pages.insert(p, kept);
    for i in hit {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        s.drop_block(i, true);
    }
}

/// Whether the program ever had code run by translation ([`code`], or a
/// code cache): until it does, a change to its memory takes no lock
/// ([`changed`]).
static ANY_CODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a page translated from maps a file shared ([`State::objects`]),
/// ever: until one does, a mapping takes no lock ([`mapped`]).
static ANY_OBJECTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `[addr, addr + len)` no longer holds such code, or changed beyond what
/// fwe kept watch over (unmapped, mapped anew, its protections changed):
/// its translations are dropped. Whether any of it held such code.
pub fn changed(addr: u64, len: u64) -> bool {
    if !ANY_CODE.load(Ordering::Acquire) {
        return false;
    }
    let mut s = state();
    let end = addr.saturating_add(len);
    let held = s.regions.range(..end).any(|(_, &e)| e > addr);
    s.drop_range(addr, len);
    remove(&mut s.regions, addr, len);
    held
}

/// The program's file is `id` (none if it has no identity of its own, a
/// memfd's), for the blocks kept of its code ([`kept`]).
pub fn program_is(id: Option<fwe_kernel::prepcache::FileId>) {
    kept::program_is(id.map(|i| i.dev_ino()));
}

/// Add the blocks this process made from files' code to those kept
/// ([`kept`]): as it ends, and before it replaces its program.
pub fn keep_made() {
    kept::write();
}

/// A new program in this process (`execve`): nothing of the old one's.
pub fn reset() {
    jitcount::write_seen();
    keep_made();
    let mut s = state();
    let regions: Vec<(u64, u64)> = s.regions.iter().map(|(&a, &e)| (a, e)).collect();
    for (a, e) in regions {
        s.drop_range(a, e - a);
    }
    s.regions.clear();
    if s.cache.is_some() {
        for &i in s.by_g.values() {
            unpublish_block(&s.blocks[i]);
        }
        for &g in &s.outside {
            unpublish(g, 0);
        }
    }
    s.by_g.clear();
    s.outside.clear();
    s.objects.clear();
    s.object_of.clear();
    s.aliases.clear();
    s.veneers.clear();
    s.calls_made.clear();
    s.returns.clear();
    s.call_sites.clear();
    s.call_stubs.clear();
    s.waiting.clear();
    s.dormant.clear();
}

/// Held across a `fork`, so that the child's copy of the translations is
/// whole (no other thread is midway through making one).
pub fn hold() -> std::sync::MutexGuard<'static, State> {
    lock_state()
}

/// In a fork child, with [`hold`]'s guard: the code cache's two views are
/// copies of their own now, so the executable one is mapped anew from the
/// writable one, which the child's translations are written to.
pub fn forked(s: &mut State) {
    kept::forked();
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
/// `lr`, which tells a return; `held` a bit for each of `x0`..`x30` that
/// holds `pc`): the translation to run instead, if `pc` holds code that
/// runs by translation.
pub fn enter(pc: u64, lr: u64, held: u32) -> Option<u64> {
    let mut s = state_at(HOLD_ENTER);
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
    if fwe_kernel::timing::on() {
        let mut spots = ENTRY_SPOTS.lock().unwrap_or_else(|e| e.into_inner());
        spots.entry((pc, lr)).or_insert((0, held)).0 += 1;
    }
    let i = translation(&mut s, pc);
    let into = s.blocks[i].unsaved_entry();
    if lr == pc {
        ENTERED_RETURNS.fetch_add(1, Ordering::Relaxed);
        return Some(into);
    }
    // Called from code fwe prepared in place (`blr xN` before `lr`, `xN`
    // the target), or branched to from code a call there led to (`bl`
    // before `lr`, whose target's words up to their first branch end in
    // `br xN`): that site looks its targets up from now on, as a
    // translation does. (Read as the host copies: `lr` may be anything.)
    let site = branch_site(&s, lr.wrapping_sub(4), held);
    let linked = site.is_some_and(|(site, n, call)| {
        let counter = if call { &ENTERED_CALLS } else { &ENTERED_BRANCHES };
        counter.fetch_add(1, Ordering::Relaxed);
        match s.call_sites.get(&site) {
            Some(&linked) => linked,
            None => link_call_site(&mut s, site, n, call),
        }
    });
    // Else nothing tells where it came from (a branch through a register,
    // a call whose site took no stub): where it returns is followed, so the
    // code that came in runs by translation from there, its next ways in
    // lookups rather than faults.
    if !linked && !s.in_region(lr) && followable(lr) {
        ENTERED_FOLLOWED.fetch_add(1, Ordering::Relaxed);
        if s.returns.insert(lr) && s.outside.remove(&lr) {
            unpublish(lr, 0);
        }
    }
    Some(into)
}

/// The site of code fwe prepared in place that a fetch came from, `xN`
/// holding its target (`held`, as [`enter`] has it), found from the word at
/// `at`, before the thread's `x30`: `blr xN` there, or `bl` there whose
/// target's words up to their first branch end in `br xN` (a hint, such
/// as `bti`, being none). The site, `N`, and whether it is a call.
fn branch_site(s: &State, at: u64, held: u32) -> Option<(u64, u32, bool)> {
    let usable = |at: u64| !s.in_region(at) && followable(at);
    let read = |at: u64| usable(at).then(|| crate::trap::read_host::<u32>(at)).flatten();
    let w = read(at)?;
    let (site, w, call) = if w & 0xfc00_0000 == 0x9400_0000 {
        let to = at.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
        // Up to a block's words in a straight line.
        (0..64u64).map(|k| to + 4 * k).find_map(|at| {
            let w = read(at)?;
            let branch = (w >> 26) & 0x7 == 0b101 && w & 0xffff_f01f != 0xd503_201f;
            branch.then_some((at, w, false))
        })?
    } else {
        (at, w, true)
    };
    let op = if call { 0xd63f_0000 } else { 0xd61f_0000 };
    let n = (w >> 5) & 0x1f;
    (w & 0xffff_fc1f == op && held & 1 << n != 0 && !matches!(n, 18 | 30))
        .then_some((site, n, call))
}

/// Give site `site` (`blr xN` if `call`, else `br xN`, in code fwe
/// prepared in place) a stub within reach that looks the target up in the
/// table, as a translation's lookup does, and goes to its translation, or
/// makes the call or branch as it was (target not translated, or not
/// yet): every register as the site would leave it. The site becomes `bl`
/// (`b`) to it, made with every other thread stopped. Whether it did.
fn link_call_site(s: &mut State, site: u64, n: u32, call: bool) -> bool {
    s.call_sites.insert(site, false);
    // As a translation's lookup ([`lookup`]): in place, or through `x16`.
    // Each entry of the target's pair in turn: a miss in the first goes to
    // the second's look, found goes on to the translation, and a miss in
    // the second and a target not translated make the call as it was.
    let (first, other, go) = if matches!(n, 16 | 17) {
        let at = |other: bool| {
            let mut w = vec![INDEX, SCALE, BASE];
            w.extend(other.then_some(OTHER));
            w.extend([KEY, CHECK, MISS, INDEX, SCALE, BASE]);
            w.extend(other.then_some(OTHER));
            w.extend([VALUE, OUTSIDE]);
            w
        };
        (at(false), at(true), vec![TO_CHECK, GO])
    } else {
        let at = |other: bool| {
            let mut w = vec![index_of(n), SCALE, BASE];
            w.extend(other.then_some(OTHER));
            w.extend([ENTRY, key_against(n), MISS_X16, OUTSIDE]);
            w
        };
        (at(false), at(true), vec![GO])
    };
    let mut words = save_words().to_vec();
    if matches!(n, 16 | 17) {
        // The target from its slot, the area's address in x17 after the save.
        let (s16, s17) = crate::parked_slots();
        let slot = if n == 16 { s16 } else { s17 };
        words.push(rewrite::LDR_UIMM | ((slot / 8) << 10) | (17 << 5) | 16);
    }
    words.extend(&first);
    let go_at = words.len();
    words.extend(&go);
    let other_at = words.len();
    words.extend(&other);
    // (Found in the second: on to the translation.)
    words.push(0x1400_0000 | ((go_at as u32).wrapping_sub(words.len() as u32) & 0x3ff_ffff));
    let restore = words.len() as u32;
    for (k, w) in words.iter_mut().enumerate() {
        let to = match *w {
            MISS | MISS_X16 if k < go_at => other_at as u32,
            MISS | MISS_X16 | OUTSIDE => restore,
            _ => continue,
        };
        *w |= (to - k as u32) << 5;
    }
    words.extend(restore_words());
    words.push(0xd61f_0000 | (n << 5)); // br xN
    let _stopped = crate::quiesce::stop_others(&mut |_| {});
    let Some(stub) = crate::prepare::call_stub(site, &words) else { return false };
    s.call_stubs.insert(stub, (site, words));
    let Some(b) = rewrite::branch(site, stub) else { return false };
    let page = site & !(page_size() - 1);
    let prot = fwe_kernel::mm::host_prot_at(page);
    // Writable a moment, not executable meanwhile (the host allows no page
    // both at once).
    let writable = (prot & !libc::PROT_EXEC) | libc::PROT_READ | libc::PROT_WRITE;
    // Code read through the site to be translated has its own word back.
    let own = if call { 0xd63f_0000 } else { 0xd61f_0000 };
    crate::prepare::note_call_site(site, own | (n << 5));
    // SAFETY: a page of the program's code, no other thread running; it
    // gets its protections back.
    unsafe {
        if libc::mprotect(page as *mut libc::c_void, page_size() as usize, writable) != 0 {
            return false;
        }
        (site as *mut u32).write(if call { b | 0x8000_0000 } else { b }); // bl or b
        libc::mprotect(page as *mut libc::c_void, page_size() as usize, prot);
        crate::prepare::flush_icache(site, 4);
    }
    CALL_SITES_LINKED.fetch_add(1, Ordering::Relaxed);
    s.call_sites.insert(site, true);
    true
}

/// The way out at `regs.pc`, taken by the exit gate (outside a signal's
/// handler): as [`exit`], and where it leads to a translation's start,
/// that translation's saved entry and its program address, for the gate
/// to enter it as a lookup does.
pub fn gate_exit(regs: &mut Regs) -> Option<(u64, u64)> {
    assert!(exit(regs, false), "the exit gate entered from no way out ({:#x})", regs.pc);
    let s = state_at(HOLD_GATE);
    let i = block_at(&s, regs.pc)?;
    let b = &s.blocks[i];
    (b.unsaved == regs.pc && !b.retired && s.by_g.get(&b.g) == Some(&i)).then_some((b.body, b.g))
}

/// The way out of a block at `regs.pc` (its trap (`trapped`), as the way
/// out has the program's `x16` and `x17`, or the exit gate's call, which
/// took them back): `regs`, the program's, go on at the translation of
/// where it leads (entered with its registers), or at the address itself
/// where that is not code run by translation; a direct branch is linked
/// there. `false` if `pc` is no way out of fwe's.
pub fn exit(regs: &mut Regs, trapped: bool) -> bool {
    let began = Clock::now();
    let r = exit_now(regs, trapped);
    began.add_to(&EXIT_NS);
    r
}

fn exit_now(regs: &mut Regs, trapped: bool) -> bool {
    let mut s = state_at(HOLD_EXIT);
    let at = regs.pc;
    let from = block_at(&s, at);
    let word = from.and_then(|i| s.blocks[i].word_at(at));
    let Some(Word::Out { exit, saved, x18, .. }) = word else { return false };
    // A wrong block's way out has the target in x16.
    let wrong_to = regs.x[16];
    if trapped && saved {
        (regs.x[16], regs.x[17]) = parked();
    }
    EXITS.fetch_add(1, Ordering::Relaxed);
    // A retired block's ways out are not linked: its room is had back once
    // nothing is in it, and a link from it would outlive it.
    let from_retired = from.is_some_and(|i| s.blocks[i].retired);
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
        Exit::Retry => (wrong_to, false),
        // Into a call whose words left (its block dropped: the program
        // changed the call, say): linked as a direct branch, to the
        // translation of the call.
        Exit::Join(to) => (to, true),
    };
    let lookup = matches!(exit, Exit::Reg { .. } | Exit::Retry);
    // Code fwe prepared in place (a library's, the program's own) that a
    // translation calls or branches to is followed: translated too, so
    // what it calls and where it returns stay in translations. A return
    // is followed only to where a translated call returns, or an entry by
    // fetch not linked to its site ([`enter`]); to a caller not
    // translated, it goes back to code that runs as it is.
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
        // reaches and the program has its registers, else through a
        // veneer.
        if link_here && !from_retired && s.cache.as_ref().is_some_and(|c| c.flushes == flushes) {
            if let Some(b) = rewrite::branch(at, to).filter(|_| !saved) {
                s.patch(at, b);
            } else {
                let i = veneer(&mut s, to, saved);
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
    let known = s.by_g.contains_key(&to);
    if known {
        if lookup { &EXITS_KNOWN_INDIRECT } else { &EXITS_KNOWN_DIRECT }
            .fetch_add(1, Ordering::Relaxed);
        let key = read_entry(entry(to)).0;
        if lookup && holding(TABLE, to).is_none() && key != 0 {
            EXITS_KNOWN_TAKEN.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut i = translation(&mut s, to);
    // (The cache emptied as blocks were made ahead: its block anew.)
    if ahead(&mut s, i) {
        i = translation(&mut s, to);
    }
    // Linked where the target is in reach (in the same chunk), unless the
    // cache was emptied meanwhile (`at` may be reused) or the block left
    // since (the lock let go as it was translated).
    let same = s.cache.as_ref().is_some_and(|c| c.flushes == flushes);
    let from_retired = same && from.is_some_and(|f| s.blocks[f].retired);
    // (Linked already where the way out waited for the translation.)
    if link_here
        && same
        && !from_retired
        && let Some(f) = from
        && unlinked(at)
        && s.link(f, at, entered(&s, i, saved, x18))
    {
        s.blocks[i].linked.push(at);
    } else if known && link_here {
        EXITS_KNOWN_UNLINKED.fetch_add(1, Ordering::Relaxed);
    }
    regs.pc = s.blocks[i].unsaved_entry();
    true
}

/// The program's address of the `svc` whose system-call stub in a
/// translation returns past `site` (as [`crate::gate::site_of`] gives it):
/// kept in the two words before it, read without the translator's lock.
pub fn syscall_site(site: u64) -> u64 {
    // SAFETY: the words of a translation's system-call stub, in the cache.
    unsafe { ((site - 4) as *const u64).read_unaligned() }
}

/// The program's address of the instruction a word of a translation at
/// `pc` stands for, if `pc` is in one: a system call made from a
/// translation is the program's `svc`'s, for the kernel (which restarts it
/// there, writes a signal frame from it, and shows it to a tracer).
pub fn guest_pc(pc: u64) -> Option<u64> {
    match word_at(&state(), pc)? {
        Word::At(g)
        | Word::Saved(g)
        | Word::SavedX18(g)
        | Word::Stashed(g)
        | Word::Out { g, .. }
        | Word::Undo { g, .. }
        | Word::Finish { g, .. }
        | Word::Lookup { g, .. } => Some(g),
    }
}

/// `regs` stopped in fwe's code cache (a fault, a signal), or in a call
/// stub ([`link_call_site`]): as the program's state at the instruction it
/// stands for. `false` if `regs.pc` is in neither.
pub fn to_guest(regs: &mut Regs) -> bool {
    let s = state();
    if call_stub_to_guest(&s, regs) {
        return true;
    }
    // On its way into the exit gate from the way out in `x16`, past its
    // first words: as at the words of the way out after them.
    let Some(w) = (if in_exit_stub(regs.pc) {
        match word_at(&s, regs.x[16]) {
            Some(Word::Out { g, .. }) => Some(Word::Saved(g)),
            _ => None,
        }
    } else {
        word_at(&s, regs.pc)
    }) else {
        return false;
    };
    let sp = regs.sp;
    // SAFETY: the stack below which a save put the program's registers.
    let below = |off: u64| unsafe { (sp.wrapping_sub(off) as *const u64).read() };
    match w {
        Word::Out { exit: Exit::Retry, .. } => {
            let to = regs.x[16];
            (regs.x[16], regs.x[17]) = parked();
            regs.pc = to;
        }
        Word::At(g) => regs.pc = g,
        Word::Out { g, saved: false, .. } => regs.pc = g,
        Word::SavedX18(g) => {
            regs.x[18] = regs.x[17];
            (regs.x[16], regs.x[17]) = parked();
            regs.pc = g;
        }
        Word::Saved(g) | Word::Out { g, .. } => {
            (regs.x[16], regs.x[17]) = parked();
            regs.pc = g;
        }
        Word::Stashed(g) => {
            (regs.x[16], regs.x[17]) = (below(16), below(8));
            regs.pc = g;
        }
        Word::Undo { g, start, .. } => {
            undo(regs, start);
            regs.pc = g;
        }
        Word::Finish { g, .. } => {
            finish(regs, |at| matches!(word_at(&s, at), Some(Word::Finish { g: o, .. }) if o == g));
            regs.pc = g + 4;
        }
        Word::Lookup { g, link, to } => {
            // In a register of the lookup's, or the program's own, as its
            // slot holds it.
            let held = to.filter(|&r| r < IN_SLOT).map(|r| regs.x[usize::from(r)]);
            (regs.x[16], regs.x[17]) = parked();
            let target = match to {
                Some(r) if r >= IN_SLOT => Some(regs.x[usize::from(r - IN_SLOT)]),
                _ => held,
            };
            if let Some(target) = target {
                if let Some(link) = link {
                    regs.x[30] = link;
                }
                regs.pc = target;
            } else {
                regs.pc = g;
            }
        }
    }
    true
}

/// [`Word::Lookup`]'s `to` for a target in the program's own `x<n>`, which
/// its slot holds, rather than in a register of the lookup's.
const IN_SLOT: u8 = 32;

/// `regs` stopped in a call stub ([`link_call_site`]): as at its site,
/// which calls or branches again (`x30` as a call sets it), the program's `x16`
/// and `x17` in their registers at its first and last words, below `sp`
/// in its save, and in their slots after. `false` if `regs.pc` is in none.
fn call_stub_to_guest(s: &State, regs: &mut Regs) -> bool {
    let Some((&stub, (site, words))) = s.call_stubs.range(..=regs.pc).next_back() else {
        return false;
    };
    let k = ((regs.pc - stub) / 4) as usize;
    if k >= words.len() {
        return false;
    }
    let sp = regs.sp;
    // SAFETY: the stack below which the stub's save put them.
    let below = |off: u64| unsafe { (sp.wrapping_sub(off) as *const u64).read() };
    if (1..SAVE_WORDS).contains(&k) {
        (regs.x[16], regs.x[17]) = (below(16), below(8));
    } else if k != 0 && k != words.len() - 1 {
        (regs.x[16], regs.x[17]) = parked();
    }
    regs.pc = *site;
    true
}

fn word_at(s: &State, pc: u64) -> Option<Word> {
    let i = block_at(s, pc)?;
    s.blocks[i].word_at(pc)
}

/// The block whose translation holds `pc`, in its hot or cold words.
fn block_at(s: &State, pc: u64) -> Option<usize> {
    let (_, &i) = s.by_t.range(..=pc).next_back()?;
    s.blocks[i].index(pc).map(|_| i)
}

/// Note block `i`'s parts' starts in `by_t` ([`State::by_t`]): its hot
/// words', and its cold ones' if it has any.
fn index_parts(by_t: &mut BTreeMap<u64, usize>, b: &Block, i: usize) {
    by_t.insert(b.t, i);
    if b.cold_len > 0 {
        by_t.insert(b.cold, i);
    }
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
        } else if w & !0x1f == STUR_SP_M16 {
            saved.push((vec![(w & 0x1f, (-16i64) as u64)], 0));
        } else if w & !0x7c1f == STP_SP_M16 {
            saved.push((vec![(w & 0x1f, (-16i64) as u64), ((w >> 10) & 0x1f, (-8i64) as u64)], 0));
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
            regs.x[r as usize] = unsafe { (regs.sp.wrapping_add(off) as *const u64).read() };
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
    } else if w & !0x1f == LDUR_SP_M16 {
        regs.x[t as usize] = read(regs.sp - 16);
    } else if w & !0x7c1f == LDP_SP_M16 {
        regs.x[t as usize] = read(regs.sp - 16);
        regs.x[((w >> 10) & 0x1f) as usize] = read(regs.sp - 8);
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

/// Where a direct branch enters block `i`: with the program's `x16` and
/// `x17` saved in their slots (`saved`), and its `x18` in `x17` too (`x18`),
/// or in their registers.
fn entered(s: &State, i: usize, saved: bool, x18: bool) -> u64 {
    let b = &s.blocks[i];
    match (saved, x18) {
        (true, true) if b.x18 != 0 => b.x18,
        (true, _) => b.body,
        _ => b.unsaved_entry(),
    }
}

/// The translation of program address `g`, made if there is none:
/// without the lock (it is let go a moment), from one look at the
/// program's words, and placed if they are still as it saw them and no
/// other thread placed one meanwhile (else it looks again).
fn translation(s: &mut Held, g: u64) -> usize {
    loop {
        if let Some(&i) = s.by_g.get(&g) {
            // Its table entry may have gone to another address since (they
            // share entries): it is its own again.
            publish_block(&s.blocks[i]);
            return i;
        }
        if s.cache.is_none() {
            s.cache = Some(new_cache());
            ANY_CODE.store(true, Ordering::Release);
        }
        let page = g & !(page_size() - 1);
        let followed = !s.in_region(g);
        if let Some(i) = revive(s, g, page) {
            return i;
        }
        let making = Clock::now();
        let source = snapshot(g);
        // A file's code: its block as kept ([`kept`]), where its words and
        // the calls made in other blocks' words that it goes on into are
        // as they were.
        let part = if followed && !jitcount::counting() { kept::part_of(g) } else { None };
        if let Some(p) = part
            && let Some((mut made, info)) = kept::take(p, g, &source, |end| calls_in(s, g, end))
        {
            // Its ways into calls made in other blocks' words, to where
            // those words are now.
            for (_, q, at) in &mut made.room.c.joins {
                *at = s.calls_made.get(q).map_or(0, |&(_, a)| a);
            }
            let n = ((made.end - g) / 4) as usize;
            let r = place(s, g, followed, made, info, source[..n].to_vec(), true);
            making.add_to(&jitcount::TAKE_NS);
            return r;
        }
        // Calls made already from the words it may read: made there.
        let known: Vec<(u64, u64)> = s
            .calls_made
            .range(g..g + 4 * source.len() as u64)
            .map(|(&p, &(_, at))| (p, at))
            .collect();
        // (Made at 0, its words standing anywhere; placed below.)
        let made = s.unlocked(|| {
            let began = Clock::now();
            let made = with_snapshot(g, &source, || translate(g, 0, followed, &known));
            began.add_to(&TRANSLATE_NS);
            made
        });
        let read_words = ((made.end - g) / 4) as usize;
        let same = source[..read_words].iter().zip((g..).step_by(4)).all(|(&w, at)| read(at) == w);
        if s.by_g.contains_key(&g) || !same || followed == s.in_region(g) {
            continue;
        }
        let info = packed(&made.room.asm, g);
        if let Some(p) = part {
            let calls: Vec<u64> =
                known.iter().map(|k| k.0).filter(|&q| q > g && q < made.end).collect();
            kept::keep(p, g, &source[..read_words], &calls, &made, &info);
        }
        let r = place(s, g, followed, made, info, source[..read_words].to_vec(), false);
        making.add_to(
            &jitcount::MAKE_NS[if followed { jitcount::FILE } else { jitcount::GENERATED }],
        );
        return r;
    }
}

/// How many blocks a way out makes ahead of the program ([`ahead`]).
const AHEAD: usize = 4;

thread_local! {
    /// Whether the blocks this thread makes are made ahead ([`jitcount`]).
    static MAKING_AHEAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make the blocks block `i` goes on to whatever its conditions ([`AHEAD`]
/// at most, from it on): its direct branch's target, a call's and where
/// it returns, the next instruction past a block cut short. Each would be
/// made at a way out of its own as the program reached it, through the
/// gate and the lock, one at a time; made now, they are linked at once.
/// Only code the program goes on to is made (a call may not return: its
/// return site is the program's words, decoded and never run). Whether
/// the cache was emptied meanwhile (block indices are then another's).
fn ahead(s: &mut Held, i: usize) -> bool {
    let flushes = s.cache.as_ref().map_or(0, |c| c.flushes);
    let mut next = vec![i];
    let mut made = 0;
    while let Some(i) = next.pop() {
        for to in successors(&s.blocks[i]) {
            if made == AHEAD {
                return false;
            }
            if s.by_g.contains_key(&to) || !(s.in_region(to) || followable(to)) {
                continue;
            }
            MAKING_AHEAD.set(true);
            let j = translation(s, to);
            MAKING_AHEAD.set(false);
            made += 1;
            if s.cache.as_ref().map_or(0, |c| c.flushes) != flushes {
                return true;
            }
            next.push(j);
        }
    }
    false
}

/// Where block `b` goes on to whatever its conditions: the targets of its
/// direct ways out that are no conditional branch's taken way.
fn successors(b: &Block) -> Vec<u64> {
    let mut to: Vec<u64> = b.jumps().filter(|&(_, _, cond)| !cond).map(|(_, to, _)| to).collect();
    to.sort_unstable();
    to.dedup();
    to
}

/// The calls made in other blocks' words ([`State::calls_made`]) past `g`
/// and before `end`: those a block made at `g` goes on into.
fn calls_in(s: &State, g: u64, end: u64) -> Vec<u64> {
    s.calls_made.range(g + 1..end).map(|(&p, _)| p).collect()
}

/// What each word of block `a`, at program address `g`, stands for, packed
/// (its expansions' starts as made, at 0).
fn packed(a: &Asm<Word>, g: u64) -> Vec<Packed> {
    let (hot, cold) = (a.info(H), a.info(C));
    let mut info = Vec::with_capacity(hot.len() + cold.len());
    info.extend(hot.iter().chain(cold).map(|&w| Packed::of(w, g, 0)));
    info
}

/// Place translation `made` of the block at `g` (`followed`, of code fwe
/// prepared in place; `info`, what its words stand for, packed; `source`,
/// the program's words it was made from; `taken`, from a record kept
/// rather than made now) in the cache, and publish it.
fn place(
    s: &mut State,
    g: u64,
    followed: bool,
    made: Made,
    info: Vec<Packed>,
    source: Vec<u32>,
    taken: bool,
) -> usize {
    let Made { mut room, entry, unsaved, x18, end: _, second, counters } = made;
    let origin = if followed { jitcount::FILE } else { jitcount::GENERATED };
    let ahead = MAKING_AHEAD.get();
    if taken {
        jitcount::TAKEN[origin].fetch_add(1, Ordering::Relaxed);
    } else {
        jitcount::MADE[origin].fetch_add(1, Ordering::Relaxed);
        if let Some(n) = second {
            jitcount::SECOND.fetch_add(1, Ordering::Relaxed);
            jitcount::SECOND_WORDS.fetch_add(n as u64, Ordering::Relaxed);
        }
        if ahead {
            jitcount::AHEAD.fetch_add(1, Ordering::Relaxed);
        }
        jitcount::seen(g, &source, origin);
    }
    let Room { asm, c: calls } = &mut room;
    let (hot, cold) = (asm.len(H), asm.len(C));
    // (Room is made first: emptying the cache forgets every page's other
    // mappings.)
    let page = g & !(page_size() - 1);
    let (stub, at, at_cold) = cache_next(s, 4 * hot as u64, 4 * cold as u64);
    note_aliases(s, page);
    // Its branches resolved where it goes, its ways out on into the exit
    // stub of its chunk.
    asm.finish([at, at_cold], stub);
    // Where its calls return is followed too, from code not translated
    // (a library's function the call went to): no longer branched to as
    // code not translated.
    for &r in &calls.calls {
        if s.returns.insert(r) && s.outside.remove(&r) {
            unpublish(r, 0);
        }
    }
    let (t, cold_t) = emit(s, asm.words(H), asm.words(C));
    assert_eq!((t, cold_t), (at, at_cold), "a block placed where its branches were pointed");
    let (len, cold_len) = (4 * hot as u64, 4 * cold as u64);
    s.cache.as_mut().expect("a code cache").live += len + cold_len;
    let i = s.blocks.len();
    s.pages.entry(page).or_default().push(i);
    s.blocks.push(Block {
        g,
        t,
        words: info,
        linked: Vec::new(),
        len,
        cold: cold_t,
        cold_len,
        body: t + 4 * entry as u64,
        unsaved: t + 4 * unsaved as u64,
        x18: if x18 == 0 { 0 } else { t + 4 * x18 as u64 },
        retired: false,
        source,
        followed,
        pads: calls.pads.iter().map(|&(r, k)| (r, t + 4 * k as u64)).collect(),
        calls_made: Vec::new(),
        notes: Notes {
            ahead,
            second: second.is_some() && !taken,
            used: Default::default(),
            counters,
        },
    });
    s.by_g.insert(g, i);
    index_parts(&mut s.by_t, &s.blocks[i], i);
    // Its calls for blocks made later, where none is made yet; its ways
    // into calls made already linked there, if they still are.
    // Other blocks enter a call's words with `x18` in its slot.
    for &(p, k, _) in calls.made.iter().filter(|m| !m.2) {
        if let std::collections::btree_map::Entry::Vacant(e) = s.calls_made.entry(p) {
            e.insert((i, t + 4 * k));
            s.blocks[i].calls_made.push((p, t + 4 * k));
        }
    }
    for &(k, p, at) in &calls.joins {
        let from = t + 4 * k as u64;
        if let Some(&(j, made)) = s.calls_made.get(&p)
            && made == at
            && !s.blocks[j].retired
            && s.link(i, from, at)
        {
            s.blocks[j].linked.push(from);
        }
    }
    publish_block(&s.blocks[i]);
    TRANSLATED.fetch_add(1, Ordering::Relaxed);
    link_waiting(s, i);
    ROOM.set(Some(room));
    i
}

/// Take back the block at program address `g`, on page `p`, that a flush
/// of its words dropped ([`State::dormant`]), if they were not changed: a
/// JIT flushes code it wrote anew as the same (a method installed again,
/// a patch undone). Only a block wanted again is taken back.
fn revive(s: &mut State, g: u64, p: u64) -> Option<usize> {
    let i = s.dormant.remove(&g)?;
    let b = &s.blocks[i];
    if b.retired || b.followed == s.in_region(g) || b.g & !(page_size() - 1) != p {
        return None;
    }
    if !b.unchanged() {
        return None;
    }
    let len = b.size();
    s.by_g.insert(g, i);
    s.pages.entry(p).or_default().push(i);
    for (q, at) in s.blocks[i].calls_made.clone() {
        s.calls_made.entry(q).or_insert((i, at));
    }
    publish_block(&s.blocks[i]);
    if let Some(c) = s.cache.as_mut() {
        c.live += len;
        c.garbage -= len;
    }
    REVIVED.fetch_add(1, Ordering::Relaxed);
    link_waiting(s, i);
    Some(i)
}

/// Link the direct ways out of new block `i` to their targets' translations
/// where there are ones, and the ways out waiting for `i`'s program address
/// to it: as a way out's first run would, without its trap.
fn link_waiting(s: &mut State, i: usize) {
    let g = s.blocks[i].g;
    // Its direct ways out ([`Block::jumps`]), by index: linking changes
    // the blocks.
    for k in 0..s.blocks[i].words.len() {
        let Packed::Out { to, exit: 0, .. } = s.blocks[i].words[k] else { continue };
        let at = s.blocks[i].addr(k);
        match s.by_g.get(&to).copied() {
            Some(j) => link_site(s, i, at, j),
            None => wait(&mut s.waiting, to, (at, i)),
        }
    }
    if let Some(w) = s.waiting.remove(&g) {
        let (first, more) = match w {
            Waiting::One(at, from) => (Some((at, from)), Vec::new()),
            Waiting::Many(v) => (None, v),
        };
        for (at, from) in first.into_iter().chain(more) {
            link_site(s, from, at, i);
        }
    }
}

/// The direct ways out waiting for one program address to be translated
/// ([`State::waiting`]): their addresses and blocks. Mostly one, kept
/// without a vector of its own.
enum Waiting {
    One(u64, usize),
    Many(Vec<(u64, usize)>),
}

/// Note way out `w` (its address and block) waiting for program address
/// `g`.
fn wait(waiting: &mut AddrMap<Waiting>, g: u64, w: (u64, usize)) {
    match waiting.entry(g) {
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(Waiting::One(w.0, w.1));
        }
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let e = e.get_mut();
            match e {
                Waiting::One(at, from) => *e = Waiting::Many(vec![(*at, *from), w]),
                Waiting::Many(v) => v.push(w),
            }
        }
    }
}

/// Link way out `at` (a direct one, still into fwe) to block `j`, if it
/// is in a live translation and the branch reaches.
fn link_site(s: &mut State, from: usize, at: u64, j: usize) {
    // A block dropped (its program address another's, or none's) is left
    // as it is: nothing new leads into it.
    if s.by_g.get(&s.blocks[from].g) != Some(&from) {
        return;
    }
    let to = s.blocks[j].g;
    let word = s.blocks[from].word_at(at);
    let Some(Word::Out { exit: Exit::Jump(x), saved, x18, .. }) = word else { return };
    if x != to || !unlinked(at) || s.blocks[from].retired || s.blocks[j].retired {
        return;
    }
    if s.link(from, at, entered(s, j, saved, x18)) {
        s.blocks[j].linked.push(at);
    }
}

/// Whether way out `at` still leads into fwe (its first word as made: not
/// linked, or unlinked again).
fn unlinked(at: u64) -> bool {
    // SAFETY: a word of fwe's code cache, readable.
    matches!(unsafe { (at as *const u32).read() }, SAVE | OUT)
}

/// The conditional branch whose taken way is way out `at` of block `b`.
fn conditional(b: &Block, at: u64) -> Option<u64> {
    let k = b.index(at)?;
    match b.word(k) {
        Some(Word::Out { cond, .. }) if cond != 0 => Some(b.addr(k - usize::from(cond))),
        _ => None,
    }
}

/// Conditional branch `w` at `at` (`b.cond`, `cbz`, `cbnz`, `tbz`,
/// `tbnz`) made to branch to `to`, if that reaches.
fn retarget(w: u32, at: u64, to: u64) -> Option<u32> {
    let bits = if (w >> 25) & 0x3f == 0b011011 { 14 } else { 19 };
    let off = (to as i64).wrapping_sub(at as i64) >> 2;
    let half = 1i64 << (bits - 1);
    if !(-half..half).contains(&off) {
        return None;
    }
    let field = ((1u32 << bits) - 1) << 5;
    Some((w & !field) | (((off as u32) << 5) & field))
}

/// Note the other mappings of the file page that program page `p` maps,
/// as code is first translated from it: a flush through one of them is a
/// flush of `p`'s code ([`flushed`]); a JIT that maps its code twice may
/// flush either.
fn note_aliases(s: &mut State, p: u64) {
    if s.pages.contains_key(&p) {
        return;
    }
    // Set before the record is read: a mapping made since is noted by
    // [`mapped`], which sees it set.
    ANY_OBJECTS.store(true, Ordering::SeqCst);
    let rec = fwe_kernel::maps::record();
    if let Some(k) = shared_page(&rec, p) {
        let others: Vec<u64> =
            rec.areas().iter().filter_map(|a| alias_in(a, k)).filter(|&q| q != p).collect();
        drop(rec);
        s.objects.entry(k).or_default().insert(p);
        s.object_of.insert(p, k);
        for q in others {
            s.aliases.entry(q).or_default().insert(p);
        }
    }
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
/// pages of it that map a file's page code was translated from are noted
/// as that code's other mappings ([`note_aliases`]).
pub fn mapped(addr: u64, len: u64) {
    // Most programs map no file shared and run code from it: no lock.
    if !ANY_OBJECTS.load(Ordering::SeqCst) {
        return;
    }
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
    }
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
    exit_stub(rw, rx);
    let n = CHUNK_COUNT.load(Ordering::Relaxed) as usize;
    assert!(n < MAX_CHUNKS, "fwe's code cache is full");
    CHUNK_RX[n].store(rx, Ordering::Relaxed);
    CHUNK_COUNT.store(n as u64 + 1, Ordering::Release);
    let mut k = Chunk { rw, rx, hot: 0, cold: 0, end: 0, retired: false };
    k.empty();
    k
}

/// Write the exit stub at the start of the chunk whose views are `rw` and
/// `rx`: `ldr x17, #8; br x17` and the exit gate's address. Each way out
/// of the chunk's blocks branches there, `x16` its own address
/// ([`gate_out`]); the stub stays while the chunk does.
fn exit_stub(rw: u64, rx: u64) {
    let gate = crate::gate::exit_address();
    let words = [0x5800_0000 | (2 << 5) | 17, GO, gate as u32, (gate >> 32) as u32];
    for (k, w) in words.into_iter().enumerate() {
        // SAFETY: the start of the chunk's writable view, fresh.
        unsafe { ((rw + 4 * k as u64) as *mut u32).write(w) };
    }
    // SAFETY: the chunk's executable view, mapped.
    unsafe { crate::prepare::flush_icache(rx, EXIT_STUB) };
}

/// The code cache.
fn new_cache() -> Cache {
    Cache { chunks: vec![new_chunk()], current: 0, live: 0, garbage: 0, flushes: 0 }
}

/// The block that branches from the cache to `to`, code not translated,
/// for a way out (with the program's `x16` and `x17` saved, `saved`: they
/// are taken back first): a branch to `to`, or where that does not reach,
/// `to` loaded
/// into `x16` and `br x16`, as a linker's veneer does (AAPCS64 lets one
/// clobber `x16` and `x17` on a direct branch to other code). A block, so
/// emptying the cache keeps it while a thread is in it, and unlinks the
/// branches to it when it goes.
fn veneer(s: &mut State, to: u64, saved: bool) -> usize {
    if let Some(&i) = s.veneers.get(&(to, saved)) {
        return i;
    }
    // At most a restore, an address made in four words and `br`.
    let (_, at, _) = cache_next(s, 4 * (RESTORE_WORDS as u64 + 5), 0);
    let mut words = if saved { restore_words().to_vec() } else { Vec::new() };
    if let Some(b) = rewrite::branch(at + 4 * words.len() as u64, to) {
        words.push(b);
    } else {
        materialize(16, to, &mut words);
        words.push(0xd61f_0200); // br x16
    }
    let (t, _) = emit(s, &words, &[]);
    let len = 4 * words.len() as u64;
    s.cache.as_mut().expect("a code cache").live += len;
    let i = s.blocks.len();
    // A thread stopped in it goes on at `to`, its x16 the veneer's once
    // it loads it.
    let mut info = vec![Packed::At(0); words.len()];
    if saved {
        info[..RESTORE_WORDS].fill(Packed::Saved(0));
    }
    s.blocks.push(Block {
        g: to,
        t,
        words: info,
        linked: Vec::new(),
        len,
        cold: 0,
        cold_len: 0,
        body: t,
        unsaved: t,
        x18: 0,
        retired: false,
        source: Vec::new(),
        followed: true,
        pads: Vec::new(),
        calls_made: Vec::new(),
        notes: Notes::default(),
    });
    s.by_t.insert(t, i);
    s.veneers.insert((to, saved), i);
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

/// Where the next block, `hot` and `cold` bytes, goes: in the current
/// chunk while it has room for it ([`Chunk::fit`]); else, the cache is
/// emptied where at least half of it is dropped translations, and the block
/// goes in a chunk with room, or a new one. Its chunk's exit stub, and its
/// parts' addresses.
fn cache_next(s: &mut State, hot: u64, cold: u64) -> (u64, u64, u64) {
    // The first segment holds the exit stub; each part may be aligned.
    assert!(
        EXIT_STUB + hot + cold + 8 <= segment(),
        "a block of {hot} and {cold} bytes, larger than a segment"
    );
    let room = |k: &Chunk| !k.retired && k.fit(hot, cold).is_some();
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
    let (h, c, _) = k.fit(hot, cold).expect("room for the block");
    (k.rx, k.rx + h, k.rx + c)
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
        s.by_t
            .range(..=at)
            .next_back()
            .is_some_and(|(_, &i)| old[i].index(at).is_some() && pinned[i])
    };
    for &i in s.by_g.values() {
        unpublish_block(&old[i]);
    }
    // No branch from a retired block leads into the room had back.
    for b in &old {
        for &at in &b.linked {
            if in_pinned(s, at)
                && let Some((_, &f)) = s.by_t.range(..=at).next_back()
            {
                s.unlink(&old[f], at);
            }
        }
    }
    let mut kept = 0;
    s.by_t.clear();
    s.by_g.clear();
    s.pages.clear();
    for (i, b) in old.into_iter().enumerate() {
        if pinned[i] {
            kept += b.size();
            index_parts(&mut s.by_t, &b, s.blocks.len());
            s.blocks.push(Block { linked: Vec::new(), retired: true, ..b });
        }
    }
    // Nothing is translated from the program's pages now.
    s.objects.clear();
    s.object_of.clear();
    s.waiting.clear();
    s.dormant.clear();
    s.veneers.clear();
    s.calls_made.clear();
    s.aliases.clear();
    let size = chunk_size();
    let blocks = &s.blocks;
    let c = s.cache.as_mut().expect("a code cache");
    for k in c.chunks.iter_mut() {
        k.retired = blocks.iter().any(|b| (k.rx..k.rx + size).contains(&b.t));
        if !k.retired {
            k.empty();
        }
    }
    c.live = 0;
    c.garbage = kept;
    c.flushes += 1;
    FLUSHES.fetch_add(1, Ordering::Relaxed);
    // The ways out unlinked seen as such before the others go on.
    s.sync_patched();
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

/// Write a block's `hot` and `cold` words in the current chunk where it
/// has room for them ([`Chunk::fit`]): their executable addresses.
fn write(c: &mut Cache, hot: &[u32], cold: &[u32]) -> (u64, u64) {
    let k = &mut c.chunks[c.current];
    let (h, cl) = (4 * hot.len() as u64, 4 * cold.len() as u64);
    let (at, at_cold, end) = k.fit(h, cl).expect("a block placed where cache_next made room");
    for (off, words) in [(at, hot), (at_cold, cold)] {
        for (i, &w) in words.iter().enumerate() {
            // SAFETY: inside the chunk's writable view.
            unsafe { ((k.rw + off + 4 * i as u64) as *mut u32).write(w) };
        }
    }
    k.hot = (at + h + 7) & !7;
    k.cold = at_cold;
    k.end = end;
    (k.rx + at, k.rx + at_cold)
}

/// Write a block's `hot` and `cold` words in the cache ([`write`]), synced
/// for instruction fetch with the words patched since the last sync
/// ([`State::sync_patched`]), once for all: their executable addresses.
/// (Room is written again only once the cache is emptied, which syncs the
/// ways out it unlinks.)
fn emit(s: &mut State, hot: &[u32], cold: &[u32]) -> (u64, u64) {
    let (t, cold_t) = write(s.cache.as_mut().expect("a code cache"), hot, cold);
    let line = 4 << (crate::hwcap::CTR_EL0 & 15);
    let mut patched = s.patched.borrow_mut();
    for (at, n) in [(t, hot.len()), (cold_t, cold.len())] {
        if n > 0 {
            patched.extend((at & !(line - 1)..at + 4 * n as u64).step_by(line as usize));
        }
    }
    drop(patched);
    s.sync_patched();
    (t, cold_t)
}

/// The program's instruction at `g`, read from its memory, or from the
/// words [`with_snapshot`] holds there while it translates.
fn read(g: u64) -> u32 {
    let (base, words, n) = SNAPSHOT.with(std::cell::Cell::get);
    if g >= base && g < base + 4 * n as u64 {
        // SAFETY: inside the words `with_snapshot` keeps alive while it
        // runs.
        return unsafe { words.add(((g - base) / 4) as usize).read() };
    }
    // SAFETY: the program's code, mapped readable (it runs by translation).
    unsafe { (g as *const u32).read() }
}

thread_local! {
    /// The program's words [`read`] reads where it is asked for them: from
    /// an address, so many ([`with_snapshot`]).
    static SNAPSHOT: std::cell::Cell<(u64, *const u32, usize)> =
        const { std::cell::Cell::new((0, std::ptr::null(), 0)) };
}

/// The program's words from `g` as far as a block made there reads them:
/// up to its page's end.
fn snapshot(g: u64) -> Vec<u32> {
    let page = page_size();
    let n = (BLOCK_INSNS + 16).min((((g | (page - 1)) + 1 - g) / 4) as usize);
    (0..n as u64).map(|k| read(g + 4 * k)).collect()
}

/// `work`, with [`read`] taking the program's words from `g` from `words`:
/// a translation made from one look at them, which another thread may be
/// changing meanwhile.
fn with_snapshot<R>(g: u64, words: &[u32], work: impl FnOnce() -> R) -> R {
    SNAPSHOT.with(|c| c.set((g, words.as_ptr(), words.len())));
    let r = work();
    SNAPSHOT.with(|c| c.set((0, std::ptr::null(), 0)));
    r
}

/// A block's translation ([`translate`]).
struct Made {
    /// Its words, hot and cold, what each stands for (to be finished where
    /// they are placed) and its calls.
    room: Room,
    /// Its saved, unsaved and `x18` entries ([`Block`]), as indexes of its
    /// hot words (the last 0 if none).
    entry: usize,
    unsaved: usize,
    x18: usize,
    /// The end of the program's words it read.
    end: u64,
    /// The words of its second pass, for its entry with the program's own
    /// `x16` and `x17`, if it has one; and its counters, if blocks count
    /// their runs ([`jitcount`]).
    second: Option<usize>,
    counters: Option<u64>,
}

/// The room a block is made in: its words ([`Asm`]) and calls ([`Calls`]).
/// A thread keeps it for the next block ([`ROOM`]).
struct Room {
    asm: Asm<Word>,
    c: Calls,
}

thread_local! {
    /// The room a thread makes blocks in ([`translate`], [`place`]), kept
    /// for the next: made afresh, its words and the rest grew a push at a
    /// time, copied at each doubling, and were let go each block.
    static ROOM: std::cell::Cell<Option<Room>> = const { std::cell::Cell::new(None) };
}

/// Translate the block at program address `g`, to be placed at `t`: its
/// words, and what each stands for. A block ends at its page's end, so it
/// is made from that page alone.
fn translate(g: u64, t: u64, followed: bool, known: &[(u64, u64)]) -> Made {
    // A lookup that read an entry's address and translation at once, and a
    // direct branch with the program's `x16` and `x17` saved in their
    // slots (as a lookup saves them), enter at the saved entry ([`CHECK_WORDS`]
    // in). A lookup that read them apart enters at the check, the target
    // in `x16`, which goes on to the saved entry if the target is this
    // block's (an entry can be taken over as such a lookup reads it).
    let mut room = ROOM.take().unwrap_or_else(|| Room { asm: Asm::new(), c: Calls::default() });
    room.c.clear();
    room.c.known.extend_from_slice(known);
    let Room { asm: a, c } = &mut room;
    a.clear();
    let check = Word::Lookup { g, link: None, to: Some(16) };
    let address = materialized(17, g).count();
    a.extend(H, std::iter::repeat_n(NOP, CHECK_WORDS - 2 - address), check);
    a.extend(H, materialized(17, g), check);
    a.push(H, CHECK, check);
    let wrong = a.label();
    a.branch(H, MISS, Field::Imm19, wrong, check);
    debug_assert_eq!(a.len(H), CHECK_WORDS);
    // Counting its runs ([`jitcount`]): its saved entry's first, its
    // other entry's after a save of the program's `x16` and `x17` there.
    let counting = jitcount::counting();
    let counters = counting.then(|| jitcount::units(2));
    if let Some(at) = counters {
        a.extend(H, counter(at), Word::Saved(g));
    }
    let Body { end, restore, x18 } = body_of(g, t, followed, true, None, c, a);
    // The wrong block's way out.
    a.bind(wrong, C);
    a.push(C, EXIT, Word::Out { g, exit: Exit::Retry, saved: true, x18: false, cond: 0 });
    // A direct branch with the program's own registers, and fwe going on
    // from a trap, enter where the block takes them back; if it does not
    // at once, at its words up to there made again with them in their
    // registers. Where those words name x18, which the saved ones keep in
    // x17 (loaded once, [`load_x18`]) and these would load and store at
    // each use, the entry saves x16 and x17 and goes on into the saved
    // words instead.
    // (Counting, every such entry is made apart, to count its runs.)
    let mut second = None;
    let unsaved = match restore {
        Some((at, k)) if at == g && !counting => k + RESTORE_WORDS,
        _ if x18.is_some() => {
            let start = a.len(H);
            push_save(a, H, Word::At(g), g);
            let entry = a.label_at(Pos::hot(CHECK_WORDS));
            a.branch(H, B, Field::Imm26, entry, Word::Saved(g));
            start
        }
        _ => {
            let start = a.len(H);
            if let Some(at) = counters {
                push_save(a, H, Word::At(g), g);
                a.extend(H, counter(at + 8), Word::Saved(g));
                push_restore(a, H, Word::Saved(g));
            }
            body_of(g, t, followed, false, restore, c, a);
            second = Some(a.len(H) - start);
            start
        }
    };
    // Each conditional branch's distance back from its taken way, in the
    // block's one run of words.
    for &(out, at) in &c.taken {
        let back = a.flat(out) - a.flat(at);
        if let Word::Out { cond, .. } = a.info_mut(out) {
            *cond = u16::try_from(back).expect("a taken way within 2^16 words of its branch");
        }
    }
    // Counting, a link enters at its saved entry, never past its load of
    // `x18`, to count the run.
    let x18 = if counting { 0 } else { x18.unwrap_or(0) };
    Made { room, entry: CHECK_WORDS, unsaved, x18, end, second, counters }
}

/// The words adding 1 to the counter at `at` ([`jitcount::units`]), with
/// the program's `x16` and `x17` saved: `stadd`, atomic.
fn counter(at: u64) -> impl Iterator<Item = u32> {
    materialized(16, at).chain([0xd280_0031, 0xf831_021f]) // mov x17, #1; stadd x17, [x16]
}

/// A block's calls as [`body_of`] makes them: those made already in other
/// blocks' words (`known`: program address, words), where its own return,
/// and what it makes: ways back after its calls' `bl`s ([`RETS`]: return
/// address, word index), calls made in its own first words (program
/// address, word index, and whether `x18` is held in `x17` there,
/// [`load_x18`]), the lookups of its branches through a register made in
/// its first words with the program's `x16` and `x17` saved (program
/// address, word index), and ways out into known ones (word index, program
/// address, words). A call's words, and those lookups, are entered with
/// the program's `x16` and `x17` saved. Word indexes are of the hot words
/// ([`Asm`]). And its conditional branches' taken ways (way out, branch);
/// where each of its instructions' words begin, as their program address,
/// word index, whether the program's `x16` and `x17` are saved there and
/// whether its `x18` is held in `x17`; and its words out of line, made
/// after the rest ([`Side`]).
#[derive(Default)]
struct Calls {
    known: Vec<(u64, u64)>,
    calls: Vec<u64>,
    pads: Vec<(u64, usize)>,
    made: Vec<(u64, u64, bool)>,
    lookups: Vec<(u64, usize)>,
    joins: Vec<(usize, u64, u64)>,
    taken: Vec<(Pos, Pos)>,
    entries: Vec<(u64, usize, bool, bool)>,
    sides: Vec<Side>,
}

impl Calls {
    /// Emptied for another block, their room kept.
    fn clear(&mut self) {
        let Calls { known, calls, pads, made, lookups, joins, taken, entries, sides } = self;
        known.clear();
        calls.clear();
        pads.clear();
        made.clear();
        lookups.clear();
        joins.clear();
        taken.clear();
        entries.clear();
        sides.clear();
    }
}

/// The instructions of the block at program address `g`, translated into
/// `a` (the block placed at `t`); `followed`, code fwe prepared in place
/// (a library's), read as the program wrote it ([`Body`]).
///
/// The program's `x16` and `x17` stay on the stack, where the way in left
/// them (if `saved`), until an instruction needs them or `sp`
/// ([`keeps_saved`]): they are restored there, and saved again at a way
/// out or a lookup. A save and the restore of what it saved cost a store's
/// forwarding to the load, some cycles; through a loop of lookups whose
/// code never needs them, each lookup would wait for the last's. Made
/// with them in their registers (not `saved`), the words go on from
/// `merge`'s address into the block made the other way, as they are there,
/// and at a call it makes or a branch through a register it looks up saved
/// (noted in `c` as the words were made saved): a lookup saves them first
/// either way.
fn body_of(
    g: u64,
    t: u64,
    followed: bool,
    mut saved: bool,
    merge: Option<(u64, usize)>,
    c: &mut Calls,
    a: &mut Asm<Word>,
) -> Body {
    let page = page_size();
    // The words made first, with `x16` and `x17` saved.
    let first = saved;
    let mut pc = g;
    let mut sides = std::mem::take(&mut c.sides);
    let mut restore = None;
    let mut ended = false;
    // The program's x18 in x17, while x16 and x17 are saved: whether it
    // was written since it was loaded.
    let mut x18 = None;
    // Loaded first where the words up to the first restore or branch use
    // it: a way out holding it enters there past the load, and a loop
    // that keeps a value in it loads it from its slot only once.
    let mut x18_entry = None;
    if saved && uses_x18_first(g, followed) {
        load_x18(g, a);
        x18 = Some(false);
        x18_entry = Some(a.len(H));
    }
    // What the code after each instruction writes before reading it, for
    // scratch registers ([`x18_beside`]): made for a block naming `x18`.
    let mut quiet = None;
    // How the words end, for the counts ([`jitcount::ENDED`]).
    let mut end = jitcount::END_LENGTH;
    for _ in 0..BLOCK_INSNS {
        if let Some((at, k)) = merge
            && at == pc
        {
            end = jitcount::END_JOIN;
            // Into the other words: before their restore while saved (x18
            // back in its slot, as there).
            put_x18(&mut x18, pc, a);
            let to = a.label_at(Pos::hot(if saved { k } else { k + RESTORE_WORDS }));
            a.branch(H, B, Field::Imm26, to, if saved { Word::Saved(pc) } else { Word::At(pc) });
            ended = true;
            break;
        }
        // Where its words begin, and as what, for a conditional branch of
        // the block's to come to.
        c.entries.push((pc, a.len(H), saved, x18.is_some()));
        let w = if followed { crate::prepare::original(pc, read(pc)) } else { read(pc) };
        // A call (`bl`, `blr`) is made once, with one way back after its
        // `bl` where its return comes ([`RETS`]): where it is made already,
        // in another block's words or in this one's made the other way, the
        // words go on there, entered as a call's words are after their save:
        // `x18` in its slot (or loaded into `x17` where those words hold it
        // there) and the program's `x16` and `x17` saved.
        let call = w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000;
        let known = c.known.iter().find(|k| k.0 == pc).filter(|_| pc != g);
        let made = c.made.iter().find(|m| m.0 == pc).filter(|_| !first);
        if call && let Some((at, held)) = known.map(|k| (k.1, false)).or(made.map(|m| (m.1, m.2))) {
            put_x18(&mut x18, pc, a);
            if !saved {
                push_save(a, H, Word::At(pc), pc);
            }
            if held {
                load_x18(pc, a);
            }
            end = jitcount::END_JOIN;
            if known.is_some() {
                c.joins.push((a.len(H), pc, at));
                gate_out(pc, Exit::Join(pc), true, false, H, a);
            } else {
                let to = a.label_at(Pos::hot(at as usize));
                a.branch(H, B, Field::Imm26, to, Word::Saved(pc));
            }
            ended = true;
            break;
        }
        // A branch through a register (`br`, `ret`), looked up with them
        // saved: made with them in their registers, saved and on into
        // that lookup.
        if matches!(w & 0xffff_fc1f, 0xd61f_0000 | 0xd65f_0000) {
            if first && saved {
                put_x18(&mut x18, pc, a);
                c.lookups.push((pc, a.len(H)));
            } else if let Some(&(_, k)) = c.lookups.iter().find(|l| l.0 == pc).filter(|_| !first) {
                if !saved {
                    push_save(a, H, Word::At(pc), pc);
                }
                let to = a.label_at(Pos::hot(k));
                a.branch(H, B, Field::Imm26, to, Word::Saved(pc));
                end = jitcount::END_JOIN;
                ended = true;
                break;
            }
        }
        // Where the words of a call made here are entered saved: past the
        // save they begin with when made unsaved; and whether `x18` is
        // held in `x17` there.
        let call_at = (call && first).then_some((a.len(H), saved, x18.is_some()));
        if crate::decode::may_name_x18(w) && quiet.is_none() {
            quiet = Some(overwritten_after(g, followed));
        }
        let quiet_here = quiet.as_ref().map_or(0, |q| q[((pc - g) / 4) as usize]);
        // `bl`, `blr`
        if first && (w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000) {
            c.calls.push(pc + 4);
        }
        if saved && !is_branch(w) && !keeps_saved(w, false) && in_x17(w).is_none() {
            put_x18(&mut x18, pc, a);
            x18 = None;
            // (Counting, why they are taken back, before the restore a
            // word index names.)
            if jitcount::counting() {
                let why = if crate::decode::names_x16_x17(w) {
                    jitcount::RESTORE_NAMED
                } else {
                    jitcount::RESTORE_STACK
                };
                a.extend(H, counter(jitcount::moves(why)), Word::Saved(pc));
            }
            if restore.is_none() {
                restore = Some((pc, a.len(H)));
            }
            push_restore(a, H, Word::Saved(pc));
            saved = false;
            c.entries.push((pc, a.len(H), false, false));
        }
        let pads = c.pads.len();
        ended = one(w, pc, t, quiet_here, &mut saved, &mut x18, &mut sides, &mut c.pads, a);
        if ended {
            end = match w & 0xffff_fc1f {
                0xd65f_0000 => jitcount::END_RETURN,
                0xd61f_0000 | 0xd63f_0000 => jitcount::END_REGISTER,
                _ => jitcount::END_BRANCH,
            };
        }
        // Counting, a call's way back counts its returns ([`jitcount`]),
        // `x16` and `x17` saved there.
        if jitcount::counting() && c.pads.len() > pads && c.pads[pads].1 == a.len(H) {
            let origin = if followed { jitcount::FILE } else { jitcount::GENERATED };
            let target = (w & 0xfc00_0000 == 0x9400_0000)
                .then(|| pc.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4)));
            a.extend(H, counter(jitcount::pad(origin, target)), Word::Saved(pc + 4));
        }
        if let Some((k, was, held)) = call_at {
            assert!(
                was || a.word(Pos::hot(k)) == SAVE,
                "a call made unsaved at {pc:#x} with no save first"
            );
            c.made.push((pc, (k + if was { 0 } else { SAVE_WORDS }) as u64, held));
        }
        pc += 4;
        // Ends at a branch out, or at the page's end (the next page may not
        // be the program's code).
        if ended || pc & (page - 1) == 0 {
            if !ended {
                end = jitcount::END_PAGE;
            }
            break;
        }
    }
    if first {
        jitcount::ENDED[end].fetch_add(1, Ordering::Relaxed);
        jitcount::WORDS.fetch_add((pc - g) / 4, Ordering::Relaxed);
    }
    if !ended {
        put_x18(&mut x18, pc, a);
        gate_out(pc, Exit::Jump(pc), saved, x18.is_some(), H, a);
    }
    // The taken ways of its conditional branches (out of the way, but a
    // `tbz`'s) and its direct calls' ways to their targets, after the rest.
    for side in sides.drain(..) {
        match side {
            Side::Taken { at, to: label, g, target, saved, x18 } => {
                // Into the block's own words where they hold the target with
                // the program's `x16` and `x17` as here, and need its `x18`
                // in `x17` only where it is: no way out, nor a block of its
                // own made for it.
                let inside =
                    c.entries.iter().rev().find(|e| e.0 == target && e.2 == saved && (x18 || !e.3));
                if let Some(&(_, k, ..)) = inside {
                    a.bind_at(label, Pos::hot(k));
                    continue;
                }
                // Out of the way, but a `tbz`'s (whose reach is short).
                let near = a.word(at) & 0x7e00_0000 == 0x3600_0000;
                let s = if near { H } else { C };
                a.bind(label, s);
                let out = gate_out(g, Exit::Jump(target), saved, x18, s, a);
                c.taken.push((out, at));
            }
            Side::Call { to: label, g, target, ret } => {
                a.bind(label, H);
                a.extend(H, materialized(30, ret), Word::Saved(g));
                gate_out(g, Exit::Jump(target), true, false, H, a);
            }
            Side::Lookup(tail) => lookup_tail(&tail, a),
        }
    }
    c.sides = sides;
    Body { end: pc, restore, x18: x18_entry }
}

/// What [`body_of`] made: the end of the program's words it read, where it
/// first restores the program's `x16` and `x17` (the program address, and
/// the word), and where it is entered with its `x18` loaded (the word).
struct Body {
    end: u64,
    restore: Option<(u64, usize)>,
    x18: Option<usize>,
}

/// Whether the block at `g` names `x18` before it restores the program's
/// `x16` and `x17` or branches ([`body_of`]).
fn uses_x18_first(g: u64, followed: bool) -> bool {
    let page = page_size();
    let mut pc = g;
    for _ in 0..BLOCK_INSNS {
        let w = if followed { crate::prepare::original(pc, read(pc)) } else { read(pc) };
        if in_x17(w).is_some() {
            return true;
        }
        if is_branch(w) {
            // A `cbz` or `tbz` of x18 tests it there.
            return matches!((w >> 25) & 0x3f, 0b011010 | 0b011011) && w & 0x1f == 18;
        }
        if !keeps_saved(w, false) {
            return false;
        }
        pc += 4;
        if pc & (page - 1) == 0 {
            return false;
        }
    }
    false
}

/// The program's `x18` loaded into `x17` from its slot, the thread's area
/// in `x16`, as at `pc` (its `x16` and `x17` saved).
fn load_x18(pc: u64, a: &mut Asm<Word>) {
    let slot = crate::x18_slot();
    a.extend(
        H,
        [
            rewrite::MRS_TPIDRRO | 16,
            rewrite::AND_NOT7 | (16 << 5) | 16,
            rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 17,
        ],
        Word::Saved(pc),
    );
}

/// Words of a block out of line, after the rest ([`body_of`]).
enum Side {
    /// A conditional branch's taken way: the branch at `at`, to `to`, at
    /// program address `g`, to `target`, the program's `x16` and `x17`
    /// saved there or not, and its `x18` held in `x17` or not.
    Taken { at: Pos, to: Label, g: u64, target: u64, saved: bool, x18: bool },
    /// A direct call's way to its target: the `bl` at program address `g`
    /// comes to `to`; `x30` is set to `ret`, the return address, and it
    /// goes on to `target`, `x16` and `x17` saved.
    Call { to: Label, g: u64, target: u64, ret: u64 },
    /// An indirect call's lookup past its `bl` ([`lookup`]).
    Lookup(Tail),
}

/// Whether `w` is a branch [`one`] makes from either state of `x16` and
/// `x17` (saved or the program's).
fn is_branch(w: u32) -> bool {
    w & 0x7c00_0000 == 0x1400_0000 // b, bl
        || w & 0xff00_0000 == 0x5400_0000 // b.cond, bc.cond
        || matches!((w >> 25) & 0x3f, 0b011010 | 0b011011) // cbz, cbnz, tbz, tbnz
        || matches!(w & 0xffff_fc1f, 0xd61f_0000 | 0xd65f_0000 | 0xd63f_0000) // br, ret, blr
}

/// Whether the program's instruction `w` runs as it is (or as [`one`]
/// stands for it with its own registers alone) with the program's `x16`
/// and `x17` saved in their slots: it names neither (nor `x18`, unless
/// `x18`), and needs no stack of fwe's. Where a field may be a register,
/// it is taken for one.
fn keeps_saved(w: u32, x18: bool) -> bool {
    names_none(w, 1 << 16 | 1 << 17 | if x18 { 0 } else { 1 << 18 }, false)
}

/// Whether the program's instruction `w` names none of the general
/// registers in `regs` (a bit each), nor `sp` where `sp` counts, and needs
/// no stack of fwe's ([`keeps_saved`]). Where a field may be a register,
/// it is taken for one.
fn names_none(w: u32, regs: u32, sp: bool) -> bool {
    let reg = |shift: u32| (w >> shift) & 31;
    let named = |fields: &[u32]| fields.iter().any(|&f| reg(f) != 31 && regs & 1 << reg(f) != 0);
    let (rd, rn) = (reg(0), reg(5));
    let op0 = (w >> 25) & 0xf;
    match op0 {
        // Loads and stores: `sp` as the base. A pair names a second
        // register at 10; the forms with an immediate offset name no other.
        0b0100 | 0b0110 | 0b1100 | 0b1110 => {
            // Literal loads: into a vector register, through x16.
            if w & 0x3b00_0000 == 0x1800_0000 {
                return (w >> 26) & 1 == 0 && !named(&[0]);
            }
            if sp && rn == 31 {
                return false;
            }
            if (w >> 27) & 7 == 0b101 {
                !named(&[0, 5, 10])
            } else if (w >> 24) & 0x3b == 0x39 || ((w >> 24) & 0x3b == 0x38 && (w >> 21) & 1 == 0) {
                !named(&[0, 5])
            } else {
                !named(&[0, 5, 10, 16])
            }
        }
        // Data processing with an immediate: `sp` in add and subtract
        // (and with tags) and in logical operations that set no flags.
        0b1000 | 0b1001 => {
            let not_s = (w >> 29) & 1 == 0;
            let names_sp = match (w >> 23) & 7 {
                0b010 => rn == 31 || (rd == 31 && not_s),
                0b011 => rn == 31 || rd == 31,
                0b100 => rd == 31 && (w >> 29) & 3 != 3,
                _ => false,
            };
            !(sp && names_sp) && !named(if (w >> 23) & 7 == 0b111 { &[0, 5, 16] } else { &[0, 5] })
        }
        // Data processing on registers: `sp` in add and subtract with an
        // extended register, and (taken as such) in the one- and two-source
        // operations (the tag ones).
        0b0101 | 0b1101 => {
            let rm = reg(16);
            if (w >> 24) & 0x1f == 0b01011 && (w >> 21) & 1 == 1 {
                let names_sp = rn == 31 || (rd == 31 && (w >> 29) & 1 == 0);
                !(sp && names_sp) && !named(&[0, 5, 16])
            } else if (w >> 21) & 0xff == 0b1101_0110 {
                let names_sp = rd == 31 || rn == 31 || rm == 31;
                !(sp && names_sp) && !named(&[0, 5, 16])
            } else if (w >> 24) & 0x1f == 0b11011 {
                !named(&[0, 5, 10, 16])
            } else {
                !named(&[0, 5, 16])
            }
        }
        // Floating point and vectors: general registers only in
        // conversions and copies.
        0b0111 | 0b1111 => {
            let convert = (w >> 24) & 0x5f == 0x1e && (w >> 21) & 1 == 1 && (w >> 10) & 0x3f == 0;
            let copy = w & 0x9fe0_8400 == 0x0e00_0400;
            !((convert || copy) && named(&[0, 5]))
        }
        // System: hints and barriers.
        0b1010 | 0b1011 => w & 0xffff_f01f == 0xd503_201f || w & 0xffff_f01f == 0xd503_301f,
        _ => false,
    }
}

/// The program's instruction `w`, which names `x18`, made to name `x17`
/// instead, and whether it writes it: where it runs with the program's
/// `x16` and `x17` saved, as [`keeps_saved`] says but for `x18`, and every
/// field naming `x18` is known ([`crate::decode::operands`]; not `casp`,
/// whose pair of registers must be even and consecutive).
fn in_x17(w: u32) -> Option<(u32, bool)> {
    if is_branch(w) || crate::decode::x18_casp(w) || !keeps_saved(w, true) {
        return None;
    }
    x18_as(w, 17).map(|(renamed, _, writes)| (renamed, writes))
}

/// The program's instruction `w` made to name `to` where it names `x18`,
/// and whether it reads and writes `x18` there; `None` if it does not
/// name it, or names it in a field not known ([`crate::decode::operands`]).
fn x18_as(w: u32, to: u32) -> Option<(u32, bool, bool)> {
    if !crate::decode::may_name_x18(w) {
        return None;
    }
    let (mut reads, mut writes, mut renamed) = (false, false, w);
    for f in crate::decode::operands(w)? {
        if (w >> f.shift) & 31 == 18 {
            reads |= f.read;
            writes |= f.write;
            renamed = (renamed & !(31 << f.shift)) | (to << f.shift);
        }
    }
    (reads || writes).then_some((renamed, reads, writes))
}

/// `stur xN, [sp, #-16]`, `stp xN, xM, [sp, #-16]` and the loads back:
/// registers kept below `sp` without moving it ([`x18_beside`]).
const STUR_SP_M16: u32 = 0xf81f_03e0;
const LDUR_SP_M16: u32 = 0xf85f_03e0;
const STP_SP_M16: u32 = 0xa93f_03e0;
const LDP_SP_M16: u32 = 0xa97f_03e0;

/// The words standing for the program's instruction `w`, which names
/// `x18` but not `sp` (nor needs a stack), with the program's `x16` and
/// `x17` in their registers; `quiet`, the registers the code after it
/// writes before it reads them ([`overwritten_after`]). One or two
/// scratch registers are kept below `sp` without moving it (fwe's signal
/// handlers run on a stack of their own), so no chain of updates of `sp`
/// runs through them, and are ones the code after it writes before it
/// reads them where it has such, so nothing waits
/// for them to be loaded back. The first holds `x18`'s value (from its
/// slot, the thread's area found through it), the second, where `w`
/// writes `x18`, the thread's area to store it back. With the index of
/// `w`'s stand-in among them: before it, the words are undone; after it,
/// finished ([`undo`], [`finish`]).
fn x18_beside(w: u32, quiet: u32) -> Option<(Vec<u32>, usize)> {
    if is_branch(w) || crate::decode::x18_casp(w) || !names_none(w, 0, true) {
        return None;
    }
    let mut used = 1u32 << 18 | 1 << 31;
    for f in crate::decode::operands(w)? {
        used |= 1 << ((w >> f.shift) & 31);
    }
    let pick = |used: u32| {
        let free = !used;
        if free & quiet != 0 { (free & quiet).trailing_zeros() } else { free.trailing_zeros() }
    };
    let s1 = pick(used);
    let (renamed, reads, writes) = x18_as(w, s1)?;
    let slot = (crate::x18_slot() / 8) << 10;
    let mut words;
    let main;
    if writes {
        let s2 = pick(used | 1 << s1);
        words = vec![
            STP_SP_M16 | s2 << 10 | s1,
            rewrite::MRS_TPIDRRO | s2,
            rewrite::AND_NOT7 | s2 << 5 | s2,
        ];
        if reads {
            words.push(rewrite::LDR_UIMM | slot | s2 << 5 | s1);
        }
        main = words.len();
        words.extend([
            renamed,
            rewrite::STR_UIMM | slot | s2 << 5 | s1,
            LDP_SP_M16 | s2 << 10 | s1,
        ]);
    } else {
        words = vec![
            STUR_SP_M16 | s1,
            rewrite::MRS_TPIDRRO | s1,
            rewrite::AND_NOT7 | s1 << 5 | s1,
            rewrite::LDR_UIMM | slot | s1 << 5 | s1,
        ];
        main = words.len();
        words.extend([renamed, LDUR_SP_M16 | s1]);
    }
    Some((words, main))
}

/// For each instruction from `g` to its page's end (as far as a block
/// and a little past it), the general registers the code after it writes
/// before it reads them, on its way on past conditional branches up to
/// another branch or an instruction [`crate::decode::operands`] does not
/// know: scratch registers whose values nothing soon waits for. Each
/// instruction is decoded once, the masks made from the last back.
fn overwritten_after(g: u64, followed: bool) -> Vec<u32> {
    let page = page_size();
    let n = (BLOCK_INSNS + 16).min((((g | (page - 1)) + 1 - g) / 4) as usize);
    // What each instruction reads and writes, or none where the way on
    // stops.
    let effect = |at: u64| -> Option<(u32, u32)> {
        let w = if followed { crate::prepare::original(at, read(at)) } else { read(at) };
        if w & 0xff00_0000 == 0x5400_0000
            || w & 0xffff_f01f == 0xd503_201f
            || w & 0xffff_f01f == 0xd503_301f
        {
            // A conditional branch (gone past), a hint or a barrier.
            return Some((0, 0));
        }
        if matches!((w >> 25) & 0x3f, 0b011010 | 0b011011) {
            return Some((1 << (w & 0x1f), 0));
        }
        if is_branch(w) || (w >> 25) & 0x7f == 0b110_1011 {
            return None;
        }
        let (mut reads, mut writes) = (0, 0);
        for f in crate::decode::operands(w)? {
            let r = 1 << ((w >> f.shift) & 31);
            if f.read {
                reads |= r;
            }
            if f.write {
                writes |= r;
            }
        }
        Some((reads, writes))
    };
    let mut quiet = vec![0u32; n];
    for k in (0..n.saturating_sub(1)).rev() {
        quiet[k] = match effect(g + 4 * (k as u64 + 1)) {
            Some((reads, writes)) => (writes | quiet[k + 1]) & !reads & !(1 << 31 | 1 << 18),
            None => 0,
        };
    }
    quiet
}

/// The program's `x18`, held in `x17` ([`one`]), written back to its slot
/// if it was changed there (`x18`: whether it was), `x16` holding the
/// thread's area that holds the slot: as at `pc`.
fn put_x18(x18: &mut Option<bool>, pc: u64, a: &mut Asm<Word>) {
    if *x18 == Some(true) {
        let slot = crate::x18_slot();
        a.push(H, rewrite::STR_UIMM | ((slot / 8) << 10) | (16 << 5) | 17, Word::SavedX18(pc));
        *x18 = Some(false);
    }
}

/// A way out into fwe through the exit gate, in section `s` (first a save
/// of the program's `x16` and `x17` in their slots unless `saved`): `x16` the
/// way out's address, and a branch to its chunk's exit stub ([`exit_stub`],
/// [`STUB`]). A direct one is
/// linked by making its first word a branch to the target's translation,
/// entered as the way out has them ([`entered`]). Its first word's place.
fn gate_out(g: u64, exit: Exit, saved: bool, x18: bool, s: Sec, a: &mut Asm<Word>) -> Pos {
    let out = Word::Out { g, exit, saved, x18: saved && x18, cond: 0 };
    let at = if saved {
        a.push(s, OUT, out)
    } else {
        let at = push_save(a, s, out, g);
        // adr x16, <the save's first word>
        let back = (0x8_0000 - SAVE_WORDS as u32) & 0x7_ffff;
        a.push(s, 0x1000_0010 | back << 5, Word::Saved(g));
        at
    };
    a.branch(s, B, Field::Imm26, STUB, Word::Saved(g));
    at
}

/// Translate the program's instruction `w` at `pc` into `a`, the block
/// placed at `t`, recording what each word stands for; `saved`, whether
/// the program's `x16` and `x17` are in their slots (only a branch is made
/// from either state). A conditional branch goes on in the block, its
/// taken way noted in `sides`. Whether it ends the block.
#[allow(clippy::too_many_arguments)]
fn one(
    w: u32,
    pc: u64,
    t: u64,
    quiet: u32,
    saved: &mut bool,
    x18: &mut Option<bool>,
    sides: &mut Vec<Side>,
    pads: &mut Vec<(u64, usize)>,
    a: &mut Asm<Word>,
) -> bool {
    let here = |a: &Asm<Word>| t + 4 * a.len(H) as u64;
    let imm26 = || pc.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
    let imm19 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x7_ffff) << 13) as i32 >> 11));
    let imm14 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x3fff) << 18) as i32 >> 16));
    // The program's x16 and x17 saved, if they are not.
    let save = |saved: &mut bool, a: &mut Asm<Word>| {
        if !*saved {
            push_save(a, H, Word::At(pc), pc);
            if jitcount::counting() {
                a.extend(H, counter(jitcount::moves(jitcount::SAVED_AGAIN)), Word::Saved(pc));
            }
            *saved = true;
        }
    };
    // Before a branch, the program's x18 back in its slot if it is held
    // changed in x17.
    if is_branch(w) || (w >> 25) & 0x7f == 0b110_1011 || w == ISB {
        put_x18(x18, pc, a);
    }
    let changed = *x18 == Some(true);
    let at_pc = |saved: bool| match (saved, changed) {
        (true, true) => Word::SavedX18(pc),
        (true, false) => Word::Saved(pc),
        _ => Word::At(pc),
    };
    // b
    if w & 0xfc00_0000 == 0x1400_0000 {
        gate_out(pc, Exit::Jump(imm26()), *saved, x18.is_some(), H, a);
        return true;
    }
    // bl: x16 and x17 saved (as a call's words are entered, [`body_of`]),
    // a `bl` to the words that set the program's return address in x30
    // and go on to the target, out of line ([`Side`]). Its return found in
    // [`RETS`] comes back after the `bl` with `ret`, where the processor
    // predicts it: the block goes on there, with x16 and x17 saved (x17
    // no longer holding x18).
    if w & 0xfc00_0000 == 0x9400_0000 {
        save(saved, a);
        let to = a.label();
        a.branch(H, BL, Field::Imm26, to, at_pc(true));
        sides.push(Side::Call { to, g: pc, target: imm26(), ret: pc + 4 });
        pads.push((pc + 4, a.len(H)));
        *x18 = None;
        return false;
    }
    // b.cond (and bc.cond)
    if w & 0xff00_0000 == 0x5400_0000 {
        let to = a.label();
        let at = a.branch(H, w & !(0x7_ffff << 5), Field::Imm19, to, at_pc(*saved));
        sides.push(Side::Taken {
            at,
            to,
            g: pc,
            target: imm19(),
            saved: *saved,
            x18: x18.is_some(),
        });
        return false;
    }
    // cbz/cbnz, tbz/tbnz
    let family = (w >> 25) & 0x3f;
    if family == 0b011010 || family == 0b011011 {
        let (target, field, mask) = if family == 0b011010 {
            (imm19(), Field::Imm19, 0x7_ffff << 5)
        } else {
            (imm14(), Field::Imm14, 0x3fff << 5)
        };
        let rt = w & 0x1f;
        let to = a.label();
        if rt == 18 && x18.is_some() {
            // Of x18, held in x17 (back in its slot above).
            let at = a.branch(H, (w & !mask & !0x1f) | 17, field, to, Word::SavedX18(pc));
            sides.push(Side::Taken { at, to, g: pc, target, saved: true, x18: true });
            return false;
        }
        if rt == 18 {
            // Of x18: its value from its slot into x16, tested there.
            save(saved, a);
            let slot = crate::x18_slot();
            a.extend(
                H,
                [
                    rewrite::MRS_TPIDRRO | 16,
                    rewrite::AND_NOT7 | (16 << 5) | 16,
                    rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 16,
                ],
                Word::Saved(pc),
            );
            let at = a.branch(H, (w & !mask & !0x1f) | 16, field, to, Word::Saved(pc));
            sides.push(Side::Taken { at, to, g: pc, target, saved: true, x18: false });
            return false;
        }
        if matches!(rt, 16 | 17) && *saved {
            // Tested where the program has it.
            push_restore(a, H, Word::Saved(pc));
            *saved = false;
            *x18 = None;
        }
        let at = a.branch(H, w & !mask, field, to, at_pc(*saved));
        sides.push(Side::Taken { at, to, g: pc, target, saved: *saved, x18: x18.is_some() });
        return false;
    }
    // br, blr, ret
    if matches!(w & 0xffff_fc1f, 0xd61f_0000 | 0xd65f_0000 | 0xd63f_0000) {
        *x18 = None;
    }
    match w & 0xffff_fc1f {
        0xd61f_0000 | 0xd65f_0000 => {
            save(saved, a);
            let ret = w & 0xffff_fc1f == 0xd65f_0000;
            lookup(pc, (w >> 5) & 0x1f, None, ret, pads, a);
            return true;
        }
        // blr: the block goes on after the call's `bl`, where its return
        // comes back, x16 and x17 saved; the rest of the lookup out of
        // line.
        0xd63f_0000 => {
            save(saved, a);
            let tail = lookup(pc, (w >> 5) & 0x1f, Some(pc + 4), false, pads, a);
            sides.push(Side::Lookup(tail.expect("a call's lookup goes on")));
            return false;
        }
        _ => {}
    }
    if (w >> 25) & 0x7f == 0b110_1011 {
        // Another branch through a register (authenticated): no stand-in.
        a.push(H, UDF, at_pc(*saved));
        return true;
    }
    // Naming x18, run on x17 where x16 and x17 are saved: x18 loaded into
    // x17 from its slot at the first (x16 holding the thread's area that
    // holds it), and written back before a branch, a lookup or a restore.
    if *saved && let Some((renamed, writes)) = in_x17(w) {
        if x18.is_none() {
            load_x18(pc, a);
            *x18 = Some(false);
        }
        a.push(H, renamed, Word::SavedX18(pc));
        if writes {
            *x18 = Some(true);
        }
        return false;
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
            expansion(Site::X18 { insn: w }, pc, here(a), a);
        } else {
            a.extend(H, materialized(w & 0x1f, v), at_pc(*saved));
        }
        return false;
    }
    // Literal loads.
    if w & 0x3b00_0000 == 0x1800_0000 {
        let addr = imm19();
        let (v, opc, rt) = ((w >> 26) & 1, w >> 30, w & 0x1f);
        match (v, opc) {
            (0, 3) => {} // prfm: a hint, dropped
            (0, _) if rt == 18 => expansion(Site::X18 { insn: w }, pc, here(a), a),
            (0, _) => {
                let load = match opc {
                    0 => 0xb940_0000,
                    1 => 0xf940_0000,
                    _ => 0xb980_0000,
                };
                let words = materialized(rt, addr).chain([load | (rt << 5) | rt]);
                a.extend(H, words, at_pc(*saved));
            }
            (_, _) => {
                // A vector register: the address in x16, saved around it.
                let start = here(a);
                a.push(H, rewrite::PUSH | 16, Word::At(pc));
                let undo = Word::Undo { g: pc, start, of: Of::Load };
                a.extend(H, materialized(16, addr), undo);
                let load = match opc {
                    0 => 0xbd40_0000,
                    1 => 0xfd40_0000,
                    _ => 0x3dc0_0000,
                };
                a.push(H, load | (16 << 5) | rt, undo);
                a.push(H, rewrite::POP | 16, Word::Finish { g: pc, of: Of::Load });
            }
        }
        return false;
    }
    // `isb`: from here the program runs what it wrote to code before it
    // (the architecture's rule for self-modifying code). The block ends:
    // its way out goes on at the next instruction's translation, made again
    // if a write dropped it (and unlinked the way there).
    if w == ISB {
        a.push(H, w, at_pc(*saved));
        gate_out(pc, Exit::Jump(pc + 4), *saved, x18.is_some(), H, a);
        return true;
    }
    // A flush of an instruction cache line: run, and fwe told through the
    // gate, as [`crate::rewrite`]'s stub does, its way back past the
    // program's address kept after it, as a system call's is.
    let gate = crate::syscall_gate();
    if rewrite::is_ic_ivau(w) && gate != 0 {
        if here(a) % 8 != 0 {
            a.push(H, rewrite::NOP, Word::At(pc));
        }
        let stub_at = here(a);
        let site = Site::Flush { rt: w & rewrite::RT_MASK, gate };
        let words = rewrite::stub(site, 0, 0, stub_at, stub_at + 40);
        for (k, &sw) in words.iter().enumerate() {
            let i = match k {
                0..=1 => Word::At(pc),
                2..=3 => Word::Undo { g: pc, start: stub_at, of: Of::Flush },
                _ => Word::Finish { g: pc, of: Of::Flush },
            };
            a.push(H, sw, i);
        }
        a.extend(H, [pc as u32, (pc >> 32) as u32], Word::Finish { g: pc, of: Of::Flush });
        return false;
    }
    // A system call (Linux ignores `svc`'s immediate).
    if w & 0xffe0_001f == 0xd400_0001 {
        if gate == 0 {
            a.push(H, rewrite::TRAP, Word::At(pc));
        } else {
            // The stub's literal is 8-byte aligned.
            if here(a) % 8 != 0 {
                a.push(H, rewrite::NOP, Word::At(pc));
            }
            let stub_at = here(a);
            // Its way back goes past the program's address of the `svc`,
            // kept after it for the gate ([`syscall_site`]).
            let words = rewrite::stub(Site::Syscall { gate }, 0, 0, stub_at, stub_at + 40);
            for (k, &sw) in words.iter().enumerate() {
                // Before the call returns: undone (the call not made);
                // after: finished.
                let i = match k {
                    0 => Word::At(pc),
                    1..=2 => Word::Undo { g: pc, start: stub_at, of: Of::Syscall },
                    _ => Word::Finish { g: pc, of: Of::Syscall },
                };
                a.push(H, sw, i);
            }
            a.extend(H, [pc as u32, (pc >> 32) as u32], Word::Finish { g: pc, of: Of::Syscall });
        }
        return false;
    }
    // The thread pointer.
    if w & !rewrite::RT_MASK == rewrite::MRS_TPIDR {
        let rt = w & rewrite::RT_MASK;
        if rt != 31 {
            expansion(Site::ReadThreadPointer { rt }, pc, here(a), a);
        }
        return false;
    }
    if w & !rewrite::RT_MASK == rewrite::MSR_TPIDR {
        expansion(Site::WriteThreadPointer { rt: w & rewrite::RT_MASK }, pc, here(a), a);
        return false;
    }
    // x18
    if rewrite::x18_site(w) {
        if let Some((words, main)) = x18_beside(w, quiet) {
            let start = here(a);
            for (k, sw) in words.into_iter().enumerate() {
                let i = match k {
                    0 => Word::At(pc),
                    k if k > main => Word::Finish { g: pc, of: Of::X18 },
                    _ => Word::Undo { g: pc, start, of: Of::X18 },
                };
                a.push(H, sw, i);
            }
        } else {
            expansion(Site::X18 { insn: w }, pc, here(a), a);
        }
        return false;
    }
    if crate::decode::names_x18(w) {
        // A form fwe has no stand-in for.
        a.push(H, UDF, Word::At(pc));
        return true;
    }
    a.push(H, w, at_pc(*saved));
    false
}

/// An indirect branch through `x<n>` at `pc`, a call if `link` (the
/// return address), the program's `x16` and `x17` saved: its target looked
/// up in the table (the entry its bits pick, then the other of the pair:
/// [`TABLE`]); a miss goes into fwe.
///
/// The target stays in `x<n>`, where the program has it, while the entry's
/// address and translation are read at once into `x16` and `x17`, and a
/// match goes to the translation's lookup entry. Through `x16`, `x17` or
/// `x18`, or a call through `x30` (whose target the return address
/// replaces), the target is copied into `x16`, which leaves only `x17` to
/// read the entry with: its address, then its translation, which is
/// entered at its check.
///
/// A call ends in a `bl` to the rest ([`lookup_tail`]), which it returns
/// to be put out of line: the block goes on after the `bl`, where the
/// call's return comes back ([`RETS`]). A branch has the rest here.
fn lookup(
    pc: u64,
    n: u32,
    link: Option<u64>,
    ret: bool,
    pads: &mut Vec<(u64, usize)>,
    a: &mut Asm<Word>,
) -> Option<Tail> {
    let before = Word::Lookup { g: pc, link, to: None };
    let in_place = !matches!(n, 16..=18) && !(n == 30 && link.is_some());
    let cold = C;
    // Where the look in the table of translations goes: past a return's
    // first look in the table of returns, out of the way.
    let main = if ret && in_place { cold } else { H };
    // A return: first the table of returns, where a call made in a
    // translation left the way back after its `bl` ([`RETS`]), each entry
    // of the pair in turn; found, back there with `ret`, predicted. Each
    // one's miss goes past its `ret`: to the second, then to the table of
    // translations.
    if ret && in_place {
        let committed = Word::Lookup { g: pc, link: None, to: Some(n as u8) };
        let mut s = H;
        for other in [false, true] {
            a.extend(s, [index_of(n), SCALE, RETS_BASE], before);
            if other {
                a.push(s, OTHER, before);
            }
            a.extend(s, [ENTRY, key_against(n)], before);
            let next = a.label();
            a.branch(s, MISS_X16, Field::Imm19, next, before);
            a.push(s, RET_X17, committed);
            s = cold;
            a.bind(next, s);
        }
    }
    let miss = a.label();
    let to = if in_place {
        a.extend(main, [index_of(n), SCALE, BASE, ENTRY, key_against(n)], before);
        a.branch(main, MISS_X16, Field::Imm19, miss, before);
        n as u8
    } else {
        // x16: the target, from its slot (x16's, x17's or x18's).
        let (s16, s17) = crate::parked_slots();
        let slot = match n {
            16 => Some(s16),
            17 => Some(s17),
            18 => Some(crate::x18_slot()),
            _ => None,
        };
        if let Some(slot) = slot {
            let words = [
                rewrite::MRS_TPIDRRO | 16,
                rewrite::AND_NOT7 | (16 << 5) | 16,
                rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 16,
            ];
            a.extend(main, words, before);
        } else {
            a.push(main, 0xaa00_03f0 | (n << 16), before); // mov x16, xN
        }
        a.extend(main, [INDEX, SCALE, BASE, KEY, CHECK], before);
        a.branch(main, MISS, Field::Imm19, miss, before);
        a.extend(main, [INDEX, SCALE, BASE, VALUE], before);
        16
    };
    let committed = Word::Lookup { g: pc, link, to: Some(to) };
    // A target fwe does not translate has no translation in the table (0):
    // the branch is made as the program made it, every register its own.
    let outside = a.label();
    let outside_at = a.branch(main, OUTSIDE, Field::Imm19, outside, committed);
    let mut tail = Tail {
        pc,
        n,
        link,
        in_place,
        main,
        miss,
        outside,
        outside_at,
        bl: None,
        committed,
        before,
    };
    if let Some(link) = link {
        let bl = a.label();
        a.branch(main, BL, Field::Imm26, bl, committed);
        tail.bl = Some(bl);
        // Entered as a lookup enters a translation: `x16` and `x17` saved.
        assert_eq!(main, H, "a call's lookup out of the way");
        pads.push((link, a.len(H)));
        return Some(tail);
    }
    lookup_tail(&tail, a);
    None
}

/// The rest of a [`lookup`]: at `pc`, through `x<n>`, a call if `link`;
/// its first look in section `main`, its miss to `miss`, its target not
/// translated to `outside` (from its word at `outside_at`); for a call, its
/// `bl` to `bl`. Its words are made as `committed` once the target is
/// known, `before` until then.
struct Tail {
    pc: u64,
    n: u32,
    link: Option<u64>,
    in_place: bool,
    main: Sec,
    miss: Label,
    outside: Label,
    outside_at: Pos,
    bl: Option<Label>,
    committed: Word,
    before: Word,
}

/// The words of `t` past its first look (a call's `bl` comes to them):
/// on to the translation found, `x30` the return address for a call, where
/// the first look was; out of the way, the branch made as the program made
/// it where the target is not translated, the second look, the miss.
fn lookup_tail(t: &Tail, a: &mut Asm<Word>) {
    let &Tail { pc, n, link, in_place, main, miss, outside, outside_at, bl, committed, before } = t;
    let cold = C;
    if let Some(bl) = bl {
        a.bind(bl, main);
    }
    if let Some(link) = link {
        a.extend(main, materialized(30, link), committed);
    }
    if !in_place {
        a.push(main, TO_CHECK, committed);
    }
    a.push(main, GO, committed);
    // Not translated: x16 and x17 back, x30 the program's return address
    // for a call, and the program's own branch through its register (whose
    // value is the target). Through x18, which has no register to branch
    // through, or a call through x30, whose target the return address
    // would replace, fwe's trap takes it.
    let trapped = n == 18 || (n == 30 && link.is_some());
    if !trapped {
        a.bind(outside, cold);
        if let Some(link) = link {
            a.extend(cold, materialized(30, link), committed);
        }
        // (Through x16 or x17, the target is the program's own register,
        // which its slot holds while the restore takes x16.)
        let restoring = if in_place {
            committed
        } else {
            Word::Lookup { g: pc, link, to: Some(IN_SLOT + n as u8) }
        };
        push_restore(a, cold, restoring);
        // `ret xN` returns as it did; a call (its x30 set above) or a branch
        // is `br xN`.
        let ret = link.is_none() && n == 30;
        a.push(cold, if ret { 0xd65f_0000 } else { 0xd61f_0000 } | (n << 5), Word::At(pc));
    }
    // The entry the target's bits pick holds another address: the other
    // of its pair, as the first; found, on as from the first.
    a.bind(miss, cold);
    let second_miss = a.label();
    if in_place {
        a.extend(cold, [index_of(n), SCALE, BASE, OTHER, ENTRY, key_against(n)], before);
        a.branch(cold, MISS_X16, Field::Imm19, second_miss, before);
    } else {
        a.extend(cold, [INDEX, SCALE, BASE, OTHER, KEY, CHECK], before);
        a.branch(cold, MISS, Field::Imm19, second_miss, before);
        a.extend(cold, [INDEX, SCALE, BASE, OTHER, VALUE], before);
    }
    let back = a.label_at(outside_at);
    a.branch(cold, B, Field::Imm26, back, before);
    // The miss: into fwe.
    a.bind(second_miss, cold);
    if trapped {
        a.bind(outside, cold);
    }
    gate_out(pc, Exit::Reg { n, link }, true, false, cold, a);
}

/// Load the value `v` into `x<rd>` with `movz`/`movk`.
fn materialize(rd: u32, v: u64, out: &mut Vec<u32>) {
    out.extend(materialized(rd, v));
}

/// The words loading the value `v` into `x<rd>`: a `movz`, and a `movk`
/// for each other half-word not 0.
fn materialized(rd: u32, v: u64) -> impl Iterator<Item = u32> {
    let part = move |hw: u32| ((v >> (16 * hw)) & 0xffff) as u32;
    std::iter::once(rewrite::MOVZ | part(0) << 5 | rd).chain(
        (1..4u32)
            .filter(move |&hw| part(hw) != 0)
            .map(move |hw| rewrite::MOVK | (hw << 21) | (part(hw) << 5) | rd),
    )
}

/// The expansion of site `site` for the program's instruction at `pc`, as
/// [`rewrite::stub_body`] makes it, placed at `start`: it runs on into the
/// next instruction's translation.
fn expansion(site: Site, pc: u64, start: u64, a: &mut Asm<Word>) {
    let (tp, x18) = (crate::thread_pointer_slot(), crate::x18_slot());
    let words = rewrite::stub_body(site, tp, x18, pc);
    let of = if matches!(site, Site::X18 { .. }) { Of::X18 } else { Of::ThreadPointer };
    // Where the instruction itself is: undone before, finished after.
    let main = match site {
        Site::X18 { insn } => rewrite::x18_special_main(insn).or_else(|| {
            (crate::decode::x18_adr(insn).is_none() && !crate::decode::x18_ldr_literal(insn))
                .then(|| rewrite::x18_stub_main(insn))
        }),
        _ => None,
    };
    for (k, &sw) in words.iter().enumerate() {
        let i = match main {
            _ if k == 0 => Word::At(pc),
            Some(m) if k > m => Word::Finish { g: pc, of },
            _ => Word::Undo { g: pc, start, of },
        };
        a.push(H, sw, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each kind of word comes back from a placed block's packed form as
    /// it was made.
    #[test]
    fn words_packed_come_back_whole() {
        let (g0, t) = (0x0200_1976_c000, 0x1_2261_0000);
        let g = g0 + 4 * 63;
        let words = [
            Word::At(g0),
            Word::Saved(g),
            Word::SavedX18(g),
            Word::Stashed(g),
            Word::Undo { g, start: t + 4 * 70, of: Of::X18 },
            Word::Finish { g, of: Of::Flush },
            Word::Lookup { g, link: None, to: None },
            Word::Lookup { g, link: Some(g + 4), to: Some(30) },
            Word::Out { g, exit: Exit::Jump(0x5555_5555_8000), saved: true, x18: true, cond: 9 },
            Word::Out { g, exit: Exit::Retry, saved: true, x18: false, cond: 0 },
            Word::Out { g, exit: Exit::Join(g), saved: true, x18: false, cond: 0 },
            Word::Out {
                g,
                exit: Exit::Reg { n: 30, link: None },
                saved: false,
                x18: false,
                cond: 0,
            },
            Word::Out {
                g,
                exit: Exit::Reg { n: 17, link: Some(g + 4) },
                saved: true,
                x18: false,
                cond: 0,
            },
        ];
        for w in words {
            assert_eq!(Packed::of(w, g0, t).word(g0, t), w);
            // And from the bytes a kept record holds it as.
            let b = Packed::of(w, g0, t).to_bytes();
            assert_eq!(Packed::from_bytes(&b).expect("a packed word").word(g0, t), w);
        }
    }
    /// A call is made once in a block, however its words are entered (here
    /// the first with `x18` held in `x17` from its load after a branch): one
    /// way back for each return address.
    #[test]
    fn a_call_held_x18_across_made_once() {
        let g = 0x0200_1976_c000;
        // cbz x1, +8; mov x0, x18; bl +0x100; add x0, x0, #1; ret
        let mut words = vec![0xb400_0041, 0xaa1203e0, 0x9400_0040, 0x9100_0400, 0xd65f_03c0];
        // As far as a block's look ahead reads ([`snapshot`]).
        words.resize(BLOCK_INSNS + 16, 0xd65f_03c0);
        let made = with_snapshot(g, &words, || translate(g, 0, false, &[]));
        let pads = &made.room.c.pads;
        let mut rets: Vec<u64> = pads.iter().map(|p| p.0).collect();
        rets.dedup();
        assert_eq!(rets.len(), pads.len(), "pads {pads:x?}");
    }
}
