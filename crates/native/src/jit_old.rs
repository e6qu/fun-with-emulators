//! TEMPORARY: the translator as it was before the assembler, run beside
//! the new one on every block, which must make the same (phase 1 check).
#![allow(dead_code, clippy::all)]
use super::*;

/// Translate the block at program address `g`, to be placed at `t`: its
/// words, and what each stands for. A block ends at its page's end, so it
/// is made from that page alone.
pub(super) fn translate(g: u64, t: u64, followed: bool, known: &[(u64, u64)]) -> Made {
    // A lookup that read an entry's address and translation at once, and a
    // direct branch with the program's `x16` and `x17` saved below `sp`
    // (as a lookup saves them), enter at the saved entry ([`CHECK_WORDS`]
    // in). A lookup that read them apart enters at the check, the target
    // in `x16`, which goes on to the saved entry if the target is this
    // block's (an entry can be taken over as such a lookup reads it).
    let (mut out, mut info) = BUFFERS.take();
    out.clear();
    info.clear();
    materialize(17, g, &mut out);
    out.splice(0..0, std::iter::repeat_n(NOP, CHECK_WORDS - 2 - out.len()));
    out.push(CHECK);
    let wrong_at = out.len();
    out.push(MISS);
    debug_assert_eq!(out.len(), CHECK_WORDS);
    info.extend([Word::Lookup { g, link: None, to: Some(16) }; CHECK_WORDS]);
    let mut c =
        Calls { known, pads: Vec::new(), made: Vec::new(), lookups: Vec::new(), joins: Vec::new() };
    let Body { calls, end, restore, x18 } =
        body_of(g, t, followed, true, None, &mut c, &mut out, &mut info);
    // The wrong block's way out.
    let wrong = out.len();
    out[wrong_at] |= ((wrong - wrong_at) as u32) << 5;
    out.push(EXIT);
    info.push(Word::Out { g, exit: Exit::Retry, saved: true, x18: false, cond: 0 });
    // A direct branch with the program's own registers, and fwe going on
    // from a trap, enter where the block takes them back; if it does not
    // at once, at its words up to there made again with them in their
    // registers. Where those words name x18, which the saved ones keep in
    // x17 (loaded once, [`load_x18`]) and these would load and store at
    // each use, the entry saves x16 and x17 and goes on into the saved
    // words instead.
    let unsaved = match restore {
        Some((at, k)) if at == g => k + 1,
        _ if x18.is_some() => {
            let start = out.len();
            out.push(SAVE);
            info.push(Word::At(g));
            let to = CHECK_WORDS as u32;
            out.push(0x1400_0000 | (to.wrapping_sub(out.len() as u32) & 0x3ff_ffff));
            info.push(Word::Saved(g));
            start
        }
        _ => {
            let start = out.len();
            body_of(g, t, followed, false, restore, &mut c, &mut out, &mut info);
            start
        }
    };
    let x18 = x18.unwrap_or(0);
    let Calls { pads, made, joins, .. } = c;
    // Other blocks enter a call's words with `x18` in its slot.
    let calls_at = made.into_iter().filter(|m| !m.2).map(|m| (m.0, m.1)).collect();
    Made { words: out, info, entry: CHECK_WORDS, unsaved, x18, calls, end, pads, calls_at, joins }
}

/// A block's calls as [`body_of`] makes them: those made already in other
/// blocks' words (`known`: program address, words), and what it makes:
/// ways back after its calls' `bl`s ([`RETS`]: return address, word
/// index), calls made in its own first words (program address, word index,
/// and whether `x18` is held in `x17` there, [`load_x18`]), the lookups of its branches through a register
/// made in its first words with the program's `x16` and `x17` saved
/// (program address, word index), and ways out into known ones (word
/// index, program address, words). A call's words, and those lookups, are
/// entered with the program's `x16` and `x17` saved.
struct Calls<'a> {
    known: &'a [(u64, u64)],
    pads: Vec<(u64, usize)>,
    made: Vec<(u64, u64, bool)>,
    lookups: Vec<(u64, usize)>,
    joins: Vec<(usize, u64, u64)>,
}

/// The instructions of the block at program address `g`, translated onto
/// `out` (the block placed at `t`); `followed`, code fwe prepared in place
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
#[allow(clippy::too_many_arguments)]
fn body_of(
    g: u64,
    t: u64,
    followed: bool,
    mut saved: bool,
    merge: Option<(u64, usize)>,
    c: &mut Calls,
    out: &mut Vec<u32>,
    info: &mut Vec<Word>,
) -> Body {
    let page = page_size();
    // The words made first, with `x16` and `x17` saved.
    let first = saved;
    let mut pc = g;
    let mut calls = Vec::new();
    let mut sides = Vec::new();
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
        load_x18(g, out, info);
        x18 = Some(false);
        x18_entry = Some(out.len());
    }
    // What the code after each instruction writes before reading it, for
    // scratch registers ([`x18_beside`]): made for a block naming `x18`.
    let mut quiet = None;
    for _ in 0..BLOCK_INSNS {
        if let Some((at, k)) = merge
            && at == pc
        {
            // Into the other words: before their restore while saved (x18
            // back in its slot, as there).
            put_x18(&mut x18, pc, out, info);
            let to = if saved { k } else { k + 1 };
            out.push(0x1400_0000 | ((to as u32).wrapping_sub(out.len() as u32) & 0x3ff_ffff));
            info.push(if saved { Word::Saved(pc) } else { Word::At(pc) });
            ended = true;
            break;
        }
        let w = if followed { crate::prepare::original(pc, read(pc)) } else { read(pc) };
        // A call (`bl`, `blr`) is made once, with one way back after its
        // `bl` where its return comes ([`RETS`]): where it is made already, in another
        // block's words or in this one's made the other way, the words go
        // on there, entered as a call's words are after their save: `x18`
        // in its slot and the program's `x16` and `x17` saved.
        let call = w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000;
        let known = c.known.iter().find(|k| k.0 == pc).filter(|_| pc != g);
        let made = c.made.iter().find(|m| m.0 == pc).filter(|_| !first);
        if call && let Some((at, held)) = known.map(|k| (k.1, false)).or(made.map(|m| (m.1, m.2))) {
            put_x18(&mut x18, pc, out, info);
            if !saved {
                out.push(SAVE);
                info.push(Word::At(pc));
            }
            // Made where the first words hold `x18` in `x17`: loaded there.
            if held {
                load_x18(pc, out, info);
            }
            if known.is_some() {
                c.joins.push((out.len(), pc, at));
                gate_out(pc, Exit::Join(pc), true, false, out, info);
            } else {
                let k = at as u32;
                out.push(0x1400_0000 | (k.wrapping_sub(out.len() as u32) & 0x3ff_ffff));
                info.push(Word::Saved(pc));
            }
            ended = true;
            break;
        }
        // A branch through a register (`br`, `ret`), looked up with them
        // saved: made with them in their registers, saved and on into
        // that lookup.
        if matches!(w & 0xffff_fc1f, 0xd61f_0000 | 0xd65f_0000) {
            if first && saved {
                put_x18(&mut x18, pc, out, info);
                c.lookups.push((pc, out.len()));
            } else if let Some(&(_, k)) = c.lookups.iter().find(|l| l.0 == pc).filter(|_| !first) {
                if !saved {
                    out.push(SAVE);
                    info.push(Word::At(pc));
                }
                out.push(0x1400_0000 | ((k as u32).wrapping_sub(out.len() as u32) & 0x3ff_ffff));
                info.push(Word::Saved(pc));
                ended = true;
                break;
            }
        }
        // Where the words of a call made here are entered saved: past the
        // save they begin with when made unsaved; and whether `x18` is
        // held in `x17` there.
        let call_at = (call && first).then_some((out.len(), saved, x18.is_some()));
        if crate::decode::may_name_x18(w) && quiet.is_none() {
            quiet = Some(overwritten_after(g, followed));
        }
        let quiet_here = quiet.as_ref().map_or(0, |q| q[((pc - g) / 4) as usize]);
        // `bl`, `blr`
        if w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000 {
            calls.push(pc + 4);
        }
        if saved && !is_branch(w) && !keeps_saved(w, false) && in_x17(w).is_none() {
            put_x18(&mut x18, pc, out, info);
            x18 = None;
            if restore.is_none() {
                restore = Some((pc, out.len()));
            }
            out.push(RESTORE);
            info.push(Word::Saved(pc));
            saved = false;
        }
        ended = one(w, pc, t, quiet_here, &mut saved, &mut x18, &mut sides, &mut c.pads, out, info);
        if let Some((k, was, held)) = call_at {
            assert!(was || out[k] == SAVE, "a call made unsaved at {pc:#x} with no save first");
            c.made.push((pc, (k + usize::from(!was)) as u64, held));
        }
        pc += 4;
        // Ends at a branch out, or at the page's end (the next page may not
        // be the program's code).
        if ended || pc & (page - 1) == 0 {
            break;
        }
    }
    if !ended {
        put_x18(&mut x18, pc, out, info);
        gate_out(pc, Exit::Jump(pc), saved, x18.is_some(), out, info);
    }
    // The taken ways of its conditional branches and its direct calls'
    // ways to their targets, after the rest.
    for side in sides {
        let here = out.len();
        match side {
            Side::Taken { at, g, to, saved, x18 } => {
                out[at] |= ((here - at) as u32) << 5;
                gate_out(g, Exit::Jump(to), saved, x18, out, info);
                if let Word::Out { cond, .. } = &mut info[here] {
                    *cond = (here - at) as u16;
                }
            }
            Side::Call { at, g, to, ret } => {
                out[at] |= (here - at) as u32;
                materialize(30, ret, out);
                info.extend((here..out.len()).map(|_| Word::Saved(g)));
                gate_out(g, Exit::Jump(to), true, false, out, info);
            }
            Side::Lookup(tail) => lookup_tail(&tail, out, info),
        }
    }
    Body { calls, end: pc, restore, x18: x18_entry }
}

/// What [`body_of`] made: where the block's calls return, the end of the
/// program's words it read, where it first restores the program's `x16`
/// and `x17` (the program address, and the word), and where it is entered
/// with its `x18` loaded (the word).
struct Body {
    calls: Vec<u64>,
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
fn load_x18(pc: u64, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    let slot = crate::x18_slot();
    out.extend([
        rewrite::MRS_TPIDRRO | 16,
        rewrite::AND_NOT7 | (16 << 5) | 16,
        rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 17,
    ]);
    info.extend([Word::Saved(pc); 3]);
}

/// Words of a block out of line, after the rest ([`body_of`]).
enum Side {
    /// A conditional branch's taken way: the branch, word `at` of the
    /// block (its offset in the field at bit 5), at program address `g`,
    /// to `to`, the program's `x16` and `x17` saved there or not, and its
    /// `x18` held in `x17` or not.
    Taken { at: usize, g: u64, to: u64, saved: bool, x18: bool },
    /// A direct call's way to its target: the `bl` at `at` (its offset in
    /// the field at bit 0), at program address `g`, comes to it; `x30` is
    /// set to `ret`, the return address, and it goes on to `to`, `x16` and
    /// `x17` saved.
    Call { at: usize, g: u64, to: u64, ret: u64 },
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
/// and `x17` saved below `sp`: it names neither, nor `sp` (nor `x18`,
/// unless `x18`), and needs no stack of fwe's. Where a field may be a
/// register, it is taken for one.
fn keeps_saved(w: u32, x18: bool) -> bool {
    names_none(w, 1 << 16 | 1 << 17 | if x18 { 0 } else { 1 << 18 })
}

/// Whether the program's instruction `w` names none of the general
/// registers in `regs` (a bit each), nor `sp`, and needs no stack of
/// fwe's ([`keeps_saved`]). Where a field may be a register, it is taken
/// for one.
fn names_none(w: u32, regs: u32) -> bool {
    let reg = |shift: u32| (w >> shift) & 31;
    let named = |fields: &[u32]| fields.iter().any(|&f| reg(f) != 31 && regs & 1 << reg(f) != 0);
    let (rd, rn) = (reg(0), reg(5));
    let op0 = (w >> 25) & 0xf;
    match op0 {
        // Loads and stores: `sp` as the base. A pair names a second
        // register at 10; the forms with an immediate offset name no other.
        0b0100 | 0b0110 | 0b1100 | 0b1110 => {
            if rn == 31 {
                return false;
            }
            // Literal loads: into a vector register, through x16.
            if w & 0x3b00_0000 == 0x1800_0000 {
                return (w >> 26) & 1 == 0 && !named(&[0]);
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
            let sp = match (w >> 23) & 7 {
                0b010 => rn == 31 || (rd == 31 && not_s),
                0b011 => rn == 31 || rd == 31,
                0b100 => rd == 31 && (w >> 29) & 3 != 3,
                _ => false,
            };
            !sp && !named(if (w >> 23) & 7 == 0b111 { &[0, 5, 16] } else { &[0, 5] })
        }
        // Data processing on registers: `sp` in add and subtract with an
        // extended register, and (taken as such) in the one- and two-source
        // operations (the tag ones).
        0b0101 | 0b1101 => {
            let rm = reg(16);
            if (w >> 24) & 0x1f == 0b01011 && (w >> 21) & 1 == 1 {
                rn != 31 && !(rd == 31 && (w >> 29) & 1 == 0) && !named(&[0, 5, 16])
            } else if (w >> 21) & 0xff == 0b1101_0110 {
                rd != 31 && rn != 31 && rm != 31 && !named(&[0, 5, 16])
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
    if is_branch(w) || crate::decode::x18_casp(w) || !names_none(w, 0) {
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
fn put_x18(x18: &mut Option<bool>, pc: u64, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    if *x18 == Some(true) {
        let slot = crate::x18_slot();
        out.push(rewrite::STR_UIMM | ((slot / 8) << 10) | (16 << 5) | 17);
        info.push(Word::SavedX18(pc));
        *x18 = Some(false);
    }
}

/// A way out into fwe through the exit gate (first a save of the
/// program's `x16` and `x17` below `sp` unless `saved`): `x16` the way
/// out's address, and a branch to its chunk's exit stub ([`exit_stub`],
/// made [`TO_STUB`] and pointed there by [`place`]). A direct one is
/// linked by making its first word a branch to the target's translation,
/// entered as the way out has them ([`entered`]).
fn gate_out(g: u64, exit: Exit, saved: bool, x18: bool, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    if saved {
        out.push(OUT);
    } else {
        out.extend([SAVE, 0x10ff_fff0]); // adr x16, #-4
    }
    out.push(TO_STUB);
    info.push(Word::Out { g, exit, saved, x18: saved && x18, cond: 0 });
    while info.len() < out.len() {
        info.push(Word::Saved(g));
    }
}

/// Translate the program's instruction `w` at `pc` into `out`, the block
/// placed at `t`, recording what each word stands for; `saved`, whether
/// the program's `x16` and `x17` are below `sp` (only a branch is made
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
    out: &mut Vec<u32>,
    info: &mut Vec<Word>,
) -> bool {
    let here = |out: &Vec<u32>| t + 4 * out.len() as u64;
    let imm26 = || pc.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
    let imm19 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x7_ffff) << 13) as i32 >> 11));
    let imm14 = || pc.wrapping_add_signed(i64::from((((w >> 5) & 0x3fff) << 18) as i32 >> 16));
    // The program's x16 and x17 saved, if they are not.
    let save = |saved: &mut bool, out: &mut Vec<u32>, info: &mut Vec<Word>| {
        if !*saved {
            out.push(SAVE);
            info.push(Word::At(pc));
            *saved = true;
        }
    };
    // Before a branch, the program's x18 back in its slot if it is held
    // changed in x17.
    if is_branch(w) || (w >> 25) & 0x7f == 0b110_1011 || w == ISB {
        put_x18(x18, pc, out, info);
    }
    let changed = *x18 == Some(true);
    let at_pc = |saved: bool| match (saved, changed) {
        (true, true) => Word::SavedX18(pc),
        (true, false) => Word::Saved(pc),
        _ => Word::At(pc),
    };
    // b
    if w & 0xfc00_0000 == 0x1400_0000 {
        gate_out(pc, Exit::Jump(imm26()), *saved, x18.is_some(), out, info);
        return true;
    }
    // bl: x16 and x17 saved (as a call's words are entered, [`body_of`]),
    // a `bl` to the words that set the program's return address in x30
    // and go on to the target, out of line ([`Side`]). Its return found in
    // [`RETS`] comes back after the `bl` with `ret`, where the processor
    // predicts it: the block goes on there, with x16 and x17 saved (x17
    // no longer holding x18).
    if w & 0xfc00_0000 == 0x9400_0000 {
        save(saved, out, info);
        sides.push(Side::Call { at: out.len(), g: pc, to: imm26(), ret: pc + 4 });
        out.push(BL);
        info.push(at_pc(true));
        pads.push((pc + 4, out.len()));
        *x18 = None;
        return false;
    }
    // b.cond (and bc.cond)
    if w & 0xff00_0000 == 0x5400_0000 {
        sides.push(Side::Taken {
            at: out.len(),
            g: pc,
            to: imm19(),
            saved: *saved,
            x18: x18.is_some(),
        });
        out.push(w & !(0x7_ffff << 5));
        info.push(at_pc(*saved));
        return false;
    }
    // cbz/cbnz, tbz/tbnz
    let family = (w >> 25) & 0x3f;
    if family == 0b011010 || family == 0b011011 {
        let taken = if family == 0b011010 { imm19() } else { imm14() };
        let field = if family == 0b011010 { 0x7_ffff << 5 } else { 0x3fff << 5 };
        let rt = w & 0x1f;
        if rt == 18 && x18.is_some() {
            // Of x18, held in x17 (back in its slot above).
            sides.push(Side::Taken { at: out.len(), g: pc, to: taken, saved: true, x18: true });
            out.push((w & !field & !0x1f) | 17);
            info.push(Word::SavedX18(pc));
            return false;
        }
        if rt == 18 {
            // Of x18: its value from its slot into x16, tested there.
            save(saved, out, info);
            let slot = crate::x18_slot();
            out.extend([
                rewrite::MRS_TPIDRRO | 16,
                rewrite::AND_NOT7 | (16 << 5) | 16,
                rewrite::LDR_UIMM | ((slot / 8) << 10) | (16 << 5) | 16,
            ]);
            info.extend([Word::Saved(pc); 3]);
            sides.push(Side::Taken { at: out.len(), g: pc, to: taken, saved: true, x18: false });
            out.push((w & !field & !0x1f) | 16);
            info.push(Word::Saved(pc));
            return false;
        }
        if matches!(rt, 16 | 17) && *saved {
            // Tested where the program has it.
            out.push(RESTORE);
            info.push(Word::Saved(pc));
            *saved = false;
            *x18 = None;
        }
        sides.push(Side::Taken {
            at: out.len(),
            g: pc,
            to: taken,
            saved: *saved,
            x18: x18.is_some(),
        });
        out.push(w & !field);
        info.push(at_pc(*saved));
        return false;
    }
    // br, blr, ret
    if matches!(w & 0xffff_fc1f, 0xd61f_0000 | 0xd65f_0000 | 0xd63f_0000) {
        *x18 = None;
    }
    match w & 0xffff_fc1f {
        0xd61f_0000 | 0xd65f_0000 => {
            save(saved, out, info);
            let ret = w & 0xffff_fc1f == 0xd65f_0000;
            lookup(pc, (w >> 5) & 0x1f, None, ret, pads, out, info);
            return true;
        }
        // blr: the block goes on after the call's `bl`, where its return
        // comes back, x16 and x17 saved; the rest of the lookup out of
        // line.
        0xd63f_0000 => {
            save(saved, out, info);
            let tail = lookup(pc, (w >> 5) & 0x1f, Some(pc + 4), false, pads, out, info);
            sides.push(Side::Lookup(tail.expect("a call's lookup goes on")));
            return false;
        }
        _ => {}
    }
    if (w >> 25) & 0x7f == 0b110_1011 {
        // Another branch through a register (authenticated): no stand-in.
        out.push(UDF);
        info.push(at_pc(*saved));
        return true;
    }
    // Naming x18, run on x17 where x16 and x17 are saved: x18 loaded into
    // x17 from its slot at the first (x16 holding the thread's area that
    // holds it), and written back before a branch, a lookup or a restore.
    if *saved && let Some((renamed, writes)) = in_x17(w) {
        if x18.is_none() {
            load_x18(pc, out, info);
            *x18 = Some(false);
        }
        out.push(renamed);
        info.push(Word::SavedX18(pc));
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
            expansion(Site::X18 { insn: w }, pc, here(out), out, info);
        } else {
            let at = out.len();
            materialize(w & 0x1f, v, out);
            info.extend((at..out.len()).map(|_| at_pc(*saved)));
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
                info.extend((m..out.len()).map(|_| Word::Undo { g: pc, start, of: Of::Load }));
                let load = match opc {
                    0 => 0xbd40_0000,
                    1 => 0xfd40_0000,
                    _ => 0x3dc0_0000,
                };
                out.push(load | (16 << 5) | rt);
                info.push(Word::Undo { g: pc, start, of: Of::Load });
                out.push(rewrite::POP | 16);
                info.push(Word::Finish { g: pc, of: Of::Load });
                return false;
            }
        }
        info.extend((at..out.len()).map(|_| at_pc(*saved)));
        return false;
    }
    // `isb`: from here the program runs what it wrote to code before it
    // (the architecture's rule for self-modifying code). The block ends:
    // its way out goes on at the next instruction's translation, made again
    // if a write dropped it (and unlinked the way there).
    if w == ISB {
        out.push(w);
        info.push(at_pc(*saved));
        gate_out(pc, Exit::Jump(pc + 4), *saved, x18.is_some(), out, info);
        return true;
    }
    // A flush of an instruction cache line: run, and fwe told through the
    // gate, as [`crate::rewrite`]'s stub does, its way back past the
    // program's address kept after it, as a system call's is.
    let gate = crate::syscall_gate();
    if rewrite::is_ic_ivau(w) && gate != 0 {
        if here(out) % 8 != 0 {
            out.push(rewrite::NOP);
            info.push(Word::At(pc));
        }
        let stub_at = here(out);
        let site = Site::Flush { rt: w & rewrite::RT_MASK, gate };
        let words = rewrite::stub(site, 0, 0, stub_at, stub_at + 40);
        for (k, &sw) in words.iter().enumerate() {
            out.push(sw);
            info.push(match k {
                0..=1 => Word::At(pc),
                2..=3 => Word::Undo { g: pc, start: stub_at, of: Of::Flush },
                _ => Word::Finish { g: pc, of: Of::Flush },
            });
        }
        out.extend([pc as u32, (pc >> 32) as u32]);
        info.extend([Word::Finish { g: pc, of: Of::Flush }; 2]);
        return false;
    }
    // A system call (Linux ignores `svc`'s immediate).
    if w & 0xffe0_001f == 0xd400_0001 {
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
            // Its way back goes past the program's address of the `svc`,
            // kept after it for the gate ([`syscall_site`]).
            let words = rewrite::stub(Site::Syscall { gate }, 0, 0, stub_at, stub_at + 40);
            for (k, &sw) in words.iter().enumerate() {
                out.push(sw);
                // Before the call returns: undone (the call not made);
                // after: finished.
                info.push(match k {
                    0 => Word::At(pc),
                    1..=2 => Word::Undo { g: pc, start: stub_at, of: Of::Syscall },
                    _ => Word::Finish { g: pc, of: Of::Syscall },
                });
            }
            out.extend([pc as u32, (pc >> 32) as u32]);
            info.extend([Word::Finish { g: pc, of: Of::Syscall }; 2]);
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
        if let Some((words, main)) = x18_beside(w, quiet) {
            let start = here(out);
            for (k, sw) in words.into_iter().enumerate() {
                out.push(sw);
                info.push(match k {
                    0 => Word::At(pc),
                    k if k > main => Word::Finish { g: pc, of: Of::X18 },
                    _ => Word::Undo { g: pc, start, of: Of::X18 },
                });
            }
        } else {
            expansion(Site::X18 { insn: w }, pc, here(out), out, info);
        }
        return false;
    }
    if crate::decode::names_x18(w) {
        // A form fwe has no stand-in for.
        out.push(UDF);
        info.push(Word::At(pc));
        return true;
    }
    out.push(w);
    info.push(at_pc(*saved));
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
#[allow(clippy::too_many_arguments)]
fn lookup(
    pc: u64,
    n: u32,
    link: Option<u64>,
    ret: bool,
    pads: &mut Vec<(u64, usize)>,
    out: &mut Vec<u32>,
    info: &mut Vec<Word>,
) -> Option<Tail> {
    let before = Word::Lookup { g: pc, link, to: None };
    let in_place = !matches!(n, 16..=18) && !(n == 30 && link.is_some());
    // A return: first the table of returns, where a call made in a
    // translation left the way back after its `bl` ([`RETS`]), each entry
    // of the pair in turn; found, back there with `ret`, predicted.
    if ret && in_place {
        let committed = Word::Lookup { g: pc, link: None, to: Some(n as u8) };
        let mut misses = Vec::new();
        for other in [false, true] {
            out.extend([index_of(n), SCALE, RETS_BASE]);
            out.extend(other.then_some(OTHER));
            out.extend([ENTRY, key_against(n), MISS_X16]);
            misses.push(out.len() - 1);
            while info.len() < out.len() {
                info.push(before);
            }
            out.push(RET_X17);
            info.push(committed);
        }
        // Each one's miss past its `ret`: to the second, then to the table
        // of translations.
        for m in misses {
            out[m] |= 2 << 5;
        }
    }
    let (miss_at, to) = if in_place {
        out.extend([index_of(n), SCALE, BASE, ENTRY, key_against(n)]);
        out.push(MISS_X16); // its offset filled in by the rest
        (out.len() - 1, n as u8)
    } else {
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
        out.extend([INDEX, SCALE, BASE, KEY, CHECK]);
        out.push(MISS); // its offset filled in by the rest
        let miss_at = out.len() - 1;
        out.extend([INDEX, SCALE, BASE, VALUE]);
        (miss_at, 16)
    };
    let committed = Word::Lookup { g: pc, link, to: Some(to) };
    while info.len() < out.len() {
        info.push(before);
    }
    // A target fwe does not translate has no translation in the table (0):
    // the branch is made as the program made it, every register its own.
    let outside_at = out.len();
    out.push(OUTSIDE);
    info.push(committed);
    let mut tail = Tail { pc, n, link, in_place, miss_at, outside_at, bl: None, committed, before };
    if let Some(link) = link {
        tail.bl = Some(out.len());
        out.push(BL);
        info.push(committed);
        // Entered as a lookup enters a translation: `x16` and `x17` saved.
        pads.push((link, out.len()));
        return Some(tail);
    }
    lookup_tail(&tail, out, info);
    None
}

/// The rest of a [`lookup`]: at `pc`, through `x<n>`, a call if `link`;
/// its first look's miss at word `miss_at` and its target not translated
/// at `outside_at`; for a call, its `bl` at `bl`. Its words are made as
/// `committed` once the target is known, `before` until then.
struct Tail {
    pc: u64,
    n: u32,
    link: Option<u64>,
    in_place: bool,
    miss_at: usize,
    outside_at: usize,
    bl: Option<usize>,
    committed: Word,
    before: Word,
}

/// The words of `t` past its first look (a call's `bl` comes to them):
/// on to the translation found, `x30` the return address for a call; the
/// branch made as the program made it where the target is not translated;
/// the second look; the miss.
fn lookup_tail(t: &Tail, out: &mut Vec<u32>, info: &mut Vec<Word>) {
    let &Tail { pc, n, link, in_place, miss_at, outside_at, bl, committed, before } = t;
    if let Some(bl) = bl {
        out[bl] |= (out.len() - bl) as u32;
    }
    if let Some(link) = link {
        let at = out.len();
        materialize(30, link, out);
        info.extend((at..out.len()).map(|_| committed));
    }
    if !in_place {
        out.push(TO_CHECK);
        info.push(committed);
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
    // The entry the target's bits pick holds another address: the other
    // of its pair, as the first; found, on as from the first.
    let second = out.len();
    out[miss_at] |= ((second - miss_at) as u32) << 5;
    let miss_at = if in_place {
        out.extend([index_of(n), SCALE, BASE, OTHER, ENTRY, key_against(n), MISS_X16]);
        out.len() - 1
    } else {
        out.extend([INDEX, SCALE, BASE, OTHER, KEY, CHECK, MISS]);
        let miss_at = out.len() - 1;
        out.extend([INDEX, SCALE, BASE, OTHER, VALUE]);
        miss_at
    };
    out.push(0x1400_0000 | ((outside_at as u32).wrapping_sub(out.len() as u32) & 0x3ff_ffff));
    while info.len() < out.len() {
        info.push(before);
    }
    // The miss: into fwe.
    let miss = out.len();
    out[miss_at] |= ((miss - miss_at) as u32) << 5;
    if trapped {
        out[outside_at] |= ((miss - outside_at) as u32) << 5;
    }
    gate_out(pc, Exit::Reg { n, link }, true, false, out, info);
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
        out.push(sw);
        info.push(match main {
            _ if k == 0 => Word::At(pc),
            Some(m) if k > m => Word::Finish { g: pc, of },
            _ => Word::Undo { g: pc, start, of },
        });
    }
}

