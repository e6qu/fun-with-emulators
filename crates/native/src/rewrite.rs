//! Rewriting guest code so it can run inside a macOS process.
//!
//! Before guest code becomes executable, instructions whose behaviour on
//! macOS differs from Linux are replaced:
//!
//! - `svc #0` (a Linux system call) would enter the macOS kernel. It becomes
//!   a `brk` with a distinctive immediate; the resulting trap is serviced by
//!   our handler, which runs the Linux system call and resumes the guest.
//! - `mrs`/`msr` of `TPIDR_EL0` (the Linux thread pointer): macOS does not
//!   preserve `TPIDR_EL0` for user code. Each access becomes a branch to a
//!   short stub that reads or writes the guest thread pointer in a per-thread
//!   slot instead. The slot lives in the host thread's TSD, which macOS points
//!   `TPIDRRO_EL0` at; that register is per-thread and read-only to us.
//! - Any instruction naming `x18`: macOS clears `x18` on every exception
//!   return, so each such instruction becomes a branch to a stub that keeps
//!   the guest's `x18` in another TSD slot (see [`crate::decode`]).
//!
//! arm64 instructions are 4 bytes and 4-byte aligned, so scanning aligned
//! words finds every instruction exactly. A data word that happens to match
//! one of these encodings would be rewritten too, so callers pass only
//! executable sections, and literal pools inside them are skipped.

/// `svc #0`.
pub const SVC0: u32 = 0xd400_0001;

/// Immediate of the trap instruction that replaces `svc #0` ("LX").
pub const TRAP_IMM: u32 = 0x4c58;

/// `brk #TRAP_IMM`.
pub const TRAP: u32 = 0xd420_0000 | (TRAP_IMM << 5);

const NOP: u32 = 0xd503_201f;
const RT_MASK: u32 = 0x1f;
/// `mrs xN, tpidr_el0`
const MRS_TPIDR: u32 = 0xd53b_d040;
/// `msr tpidr_el0, xN`
const MSR_TPIDR: u32 = 0xd51b_d040;
/// `mrs xN, tpidrro_el0`
const MRS_TPIDRRO: u32 = 0xd53b_d060;
/// `and xD, xN, #~7`
const AND_NOT7: u32 = 0x927d_f000;
/// `ldr xT, [xN, #imm]` (unsigned offset, imm/8 in bits 10..22)
const LDR_UIMM: u32 = 0xf940_0000;
/// `str xT, [xN, #imm]` (unsigned offset)
const STR_UIMM: u32 = 0xf900_0000;
/// `str xT, [sp, #-16]!`
const PUSH: u32 = 0xf81f_0fe0;
/// `ldr xT, [sp], #16`
const POP: u32 = 0xf841_07e0;
/// `add xD, sp, #48`: the `sp` a three-register stub was entered with.
const ADD_SP_48: u32 = 0x9100_c3e0;
/// `sub sp, sp, #imm12`; `| (imm << 10)`.
const SUB_SP: u32 = 0xd100_03ff;
/// `add sp, sp, #imm12`; `| (imm << 10)`.
const ADD_SP: u32 = 0x9100_03ff;
/// `add xD, sp, #imm12`; `| (imm << 10) | d`.
const ADD_FROM_SP: u32 = 0x9100_03e0;
/// `mov sp, xN` (`add sp, xN, #0`); `| (n << 5)`.
const MOV_TO_SP: u32 = 0x9100_001f;
/// `stp xA, xB, [sp]`; `| (b << 10) | a`.
const STP_SP: u32 = 0xa900_03e0;
/// `ldp xA, xB, [sp]`; `| (b << 10) | a`.
const LDP_SP: u32 = 0xa940_03e0;
/// `stp xA, xB, [sp, #-16]!`; `| (b << 10) | a`.
const PUSH_PAIR: u32 = 0xa9bf_03e0;
/// `ldp xA, xB, [sp], #16`; `| (b << 10) | a`.
const POP_PAIR: u32 = 0xa8c1_03e0;
/// `ldur xT, [xN, #imm9]`; `| ((imm & 0x1ff) << 12) | (n << 5) | t`.
pub const LDUR: u32 = 0xf840_0000;
/// `mov xD, xM` (`orr xD, xzr, xM`); `| (m << 16) | d`.
const MOV: u32 = 0xaa00_03e0;
/// `add xD, xN, xM`; `| (m << 16) | (n << 5) | d`.
const ADD_REG: u32 = 0x8b00_0000;
/// `b <label>`
const B: u32 = 0x1400_0000;
/// `movz xN, #imm16` base; `| (hw << 21) | (imm16 << 5) | n`.
const MOVZ: u32 = 0xd280_0000;
/// `movk xN, #imm16` base.
const MOVK: u32 = 0xf280_0000;

/// Largest stub, in instructions. The `x18` branch stub and the stub for a
/// load or store written back onto `sp` are the biggest.
pub const STUB_WORDS: usize = 14;

/// Reach of a `b` instruction.
pub const BRANCH_RANGE: u64 = 128 << 20;

/// An instruction that needs an out-of-line stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// `mrs xN, tpidr_el0`
    ReadThreadPointer { rt: u32 },
    /// `msr tpidr_el0, xN` (N = 31 is `xzr`)
    WriteThreadPointer { rt: u32 },
    /// An instruction that names `x18`; the stub keeps `x18` in a slot.
    X18 { insn: u32 },
}

/// Whether `insn` names `x18` in an operand position this pass can rewrite by
/// substituting a scratch register.
fn rewritable_x18(insn: u32) -> bool {
    crate::decode::operands(insn)
        .is_some_and(|ops| ops.iter().any(|f| (insn >> f.shift) & 0x1f == 18))
}

/// Whether `insn` is any instruction naming `x18` that this pass rewrites —
/// operand substitution, a PC-relative form, a branch, or an indirect branch.
fn x18_site(insn: u32) -> bool {
    use crate::decode::*;
    rewritable_x18(insn)
        || x18_branch(insn)
        || x18_adr(insn).is_some()
        || x18_ldr_literal(insn)
        || x18_indirect(insn).is_some()
        || x18_casp(insn)
        || x18_sp_writeback(insn)
        || x18_writes_sp(insn)
}

/// Result of rewriting a block of code in place.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Patched {
    pub syscalls: usize,
    /// Offsets (from the start of the block) of instructions that must be
    /// redirected to stubs.
    pub sites: Vec<(u64, Site)>,
    /// Count of instructions that name `x18` but are left alone (the `sp`
    /// writeback and `sp` register-offset load/store forms, and data-processing
    /// forms with an `sp` operand). Diagnostic only.
    pub x18_deferred: usize,
}

/// Rewrite what can be rewritten in place and collect the rest. `code`
/// must start at a 4-byte aligned address. `known`, when given, is the
/// `(offset, length)` byte ranges of `code` that are known to be code (the
/// image's unwind table covers them): a word outside them that looks like
/// an `x18` instruction is data in practice — a constant table hand-written
/// assembly keeps among its code — and is left alone.
pub fn patch(code: &mut [u8], known: Option<&[(u64, u64)]>) -> Patched {
    let mut out = Patched::default();
    let words = code.len() / 4;
    let is_code: Vec<bool> = match known {
        None => vec![true; words],
        Some(ranges) => {
            let mut v = vec![false; words];
            for &(off, len) in ranges {
                let first = (off / 4) as usize;
                let last = (off.saturating_add(len).div_ceil(4) as usize).min(words);
                for w in v.iter_mut().take(last).skip(first) {
                    *w = true;
                }
            }
            v
        }
    };
    let data = literal_pool_words(code, &is_code);
    for (i, word) in code.chunks_exact_mut(4).enumerate() {
        // Words that belong to a literal pool are data, not instructions, and a
        // constant can encode anything — never rewrite them.
        if data[i] {
            continue;
        }
        let insn = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        let replacement = if insn == SVC0 {
            out.syscalls += 1;
            Some(TRAP)
        } else if insn & !RT_MASK == MRS_TPIDR {
            let rt = insn & RT_MASK;
            if rt == 31 {
                // Reading into xzr has no effect.
                Some(NOP)
            } else {
                out.sites.push((i as u64 * 4, Site::ReadThreadPointer { rt }));
                None
            }
        } else if insn & !RT_MASK == MSR_TPIDR {
            out.sites.push((i as u64 * 4, Site::WriteThreadPointer { rt: insn & RT_MASK }));
            None
        } else if !is_code[i] {
            None
        } else if x18_site(insn) {
            out.sites.push((i as u64 * 4, Site::X18 { insn }));
            None
        } else {
            if crate::decode::names_x18(insn) {
                out.x18_deferred += 1;
            }
            None
        };
        if let Some(r) = replacement {
            word.copy_from_slice(&r.to_le_bytes());
        }
    }
    out
}

/// Mark, for each word of `code`, whether it is the target of a `ldr`-literal
/// (so part of a literal pool) and therefore data rather than an instruction.
fn literal_pool_words(code: &[u8], is_code: &[bool]) -> Vec<bool> {
    let n = code.len() / 4;
    let mut data = vec![false; n];
    for (i, w) in code.chunks_exact(4).enumerate() {
        // Only a load that is code names a literal: a data word that happens
        // to decode as one could otherwise hide a real instruction.
        if !is_code[i] {
            continue;
        }
        let insn = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        if let Some((off, size)) = crate::decode::literal_target(insn) {
            let target = i as i64 * 4 + off;
            if target >= 0 {
                let start = target as usize / 4;
                let end = (target as usize + size).div_ceil(4);
                for d in data.iter_mut().take(end.min(n)).skip(start) {
                    *d = true;
                }
            }
        }
    }
    data
}

/// Number of instructions in `code` that [`patch`] would redirect to stubs.
pub fn count_sites(code: &[u8]) -> usize {
    code.chunks_exact(4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .filter(|&i| {
            (i & !RT_MASK == MRS_TPIDR && i & RT_MASK != 31)
                || i & !RT_MASK == MSR_TPIDR
                || x18_site(i)
        })
        .count()
}

/// `b` from `from` to `to`, if in range.
pub fn branch(from: u64, to: u64) -> Option<u32> {
    let offset = to.wrapping_sub(from) as i64;
    if offset % 4 != 0 || !(-(BRANCH_RANGE as i64)..BRANCH_RANGE as i64).contains(&offset) {
        return None;
    }
    Some(B | ((offset >> 2) as u32 & 0x03ff_ffff))
}

/// The stub for `site`, placed at `stub`, returning to `ret`. `tp_slot` and
/// `x18_slot` are the byte offsets of the guest thread pointer and of the guest
/// `x18` in the host TSD.
pub fn stub(site: Site, tp_slot: u32, x18_slot: u32, stub: u64, ret: u64) -> Vec<u32> {
    let imm = |slot: u32| {
        assert!(slot % 8 == 0 && slot / 8 < 4096, "slot offset must fit an ldr/str immediate");
        (slot / 8) << 10
    };
    let mut words = match site {
        // Through `x18`: from one slot to the other.
        Site::ReadThreadPointer { rt: 18 } | Site::WriteThreadPointer { rt: 18 } => {
            let (from, to) = match site {
                Site::ReadThreadPointer { .. } => (imm(tp_slot), imm(x18_slot)),
                _ => (imm(x18_slot), imm(tp_slot)),
            };
            let (s1, s2) = (0, 1);
            vec![
                PUSH | s1,
                PUSH | s2,
                MRS_TPIDRRO | s2,
                AND_NOT7 | (s2 << 5) | s2,
                LDR_UIMM | from | (s2 << 5) | s1,
                STR_UIMM | to | (s2 << 5) | s1,
                POP | s2,
                POP | s1,
            ]
        }
        Site::ReadThreadPointer { rt } => {
            let imm = imm(tp_slot);
            vec![MRS_TPIDRRO | rt, AND_NOT7 | (rt << 5) | rt, LDR_UIMM | imm | (rt << 5) | rt]
        }
        Site::WriteThreadPointer { rt } => {
            // A scratch register, saved below sp (Linux arm64 has no red zone,
            // so memory below sp is not live).
            let imm = imm(tp_slot);
            let s = if rt == 16 { 17 } else { 16 };
            vec![
                PUSH | s,
                MRS_TPIDRRO | s,
                AND_NOT7 | (s << 5) | s,
                STR_UIMM | imm | (s << 5) | rt,
                POP | s,
            ]
        }
        // An indirect branch through x18 builds a complete, self-terminating
        // stub (it ends in `br`), so it is returned directly.
        Site::X18 { insn } if crate::decode::x18_indirect(insn).is_some() => {
            return x18_indirect_stub(insn, imm(x18_slot), ret);
        }
        // A compare/test branch that reads x18 also builds its own complete
        // stub, including its outgoing branches.
        Site::X18 { insn } if crate::decode::x18_branch(insn) => {
            return x18_branch_stub(insn, imm(x18_slot), stub, ret);
        }
        // PC-relative forms materialize the value computed from the original pc.
        Site::X18 { insn } if crate::decode::x18_adr(insn).is_some() => {
            x18_adr_stub(insn, imm(x18_slot), ret)
        }
        Site::X18 { insn } if crate::decode::x18_ldr_literal(insn) => {
            x18_ldr_literal_stub(insn, imm(x18_slot), ret)
        }
        Site::X18 { insn } if crate::decode::x18_casp(insn) => x18_casp_stub(insn, imm(x18_slot)),
        Site::X18 { insn } if crate::decode::x18_sp_writeback(insn) => {
            x18_sp_writeback_stub(insn, imm(x18_slot))
        }
        Site::X18 { insn } if crate::decode::x18_writes_sp(insn) => {
            x18_writes_sp_stub(insn, imm(x18_slot))
        }
        Site::X18 { insn } => x18_stub(insn, imm(x18_slot)),
    };
    let at = stub + 4 * words.len() as u64;
    words.push(branch(at, ret).expect("stub placed within branch range of its site"));
    assert!(words.len() <= STUB_WORDS, "a stub longer than its slot");
    words
}

/// Stub for a `cbz`/`cbnz`/`tbz`/`tbnz` that tests `x18`. It loads `x18` into a
/// scratch, runs the branch against the scratch to a local label, then restores
/// the scratch registers down both paths and branches (full range) to the real
/// target or the fall-through. `x0`/`x1` are free here — these branches read no
/// register other than `x18` — and are saved and restored, so they are intact
/// at both destinations.
fn x18_branch_stub(insn: u32, imm: u32, stub: u64, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let (s1, s2) = (0u32, 1u32);
    let tb = (insn >> 25) & 0x3f == 0b011011; // tbz/tbnz (vs cbz/cbnz)
    let imm_bits = if tb {
        (((insn >> 5) & 0x3fff) as i64) << 50 >> 50
    } else {
        (((insn >> 5) & 0x7ffff) as i64) << 45 >> 45
    };
    let off = imm_bits * 4;
    let target = (site as i64).wrapping_add(off) as u64;

    // The conditional branch with Rt -> s1 and its offset retargeted to the
    // local `taken` label, which sits 4 words after the branch.
    let mut cond = (insn & !0x1f) | s1;
    cond =
        if tb { (cond & !(0x3fff << 5)) | (4 << 5) } else { (cond & !(0x7ffff << 5)) | (4 << 5) };
    let at = |i: u64| stub + 4 * i;
    vec![
        PUSH | s1,                                                   // 0: save x0
        PUSH | s2,                                                   // 1: save x1
        MRS_TPIDRRO | s2,                                            // 2
        AND_NOT7 | (s2 << 5) | s2,                                   // 3: s2 = TSD base
        LDR_UIMM | imm | (s2 << 5) | s1,                             // 4: s1 = x18
        cond,                                                        // 5: if taken -> word 9
        POP | s2,                                                    // 6: not taken: restore x1
        POP | s1,                                                    // 7: restore x0
        branch(at(8), ret).expect("fall-through within range"),      // 8
        POP | s2,                                                    // 9: taken: restore x1
        POP | s1,                                                    // 10: restore x0
        branch(at(11), target).expect("branch target within range"), // 11
    ]
}

/// Instructions that load the 64-bit `val` into GPR `reg` (`movz` + three
/// `movk`, fixed length).
fn materialize(reg: u32, val: u64) -> [u32; 4] {
    let h = |i: u32| (((val >> (16 * i)) & 0xffff) as u32) << 5;
    [
        MOVZ | h(0) | reg,
        MOVK | (1 << 21) | h(1) | reg,
        MOVK | (2 << 21) | h(2) | reg,
        MOVK | (3 << 21) | h(3) | reg,
    ]
}

/// Stub for `adr`/`adrp` writing `x18`: compute the value from the *original*
/// pc, materialize it into a scratch, and store it to the slot. `imm` is the
/// slot `str` immediate.
fn x18_adr_stub(insn: u32, imm: u32, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let immlo = (insn >> 29) & 0b11;
    let immhi = (insn >> 5) & 0x7_ffff;
    let imm21 = (((immhi << 2) | immlo) as i64) << 43 >> 43; // sign-extend 21 bits
    let target = if (insn >> 31) & 1 == 1 {
        (site & !0xfff).wrapping_add((imm21 << 12) as u64) // adrp
    } else {
        site.wrapping_add(imm21 as u64) // adr
    };
    let (s1, s2) = (0u32, 1u32); // adr/adrp name only Rd = x18
    let m = materialize(s1, target);
    vec![
        PUSH | s1,
        PUSH | s2,
        MRS_TPIDRRO | s2,
        AND_NOT7 | (s2 << 5) | s2,
        m[0],
        m[1],
        m[2],
        m[3],
        STR_UIMM | imm | (s2 << 5) | s1,
        POP | s2,
        POP | s1,
    ]
}

/// Stub for a general-purpose `ldr`-literal into `x18`: materialize the literal
/// address (from the original pc), load from it, and store to the slot.
fn x18_ldr_literal_stub(insn: u32, imm: u32, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let imm19 = (((insn >> 5) & 0x7_ffff) as i64) << 45 >> 45;
    let lit = site.wrapping_add((imm19 * 4) as u64);
    let (s1, s2) = (0u32, 1u32);
    let m = materialize(s1, lit);
    // opc: 00 = ldr w (zero-extend), 01 = ldr x, 10 = ldrsw.
    let load = match (insn >> 30) & 0b11 {
        0b01 => LDR_UIMM,    // ldr x(s1), [s1]
        0b10 => 0xb980_0000, // ldrsw x(s1), [s1]
        _ => 0xb940_0000,    // ldr w(s1), [s1]
    } | (s1 << 5)
        | s1;
    vec![
        PUSH | s1,
        PUSH | s2,
        m[0],
        m[1],
        m[2],
        m[3],
        load,
        MRS_TPIDRRO | s2,
        AND_NOT7 | (s2 << 5) | s2,
        STR_UIMM | imm | (s2 << 5) | s1,
        POP | s2,
        POP | s1,
    ]
}

/// Stub for an indirect branch through `x18` (`br`/`blr`/`ret`, and the
/// authenticated forms). Loads the target from the slot into `x16` (`x17`
/// when the modifier is `x16`) and branches with the original's kind:
/// `x16`/`x17` are the intra-procedure-call scratch registers, dead at any
/// branch, so no save is needed, and a branch through them may land on a
/// `bti c`. For the `blr` forms the link register is set to the instruction
/// after the original branch, and the branch made without link.
/// Self-terminating (ends in the branch).
fn x18_indirect_stub(insn: u32, imm: u32, ret: u64) -> Vec<u32> {
    let sets_link = crate::decode::x18_indirect(insn) == Some(true);
    let modifier = ((insn >> 24) & 1 == 1).then_some(insn & 0x1f);
    let t = if modifier == Some(16) { 17 } else { 16 };
    let mut v = vec![MRS_TPIDRRO | t, AND_NOT7 | (t << 5) | t, LDR_UIMM | imm | (t << 5) | t];
    if sets_link {
        v.extend(materialize(30, ret)); // lr = site + 4
    }
    // The same branch, without link, through `t`.
    v.push((insn & !(1 << 21) & !(0x1f << 5)) | (t << 5));
    v
}

/// The registers 0..=30 not in `used`, lowest first.
fn free(used: u32) -> impl Iterator<Item = u32> {
    (0u32..=30).filter(move |&r| used & (1 << r) == 0)
}

/// Stub for a `casp` naming `x18` in a pair or as its base. A pair must be
/// an even-numbered register and the next, so one holding `x18` is replaced
/// by a free even pair: its first holds `x18`, its second a copy of `x19`,
/// and both go back after (`x18` to the slot) if the pair is the one
/// written (`Rs`). A base of `x18` goes through one more scratch register.
fn x18_casp_stub(insn: u32, imm: u32) -> Vec<u32> {
    let (rs, rt, rn) = ((insn >> 16) & 0x1f, insn & 0x1f, (insn >> 5) & 0x1f);
    let used = [rs, rs + 1, rt, rt + 1, rn, 18, 19].iter().fold(0u32, |u, &r| u | 1 << r);
    let pair = rs == 18 || rt == 18;
    let p = (0u32..=28).step_by(2).find(|&r| used & (3 << r) == 0).expect("a free even pair");
    let mut taken = used | 3 << p;
    let mut next = || {
        let r = free(taken).next().expect("a free register");
        taken |= 1 << r;
        r
    };
    let b = next(); // the TSD base
    let q = next(); // a base of x18
    let mut casp = insn;
    let sub = |i: u32, shift: u32, r: u32| (i & !(0x1f << shift)) | (r << shift);
    if rs == 18 {
        casp = sub(casp, 16, p);
    }
    if rt == 18 {
        casp = sub(casp, 0, p);
    }
    if rn == 18 {
        casp = sub(casp, 5, q);
    }
    let mut w = Vec::new();
    if pair {
        w.push(PUSH_PAIR | (p + 1) << 10 | p);
    }
    w.extend([PUSH_PAIR | q << 10 | b, MRS_TPIDRRO | b, AND_NOT7 | (b << 5) | b]);
    if pair {
        w.extend([LDR_UIMM | imm | (b << 5) | p, MOV | 19 << 16 | (p + 1)]);
    }
    if rn == 18 {
        w.push(LDR_UIMM | imm | (b << 5) | q);
    }
    w.push(casp);
    if rs == 18 {
        w.extend([STR_UIMM | imm | (b << 5) | p, MOV | (p + 1) << 16 | 19]);
    }
    w.push(POP_PAIR | q << 10 | b);
    if pair {
        w.push(POP_PAIR | (p + 1) << 10 | p);
    }
    w
}

/// Stub for a load or store of `x18` written back onto `sp`. It runs the
/// access without the writeback, at the address the original uses, through
/// a scratch register, then moves `sp` by the immediate. Its scratch
/// registers are saved below the access, and `sp` covers both all along, so
/// a signal at any point finds nothing live below `sp`.
fn x18_sp_writeback_stub(insn: u32, imm: u32) -> Vec<u32> {
    let pair = insn & 0x3a00_0000 == 0x2800_0000;
    let rt = insn & 0x1f;
    let rt2 = (insn >> 10) & 0x1f;
    let (pre, delta, load) = if pair {
        // opc 00: 32-bit, 01: `ldpsw` (32-bit loads), 10: 64-bit.
        let scale = if insn >> 31 == 1 { 8 } else { 4 };
        let imm7 = (((insn >> 15) & 0x7f) as i32) << 25 >> 25;
        ((insn >> 23) & 3 == 0b11, imm7 * scale, (insn >> 22) & 1 == 1)
    } else {
        let imm9 = (((insn >> 12) & 0x1ff) as i32) << 23 >> 23;
        ((insn >> 11) & 1 == 1, imm9, (insn >> 22) & 3 != 0)
    };
    // The access, from `sp` on entry; the scratch registers saved below it.
    let at = if pre { delta } else { 0 };
    let k = 32 + ((-at).max(0) as u32).div_ceil(16) * 16;
    let mut used = 1u32 << 18 | 1 << rt;
    if pair && rt2 != 31 {
        used |= 1 << rt2;
    }
    let mut regs = free(used);
    let (s1, s2, s3) = (regs.next().unwrap(), regs.next().unwrap(), regs.next().unwrap());
    let x = |r: u32| if r == 18 { s1 } else { r };
    let access = if pair {
        let keep = insn & !(3 << 23) & !(0x7f << 15) & !(0x1f << 10) & !(0x1f << 5) & !0x1f;
        keep | 0b10 << 23 | x(rt2) << 10 | s3 << 5 | x(rt)
    } else {
        (insn & 0xc4c0_0000) | 0x3900_0000 | s3 << 5 | x(rt)
    };
    let mut w = vec![
        SUB_SP | k << 10,
        STP_SP | s2 << 10 | s1,
        STR_UIMM | (2 << 10) | (31 << 5) | s3,
        MRS_TPIDRRO | s2,
        AND_NOT7 | (s2 << 5) | s2,
    ];
    if !load {
        w.push(LDR_UIMM | imm | (s2 << 5) | s1);
    }
    w.extend([ADD_FROM_SP | ((k as i32 + at) as u32) << 10 | s3, access]);
    if load {
        w.push(STR_UIMM | imm | (s2 << 5) | s1);
    }
    w.extend([LDR_UIMM | (2 << 10) | (31 << 5) | s3, LDP_SP | s2 << 10 | s1, ADD_SP | k << 10]);
    match delta {
        0 => {}
        d if d > 0 => w.push(ADD_SP | (d as u32) << 10),
        d => w.push(SUB_SP | ((-d) as u32) << 10),
    }
    w
}

/// Stub for an instruction that writes `sp` from `x18`. The new `sp` is
/// computed in a scratch register, with `x18` from its slot and the
/// original `sp` in a second scratch register, then moved into `sp`; the
/// two scratch registers come back from where they were saved, through the
/// second. Those last two loads read below a new `sp` higher than the
/// old: a signal delivered between the move and them finishes them first
/// (`trap::finish_sp_stub` in the native backend), so its frame cannot
/// overwrite what they read.
fn x18_writes_sp_stub(insn: u32, imm: u32) -> Vec<u32> {
    let (rn, rm) = ((insn >> 5) & 0x1f, (insn >> 16) & 0x1f);
    let simd = insn & 0x1f != 31;
    // Rm is a register in the extended-register and SIMD forms only.
    let has_rm = simd || (insn >> 24) & 0x1f == 0b01011;
    let mut used = 1u32 << 18;
    for (r, is_reg) in [(rn, true), (rm, has_rm)] {
        if is_reg && r != 31 {
            used |= 1 << r;
        }
    }
    let mut regs = free(used);
    let (s1, s2) = (regs.next().unwrap(), regs.next().unwrap());
    let mut w = vec![
        PUSH | s1,
        PUSH | s2,
        MRS_TPIDRRO | s2,
        AND_NOT7 | (s2 << 5) | s2,
        LDR_UIMM | imm | (s2 << 5) | s1,
        ADD_FROM_SP | (32 << 10) | s2,
    ];
    if simd {
        // The access at `sp` without the writeback, then `sp` + `x18`.
        w.push((insn & !(1 << 23) & !(0x1f << 16) & !(0x1f << 5)) | s2 << 5);
        w.push(ADD_REG | s1 << 16 | s2 << 5 | s1);
    } else {
        let sub = |i: u32, shift: u32, r: u32| (i & !(0x1f << shift)) | (r << shift);
        let mut c = sub(insn, 0, s1);
        c = sub(
            c,
            5,
            if rn == 31 {
                s2
            } else if rn == 18 {
                s1
            } else {
                rn
            },
        );
        // The extended-register form's Rm.
        if (insn >> 24) & 0x1f == 0b01011 && rm == 18 {
            c = sub(c, 16, s1);
        }
        w.push(c);
    }
    w.extend([
        MOV_TO_SP | s1 << 5,
        LDUR | (((-16i32) as u32) & 0x1ff) << 12 | s2 << 5 | s1,
        LDUR | (((-32i32) as u32) & 0x1ff) << 12 | s2 << 5 | s2,
    ]);
    w
}

/// Body of the stub for an `x18`-naming instruction (without the final branch
/// back). `x18` lives in the TSD slot whose `ldr`/`str` immediate is `imm`.
fn x18_stub(insn: u32, imm: u32) -> Vec<u32> {
    let ops = crate::decode::operands(insn).expect("x18 site must decode");
    let field_reg = |f: &crate::decode::Field| (insn >> f.shift) & 0x1f;

    // Registers the instruction already uses (real GPRs, not xzr), plus x18.
    let mut used = 1u32 << 18;
    for f in &ops {
        let r = field_reg(f);
        if r != 31 {
            used |= 1 << r;
        }
    }
    // Two scratch registers the instruction does not use: s1 stands in for x18,
    // s2 holds the TSD base. macOS preserves every register but x18 across
    // preemption, so ordinary scratch registers are safe to rely on.
    let pick = |used: u32| (0u32..=30).find(|&r| used & (1 << r) == 0).expect("a free register");
    let s1 = pick(used);
    let s2 = pick(used | (1 << s1));
    // An `sp` operand the push cannot be folded into is replaced by a third
    // scratch register holding `sp` as it was on entry (see
    // [`crate::decode::sp_scratch_field`]).
    let sp_field = crate::decode::sp_scratch_field(insn);
    let sp_base = sp_field.is_some();
    let s3 = pick(used | (1 << s1) | (1 << s2));

    let reads = ops.iter().any(|f| field_reg(f) == 18 && f.read);
    let writes = ops.iter().any(|f| field_reg(f) == 18 && f.write);

    // Start from the instruction with any `sp`-relative offset bumped past the
    // 32 bytes the stub pushes, then replace every x18 operand with s1. The
    // offset fix-up touches only immediate bits, the substitution only the
    // register fields that hold x18 in the original instruction, so the two are
    // independent.
    let mut rewritten = match crate::decode::sp_fixup(insn) {
        crate::decode::SpFixup::Adjusted(a) => a,
        _ if sp_base => {
            let f = sp_field.unwrap_or(5);
            (insn & !(0x1f << f)) | (s3 << f)
        }
        _ => insn,
    };
    for f in &ops {
        if field_reg(f) == 18 {
            rewritten = (rewritten & !(0x1f << f.shift)) | (s1 << f.shift);
        }
    }

    let mut words = vec![PUSH | s1, PUSH | s2];
    if sp_base {
        words.extend([PUSH | s3, ADD_SP_48 | s3]);
    }
    words.extend([MRS_TPIDRRO | s2, AND_NOT7 | (s2 << 5) | s2]);
    if reads {
        words.push(LDR_UIMM | imm | (s2 << 5) | s1);
    }
    words.push(rewritten);
    if writes {
        words.push(STR_UIMM | imm | (s2 << 5) | s1);
    }
    if sp_base {
        words.push(POP | s3);
    }
    words.push(POP | s2);
    words.push(POP | s1);
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// `add x1, sp, x18`: no immediate can absorb the 32-byte push, so a
    /// third scratch register holds `sp` as it was on entry and stands in
    /// for it.
    #[test]
    fn x18_stub_with_sp_in_a_scratch_register() {
        let words = x18_stub(0x8b3263e1, 3 << 10);
        // x1 and x18 are used: s1 = x0, s2 = x2, s3 = x3.
        assert_eq!(
            words,
            vec![
                PUSH,                            // str x0, [sp, #-16]!
                PUSH | 2,                        // str x2, [sp, #-16]!
                PUSH | 3,                        // str x3, [sp, #-16]!
                ADD_SP_48 | 3,                   // add x3, sp, #48
                MRS_TPIDRRO | 2,                 // mrs x2, tpidrro_el0
                AND_NOT7 | (2 << 5) | 2,         // and x2, x2, #~7
                LDR_UIMM | (3 << 10) | (2 << 5), // ldr x0, [x2, #24]
                0x8b206061,                      // add x1, x3, x0 (uxtx)
                POP | 3,
                POP | 2,
                POP,
            ]
        );
    }

    #[test]
    fn trap_encoding() {
        // brk #0x4c58
        assert_eq!(TRAP, 0xd429_8b00);
    }

    #[test]
    fn rewrites_syscalls_in_place() {
        let mov_x8 = 0xd280_0808; // mov x8, #64
        let svc1 = 0xd400_0021; // svc #1
        let mut code = words(&[mov_x8, SVC0, svc1, SVC0]);
        let p = patch(&mut code, None);
        assert_eq!(p.syscalls, 2);
        assert!(p.sites.is_empty());
        assert_eq!(code, words(&[mov_x8, TRAP, svc1, TRAP]));
    }

    #[test]
    fn finds_thread_pointer_accesses() {
        let mut code = words(&[
            0xd53b_d049, // mrs x9, tpidr_el0
            0xd51b_d040, // msr tpidr_el0, x0
            0xd53b_d05f, // mrs xzr, tpidr_el0
            0xd53b_d060, // mrs x0, tpidrro_el0 (left alone)
        ]);
        let p = patch(&mut code, None);
        assert_eq!(
            p.sites,
            vec![(0, Site::ReadThreadPointer { rt: 9 }), (4, Site::WriteThreadPointer { rt: 0 }),]
        );
        assert_eq!(&code[8..12], &NOP.to_le_bytes());
        assert_eq!(&code[12..16], &0xd53b_d060u32.to_le_bytes());
    }

    #[test]
    fn ignores_unaligned_matches() {
        let mut code = vec![0u8; 2];
        code.extend_from_slice(&SVC0.to_le_bytes());
        code.extend_from_slice(&[0, 0]);
        assert_eq!(patch(&mut code, None), Patched::default());
    }

    #[test]
    fn branch_encoding_and_range() {
        assert_eq!(branch(0x1000, 0x1008), Some(0x1400_0002));
        assert_eq!(branch(0x1008, 0x1000), Some(0x17ff_fffe));
        assert_eq!(branch(0, BRANCH_RANGE), None);
        assert!(branch(BRANCH_RANGE, 0).is_some());
        assert_eq!(branch(0, 2), None);
    }

    // Encodings checked against llvm-mc.
    #[test]
    fn read_stub_encoding() {
        let s = stub(Site::ReadThreadPointer { rt: 5 }, 16, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xd53b_d065, // mrs x5, tpidrro_el0
                0x927d_f0a5, // and x5, x5, #0xfffffffffffffff8
                0xf940_08a5, // ldr x5, [x5, #16]
                branch(0x200c, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn write_stub_encoding() {
        let s = stub(Site::WriteThreadPointer { rt: 0 }, 8, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0ff0, // str x16, [sp, #-16]!
                0xd53b_d070, // mrs x16, tpidrro_el0
                0x927d_f210, // and x16, x16, #0xfffffffffffffff8
                0xf900_0600, // str x0, [x16, #8]
                0xf841_07f0, // ldr x16, [sp], #16
                branch(0x2014, 0x1004).unwrap(),
            ]
        );
        // Writing x16 uses x17 as scratch.
        let s = stub(Site::WriteThreadPointer { rt: 16 }, 8, 24, 0x2000, 0x1004);
        assert_eq!(s[0], 0xf81f_0ff1);
    }

    #[test]
    fn x18_read_stub() {
        // mov x10, x18 (orr x10, xzr, x18): reads x18 via Rm. x0/x1 are free,
        // so s1=x0 (stands in for x18), s2=x1 (TSD base). x18 slot 24 -> imm 3.
        let s = stub(Site::X18 { insn: 0xaa1203ea }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0, // str x0, [sp, #-16]!
                0xf81f_0fe1, // str x1, [sp, #-16]!
                0xd53b_d061, // mrs x1, tpidrro_el0
                0x927d_f021, // and x1, x1, #~7
                0xf940_0c20, // ldr x0, [x1, #24]
                0xaa00_03ea, // orr x10, xzr, x0  (x18 -> x0)
                0xf841_07e1, // ldr x1, [sp], #16
                0xf841_07e0, // ldr x0, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn x18_write_stub() {
        // movz x18, #0x1818: writes x18 via Rd. s1=x0, s2=x1.
        let s = stub(Site::X18 { insn: 0xd2830312 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0, // str x0, [sp, #-16]!
                0xf81f_0fe1, // str x1, [sp, #-16]!
                0xd53b_d061, // mrs x1, tpidrro_el0
                0x927d_f021, // and x1, x1, #~7
                0xd283_0300, // movz x0, #0x1818  (x18 -> x0)
                0xf900_0c20, // str x0, [x1, #24]
                0xf841_07e1, // ldr x1, [sp], #16
                0xf841_07e0, // ldr x0, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn x18_adr_stub_materializes_value() {
        // adr x18, . at site 0x1000 -> target 0x1000. s1=x0, s2=x1.
        let s = stub(Site::X18 { insn: 0x10000012 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0, // str x0, [sp, #-16]!
                0xf81f_0fe1, // str x1, [sp, #-16]!
                0xd53b_d061, // mrs x1, tpidrro_el0
                0x927d_f021, // and x1, x1, #~7
                0xd282_0000, // movz x0, #0x1000
                0xf2a0_0000, // movk x0, #0, lsl #16
                0xf2c0_0000, // movk x0, #0, lsl #32
                0xf2e0_0000, // movk x0, #0, lsl #48
                0xf900_0c20, // str x0, [x1, #24]
                0xf841_07e1, // ldr x1, [sp], #16
                0xf841_07e0, // ldr x0, [sp], #16
                branch(0x2000 + 11 * 4, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn x18_indirect_blr_stub() {
        // blr x18 at site 0x1000: target from slot into x16, lr = 0x1004, br x16.
        let s = stub(Site::X18 { insn: 0xd63f0240 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xd53b_d070, // mrs x16, tpidrro_el0
                0x927d_f210, // and x16, x16, #~7
                0xf940_0e10, // ldr x16, [x16, #24]
                0xd282_009e, // movz x30, #0x1004
                0xf2a0_001e, // movk x30, #0, lsl #16
                0xf2c0_001e, // movk x30, #0, lsl #32
                0xf2e0_001e, // movk x30, #0, lsl #48
                0xd61f_0200, // br x16
            ]
        );
    }

    #[test]
    fn x18_compare_branch_stub() {
        // cbnz x18, #8 at site 0x1000 (target 0x1008). s1=x0, s2=x1.
        let s = stub(Site::X18 { insn: 0xb5000052 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0,                              // str x0, [sp, #-16]!
                0xf81f_0fe1,                              // str x1, [sp, #-16]!
                0xd53b_d061,                              // mrs x1, tpidrro_el0
                0x927d_f021,                              // and x1, x1, #~7
                0xf940_0c20,                              // ldr x0, [x1, #24]   (x18)
                0xb500_0080,                              // cbnz x0, #16        (-> taken, word 9)
                0xf841_07e1,                              // ldr x1, [sp], #16   (not taken)
                0xf841_07e0,                              // ldr x0, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),  // b site+4
                0xf841_07e1,                              // ldr x1, [sp], #16   (taken)
                0xf841_07e0,                              // ldr x0, [sp], #16
                branch(0x2000 + 11 * 4, 0x1008).unwrap(), // b target
            ]
        );
    }

    #[test]
    fn x18_three_source_stub() {
        // madd x18, x0, x1, x2: x18 is the destination (Rd). Rn/Rm/Ra = x0/x1/x2
        // are used, so s1=x3 (stands in for x18), s2=x4 (TSD base). No read of
        // x18, so the result is just stored to the slot.
        let s = stub(Site::X18 { insn: 0x9b010812 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe3, // str x3, [sp, #-16]!
                0xf81f_0fe4, // str x4, [sp, #-16]!
                0xd53b_d064, // mrs x4, tpidrro_el0
                0x927d_f084, // and x4, x4, #~7
                0x9b01_0803, // madd x3, x0, x1, x2   (x18 -> x3)
                0xf900_0c83, // str x3, [x4, #24]      (x18 slot)
                0xf841_07e4, // ldr x4, [sp], #16
                0xf841_07e3, // ldr x3, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn x18_load_from_sp_stub() {
        // ldr x18, [sp, #16]: load into x18 from the stack. s1=x0, s2=x1. The
        // stub pushes 32 bytes, so the reload becomes ldr x0, [sp, #48], and
        // the result is stored to the x18 slot.
        let s = stub(Site::X18 { insn: 0xf9400bf2 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0, // str x0, [sp, #-16]!
                0xf81f_0fe1, // str x1, [sp, #-16]!
                0xd53b_d061, // mrs x1, tpidrro_el0
                0x927d_f021, // and x1, x1, #~7
                0xf940_1be0, // ldr x0, [sp, #48]   (16 + 32)
                0xf900_0c20, // str x0, [x1, #24]   (x18 slot)
                0xf841_07e1, // ldr x1, [sp], #16
                0xf841_07e0, // ldr x0, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),
            ]
        );
    }

    #[test]
    fn x18_store_to_base_stub() {
        // str x18, [x1, #8]: store x18 through x1. x0 and x1 are used, so
        // s1=x0 (stands in for x18), s2=x2 (TSD base). x18 is loaded from the
        // slot and stored via the rewritten str x0, [x1, #8].
        let s = stub(Site::X18 { insn: 0xf9000432 }, 0, 24, 0x2000, 0x1004);
        assert_eq!(
            s,
            vec![
                0xf81f_0fe0, // str x0, [sp, #-16]!
                0xf81f_0fe2, // str x2, [sp, #-16]!
                0xd53b_d062, // mrs x2, tpidrro_el0
                0x927d_f042, // and x2, x2, #~7
                0xf940_0c40, // ldr x0, [x2, #24]   (x18 slot)
                0xf900_0420, // str x0, [x1, #8]
                0xf841_07e2, // ldr x2, [sp], #16
                0xf841_07e0, // ldr x0, [sp], #16
                branch(0x2000 + 8 * 4, 0x1004).unwrap(),
            ]
        );
    }

    /// The `x18` stubs of their own, as `llvm-mc` assembles their listings
    /// (stub at 0x1000, returning to 0x2004; thread pointer in slot 0x10,
    /// `x18` in 0x18).
    #[test]
    fn x18_stubs_for_sp_pairs_and_authenticated_branches() {
        let stub_of = |site: Site| {
            let mut w = stub(site, 0x10, 0x18, 0x1000, 0x2004);
            w.pop(); // the branch back
            w
        };
        // str x18, [sp, #-16]!: the access below the saves, sp moved after.
        assert_eq!(
            stub_of(Site::X18 { insn: 0xf81f0ff2 }),
            [
                0xd100c3ff, 0xa90007e0, 0xf9000be2, 0xd53bd061, 0x927df021, 0xf9400c20, 0x910083e2,
                0xf9000040, 0xf9400be2, 0xa94007e0, 0x9100c3ff, 0xd10043ff
            ]
        );
        // mov sp, x18: sp set last, the scratch registers read back after.
        assert_eq!(
            stub_of(Site::X18 { insn: 0x9100025f }),
            [
                0xf81f0fe0, 0xf81f0fe1, 0xd53bd061, 0x927df021, 0xf9400c20, 0x910083e1, 0x91000000,
                0x9100001f, 0xf85f0020, 0xf85e0021
            ]
        );
        // casp x18, x19, x2, x3, [x0]: an even pair of scratch registers.
        assert_eq!(
            stub_of(Site::X18 { insn: 0x48327c02 }),
            [
                0xa9bf17e4, 0xa9bf1be1, 0xd53bd061, 0x927df021, 0xf9400c24, 0xaa1303e5, 0x48247c02,
                0xf9000c24, 0xaa0503f3, 0xa8c11be1, 0xa8c117e4
            ]
        );
        // braa x18, x1 through x16; braa x18, x16 through x17.
        assert_eq!(
            stub(Site::X18 { insn: 0xd71f0a41 }, 0x10, 0x18, 0x1000, 0x2004),
            [0xd53bd070, 0x927df210, 0xf9400e10, 0xd71f0a01]
        );
        assert_eq!(stub(Site::X18 { insn: 0xd71f0a50 }, 0x10, 0x18, 0x1000, 0x2004)[3], 0xd71f0a30);
        // mrs x18, tpidr_el0: from the thread pointer's slot to x18's.
        let tp = stub_of(Site::ReadThreadPointer { rt: 18 });
        assert_eq!(&tp[4..6], [0xf9400820, 0xf9000c20]);
        let tp = stub_of(Site::WriteThreadPointer { rt: 18 });
        assert_eq!(&tp[4..6], [0xf9400c20, 0xf9000820]);
    }

    #[test]
    fn literal_pool_words_are_not_rewritten() {
        // ldr x0, <+8> makes the two words at offset 8 a literal pool. The
        // first pool word encodes `movz x18` but must be left as data.
        let mut code = words(&[
            0x5800_0040, // ldr x0, #8  (target = this + 8)
            0xd280_0000, // movz x0, #0 (filler)
            0xd283_0312, // data that looks like movz x18
            0x0000_0000, // data
        ]);
        let p = patch(&mut code, None);
        assert!(p.sites.is_empty(), "literal-pool data must not become a site");
        assert_eq!(p.x18_deferred, 0);
        // The data word is untouched.
        assert_eq!(&code[8..12], &0xd283_0312u32.to_le_bytes());
    }

    /// Outside the known code (what the unwind table covers), a word that
    /// looks like an `x18` instruction is data — a constant table kept
    /// among hand-written assembly — and stays as it is; system calls are
    /// still translated.
    #[test]
    fn x18_lookalikes_outside_known_code_are_data() {
        let mut code = words(&[
            0xd283_0312, // movz x18, #0x1818: code, rewritten
            0xd400_0001, // svc #0: code
            0xd283_0312, // the same word in a table: data
            0x3956_c25b, // a SHA-256 constant that decodes as `ldrb w27, [x18, ...]`
        ]);
        let p = patch(&mut code, Some(&[(0, 8)]));
        assert_eq!(p.sites.iter().map(|s| s.0).collect::<Vec<_>>(), vec![0]);
        assert_eq!(p.syscalls, 1);
        assert_eq!(p.x18_deferred, 0);
        assert_eq!(&code[8..16], &words(&[0xd283_0312, 0x3956_c25b])[..]);
    }

    /// A data word that happens to decode as a literal load does not make a
    /// real instruction it "targets" into data (it hid an `x18` use in
    /// OpenSSL's MD5 from the rewrite).
    #[test]
    fn literal_lookalikes_in_data_hide_no_code() {
        let mut code = words(&[
            0x1392_2a52, // ror w18, w18, #10: code
            0xd65f_03c0, // ret
            0x58ff_ffc0, // data that decodes as `ldr x0, #-8`, aimed at the ror
        ]);
        let p = patch(&mut code, Some(&[(0, 8)]));
        assert_eq!(p.sites.iter().map(|s| s.0).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn x18_sites_and_deferrals_counted() {
        let mut code = words(&[
            0xd2830312, // movz x18, #0x1818   -> rewritable site
            0xaa1203ea, // mov x10, x18        -> rewritable site
            0xf9400012, // ldr x18, [x0]       -> rewritable site (load/store)
            0x90000012, // adrp x18, .         -> site (PC-relative)
            0xf8010ff2, // str x18, [sp, #16]! -> site (sp writeback)
            0x9adf13f2, // irg x18, sp         -> deferred (memory tagging)
            0xd2800000, // movz x0, #0         -> untouched
        ]);
        let p = patch(&mut code, None);
        assert_eq!(p.sites.len(), 5);
        assert_eq!(p.x18_deferred, 1);
        assert!(matches!(p.sites[0].1, Site::X18 { insn: 0xd2830312 }));
    }
}
