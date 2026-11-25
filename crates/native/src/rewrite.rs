//! Rewriting guest code so it can run inside a macOS process.
//!
//! Before guest code becomes executable, instructions whose behaviour on
//! macOS differs from Linux are replaced:
//!
//! - `svc #0` (a Linux system call) would enter the macOS kernel. It becomes
//!   a branch to a stub that calls fwe's system-call gate directly (see
//!   [`crate::gate`]), which runs the Linux system call and returns past the
//!   site. Where no stub can be placed it becomes a `brk` with a distinctive
//!   immediate instead, whose trap fwe's handler services the same way.
//! - `mrs`/`msr` of `TPIDR_EL0` (the Linux thread pointer): macOS does not
//!   preserve `TPIDR_EL0` for user code. Each access becomes a branch to a
//!   short stub that reads or writes the guest thread pointer in a per-thread
//!   slot instead. The slot lives in the host thread's TSD, which macOS points
//!   `TPIDRRO_EL0` at; that register is per-thread and read-only to us.
//! - Any instruction naming `x18`: macOS clears `x18` on every exception
//!   return, so each such instruction becomes a branch to a stub that keeps
//!   the guest's `x18` in another TSD slot (see [`crate::decode`]).
//! - `ic ivau, xN`: the program says it changed the code at that cache
//!   line. The stub runs it and tells fwe through the system-call gate,
//!   which drops the translations made from that line (see
//!   [`crate::jit`]).
//!
//! A stub keeps the registers it uses in the host thread's TSD, never
//! below the program's `sp`, whose memory is the program's: a Linux system
//! call, like any of these instructions on Linux, leaves it as it was
//! ([`TSD18`]). A thread stopped in a stub (a signal, a fault) is made the
//! program's state, as at the site or past it ([`to_guest`]).
//!
//! arm64 instructions are 4 bytes and 4-byte aligned, so scanning aligned
//! words finds every instruction exactly. A data word that happens to match
//! one of these encodings would be rewritten too, so callers pass only
//! executable sections, and literal pools inside them are skipped.

/// `svc #0`.
pub const SVC0: u32 = 0xd400_0001;

/// Whether `insn` is an `svc`, whatever its immediate: Linux takes any as
/// a system call (macOS's own calls use `svc #0x80`).
pub fn is_svc(insn: u32) -> bool {
    insn & 0xffe0_001f == SVC0
}

/// Immediate of the trap instruction that replaces `svc #0` ("LX").
pub const TRAP_IMM: u32 = 0x4c58;

/// `brk #TRAP_IMM`.
pub const TRAP: u32 = 0xd420_0000 | (TRAP_IMM << 5);

pub(crate) const NOP: u32 = 0xd503_201f;
pub(crate) const RT_MASK: u32 = 0x1f;
/// `mrs xN, tpidr_el0`
pub(crate) const MRS_TPIDR: u32 = 0xd53b_d040;
/// `msr tpidr_el0, xN`
pub(crate) const MSR_TPIDR: u32 = 0xd51b_d040;
/// `mrs xN, tpidrro_el0`
pub(crate) const MRS_TPIDRRO: u32 = 0xd53b_d060;
/// `and xD, xN, #~7`
pub(crate) const AND_NOT7: u32 = 0x927d_f000;
/// `ldr xT, [xN, #imm]` (unsigned offset, imm/8 in bits 10..22)
pub(crate) const LDR_UIMM: u32 = 0xf940_0000;
/// `str xT, [xN, #imm]` (unsigned offset)
pub(crate) const STR_UIMM: u32 = 0xf900_0000;
/// `mov xD, xM` (`orr xD, xzr, xM`); `| (m << 16) | d`.
pub(crate) const MOV: u32 = 0xaa00_03e0;
/// `b <label>`
pub(crate) const B: u32 = 0x1400_0000;
/// `movz xN, #imm16` base; `| (hw << 21) | (imm16 << 5) | n`.
pub(crate) const MOVZ: u32 = 0xd280_0000;
/// `movk xN, #imm16` base.
pub(crate) const MOVK: u32 = 0xf280_0000;

/// Largest stub, in instructions: a `casp` naming `x18` in its pair and as
/// its base.
pub const STUB_WORDS: usize = 18;

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
    /// `svc #0`, already a `brk` ([`TRAP`]) in place: the stub calls the
    /// system-call gate at `gate` (0 until the caller knows it).
    Syscall { gate: u64 },
    /// `ic ivau, xN`: the stub runs it and calls the gate at `gate` (as
    /// [`Site::Syscall`]'s), which takes it for a flush of that line.
    Flush { rt: u32, gate: u64 },
}

/// `ic ivau, xN`; `| n`.
pub const IC_IVAU: u32 = 0xd50b_7520;

/// Whether `insn` is `ic ivau, xN`: the program invalidating the
/// instruction cache line at `xN`, as a program does after writing code there.
pub fn is_ic_ivau(insn: u32) -> bool {
    insn & !RT_MASK == IC_IVAU
}

/// Whether `insn` names `x18` in an operand position this pass can rewrite by
/// substituting a scratch register.
fn rewritable_x18(insn: u32) -> bool {
    crate::decode::operands(insn)
        .is_some_and(|ops| ops.iter().any(|f| (insn >> f.shift) & 0x1f == 18))
}

/// Whether `insn` is any instruction naming `x18` that this pass rewrites —
/// operand substitution, a PC-relative form, a branch, or an indirect branch.
pub(crate) fn x18_site(insn: u32) -> bool {
    // Most words name no x18, which the quick check tells.
    crate::decode::may_name_x18(insn) && x18_form(insn)
}

/// [`x18_site`] by decoding alone.
fn x18_form(insn: u32) -> bool {
    use crate::decode::*;
    rewritable_x18(insn)
        || x18_branch(insn)
        || x18_adr(insn).is_some()
        || x18_ldr_literal(insn)
        || x18_indirect(insn).is_some()
        || x18_casp(insn)
        || x18_writes_sp(insn)
}

/// Result of rewriting a block of code in place.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Patched {
    pub syscalls: usize,
    /// Offsets (from the start of the block) of instructions that are
    /// redirected to stubs.
    pub sites: Vec<(u64, Site)>,
    /// Count of instructions that name `x18` but are left alone (the `sp`
    /// writeback and `sp` register-offset load/store forms, and data-processing
    /// forms with an `sp` operand). Diagnostic only.
    pub x18_deferred: usize,
    /// Each word that was changed in place or is a site: its offset, what
    /// it was, and whether it was taken for code and known to be code,
    /// which is all [`replay`] needs to do the same again.
    pub noted: Vec<Noted>,
}

/// A word [`patch`] noted: its offset, what it was, and its flags.
pub type Noted = (u64, u32, u8);

/// [`Patched::noted`]'s flags.
const IS_CODE: u8 = 1;
const KNOWN_CODE: u8 = 2;

/// What [`patch`] does with word `insn`: its replacement in place, the
/// site it is, and whether it counts as a system call or as an `x18` use
/// left alone.
struct Word {
    replacement: Option<u32>,
    site: Option<Site>,
    syscall: bool,
    deferred: bool,
}

fn classify(insn: u32, is_code: bool, known_code: bool) -> Word {
    let mut w = Word { replacement: None, site: None, syscall: false, deferred: false };
    if insn == SVC0 || (is_svc(insn) && known_code) {
        w.syscall = true;
        w.site = Some(Site::Syscall { gate: 0 });
        w.replacement = Some(TRAP);
    } else if insn & !RT_MASK == MRS_TPIDR {
        let rt = insn & RT_MASK;
        if rt == 31 {
            // Reading into xzr has no effect.
            w.replacement = Some(NOP);
        } else {
            w.site = Some(Site::ReadThreadPointer { rt });
        }
    } else if insn & !RT_MASK == MSR_TPIDR {
        w.site = Some(Site::WriteThreadPointer { rt: insn & RT_MASK });
    } else if is_code && is_ic_ivau(insn) {
        w.site = Some(Site::Flush { rt: insn & RT_MASK, gate: 0 });
    } else if is_code && x18_site(insn) {
        w.site = Some(Site::X18 { insn });
    } else if is_code && crate::decode::names_x18(insn) {
        w.deferred = true;
    }
    w
}

/// What [`replay`] would do, without touching the code: the sites, and
/// for every word noted its offset, what it was and what it is to be (the
/// same for a site, which its stub's branch replaces later).
pub fn plan(noted: &[Noted], x18_deferred: usize) -> (Patched, Vec<(u64, u32, u32)>) {
    let mut out = Patched { x18_deferred, ..Patched::default() };
    let mut words = Vec::with_capacity(noted.len());
    for &(off, orig, flags) in noted {
        let w = classify(orig, flags & IS_CODE != 0, flags & KNOWN_CODE != 0);
        if w.syscall {
            out.syscalls += 1;
        }
        if let Some(site) = w.site {
            out.sites.push((off, site));
        }
        words.push((off, orig, w.replacement.unwrap_or(orig)));
    }
    out.noted = noted.to_vec();
    (out, words)
}

/// Do again in `code` what [`patch`] did to the same code, from its
/// [`Patched::noted`] and `x18_deferred`, touching only the words noted.
/// `None`, with `code` untouched, if a noted word is not what it was.
pub fn replay(code: &mut [u8], noted: &[Noted], x18_deferred: usize) -> Option<Patched> {
    let word = |code: &[u8], off: u64| -> Option<u32> {
        let at = usize::try_from(off).ok()?;
        Some(u32::from_le_bytes(code.get(at..at.checked_add(4)?)?.try_into().ok()?))
    };
    if noted.iter().any(|&(off, orig, _)| word(code, off) != Some(orig)) {
        return None;
    }
    let mut out = Patched { x18_deferred, ..Patched::default() };
    for &(off, orig, flags) in noted {
        let w = classify(orig, flags & IS_CODE != 0, flags & KNOWN_CODE != 0);
        if w.syscall {
            out.syscalls += 1;
        }
        if let Some(site) = w.site {
            out.sites.push((off, site));
        }
        if let Some(r) = w.replacement {
            let at = off as usize;
            code[at..at + 4].copy_from_slice(&r.to_le_bytes());
        }
    }
    out.noted = noted.to_vec();
    Some(out)
}

/// Rewrite what can be rewritten in place and collect the rest. `code`
/// MUST start at a 4-byte aligned address. `known`, when given, is the
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
    // An `svc` with an immediate other than 0 only where the image's tables
    // say there is code: as data it is likelier than `svc #0`'s one word.
    let known_code = |i: usize| known.is_some() && is_code[i];
    for (i, word) in code.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        // Words that belong to a literal pool are data, not instructions, and a
        // constant can encode anything — they are never rewritten.
        if data[i] {
            continue;
        }
        let insn = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        let w = classify(insn, is_code[i], known_code(i));
        if w.syscall {
            out.syscalls += 1;
        }
        if w.deferred {
            out.x18_deferred += 1;
        }
        if let Some(site) = w.site {
            out.sites.push((i as u64 * 4, site));
        }
        let replacement = w.replacement;
        if replacement.is_some() || w.site.is_some() {
            let flags = (u8::from(is_code[i]) * IS_CODE) | (u8::from(known_code(i)) * KNOWN_CODE);
            out.noted.push((i as u64 * 4, insn, flags));
        }
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
    for (i, w) in code.as_chunks::<4>().0.iter().enumerate() {
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
    code.as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .filter(|&i| {
            is_svc(i)
                || (i & !RT_MASK == MRS_TPIDR && i & RT_MASK != 31)
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

/// How many registers a stub keeps in the thread's scratch slots at most.
pub const SCRATCH: usize = 3;

/// The host TSD slots stubs use, as byte offsets from the TSD base that
/// `TPIDRRO_EL0` points to: the program's thread pointer, its `x18`, and
/// the scratch slots a stub keeps the program's registers in while it uses
/// them (`scratch[0]` and `scratch[1]` hold `x30` and `x0` across a
/// system call's call into the gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slots {
    pub tp: u32,
    pub x18: u32,
    pub scratch: [u32; SCRATCH],
}

/// The `ldr`/`str` unsigned-offset immediate field for TSD slot `slot`.
fn imm(slot: u32) -> u32 {
    assert!(slot.is_multiple_of(8) && slot / 8 < 4096, "slot offset must fit an ldr/str immediate");
    (slot / 8) << 10
}

/// `mrs x18, tpidrro_el0; and x18, x18, #~7`: the thread's TSD base into
/// `x18`, opening a group of accesses through it.
///
/// No stub of fwe's touches memory below the program's `sp`, which is the
/// program's (Go keeps a new thread's start there across its first system
/// call), so a stub keeps the registers it uses in TSD slots, and the
/// first one, before any register is free, goes there through `x18`.
/// `x18` is fwe's: every instruction of the program naming it is
/// rewritten, the program's `x18` kept in a slot. The host zeroes `x18`
/// whenever it enters the kernel, and maps nothing in the low 4 GiB, so an
/// access through `x18` after that faults, and the fault handler starts
/// the group again from its `mrs` ([`restart_at`]). So a group run again
/// from its start does the same: a register it stores and loads is loaded
/// by its last access, after which nothing of the group faults.
pub const TSD18: [u32; 2] = [MRS_TPIDRRO | 18, AND_NOT7 | 18 << 5 | 18];

/// `str xR, [x18, #slot]`.
fn str18(r: u32, slot: u32) -> u32 {
    STR_UIMM | imm(slot) | 18 << 5 | r
}

/// `ldr xR, [x18, #slot]`.
fn ldr18(r: u32, slot: u32) -> u32 {
    LDR_UIMM | imm(slot) | 18 << 5 | r
}

/// Whether `w` is an `ldr`/`str` of a general register at an unsigned
/// offset from `x18`: an access of a group ([`TSD18`]).
fn through_x18(w: u32) -> bool {
    matches!(w & 0xffc0_0000, STR_UIMM | LDR_UIMM) && (w >> 5) & 0x1f == 18
}

/// Where a thread whose access through `x18` at `pc` faulted starts again
/// ([`TSD18`]): its group's `mrs x18`, before the accesses through `x18`
/// that lead to `pc`. `None` if `pc` holds no such access, or is in no
/// group (`word` reads the code, `None` where nothing is mapped).
pub fn restart_at(word: impl Fn(u64) -> Option<u32>, pc: u64) -> Option<u64> {
    if !through_x18(word(pc)?) {
        return None;
    }
    let mut at = pc;
    for _ in 0..8 {
        at = at.checked_sub(4)?;
        let w = word(at)?;
        if w == TSD18[1] {
            let mrs = at.checked_sub(4)?;
            return (word(mrs)? == TSD18[0]).then_some(mrs);
        }
        if !through_x18(w) {
            return None;
        }
    }
    None
}

/// The stub for `site`, placed at `stub`, returning to `ret`, with the TSD
/// slots `slots`.
pub fn stub(site: Site, slots: Slots, stub: u64, ret: u64) -> Vec<u32> {
    match site {
        // Indirect and compare/test branches through x18, and system calls:
        // complete stubs of their own, with their own ways out.
        // A plain `br x18`, which can lead on in the same function with
        // `x16` and `x17` live: into fwe, and on by translation.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Site::X18 { insn: BR_X18 } => return crate::jit::x18_branch_stub(ret - 4, stub),
        Site::X18 { insn } if crate::decode::x18_indirect(insn).is_some() => {
            return x18_indirect_stub(insn, imm(slots.x18), ret);
        }
        Site::X18 { insn } if crate::decode::x18_branch(insn) => {
            return x18_branch_stub(insn, slots, stub, ret);
        }
        Site::Syscall { gate } => return syscall_stub(gate, slots, stub, ret),
        Site::Flush { rt, gate } => return flush_stub(rt, gate, slots, stub, ret),
        _ => {}
    }
    let mut words = stub_body(site, slots, ret - 4);
    let at = stub + 4 * words.len() as u64;
    words.push(branch(at, ret).expect("stub placed within branch range of its site"));
    assert!(words.len() <= STUB_WORDS, "a stub longer than its slot");
    words
}

/// The words of the stub for `site` (a thread-pointer access, or an
/// instruction naming `x18` other than a branch), for the instruction at
/// `pc`, without the branch back: they run on into what follows them.
pub(crate) fn stub_body(site: Site, slots: Slots, pc: u64) -> Vec<u32> {
    let ret = pc + 4;
    let [s0, ..] = slots.scratch;
    match site {
        // Through `x18`: from one slot to the other, through a register
        // kept meanwhile. The copy is a group of its own, which does the
        // same run again.
        Site::ReadThreadPointer { rt: 18 } | Site::WriteThreadPointer { rt: 18 } => {
            let (from, to) = match site {
                Site::ReadThreadPointer { .. } => (slots.tp, slots.x18),
                _ => (slots.x18, slots.tp),
            };
            let s = 0;
            let mut w = TSD18.to_vec();
            w.push(str18(s, s0));
            w.extend(TSD18);
            w.extend([ldr18(s, from), str18(s, to)]);
            w.extend(TSD18);
            w.push(ldr18(s, s0));
            w
        }
        Site::ReadThreadPointer { rt } => {
            let i = imm(slots.tp);
            vec![MRS_TPIDRRO | rt, AND_NOT7 | (rt << 5) | rt, LDR_UIMM | i | (rt << 5) | rt]
        }
        Site::WriteThreadPointer { rt } => {
            let mut w = TSD18.to_vec();
            w.push(str18(rt, slots.tp));
            w
        }
        Site::X18 { insn }
            if crate::decode::x18_indirect(insn).is_some() || crate::decode::x18_branch(insn) =>
        {
            panic!("a branch through x18 has a stub of its own")
        }
        // PC-relative forms materialize the value computed from the original pc.
        Site::X18 { insn } if crate::decode::x18_adr(insn).is_some() => {
            x18_adr_stub(insn, slots, ret)
        }
        Site::X18 { insn } if crate::decode::x18_ldr_literal(insn) => {
            x18_ldr_literal_stub(insn, slots, ret)
        }
        Site::X18 { insn } if crate::decode::x18_casp(insn) => x18_casp_stub(insn, slots),
        Site::X18 { insn } => {
            let (main, s, reads, writes) = x18_rename(insn);
            x18_template(main, s, reads, writes, slots)
        }
        Site::Syscall { .. } => panic!("a system call has a stub of its own"),
        Site::Flush { .. } => panic!("a flush has a stub of its own"),
    }
}

/// `ldr x30, <pc + 24>`: the gate's address, the literal at word 10 of a
/// system call's stub, read from word 4.
pub const LDR_X30_LIT: u32 = 0x5800_0000 | (6 << 5) | 30;
/// `ldr x30, <pc + 28>`: the gate's address, the literal at word 12 of a
/// flush's stub, read from word 5. It tells the gate the call is a flush.
pub const FLUSH_LDR_X30_LIT: u32 = 0x5800_0000 | (7 << 5) | 30;
/// `blr x30`
pub const BLR_X30: u32 = 0xd63f_03c0;

/// Words of a system call's stub, its literal's included.
pub const SYSCALL_STUB_WORDS: usize = 12;
/// Words of a flush's stub, its literal's included.
pub const FLUSH_STUB_WORDS: usize = 14;
/// Where in a system call's stub its call into the gate is: before it,
/// the call is not made, and a thread stopped there makes it again from
/// the site; after it, the stub finishes.
pub const SYSCALL_STUB_CALL: usize = 5;
/// [`SYSCALL_STUB_CALL`] for a flush's stub.
pub const FLUSH_STUB_CALL: usize = 6;

/// The calling words of a system call's or a flush's stub: `x30` and `x0`
/// kept in their scratch slots (the gate saves the rest), the gate called
/// through `x30` (its address the literal `lit` loads), `x30` taken back,
/// and back past the site from `at`.
fn gate_call(lit: u32, slots: Slots, at: u64, ret: u64) -> [u32; 10] {
    let [s30, s0, _] = slots.scratch;
    [
        TSD18[0],
        TSD18[1],
        str18(30, s30),
        str18(0, s0),
        lit,
        BLR_X30,
        TSD18[0],
        TSD18[1],
        ldr18(30, s30),
        branch(at + 36, ret).expect("stub placed within branch range of its site"),
    ]
}

/// Stub for `svc #0`: [`gate_call`], then the gate's address. The gate
/// returns here only when the call changed nothing but `x0`; any other
/// outcome it installs itself. `stub` is 8-byte aligned.
fn syscall_stub(gate: u64, slots: Slots, stub: u64, ret: u64) -> Vec<u32> {
    debug_assert!(stub.is_multiple_of(8), "a system-call stub's literal must be aligned");
    let mut w = gate_call(LDR_X30_LIT, slots, stub, ret).to_vec();
    w.extend([gate as u32, (gate >> 32) as u32]);
    debug_assert_eq!(w.len(), SYSCALL_STUB_WORDS);
    w
}

/// Stub for `ic ivau, xN`: the instruction itself (where it can fault, as
/// at its site; through `x18`, whose value only the gate knows, it is the
/// gate's), then the gate called as by a system call's stub, and back past
/// the site. The gate knows a flush by the stub's literal load
/// ([`flush_reg`]). `stub` is 8-byte aligned.
fn flush_stub(rt: u32, gate: u64, slots: Slots, stub: u64, ret: u64) -> Vec<u32> {
    debug_assert!(stub.is_multiple_of(8), "a flush stub's literal must be aligned");
    let mut w = vec![if rt == 18 { NOP } else { IC_IVAU | rt }];
    w.extend(gate_call(FLUSH_LDR_X30_LIT, slots, stub + 4, ret));
    w.extend([NOP, gate as u32, (gate >> 32) as u32]);
    debug_assert_eq!(w.len(), FLUSH_STUB_WORDS);
    w
}

/// The system-call site of the stub whose call into the gate returns to
/// `ret`: its branch back, three words on, goes past it.
pub fn syscall_site_of(word: impl Fn(u64) -> u32, ret: u64) -> u64 {
    let b = word(ret + 12);
    let offset = i64::from(((b << 6) as i32) >> 4);
    (ret + 12).wrapping_add_signed(offset) - 4
}

/// The register a flush's stub names, if the gate was called from one
/// (`word(ret - 8)`, the word that loaded the gate's address, says), its
/// call returning to `ret`.
pub fn flush_reg(word: impl Fn(u64) -> u32, ret: u64) -> Option<u32> {
    if word(ret - 8) != FLUSH_LDR_X30_LIT {
        return None;
    }
    let w = word(ret - 4 * (FLUSH_STUB_CALL as u64 + 1));
    Some(if w == NOP { 18 } else { w & RT_MASK })
}

/// The program's `x18` into scratch register `s` (`x18`'s stand-in), `s`
/// kept first: a group that loads after it stores.
fn x18_in(s: u32, reads: bool, slots: Slots) -> Vec<u32> {
    let mut w = TSD18.to_vec();
    w.push(str18(s, slots.scratch[0]));
    if reads {
        w.push(ldr18(s, slots.x18));
    }
    w
}

/// Scratch register `s` into the program's `x18` where `writes`, and `s`
/// taken back: a group that stores before it loads.
fn x18_out(s: u32, writes: bool, slots: Slots) -> Vec<u32> {
    let mut w = TSD18.to_vec();
    if writes {
        w.push(str18(s, slots.x18));
    }
    w.push(ldr18(s, slots.scratch[0]));
    w
}

/// The stub body for an instruction naming `x18`, `main` being the
/// instruction with scratch register `s` in `x18`'s place: `s` holds
/// `x18`'s value where the instruction `reads` it, and its new value goes
/// back to the slot where it `writes` it. The instruction itself is at
/// [`x18_main`]: before it, a thread stopped in the stub is as at the
/// site; after it, the stub finishes.
pub(crate) fn x18_template(main: u32, s: u32, reads: bool, writes: bool, slots: Slots) -> Vec<u32> {
    let mut w = x18_in(s, reads, slots);
    w.push(main);
    w.extend(x18_out(s, writes, slots));
    w
}

/// Where in [`x18_template`]'s words the instruction is.
pub(crate) fn x18_main(reads: bool) -> usize {
    3 + usize::from(reads)
}

/// The registers 0..=30 not in `used`, lowest first.
fn free(used: u32) -> impl Iterator<Item = u32> {
    (0u32..=30).filter(move |&r| used & (1 << r) == 0)
}

/// Instruction `insn`, which names `x18` (not as a branch, a pc-relative
/// load or `casp`), with a scratch register in `x18`'s place: the
/// instruction, the register, and whether it reads and writes `x18`.
fn x18_rename(insn: u32) -> (u32, u32, bool, bool) {
    let sub = |i: u32, shift: u32, r: u32| (i & !(0x1f << shift)) | (r << shift);
    // The fields that can hold x18, each a read and/or a write of it.
    let fields: Vec<(u32, bool, bool)> = if crate::decode::x18_writes_sp(insn) {
        // An instruction writing `sp` from `x18`: its `Rn`, and its `Rm`
        // in the extended-register and SIMD forms, the only ones with one
        // (a SIMD load or store from `sp` written back by `Rm`).
        let simd = insn & 0x1f != 31;
        let mut f = vec![(5, true, false)];
        if simd || (insn >> 24) & 0x1f == 0b01011 {
            f.push((16, true, false));
        }
        f
    } else {
        crate::decode::operands(insn)
            .expect("x18 site must decode")
            .iter()
            .map(|f| (f.shift, f.read, f.write))
            .collect()
    };
    let mut used = 1u32 << 18;
    for &(shift, ..) in &fields {
        let r = (insn >> shift) & 0x1f;
        if r != 31 {
            used |= 1 << r;
        }
    }
    let s = free(used).next().expect("a free register");
    let (mut main, mut reads, mut writes) = (insn, false, false);
    for &(shift, r, w) in &fields {
        if (insn >> shift) & 0x1f == 18 {
            main = sub(main, shift, s);
            reads |= r;
            writes |= w;
        }
    }
    (main, s, reads, writes)
}

/// Stub for a `cbz`/`cbnz`/`tbz`/`tbnz` that tests `x18`. It loads `x18` into a
/// scratch, runs the branch against the scratch to a local label, then restores
/// the scratch down both paths and branches (full range) to the real target
/// or the fall-through. `x0` is free here (these branches read no register
/// other than `x18`), and kept and taken back, so it is intact at both
/// destinations.
fn x18_branch_stub(insn: u32, slots: Slots, stub: u64, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let s = 0u32;
    let tb = (insn >> 25) & 0x3f == 0b011011; // tbz/tbnz (vs cbz/cbnz)
    let imm_bits = if tb {
        (((insn >> 5) & 0x3fff) as i64) << 50 >> 50
    } else {
        (((insn >> 5) & 0x7ffff) as i64) << 45 >> 45
    };
    let target = (site as i64).wrapping_add(imm_bits * 4) as u64;
    // The conditional branch with Rt -> s and its offset retargeted to the
    // taken path, which starts 5 words after it.
    let mut cond = (insn & !0x1f) | s;
    cond =
        if tb { (cond & !(0x3fff << 5)) | (5 << 5) } else { (cond & !(0x7ffff << 5)) | (5 << 5) };
    let at = |i: u64| stub + 4 * i;
    let mut w = x18_in(s, true, slots); // 0..=3
    w.push(cond); // 4: taken: to word 9
    w.extend(x18_out(s, false, slots)); // 5..=7: not taken
    w.push(branch(at(8), ret).expect("fall-through within range"));
    w.extend(x18_out(s, false, slots)); // 9..=11: taken
    w.push(branch(at(12), target).expect("branch target within range"));
    w
}

/// Where in [`x18_branch_stub`]'s words the branch is.
const X18_BRANCH_MAIN: usize = 4;

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

/// Stub for `adr`/`adrp` writing `x18`: the value computed from the
/// *original* pc into a scratch register, and stored to the slot.
fn x18_adr_stub(insn: u32, slots: Slots, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let immlo = (insn >> 29) & 0b11;
    let immhi = (insn >> 5) & 0x7_ffff;
    let imm21 = (((immhi << 2) | immlo) as i64) << 43 >> 43; // sign-extend 21 bits
    let target = if (insn >> 31) & 1 == 1 {
        (site & !0xfff).wrapping_add((imm21 << 12) as u64) // adrp
    } else {
        site.wrapping_add(imm21 as u64) // adr
    };
    let s = 0u32; // adr/adrp name only Rd = x18
    let mut w = x18_in(s, false, slots);
    w.extend(materialize(s, target));
    w.extend(x18_out(s, true, slots));
    w
}

/// Stub for a general-purpose `ldr`-literal into `x18`: the literal's
/// address (from the original pc) materialized, loaded from, and the value
/// stored to the slot.
fn x18_ldr_literal_stub(insn: u32, slots: Slots, ret: u64) -> Vec<u32> {
    let site = ret.wrapping_sub(4);
    let imm19 = (((insn >> 5) & 0x7_ffff) as i64) << 45 >> 45;
    let lit = site.wrapping_add((imm19 * 4) as u64);
    let s = 0u32;
    // opc: 00 = ldr w (zero-extend), 01 = ldr x, 10 = ldrsw.
    let load = match (insn >> 30) & 0b11 {
        0b01 => LDR_UIMM,    // ldr x(s), [s]
        0b10 => 0xb980_0000, // ldrsw x(s), [s]
        _ => 0xb940_0000,    // ldr w(s), [s]
    } | (s << 5)
        | s;
    let mut w = x18_in(s, false, slots);
    w.extend(materialize(s, lit));
    w.push(load);
    w.extend(x18_out(s, true, slots));
    w
}

/// Where in the stub for an `adr`/`adrp` or `ldr`-literal of `x18` the
/// program's `x18` is written: before, the stub is as at its site (its
/// words load and compute only); from there on, it finishes.
const X18_PC_RELATIVE_MAIN_FROM_END: usize = 2;

/// `br x18`.
pub const BR_X18: u32 = 0xd61f_0240;

/// The site of the stub whose slot (from its start, `stub`) holds
/// `words`: before where its branch back, the first plain branch leading
/// out of the slot, goes.
pub fn site_of(words: &[u32], stub: u64) -> Option<u64> {
    let end = stub + 4 * words.len() as u64;
    words.iter().enumerate().find_map(|(i, &w)| {
        let at = stub + 4 * i as u64;
        let to = (w & 0xfc00_0000 == B)
            .then(|| at.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4)))?;
        (to < stub || to >= end).then(|| to.wrapping_sub(4))
    })
}

/// Stub for an indirect branch through `x18` that calls, returns or leaves
/// the function (`blr`, `ret`, and the authenticated forms; a plain `br`
/// has a stub of its own where fwe translates: `jit::x18_branch_stub`).
/// Loads the target from the slot into `x16` (`x17` when the modifier is
/// `x16`) and branches with the original's kind: `x16`/`x17` are the
/// intra-procedure-call scratch registers, which a call, a return or a
/// tail call leaves free (a linker's veneer can clobber them), so no save
/// is needed, and a branch through them can land on a `bti c`. For the
/// `blr` forms the link register is set to the instruction after the
/// original branch, and the branch made without link. Self-terminating
/// (ends in the branch).
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

/// Stub for a `casp` naming `x18` in a pair or as its base. A pair is
/// an even-numbered register and the next, so one holding `x18` is replaced
/// by a free even pair: its first holds `x18`, its second a copy of `x19`,
/// and both go back after (`x18` to the slot, `x19` from the second) if the
/// pair is the one written (`Rs`). A base of `x18` goes through one more
/// scratch register.
fn x18_casp_stub(insn: u32, slots: Slots) -> Vec<u32> {
    let (rs, rt, rn) = ((insn >> 16) & 0x1f, insn & 0x1f, (insn >> 5) & 0x1f);
    let used = [rs, rs + 1, rt, rt + 1, rn, 18, 19].iter().fold(0u32, |u, &r| u | 1 << r);
    let pair = rs == 18 || rt == 18;
    let p = (0u32..=28).step_by(2).find(|&r| used & (3 << r) == 0).expect("a free even pair");
    let q = free(used | 3 << p).next().expect("a free register"); // a base of x18
    let [k0, k1, k2] = slots.scratch;
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
    // Kept, then `x18`'s value loaded by the group's last access, into
    // one register and copied to the other.
    let mut w = TSD18.to_vec();
    if pair {
        w.extend([str18(p, k0), str18(p + 1, k1)]);
    }
    if rn == 18 {
        w.push(str18(q, k2));
    }
    let first = if pair { p } else { q };
    w.push(ldr18(first, slots.x18));
    if pair && rn == 18 {
        w.push(MOV | p << 16 | q);
    }
    if pair {
        w.push(MOV | 19 << 16 | (p + 1));
    }
    w.push(casp);
    if rs == 18 {
        w.push(MOV | (p + 1) << 16 | 19);
    }
    // Stored, then taken back: another, the register it stores last.
    w.extend(TSD18);
    if rs == 18 {
        w.push(str18(p, slots.x18));
    }
    if rn == 18 {
        w.push(ldr18(q, k2));
    }
    if pair {
        w.extend([ldr18(p + 1, k1), ldr18(p, k0)]);
    }
    w
}

/// Where in the stub for an `x18`-naming instruction other than a branch
/// (`stub_body`'s words for `Site::X18 { insn }`) the instruction itself
/// is: the words before it only keep registers and load `x18`'s value, so
/// a thread stopped there is as at the site ([`undo`]); the words after it
/// store `x18` back and take the registers back, so a thread stopped there
/// has them finished ([`step`]), the instruction having run (it might be
/// an atomic one).
pub(crate) fn x18_stub_main(insn: u32) -> usize {
    use crate::decode::{x18_adr, x18_casp, x18_indirect, x18_ldr_literal};
    if x18_indirect(insn).is_some() || insn == BR_X18 {
        // Its words load a target into a free register: run again.
        usize::MAX
    } else if x18_casp(insn) {
        let (rs, rt, rn) = ((insn >> 16) & 0x1f, insn & 0x1f, (insn >> 5) & 0x1f);
        let pair = rs == 18 || rt == 18;
        2 + if pair { 4 } else { 0 } + if rn == 18 { 2 } else { 0 }
    } else if crate::decode::x18_branch(insn) {
        X18_BRANCH_MAIN
    } else if x18_adr(insn).is_some() || x18_ldr_literal(insn) {
        // The store of `x18` in its last group.
        let n = stub_body(Site::X18 { insn }, DUMMY_SLOTS, 0).len();
        n - X18_PC_RELATIVE_MAIN_FROM_END
    } else {
        x18_main(x18_rename(insn).2)
    }
}

/// Slots for working out a stub's layout, which does not depend on them.
const DUMMY_SLOTS: Slots = Slots { tp: 8, x18: 16, scratch: [24, 32, 40] };

/// Where in the stub for `site` its instruction is (a system call's or a
/// flush's: its call into the gate): before it, a thread stopped in the
/// stub is as at the site ([`undo`]); after it, the stub finishes
/// ([`step`]).
pub fn main_of(site: Site) -> usize {
    match site {
        Site::Syscall { .. } => SYSCALL_STUB_CALL,
        Site::Flush { .. } => FLUSH_STUB_CALL,
        Site::ReadThreadPointer { rt: 18 } | Site::WriteThreadPointer { rt: 18 } => 6,
        // A read writes only its register: finished once begun. A write
        // is its last word.
        Site::ReadThreadPointer { .. } => 0,
        Site::WriteThreadPointer { .. } => 2,
        Site::X18 { insn } => x18_stub_main(insn),
    }
}

/// The program's general registers `x` (`x[18]` the program's `x18`) of a
/// thread stopped at a word of a stub before its instruction, after
/// `words` of it ran: each it kept in a scratch slot and has not taken back
/// is read back (`read` reads a TSD slot by its offset), so `x` is as at
/// the stub's site. `scratch` are the scratch slots.
pub fn undo(words: &[u32], scratch: &[u32], read: impl Fn(u32) -> u64, x: &mut [u64; 31]) {
    let mut kept: Vec<(u32, u32)> = Vec::new();
    // Registers holding the TSD base (`x18` always does, in a group).
    let mut base = 1u32 << 18;
    for &w in words {
        let (t, n) = (w & 0x1f, (w >> 5) & 0x1f);
        let off = ((w >> 10) & 0xfff) * 8;
        if w & !0x1f == MRS_TPIDRRO {
            base |= 1 << t;
        } else if w & 0xffc0_0000 == STR_UIMM && base & 1 << n != 0 && scratch.contains(&off) {
            kept.retain(|&(r, _)| r != t);
            kept.push((t, off));
        } else if w & 0xffc0_0000 == LDR_UIMM && base & 1 << n != 0 && scratch.contains(&off) {
            kept.retain(|&(r, _)| r != t);
        } else if t != 18 && w & 0xffc0_0000 != STR_UIMM {
            // Any other word writing `t` (a load into it, a move): it
            // holds no base now.
            base &= !(1 << t) | 1 << 18;
        }
    }
    for (r, off) in kept {
        if r != 18 {
            x[r as usize] = read(off);
        }
    }
}

/// What [`step`] made of a word.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Carried out: on at the next word.
    Next,
    /// A branch, to this address: the stub's way on.
    Branch(u64),
    /// No word of a stub's ending: its way on (a translation's next
    /// instruction).
    Other,
}

/// Carry out word `w`, at `pc`, of a stub's ending (after its instruction)
/// on the program's general registers `x` (`x[18]` the program's `x18`):
/// the TSD base into a register, a load or store at an offset from it,
/// a move, a branch. `tsd` is the thread's `tpidrro_el0`; `read` and
/// `write` access memory; `x18_slot` is the program's `x18`'s, which a
/// store to it sets in `x` too.
pub fn step(
    w: u32,
    pc: u64,
    tsd: u64,
    x18_slot: u32,
    x: &mut [u64; 31],
    read: impl Fn(u64) -> u64,
    mut write: impl FnMut(u64, u64),
) -> Step {
    let (t, n) = ((w & 0x1f) as usize, ((w >> 5) & 0x1f) as usize);
    // A base register: `x18`, in a group, is the TSD base.
    let base = |x: &[u64; 31], n: usize| if n == 18 { tsd & !7 } else { x[n] };
    if w & !0x1f == MRS_TPIDRRO {
        if t != 18 {
            x[t] = tsd;
        }
    } else if w & !0x3ff == AND_NOT7 && t == n {
        if t != 18 {
            x[t] &= !7;
        }
    } else if w & 0xffc0_0000 == STR_UIMM {
        let off = ((w >> 10) & 0xfff) * 8;
        let value = x[t];
        write(base(x, n) + u64::from(off), value);
        if n == 18 && off == x18_slot {
            x[18] = value;
        }
    } else if w & 0xffc0_0000 == LDR_UIMM {
        let off = ((w >> 10) & 0xfff) * 8;
        x[t] = read(base(x, n) + u64::from(off));
    } else if w & 0xffe0_ffe0 == MOV {
        x[t] = x[((w >> 16) & 0x1f) as usize];
    } else if w & 0xfc00_0000 == B {
        return Step::Branch(pc.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4)));
    } else {
        return Step::Other;
    }
    Step::Next
}

/// A stub whose words are `words` from `stub`, of `site`, a thread stopped
/// at `pc` in it: the program's state there, as at the site before its
/// instruction ([`undo`]), past it after ([`step`]). `x` are the program's
/// general registers, made the program's; the address it goes on at is
/// returned. `tsd` is the thread's `tpidrro_el0`, `scratch` its scratch
/// slots and `x18_slot` its `x18`'s; `read` and `write` access memory.
#[allow(clippy::too_many_arguments)]
pub fn to_guest(
    words: &[u32],
    stub: u64,
    site: (u64, Site),
    pc: u64,
    tsd: u64,
    (scratch, x18_slot): (&[u32], u32),
    x: &mut [u64; 31],
    read: impl Fn(u64) -> u64,
    mut write: impl FnMut(u64, u64),
) -> u64 {
    let k = ((pc - stub) / 4) as usize;
    if k <= main_of(site.1) {
        undo(&words[..k], scratch, |off| read((tsd & !7) + u64::from(off)), x);
        return site.0;
    }
    let mut at = pc;
    for &w in &words[k..] {
        match step(w, at, tsd, x18_slot, x, &read, &mut write) {
            Step::Next => at += 4,
            Step::Branch(to) => return to,
            Step::Other => break,
        }
    }
    site.0 + 4
}

#[cfg(test)]
mod tests {
    /// A replay of what `patch` noted does the same to the same code.
    #[test]
    fn replay_matches_patch() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let mut code = exe[..(exe.len() & !3).min(8 << 20)].to_vec();
        let mut again = code.clone();
        let known = [(4096u64, 1 << 20)];
        let p = patch(&mut code, Some(&known));
        let r = replay(&mut again, &p.noted, p.x18_deferred).expect("the same words");
        assert_eq!(code, again);
        assert_eq!((p.syscalls, p.sites, p.x18_deferred), (r.syscalls, r.sites, r.x18_deferred));
        // A word that changed since: nothing done.
        let mut changed = exe[..code.len()].to_vec();
        if let Some(&(off, orig, _)) = p.noted.first() {
            let at = off as usize;
            changed[at..at + 4].copy_from_slice(&(orig ^ 1).to_le_bytes());
            let before = changed.clone();
            assert!(replay(&mut changed, &p.noted, 0).is_none());
            assert_eq!(changed, before);
        }
    }

    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
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
        // Each is the trap in place, and a site for a stub to the gate.
        let gate = Site::Syscall { gate: 0 };
        assert_eq!(p.sites, vec![(4, gate), (12, gate)]);
        // With no table saying where code is, only `svc #0` is taken.
        assert_eq!(code, words(&[mov_x8, TRAP, svc1, TRAP]));
    }

    /// Linux takes any `svc` as a system call: one with another immediate
    /// (`svc #0x80`, macOS's own) is rewritten too where the image's tables
    /// say there is code, and left alone outside it.
    #[test]
    fn any_svc_in_known_code_is_a_system_call() {
        let svc80 = 0xd400_1001; // svc #0x80
        assert!(is_svc(svc80) && is_svc(SVC0) && !is_svc(TRAP));
        let mut code = words(&[svc80, SVC0, svc80]);
        let p = patch(&mut code, Some(&[(0, 8)]));
        assert_eq!(p.syscalls, 2);
        assert_eq!(code, words(&[TRAP, TRAP, svc80]));
    }

    /// A system call's stub saves `x30` and `x0` in one store (its only
    /// one that can fault), calls the gate from its literal and goes back
    /// past the site; its site is found from its first word.
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

    #[test]
    fn literal_pool_words_are_not_rewritten() {
        // ldr x0, <+8> makes the two words at offset 8 a literal pool. The
        // first pool word encodes `movz x18` but is left as data.
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

    /// Slots for the tests: the thread pointer's at 16, `x18`'s at 24, the
    /// scratch slots at 32, 40 and 48.
    const S: Slots = Slots { tp: 16, x18: 24, scratch: [32, 40, 48] };
    /// `mrs x18, tpidrro_el0; and x18, x18, #~7`, as `llvm-mc` assembles it.
    const G: [u32; 2] = [0xd53b_d072, 0x927d_f252];

    /// A stub's words, its branch back from `stub` 0x2000 to 0x1004 (site
    /// 0x1000) last, for a slot `S` names.
    fn stub_of(site: Site) -> Vec<u32> {
        stub(site, S, 0x2000, 0x1004)
    }

    /// The groups' words, as `llvm-mc` assembles them.
    #[test]
    fn group_encoding() {
        assert_eq!(TSD18, G);
        assert_eq!(str18(30, 32), 0xf900_125e); // str x30, [x18, #32]
        assert_eq!(str18(0, 40), 0xf900_1640); // str x0, [x18, #40]
        assert_eq!(ldr18(30, 32), 0xf940_125e); // ldr x30, [x18, #32]
        assert_eq!(ldr18(0, 24), 0xf940_0e40); // ldr x0, [x18, #24]
    }

    /// A system call's stub keeps `x30` and `x0` in their scratch slots,
    /// calls the gate, takes `x30` back and goes back past its site.
    #[test]
    fn syscall_stub_calls_the_gate_and_names_its_site() {
        let gate = 0x0001_0203_0405_0608;
        let s = stub_of(Site::Syscall { gate });
        assert_eq!(s.len(), SYSCALL_STUB_WORDS);
        assert!(s.len() <= STUB_WORDS);
        assert_eq!(
            s[..10],
            [
                G[0],
                G[1],
                0xf900_125e, // str x30, [x18, #32]
                0xf900_1640, // str x0, [x18, #40]
                LDR_X30_LIT,
                BLR_X30,
                G[0],
                G[1],
                0xf940_125e, // ldr x30, [x18, #32]
                branch(0x2024, 0x1004).unwrap(),
            ]
        );
        assert_eq!(s[SYSCALL_STUB_CALL], BLR_X30);
        // The literal `ldr` (at word 4) reads 24 bytes on: words 10 and 11.
        assert_eq!(s[10] as u64 | (s[11] as u64) << 32, gate);
        // The call returns to word 6.
        let word = |a: u64| s[((a - 0x2000) / 4) as usize];
        assert_eq!(syscall_site_of(word, 0x2018), 0x1000);
    }

    /// `ic ivau, xN` in code becomes a site whose stub runs it and calls
    /// the gate, which tells it from a system call's by the stub's load of
    /// the gate's address; through `x18`, the stub leaves it to the gate.
    #[test]
    fn a_flush_calls_the_gate_and_is_told_from_a_system_call() {
        let ic = IC_IVAU | 3; // ic ivau, x3
        assert!(is_ic_ivau(ic) && !is_ic_ivau(0xd50b_7a23)); // dc cvau, x3
        let p = patch(&mut words(&[ic]), Some(&[(0, 4)]));
        assert_eq!(p.sites, vec![(0, Site::Flush { rt: 3, gate: 0 })]);
        let gate = 0x1_2345_6780u64;
        for (rt, first) in [(3, ic), (18, NOP)] {
            let stub = stub_of(Site::Flush { rt, gate });
            assert_eq!(stub.len(), FLUSH_STUB_WORDS);
            assert_eq!(stub[0], first);
            assert_eq!(
                stub[1..7],
                [G[0], G[1], 0xf900_125e, 0xf900_1640, FLUSH_LDR_X30_LIT, BLR_X30]
            );
            assert_eq!(stub[FLUSH_STUB_CALL], BLR_X30);
            // The literal `ldr` (at word 5) reads 28 bytes on: words 12 and 13.
            assert_eq!(u64::from(stub[12]) | u64::from(stub[13]) << 32, gate);
            let word = |a: u64| stub[((a - 0x2000) / 4) as usize];
            let ret = 0x2000 + 4 * (FLUSH_STUB_CALL as u64 + 1);
            assert_eq!(flush_reg(word, ret), Some(rt));
            assert_eq!(syscall_site_of(word, ret), 0x1000);
        }
        let call = stub_of(Site::Syscall { gate });
        let word = |a: u64| call[((a - 0x2000) / 4) as usize];
        assert_eq!(flush_reg(word, 0x2000 + 4 * (SYSCALL_STUB_CALL as u64 + 1)), None);
    }

    /// The thread pointer's stubs, and the instructions naming `x18`, as
    /// `llvm-mc` assembles their listings (slots as `S` names them).
    #[test]
    fn stub_encodings() {
        let back = |k: u64, to: u64| branch(0x2000 + 4 * k, to).unwrap();
        // mrs x5, tpidr_el0: through x5 alone.
        assert_eq!(
            stub_of(Site::ReadThreadPointer { rt: 5 }),
            [0xd53b_d065, 0x927d_f0a5, 0xf940_08a5, back(3, 0x1004)]
        );
        // msr tpidr_el0, x0: str x0, [x18, #16].
        assert_eq!(
            stub_of(Site::WriteThreadPointer { rt: 0 }),
            [G[0], G[1], 0xf900_0a40, back(3, 0x1004)]
        );
        // mrs x18, tpidr_el0: x0 kept, the thread pointer's slot copied to
        // x18's, x0 taken back.
        assert_eq!(
            stub_of(Site::ReadThreadPointer { rt: 18 }),
            [
                G[0],
                G[1],
                0xf900_1240,
                G[0],
                G[1],
                0xf940_0a40,
                0xf900_0e40,
                G[0],
                G[1],
                0xf940_1240,
                back(10, 0x1004)
            ]
        );
        // The x18 stand-in is x0 where the instruction leaves it free: kept
        // at [x18, #32] (0xf900_1240), the program's x18 loaded from
        // [x18, #24] (0xf940_0e40) where read, stored there (0xf900_0e40)
        // where written, x0 taken back (0xf940_1240).
        let (keep, load, store, back0) = (0xf900_1240, 0xf940_0e40, 0xf900_0e40, 0xf940_1240);
        for (insn, main, reads, writes) in [
            (0xaa12_03ea, 0xaa00_03ea, true, false), // mov x10, x18
            (0xd283_0312, 0xd283_0300, false, true), // movz x18, #0x1818
            (0xf940_0bf2, 0xf940_0be0, false, true), // ldr x18, [sp, #16]
            (0xf900_0432, 0xf900_0420, true, false), // str x18, [x1, #8]
            (0xf81f_0ff2, 0xf81f_0fe0, true, false), // str x18, [sp, #-16]!
            (0xa9bf_4ff2, 0xa9bf_4fe0, true, false), // stp x18, x19, [sp, #-16]!
            (0x9100_025f, 0x9100_001f, true, false), // mov sp, x18
            (0x8b32_63e1, 0x8b20_63e1, true, false), // add x1, sp, x18
            (0x9100_0652, 0x9100_0400, true, true),  // add x18, x18, #1
        ] {
            let mut want = vec![G[0], G[1], keep];
            want.extend(reads.then_some(load));
            want.push(main);
            want.extend([G[0], G[1]]);
            want.extend(writes.then_some(store));
            want.push(back0);
            want.push(back(want.len() as u64, 0x1004));
            assert_eq!(stub_of(Site::X18 { insn }), want, "{insn:#010x}");
            assert_eq!(x18_stub_main(insn), 3 + usize::from(reads), "{insn:#010x}");
        }
        // madd x18, x0, x1, x2: x0 to x2 named, so x3 stands in.
        assert_eq!(
            stub_of(Site::X18 { insn: 0x9b01_0812 }),
            [
                G[0],
                G[1],
                0xf900_1243,
                0x9b01_0803,
                G[0],
                G[1],
                0xf900_0e43,
                0xf940_1243,
                back(8, 0x1004)
            ]
        );
        // adr x18, . at 0x1000: the address made in x0 and stored.
        assert_eq!(
            stub_of(Site::X18 { insn: 0x1000_0012 }),
            [
                G[0],
                G[1],
                keep,
                0xd282_0000,
                0xf2a0_0000,
                0xf2c0_0000,
                0xf2e0_0000,
                G[0],
                G[1],
                store,
                back0,
                back(11, 0x1004)
            ]
        );
        // cbnz x18, #8 at 0x1000: x0 taken back down both ways.
        assert_eq!(
            stub_of(Site::X18 { insn: 0xb500_0052 }),
            [
                G[0],
                G[1],
                keep,
                load,
                0xb500_00a0,
                G[0],
                G[1],
                back0,
                back(8, 0x1004),
                G[0],
                G[1],
                back0,
                back(12, 0x1008)
            ]
        );
        // casp x18, x19, x2, x3, [x0]: the even pair x4, x5 for x18, x19.
        assert_eq!(
            stub_of(Site::X18 { insn: 0x4832_7c02 })[..13],
            [
                G[0],
                G[1],
                0xf900_1244,
                0xf900_1645,
                0xf940_0e44,
                0xaa13_03e5,
                0x4824_7c02,
                0xaa05_03f3,
                G[0],
                G[1],
                0xf900_0e44,
                0xf940_1645,
                0xf940_1244
            ]
        );
        // braa x18, x1 through x16; braa x18, x16 through x17.
        assert_eq!(
            stub_of(Site::X18 { insn: 0xd71f_0a41 }),
            [0xd53b_d070, 0x927d_f210, 0xf940_0e10, 0xd71f_0a01]
        );
        assert_eq!(stub_of(Site::X18 { insn: 0xd71f_0a50 })[3], 0xd71f_0a30);
        // blr x18: the target into x16, x30 the site's next, br x16.
        assert_eq!(
            stub_of(Site::X18 { insn: 0xd63f_0240 }),
            [
                0xd53b_d070,
                0x927d_f210,
                0xf940_0e10,
                0xd282_009e,
                0xf2a0_001e,
                0xf2c0_001e,
                0xf2e0_001e,
                0xd61f_0200
            ]
        );
    }

    /// The sites of the stubs the tests below run: one of each kind.
    fn sites() -> Vec<Site> {
        let mut v = vec![
            Site::Syscall { gate: 0x1_2345_6780 },
            Site::Flush { rt: 3, gate: 0x1_2345_6780 },
            Site::Flush { rt: 18, gate: 0x1_2345_6780 },
            Site::ReadThreadPointer { rt: 5 },
            Site::WriteThreadPointer { rt: 0 },
            Site::ReadThreadPointer { rt: 18 },
            Site::WriteThreadPointer { rt: 18 },
        ];
        for insn in [
            0xaa12_03ea,
            0xd283_0312,
            0xf940_0bf2,
            0xf900_0432,
            0xf81f_0ff2,
            0xa9bf_4ff2,
            0x9100_025f,
            0x8b32_63e1,
            0x9100_0652,
            0x9b01_0812,
            0x1000_0012,
            0x5800_0052,
            0xb500_0052,
            0x3700_0052,
            0x4832_7c02,
            0x4820_7e42,
            0x4832_7e42,
            0xb8bf_c252,
        ] {
            v.push(Site::X18 { insn });
        }
        v
    }

    /// No stub of fwe's touches memory below the program's `sp`: none of
    /// its words but the program's own instruction is addressed through
    /// `sp` or moves it.
    #[test]
    fn stubs_leave_the_stack_alone() {
        for site in sites() {
            let words = stub_of(site);
            let main = main_of(site);
            for (k, &w) in words.iter().enumerate() {
                if k == main || w == NOP {
                    continue;
                }
                let load_store = w & 0x0a00_0000 == 0x0800_0000;
                let writes_sp = (w >> 24) & 0x1f == 0b10001 && (w >> 29) & 1 == 0 && w & 0x1f == 31;
                assert!(
                    !(load_store && (w >> 5) & 0x1f == 31) && !writes_sp,
                    "{site:?}: word {k}, {w:#010x}"
                );
            }
        }
    }

    /// Where the test machine finds the thread's TSD.
    const TSD: u64 = 0x1_0000_1000;

    /// The program's registers as a stub's site has them, and its TSD
    /// slots (the program's `x18` and thread pointer in theirs).
    fn start() -> ([u64; 32], [u64; 8]) {
        let mut tsd = [0u64; 8];
        (tsd[2], tsd[3]) = (0x7f00, 0xab18);
        (core::array::from_fn(|r| 0x1000 + r as u64), tsd)
    }

    /// Runs a stub's words from word 0, as the host would but for the
    /// program's instruction (word `skip`) and the call into the gate
    /// (skipped; the literal load
    /// of the gate's address gives `x30` a value of its own), up to its
    /// first branch out or word `stop`, `x18` zeroed before word `zero`
    /// (the host entering its kernel there): an access through `x18`
    /// faults then and starts again where [`restart_at`] says. Memory
    /// other than the TSD's is not modelled. The words reached, in order,
    /// and the registers and slots there.
    fn run(
        words: &[u32],
        skip: usize,
        stop: usize,
        zero: Option<usize>,
    ) -> (Vec<usize>, [u64; 32], [u64; 8]) {
        let (mut x, mut tsd) = start();
        x[18] = 0;
        let (mut k, mut zero, mut path, mut steps) = (0, zero, vec![], 0);
        while k < words.len() && k < stop {
            steps += 1;
            assert!(steps < 1000, "no end");
            if zero == Some(k) {
                (x[18], zero) = (0, None);
            }
            path.push(k);
            let w = words[k];
            let (t, n, off) =
                ((w & 0x1f) as usize, ((w >> 5) & 0x1f) as usize, (w >> 10 & 0xfff) * 8);
            if k == skip || w == BLR_X30 {
            } else if w & 0xff00_001f == 0x5800_001e {
                x[30] = 0x6a7e;
            } else if w & !0x1f == MRS_TPIDRRO {
                x[t] = TSD | 3;
            } else if w & !0x3ff == AND_NOT7 && t == n {
                x[t] &= !7;
            } else if w & 0xffe0_ffe0 == MOV {
                x[t] = x[(w >> 16 & 0x1f) as usize];
            } else if w & 0xff80_0000 == MOVZ {
                x[t] = u64::from(w >> 5 & 0xffff) << (16 * (w >> 21 & 3));
            } else if w & 0xff80_0000 == MOVK {
                let sh = 16 * (w >> 21 & 3);
                x[t] = x[t] & !(0xffff << sh) | u64::from(w >> 5 & 0xffff) << sh;
            } else if w & 0xfc00_0000 == B {
                break;
            } else if matches!(w & 0xffc0_0000, STR_UIMM | LDR_UIMM) {
                let a = x[n] + u64::from(off);
                if n == 18 && a < 1 << 32 {
                    let word = |a: u64| words.get(((a - 0x2000) / 4) as usize).copied();
                    let to = restart_at(word, 0x2000 + 4 * k as u64).expect("a group's access");
                    k = ((to - 0x2000) / 4) as usize;
                    continue;
                }
                if (TSD..TSD + 64).contains(&a) {
                    let slot = &mut tsd[((a - TSD) / 8) as usize];
                    if w & 0xffc0_0000 == STR_UIMM {
                        *slot = x[t];
                    } else {
                        x[t] = *slot;
                    }
                }
            }
            k += 1;
        }
        (path, x, tsd)
    }

    /// The word of `site`'s stub the test machine skips: an `x18` site's
    /// instruction, the program's.
    fn skipped(site: Site) -> usize {
        if matches!(site, Site::X18 { .. }) { main_of(site) } else { usize::MAX }
    }

    /// A group run again from its start does the same: wherever the host
    /// zeroes `x18`, a stub ends with the registers and slots it ends with
    /// when nothing does.
    #[test]
    fn groups_run_again_do_the_same() {
        for site in sites() {
            let words = stub_of(site);
            let skip = skipped(site);
            let (path, x, tsd) = run(&words, skip, usize::MAX, None);
            for &z in &path {
                let (_, xz, tsdz) = run(&words, skip, usize::MAX, Some(z));
                assert_eq!(
                    (&xz[..18], &xz[19..], tsdz),
                    (&x[..18], &x[19..], tsd),
                    "{site:?}, {z}"
                );
            }
        }
    }

    /// A thread stopped at any word of a stub is shown as the program
    /// is: before its instruction, at its site as it was there; after, past
    /// it, as the stub leaves it.
    #[test]
    fn a_thread_stopped_in_a_stub_is_the_programs() {
        for site in sites() {
            if matches!(site, Site::X18 { insn } if crate::decode::x18_indirect(insn).is_some()) {
                continue;
            }
            let words = stub_of(site);
            let (main, skip) = (main_of(site), skipped(site));
            let (path, end, end_tsd) = run(&words, skip, usize::MAX, None);
            let (initial, _) = start();
            for &k in &path {
                let (_, mut x, mut tsd) = run(&words, skip, k, None);
                let mut regs: [u64; 31] = core::array::from_fn(|r| x[r]);
                regs[18] = tsd[3];
                let pc = 0x2000 + 4 * k as u64;
                let slot = |a: u64| ((a - TSD) / 8) as usize;
                let snapshot = tsd;
                let to = to_guest(
                    &words,
                    0x2000,
                    (0x1000, site),
                    pc,
                    TSD | 3,
                    (&S.scratch, S.x18),
                    &mut regs,
                    |a| snapshot[slot(a)],
                    |a, v| tsd[slot(a)] = v,
                );
                x[..31].copy_from_slice(&regs);
                if k <= main {
                    let mut want = initial;
                    want[18] = 0xab18;
                    assert_eq!((to, &x[..31]), (0x1000, &want[..31]), "{site:?}, {k}");
                } else {
                    let mut want = end;
                    want[18] = end_tsd[3];
                    assert_eq!((to, &x[..31]), (0x1004, &want[..31]), "{site:?}, {k}");
                }
            }
        }
    }

    /// A fault through `x18` restarts at its group's start; one through
    /// another register, or outside a group, does not.
    #[test]
    fn faults_restart_at_their_group() {
        let words = stub_of(Site::Syscall { gate: 0x1_2345_6780 });
        let word = |a: u64| words.get(((a - 0x2000) / 4) as usize).copied();
        assert_eq!(restart_at(word, 0x2008), Some(0x2000));
        assert_eq!(restart_at(word, 0x200c), Some(0x2000));
        assert_eq!(restart_at(word, 0x2020), Some(0x2018));
        assert_eq!(restart_at(word, 0x2010), None); // the literal load
        let tp = stub_of(Site::ReadThreadPointer { rt: 5 });
        assert_eq!(restart_at(|a| tp.get(((a - 0x2000) / 4) as usize).copied(), 0x2008), None);
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
        assert_eq!(p.sites.iter().map(|s| s.0).collect::<Vec<_>>(), vec![0, 4]);
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
    fn the_quick_check_passes_every_x18_site() {
        // A spread of words (every one of the 2^32 was checked once).
        let mut w: u32 = 1;
        for _ in 0..1 << 22 {
            w = w.wrapping_mul(0x9e37_79b1).wrapping_add(0x7f4a_7c15);
            for insn in
                [w, w & !(0x1f << 5) | 18 << 5, w & !0x1f | 18, w & !(0x1f << 10) | 18 << 10]
            {
                assert!(crate::decode::may_name_x18(insn) || !x18_form(insn), "{insn:#010x}");
            }
        }
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
