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
//!
//! arm64 instructions are 4 bytes and 4-byte aligned, so scanning aligned
//! words finds every instruction exactly. A data word inside an executable
//! segment that happens to match one of these encodings is rewritten too.

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
/// `b <label>`
const B: u32 = 0x1400_0000;

/// Largest stub, in instructions. The `x18` branch stub is the biggest: save
/// two scratch registers, load the TSD base and `x18`, test it, and restore the
/// scratch registers down each of the taken and not-taken paths before a
/// full-range branch.
pub const STUB_WORDS: usize = 12;

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

/// Whether `insn` names `x18` in a form this pass can rewrite to a stub.
fn rewritable_x18(insn: u32) -> bool {
    crate::decode::operands(insn)
        .is_some_and(|ops| ops.iter().any(|f| (insn >> f.shift) & 0x1f == 18))
}

/// Result of rewriting a block of code in place.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Patched {
    pub syscalls: usize,
    /// Offsets (from the start of the block) of instructions that must be
    /// redirected to stubs.
    pub sites: Vec<(u64, Site)>,
    /// Count of instructions that name `x18` but are not yet rewritable
    /// (loads/stores, PC-relative forms, branches, `sp` forms). Diagnostic
    /// only; those instructions are left untouched.
    pub x18_deferred: usize,
}

/// Rewrite what can be rewritten in place and collect the rest. `code`
/// must start at a 4-byte aligned address.
pub fn patch(code: &mut [u8]) -> Patched {
    let mut out = Patched::default();
    let data = literal_pool_words(code);
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
        } else if rewritable_x18(insn) || crate::decode::x18_branch(insn) {
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
fn literal_pool_words(code: &[u8]) -> Vec<bool> {
    let n = code.len() / 4;
    let mut data = vec![false; n];
    for (i, w) in code.chunks_exact(4).enumerate() {
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
                || rewritable_x18(i)
                || crate::decode::x18_branch(i)
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
        // A compare/test branch that reads x18 builds its own complete stub,
        // including its outgoing branches.
        Site::X18 { insn } if crate::decode::x18_branch(insn) => {
            return x18_branch_stub(insn, imm(x18_slot), stub, ret);
        }
        Site::X18 { insn } => x18_stub(insn, imm(x18_slot)),
    };
    let at = stub + 4 * words.len() as u64;
    words.push(branch(at, ret).expect("stub placed within branch range of its site"));
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

    let reads = ops.iter().any(|f| field_reg(f) == 18 && f.read);
    let writes = ops.iter().any(|f| field_reg(f) == 18 && f.write);

    // Start from the instruction with any `sp`-relative offset bumped past the
    // 32 bytes the stub pushes, then replace every x18 operand with s1. The
    // offset fix-up touches only immediate bits, the substitution only the
    // register fields that hold x18 in the original instruction, so the two are
    // independent.
    let mut rewritten = match crate::decode::sp_fixup(insn) {
        crate::decode::SpFixup::Adjusted(a) => a,
        _ => insn,
    };
    for f in &ops {
        if field_reg(f) == 18 {
            rewritten = (rewritten & !(0x1f << f.shift)) | (s1 << f.shift);
        }
    }

    let mut words = vec![PUSH | s1, PUSH | s2, MRS_TPIDRRO | s2, AND_NOT7 | (s2 << 5) | s2];
    if reads {
        words.push(LDR_UIMM | imm | (s2 << 5) | s1);
    }
    words.push(rewritten);
    if writes {
        words.push(STR_UIMM | imm | (s2 << 5) | s1);
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
        let p = patch(&mut code);
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
        let p = patch(&mut code);
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
        assert_eq!(patch(&mut code), Patched::default());
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
        let p = patch(&mut code);
        assert!(p.sites.is_empty(), "literal-pool data must not become a site");
        assert_eq!(p.x18_deferred, 0);
        // The data word is untouched.
        assert_eq!(&code[8..12], &0xd283_0312u32.to_le_bytes());
    }

    #[test]
    fn x18_sites_and_deferrals_counted() {
        let mut code = words(&[
            0xd2830312, // movz x18, #0x1818  -> rewritable site
            0xaa1203ea, // mov x10, x18       -> rewritable site
            0xf9400012, // ldr x18, [x0]      -> rewritable site (load/store)
            0x90000012, // adrp x18, .        -> deferred (PC-relative)
            0xd2800000, // movz x0, #0        -> untouched
        ]);
        let p = patch(&mut code);
        assert_eq!(p.sites.len(), 3);
        assert_eq!(p.x18_deferred, 1);
        assert!(matches!(p.sites[0].1, Site::X18 { insn: 0xd2830312 }));
    }
}
