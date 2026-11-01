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

/// Largest stub, in instructions.
pub const STUB_WORDS: usize = 6;

/// Reach of a `b` instruction.
pub const BRANCH_RANGE: u64 = 128 << 20;

/// An instruction that needs an out-of-line stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// `mrs xN, tpidr_el0`
    ReadThreadPointer { rt: u32 },
    /// `msr tpidr_el0, xN` (N = 31 is `xzr`)
    WriteThreadPointer { rt: u32 },
}

/// Result of rewriting a block of code in place.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Patched {
    pub syscalls: usize,
    /// Offsets (from the start of the block) of instructions that must be
    /// redirected to stubs.
    pub sites: Vec<(u64, Site)>,
}

/// Rewrite what can be rewritten in place and collect the rest. `code`
/// must start at a 4-byte aligned address.
pub fn patch(code: &mut [u8]) -> Patched {
    let mut out = Patched::default();
    for (i, word) in code.chunks_exact_mut(4).enumerate() {
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
        } else {
            None
        };
        if let Some(r) = replacement {
            word.copy_from_slice(&r.to_le_bytes());
        }
    }
    out
}

/// `b` from `from` to `to`, if in range.
pub fn branch(from: u64, to: u64) -> Option<u32> {
    let offset = to.wrapping_sub(from) as i64;
    if offset % 4 != 0 || !(-(BRANCH_RANGE as i64)..BRANCH_RANGE as i64).contains(&offset) {
        return None;
    }
    Some(B | ((offset >> 2) as u32 & 0x03ff_ffff))
}

/// The stub for `site`, placed at `stub`, returning to `ret`. `slot` is the
/// byte offset of the guest thread pointer in the host TSD.
pub fn stub(site: Site, slot: u32, stub: u64, ret: u64) -> Vec<u32> {
    assert!(slot % 8 == 0 && slot / 8 < 4096, "slot offset must fit an ldr/str immediate");
    let imm = (slot / 8) << 10;
    let mut words = match site {
        Site::ReadThreadPointer { rt } => {
            vec![MRS_TPIDRRO | rt, AND_NOT7 | (rt << 5) | rt, LDR_UIMM | imm | (rt << 5) | rt]
        }
        Site::WriteThreadPointer { rt } => {
            // A scratch register, saved below sp (Linux arm64 has no red zone,
            // so memory below sp is not live).
            let s = if rt == 16 { 17 } else { 16 };
            vec![
                PUSH | s,
                MRS_TPIDRRO | s,
                AND_NOT7 | (s << 5) | s,
                STR_UIMM | imm | (s << 5) | rt,
                POP | s,
            ]
        }
    };
    let at = stub + 4 * words.len() as u64;
    words.push(branch(at, ret).expect("stub placed within branch range of its site"));
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
        let s = stub(Site::ReadThreadPointer { rt: 5 }, 16, 0x2000, 0x1004);
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
        let s = stub(Site::WriteThreadPointer { rt: 0 }, 8, 0x2000, 0x1004);
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
        let s = stub(Site::WriteThreadPointer { rt: 16 }, 8, 0x2000, 0x1004);
        assert_eq!(s[0], 0xf81f_0ff1);
    }
}
