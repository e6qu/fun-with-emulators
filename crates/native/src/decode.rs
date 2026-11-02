//! Just enough AArch64 decoding to rewrite guest uses of `x18`.
//!
//! macOS clears `x18` on every exception return — including involuntary
//! preemption, which no handler can intercept — so a Linux value kept in `x18`
//! can vanish between any two instructions. The fix is to never let guest state
//! live in the hardware `x18`: each instruction that names `x18` is redirected
//! to a stub that keeps the guest's `x18` in a per-thread memory slot and uses
//! an ordinary scratch register (which macOS *does* preserve) in its place.
//!
//! To build such a stub we need, for one instruction, which register-operand
//! fields it has and whether each is read or written. [`operands`] returns that
//! for the instruction classes this pass handles, and `None` for everything
//! else — the conservative answer, since an undecoded instruction is simply
//! left alone rather than risk a wrong rewrite. Classes left for later
//! (loads/stores, PC-relative forms, branches, anything touching `sp`) are
//! reported by [`names_x18`] so they can be counted.

/// A register operand: its field position (low bit) and access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub shift: u32,
    pub read: bool,
    pub write: bool,
}

const RD: u32 = 0;
const RN: u32 = 5;
const RM: u32 = 16;

fn reg(insn: u32, shift: u32) -> u32 {
    (insn >> shift) & 0x1f
}

/// The register-operand fields of `insn`, if it is a class this pass can
/// relocate and rewrite. `None` means "leave it alone" (unknown class,
/// PC-relative, a branch, a load/store, or anything that uses `sp`).
pub fn operands(insn: u32) -> Option<Vec<Field>> {
    // Move wide immediate: op[28:23] = 100101. opc[30:29]: 00=MOVN, 10=MOVZ,
    // 11=MOVK (01 is unallocated). MOVK preserves the other bits, so it reads
    // its destination as well as writing it.
    if (insn >> 23) & 0x3f == 0b100101 {
        let opc = (insn >> 29) & 0b11;
        if opc == 0b01 {
            return None;
        }
        let movk = opc == 0b11;
        return Some(vec![Field { shift: RD, read: movk, write: true }]);
    }

    // Add/subtract (immediate): op[28:24] = 10001. Here register 31 is `sp` in
    // both the Rd and Rn fields, so defer when either is 31.
    if (insn >> 24) & 0x1f == 0b10001 {
        if reg(insn, RD) == 31 || reg(insn, RN) == 31 {
            return None;
        }
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Logical (immediate): op[28:23] = 100100. Rd is `sp` when 31 in this
    // class; Rn 31 is `xzr`.
    if (insn >> 23) & 0x3f == 0b100100 {
        if reg(insn, RD) == 31 {
            return None;
        }
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Logical (shifted register): op[28:24] = 01010. All of Rd/Rn/Rm are `xzr`
    // when 31, never `sp`.
    if (insn >> 24) & 0x1f == 0b01010 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Add/subtract (shifted register): op[28:24] = 01011 with bit 21 = 0. The
    // extended-register form (bit 21 = 1) can name `sp`, so defer it.
    if (insn >> 24) & 0x1f == 0b01011 && (insn >> 21) & 1 == 0 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    None
}

/// Whether `insn` names `x18` in any standard register-operand position. This
/// over-approximates (it looks at the fixed Rd/Rn/Rm/Rt positions regardless of
/// class) and is used only to *count* `x18` uses this pass does not yet
/// rewrite, so a false positive inflates a diagnostic but changes no code.
pub fn names_x18(insn: u32) -> bool {
    [RD, RN, RM, 10].iter().any(|&s| reg(insn, s) == 18)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(shift: u32) -> Field {
        Field { shift, read: false, write: true }
    }
    fn rr(shift: u32) -> Field {
        Field { shift, read: true, write: false }
    }

    #[test]
    fn move_wide() {
        // movz x18, #0x1818  -> writes Rd only
        assert_eq!(operands(0xd2830312), Some(vec![rd(RD)]));
        // movk x18, #0x1818, lsl #48 -> reads and writes Rd
        assert_eq!(operands(0xf2e30312), Some(vec![Field { shift: RD, read: true, write: true }]));
        // movn x0, #0 -> writes Rd only
        assert_eq!(operands(0x92800000), Some(vec![rd(RD)]));
    }

    #[test]
    fn logical_shifted_register_mov_and_cmp() {
        // mov x10, x18  == orr x10, xzr, x18 -> Rd write, Rn read, Rm read
        assert_eq!(operands(0xaa1203ea), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // cmp x18, x10  == subs xzr, x18, x10 -> add/sub shifted register
        assert_eq!(operands(0xeb0a025f), Some(vec![rd(RD), rr(RN), rr(RM)]));
    }

    #[test]
    fn add_sub_immediate_defers_on_sp() {
        // add x1, x2, #4 -> Rd write, Rn read
        assert_eq!(operands(0x91001041), Some(vec![rd(RD), rr(RN)]));
        // add x18, sp, #0 (mov x18, sp) -> names sp, deferred
        assert_eq!(operands(0x910003f2), None);
    }

    #[test]
    fn unhandled_classes_defer() {
        // ldr x18, [x0] -> load/store, deferred
        assert_eq!(operands(0xf9400012), None);
        // adrp x18, . -> PC-relative, deferred
        assert_eq!(operands(0x90000012), None);
        // ret -> branch, deferred
        assert_eq!(operands(0xd65f03c0), None);
        // svc #0 -> deferred (handled elsewhere)
        assert_eq!(operands(0xd4000001), None);
    }

    #[test]
    fn names_x18_detects_fields() {
        assert!(names_x18(0xd2830312)); // movz x18
        assert!(names_x18(0xf9400012)); // ldr x18, [x0]
        assert!(!names_x18(0xd2800000)); // movz x0
    }
}
