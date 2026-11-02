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

    // Load/store register, unsigned immediate offset, general-purpose. This
    // excludes the pair, pre/post-index, register-offset and literal forms and
    // the SIMD variants. Rt is written by a load and read by a store; the base
    // Rn is read (31 is `sp`). An `sp` base is allowed only when the stub's
    // 32-byte push can be compensated in the immediate (see `sp_adjust`).
    if insn & 0x3f00_0000 == 0x3900_0000 {
        if reg(insn, RN) == 31 && sp_adjust(insn).is_none() {
            return None;
        }
        let is_load = (insn >> 22) & 1 == 1;
        return Some(vec![
            Field { shift: RD, read: !is_load, write: is_load }, // Rt
            Field { shift: RN, read: true, write: false },       // base
        ]);
    }

    None
}

/// For a load/store (unsigned immediate) with an `sp` base, the amount to add
/// to the scaled `imm12` so the access still reaches the caller's data after
/// the stub pushes 32 bytes below `sp`. `None` if `insn` is not such an
/// instruction or the adjusted immediate would not fit.
pub fn sp_adjust(insn: u32) -> Option<u32> {
    if insn & 0x3f00_0000 != 0x3900_0000 || reg(insn, RN) != 31 {
        return None;
    }
    let scale = 1u32 << (insn >> 30); // size field: log2 of the access width
    let delta = 32 / scale;
    let imm12 = (insn >> 10) & 0xfff;
    (imm12 + delta <= 0xfff).then_some(delta)
}

/// If `insn` is a `ldr`-literal (PC-relative load), the byte offset of its
/// target relative to the instruction, and the number of bytes it loads. Used
/// to mark literal-pool data so the rewrite pass does not scan it as code.
pub fn literal_target(insn: u32) -> Option<(i64, usize)> {
    if insn & 0x3b00_0000 != 0x1800_0000 {
        return None;
    }
    let imm19 = ((insn >> 5) & 0x7_ffff) as i64;
    let off = (imm19 << 45 >> 45) * 4; // sign-extend 19 bits, scale by 4
    let v = (insn >> 26) & 1;
    let opc = (insn >> 30) & 0b11;
    let size = match (v, opc) {
        (0, 0b00) => 4,
        (0, 0b01) => 8,
        (0, 0b10) => 4, // ldrsw
        (1, 0b00) => 4,
        (1, 0b01) => 8,
        (1, 0b10) => 16,
        _ => return None, // prefetch / reserved: no data load
    };
    Some((off, size))
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
    fn load_store_unsigned_immediate() {
        // ldr x18, [x0]       -> Rt write, Rn read
        assert_eq!(operands(0xf9400012), Some(vec![rd(RD), rr(RN)]));
        // str x18, [x1, #8]   -> Rt read, Rn read
        assert_eq!(operands(0xf9000432), Some(vec![rr(RD), rr(RN)]));
        // ldr x18, [sp, #16]  -> allowed (sp offset adjusts)
        assert_eq!(operands(0xf9400bf2), Some(vec![rd(RD), rr(RN)]));
        // ldr x18, [x18, #8]  -> base and dest both x18
        assert_eq!(operands(0xf9400652), Some(vec![rd(RD), rr(RN)]));
    }

    #[test]
    fn sp_adjust_scales_by_access_size() {
        // ldr x18, [sp, #16] (64-bit): +32 bytes = +4 in the scaled imm12
        assert_eq!(sp_adjust(0xf9400bf2), Some(4));
        // ldr w18, [sp, #4] (32-bit): +32 bytes = +8
        assert_eq!(sp_adjust(0xb94007f2), Some(8));
        // a non-sp base is not adjusted
        assert_eq!(sp_adjust(0xf9400012), None);
    }

    #[test]
    fn literal_loads_are_data_targets() {
        // ldr x0, <next word> : target +0 bytes (label at the instruction), 8 bytes
        assert_eq!(literal_target(0x58000000), Some((0, 8)));
        // a plain ldr is not a literal load
        assert_eq!(literal_target(0xf9400012), None);
    }

    #[test]
    fn unhandled_classes_defer() {
        // ldp x18, x19, [sp] -> pair form, deferred
        assert_eq!(operands(0xa9404ff2), None);
        // str x18, [x0, #8]! -> pre-index writeback, deferred
        assert_eq!(operands(0xf8008c12), None);
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
