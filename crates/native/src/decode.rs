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
//! left alone rather than risk a wrong rewrite. The PC-relative forms,
//! compare/test branches and indirect branches through `x18` have their own
//! decoders here, since their stubs differ. What is still left alone — a
//! load/store with writeback onto `sp` or a register offset from `sp`, a
//! data-processing form whose operand is `sp`, `casp` and the
//! pointer-authenticated loads — is reported by [`names_x18`] so it can be
//! counted.

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

    // Add/subtract (immediate): op[28:24] = 10001. Rn 31 is `sp`. Rd 31 is `sp`
    // for plain ADD/SUB but `xzr` for the flag-setting ADDS/SUBS (bit 29 = S),
    // i.e. `cmp`/`cmn` — those must still be rewritten when they read x18.
    if (insn >> 24) & 0x1f == 0b10001 {
        let flag_setting = (insn >> 29) & 1 == 1;
        if reg(insn, RN) == 31 || (!flag_setting && reg(insn, RD) == 31) {
            return None;
        }
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Logical (immediate): op[28:23] = 100100. Rn 31 is `xzr`. Rd 31 is `sp`
    // except for ANDS (opc = 11, i.e. `tst`), where it is `xzr`.
    if (insn >> 23) & 0x3f == 0b100100 {
        let ands = (insn >> 29) & 0b11 == 0b11;
        if reg(insn, RD) == 31 && !ands {
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

    // Add/subtract (shifted register): op[28:24] = 01011 with bit 21 = 0;
    // Rd/Rn/Rm are `xzr` when 31. The extended-register form (bit 21 = 1)
    // names `sp` for Rn = 31 and, unless flag-setting (`cmp`/`cmn`), for
    // Rd = 31, which the stub cannot substitute.
    if (insn >> 24) & 0x1f == 0b01011 {
        if (insn >> 21) & 1 == 1 {
            let flag_setting = (insn >> 29) & 1 == 1;
            if reg(insn, RN) == 31 || (!flag_setting && reg(insn, RD) == 31) {
                return None;
            }
        }
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Add/subtract with carry (ADC/ADCS/SBC/SBCS): op[28:21] = 11010000.
    if (insn >> 21) & 0xff == 0b1101_0000 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Bitfield (SBFM/BFM/UBFM, and their aliases lsl/lsr/asr/ubfx/sbfiz/...).
    // op[28:23] = 100110. BFM (opc 01) preserves the untouched bits of Rd, so
    // it reads Rd as well as writing it.
    if (insn >> 23) & 0x3f == 0b100110 {
        let bfm = (insn >> 29) & 0b11 == 0b01;
        return Some(vec![
            Field { shift: RD, read: bfm, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Extract (EXTR / ROR immediate): op[28:23] = 100111.
    if (insn >> 23) & 0x3f == 0b100111 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Conditional select (CSEL/CSINC/CSINV/CSNEG): op[28:21] = 11010100.
    if (insn >> 21) & 0xff == 0b1101_0100 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Conditional compare (CCMP/CCMN): op[28:21] = 11010010. No GPR result;
    // the register form (bit 11 = 0) has Rm, the immediate form does not.
    if (insn >> 21) & 0xff == 0b1101_0010 {
        let mut f = vec![Field { shift: RN, read: true, write: false }];
        if (insn >> 11) & 1 == 0 {
            f.push(Field { shift: RM, read: true, write: false });
        }
        return Some(f);
    }

    // Data-processing (1- and 2-source): op[28:21] = 11010110. Bit 30 = 1 is a
    // one-source op (RBIT/CLZ/REV, Rd/Rn); bit 30 = 0 is two-source
    // (UDIV/LSLV/..., Rd/Rn/Rm).
    if (insn >> 21) & 0xff == 0b1101_0110 {
        let mut f = vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
        ];
        if (insn >> 30) & 1 == 0 {
            f.push(Field { shift: RM, read: true, write: false });
        }
        return Some(f);
    }

    // Data-processing (3-source): op[28:24] = 11011 (MADD/MSUB/SMULH/...).
    // Rd/Rn/Rm and the accumulator Ra at bit 10.
    if (insn >> 24) & 0x1f == 0b11011 {
        return Some(vec![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: 10, read: true, write: false }, // Ra
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Conversions between floating-point and integer (FMOV to/from a GPR,
    // FCVT*, SCVTF/UCVTF). These are the only FP instructions that touch a GPR;
    // the FP operand is a vector register (which macOS does not clear) and is
    // left alone. op[28:24] = 11110, bit 21 = 1, bits[15:10] = 0 (which
    // excludes FP arithmetic and compares). The "from general register" ops
    // (SCVTF/UCVTF and FMOV into FP, opcode 010/011/111) read Rn; the rest
    // write Rd.
    if (insn >> 24) & 0x1f == 0b11110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3f == 0 {
        let opcode = (insn >> 16) & 0b111;
        let from_gpr = matches!(opcode, 0b010 | 0b011 | 0b111);
        return Some(if from_gpr {
            vec![Field { shift: RN, read: true, write: false }]
        } else {
            vec![Field { shift: RD, read: false, write: true }]
        });
    }

    load_store(insn)
}

/// GPR operand fields of a load/store instruction, or `None` to defer. For
/// SIMD variants only the base (and a register offset) are GPRs — the
/// transfer registers are vectors, which macOS does not clear. An `sp` base is
/// kept only when the stub's 32-byte push can be compensated (see [`sp_fixup`]).
fn load_store(insn: u32) -> Option<Vec<Field>> {
    let v = (insn >> 26) & 1 == 1; // SIMD?
    let size = insn >> 30;
    let opc = (insn >> 22) & 3;
    let base = |write| Field { shift: RN, read: true, write };
    let rr = |shift| Field { shift, read: true, write: false };
    let sp_base = reg(insn, RN) == 31;
    let sp_defer = sp_base && !v && matches!(sp_fixup(insn), SpFixup::Defer);

    // Load/store exclusive, ordered (acquire/release) and compare-and-swap:
    // op[29:24] = 001000.
    if (insn >> 24) & 0x3f == 0b001000 {
        return exclusive(insn);
    }

    // Single register: unsigned immediate offset (op[29:24] = x11001), or the
    // unscaled / unprivileged / pre- and post-index / register-offset group
    // (x11000).
    let unsigned_imm = insn & 0x3b00_0000 == 0x3900_0000;
    if unsigned_imm || insn & 0x3b00_0000 == 0x3800_0000 {
        let bit21 = !unsigned_imm && (insn >> 21) & 1 == 1;
        if bit21 {
            match (insn >> 10) & 3 {
                0b10 => {} // register offset
                // The atomic memory operations.
                0b00 if !v => return atomic(insn),
                // Pointer-authenticated loads (x1), SIMD with bits 00: left alone.
                _ => return None,
            }
        }
        if bit21 {
            // Register offset: no immediate to absorb the stub's push.
            if sp_base {
                return None;
            }
        } else if sp_defer {
            return None;
        }
        let writeback = !unsigned_imm && !bit21 && matches!((insn >> 10) & 3, 0b01 | 0b11);
        let mut fields = Vec::new();
        // The transfer register. For the GPR forms opc 00 stores, 01 loads,
        // and 10/11 are the sign-extending loads (`ldrsb`/`ldrsh`/`ldrsw`) —
        // except size 11 with opc 10, `prfm`, whose Rt is a prefetch operation
        // rather than a register. For SIMD forms it is a vector register.
        if !v && !(size == 0b11 && opc == 0b10) {
            let load = opc != 0;
            fields.push(Field { shift: RD, read: !load, write: load });
        }
        fields.push(base(writeback));
        if bit21 {
            fields.push(rr(RM));
        }
        return Some(fields);
    }
    // Load/store pair: the L bit (22) is the direction.
    if insn & 0x3a00_0000 == 0x2800_0000 {
        let mode = (insn >> 23) & 3; // 01 post, 10 offset, 11 pre, 00 no-alloc
        let writeback = mode == 0b01 || mode == 0b11;
        if sp_defer {
            return None;
        }
        let load = (insn >> 22) & 1 == 1;
        let rt = |shift| Field { shift, read: !load, write: load };
        return Some(if v {
            vec![base(writeback)]
        } else {
            vec![rt(RD), rt(10), base(writeback)] // Rt, Rt2, base
        });
    }
    None
}

/// The atomic memory operations (LSE: `ldadd`/`ldclr`/`ldeor`/`ldset`/
/// `ldsmax`/…, their `st*` aliases, `swp`) and `ldapr`: Rs at the Rm position
/// is read, Rt written, Rn the base. There is no immediate, so an `sp` base
/// cannot absorb the stub's push and is left alone.
fn atomic(insn: u32) -> Option<Vec<Field>> {
    if reg(insn, RN) == 31 {
        return None;
    }
    let o3 = (insn >> 15) & 1;
    let opc = (insn >> 12) & 7;
    let rs = Field { shift: RM, read: true, write: false };
    let rt = Field { shift: RD, read: false, write: true };
    let base = Field { shift: RN, read: true, write: false };
    match (o3, opc) {
        (0, _) | (1, 0b000) => Some(vec![rs, rt, base]),
        (1, 0b100) => Some(vec![rt, base]), // ldapr: Rs is 11111
        _ => None,
    }
}

/// Load/store exclusive (`ldxr`/`stxr`, `ldaxr`/`stlxr`, the pairs), the
/// ordered loads and stores (`ldar`/`stlr`, `ldlar`/`stllr`) and
/// compare-and-swap (`cas*`). A store-exclusive writes its status to Rs (at
/// the Rm position); `cas` reads and writes Rs. `casp` names register pairs
/// and is left alone, as is an `sp` base (no immediate to adjust).
fn exclusive(insn: u32) -> Option<Vec<Field>> {
    if reg(insn, RN) == 31 {
        return None;
    }
    let o2 = (insn >> 23) & 1;
    let load = (insn >> 22) & 1 == 1;
    let o1 = (insn >> 21) & 1;
    let status = Field { shift: RM, read: false, write: true };
    let rt = Field { shift: RD, read: !load, write: load };
    let rt2 = Field { shift: 10, read: !load, write: load };
    let base = Field { shift: RN, read: true, write: false };
    match (o2, o1) {
        // Exclusive, single register.
        (0, 0) => Some(if load { vec![rt, base] } else { vec![status, rt, base] }),
        // Exclusive pair (size 1x); size 0x here is `casp`.
        (0, 1) => {
            if insn >> 31 == 0 {
                return None;
            }
            Some(if load { vec![rt, rt2, base] } else { vec![status, rt, rt2, base] })
        }
        // Ordered load/store.
        (1, 0) => Some(vec![rt, base]),
        // Compare and swap: Rs holds the comparison value and receives the old
        // one; Rt is the value stored. Bit 22 is acquire here, not a direction.
        _ => Some(vec![
            Field { shift: RM, read: true, write: true },
            Field { shift: RD, read: true, write: false },
            base,
        ]),
    }
}

/// What to do with the `sp`-relative offset of a load/store when the stub has
/// pushed 32 bytes below `sp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpFixup {
    /// Base is not `sp`; the instruction runs unchanged.
    NotSp,
    /// Base is `sp`; run this instruction (offset bumped by 32 bytes) instead.
    Adjusted(u32),
    /// Base is `sp` but the bump cannot be encoded (or is a writeback form);
    /// do not rewrite.
    Defer,
}

/// Compute the [`SpFixup`] for a general-purpose load/store. Only called for
/// GPR forms (`V == 0`); SIMD forms never name `x18` as a transfer register.
pub fn sp_fixup(insn: u32) -> SpFixup {
    if reg(insn, RN) != 31 {
        return SpFixup::NotSp;
    }
    // Unsigned immediate: scaled imm12.
    if insn & 0x3b00_0000 == 0x3900_0000 {
        let scale = 1u32 << (insn >> 30);
        let imm12 = (insn >> 10) & 0xfff;
        let n = imm12 + 32 / scale;
        return if n <= 0xfff {
            SpFixup::Adjusted((insn & !(0xfff << 10)) | (n << 10))
        } else {
            SpFixup::Defer
        };
    }
    // Unscaled / index / register-offset family.
    if insn & 0x3b00_0000 == 0x3800_0000 {
        if (insn >> 21) & 1 == 1 {
            return SpFixup::Defer; // register offset
        }
        let idx = (insn >> 10) & 3;
        if idx == 0b01 || idx == 0b11 {
            return SpFixup::Defer; // writeback onto sp
        }
        let imm9 = (((insn >> 12) & 0x1ff) as i32) << 23 >> 23; // signed byte offset
        let n = imm9 + 32;
        return if (-256..=255).contains(&n) {
            SpFixup::Adjusted((insn & !(0x1ff << 12)) | (((n as u32) & 0x1ff) << 12))
        } else {
            SpFixup::Defer
        };
    }
    // Pair.
    if insn & 0x3a00_0000 == 0x2800_0000 {
        let mode = (insn >> 23) & 3;
        if mode == 0b01 || mode == 0b11 {
            return SpFixup::Defer; // writeback onto sp
        }
        let scale = 4i32 << ((insn >> 31) & 1); // 4 (w) or 8 (x)
        let imm7 = (((insn >> 15) & 0x7f) as i32) << 25 >> 25; // signed count of `scale`
        let n = imm7 + 32 / scale;
        return if (-64..=63).contains(&n) {
            SpFixup::Adjusted((insn & !(0x7f << 15)) | (((n as u32) & 0x7f) << 15))
        } else {
            SpFixup::Defer
        };
    }
    SpFixup::NotSp
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

/// If `insn` is `adr`/`adrp` writing `x18`, returns `Some(is_adrp)`. These are
/// PC-relative, so moving them to a stub would change the result; the stub
/// instead materializes the value computed from the original pc.
pub fn x18_adr(insn: u32) -> Option<bool> {
    ((insn >> 24) & 0x1f == 0b10000 && insn & 0x1f == 18).then_some((insn >> 31) & 1 == 1)
}

/// Whether `insn` is a general-purpose `ldr`-literal loading into `x18` (also
/// PC-relative). SIMD literal loads target a vector register, not `x18`.
pub fn x18_ldr_literal(insn: u32) -> bool {
    insn & 0x3b00_0000 == 0x1800_0000 && (insn >> 26) & 1 == 0 && insn & 0x1f == 18
}

/// If `insn` is an indirect branch (`br`/`blr`/`ret`) through `x18`, returns
/// `Some(sets_link)` — true for `blr`. The target register is `Rn` (bits 9:5).
pub fn x18_indirect(insn: u32) -> Option<bool> {
    if (insn >> 25) & 0x7f != 0b1101011 || (insn >> 5) & 0x1f != 18 {
        return None;
    }
    match (insn >> 21) & 0xf {
        0b0000 | 0b0010 => Some(false), // br, ret
        0b0001 => Some(true),           // blr
        _ => None,                      // authenticated variants: not handled
    }
}

/// Whether `insn` is a compare-and-branch (`cbz`/`cbnz`) or test-branch
/// (`tbz`/`tbnz`) that reads `x18`. These are branches, so they cannot be moved
/// to a stub naively; the branch stub loads `x18` into a scratch, tests it, and
/// jumps to the real target or the fall-through. The tested register is `Rt`
/// (bits 4:0).
pub fn x18_branch(insn: u32) -> bool {
    let family = (insn >> 25) & 0x3f;
    (family == 0b011010 || family == 0b011011) && insn & 0x1f == 18
}

/// Whether `insn` names `x18` in any standard register-operand position. This
/// over-approximates (it looks at the fixed Rd/Rn/Rm/Rt positions regardless of
/// class) and is used only to *count* `x18` uses this pass leaves alone (the
/// `sp` forms), so a false positive inflates a diagnostic but changes no code.
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
        // add x18, sp, #0 (mov x18, sp) -> Rn is sp, deferred
        assert_eq!(operands(0x910003f2), None);
        // add sp, x18, #8 -> Rd is sp, deferred
        assert_eq!(operands(0x9100225f), None);
        // cmp x18, #42 == subs xzr, x18, #42 -> Rd is xzr; read x18
        assert_eq!(operands(0xf100aa5f), Some(vec![rd(RD), rr(RN)]));
        // cmn x18, #1 == adds xzr, x18, #1 -> read x18
        assert_eq!(operands(0xb100065f), Some(vec![rd(RD), rr(RN)]));
        // subs x18, x19, #1 -> write x18, read x19
        assert_eq!(operands(0xf1000672), Some(vec![rd(RD), rr(RN)]));
    }

    #[test]
    fn logical_immediate_tst_reads_x18() {
        // tst x18, #0xff == ands xzr, x18, #0xff -> Rd is xzr; read x18
        assert_eq!(operands(0xf2401e5f), Some(vec![rd(RD), rr(RN)]));
        // ands x18, x0, #0xff -> write x18, read x0
        assert_eq!(operands(0xf2401c12), Some(vec![rd(RD), rr(RN)]));
    }

    #[test]
    fn register_only_data_processing() {
        // ubfx x18, x0, #4, #8 (bitfield, UBFM): Rd write, Rn read
        assert_eq!(operands(0xd3442c12), Some(vec![rd(RD), rr(RN)]));
        // sbfiz x18, x1, #3, #5 (SBFM): Rd write only
        assert_eq!(operands(0x937d1032), Some(vec![rd(RD), rr(RN)]));
        // extr x18, x0, x1, #8: Rd write, Rn/Rm read
        assert_eq!(operands(0x93c12012), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // csel x18, x0, x1, eq: Rd write, Rn/Rm read
        assert_eq!(operands(0x9a810012), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // ccmp x18, x0, #0, eq (register form): Rn/Rm read, no Rd
        assert_eq!(operands(0xfa400240), Some(vec![rr(RN), rr(RM)]));
        // ccmp x18, #3, #0, eq (immediate form): Rn read only
        assert_eq!(operands(0xfa430a40), Some(vec![rr(RN)]));
        // udiv x18, x0, x1 (two-source): Rd write, Rn/Rm read
        assert_eq!(operands(0x9ac10812), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // rbit x18, x0 (one-source): Rd write, Rn read
        assert_eq!(operands(0xdac00012), Some(vec![rd(RD), rr(RN)]));
        // madd x18, x0, x1, x2 (three-source): Rd write, Rn/Ra/Rm read
        assert_eq!(operands(0x9b010812), Some(vec![rd(RD), rr(RN), rr(10), rr(RM)]));
    }

    #[test]
    fn bfm_reads_its_destination() {
        // bfxil x18, x0, #8, #8 (BFM, opc=01) reads and writes Rd.
        assert_eq!(
            operands(0xb3483c12).map(|v| v[0]),
            Some(Field { shift: RD, read: true, write: true })
        );
        // bfi x18, x0, #0, #8 (also BFM)
        assert_eq!(
            operands(0xb3401c12).map(|v| v[0]),
            Some(Field { shift: RD, read: true, write: true })
        );
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
    fn sp_fixup_bumps_the_offset() {
        // ldr x18, [sp, #16] (64-bit): +32 bytes = +4 scaled -> ldr x18,[sp,#48]
        assert_eq!(sp_fixup(0xf9400bf2), SpFixup::Adjusted(0xf9401bf2));
        // a non-sp base is left unchanged
        assert_eq!(sp_fixup(0xf9400012), SpFixup::NotSp);
    }

    #[test]
    fn load_store_addressing_forms() {
        // ldur x18, [x0, #-8]: unscaled, Rt write (load), base read
        assert_eq!(operands(0xf85f8012), Some(vec![rd(RD), rr(RN)]));
        // ldr x18, [x0, #8]! : pre-index, base read+write
        assert_eq!(
            operands(0xf8408c12),
            Some(vec![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // ldr x18, [x0], #8  : post-index, base read+write
        assert_eq!(
            operands(0xf8408412),
            Some(vec![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // str x18, [sp, #16]! : pre-index onto sp -> deferred
        assert_eq!(operands(0xf8010ff2), None);
        // ldr x18, [x0, x1]  : register offset, Rt write, base read, Rm read
        assert_eq!(operands(0xf8616812), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // ldp x18, x19, [x0, #16] : pair offset, Rt/Rt2 write, base read
        assert_eq!(operands(0xa9414c12), Some(vec![rd(RD), rd(10), rr(RN)]));
        // ldp x18, x19, [sp, #16] : pair offset onto sp -> allowed (imm7 adjusts)
        assert_eq!(operands(0xa9414ff2), Some(vec![rd(RD), rd(10), rr(RN)]));
        // ldp x18, x19, [x0], #16 : pair post-index, base read+write
        assert_eq!(
            operands(0xa8c14c12),
            Some(vec![rd(RD), rd(10), Field { shift: RN, read: true, write: true }])
        );
    }

    #[test]
    fn sign_extending_loads_write_their_destination() {
        // ldrsw x18, [x1, #4]: opc 10 is a load, not a store
        assert_eq!(operands(0xb9800432), Some(vec![rd(RD), rr(RN)]));
        // ldrsb x18, [x1]
        assert_eq!(operands(0x39800032), Some(vec![rd(RD), rr(RN)]));
        // ldrsh w18, [x1, #2]: opc 11
        assert_eq!(operands(0x79c00432), Some(vec![rd(RD), rr(RN)]));
        // ldursw x18, [x1, #-4]
        assert_eq!(operands(0xb89fc032), Some(vec![rd(RD), rr(RN)]));
        // ldrsw x18, [x1, x2]
        assert_eq!(operands(0xb8a26832), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // ldrsw x18, [x1], #4
        assert_eq!(
            operands(0xb8804432),
            Some(vec![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // prfm pldl1keep, [x18]: Rt is a prefetch operation; only the base is
        // a register
        assert_eq!(operands(0xf9800240), Some(vec![rr(RN)]));
        // prfm pstl2keep, [x0, #8]: its operation field happens to be 18
        assert_eq!(operands(0xf9800412), Some(vec![rr(RN)]));
    }

    #[test]
    fn atomic_memory_operations() {
        // ldadd x0, x18, [x1]: Rs read, Rt write, base read
        assert_eq!(operands(0xf8200032), Some(vec![rr(RM), rd(RD), rr(RN)]));
        // ldadd x18, x0, [x1]
        assert_eq!(operands(0xf8320020), Some(vec![rr(RM), rd(RD), rr(RN)]));
        // stadd x18, [x1] (Rt = xzr)
        assert_eq!(operands(0xf832003f), Some(vec![rr(RM), rd(RD), rr(RN)]));
        // swp x18, x0, [x1]
        assert_eq!(operands(0xf8328020), Some(vec![rr(RM), rd(RD), rr(RN)]));
        // ldapr x18, [x1]
        assert_eq!(operands(0xf8bfc032), Some(vec![rd(RD), rr(RN)]));
        // ldaddal x18, x0, [sp]: sp base, deferred
        assert_eq!(operands(0xf8f203e0), None);
        // ldraa x18, [x1]: pointer-authenticated load, deferred
        assert_eq!(operands(0xf8200432), None);
    }

    #[test]
    fn exclusive_and_ordered_loads_stores() {
        let rw = |shift| Field { shift, read: true, write: true };
        // ldxr x18, [x1]; ldaxr x18, [x1]
        assert_eq!(operands(0xc85f7c32), Some(vec![rd(RD), rr(RN)]));
        assert_eq!(operands(0xc85ffc32), Some(vec![rd(RD), rr(RN)]));
        // stxr w18, x1, [x2]: status write, data read, base read
        assert_eq!(operands(0xc8127c41), Some(vec![rd(RM), rr(RD), rr(RN)]));
        // stlxr w2, x18, [x1]
        assert_eq!(operands(0xc802fc32), Some(vec![rd(RM), rr(RD), rr(RN)]));
        // ldxp x18, x19, [x1]
        assert_eq!(operands(0xc87f4c32), Some(vec![rd(RD), rd(10), rr(RN)]));
        // stxp w18, x1, x2, [x3]
        assert_eq!(operands(0xc8320861), Some(vec![rd(RM), rr(RD), rr(10), rr(RN)]));
        // ldar x18, [x1]; stlr x18, [x1]
        assert_eq!(operands(0xc8dffc32), Some(vec![rd(RD), rr(RN)]));
        assert_eq!(operands(0xc89ffc32), Some(vec![rr(RD), rr(RN)]));
        // cas x18, x0, [x1]: Rs is compared and receives the old value
        assert_eq!(operands(0xc8b27c20), Some(vec![rw(RM), rr(RD), rr(RN)]));
        // casal x0, x18, [x1]
        assert_eq!(operands(0xc8e0fc32), Some(vec![rw(RM), rr(RD), rr(RN)]));
        // casp x0, x1, x2, x3, [x18]: register pairs, deferred
        assert_eq!(operands(0x48207e42), None);
        // ldar x18, [sp]: sp base, deferred
        assert_eq!(operands(0xc8dffff2), None);
    }

    #[test]
    fn extended_register_and_carry_arithmetic() {
        // add x18, x0, w1, sxtw
        assert_eq!(operands(0x8b21c012), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // cmp x18, w1, uxtw (Rd is xzr)
        assert_eq!(operands(0xeb21425f), Some(vec![rd(RD), rr(RN), rr(RM)]));
        // add sp, x18, x1: Rd is sp, deferred
        assert_eq!(operands(0x8b21625f), None);
        // add x18, sp, x1: Rn is sp, deferred
        assert_eq!(operands(0x8b2163f2), None);
        // adc x18, x0, x1; sbcs x18, x0, x1
        assert_eq!(operands(0x9a010012), Some(vec![rd(RD), rr(RN), rr(RM)]));
        assert_eq!(operands(0xfa010012), Some(vec![rd(RD), rr(RN), rr(RM)]));
    }

    #[test]
    fn fp_integer_conversions() {
        // fmov x18, d0 (to GPR): Rd write
        assert_eq!(operands(0x9e660012), Some(vec![rd(RD)]));
        // fcvtzs x18, d0 (to GPR): Rd write
        assert_eq!(operands(0x9e780012), Some(vec![rd(RD)]));
        // fmov x18, v0.d[1] (to GPR): Rd write
        assert_eq!(operands(0x9eae0012), Some(vec![rd(RD)]));
        // fmov d0, x18 (from GPR): Rn read
        assert_eq!(operands(0x9e670240), Some(vec![rr(RN)]));
        // scvtf d0, x18 (from GPR): Rn read
        assert_eq!(operands(0x9e620240), Some(vec![rr(RN)]));
        // ucvtf s0, w18 (from GPR): Rn read
        assert_eq!(operands(0x1e230240), Some(vec![rr(RN)]));
        // fadd d0, d1, d2 (FP arithmetic, no GPR): deferred
        assert_eq!(operands(0x1e622820), None);
    }

    #[test]
    fn simd_load_store_only_exposes_the_base() {
        // ldr q0, [x18]: SIMD, base read only (q0 is a vector, not x18)
        assert_eq!(operands(0x3dc00240), Some(vec![rr(RN)]));
        // ldp q0, q1, [x18]: SIMD pair, base read only
        assert_eq!(operands(0xad400640), Some(vec![rr(RN)]));
        // str d0, [x18, x1]: SIMD register offset, base + Rm
        assert_eq!(operands(0xfc216a40), Some(vec![rr(RN), rr(RM)]));
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
        // adrp x18, . -> PC-relative, deferred
        assert_eq!(operands(0x90000012), None);
        // ret -> branch, deferred
        assert_eq!(operands(0xd65f03c0), None);
        // svc #0 -> deferred (handled elsewhere)
        assert_eq!(operands(0xd4000001), None);
        // str x18, [sp, #16]! -> pre-index writeback onto sp, deferred
        assert_eq!(operands(0xf8010ff2), None);
    }

    #[test]
    fn pc_relative_and_indirect_x18() {
        assert_eq!(x18_adr(0x10000012), Some(false)); // adr x18
        assert_eq!(x18_adr(0x90000012), Some(true)); // adrp x18
        assert_eq!(x18_adr(0x10000000), None); // adr x0
        assert!(x18_ldr_literal(0x58000012)); // ldr x18, <lit>
        assert!(!x18_ldr_literal(0x58000000)); // ldr x0, <lit>
        assert_eq!(x18_indirect(0xd61f0240), Some(false)); // br x18
        assert_eq!(x18_indirect(0xd63f0240), Some(true)); // blr x18
        assert_eq!(x18_indirect(0xd65f0240), Some(false)); // ret x18
        assert_eq!(x18_indirect(0xd61f0000), None); // br x0
        // these are all left out of the operand decoder
        assert_eq!(operands(0x90000012), None);
        assert_eq!(operands(0xd61f0240), None);
    }

    #[test]
    fn x18_branches_detected() {
        assert!(x18_branch(0xb5000012)); // cbnz x18
        assert!(x18_branch(0xb4000012)); // cbz x18
        assert!(x18_branch(0x37280012)); // tbnz x18, #5
        assert!(x18_branch(0x36180012)); // tbz w18, #3
        assert!(!x18_branch(0xb5000000)); // cbnz x0
        assert!(!x18_branch(0x14000000)); // b
        // these are branches, so the register decoder leaves them alone
        assert_eq!(operands(0xb5000012), None);
    }

    #[test]
    fn names_x18_detects_fields() {
        assert!(names_x18(0xd2830312)); // movz x18
        assert!(names_x18(0xf9400012)); // ldr x18, [x0]
        assert!(!names_x18(0xd2800000)); // movz x0
    }
}
