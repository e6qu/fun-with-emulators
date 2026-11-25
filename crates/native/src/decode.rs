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
//! decoders here, since their stubs differ, as do `casp` (register pairs), a
//! load/store with writeback onto `sp` and a result written to `sp`. What is
//! still left alone — the memory-tagging instructions with an `sp` operand
//! (which no Apple CPU runs), `casp` on `sp`, a pointer-authenticated load
//! written back onto `sp` and `blraa x18, x30` — is found by [`names_x18`],
//! which knows the register fields of every non-SIMD group, so it can be
//! counted exactly.

/// At most four values, held in place: an instruction's register fields
/// ([`operands`], [`gpr_fields`]), found for each instruction of each block
/// translated, where a `Vec` cost an allocation each.
#[derive(Clone, Copy)]
pub struct Few<T: Copy + Default> {
    items: [T; 4],
    len: usize,
}

impl<T: Copy + Default> Few<T> {
    pub fn new() -> Few<T> {
        Few { items: [T::default(); 4], len: 0 }
    }

    pub fn push(&mut self, v: T) {
        assert!(self.len < self.items.len(), "more than four fields");
        self.items[self.len] = v;
        self.len += 1;
    }
}

impl<T: Copy + Default> Default for Few<T> {
    fn default() -> Few<T> {
        Few::new()
    }
}

impl<T: Copy + Default> std::ops::Deref for Few<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.items[..self.len]
    }
}

impl<T: Copy + Default> IntoIterator for Few<T> {
    type Item = T;
    type IntoIter = std::iter::Take<std::array::IntoIter<T, 4>>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter().take(self.len)
    }
}

impl<'a, T: Copy + Default> IntoIterator for &'a Few<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Copy + Default> Extend<T> for Few<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, vs: I) {
        for v in vs {
            self.push(v);
        }
    }
}

impl<T: Copy + Default> FromIterator<T> for Few<T> {
    fn from_iter<I: IntoIterator<Item = T>>(vs: I) -> Few<T> {
        let mut f = Few::new();
        f.extend(vs);
        f
    }
}

impl<T: Copy + Default + PartialEq> PartialEq for Few<T> {
    fn eq(&self, other: &Few<T>) -> bool {
        **self == **other
    }
}

impl<T: Copy + Default + std::fmt::Debug> std::fmt::Debug for Few<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt(f)
    }
}

/// A [`Few`] of the values given.
macro_rules! few {
    ($($v:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut f = Few::new();
        $(f.push($v);)*
        f
    }};
}

/// A register operand: its field position (low bit) and access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
pub fn operands(insn: u32) -> Option<Few<Field>> {
    // System instructions with a general register: `mrs`/`msr` of a system
    // register, `sys`/`sysl` (`dc civac, x18` and the like) and `wfet`/
    // `wfit`. L (bit 21) set: the register is written. `TPIDR_EL0` never
    // gets here (the thread-pointer stubs take it); `ctr_el0`, which macOS
    // traps, is emulated as it traps, in the stub as anywhere.
    if insn >> 22 == 0b11_0101_0100 {
        let write = (insn >> 21) & 1 == 1;
        let op0 = (insn >> 19) & 3;
        let wfet = op0 == 0 && (insn >> 12) & 0xf == 0b0001 && !write;
        if op0 == 0 && !wfet {
            return None; // hints, barriers, `msr` of PSTATE fields
        }
        return Some(few![Field { shift: RD, read: !write, write }]);
    }

    // Move wide immediate: op[28:23] = 100101. opc[30:29]: 00=MOVN, 10=MOVZ,
    // 11=MOVK (01 is unallocated). MOVK preserves the other bits, so it reads
    // its destination as well as writing it.
    if (insn >> 23) & 0x3f == 0b100101 {
        let opc = (insn >> 29) & 0b11;
        if opc == 0b01 {
            return None;
        }
        let movk = opc == 0b11;
        return Some(few![Field { shift: RD, read: movk, write: true }]);
    }

    // Add/subtract (immediate): op[28:24] = 10001. Rn 31 is `sp`. Rd 31 is `sp`
    // for plain ADD/SUB but `xzr` for the flag-setting ADDS/SUBS (bit 29 = S),
    // i.e. `cmp`/`cmn` — those still need rewriting when they read x18.
    if (insn >> 24) & 0x1f == 0b10001 {
        let flag_setting = (insn >> 29) & 1 == 1;
        if reg(insn, RN) == 31 {
            // `add x18, sp, #imm` and the like (`mov x18, sp`): `sp` as it
            // is (a stub leaves it); one writing `sp` names no `x18`.
            if flag_setting || reg(insn, RD) != 31 {
                return Some(few![Field { shift: RD, read: false, write: true }]);
            }
            return None;
        }
        if !flag_setting && reg(insn, RD) == 31 {
            return None;
        }
        return Some(few![
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
        return Some(few![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Logical (shifted register): op[28:24] = 01010. All of Rd/Rn/Rm are `xzr`
    // when 31, never `sp`.
    if (insn >> 24) & 0x1f == 0b01010 {
        return Some(few![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Add/subtract (shifted register): op[28:24] = 01011 with bit 21 = 0;
    // Rd/Rn/Rm are `xzr` when 31. The extended-register form (bit 21 = 1)
    // names `sp` for Rn = 31 (left as it is) and, unless flag-setting
    // (`cmp`/`cmn`), for Rd = 31: one writing `sp` has a stub of its own
    // ([`x18_writes_sp`]).
    if (insn >> 24) & 0x1f == 0b01011 {
        if (insn >> 21) & 1 == 1 {
            let flag_setting = (insn >> 29) & 1 == 1;
            if !flag_setting && reg(insn, RD) == 31 {
                return None;
            }
        }
        return Some(few![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Add/subtract with carry (ADC/ADCS/SBC/SBCS): op[28:21] = 11010000.
    if (insn >> 21) & 0xff == 0b1101_0000 {
        return Some(few![
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
        return Some(few![
            Field { shift: RD, read: bfm, write: true },
            Field { shift: RN, read: true, write: false },
        ]);
    }

    // Extract (EXTR / ROR immediate): op[28:23] = 100111.
    if (insn >> 23) & 0x3f == 0b100111 {
        return Some(few![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Conditional select (CSEL/CSINC/CSINV/CSNEG): op[28:21] = 11010100.
    if (insn >> 21) & 0xff == 0b1101_0100 {
        return Some(few![
            Field { shift: RD, read: false, write: true },
            Field { shift: RN, read: true, write: false },
            Field { shift: RM, read: true, write: false },
        ]);
    }

    // Conditional compare (CCMP/CCMN): op[28:21] = 11010010. No GPR result;
    // the register form (bit 11 = 0) has Rm, the immediate form does not.
    if (insn >> 21) & 0xff == 0b1101_0010 {
        let mut f = few![Field { shift: RN, read: true, write: false }];
        if (insn >> 11) & 1 == 0 {
            f.push(Field { shift: RM, read: true, write: false });
        }
        return Some(f);
    }

    // Data-processing (1- and 2-source): op[28:21] = 11010110. Bit 30 = 1 is a
    // one-source op (RBIT/CLZ/REV, Rd/Rn); bit 30 = 0 is two-source
    // (UDIV/LSLV/..., Rd/Rn/Rm).
    if (insn >> 21) & 0xff == 0b1101_0110 {
        let opcode = (insn >> 10) & 0x3f;
        let rn = Field { shift: RN, read: true, write: false };
        let rm = Field { shift: RM, read: true, write: false };
        if (insn >> 30) & 1 == 1 {
            // Pointer authentication (opcode2 00001): `pacia`/`autia` and
            // the rest sign or check Rd in place, with the modifier in Rn
            // (`sp` for 31); the zero-modifier forms and `xpaci`/`xpacd`
            // have no Rn.
            if (insn >> 16) & 0x1f == 0b00001 {
                let rd = Field { shift: RD, read: true, write: true };
                return match opcode {
                    0..=7 => Some(few![rd, rn]),
                    8..=17 => Some(few![rd]),
                    _ => None,
                };
            }
            return Some(few![Field { shift: RD, read: false, write: true }, rn]);
        }
        let rd = Field { shift: RD, read: false, write: true };
        let sp = |shift| reg(insn, shift) == 31;
        return match opcode {
            // `pacga`: Rm 31 is `sp`, through a scratch register.
            0b001100 => Some(few![rd, rn, rm]),
            // The memory-tagging `subp`, `irg` and `gmi`, whose 31s are
            // `sp`: left alone with one (no Apple CPU runs them).
            0b000000 | 0b000100 | 0b000101 if sp(RD) || sp(RN) || sp(RM) => None,
            _ => Some(few![rd, rn, rm]),
        };
    }

    // Data-processing (3-source): op[28:24] = 11011 (MADD/MSUB/SMULH/...).
    // Rd/Rn/Rm and the accumulator Ra at bit 10.
    if (insn >> 24) & 0x1f == 0b11011 {
        return Some(few![
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
            few![Field { shift: RN, read: true, write: false }]
        } else {
            few![Field { shift: RD, read: false, write: true }]
        });
    }

    // Moves between a general register and a vector element (AdvSIMD copy,
    // op = 0): `dup` and `ins` from a general register read Rn; `smov` and
    // `umov` (`mov` to a general register) write Rd. The vector operand is
    // left alone, as for the conversions above.
    if insn & 0xbfe0_8400 == 0x0e00_0400 {
        return match (insn >> 11) & 0xf {
            0b0001 | 0b0011 => Some(few![Field { shift: RN, read: true, write: false }]),
            0b0101 | 0b0111 => Some(few![Field { shift: RD, read: false, write: true }]),
            _ => None,
        };
    }

    // AdvSIMD load/store of multiple structures or of a single structure
    // (`ld1`..`ld4`, `st1`..`st4`, `ld1r`..`ld4r`): the vectors are left
    // alone; Rn is the base, written back by the post-index forms (bit 23),
    // whose Rm is a register offset unless it is 31 (an immediate). With an
    // `sp` base, `x18` can be only the offset that writes `sp` back, which
    // [`x18_writes_sp`] finds.
    if insn & 0xbe00_0000 == 0x0c00_0000 {
        if reg(insn, RN) == 31 {
            return None;
        }
        let post = (insn >> 23) & 1 == 1;
        let mut f = few![Field { shift: RN, read: true, write: post }];
        if post && reg(insn, RM) != 31 {
            f.push(Field { shift: RM, read: true, write: false });
        }
        return Some(f);
    }

    load_store(insn)
}

/// GPR operand fields of a load/store instruction, or `None` to defer. For
/// SIMD variants only the base (and a register offset) are GPRs — the
/// transfer registers are vectors, which macOS does not clear. An `sp` base,
/// written back or not, stays as it is: a stub leaves `sp` alone.
fn load_store(insn: u32) -> Option<Few<Field>> {
    let v = (insn >> 26) & 1 == 1; // SIMD?
    let size = insn >> 30;
    let opc = (insn >> 22) & 3;
    let base = |write| Field { shift: RN, read: true, write };
    let rr = |shift| Field { shift, read: true, write: false };

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
                // The pointer-authenticated loads (`ldraa`/`ldrab`, bits x1):
                // Rt written, the base written back with W (bit 11).
                0b01 | 0b11 if !v && size == 0b11 => {
                    let w = (insn >> 11) & 1 == 1;
                    return Some(few![Field { shift: RD, read: false, write: true }, base(w)]);
                }
                _ => return None,
            }
        }
        let writeback = !unsigned_imm && !bit21 && matches!((insn >> 10) & 3, 0b01 | 0b11);
        let mut fields = Few::new();
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
        let load = (insn >> 22) & 1 == 1;
        let rt = |shift| Field { shift, read: !load, write: load };
        return Some(if v {
            few![base(writeback)]
        } else {
            few![rt(RD), rt(10), base(writeback)] // Rt, Rt2, base
        });
    }
    None
}

/// The atomic memory operations (LSE: `ldadd`/`ldclr`/`ldeor`/`ldset`/
/// `ldsmax`/…, their `st*` aliases, `swp`) and `ldapr`: Rs at the Rm position
/// is read, Rt written, Rn the base (`sp` as it is).
fn atomic(insn: u32) -> Option<Few<Field>> {
    let o3 = (insn >> 15) & 1;
    let opc = (insn >> 12) & 7;
    let rs = Field { shift: RM, read: true, write: false };
    let rt = Field { shift: RD, read: false, write: true };
    let base = Field { shift: RN, read: true, write: false };
    match (o3, opc) {
        (0, _) | (1, 0b000) => Some(few![rs, rt, base]),
        (1, 0b100) => Some(few![rt, base]), // ldapr: Rs is 11111
        _ => None,
    }
}

/// Load/store exclusive (`ldxr`/`stxr`, `ldaxr`/`stlxr`, the pairs), the
/// ordered loads and stores (`ldar`/`stlr`, `ldlar`/`stllr`) and
/// compare-and-swap (`cas*`). A store-exclusive writes its status to Rs (at
/// the Rm position); `cas` reads and writes Rs. An `sp` base goes through a
/// scratch register (no immediate to adjust). `casp` names register pairs,
/// which a stub of its own takes ([`x18_casp`]).
fn exclusive(insn: u32) -> Option<Few<Field>> {
    let o2 = (insn >> 23) & 1;
    let load = (insn >> 22) & 1 == 1;
    let o1 = (insn >> 21) & 1;
    let status = Field { shift: RM, read: false, write: true };
    let rt = Field { shift: RD, read: !load, write: load };
    let rt2 = Field { shift: 10, read: !load, write: load };
    let base = Field { shift: RN, read: true, write: false };
    match (o2, o1) {
        // Exclusive, single register.
        (0, 0) => Some(if load { few![rt, base] } else { few![status, rt, base] }),
        // Exclusive pair (size 1x); size 0x here is `casp`.
        (0, 1) => {
            if insn >> 31 == 0 {
                return None;
            }
            Some(if load { few![rt, rt2, base] } else { few![status, rt, rt2, base] })
        }
        // Ordered load/store.
        (1, 0) => Some(few![rt, base]),
        // Compare and swap: Rs holds the comparison value and receives the old
        // one; Rt is the value stored. Bit 22 is acquire here, not a direction.
        _ => Some(few![
            Field { shift: RM, read: true, write: true },
            Field { shift: RD, read: true, write: false },
            base,
        ]),
    }
}

/// Whether `insn` is a `casp` (compare and swap a pair) that names `x18`
/// in one of its pairs or as its base, which [`operands`] leaves to a stub
/// of its own: its pairs stay even-numbered pairs of registers. One
/// on `sp` is left alone.
pub fn x18_casp(insn: u32) -> bool {
    insn & 0xbfa0_7c00 == 0x0820_7c00
        && reg(insn, RN) != 31
        && [RM, RD, RN].iter().any(|&f| reg(insn, f) == 18)
}

/// Whether `insn` writes `sp` from a value computed with `x18`: `mov sp,
/// x18`, `add`/`sub` (immediate or extended register) or a logical
/// immediate into `sp`, or a SIMD structure load or store on `sp` written
/// back by `x18`. [`operands`] defers it; its stub runs it with a scratch
/// register for `x18`, writing `sp` itself.
pub fn x18_writes_sp(insn: u32) -> bool {
    if reg(insn, RD) != 31 {
        return insn & 0xbe80_0000 == 0x0c80_0000 && reg(insn, RN) == 31 && reg(insn, RM) == 18;
    }
    let flag_setting = (insn >> 29) & 1 == 1;
    if (insn >> 24) & 0x1f == 0b10001 {
        return !flag_setting && reg(insn, RN) == 18;
    }
    if (insn >> 24) & 0x1f == 0b01011 && (insn >> 21) & 1 == 1 {
        return !flag_setting && (reg(insn, RN) == 18 || reg(insn, RM) == 18);
    }
    if (insn >> 23) & 0x3f == 0b100100 {
        return (insn >> 29) & 3 != 0b11 && reg(insn, RN) == 18;
    }
    false
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

/// If `insn` is an indirect branch through `x18` (`br`/`blr`/`ret`, and the
/// authenticated `braa`/`blraa` and their `b` and zero-modifier forms),
/// returns `Some(sets_link)` — true for the `blr` forms. The target register
/// is `Rn` (bits 9:5); an authenticated one's modifier is `Rm` (bits 4:0,
/// `sp` for 31). `blraa x18, x30` is left alone: its stub sets the link
/// register before the branch reads the modifier.
pub fn x18_indirect(insn: u32) -> Option<bool> {
    if (insn >> 25) & 0x7f != 0b1101011 || reg(insn, RN) != 18 || (insn >> 16) & 0x1f != 0x1f {
        return None;
    }
    let z = (insn >> 24) & 1; // 1: a modifier register
    let opc = (insn >> 21) & 0x3;
    let auth = (insn >> 11) & 1 == 1;
    if (insn >> 12) & 0xf != 0 || (insn >> 23) & 1 != 0 || (insn >> 22) & 1 == 1 && (z == 1 || auth)
    {
        return None;
    }
    if !auth && (z == 1 || (insn >> 10) & 1 != 0 || insn & 0x1f != 0) {
        return None;
    }
    if auth && z == 0 && insn & 0x1f != 0x1f {
        return None;
    }
    let link = opc == 0b01;
    if link && auth && z == 1 && insn & 0x1f == 30 {
        return None;
    }
    match opc {
        0b00 | 0b10 => Some(false), // br, ret (and braa, brab)
        0b01 => Some(true),         // blr (and blraa, blrab)
        _ => None,
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

/// The bit positions of `insn`'s general-purpose register fields, for the
/// instruction groups that have them, or `None` for a group this does not
/// classify (SIMD and floating point other than the GPR conversions).
/// Unlike [`operands`] it includes the forms the rewrite defers, so the
/// deferred `x18` uses can be counted precisely.
fn gpr_fields(insn: u32) -> Option<Few<u32>> {
    let v = (insn >> 26) & 1 == 1;
    let top = (insn >> 25) & 0xf; // op0, bits 28:25
    match top {
        // Data processing, immediate.
        0b1000 | 0b1001 => Some(match (insn >> 23) & 0x7 {
            0b000 | 0b001 => few![RD], // adr, adrp
            0b101 => few![RD],         // move wide
            0b111 => few![RD, RN, RM], // extract
            _ => few![RD, RN],         // add/sub, logical, bitfield
        }),
        // Branches, exceptions and system instructions.
        0b1010 | 0b1011 => {
            if (insn >> 25) & 0x3f == 0b011010 || (insn >> 25) & 0x3f == 0b011011 {
                Some(few![RD]) // cbz/cbnz, tbz/tbnz
            } else if (insn >> 25) & 0x7f == 0b1101011 {
                Some(few![RN, RD]) // br/blr/ret and the authenticated forms
            } else if insn >> 22 == 0b11_0101_0100 {
                Some(few![RD]) // mrs/msr/sys: Rt
            } else {
                Some(few![]) // b, bl, b.cond, svc, hints
            }
        }
        // Loads and stores.
        0b0100 | 0b0110 | 0b1100 | 0b1110 => {
            let rt = |mut f: Few<u32>| {
                if !v {
                    f.push(RD);
                }
                f
            };
            if (insn >> 24) & 0x3f == 0b001000 {
                // Exclusive, ordered, compare-and-swap: Rs, Rt(, Rt2), Rn.
                return Some(rt(few![RM, 10, RN]));
            }
            if insn & 0x3a00_0000 == 0x2800_0000 {
                let mut f = few![RN];
                if !v {
                    f.extend([RD, 10]);
                }
                return Some(f); // pair
            }
            if insn & 0x3b00_0000 == 0x1800_0000 {
                return Some(rt(few![])); // literal
            }
            if insn & 0x3b00_0000 == 0x3900_0000 {
                return Some(rt(few![RN])); // unsigned immediate
            }
            if insn & 0x3b00_0000 == 0x3800_0000 {
                if (insn >> 21) & 1 == 1 && (insn >> 10) & 1 == 0 {
                    return Some(rt(few![RN, RM])); // register offset, atomics
                }
                return Some(rt(few![RN])); // immediate forms, PAC loads
            }
            if insn & 0xbe00_0000 == 0x0c00_0000 && (insn >> 23) & 1 == 1 {
                return Some(few![RN, RM]); // SIMD structures, post-index
            }
            Some(few![RN]) // SIMD structure loads and stores
        }
        // Data processing, register.
        0b0101 | 0b1101 => Some(if (insn >> 24) & 0x1f == 0b11011 {
            few![RD, RN, RM, 10] // 3-source
        } else if (insn >> 21) & 0xff == 0b1101_0010 && (insn >> 11) & 1 == 1 {
            few![RN] // ccmp/ccmn immediate: an imm5 where Rm would be
        } else {
            few![RD, RN, RM]
        }),
        // SIMD and floating point: only the GPR conversions are known.
        _ => operands(insn).map(|f| f.into_iter().map(|f| f.shift).collect()),
    }
}

/// Whether `insn` names `x18` in a general-purpose register field. Used to
/// count the `x18` uses the rewrite leaves alone, a diagnostic only.
pub fn names_x18(insn: u32) -> bool {
    may_name_x18(insn) && fields_name_x18(insn)
}

/// Whether `insn` names `x16` or `x17` in a general-purpose register
/// field, where its group is known ([`gpr_fields`]).
pub fn names_x16_x17(insn: u32) -> bool {
    gpr_fields(insn).is_some_and(|f| f.iter().any(|&s| matches!(reg(insn, s), 16 | 17)))
}

/// [`names_x18`] by decoding alone.
fn fields_name_x18(insn: u32) -> bool {
    gpr_fields(insn).is_some_and(|f| f.iter().any(|&s| reg(insn, s) == 18))
}

/// Whether `insn` might name `x18`: in one of its general-register fields
/// where its group is known ([`gpr_fields`]), else wherever an instruction
/// names one ([`may_name_x18`]).
pub fn may_use_x18(insn: u32) -> bool {
    gpr_fields(insn).map_or_else(|| may_name_x18(insn), |f| f.iter().any(|&s| reg(insn, s) == 18))
}

/// Whether `insn` has 18 in one of the places an instruction names a
/// general register (bits 0, 5, 10 and 16): one that has not names no
/// `x18`, which is told at once, where decoding it costs far more.
#[inline]
pub fn may_name_x18(insn: u32) -> bool {
    const ALL: u32 = 0x1f | 0x1f << 5 | 0x1f << 10 | 0x1f << 16;
    const X18: u32 = 18 | 18 << 5 | 18 << 10 | 18 << 16;
    // Each field equal to 18 is all zeros once XORed with it.
    let x = (insn ^ X18) & ALL;
    [0, 5, 10, 16].iter().any(|&s| (x >> s) & 0x1f == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quick_check_passes_every_x18_word() {
        // A spread of words (every one of the 2^32 was checked once):
        // whatever decoding finds naming x18, the quick check lets through.
        let mut w: u32 = 1;
        for _ in 0..1 << 22 {
            w = w.wrapping_mul(0x9e37_79b1).wrapping_add(0x7f4a_7c15);
            for insn in
                [w, w & !(0x1f << 5) | 18 << 5, w & !0x1f | 18, w & !(0x1f << 16) | 18 << 16]
            {
                assert!(may_name_x18(insn) || !fields_name_x18(insn), "{insn:#010x}");
            }
        }
        assert!(!may_name_x18(0xaa0103e0)); // mov x0, x1
        assert!(may_name_x18(0xaa1203ea)); // mov x10, x18
    }

    fn rd(shift: u32) -> Field {
        Field { shift, read: false, write: true }
    }
    fn rr(shift: u32) -> Field {
        Field { shift, read: true, write: false }
    }

    #[test]
    fn move_wide() {
        // movz x18, #0x1818  -> writes Rd only
        assert_eq!(operands(0xd2830312), Some(few![rd(RD)]));
        // movk x18, #0x1818, lsl #48 -> reads and writes Rd
        assert_eq!(operands(0xf2e30312), Some(few![Field { shift: RD, read: true, write: true }]));
        // movn x0, #0 -> writes Rd only
        assert_eq!(operands(0x92800000), Some(few![rd(RD)]));
    }

    #[test]
    fn logical_shifted_register_mov_and_cmp() {
        // mov x10, x18  == orr x10, xzr, x18 -> Rd write, Rn read, Rm read
        assert_eq!(operands(0xaa1203ea), Some(few![rd(RD), rr(RN), rr(RM)]));
        // cmp x18, x10  == subs xzr, x18, x10 -> add/sub shifted register
        assert_eq!(operands(0xeb0a025f), Some(few![rd(RD), rr(RN), rr(RM)]));
    }

    #[test]
    fn add_sub_immediate_with_sp() {
        // add x1, x2, #4 -> Rd write, Rn read
        assert_eq!(operands(0x91001041), Some(few![rd(RD), rr(RN)]));
        // add x18, sp, #0 (mov x18, sp) -> sp source, folded into the stub
        assert_eq!(operands(0x910003f2), Some(few![rd(RD)]));
        // adds x18, sp, #8 -> flag-setting from sp: sp through a scratch
        assert_eq!(operands(0xb10023f2), Some(few![rd(RD)]));
        // add x18, sp, #1, lsl #12 -> shifted immediate: sp through a scratch
        assert_eq!(operands(0x914007f2), Some(few![rd(RD)]));
        // add sp, x18, #8 -> Rd is sp, deferred
        assert_eq!(operands(0x9100225f), None);
        // cmp x18, #42 == subs xzr, x18, #42 -> Rd is xzr; read x18
        assert_eq!(operands(0xf100aa5f), Some(few![rd(RD), rr(RN)]));
        // cmn x18, #1 == adds xzr, x18, #1 -> read x18
        assert_eq!(operands(0xb100065f), Some(few![rd(RD), rr(RN)]));
        // subs x18, x19, #1 -> write x18, read x19
        assert_eq!(operands(0xf1000672), Some(few![rd(RD), rr(RN)]));
    }

    /// An `sp` operand stays as it is: a stub leaves `sp`, so the
    /// instruction runs with its offset, its register and its writeback as
    /// the program wrote them. One writing `sp` has a stub of its own.
    /// Encodings from `llvm-mc`.
    #[test]
    fn sp_operands_run_as_they_are() {
        for insn in [
            0x910063f2, // add x18, sp, #0x18
            0xd10103f2, // sub x18, sp, #0x40
            0x913fe3f2, // add x18, sp, #4088
            0x8b3263e1, // add x1, sp, x18
            0xab3263e1, // adds x1, sp, x18
            0x8b3263f2, // add x18, sp, x18
            0x0b3243e3, // add w3, wsp, w18
            0xcb296bf2, // sub x18, sp, x9, lsl #2
            0xa91f4bf0, // stp x16, x18, [sp, #496]
            0x295c4bef, // ldp w15, w18, [sp, #224]
            0xf8636bf2, // ldr x18, [sp, x3]
            0xf9400bf2, // ldr x18, [sp, #16]
            0xf81f0ff2, // str x18, [sp, #-16]!
            0xa9bf4ff2, // stp x18, x19, [sp, #-16]!
        ] {
            assert!(operands(insn).is_some(), "{insn:#x}");
        }
        // add sp, sp, x18 writes sp.
        assert_eq!(operands(0x8b3263ff), None);
    }

    /// Only real register fields count: immediates and branch offsets whose
    /// bits happen to read 18 do not.
    #[test]
    fn names_x18_is_precise() {
        assert!(!names_x18(0x7a521840)); // ccmp w2, #18, #0, ne: an immediate
        assert!(!names_x18(0x94004869)); // bl: an offset, no registers
        assert!(!names_x18(0x54000240)); // b.eq
        assert!(!names_x18(0xf9404a60)); // ldr x0, [x19, #0x90]: imm12 bits
        assert!(names_x18(0x910063f2)); // add x18, sp, #0x18
        assert!(names_x18(0xa9124bf3)); // stp x19, x18, [sp, #0x120]
        assert!(names_x18(0xf8616a52)); // ldr x18, [x18, x1]
    }

    #[test]
    fn logical_immediate_tst_reads_x18() {
        // tst x18, #0xff == ands xzr, x18, #0xff -> Rd is xzr; read x18
        assert_eq!(operands(0xf2401e5f), Some(few![rd(RD), rr(RN)]));
        // ands x18, x0, #0xff -> write x18, read x0
        assert_eq!(operands(0xf2401c12), Some(few![rd(RD), rr(RN)]));
    }

    #[test]
    fn register_only_data_processing() {
        // ubfx x18, x0, #4, #8 (bitfield, UBFM): Rd write, Rn read
        assert_eq!(operands(0xd3442c12), Some(few![rd(RD), rr(RN)]));
        // sbfiz x18, x1, #3, #5 (SBFM): Rd write only
        assert_eq!(operands(0x937d1032), Some(few![rd(RD), rr(RN)]));
        // extr x18, x0, x1, #8: Rd write, Rn/Rm read
        assert_eq!(operands(0x93c12012), Some(few![rd(RD), rr(RN), rr(RM)]));
        // csel x18, x0, x1, eq: Rd write, Rn/Rm read
        assert_eq!(operands(0x9a810012), Some(few![rd(RD), rr(RN), rr(RM)]));
        // ccmp x18, x0, #0, eq (register form): Rn/Rm read, no Rd
        assert_eq!(operands(0xfa400240), Some(few![rr(RN), rr(RM)]));
        // ccmp x18, #3, #0, eq (immediate form): Rn read only
        assert_eq!(operands(0xfa430a40), Some(few![rr(RN)]));
        // udiv x18, x0, x1 (two-source): Rd write, Rn/Rm read
        assert_eq!(operands(0x9ac10812), Some(few![rd(RD), rr(RN), rr(RM)]));
        // rbit x18, x0 (one-source): Rd write, Rn read
        assert_eq!(operands(0xdac00012), Some(few![rd(RD), rr(RN)]));
        // madd x18, x0, x1, x2 (three-source): Rd write, Rn/Ra/Rm read
        assert_eq!(operands(0x9b010812), Some(few![rd(RD), rr(RN), rr(10), rr(RM)]));
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
        assert_eq!(operands(0xf9400012), Some(few![rd(RD), rr(RN)]));
        // str x18, [x1, #8]   -> Rt read, Rn read
        assert_eq!(operands(0xf9000432), Some(few![rr(RD), rr(RN)]));
        // ldr x18, [sp, #16]  -> allowed (sp offset adjusts)
        assert_eq!(operands(0xf9400bf2), Some(few![rd(RD), rr(RN)]));
        // ldr x18, [x18, #8]  -> base and dest both x18
        assert_eq!(operands(0xf9400652), Some(few![rd(RD), rr(RN)]));
    }

    #[test]
    fn load_store_addressing_forms() {
        // ldur x18, [x0, #-8]: unscaled, Rt write (load), base read
        assert_eq!(operands(0xf85f8012), Some(few![rd(RD), rr(RN)]));
        // ldr x18, [x0, #8]! : pre-index, base read+write
        assert_eq!(
            operands(0xf8408c12),
            Some(few![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // ldr x18, [x0], #8  : post-index, base read+write
        assert_eq!(
            operands(0xf8408412),
            Some(few![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // str x18, [sp, #16]! : pre-index onto sp, sp as it is
        assert_eq!(
            operands(0xf8010ff2),
            Some(few![rr(RD), Field { shift: RN, read: true, write: true }])
        );
        // ldr x18, [x0, x1]  : register offset, Rt write, base read, Rm read
        assert_eq!(operands(0xf8616812), Some(few![rd(RD), rr(RN), rr(RM)]));
        // ldp x18, x19, [x0, #16] : pair offset, Rt/Rt2 write, base read
        assert_eq!(operands(0xa9414c12), Some(few![rd(RD), rd(10), rr(RN)]));
        // ldp x18, x19, [sp, #16] : pair offset onto sp -> allowed (imm7 adjusts)
        assert_eq!(operands(0xa9414ff2), Some(few![rd(RD), rd(10), rr(RN)]));
        // ldp x18, x19, [x0], #16 : pair post-index, base read+write
        assert_eq!(
            operands(0xa8c14c12),
            Some(few![rd(RD), rd(10), Field { shift: RN, read: true, write: true }])
        );
    }

    #[test]
    fn sign_extending_loads_write_their_destination() {
        // ldrsw x18, [x1, #4]: opc 10 is a load, not a store
        assert_eq!(operands(0xb9800432), Some(few![rd(RD), rr(RN)]));
        // ldrsb x18, [x1]
        assert_eq!(operands(0x39800032), Some(few![rd(RD), rr(RN)]));
        // ldrsh w18, [x1, #2]: opc 11
        assert_eq!(operands(0x79c00432), Some(few![rd(RD), rr(RN)]));
        // ldursw x18, [x1, #-4]
        assert_eq!(operands(0xb89fc032), Some(few![rd(RD), rr(RN)]));
        // ldrsw x18, [x1, x2]
        assert_eq!(operands(0xb8a26832), Some(few![rd(RD), rr(RN), rr(RM)]));
        // ldrsw x18, [x1], #4
        assert_eq!(
            operands(0xb8804432),
            Some(few![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // prfm pldl1keep, [x18]: Rt is a prefetch operation; only the base is
        // a register
        assert_eq!(operands(0xf9800240), Some(few![rr(RN)]));
        // prfm pstl2keep, [x0, #8]: its operation field happens to be 18
        assert_eq!(operands(0xf9800412), Some(few![rr(RN)]));
    }

    #[test]
    fn atomic_memory_operations() {
        // ldadd x0, x18, [x1]: Rs read, Rt write, base read
        assert_eq!(operands(0xf8200032), Some(few![rr(RM), rd(RD), rr(RN)]));
        // ldadd x18, x0, [x1]
        assert_eq!(operands(0xf8320020), Some(few![rr(RM), rd(RD), rr(RN)]));
        // stadd x18, [x1] (Rt = xzr)
        assert_eq!(operands(0xf832003f), Some(few![rr(RM), rd(RD), rr(RN)]));
        // swp x18, x0, [x1]
        assert_eq!(operands(0xf8328020), Some(few![rr(RM), rd(RD), rr(RN)]));
        // ldapr x18, [x1]
        assert_eq!(operands(0xf8bfc032), Some(few![rd(RD), rr(RN)]));
        // ldaddal x18, x0, [sp]: sp base, as it is
        assert_eq!(operands(0xf8f203e0), Some(few![rr(RM), rd(RD), rr(RN)]));
    }

    #[test]
    fn exclusive_and_ordered_loads_stores() {
        let rw = |shift| Field { shift, read: true, write: true };
        // ldxr x18, [x1]; ldaxr x18, [x1]
        assert_eq!(operands(0xc85f7c32), Some(few![rd(RD), rr(RN)]));
        assert_eq!(operands(0xc85ffc32), Some(few![rd(RD), rr(RN)]));
        // stxr w18, x1, [x2]: status write, data read, base read
        assert_eq!(operands(0xc8127c41), Some(few![rd(RM), rr(RD), rr(RN)]));
        // stlxr w2, x18, [x1]
        assert_eq!(operands(0xc802fc32), Some(few![rd(RM), rr(RD), rr(RN)]));
        // ldxp x18, x19, [x1]
        assert_eq!(operands(0xc87f4c32), Some(few![rd(RD), rd(10), rr(RN)]));
        // stxp w18, x1, x2, [x3]
        assert_eq!(operands(0xc8320861), Some(few![rd(RM), rr(RD), rr(10), rr(RN)]));
        // ldar x18, [x1]; stlr x18, [x1]
        assert_eq!(operands(0xc8dffc32), Some(few![rd(RD), rr(RN)]));
        assert_eq!(operands(0xc89ffc32), Some(few![rr(RD), rr(RN)]));
        // cas x18, x0, [x1]: Rs is compared and receives the old value
        assert_eq!(operands(0xc8b27c20), Some(few![rw(RM), rr(RD), rr(RN)]));
        // casal x0, x18, [x1]
        assert_eq!(operands(0xc8e0fc32), Some(few![rw(RM), rr(RD), rr(RN)]));
        // casp x0, x1, x2, x3, [x18]: register pairs, deferred
        assert_eq!(operands(0x48207e42), None);
        // ldar x18, [sp]; stxr w18, x1, [sp]: sp base, as it is
        assert_eq!(operands(0xc8dffff2), Some(few![rd(RD), rr(RN)]));
        assert_eq!(operands(0xc8127fe1), Some(few![rd(RM), rr(RD), rr(RN)]));
    }

    #[test]
    fn extended_register_and_carry_arithmetic() {
        // add x18, x0, w1, sxtw
        assert_eq!(operands(0x8b21c012), Some(few![rd(RD), rr(RN), rr(RM)]));
        // cmp x18, w1, uxtw (Rd is xzr)
        assert_eq!(operands(0xeb21425f), Some(few![rd(RD), rr(RN), rr(RM)]));
        // add sp, x18, x1: Rd is sp, deferred
        assert_eq!(operands(0x8b21625f), None);
        // add x18, sp, x1: Rn is sp, which the stub keeps in a scratch
        assert_eq!(operands(0x8b2163f2), Some(few![rd(RD), rr(RN), rr(RM)]));
        // adc x18, x0, x1; sbcs x18, x0, x1
        assert_eq!(operands(0x9a010012), Some(few![rd(RD), rr(RN), rr(RM)]));
        assert_eq!(operands(0xfa010012), Some(few![rd(RD), rr(RN), rr(RM)]));
    }

    /// Encodings from `llvm-mc`.
    #[test]
    fn moves_between_general_registers_and_vector_elements() {
        let reads = Some(few![rr(RN)]);
        let writes = Some(few![rd(RD)]);
        assert_eq!(operands(0x4e051e40), reads); // mov v0.b[2], w18 (ins)
        assert_eq!(operands(0x4e081e45), reads); // mov v5.d[0], x18 (ins)
        assert_eq!(operands(0x4e040e41), reads); // dup v1.4s, w18
        assert_eq!(operands(0x0e0e3c52), writes); // umov w18, v2.h[3]
        assert_eq!(operands(0x4e182c72), writes); // smov x18, v3.b[1]
        assert_eq!(operands(0x4e183c92), writes); // mov x18, v4.d[1] (umov)
        assert_eq!(operands(0x6e0c0420), None); // ins v0.s[1], v1.s[0]: no GPR
        assert!(names_x18(0x4e051e40));
    }

    /// SIMD structure loads and stores through `x18`: a base, written back by
    /// the post-index forms, or a post-index register offset. Encodings from
    /// `llvm-mc`.
    #[test]
    fn simd_structure_loads_and_stores() {
        let base = |write| Field { shift: RN, read: true, write };
        assert_eq!(operands(0x0c408a42), Some(few![base(false)])); // ld2 {v2.2s, v3.2s}, [x18]
        assert_eq!(operands(0x4c407642), Some(few![base(false)])); // ld1 {v2.8h}, [x18]
        assert_eq!(operands(0x0d409240), Some(few![base(false)])); // ld1 {v0.s}[1], [x18]
        assert_eq!(operands(0x0cdf8240), Some(few![base(true)])); // ld2 {..}, [x18], #16
        assert_eq!(operands(0x4c837240), Some(few![base(true), rr(RM)])); // st1 {..}, [x18], x3
        assert_eq!(operands(0x4dc2ca40), Some(few![base(true), rr(RM)])); // ld1r {..}, [x18], x2
        assert_eq!(operands(0x4c927020), Some(few![base(true), rr(RM)])); // st1 {..}, [x1], x18
        assert!(names_x18(0x4c927020));
        assert_eq!(operands(0x4c4073e0), None); // ld1 {v0.16b}, [sp]
    }

    #[test]
    fn fp_integer_conversions() {
        // fmov x18, d0 (to GPR): Rd write
        assert_eq!(operands(0x9e660012), Some(few![rd(RD)]));
        // fcvtzs x18, d0 (to GPR): Rd write
        assert_eq!(operands(0x9e780012), Some(few![rd(RD)]));
        // fmov x18, v0.d[1] (to GPR): Rd write
        assert_eq!(operands(0x9eae0012), Some(few![rd(RD)]));
        // fmov d0, x18 (from GPR): Rn read
        assert_eq!(operands(0x9e670240), Some(few![rr(RN)]));
        // scvtf d0, x18 (from GPR): Rn read
        assert_eq!(operands(0x9e620240), Some(few![rr(RN)]));
        // ucvtf s0, w18 (from GPR): Rn read
        assert_eq!(operands(0x1e230240), Some(few![rr(RN)]));
        // fadd d0, d1, d2 (FP arithmetic, no GPR): deferred
        assert_eq!(operands(0x1e622820), None);
    }

    #[test]
    fn simd_load_store_only_exposes_the_base() {
        // ldr q0, [x18]: SIMD, base read only (q0 is a vector, not x18)
        assert_eq!(operands(0x3dc00240), Some(few![rr(RN)]));
        // ldp q0, q1, [x18]: SIMD pair, base read only
        assert_eq!(operands(0xad400640), Some(few![rr(RN)]));
        // str d0, [x18, x1]: SIMD register offset, base + Rm
        assert_eq!(operands(0xfc216a40), Some(few![rr(RN), rr(RM)]));
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

    /// System registers, `sys` and the pointer-authentication instructions
    /// naming `x18`. Encodings from `llvm-mc`.
    #[test]
    fn system_and_pointer_authentication() {
        let rw = Field { shift: RD, read: true, write: true };
        assert_eq!(operands(0xd53be052), Some(few![rd(RD)])); // mrs x18, cntvct_el0
        assert_eq!(operands(0xd53b4212), Some(few![rd(RD)])); // mrs x18, nzcv
        assert_eq!(operands(0xd51b4412), Some(few![rr(RD)])); // msr fpcr, x18
        assert_eq!(operands(0xd50b7e32), Some(few![rr(RD)])); // dc civac, x18
        assert_eq!(operands(0xd503201f), None); // nop
        assert_eq!(operands(0xdac103f2), Some(few![rw, rr(RN)])); // pacia x18, sp
        assert_eq!(operands(0xdac10032), Some(few![rw, rr(RN)])); // pacia x18, x1
        assert_eq!(operands(0xdac10832), Some(few![rw, rr(RN)])); // pacda x18, x1
        assert_eq!(
            operands(0xdac11241), // autia x1, x18
            Some(few![rw, rr(RN)])
        );
        assert_eq!(operands(0xdac123f2), Some(few![rw])); // paciza x18
        assert_eq!(operands(0xdac143f2), Some(few![rw])); // xpaci x18
        assert_eq!(operands(0x9adf3032), Some(few![rd(RD), rr(RN), rr(RM)])); // pacga x18, x1, sp
        assert_eq!(operands(0x9ac23241), Some(few![rd(RD), rr(RN), rr(RM)])); // pacga x1, x18, x2
        // The memory-tagging forms with an sp operand: left alone.
        assert_eq!(operands(0x9adf13f2), None); // irg x18, sp
        assert_eq!(operands(0x9ac103f2), None); // subp x18, sp, x1
        assert!(names_x18(0x9adf13f2));
        // ldraa x18, [x1, #8]; ldraa x1, [x18, #-16]! (base written back)
        assert_eq!(operands(0xf8201432), Some(few![rd(RD), rr(RN)]));
        assert_eq!(
            operands(0xf87fee41),
            Some(few![rd(RD), Field { shift: RN, read: true, write: true }])
        );
        // ldrab x18, [sp, #16]; ldraa x18, [sp, #-8]! (written back)
        assert_eq!(operands(0xf8a027f2), Some(few![rd(RD), rr(RN)]));
        assert_eq!(
            operands(0xf87ffff2),
            Some(few![rd(RD), Field { shift: RN, read: true, write: true }])
        );
    }

    /// Authenticated branches through `x18`. Encodings from `llvm-mc`.
    #[test]
    fn authenticated_indirect_branches() {
        assert_eq!(x18_indirect(0xd71f0a41), Some(false)); // braa x18, x1
        assert_eq!(x18_indirect(0xd61f0a5f), Some(false)); // braaz x18
        assert_eq!(x18_indirect(0xd73f0a5f), Some(true)); // blraa x18, sp
        assert_eq!(x18_indirect(0xd63f0e5f), Some(true)); // blrabz x18
        assert_eq!(x18_indirect(0xd73f0a5e), None); // blraa x18, x30
        assert_eq!(x18_indirect(0xd65f0bff), None); // retaa
    }

    /// The forms decoded apart: `casp` and a result in `sp`; writeback onto
    /// `sp` is any store's or load's. Encodings from `llvm-mc`.
    #[test]
    fn casp_and_sp_writing_forms() {
        for insn in [0x48327c02, 0x4862fc32, 0x08327c02, 0x48227e44] {
            assert!(x18_casp(insn), "{insn:#x}");
            assert_eq!(operands(insn), None, "{insn:#x}");
        }
        assert!(!x18_casp(0x48207c82)); // casp x0, x1, x2, x3, [x4]
        assert!(!x18_casp(0x48327fe2)); // casp x18, x19, x2, x3, [sp]
        for insn in [0xf81f0ff2, 0xf84107f2, 0xa9be4bfd, 0xa8c14ff2, 0xb8408ff2, 0xf8100ff2] {
            let ops = operands(insn).unwrap_or_else(|| panic!("{insn:#x}"));
            assert!(ops.iter().any(|f| (insn >> f.shift) & 0x1f == 18), "{insn:#x}");
        }
        for insn in [0x9100025f, 0x9100425f, 0xcb3263ff, 0x8b326bff, 0x927cee5f, 0x4cd273e0] {
            assert!(x18_writes_sp(insn), "{insn:#x}");
        }
        assert!(!x18_writes_sp(0x910043ff)); // add sp, sp, #16
        assert!(!x18_writes_sp(0x91000640)); // add x0, x18, #1
        assert!(!x18_writes_sp(0xf2401e5f)); // tst x18, #0xff
    }

    #[test]
    fn names_x18_detects_fields() {
        assert!(names_x18(0xd2830312)); // movz x18
        assert!(names_x18(0xf9400012)); // ldr x18, [x0]
        assert!(!names_x18(0xd2800000)); // movz x0
    }
}
