//! A socket filter's map accesses checked as it is loaded, as Linux's
//! verifier checks them: each path through the program is followed with
//! what is known of each register (a constant, a map, a value of a map
//! at an offset), and an access through a map value at a known offset
//! outside the value is refused (`EACCES`, with a line for the verifier
//! log). What an offset only the run knows reaches is checked by the
//! interpreter as the program runs ([`crate::bpf`]).

use crate::bpf::Insn;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Val {
    Unknown,
    Const(u64),
    /// A map's descriptor (`BPF_LD_MAP_FD`), with its value size.
    Map(u32),
    /// A lookup's result, a value of `size` bytes or null.
    ValueOrNull(u32),
    /// A value of `size` bytes, at offset `off` into it if known.
    Value(u32, Option<i64>),
}

type State = [Val; 11];

/// The most instructions followed over every path before the rest is left
/// to the run's checks.
const BUDGET: usize = 100_000;

/// Check `insns` (`value_size` gives each map descriptor's value size):
/// the verifier's message for an access it refuses.
pub fn check(insns: &[Insn], value_size: impl Fn(i32) -> Option<u32>) -> Result<(), String> {
    let mut work: Vec<(usize, State)> = vec![(0, [Val::Unknown; 11])];
    let mut seen = std::collections::HashSet::new();
    let mut spent = 0;
    while let Some((mut pc, mut r)) = work.pop() {
        loop {
            spent += 1;
            if spent > BUDGET || pc >= insns.len() || !seen.insert((pc, r)) {
                break;
            }
            let ins = insns[pc];
            let class = ins.code & 7;
            let (d, s) = (ins.dst as usize, ins.src as usize);
            match class {
                // The 64-bit immediate load: a map, or a constant.
                0 => {
                    let hi = insns.get(pc + 1).map_or(0, |n| n.imm as u32 as u64);
                    r[d] = if ins.src == 1 {
                        value_size(ins.imm).map_or(Val::Unknown, Val::Map)
                    } else {
                        Val::Const(hi << 32 | ins.imm as u32 as u64)
                    };
                    pc += 2;
                    continue;
                }
                // Loads and stores: through a map value, within it.
                1..=3 => {
                    let size = [4, 2, 1, 8][usize::from((ins.code >> 3) & 3)];
                    let base = if class == 1 { s } else { d };
                    if let Val::Value(vs, Some(off)) = r[base] {
                        let at = off + i64::from(ins.off);
                        if at < 0 || at + size > i64::from(vs) {
                            return Err(format!(
                                "{pc}: invalid access to map value, value_size={vs} off={at} size={size}\n\
                                 R{base} min value is outside of the allowed memory range\n"
                            ));
                        }
                    }
                    if class == 1 {
                        r[d] = Val::Unknown;
                    }
                }
                4 | 7 => r[d] = alu(&ins, r[d], if ins.code & 8 != 0 { r[s] } else { imm(&ins) }),
                5 | 6 => {
                    let op = ins.code & 0xf0;
                    match op {
                        0x90 => break,
                        0x80 => {
                            // A map lookup's result; the helpers clobber r1-r5.
                            r[0] = match (ins.imm, r[1]) {
                                (1, Val::Map(vs)) => Val::ValueOrNull(vs),
                                _ => Val::Unknown,
                            };
                            for x in &mut r[1..=5] {
                                *x = Val::Unknown;
                            }
                        }
                        0x00 if class == 5 => {
                            pc = (pc as i64 + 1 + i64::from(ins.off)) as usize;
                            continue;
                        }
                        _ => {
                            let target = (pc as i64 + 1 + i64::from(ins.off)) as usize;
                            let (mut taken, mut fall) = (r, r);
                            // A null check of a lookup's result.
                            if let Val::ValueOrNull(vs) = r[d]
                                && ins.code & 8 == 0
                                && ins.imm == 0
                                && (op == 0x10 || op == 0x50)
                            {
                                let (null, value) = (Val::Const(0), Val::Value(vs, Some(0)));
                                (taken[d], fall[d]) =
                                    if op == 0x10 { (null, value) } else { (value, null) };
                            }
                            work.push((target, taken));
                            r = fall;
                        }
                    }
                }
                _ => {}
            }
            pc += 1;
        }
    }
    Ok(())
}

fn imm(ins: &Insn) -> Val {
    Val::Const(ins.imm as i64 as u64)
}

/// `dst op src`, 32-bit for the `ALU` class.
fn alu(ins: &Insn, dst: Val, src: Val) -> Val {
    let wide = ins.code & 7 == 7;
    let op = ins.code & 0xf0;
    let narrow = |v: u64| if wide { v } else { v as u32 as u64 };
    if op == 0xb0 {
        // A move.
        return match src {
            Val::Const(v) => Val::Const(narrow(v)),
            other if wide => other,
            _ => Val::Unknown,
        };
    }
    match (dst, src) {
        (Val::Const(a), Val::Const(b)) => {
            let (a, b) = (narrow(a), narrow(b));
            let shift = (b & if wide { 63 } else { 31 }) as u32;
            let v = match op {
                0x00 => a.wrapping_add(b),
                0x10 => a.wrapping_sub(b),
                0x20 => a.wrapping_mul(b),
                0x30 => a.checked_div(b).unwrap_or(0),
                0x40 => a | b,
                0x50 => a & b,
                0x60 => a << shift,
                0x70 => a >> shift,
                0x80 => a.wrapping_neg(),
                0x90 => a.checked_rem(b).unwrap_or(a),
                0xa0 => a ^ b,
                0xc0 if wide => ((a as i64) >> shift) as u64,
                0xc0 => ((a as u32 as i32) >> shift) as u32 as u64,
                _ => return Val::Unknown,
            };
            Val::Const(narrow(v))
        }
        // Pointer arithmetic on a map value, 64-bit only.
        (Val::Value(vs, off), Val::Const(b)) if wide && (op == 0x00 || op == 0x10) => {
            let b = b as i64;
            Val::Value(
                vs,
                off.and_then(|o| if op == 0x00 { o.checked_add(b) } else { o.checked_sub(b) }),
            )
        }
        (Val::Value(vs, _), Val::Unknown) if wide && (op == 0x00 || op == 0x10) => {
            Val::Value(vs, None)
        }
        _ => Val::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn { code, dst, src, off, imm }
    }

    /// A lookup, then a store at offset `at` from the value (of 8 bytes).
    fn store_at(at: i32) -> Vec<Insn> {
        vec![
            ins(0x18, 1, 1, 0, 3), // r1 = map
            ins(0, 0, 0, 0, 0),
            ins(0xbf, 2, 10, 0, 0), // r2 = r10
            ins(0x07, 2, 0, 0, -4), // r2 += -4
            ins(0x85, 0, 0, 0, 1),  // call lookup
            ins(0x55, 0, 0, 1, 0),  // if r0 != 0 skip
            ins(0x95, 0, 0, 0, 0),  // exit
            ins(0x07, 0, 0, 0, at), // r0 += at
            ins(0x7a, 0, 0, 0, 7),  // *(u64 *)r0 = 7
            ins(0xb7, 0, 0, 0, 0),  // r0 = 0
            ins(0x95, 0, 0, 0, 0),  // exit
        ]
    }

    #[test]
    fn an_access_outside_a_map_value_is_refused() {
        let size = |_| Some(8);
        assert!(check(&store_at(0), size).is_ok());
        assert!(check(&store_at(8), size).is_err());
        assert!(check(&store_at(-64), size).is_err());
    }
}
