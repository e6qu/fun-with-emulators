//! seccomp: system call filters (`seccomp(2)`, `PR_SET_SECCOMP`).
//!
//! A filter is a classic BPF program run on Linux's `struct seccomp_data`
//! (the call's number, the architecture `AUDIT_ARCH_AARCH64`, the
//! instruction pointer and the six arguments); it answers with an action.
//! Every filter installed runs on every call, and the action with the
//! highest precedence is taken: kill the process, kill the thread, raise
//! `SIGSYS`, fail with an errno, or allow (`SECCOMP_RET_TRACE` and
//! `SECCOMP_RET_USER_NOTIF` with nobody to hand the call to fail with
//! `ENOSYS`, as on Linux). The backends ask [`check`] before they route a
//! call anywhere, so no call escapes it.
//!
//! Filters are the process's: one installed by a thread applies to all of
//! them, as with `SECCOMP_FILTER_FLAG_TSYNC`. They are kept across `fork`
//! and `execve`, as on Linux, and cannot be removed.

use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

/// `AUDIT_ARCH_AARCH64`.
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// Actions (the high 16 bits of a filter's answer).
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0x0000_0000;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_TRACE: u32 = 0x7ff0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
const ACTION_FULL: u32 = 0xffff_0000;
const DATA: u32 = 0x0000_ffff;

/// `seccomp(2)` operations.
pub const SET_MODE_STRICT: u64 = 0;
pub const SET_MODE_FILTER: u64 = 1;
pub const GET_ACTION_AVAIL: u64 = 2;
pub const GET_NOTIF_SIZES: u64 = 3;
/// `SECCOMP_FILTER_FLAG_*`.
const FLAG_TSYNC: u64 = 1;
const FLAG_LOG: u64 = 2;
const FLAG_SPEC_ALLOW: u64 = 4;
const FLAG_NEW_LISTENER: u64 = 8;
const FLAG_TSYNC_ESRCH: u64 = 16;

/// The longest filter (`BPF_MAXINSNS`).
const MAX_INSNS: usize = 4096;

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// A filter checked to be well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter(Vec<Insn>);

/// What a call is to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    /// Fail with this errno, the call not made.
    Errno(i32),
    /// Raise `SIGSYS` with this data, the call not made.
    Trap(u16),
    KillThread,
    KillProcess,
}

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;
const BPF_W: u16 = 0x00;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;
/// `struct seccomp_data`'s size.
const DATA_LEN: u32 = 64;

/// Check `insns` as Linux checks a seccomp filter: every instruction known,
/// loads aligned words inside `seccomp_data`, jumps forward and inside the
/// program, scratch slots in range, and the last a return.
pub fn load(insns: &[Insn]) -> Result<Filter, i32> {
    let n = insns.len();
    if n == 0 || n > MAX_INSNS {
        return Err(errno::EINVAL);
    }
    for (i, ins) in insns.iter().enumerate() {
        let class = ins.code & 7;
        let ok = match class {
            BPF_LD => match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => ins.k % 4 == 0 && ins.k < DATA_LEN,
                c if c == BPF_LD | BPF_W | BPF_LEN || c == BPF_LD | BPF_IMM => true,
                c if c == BPF_LD | BPF_MEM => ins.k < 16,
                _ => false,
            },
            BPF_LDX => match ins.code {
                c if c == BPF_LDX | BPF_W | BPF_IMM || c == BPF_LDX | BPF_W | BPF_LEN => true,
                c if c == BPF_LDX | BPF_MEM => ins.k < 16,
                _ => false,
            },
            BPF_ST | BPF_STX => ins.code & !7 == 0 && ins.k < 16,
            BPF_ALU => {
                let op = ins.code & 0xf0;
                // add sub mul div or and lsh rsh neg mod xor
                op <= 0xa0 && !(op == 0x30 || op == 0x90)
                    || (op == 0x30 || op == 0x90) && (ins.code & BPF_X != 0 || ins.k != 0)
            }
            BPF_JMP => {
                let op = ins.code & 0xf0;
                if op == 0x00 {
                    (i as u64 + 1 + ins.k as u64) < n as u64
                } else {
                    op <= 0x40 && i + 1 + (ins.jt as usize) < n && i + 1 + (ins.jf as usize) < n
                }
            }
            BPF_RET => ins.code & 0x18 != BPF_X,
            BPF_MISC => ins.code == BPF_MISC || ins.code == (BPF_MISC | 0x80),
            _ => false,
        };
        if !ok {
            return Err(errno::EINVAL);
        }
    }
    if insns[n - 1].code & 7 != BPF_RET {
        return Err(errno::EINVAL);
    }
    Ok(Filter(insns.to_vec()))
}

/// `struct seccomp_data` for call `nr` with `args` at `pc`.
fn data(nr: u64, args: &[u64; 6], pc: u64) -> [u8; DATA_LEN as usize] {
    let mut d = [0u8; DATA_LEN as usize];
    d[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
    d[4..8].copy_from_slice(&AUDIT_ARCH_AARCH64.to_le_bytes());
    d[8..16].copy_from_slice(&pc.to_le_bytes());
    for (i, a) in args.iter().enumerate() {
        d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
    }
    d
}

/// Run `f` on `seccomp_data` `d`: its answer.
fn run(f: &Filter, d: &[u8; DATA_LEN as usize]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; 16];
    let mut pc = 0usize;
    // Jumps only go forward, so every program ends.
    while let Some(ins) = f.0.get(pc) {
        pc += 1;
        let src = if ins.code & BPF_X != 0 { x } else { ins.k };
        match ins.code & 7 {
            BPF_LD => {
                a = match ins.code & 0xe0 {
                    BPF_ABS => u32::from_le_bytes(
                        d[ins.k as usize..ins.k as usize + 4].try_into().unwrap(),
                    ),
                    BPF_LEN => DATA_LEN,
                    BPF_MEM => mem[ins.k as usize],
                    _ => ins.k,
                }
            }
            BPF_LDX => {
                x = match ins.code & 0xe0 {
                    BPF_LEN => DATA_LEN,
                    BPF_MEM => mem[ins.k as usize],
                    _ => ins.k,
                }
            }
            BPF_ST => mem[ins.k as usize] = a,
            BPF_STX => mem[ins.k as usize] = x,
            BPF_ALU => {
                // Dividing by a zero X ends the program with 0, as Linux's
                // classic BPF does.
                if matches!(ins.code & 0xf0, 0x30 | 0x90) && ins.code & BPF_X != 0 && x == 0 {
                    return 0;
                }
                a = match ins.code & 0xf0 {
                    0x00 => a.wrapping_add(src),
                    0x10 => a.wrapping_sub(src),
                    0x20 => a.wrapping_mul(src),
                    0x30 => a.checked_div(src).unwrap_or(0),
                    0x40 => a | src,
                    0x50 => a & src,
                    0x60 => a.checked_shl(src).unwrap_or(0),
                    0x70 => a.checked_shr(src).unwrap_or(0),
                    0x80 => a.wrapping_neg(),
                    0x90 => a.checked_rem(src).unwrap_or(0),
                    _ => a ^ src,
                }
            }
            BPF_JMP => {
                let op = ins.code & 0xf0;
                if op == 0x00 {
                    pc += ins.k as usize;
                } else {
                    let taken = match op {
                        0x10 => a == src,
                        0x20 => a > src,
                        0x30 => a >= src,
                        _ => a & src != 0,
                    };
                    pc += if taken { ins.jt } else { ins.jf } as usize;
                }
            }
            BPF_RET => return if ins.code & 0x18 == BPF_A { a } else { ins.k },
            _ => {
                if ins.code == BPF_MISC {
                    x = a; // tax
                } else {
                    a = x; // txa
                }
            }
        }
    }
    RET_KILL_PROCESS
}

/// The process's seccomp state.
#[derive(Clone, Debug, Default)]
struct State {
    strict: bool,
    filters: Vec<Arc<Filter>>,
}

static STATE: RwLock<State> = RwLock::new(State { strict: false, filters: Vec::new() });
/// 0 with no seccomp, 1 strict, 2 filtering: what `/proc/self/status`
/// shows, and what [`check`] looks at first.
static MODE: AtomicU8 = AtomicU8::new(0);

/// `Seccomp:` in `/proc/self/status`.
pub fn mode() -> u8 {
    MODE.load(Ordering::Relaxed)
}

/// The action for call `nr` with `args` at `pc`.
pub fn check(nr: u64, args: &[u64; 6], pc: u64) -> Action {
    match MODE.load(Ordering::Relaxed) {
        0 => Action::Allow,
        1 => {
            use fwe_abi::nr as n;
            if matches!(nr, n::READ | n::WRITE | n::EXIT | n::RT_SIGRETURN) {
                Action::Allow
            } else {
                Action::KillThread
            }
        }
        _ => {
            let d = data(nr, args, pc);
            let st = STATE.read().unwrap_or_else(|e| e.into_inner());
            // The answer with the highest precedence: the lowest action, as
            // a signed number (kill-process is negative).
            // On a tie the newest filter's answer (its data) is taken.
            let ret = st
                .filters
                .iter()
                .rev()
                .map(|f| run(f, &d))
                .min_by_key(|r| (r & ACTION_FULL) as i32);
            match ret {
                None => Action::Allow,
                Some(r) => match r & ACTION_FULL {
                    RET_ALLOW | RET_LOG => Action::Allow,
                    RET_ERRNO => Action::Errno(((r & DATA) as i32).min(4095)),
                    RET_TRAP => Action::Trap((r & DATA) as u16),
                    // Nobody traces or listens: the call fails as Linux
                    // fails it then.
                    RET_TRACE | RET_USER_NOTIF => Action::Errno(errno::ENOSYS),
                    RET_KILL_THREAD => Action::KillThread,
                    _ => Action::KillProcess,
                },
            }
        }
    }
}

/// Install a filter read from the guest's `struct sock_fprog` at `prog`,
/// for a process with `CAP_SYS_ADMIN` or `no_new_privs` (`allowed`).
pub fn install_filter(prog: u64, flags: u64, allowed: bool) -> Result<i64, i32> {
    if flags & !(FLAG_TSYNC | FLAG_LOG | FLAG_SPEC_ALLOW | FLAG_NEW_LISTENER | FLAG_TSYNC_ESRCH)
        != 0
    {
        return Err(errno::EINVAL);
    }
    if flags & FLAG_NEW_LISTENER != 0 {
        // A listener descriptor for user notification is not offered.
        return Err(errno::EINVAL);
    }
    if !allowed {
        return Err(errno::EACCES);
    }
    let hdr: [u64; 2] = crate::uaccess::read(prog)?;
    let len = (hdr[0] & 0xffff) as usize;
    if len == 0 || len > MAX_INSNS {
        return Err(errno::EINVAL);
    }
    let raw = crate::uaccess::read_bytes(hdr[1], len * 8)?;
    let insns: Vec<Insn> = raw
        .chunks(8)
        .map(|c| Insn {
            code: u16::from_le_bytes([c[0], c[1]]),
            jt: c[2],
            jf: c[3],
            k: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect();
    let f = load(&insns)?;
    let mut st = STATE.write().unwrap_or_else(|e| e.into_inner());
    if st.strict {
        return Err(errno::EINVAL);
    }
    st.filters.push(Arc::new(f));
    MODE.store(2, Ordering::SeqCst);
    Ok(0)
}

/// Enter strict mode.
pub fn set_strict() -> Result<i64, i32> {
    let mut st = STATE.write().unwrap_or_else(|e| e.into_inner());
    if !st.filters.is_empty() {
        return Err(errno::EINVAL);
    }
    st.strict = true;
    MODE.store(1, Ordering::SeqCst);
    Ok(0)
}

/// `SECCOMP_GET_ACTION_AVAIL`: whether the action at `action` is offered.
pub fn action_available(action: u32) -> Result<i64, i32> {
    match action {
        RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP | RET_ERRNO | RET_TRACE | RET_LOG
        | RET_ALLOW => Ok(0),
        _ => Err(errno::EOPNOTSUPP),
    }
}

/// Write the state into a fork snapshot or exec state.
pub fn save(e: &mut Enc) {
    let st = STATE.read().unwrap_or_else(|e| e.into_inner());
    e.bool(st.strict);
    e.u64(st.filters.len() as u64);
    for f in &st.filters {
        e.u64(f.0.len() as u64);
        for i in &f.0 {
            e.u32(u32::from(i.code) | u32::from(i.jt) << 16 | u32::from(i.jf) << 24);
            e.u32(i.k);
        }
    }
}

/// What [`save`] wrote, in the new process.
pub fn load_state(d: &mut Dec) {
    let strict = d.bool();
    let n = d.count(8);
    let filters = (0..n)
        .filter_map(|_| {
            let m = d.count(8);
            let insns: Vec<Insn> = (0..m)
                .map(|_| {
                    let w = d.u32();
                    Insn { code: w as u16, jt: (w >> 16) as u8, jf: (w >> 24) as u8, k: d.u32() }
                })
                .collect();
            load(&insns).ok().map(Arc::new)
        })
        .collect::<Vec<_>>();
    let mode = if strict {
        1
    } else if filters.is_empty() {
        0
    } else {
        2
    };
    *STATE.write().unwrap_or_else(|e| e.into_inner()) = State { strict, filters };
    MODE.store(mode, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }

    /// The shape of a runtime's profile: check the architecture, then fail
    /// one call with EPERM and allow the rest.
    #[test]
    fn a_profile_answers_by_call() {
        let f = load(&[
            ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
            ins(BPF_JMP | 0x10, 1, 0, AUDIT_ARCH_AARCH64),
            ins(BPF_RET, 0, 0, RET_KILL_PROCESS),
            ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
            ins(BPF_JMP | 0x10, 0, 1, 40), // mount
            ins(BPF_RET, 0, 0, RET_ERRNO | 1),
            ins(BPF_RET, 0, 0, RET_ALLOW),
        ])
        .unwrap();
        assert_eq!(run(&f, &data(40, &[0; 6], 0)), RET_ERRNO | 1);
        assert_eq!(run(&f, &data(63, &[0; 6], 0)), RET_ALLOW);
        // Out-of-range and misaligned loads, backward jumps and a program
        // that does not end in a return are refused.
        assert!(load(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 64), ins(BPF_RET, 0, 0, 0)]).is_err());
        assert!(load(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 2), ins(BPF_RET, 0, 0, 0)]).is_err());
        assert!(load(&[ins(BPF_JMP | 0x10, 5, 0, 0), ins(BPF_RET, 0, 0, 0)]).is_err());
        assert!(load(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0)]).is_err());
    }
}
