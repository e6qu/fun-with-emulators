//! eBPF programs: the cgroup v2 device controller's, and socket filters.
//!
//! cgroup v2 has no device files: a runtime restricts a container's
//! devices by attaching a `BPF_PROG_TYPE_CGROUP_DEVICE` program to its
//! cgroup, which the kernel runs on each device access with the access
//! type and the device's numbers, allowing it when the program returns 1.
//! fwe loads such programs ([`load`]), keeps the ones attached to a cgroup
//! in the cgroup's directory (so they hold for every process in it, after
//! the runtime that attached them has gone), and runs them ([`run`]) on an
//! interpreter that checks every access against the context and the stack
//! at run time and stops a program that runs too long, so that a guest's
//! program can do nothing but answer.
//!
//! A socket filter (`BPF_PROG_TYPE_SOCKET_FILTER`) may also load maps
//! ([`crate::bpfmap`]) and call their helpers (lookup, update, delete),
//! reading and writing a value through the pointer a lookup returns.
//! Attached to a socket (`SO_ATTACH_BPF`), it runs as data is sent to it
//! by this process, found by the socket's connected peer: what it returns
//! is how much of the data arrives (none: dropped).

use fwe_abi::errno;

/// `bpf` commands.
pub const BPF_PROG_LOAD: u64 = 5;
pub const BPF_PROG_ATTACH: u64 = 8;
pub const BPF_PROG_DETACH: u64 = 9;
pub const BPF_PROG_GET_FD_BY_ID: u64 = 13;
pub const BPF_PROG_QUERY: u64 = 16;

/// The one program type fwe runs.
pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// The highest program type Linux 6.x has (`BPF_PROG_TYPE_NETFILTER`).
const MAX_PROG_TYPE: u32 = 32;
/// Its attach type.
pub const BPF_CGROUP_DEVICE: u32 = 6;

/// Device types and access kinds in the context's `access_type`: the type
/// in the low 16 bits, the access in the high.
pub const BPF_DEVCG_DEV_BLOCK: u32 = 1;
pub const BPF_DEVCG_DEV_CHAR: u32 = 2;
pub const BPF_DEVCG_ACC_MKNOD: u32 = 1;
pub const BPF_DEVCG_ACC_READ: u32 = 2;
pub const BPF_DEVCG_ACC_WRITE: u32 = 4;

/// The most instructions a program may have (Linux's limit for programs an
/// unprivileged loader may load; device programs are far smaller).
pub const MAX_INSNS: usize = 4096;
/// The most instructions one run may execute.
const MAX_STEPS: usize = 1 << 20;
/// The stack, below the frame pointer.
const STACK: usize = 512;
/// The context: `struct bpf_cgroup_dev_ctx { u32 access_type; u32 major;
/// u32 minor; }`.
const CTX: usize = 12;

/// One instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    pub fn decode(b: &[u8]) -> Insn {
        Insn {
            code: b[0],
            dst: b[1] & 0xf,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

const CLASS_LD: u8 = 0;
const CLASS_LDX: u8 = 1;
const CLASS_ST: u8 = 2;
const CLASS_STX: u8 = 3;
const CLASS_ALU: u8 = 4;
const CLASS_JMP: u8 = 5;
const CLASS_JMP32: u8 = 6;
const CLASS_ALU64: u8 = 7;
const MODE_MEM: u8 = 0x60;
const LD_IMM64: u8 = 0x18;

/// A program checked to be well formed: its instructions decode, every
/// jump lands inside it, register numbers are real, and it calls no
/// helper. What it does at run time is checked as it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub insns: Vec<Insn>,
}

/// Check and keep the device program `bytes` (instructions as Linux lays
/// them out), or `EINVAL` as Linux's verifier would refuse it.
pub fn load(bytes: &[u8]) -> Result<Program, i32> {
    check(bytes, false)
}

/// [`load`] for a socket filter, which may load a map's descriptor
/// (`BPF_LD_MAP_FD`) and call the map helpers.
pub fn load_filter(bytes: &[u8]) -> Result<Program, i32> {
    check(bytes, true)
}

/// The map helpers a socket filter may call: `bpf_map_lookup_elem`,
/// `bpf_map_update_elem`, `bpf_map_delete_elem`.
const HELPER_LOOKUP: i32 = 1;
const HELPER_UPDATE: i32 = 2;
const HELPER_DELETE: i32 = 3;
/// A 64-bit immediate load of a map's descriptor.
const PSEUDO_MAP_FD: u8 = 1;

fn check(bytes: &[u8], filter: bool) -> Result<Program, i32> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) || bytes.len() / 8 > MAX_INSNS {
        return Err(errno::EINVAL);
    }
    let insns: Vec<Insn> = bytes.chunks(8).map(Insn::decode).collect();
    let n = insns.len();
    // The second halves of 64-bit immediate loads, where no jump may land.
    let mut halves = vec![false; n];
    let mut j = 0;
    while j < n {
        if insns[j].code == LD_IMM64 && j + 1 < n {
            halves[j + 1] = true;
            j += 2;
        } else {
            j += 1;
        }
    }
    let mut i = 0;
    while i < n {
        let ins = insns[i];
        if ins.dst > 10 || ins.src > 10 {
            return Err(errno::EINVAL);
        }
        let class = ins.code & 7;
        match class {
            CLASS_LD => {
                // Only the 64-bit immediate load, which takes two slots.
                let second = insns.get(i + 1);
                let pseudo = filter && ins.src == PSEUDO_MAP_FD;
                if ins.code != LD_IMM64
                    || (ins.src != 0 && !pseudo)
                    || second.is_none_or(|s| s.code != 0 || s.dst != 0 || s.src != 0 || s.off != 0)
                {
                    return Err(errno::EINVAL);
                }
                i += 2;
                continue;
            }
            CLASS_LDX | CLASS_ST | CLASS_STX => {
                if ins.code & 0xe0 != MODE_MEM {
                    return Err(errno::EINVAL);
                }
            }
            CLASS_ALU | CLASS_ALU64 => {
                let op = ins.code & 0xf0;
                if op > 0xd0 {
                    return Err(errno::EINVAL);
                }
            }
            CLASS_JMP | CLASS_JMP32 => {
                let op = ins.code & 0xf0;
                match op {
                    // A helper call: the map helpers, for a filter.
                    0x80 if filter
                        && class == CLASS_JMP
                        && matches!(ins.imm, HELPER_LOOKUP | HELPER_UPDATE | HELPER_DELETE) => {}
                    0x80 => return Err(errno::EINVAL),
                    0x90 => {} // exit
                    _ if op > 0xd0 => return Err(errno::EINVAL),
                    _ => {
                        let target = i as i64 + 1 + ins.off as i64;
                        if target < 0 || target as usize >= n || halves[target as usize] {
                            return Err(errno::EINVAL);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        i += 1;
    }
    // It must end: the last instruction is an exit or an unconditional jump.
    let last = insns[n - 1];
    if last.code != (CLASS_JMP | 0x90) && last.code != CLASS_JMP {
        return Err(errno::EINVAL);
    }
    Ok(Program { insns })
}

/// A register's value: a number, or a pointer into the context or the
/// stack (an offset from its start, or from the frame pointer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    Scalar(u64),
    Ctx(i64),
    Stack(i64),
    /// A map (its place in the program's maps).
    Map(usize),
    /// A map's value: the map, where the value is in its file, and the
    /// offset from there.
    Value(usize, u64, i64),
}

impl Val {
    fn scalar(self) -> Option<u64> {
        if let Val::Scalar(v) = self { Some(v) } else { None }
    }
}

/// Run `prog` on a device access: `access` is `BPF_DEVCG_ACC_*`, `dev_type`
/// `BPF_DEVCG_DEV_*`. Returns the program's verdict (non-zero allows), or
/// `None` when it went wrong (a bad access, too long a run), which denies.
pub fn run(prog: &Program, access: u32, dev_type: u32, major: u32, minor: u32) -> Option<u64> {
    let mut ctx = [0u8; CTX];
    ctx[0..4].copy_from_slice(&((access << 16) | dev_type).to_le_bytes());
    ctx[4..8].copy_from_slice(&major.to_le_bytes());
    ctx[8..12].copy_from_slice(&minor.to_le_bytes());
    exec(prog, &ctx, &[])
}

/// Run `prog` with context `ctx` (read only) and the maps it loads, by the
/// index of the instruction that loads each: its return value, or `None`
/// when it went wrong.
fn exec(prog: &Program, ctx: &[u8], maps: &[(usize, crate::bpfmap::Map)]) -> Option<u64> {
    let mut stack = [0u8; STACK];
    let mut r = [Val::Scalar(0); 11];
    r[1] = Val::Ctx(0);
    r[10] = Val::Stack(0);
    let mut pc = 0usize;
    for _ in 0..MAX_STEPS {
        let ins = *prog.insns.get(pc)?;
        let class = ins.code & 7;
        pc += 1;
        match class {
            CLASS_LD if ins.src == PSEUDO_MAP_FD => {
                let i = maps.iter().position(|&(at, _)| at == pc - 1)?;
                r[ins.dst as usize] = Val::Map(i);
                pc += 1;
            }
            CLASS_LD => {
                let hi = prog.insns.get(pc)?.imm as u32 as u64;
                r[ins.dst as usize] = Val::Scalar((hi << 32) | ins.imm as u32 as u64);
                pc += 1;
            }
            CLASS_LDX => {
                let size = size_of(ins.code);
                let v = mem(ctx, &stack, maps, r[ins.src as usize], ins.off, size)?;
                r[ins.dst as usize] = Val::Scalar(v);
            }
            CLASS_ST | CLASS_STX => {
                let size = size_of(ins.code);
                let value = if class == CLASS_ST {
                    ins.imm as i64 as u64
                } else {
                    r[ins.src as usize].scalar()?
                };
                let bytes = &value.to_le_bytes()[..size];
                match r[ins.dst as usize] {
                    Val::Stack(base) => {
                        let at = (STACK as i64).checked_add(base)?.checked_add(ins.off as i64)?;
                        if at < 0 || at as usize + size > STACK {
                            return None;
                        }
                        let at = at as usize;
                        stack[at..at + size].copy_from_slice(bytes);
                    }
                    Val::Value(m, file, rel) => {
                        let map = &maps.get(m)?.1;
                        let rel = rel.checked_add(ins.off as i64)?;
                        if rel < 0 || rel as u64 + size as u64 > u64::from(map.value_size) {
                            return None;
                        }
                        map_write(map, file + rel as u64, bytes)?;
                    }
                    _ => return None,
                }
            }
            CLASS_JMP if ins.code & 0xf0 == 0x80 => {
                r[0] = helper(ins.imm, &r, &stack, maps)?;
                // The argument registers are the helper's to spoil.
                for reg in &mut r[1..=5] {
                    *reg = Val::Scalar(0);
                }
            }
            CLASS_ALU | CLASS_ALU64 => {
                let wide = class == CLASS_ALU64;
                let op = ins.code & 0xf0;
                let src = if ins.code & 8 != 0 {
                    r[ins.src as usize]
                } else {
                    Val::Scalar(ins.imm as i64 as u64)
                };
                r[ins.dst as usize] =
                    alu(op, wide, r[ins.dst as usize], src, ins.imm, ins.code & 8 != 0)?;
            }
            CLASS_JMP | CLASS_JMP32 => {
                let op = ins.code & 0xf0;
                if op == 0x90 {
                    return r[0].scalar();
                }
                let taken = if op == 0x00 {
                    true
                } else if let (Val::Value(..), 0x10 | 0x50, false, 0) =
                    (r[ins.dst as usize], op, ins.code & 8 != 0, ins.imm)
                {
                    // A value a lookup found is never null.
                    op == 0x50
                } else {
                    let a = r[ins.dst as usize].scalar()?;
                    let b = if ins.code & 8 != 0 {
                        r[ins.src as usize].scalar()?
                    } else {
                        ins.imm as i64 as u64
                    };
                    let (a, b) = if class == CLASS_JMP32 {
                        (a as u32 as u64, b as u32 as u64)
                    } else {
                        (a, b)
                    };
                    let (sa, sb) = if class == CLASS_JMP32 {
                        (a as u32 as i32 as i64, b as u32 as i32 as i64)
                    } else {
                        (a as i64, b as i64)
                    };
                    match op {
                        0x10 => a == b,
                        0x20 => a > b,
                        0x30 => a >= b,
                        0x40 => a & b != 0,
                        0x50 => a != b,
                        0x60 => sa > sb,
                        0x70 => sa >= sb,
                        0xa0 => a < b,
                        0xb0 => a <= b,
                        0xc0 => sa < sb,
                        0xd0 => sa <= sb,
                        _ => return None,
                    }
                };
                if taken {
                    pc = (pc as i64 + ins.off as i64) as usize;
                }
            }
            _ => return None,
        }
    }
    None
}

fn size_of(code: u8) -> usize {
    match code & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    }
}

/// A load through pointer `p` at `off`, of `size` bytes.
fn mem(
    ctx: &[u8],
    stack: &[u8; STACK],
    maps: &[(usize, crate::bpfmap::Map)],
    p: Val,
    off: i16,
    size: usize,
) -> Option<u64> {
    let (buf, at): (&[u8], i64) = match p {
        Val::Ctx(base) => (ctx, base.checked_add(off as i64)?),
        Val::Stack(base) => (stack, (STACK as i64).checked_add(base)?.checked_add(off as i64)?),
        Val::Value(m, file, rel) => {
            let map = &maps.get(m)?.1;
            let rel = rel.checked_add(off as i64)?;
            if rel < 0 || rel as u64 + size as u64 > u64::from(map.value_size) {
                return None;
            }
            let mut b = [0u8; 8];
            // SAFETY: a valid buffer of `size` bytes (at most 8).
            let n = unsafe {
                libc::pread(map.fd, b.as_mut_ptr().cast(), size, (file + rel as u64) as libc::off_t)
            };
            return (n == size as isize).then(|| u64::from_le_bytes(b));
        }
        Val::Scalar(_) | Val::Map(_) => return None,
    };
    if at < 0 || at as usize + size > buf.len() {
        return None;
    }
    let at = at as usize;
    let mut b = [0u8; 8];
    b[..size].copy_from_slice(&buf[at..at + size]);
    Some(u64::from_le_bytes(b))
}

/// One ALU operation. A pointer may only move by a number; anything else
/// done to one ends the run.
fn alu(op: u8, wide: bool, dst: Val, src: Val, imm: i32, src_is_x: bool) -> Option<Val> {
    let fit = |v: u64| if wide { v } else { v as u32 as u64 };
    match (op, dst, src) {
        (0xb0, _, s) => {
            // mov
            return Some(match s {
                Val::Scalar(v) => Val::Scalar(fit(v)),
                p if wide => p,
                _ => return None,
            });
        }
        (0x00 | 0x10, Val::Ctx(o) | Val::Stack(o) | Val::Value(_, _, o), Val::Scalar(v))
            if wide =>
        {
            let d = if op == 0x00 { o.wrapping_add(v as i64) } else { o.wrapping_sub(v as i64) };
            return Some(match dst {
                Val::Ctx(_) => Val::Ctx(d),
                Val::Value(m, file, _) => Val::Value(m, file, d),
                _ => Val::Stack(d),
            });
        }
        _ => {}
    }
    let a = dst.scalar()?;
    let b = src.scalar()?;
    let (a, b) = if wide { (a, b) } else { (a as u32 as u64, b as u32 as u64) };
    let bits = if wide { 64 } else { 32 };
    let v = match op {
        0x00 => a.wrapping_add(b),
        0x10 => a.wrapping_sub(b),
        0x20 => a.wrapping_mul(b),
        0x30 => a.checked_div(b).unwrap_or(0),
        0x40 => a | b,
        0x50 => a & b,
        0x60 => a.wrapping_shl((b % bits) as u32),
        0x70 => {
            if wide {
                a.wrapping_shr((b % 64) as u32)
            } else {
                (a as u32).wrapping_shr((b % 32) as u32) as u64
            }
        }
        0x80 => (a as i64).wrapping_neg() as u64,
        0x90 => a.checked_rem(b).unwrap_or(a),
        0xa0 => a ^ b,
        0xc0 => {
            if wide {
                ((a as i64) >> (b % 64)) as u64
            } else {
                ((a as u32 as i32) >> (b % 32)) as u32 as u64
            }
        }
        0xd0 => {
            // Byte order: to little-endian (the source bit clear) is the
            // host's order and only truncates; to big-endian swaps the low
            // `imm` bits.
            let big = src_is_x;
            match (imm, big) {
                (16, false) => a as u16 as u64,
                (32, false) => a as u32 as u64,
                (64, false) => a,
                (16, true) => (a as u16).swap_bytes() as u64,
                (32, true) => (a as u32).swap_bytes() as u64,
                (64, true) => a.swap_bytes(),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(Val::Scalar(fit(v)))
}

/// Write `bytes` to map `m`'s file at `at`.
fn map_write(m: &crate::bpfmap::Map, at: u64, bytes: &[u8]) -> Option<()> {
    // SAFETY: a valid buffer of its length.
    let n = unsafe { libc::pwrite(m.fd, bytes.as_ptr().cast(), bytes.len(), at as libc::off_t) };
    (n == bytes.len() as isize).then_some(())
}

/// `len` bytes of the stack at pointer `p`.
fn stack_bytes(stack: &[u8; STACK], p: Val, len: usize) -> Option<Vec<u8>> {
    let Val::Stack(base) = p else { return None };
    let at = (STACK as i64).checked_add(base)?;
    if at < 0 || at as usize + len > STACK {
        return None;
    }
    Some(stack[at as usize..at as usize + len].to_vec())
}

/// Call map helper `which` with the registers `r`.
fn helper(
    which: i32,
    r: &[Val; 11],
    stack: &[u8; STACK],
    maps: &[(usize, crate::bpfmap::Map)],
) -> Option<Val> {
    let Val::Map(i) = r[1] else { return None };
    let m = &maps.get(i)?.1;
    let key = stack_bytes(stack, r[2], m.key_size as usize)?;
    let status =
        |res: Result<(), i32>| Val::Scalar(res.map_or_else(|e| -(e as i64), |()| 0) as u64);
    Some(match which {
        HELPER_LOOKUP => match m.find(&key).ok()? {
            Some(file) => Val::Value(i, file, 0),
            None => Val::Scalar(0),
        },
        HELPER_UPDATE => {
            let value = stack_bytes(stack, r[3], m.value_size as usize)?;
            status(m.update(&key, &value, r[4].scalar()?))
        }
        HELPER_DELETE => status(m.delete(&key)),
        _ => return None,
    })
}

// --- the bpf system call -------------------------------------------------------

/// The extended attribute that makes a file one of fwe's loaded programs,
/// holding the program's identity.
#[cfg(target_os = "macos")]
const PROG_ATTR: &std::ffi::CStr = c"org.fwe.bpf.prog";

#[cfg(target_os = "macos")]
fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// A descriptor for loaded program `bytes` of type `ty` with identity
/// `id`: an unlinked file of fwe's holding its instructions, its identity
/// and type in an attribute.
#[cfg(target_os = "macos")]
fn prog_fd(bytes: &[u8], id: u32, ty: u32) -> Result<i32, i32> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut path = crate::fs::shm::user_dir()?;
    let pid = crate::host::pid();
    path.extend_from_slice(format!("/bpf-{pid}-{}", N.fetch_add(1, Ordering::Relaxed)).as_bytes());
    let p = std::ffi::CString::new(path).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    let fd = unsafe {
        libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC, 0o600)
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: as above; fwe's own file.
    unsafe { libc::unlink(p.as_ptr()) };
    let mut idb = [0u8; 8];
    idb[..4].copy_from_slice(&id.to_le_bytes());
    idb[4..].copy_from_slice(&ty.to_le_bytes());
    // SAFETY: valid buffers for the calls.
    let ok = unsafe {
        libc::write(fd, bytes.as_ptr().cast(), bytes.len()) == bytes.len() as isize
            && libc::fsetxattr(fd, PROG_ATTR.as_ptr(), idb.as_ptr().cast(), 8, 0, 0) == 0
    };
    if !ok {
        let e = last();
        // SAFETY: closing the descriptor just made.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// The identity and instructions of the program `fd` is a descriptor of.
#[cfg(target_os = "macos")]
pub fn prog_of(fd: i32) -> Option<(u32, Vec<u8>)> {
    let (id, _) = prog_id_type(fd)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: a valid buffer.
        let n =
            unsafe { libc::pread(fd, chunk.as_mut_ptr().cast(), chunk.len(), bytes.len() as i64) };
        if n <= 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n as usize]);
    }
    Some((id, bytes))
}

/// The identity and program type of the program `fd` is a descriptor of.
#[cfg(target_os = "macos")]
fn prog_id_type(fd: i32) -> Option<(u32, u32)> {
    let mut idb = [0u8; 8];
    // SAFETY: a valid buffer of its length.
    let n = unsafe { libc::fgetxattr(fd, PROG_ATTR.as_ptr(), idb.as_mut_ptr().cast(), 8, 0, 0) };
    let w = |i: usize| u32::from_le_bytes(idb[i..i + 4].try_into().unwrap());
    match n {
        8 => Some((w(0), w(4))),
        // Written by an fwe that kept device programs only.
        4 => Some((w(0), BPF_PROG_TYPE_CGROUP_DEVICE)),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn prog_id_type(_fd: i32) -> Option<(u32, u32)> {
    None
}

#[cfg(not(target_os = "macos"))]
pub fn prog_of(_fd: i32) -> Option<(u32, Vec<u8>)> {
    None
}

/// A new program identity.
#[cfg(target_os = "macos")]
fn fresh_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let pid = crate::host::pid() as u32;
    ((now ^ pid.rotate_left(16) ^ N.fetch_add(1, Ordering::Relaxed).wrapping_mul(2654435761))
        & 0x7fff_ffff)
        .max(1)
}

/// A new map identity.
pub fn fresh_map_id() -> u32 {
    #[cfg(target_os = "macos")]
    return fresh_id();
    #[cfg(not(target_os = "macos"))]
    return 1;
}

/// The maps of each loaded socket filter, by the program file's host
/// identity: the instruction that loads each, and the map (through a
/// descriptor of fwe's, so the program keeps it).
type FilterMaps = Vec<(usize, crate::bpfmap::Map)>;
pub(crate) static PROG_MAPS: std::sync::Mutex<Vec<((u64, u64), FilterMaps)>> =
    std::sync::Mutex::new(Vec::new());

/// The maps program `bytes` loads by descriptor, as fwe keeps them.
fn resolve_maps(bytes: &[u8]) -> Result<FilterMaps, i32> {
    let insns: Vec<Insn> = bytes.chunks(8).map(Insn::decode).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < insns.len() {
        let ins = insns[i];
        if ins.code == LD_IMM64 {
            if ins.src == PSEUDO_MAP_FD {
                let m = crate::bpfmap::of(ins.imm).ok_or(errno::EBADF)?;
                let fd = crate::fdtable::dup_reserved(m.fd)?;
                out.push((i, crate::bpfmap::Map { fd, ..m }));
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(out)
}

/// Socket filters attached (`SO_ATTACH_BPF`), by the host's handle of the
/// socket they filter what arrives at.
pub(crate) static FILTERS: std::sync::Mutex<Vec<(u64, Program, FilterMaps)>> =
    std::sync::Mutex::new(Vec::new());
static ANY_FILTER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF)` with program `prog`, or
/// `SO_DETACH_BPF` (`prog` `None`).
pub fn attach_socket(fd: i32, prog: Option<i32>) -> Result<(), i32> {
    let me = crate::host::pid();
    let so = crate::procpid::socket_id(me, fd).ok_or(errno::ENOTSOCK)?;
    let mut f = FILTERS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(prog) = prog else {
        let before = f.len();
        f.retain(|e| e.0 != so);
        return if f.len() < before { Ok(()) } else { Err(errno::ENOENT) };
    };
    let (_, ty, bytes) = prog_info(prog).ok_or(errno::EBADF)?;
    if ty != BPF_PROG_TYPE_SOCKET_FILTER {
        return Err(errno::EINVAL);
    }
    let program = load_filter(&bytes)?;
    let id = crate::fsops::host_identity(prog).ok_or(errno::EBADF)?;
    let maps = PROG_MAPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|e| e.0 == id)
        .map(|e| e.1.clone())
        .unwrap_or_default();
    f.retain(|e| e.0 != so);
    f.push((so, program, maps));
    ANY_FILTER.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// What of `len` bytes sent on socket `fd` the filter of the socket they
/// reach lets in (`None`: no filter; `Some(0)`: none, the data dropped).
pub fn filter_send(fd: i32, len: u64) -> Option<u64> {
    if !ANY_FILTER.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let me = crate::host::pid();
    let peer = crate::procpid::socket_peer(me, fd)?;
    let f = FILTERS.lock().unwrap_or_else(|e| e.into_inner());
    let (_, prog, maps) = f.iter().find(|e| e.0 == peer)?;
    // The context: `struct __sk_buff`, its length first.
    let mut ctx = [0u8; 192];
    ctx[0..4].copy_from_slice(&(len as u32).to_le_bytes());
    let keep = exec(prog, &ctx, maps).unwrap_or(0);
    Some(keep.min(len))
}

/// The cgroup directory `fd` is open on, on the host.
fn cgroup_dir(fd: i32) -> Result<Vec<u8>, i32> {
    let host = crate::fs::host_path_of(fd).ok_or(errno::EBADF)?;
    match crate::cgroupfs::locate(&host) {
        Some((_, None)) => Ok(host),
        _ => Err(errno::EINVAL),
    }
}

fn word(a: &[u8], at: usize) -> u32 {
    a.get(at..at + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn dword(a: &[u8], at: usize) -> u64 {
    a.get(at..at + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// `bpf(cmd, attr, size)`: maps and their elements ([`crate::bpfmap`]);
/// the device controller's programs: load, attach, detach, query, and a
/// descriptor by identity; socket filters, loaded with the maps they use
/// and attached with `SO_ATTACH_BPF`. A program of another type loads (as
/// programs probe for features by loading one) but cannot be attached;
/// other commands fail as on a kernel without them.
pub fn sys_bpf(cmd: u64, attr: u64, size: u64) -> i64 {
    use fwe_abi::err;
    let size = size.min(256) as usize;
    let mut a = vec![0u8; size];
    if let Err(e) = crate::uaccess::read_into(attr, &mut a) {
        return err(e);
    }
    let r = match cmd {
        BPF_PROG_LOAD => (|| {
            let ty = word(&a, 0);
            if ty == 0 || ty > MAX_PROG_TYPE {
                return Err(errno::EINVAL);
            }
            let n = word(&a, 4) as usize;
            if n == 0 || n > MAX_INSNS {
                return Err(errno::E2BIG);
            }
            let bytes = crate::uaccess::read_bytes(dword(&a, 8), n * 8)?;
            // A device program or a socket filter is checked as fwe will
            // run it; one of another type is kept but never attached.
            let maps = match ty {
                BPF_PROG_TYPE_CGROUP_DEVICE => load(&bytes).map(|_| Vec::new())?,
                BPF_PROG_TYPE_SOCKET_FILTER => {
                    load_filter(&bytes)?;
                    let insns: Vec<Insn> = bytes.chunks(8).map(Insn::decode).collect();
                    let sizes = |fd| crate::bpfmap::of(fd).map(|m| m.value_size);
                    if let Err(msg) = crate::bpfcheck::check(&insns, sizes) {
                        // The verifier's log (`log_level`, `log_size`,
                        // `log_buf`), NUL-terminated.
                        let (level, room, buf) =
                            (word(&a, 24), word(&a, 28) as usize, dword(&a, 32));
                        if level != 0 && room > 0 && buf != 0 {
                            let mut text = msg.into_bytes();
                            text.truncate(room - 1);
                            text.push(0);
                            crate::uaccess::write_from(buf, &text)?;
                        }
                        return Err(errno::EACCES);
                    }
                    resolve_maps(&bytes)?
                }
                _ => Vec::new(),
            };
            #[cfg(target_os = "macos")]
            return prog_fd(&bytes, fresh_id(), ty).map(|fd| {
                if !maps.is_empty()
                    && let Some(id) = crate::fsops::host_identity(fd)
                {
                    PROG_MAPS.lock().unwrap_or_else(|e| e.into_inner()).push((id, maps));
                }
                fd as i64
            });
            #[cfg(not(target_os = "macos"))]
            return {
                let _ = maps;
                Err(errno::ENOSYS)
            };
        })(),
        BPF_PROG_ATTACH | BPF_PROG_DETACH => (|| {
            let (target, prog, ty) = (word(&a, 0) as i32, word(&a, 4) as i32, word(&a, 8));
            if ty != BPF_CGROUP_DEVICE {
                return Err(errno::EINVAL);
            }
            let dir = cgroup_dir(target)?;
            if cmd == BPF_PROG_DETACH {
                let (id, _) = prog_of(prog).ok_or(errno::EBADF)?;
                return crate::cgroupfs::detach(&dir, id).map(|()| 0);
            }
            let (id, bytes) = prog_of(prog).ok_or(errno::EBADF)?;
            if prog_id_type(prog).map(|(_, t)| t) != Some(BPF_PROG_TYPE_CGROUP_DEVICE) {
                // fwe runs device programs only.
                return Err(errno::EINVAL);
            }
            // Without BPF_F_ALLOW_MULTI (2) the program replaces what was
            // attached; with BPF_F_REPLACE (4) it replaces the one named.
            let flags = word(&a, 12);
            if flags & 2 == 0 {
                for old in crate::cgroupfs::attached(&dir) {
                    let _ = crate::cgroupfs::detach(&dir, old);
                }
            } else if flags & 4 != 0
                && let Some((old, _)) = prog_of(word(&a, 16) as i32)
            {
                let _ = crate::cgroupfs::detach(&dir, old);
            }
            crate::cgroupfs::attach(&dir, id, &bytes).map(|()| 0)
        })(),
        BPF_PROG_QUERY => (|| {
            let (target, ty) = (word(&a, 0) as i32, word(&a, 4));
            if ty != BPF_CGROUP_DEVICE {
                return Err(errno::EINVAL);
            }
            let dir = cgroup_dir(target)?;
            let ids = crate::cgroupfs::attached(&dir);
            let room = word(&a, 24) as usize;
            let out = dword(&a, 16);
            if out != 0 {
                for (i, id) in ids.iter().take(room).enumerate() {
                    crate::uaccess::write(out + 4 * i as u64, *id)?;
                }
            }
            // The attach flags (multi), then the count.
            crate::uaccess::write(attr + 12, 2u32)?;
            crate::uaccess::write(attr + 24, ids.len() as u32)?;
            if out != 0 && ids.len() > room {
                return Err(errno::ENOSPC);
            }
            Ok(0)
        })(),
        BPF_PROG_GET_FD_BY_ID => (|| {
            let id = word(&a, 0);
            // Only attached programs are found by identity: device ones.
            let bytes = crate::cgroupfs::find(id).ok_or(errno::ENOENT)?;
            #[cfg(target_os = "macos")]
            return prog_fd(&bytes, id, BPF_PROG_TYPE_CGROUP_DEVICE).map(|fd| fd as i64);
            #[cfg(not(target_os = "macos"))]
            return {
                let _ = bytes;
                Err(errno::ENOSYS)
            };
        })(),
        crate::bpfmap::BPF_MAP_CREATE => crate::bpfmap::create(&a),
        crate::bpfmap::BPF_MAP_LOOKUP_ELEM
        | crate::bpfmap::BPF_MAP_UPDATE_ELEM
        | crate::bpfmap::BPF_MAP_DELETE_ELEM
        | crate::bpfmap::BPF_MAP_GET_NEXT_KEY => crate::bpfmap::command(cmd, &a),
        _ => Err(errno::EINVAL),
    };
    match r {
        Ok(v) => v,
        Err(e) => err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = code;
        b[1] = dst | src << 4;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    /// A program of the shape crun generates: deny everything but reads and
    /// writes of the character device 1:3 (`/dev/null`).
    fn allow_null() -> Vec<u8> {
        [
            ins(0x61, 2, 1, 0, 0),      // r2 = ctx->access_type (u32)
            ins(0x54, 2, 0, 0, 0xffff), // w2 &= 0xffff: the type
            ins(0x61, 3, 1, 0, 0),      // r3 = ctx->access_type
            ins(0x74, 3, 0, 0, 16),     // w3 >>= 16: the access
            ins(0x61, 4, 1, 4, 0),      // r4 = ctx->major
            ins(0x61, 5, 1, 8, 0),      // r5 = ctx->minor
            ins(0x55, 2, 0, 5, 2),      // if r2 != CHAR goto deny
            ins(0x55, 4, 0, 4, 1),      // if r4 != 1 goto deny
            ins(0x55, 5, 0, 3, 3),      // if r5 != 3 goto deny
            ins(0x45, 3, 0, 2, 1),      // if r3 & MKNOD goto deny
            ins(0xb7, 0, 0, 0, 1),      // r0 = 1
            ins(0x95, 0, 0, 0, 0),      // exit
            ins(0xb7, 0, 0, 0, 0),      // deny: r0 = 0
            ins(0x95, 0, 0, 0, 0),      // exit
        ]
        .concat()
    }

    #[test]
    fn runs_a_device_program() {
        let p = load(&allow_null()).unwrap();
        let rw = BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE;
        assert_eq!(run(&p, rw, BPF_DEVCG_DEV_CHAR, 1, 3), Some(1));
        assert_eq!(run(&p, BPF_DEVCG_ACC_MKNOD, BPF_DEVCG_DEV_CHAR, 1, 3), Some(0));
        assert_eq!(run(&p, rw, BPF_DEVCG_DEV_CHAR, 1, 5), Some(0));
        assert_eq!(run(&p, rw, BPF_DEVCG_DEV_BLOCK, 1, 3), Some(0));
    }

    /// A map of `entries` values of 8 bytes, keyed by 4 (an array) or 8
    /// (a hash table), in a file of the test's own.
    fn test_map(ty: u32, entries: u32) -> crate::bpfmap::Map {
        let path = std::env::temp_dir().join(format!(
            "fwe-bpfmap-{}-{ty}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let f = std::fs::File::create_new(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let key_size = if ty == 2 { 4 } else { 8 };
        f.set_len(u64::from(entries) * (if ty == 2 { 8 } else { 1 + 8 + 8 })).unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(f);
        crate::bpfmap::Map { fd, ty, key_size, value_size: 8, max_entries: entries, id: 1 }
    }

    #[test]
    fn maps_keep_their_elements() {
        let a = test_map(2, 2);
        assert_eq!(a.lookup(&0u32.to_le_bytes()), Ok(vec![0; 8]));
        a.update(&1u32.to_le_bytes(), &7u64.to_le_bytes(), 0).unwrap();
        assert_eq!(a.lookup(&1u32.to_le_bytes()), Ok(7u64.to_le_bytes().to_vec()));
        assert_eq!(a.update(&2u32.to_le_bytes(), &[0; 8], 0), Err(errno::E2BIG));
        assert_eq!(a.delete(&0u32.to_le_bytes()), Err(errno::EINVAL));
        let h = test_map(1, 1);
        assert_eq!(h.lookup(b"12345678"), Err(errno::ENOENT));
        h.update(b"12345678", &9u64.to_le_bytes(), 1).unwrap();
        assert_eq!(h.update(b"12345678", &[0; 8], 1), Err(errno::EEXIST));
        assert_eq!(h.update(b"87654321", &[0; 8], 0), Err(errno::E2BIG));
        assert_eq!(h.next_key(None), Ok(b"12345678".to_vec()));
        h.delete(b"12345678").unwrap();
        assert_eq!(h.lookup(b"12345678"), Err(errno::ENOENT));
    }

    /// LTP's bpf_prog01: look element 0 up and set it to 1 through the
    /// pointer the helper returns.
    #[test]
    fn a_filter_writes_through_a_map_value() {
        let m = test_map(2, 1);
        let mut ld = ins(0x18, 1, PSEUDO_MAP_FD, 0, m.fd).to_vec();
        ld.extend_from_slice(&ins(0, 0, 0, 0, 0));
        let prog = [
            ld,
            ins(0xbf, 2, 10, 0, 0).to_vec(), // r2 = fp
            ins(0x07, 2, 0, 0, -8).to_vec(), // r2 -= 8
            ins(0x7a, 2, 0, 0, 0).to_vec(),  // *(u64 *)r2 = 0
            ins(0x85, 0, 0, 0, 1).to_vec(),  // r0 = lookup(r1, r2)
            ins(0x15, 0, 0, 3, 0).to_vec(),  // if r0 == 0 goto out
            ins(0xbf, 1, 0, 0, 0).to_vec(),  // r1 = r0
            ins(0x7a, 1, 0, 0, 1).to_vec(),  // *(u64 *)r1 = 1
            ins(0xb7, 0, 0, 0, 0).to_vec(),  // r0 = 0
            ins(0x95, 0, 0, 0, 0).to_vec(),  // out: exit
        ]
        .concat();
        assert_eq!(load(&prog), Err(errno::EINVAL));
        let p = load_filter(&prog).unwrap();
        assert_eq!(exec(&p, &[0u8; 192], &[(0, m)]), Some(0));
        assert_eq!(m.lookup(&0u32.to_le_bytes()), Ok(1u64.to_le_bytes().to_vec()));
    }

    /// A program cannot reach past its context or stack, use a number as
    /// a pointer, call a helper, jump outside itself or run forever.
    #[test]
    fn a_program_can_only_answer() {
        let past_ctx = [ins(0x61, 0, 1, 12, 0), ins(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(run(&load(&past_ctx).unwrap(), 2, 2, 1, 3), None);
        let below_stack = [ins(0x7a, 10, 0, -520, 1), ins(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(run(&load(&below_stack).unwrap(), 2, 2, 1, 3), None);
        let stack_ok =
            [ins(0x7a, 10, 0, -8, 7), ins(0x79, 0, 10, -8, 0), ins(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(run(&load(&stack_ok).unwrap(), 2, 2, 1, 3), Some(7));
        let number_as_pointer =
            [ins(0xb7, 1, 0, 0, 4096), ins(0x61, 0, 1, 0, 0), ins(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(run(&load(&number_as_pointer).unwrap(), 2, 2, 1, 3), None);
        assert_eq!(
            load(&[ins(0x85, 0, 0, 0, 1), ins(0x95, 0, 0, 0, 0)].concat()),
            Err(errno::EINVAL)
        );
        assert_eq!(
            load(&[ins(0x05, 0, 0, 5, 0), ins(0x95, 0, 0, 0, 0)].concat()),
            Err(errno::EINVAL)
        );
        // A jump into the second half of a 64-bit immediate load.
        let half = [
            ins(0x05, 0, 0, 1, 0),
            ins(0x18, 0, 0, 0, 0),
            ins(0xb7, 15, 0, 0, 0),
            ins(0x95, 0, 0, 0, 0),
        ]
        .concat();
        assert_eq!(load(&half), Err(errno::EINVAL));
        let forever = [ins(0x05, 0, 0, -1, 0)].concat();
        assert_eq!(run(&load(&forever).unwrap(), 2, 2, 1, 3), None);
    }
}

/// Whether `fd` is a descriptor of a program or a map (an anonymous inode
/// on Linux).
pub fn is_bpf_fd(fd: i32) -> bool {
    prog_id_type(fd).is_some() || crate::bpfmap::of(fd).is_some()
}

/// The identity, type and instructions of the program `fd` is a
/// descriptor of, if it is one.
pub fn prog_info(fd: i32) -> Option<(u32, u32, Vec<u8>)> {
    let (id, bytes) = prog_of(fd)?;
    let (_, ty) = prog_id_type(fd)?;
    Some((id, ty, bytes))
}

/// A program's tag, as Linux computes it: the first 8 bytes of the SHA-1
/// of its instructions, in hex.
pub fn tag_hex(insns: &[u8]) -> String {
    // As Linux hashes it: a 64-bit load of a map's descriptor or value
    // (BPF_LD|BPF_IMM|BPF_DW with source 1 or 2) without its immediates,
    // which name the map only in the loading process.
    let mut v = insns.to_vec();
    let mut i = 0;
    while i + 16 <= v.len() {
        if v[i] == 0x18 && matches!(v[i + 1] >> 4, 1 | 2) {
            v[i + 4..i + 8].fill(0);
            v[i + 12..i + 16].fill(0);
            i += 16;
        } else {
            i += 8;
        }
    }
    sha1(&v)[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-1 (FIPS 180-4) of `data`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod sha1_tests {
    #[test]
    fn known_digests() {
        let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(super::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(super::sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}
