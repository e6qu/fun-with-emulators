//! eBPF programs for the cgroup v2 device controller.
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

use fwe_abi::errno;

/// `bpf` commands.
pub const BPF_PROG_LOAD: u64 = 5;
pub const BPF_PROG_ATTACH: u64 = 8;
pub const BPF_PROG_DETACH: u64 = 9;
pub const BPF_PROG_GET_FD_BY_ID: u64 = 13;
pub const BPF_PROG_QUERY: u64 = 16;

/// The one program type fwe runs.
pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
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

/// Check and keep the program `bytes` (instructions as Linux lays them
/// out), or `EINVAL` as Linux's verifier would refuse it.
pub fn load(bytes: &[u8]) -> Result<Program, i32> {
    if bytes.is_empty() || bytes.len() % 8 != 0 || bytes.len() / 8 > MAX_INSNS {
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
                if ins.code != LD_IMM64
                    || ins.src != 0
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
                    0x80 => return Err(errno::EINVAL), // a helper call
                    0x90 => {}                         // exit
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
            CLASS_LD => {
                let hi = prog.insns.get(pc)?.imm as u32 as u64;
                r[ins.dst as usize] = Val::Scalar((hi << 32) | ins.imm as u32 as u64);
                pc += 1;
            }
            CLASS_LDX => {
                let size = size_of(ins.code);
                let v = mem(&ctx, &stack, r[ins.src as usize], ins.off, size, false)?;
                r[ins.dst as usize] = Val::Scalar(v);
            }
            CLASS_ST | CLASS_STX => {
                let size = size_of(ins.code);
                let value = if class == CLASS_ST {
                    ins.imm as i64 as u64
                } else {
                    r[ins.src as usize].scalar()?
                };
                let Val::Stack(base) = r[ins.dst as usize] else { return None };
                let at = (STACK as i64).checked_add(base)?.checked_add(ins.off as i64)?;
                if at < 0 || at as usize + size > STACK {
                    return None;
                }
                let at = at as usize;
                stack[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
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
    ctx: &[u8; CTX],
    stack: &[u8; STACK],
    p: Val,
    off: i16,
    size: usize,
    _write: bool,
) -> Option<u64> {
    let (buf, at): (&[u8], i64) = match p {
        Val::Ctx(base) => (ctx, base.checked_add(off as i64)?),
        Val::Stack(base) => (stack, (STACK as i64).checked_add(base)?.checked_add(off as i64)?),
        Val::Scalar(_) => return None,
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
        (0x00 | 0x10, Val::Ctx(o) | Val::Stack(o), Val::Scalar(v)) if wide => {
            let d = if op == 0x00 { o.wrapping_add(v as i64) } else { o.wrapping_sub(v as i64) };
            return Some(if matches!(dst, Val::Ctx(_)) { Val::Ctx(d) } else { Val::Stack(d) });
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
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
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
    if n != 8 {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes(idb[i..i + 4].try_into().unwrap());
    Some((w(0), w(4)))
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
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() } as u32;
    ((now ^ pid.rotate_left(16) ^ N.fetch_add(1, Ordering::Relaxed).wrapping_mul(2654435761))
        & 0x7fff_ffff)
        .max(1)
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

/// `bpf(cmd, attr, size)` for the device controller's programs: load,
/// attach, detach, query, and a descriptor by identity. A program of
/// another type loads (as programs probe for features by loading one) but
/// cannot be attached; other commands fail as on a kernel without them.
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
            // A device program is checked as fwe will run it; one of
            // another type is kept but never attached (see below).
            if ty == BPF_PROG_TYPE_CGROUP_DEVICE {
                load(&bytes)?;
            }
            #[cfg(target_os = "macos")]
            return prog_fd(&bytes, fresh_id(), ty).map(|fd| fd as i64);
            #[cfg(not(target_os = "macos"))]
            return Err(errno::ENOSYS);
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
    sha1(insns)[..8].iter().map(|b| format!("{b:02x}")).collect()
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
