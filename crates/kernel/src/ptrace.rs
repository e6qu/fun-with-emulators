//! `ptrace`: a process traced by its parent (`PTRACE_TRACEME`) or by a
//! process that attached to it, which stops for its tracer and lets it
//! read and change its memory and registers.
//!
//! macOS gives no process another's memory or threads, so a tracee does
//! its tracer's work itself. Each traced process has a mailbox: a page in
//! fwe's private directory (`ptrace-<pid>`) that it and its tracer map.
//! At a stop (a signal about to be delivered, a system call's entry or
//! exit, an `execve`) the tracee writes its registers, the stop's wait
//! status and the signal's `siginfo` there, tells its tracer (an entry in
//! the tracer's inbox, its generation moved, `SIGCHLD` and fwe's wake
//! signal, which ends a host wait the tracer is in), and waits
//! for requests: the tracer reads and writes the registers and `siginfo`
//! in the mailbox itself, and asks the tracee to read or write memory
//! (`PEEK`/`POKE`) and to go on (`CONT`, `SYSCALL`, `DETACH`, with the
//! signal to deliver, if any). The tracee is never stopped on the host,
//! so the tracer's `wait` learns of a stop from its inbox ([`take_stop`])
//! before it asks the host about its children.
//!
//! A tracee whose tracer has ended goes on as if detached.

use crate::shared::{wait_word_for, wake_word};
use fwe_abi::errno;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

pub const PTRACE_TRACEME: u64 = 0;
pub const PTRACE_PEEKTEXT: u64 = 1;
pub const PTRACE_PEEKDATA: u64 = 2;
pub const PTRACE_PEEKUSR: u64 = 3;
pub const PTRACE_POKETEXT: u64 = 4;
pub const PTRACE_POKEDATA: u64 = 5;
pub const PTRACE_POKEUSR: u64 = 6;
pub const PTRACE_CONT: u64 = 7;
pub const PTRACE_KILL: u64 = 8;
pub const PTRACE_SINGLESTEP: u64 = 9;
pub const PTRACE_ATTACH: u64 = 16;
pub const PTRACE_DETACH: u64 = 17;
pub const PTRACE_SYSCALL: u64 = 24;
pub const PTRACE_SETOPTIONS: u64 = 0x4200;
pub const PTRACE_GETEVENTMSG: u64 = 0x4201;
pub const PTRACE_GETSIGINFO: u64 = 0x4202;
pub const PTRACE_SETSIGINFO: u64 = 0x4203;
pub const PTRACE_GETREGSET: u64 = 0x4204;
pub const PTRACE_SETREGSET: u64 = 0x4205;
pub const PTRACE_SEIZE: u64 = 0x4206;

pub const PTRACE_O_TRACESYSGOOD: u64 = 1;
pub const PTRACE_O_TRACEEXEC: u64 = 0x10;
/// The options fwe takes (the others need events it does not raise).
const KNOWN_OPTIONS: u64 = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | 0x0010_0000;
pub const PTRACE_EVENT_EXEC: i32 = 4;

const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;
/// `struct user_pt_regs`: x0-x30, sp, pc, pstate.
const PRSTATUS_SIZE: usize = 34 * 8;
/// `struct user_fpsimd_state`: v0-v31, fpsr, fpcr, two reserved words.
const PRFPREG_SIZE: usize = 32 * 16 + 16;

/// The mailbox's words.
const W_STATE: usize = 0;
const W_REQ: usize = 1;
const W_DONE: usize = 2;
const W_TRACER: usize = 3;
const W_STATUS: usize = 4;
const W_OP: usize = 5;
const W_ADDR: usize = 6;
const W_DATA: usize = 7;
const W_RESULT: usize = 8;
const W_OPTIONS: usize = 9;
const W_EVENTMSG: usize = 10;
/// Where the `siginfo`, the general registers and the FP registers are
/// kept, in bytes.
const SIGINFO_AT: usize = 256;
const REGS_AT: usize = 512;
const FPREGS_AT: usize = 1024;
const PAGE: usize = 4096;

/// [`W_STATE`]: running, stopped and not yet reported by `wait`, stopped
/// and reported.
const RUNNING: u64 = 0;
const STOPPED: u64 = 1;
const REPORTED: u64 = 2;

/// Requests: memory, and going on (the signal in [`W_DATA`]).
const OP_PEEK: u64 = 1;
const OP_POKE: u64 = 2;
const OP_CONT: u64 = 3;
const OP_SYSCALL: u64 = 4;
const OP_DETACH: u64 = 5;

/// A mapped mailbox or inbox page.
struct Page(&'static [AtomicU64]);

impl Page {
    fn word(&self, i: usize) -> &AtomicU64 {
        &self.0[i]
    }

    fn bytes(&self, at: usize, len: usize) -> Vec<u8> {
        (at..at + len)
            .step_by(8)
            .flat_map(|i| self.0[i / 8].load(Ordering::Acquire).to_le_bytes())
            .collect()
    }

    fn put(&self, at: usize, data: &[u8]) {
        for (i, chunk) in data.chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            self.0[at / 8 + i].store(u64::from_le_bytes(w), Ordering::Release);
        }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: the page `open` mapped, no longer used.
        unsafe { libc::munmap(self.0.as_ptr() as *mut libc::c_void, PAGE) };
    }
}

fn path(name: &str) -> Option<std::ffi::CString> {
    let mut p = crate::fs::shm::user_dir().ok()?;
    p.extend_from_slice(name.as_bytes());
    std::ffi::CString::new(p).ok()
}

/// Map the page `name` in fwe's private directory, made if `create`.
fn open(name: &str, create: bool) -> Option<Page> {
    let c = path(name)?;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | if create { libc::O_CREAT } else { 0 };
    // SAFETY: a NUL-terminated path in fwe's private directory.
    let fd = unsafe { libc::open(c.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return None;
    }
    // SAFETY: plain host calls on the descriptor just opened; a file
    // shorter than a page is grown with zeros.
    let map = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) == 0 && (st.st_size as usize) < PAGE {
            libc::ftruncate(fd, PAGE as libc::off_t);
        }
        let m = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        m
    };
    if map == libc::MAP_FAILED {
        return None;
    }
    // SAFETY: a page, shared, page-aligned, every access atomic; unmapped
    // when the `Page` goes.
    Some(Page(unsafe { std::slice::from_raw_parts(map as *const AtomicU64, PAGE / 8) }))
}

fn mailbox_name(pid: i32) -> String {
    format!("/ptrace-{pid}")
}

fn inbox_name(pid: i32) -> String {
    format!("/ptrace-inbox-{pid}")
}

fn me() -> i32 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() }
}

fn alive(pid: i32) -> bool {
    crate::host::process_exists(pid)
}

// --- the tracee ----------------------------------------------------------------

/// Whether this process is traced, by whom (host pid), and with which
/// options; whether it stops at system calls.
static TRACED: AtomicBool = AtomicBool::new(false);
static TRACER: AtomicI32 = AtomicI32::new(0);
static SYSCALLS: AtomicBool = AtomicBool::new(false);

/// Whether this process is traced.
pub fn traced() -> bool {
    TRACED.load(Ordering::Acquire)
}

/// Whether it stops at each system call's entry and exit.
pub fn stops_at_syscalls() -> bool {
    traced() && SYSCALLS.load(Ordering::Acquire)
}

/// This process is traced by host process `tracer` from now on.
fn begin(tracer: i32) -> Result<(), i32> {
    let mb = open(&mailbox_name(me()), true).ok_or(errno::ENOMEM)?;
    for w in [W_STATE, W_REQ, W_DONE, W_OPTIONS, W_EVENTMSG] {
        mb.word(w).store(0, Ordering::Release);
    }
    mb.word(W_TRACER).store(tracer as u64, Ordering::Release);
    TRACER.store(tracer, Ordering::Release);
    SYSCALLS.store(false, Ordering::Release);
    TRACED.store(true, Ordering::Release);
    // Its tracer looks for its stops in its inbox.
    if let Some(inbox) = open(&inbox_name(tracer), true) {
        let pid = me() as u64;
        let slots = &inbox.0[1..];
        if !slots.iter().any(|s| s.load(Ordering::Acquire) == pid) {
            for s in slots {
                if s.compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// `PTRACE_TRACEME`: traced by the parent, host process `parent`.
pub fn traceme(parent: i32) -> Result<(), i32> {
    if traced() {
        return Err(errno::EPERM);
    }
    begin(parent)
}

/// Tracing ends (detached, or the tracer gone).
fn end() {
    TRACED.store(false, Ordering::Release);
    SYSCALLS.store(false, Ordering::Release);
    if let Some(c) = path(&mailbox_name(me())) {
        // SAFETY: a NUL-terminated path of fwe's.
        unsafe { libc::unlink(c.as_ptr()) };
    }
}

/// In a fork child: not traced (its parent's tracer does not trace it).
pub fn forked_child() {
    TRACED.store(false, Ordering::Release);
    SYSCALLS.store(false, Ordering::Release);
}

/// As this process ends: its mailbox goes.
pub fn exiting() {
    if traced() {
        end();
    }
}

/// What a re-executed fwe must know: the tracer (0: none).
pub fn exec_state() -> i32 {
    if traced() { TRACER.load(Ordering::Acquire) } else { 0 }
}

/// In a re-executed fwe: traced by `tracer` again, as before `execve`.
pub fn restore(tracer: i32) {
    if tracer > 0 && alive(tracer) {
        let _ = begin(tracer);
    }
}

/// How a stop ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// Go on, delivering this signal (0: none).
    Cont(u64),
    /// Go on, stopping at the next system call's entry or exit.
    Syscall(u64),
}

impl Resume {
    pub fn signal(self) -> u64 {
        match self {
            Resume::Cont(s) | Resume::Syscall(s) => s,
        }
    }
}

/// The options the tracer set.
pub fn options() -> u64 {
    open(&mailbox_name(me()), false).map_or(0, |mb| mb.word(W_OPTIONS).load(Ordering::Acquire))
}

/// Stop for the tracer with wait status `status` and `siginfo` (128
/// bytes), the registers `regs` its to read and change, until it says to
/// go on: how. Not traced, or the tracer gone: `Cont(0)`, or the signal
/// the stop was for.
pub fn stop(regs: &mut crate::Regs, status: i32, siginfo: &[u8; 128], event: u64) -> Resume {
    let sig = ((status >> 8) & 0x7f) as u64;
    let passing = if status >> 16 == 0 && sig != libc::SIGTRAP as u64 { sig } else { 0 };
    let Some(mb) = open(&mailbox_name(me()), false) else { return Resume::Cont(passing) };
    let tracer = TRACER.load(Ordering::Acquire);
    if !alive(tracer) {
        end();
        return Resume::Cont(passing);
    }
    put_regs(&mb, regs);
    mb.put(SIGINFO_AT, siginfo);
    mb.word(W_EVENTMSG).store(event, Ordering::Release);
    mb.word(W_STATUS).store(status as u32 as u64, Ordering::Release);
    mb.word(W_STATE).store(STOPPED, Ordering::Release);
    wake_word(mb.word(W_STATE));
    // Its tracer is told: its inbox's generation, and `SIGCHLD`.
    if let Some(inbox) = open(&inbox_name(tracer), false) {
        inbox.word(0).fetch_add(1, Ordering::AcqRel);
        wake_word(inbox.word(0));
    }
    crate::host::kill_process(tracer, libc::SIGCHLD);
    // fwe's wake signal too, which ends a host wait the tracer is in.
    crate::host::kill_process(tracer, crate::host::WAKE_SIGNAL);
    loop {
        let req = mb.word(W_REQ).load(Ordering::Acquire);
        if req == mb.word(W_DONE).load(Ordering::Acquire) {
            if !alive(tracer) {
                end();
                break Resume::Cont(passing);
            }
            wait_word_for(mb.word(W_REQ), req, Duration::from_millis(100));
            continue;
        }
        let (op, addr, data) = (
            mb.word(W_OP).load(Ordering::Acquire),
            mb.word(W_ADDR).load(Ordering::Acquire),
            mb.word(W_DATA).load(Ordering::Acquire),
        );
        let mut resume = None;
        let result: i64 = match op {
            OP_PEEK => match peek(addr) {
                Ok(v) => {
                    mb.word(W_DATA).store(v, Ordering::Release);
                    0
                }
                Err(e) => -(e as i64),
            },
            OP_POKE => match poke(addr, data) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            },
            OP_CONT => {
                resume = Some(Resume::Cont(data));
                0
            }
            OP_SYSCALL => {
                resume = Some(Resume::Syscall(data));
                0
            }
            OP_DETACH => {
                resume = Some(Resume::Cont(data));
                0
            }
            _ => -(errno::EIO as i64),
        };
        mb.word(W_RESULT).store(result as u64, Ordering::Release);
        if let Some(r) = resume {
            get_regs(&mb, regs);
            SYSCALLS.store(matches!(r, Resume::Syscall(_)), Ordering::Release);
            mb.word(W_STATE).store(RUNNING, Ordering::Release);
            mb.word(W_DONE).store(req, Ordering::Release);
            wake_word(mb.word(W_DONE));
            if op == OP_DETACH {
                end();
            }
            break r;
        }
        mb.word(W_DONE).store(req, Ordering::Release);
        wake_word(mb.word(W_DONE));
    }
}

fn put_regs(mb: &Page, regs: &crate::Regs) {
    let mut b = Vec::with_capacity(PRSTATUS_SIZE);
    for v in regs.x.iter().chain([regs.sp, regs.pc, regs.pstate].iter()) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    mb.put(REGS_AT, &b);
    let mut f = Vec::with_capacity(PRFPREG_SIZE);
    for v in &regs.fp.v {
        f.extend_from_slice(&v.to_le_bytes());
    }
    f.extend_from_slice(&regs.fp.fpsr.to_le_bytes());
    f.extend_from_slice(&regs.fp.fpcr.to_le_bytes());
    f.extend_from_slice(&[0u8; 8]);
    mb.put(FPREGS_AT, &f);
}

fn get_regs(mb: &Page, regs: &mut crate::Regs) {
    let b = mb.bytes(REGS_AT, PRSTATUS_SIZE);
    let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    for (i, x) in regs.x.iter_mut().enumerate() {
        *x = w(i);
    }
    regs.sp = w(31);
    regs.pc = w(32);
    regs.pstate = w(33);
    let f = mb.bytes(FPREGS_AT, PRFPREG_SIZE);
    for (i, v) in regs.fp.v.iter_mut().enumerate() {
        *v = u128::from_le_bytes(f[i * 16..i * 16 + 16].try_into().unwrap());
    }
    regs.fp.fpsr = u32::from_le_bytes(f[512..516].try_into().unwrap());
    regs.fp.fpcr = u32::from_le_bytes(f[516..520].try_into().unwrap());
}

/// A word of this process's memory, as the tracer reads it (`EIO` where
/// none is mapped or readable, as Linux's).
fn peek(addr: u64) -> Result<u64, i32> {
    let mut b = [0u8; 8];
    crate::procmem::read_forced(addr, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Write a word of this process's memory, as the tracer does (read-only
/// private memory too, as Linux's forced write).
fn poke(addr: u64, value: u64) -> Result<(), i32> {
    crate::procmem::write_forced(addr, &value.to_le_bytes())
}

/// A wait status of a stop for signal `sig` (`event`: a ptrace event's
/// number, in the high half).
pub fn stop_status(sig: u64, event: i32) -> i32 {
    0x7f | ((sig as i32) << 8) | (event << 16)
}

// --- the tracer ----------------------------------------------------------------

/// The tracee host process `pid`'s mailbox, if this process traces it.
fn tracee(pid: i32) -> Result<Page, i32> {
    let mb = open(&mailbox_name(pid), false).ok_or(errno::ESRCH)?;
    if mb.word(W_TRACER).load(Ordering::Acquire) != me() as u64 || !alive(pid) {
        return Err(errno::ESRCH);
    }
    Ok(mb)
}

/// The tracee host process `pid`'s mailbox, if this process traces it and
/// it is stopped (`ESRCH` otherwise, as Linux's).
fn stopped(pid: i32) -> Result<Page, i32> {
    let mb = tracee(pid)?;
    if mb.word(W_STATE).load(Ordering::Acquire) == RUNNING {
        return Err(errno::ESRCH);
    }
    Ok(mb)
}

/// Ask stopped tracee `mb` (host process `pid`) to do `op`: its result.
fn ask(mb: &Page, pid: i32, op: u64, addr: u64, data: u64) -> Result<i64, i32> {
    mb.word(W_OP).store(op, Ordering::Release);
    mb.word(W_ADDR).store(addr, Ordering::Release);
    mb.word(W_DATA).store(data, Ordering::Release);
    let req = mb.word(W_REQ).fetch_add(1, Ordering::AcqRel) + 1;
    wake_word(mb.word(W_REQ));
    loop {
        let done = mb.word(W_DONE).load(Ordering::Acquire);
        if done == req {
            break;
        }
        if !alive(pid) {
            return Err(errno::ESRCH);
        }
        wait_word_for(mb.word(W_DONE), done, Duration::from_millis(100));
    }
    let r = mb.word(W_RESULT).load(Ordering::Acquire) as i64;
    if r < 0 { Err(-r as i32) } else { Ok(r) }
}

/// Whether this process traces any process.
pub fn tracing() -> bool {
    let Some(c) = path(&inbox_name(me())) else { return false };
    // SAFETY: a NUL-terminated path; F_OK only checks it is there.
    unsafe { libc::access(c.as_ptr(), libc::F_OK) == 0 }
}

/// The inbox's generation, which every tracee's stop moves.
pub fn inbox_generation() -> u64 {
    open(&inbox_name(me()), false).map_or(0, |i| i.word(0).load(Ordering::Acquire))
}

/// Sleep until a tracee stops (the inbox's generation moves from `seen`)
/// or `slice` passes.
pub fn wait_for_stop(seen: u64, slice: Duration) {
    if let Some(inbox) = open(&inbox_name(me()), false) {
        wait_word_for(inbox.word(0), seen, slice);
    } else {
        std::thread::sleep(slice);
    }
}

/// A stop of a tracee `wanted` accepts (by host pid) not yet reported:
/// its pid and wait status, reported now unless `peek`.
pub fn take_stop(wanted: impl Fn(i32) -> bool, peek: bool) -> Option<(i32, i32)> {
    let inbox = open(&inbox_name(me()), false)?;
    for slot in &inbox.0[1..] {
        let pid = slot.load(Ordering::Acquire) as i32;
        if pid <= 0 {
            continue;
        }
        let Some(mb) = open(&mailbox_name(pid), false) else {
            // Its tracing ended: the slot is free.
            let _ = slot.compare_exchange(pid as u64, 0, Ordering::AcqRel, Ordering::Acquire);
            continue;
        };
        if mb.word(W_TRACER).load(Ordering::Acquire) != me() as u64 || !wanted(pid) {
            continue;
        }
        if mb.word(W_STATE).load(Ordering::Acquire) == STOPPED {
            if !peek {
                mb.word(W_STATE).store(REPORTED, Ordering::Release);
            }
            return Some((pid, mb.word(W_STATUS).load(Ordering::Acquire) as i32));
        }
    }
    None
}

/// The `PTRACE_*` requests on tracee host process `pid`, `addr` and `data`
/// as the guest gave them. Requests that copy to or from the guest are
/// the caller's ([`crate::Kernel::sys_ptrace`]); this is what touches the
/// tracee.
pub fn peek_word(pid: i32, addr: u64) -> Result<u64, i32> {
    let mb = stopped(pid)?;
    ask(&mb, pid, OP_PEEK, addr, 0)?;
    Ok(mb.word(W_DATA).load(Ordering::Acquire))
}

pub fn poke_word(pid: i32, addr: u64, value: u64) -> Result<(), i32> {
    let mb = stopped(pid)?;
    ask(&mb, pid, OP_POKE, addr, value).map(|_| ())
}

/// Let stopped tracee `pid` go on as `op` says, delivering `sig`.
pub fn resume(pid: i32, op: u64, sig: u64) -> Result<(), i32> {
    let mb = stopped(pid)?;
    let op = match op {
        PTRACE_CONT => OP_CONT,
        PTRACE_SYSCALL => OP_SYSCALL,
        _ => OP_DETACH,
    };
    ask(&mb, pid, op, 0, sig).map(|_| ())
}

/// The register set `kind` of stopped tracee `pid`.
pub fn get_regset(pid: i32, kind: u64) -> Result<Vec<u8>, i32> {
    let mb = stopped(pid)?;
    match kind {
        NT_PRSTATUS => Ok(mb.bytes(REGS_AT, PRSTATUS_SIZE)),
        NT_PRFPREG => Ok(mb.bytes(FPREGS_AT, PRFPREG_SIZE)),
        _ => Err(errno::EINVAL),
    }
}

/// Set (the first `data.len()` bytes of) register set `kind` of stopped
/// tracee `pid`.
pub fn set_regset(pid: i32, kind: u64, data: &[u8]) -> Result<(), i32> {
    let mb = stopped(pid)?;
    let (at, size) = match kind {
        NT_PRSTATUS => (REGS_AT, PRSTATUS_SIZE),
        NT_PRFPREG => (FPREGS_AT, PRFPREG_SIZE),
        _ => return Err(errno::EINVAL),
    };
    let mut all = mb.bytes(at, size);
    let n = data.len().min(size);
    all[..n].copy_from_slice(&data[..n]);
    mb.put(at, &all);
    Ok(())
}

/// The `siginfo` of stopped tracee `pid`'s stop.
pub fn get_siginfo(pid: i32) -> Result<[u8; 128], i32> {
    let mb = stopped(pid)?;
    let b = mb.bytes(SIGINFO_AT, 128);
    Ok(b.try_into().unwrap())
}

pub fn set_siginfo(pid: i32, info: &[u8; 128]) -> Result<(), i32> {
    let mb = stopped(pid)?;
    mb.put(SIGINFO_AT, info);
    Ok(())
}

pub fn set_options(pid: i32, options: u64) -> Result<(), i32> {
    let mb = stopped(pid)?;
    if options & !KNOWN_OPTIONS != 0 {
        return Err(errno::EINVAL);
    }
    mb.word(W_OPTIONS).store(options, Ordering::Release);
    Ok(())
}

pub fn event_msg(pid: i32) -> Result<u64, i32> {
    Ok(stopped(pid)?.word(W_EVENTMSG).load(Ordering::Acquire))
}

/// Whether host process `pid` is traced by any process.
pub fn is_traced(pid: i32) -> bool {
    open(&mailbox_name(pid), false)
        .is_some_and(|mb| alive(mb.word(W_TRACER).load(Ordering::Acquire) as i32))
}

/// Whether this process traces host process `pid`.
pub fn traces(pid: i32) -> bool {
    tracee(pid).is_ok()
}

/// `PTRACE_ATTACH` of host process `pid` by this process: its mailbox made
/// with this process as its tracer, ready for the SIGSTOP the caller sends
/// it, which it stops for ([`attached`]).
pub fn attach(pid: i32) -> Result<(), i32> {
    if is_traced(pid) {
        return Err(errno::EPERM);
    }
    let mb = open(&mailbox_name(pid), true).ok_or(errno::ENOMEM)?;
    for w in [W_STATE, W_REQ, W_DONE, W_OPTIONS, W_EVENTMSG] {
        mb.word(w).store(0, Ordering::Release);
    }
    mb.word(W_TRACER).store(me() as u64, Ordering::Release);
    let inbox = open(&inbox_name(me()), true).ok_or(errno::ENOMEM)?;
    let slots = &inbox.0[1..];
    if !slots.iter().any(|s| s.load(Ordering::Acquire) == pid as u64)
        && !slots
            .iter()
            .any(|s| s.compare_exchange(0, pid as u64, Ordering::AcqRel, Ordering::Acquire).is_ok())
    {
        return Err(errno::EAGAIN);
    }
    Ok(())
}

/// Whether taking `sig` begins this process's tracing: a SIGSTOP a tracer
/// sent as it attached (its mailbox names a live tracer).
pub fn attached(sig: u64) -> bool {
    if sig != fwe_abi::signal::SIGSTOP || traced() {
        return false;
    }
    let Some(mb) = open(&mailbox_name(me()), false) else { return false };
    let tracer = mb.word(W_TRACER).load(Ordering::Acquire) as i32;
    if tracer <= 0 || !alive(tracer) {
        return false;
    }
    TRACER.store(tracer, Ordering::Release);
    SYSCALLS.store(false, Ordering::Release);
    TRACED.store(true, Ordering::Release);
    true
}

impl<P: crate::Platform> crate::Kernel<P> {
    /// Every signal caught on the host while traced, and as before after.
    fn resync_for_tracing(&mut self) {
        for sig in 1..=fwe_abi::signal::NSIG {
            self.sync_host_signal(sig);
        }
    }

    /// A signal-delivery stop for `sig` raised with `info`: the signal to
    /// deliver after it, as the tracer chose (`None`: none).
    pub(crate) fn ptrace_signal_stop(
        &mut self,
        regs: &mut crate::Regs,
        sig: u64,
        info: crate::thread::SigInfo,
    ) -> Option<(u64, crate::thread::SigInfo)> {
        if !traced() {
            // Just attached: the host catches every signal from now on.
            self.resync_for_tracing();
        }
        let si = crate::signal::siginfo_bytes(sig, info);
        let r = stop(regs, stop_status(sig, 0), &si, 0);
        if !traced() {
            self.resync_for_tracing();
        }
        let to = r.signal();
        if to == 0 || to > fwe_abi::signal::NSIG {
            return None;
        }
        // The same signal carries what the tracer left of its `siginfo`;
        // another one is raised by the tracer.
        let info = match get_own_siginfo() {
            Some(b) if to == sig => crate::signal::siginfo_parse(&b).1,
            _ => crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() },
        };
        Some((to, info))
    }

    /// The stop after a successful `execve` of a traced process: SIGTRAP,
    /// or the exec event (`PTRACE_O_TRACEEXEC`).
    pub fn ptrace_exec_stop(&mut self, regs: &mut crate::Regs) {
        if !traced() {
            return;
        }
        self.resync_for_tracing();
        let trap = fwe_abi::signal::SIGTRAP;
        let event = if options() & PTRACE_O_TRACEEXEC != 0 { PTRACE_EVENT_EXEC } else { 0 };
        let info = crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
        let si = crate::signal::siginfo_bytes(trap, info);
        let msg = crate::thread::tgid() as u64;
        let r = stop(regs, stop_status(trap, event), &si, msg);
        if r.signal() != 0 {
            crate::thread::post_process(r.signal(), info);
        }
    }

    /// A system call's entry or exit stop (`PTRACE_SYSCALL`).
    pub fn ptrace_syscall_stop(&mut self, regs: &mut crate::Regs) {
        if !stops_at_syscalls() {
            return;
        }
        let good = options() & PTRACE_O_TRACESYSGOOD != 0;
        let trap = fwe_abi::signal::SIGTRAP | if good { 0x80 } else { 0 };
        let info =
            crate::thread::SigInfo { code: fwe_abi::signal::SIGTRAP as i32, ..Default::default() };
        let si = crate::signal::siginfo_bytes(fwe_abi::signal::SIGTRAP, info);
        let r = stop(regs, stop_status(trap, 0), &si, 0);
        if r.signal() != 0 {
            let info =
                crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
            crate::thread::post_process(r.signal(), info);
        }
    }

    /// Whether the caller may trace host process `target` (Linux's
    /// `ptrace_may_access` for attaching): `CAP_SYS_PTRACE`, or the same
    /// real, effective and saved ids as the target's, and the target
    /// dumpable.
    fn may_trace(&self, target: i32) -> bool {
        if self.creds.has(crate::caps::CAP_SYS_PTRACE) {
            return true;
        }
        let ids = crate::procreg::ids(target);
        let c = &self.creds;
        let uid = [c.uid, c.euid, c.suid];
        let gid = [c.gid, c.egid, c.sgid];
        ids[..3].iter().all(|u| uid.iter().all(|x| x == u))
            && ids[4..7].iter().all(|g| gid.iter().all(|x| x == g))
    }

    /// `ptrace(request, pid, addr, data)`.
    pub(crate) fn sys_ptrace(&mut self, request: u64, pid: u64, addr: u64, data: u64) -> i64 {
        use crate::uaccess;
        use fwe_abi::err;
        if request == PTRACE_TRACEME {
            // SAFETY: getppid cannot fail.
            let parent = unsafe { libc::getppid() };
            return match traceme(parent) {
                Ok(()) => {
                    self.resync_for_tracing();
                    0
                }
                Err(e) => err(e),
            };
        }
        let Some(target) = crate::pidns::to_host(pid as i32).filter(|&h| alive(h)) else {
            return err(errno::ESRCH);
        };
        if matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
            if target == me() || crate::thread::host_thread(pid as i32).is_some() {
                return err(errno::EPERM);
            }
            if !self.may_trace(target) || crate::procreg::read(target).is_none() {
                return err(errno::EPERM);
            }
            if let Err(e) = attach(target) {
                return err(e);
            }
            return crate::signal::send_unhosted(
                target,
                fwe_abi::signal::SIGSTOP,
                fwe_abi::signal::SI_USER,
                0,
            );
        }
        if request == PTRACE_KILL {
            if !traces(target) {
                return err(errno::ESRCH);
            }
            crate::host::kill_process(target, libc::SIGKILL);
            return 0;
        }
        let r: Result<i64, i32> = (|| match request {
            PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
                let v = peek_word(target, addr)?;
                uaccess::write(data, v)?;
                Ok(0)
            }
            PTRACE_POKETEXT | PTRACE_POKEDATA => poke_word(target, addr, data).map(|()| 0),
            // No `struct user` on arm64.
            PTRACE_PEEKUSR | PTRACE_POKEUSR => {
                stopped(target)?;
                Err(errno::EIO)
            }
            PTRACE_CONT | PTRACE_SYSCALL | PTRACE_DETACH => {
                if data > fwe_abi::signal::NSIG {
                    stopped(target)?;
                    return Err(errno::EIO);
                }
                resume(target, request, data).map(|()| 0)
            }
            PTRACE_GETREGSET | PTRACE_SETREGSET => {
                let iov: [u64; 2] = uaccess::read(data)?;
                if request == PTRACE_GETREGSET {
                    let set = get_regset(target, addr)?;
                    let n = set.len().min(iov[1] as usize);
                    uaccess::write_from(iov[0], &set[..n])?;
                    uaccess::write(data + 8, n as u64)?;
                } else {
                    stopped(target)?;
                    let bytes = uaccess::read_bytes(iov[0], iov[1].min(4096) as usize)?;
                    set_regset(target, addr, &bytes)?;
                }
                Ok(0)
            }
            PTRACE_GETSIGINFO => {
                let si = get_siginfo(target)?;
                uaccess::write_from(data, &si)?;
                Ok(0)
            }
            PTRACE_SETSIGINFO => {
                stopped(target)?;
                let b: [u8; 128] = uaccess::read(data)?;
                set_siginfo(target, &b).map(|()| 0)
            }
            PTRACE_SETOPTIONS => set_options(target, data).map(|()| 0),
            PTRACE_GETEVENTMSG => {
                let m = event_msg(target)?;
                uaccess::write(data, m)?;
                Ok(0)
            }
            _ => {
                stopped(target)?;
                Err(errno::EIO)
            }
        })();
        match r {
            Ok(v) => v,
            Err(e) => err(e),
        }
    }
}

/// The `siginfo` this process's tracer left in its mailbox.
fn get_own_siginfo() -> Option<[u8; 128]> {
    let mb = open(&mailbox_name(me()), false)?;
    mb.bytes(SIGINFO_AT, 128).try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_statuses_are_linuxs() {
        // WIFSTOPPED, WSTOPSIG: a signal-delivery stop of SIGUSR2.
        let s = stop_status(12, 0);
        assert_eq!(s & 0xff, 0x7f);
        assert_eq!((s >> 8) & 0xff, 12);
        // A system call's stop with PTRACE_O_TRACESYSGOOD.
        assert_eq!((stop_status(5 | 0x80, 0) >> 8) & 0xff, 0x85);
        // The exec event: SIGTRAP with the event in the high half.
        assert_eq!(stop_status(5, PTRACE_EVENT_EXEC), 0x7f | 5 << 8 | 4 << 16);
    }

    #[test]
    fn a_mailbox_keeps_registers_and_siginfo() {
        let words: &'static [AtomicU64] =
            Box::leak((0..PAGE / 8).map(|_| AtomicU64::new(0)).collect::<Vec<_>>().into());
        let mb = std::mem::ManuallyDrop::new(Page(words));
        let mut regs = crate::Regs::default();
        for (i, x) in regs.x.iter_mut().enumerate() {
            *x = i as u64 * 3;
        }
        regs.sp = 0x7ff0;
        regs.pc = 0x4000;
        regs.fp.v[31] = u128::MAX - 1;
        regs.fp.fpcr = 7;
        put_regs(&mb, &regs);
        let mut back = crate::Regs::default();
        get_regs(&mb, &mut back);
        assert_eq!(back, regs);
        let si: [u8; 128] = std::array::from_fn(|i| i as u8);
        mb.put(SIGINFO_AT, &si);
        assert_eq!(mb.bytes(SIGINFO_AT, 128), si.to_vec());
        // The tracer's view of the general registers: x0 first, pc at 32.
        let set = mb.bytes(REGS_AT, PRSTATUS_SIZE);
        assert_eq!(u64::from_le_bytes(set[32 * 8..33 * 8].try_into().unwrap()), 0x4000);
    }
}
