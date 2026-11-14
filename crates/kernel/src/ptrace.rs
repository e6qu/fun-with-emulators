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
pub const PTRACE_INTERRUPT: u64 = 0x4207;
pub const PTRACE_LISTEN: u64 = 0x4208;
pub const PTRACE_GETSIGMASK: u64 = 0x420a;
pub const PTRACE_SETSIGMASK: u64 = 0x420b;
pub const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;

pub const PTRACE_O_TRACESYSGOOD: u64 = 1;
pub const PTRACE_O_TRACEFORK: u64 = 0x2;
pub const PTRACE_O_TRACEVFORK: u64 = 0x4;
pub const PTRACE_O_TRACECLONE: u64 = 0x8;
pub const PTRACE_O_TRACEEXEC: u64 = 0x10;
pub const PTRACE_O_TRACEVFORKDONE: u64 = 0x20;
pub const PTRACE_O_TRACEEXIT: u64 = 0x40;
pub const PTRACE_O_EXITKILL: u64 = 0x10_0000;
/// The options fwe takes (not `PTRACE_O_TRACESECCOMP` or
/// `PTRACE_O_SUSPEND_SECCOMP`, which need seccomp's tracer return).
const KNOWN_OPTIONS: u64 = PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEVFORKDONE
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_EXITKILL;
pub const PTRACE_EVENT_FORK: i32 = 1;
pub const PTRACE_EVENT_VFORK: i32 = 2;
pub const PTRACE_EVENT_CLONE: i32 = 3;
pub const PTRACE_EVENT_EXEC: i32 = 4;
pub const PTRACE_EVENT_VFORK_DONE: i32 = 5;
pub const PTRACE_EVENT_EXIT: i32 = 6;
/// A seized tracee's stop that no signal or event made: an interrupt, a
/// group-stop, the end of one.
pub const PTRACE_EVENT_STOP: i32 = 128;

/// The `si_code` of the SIGSTOP fwe sends a seized tracee, through fwe's
/// own queue: no signal for the guest, but a nudge to look at its mailbox
/// (to begin being traced, or for an interrupt), which ends a wait it is
/// in as a signal would, and the call it was in starts again after.
pub const POKE_CODE: i32 = 0x4206;
/// `AUDIT_ARCH_AARCH64`, a system call's architecture.
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;
/// The system call's number (`x8` at a system call's stop), to read and
/// change (-1 skips the call).
const NT_ARM_SYSTEM_CALL: u64 = 0x404;
/// The thread pointer.
const NT_ARM_TLS: u64 = 0x401;
/// The hardware breakpoint and watchpoint registers: none here (their
/// `dbg_info` says 0 of each), so a debugger plants breakpoints in the
/// code and watches by stepping.
const NT_ARM_HW_BREAK: u64 = 0x402;
const NT_ARM_HW_WATCH: u64 = 0x403;
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
/// The host process the tracee (a process, or a thread of it) is.
const W_PROC: usize = 11;
/// The tracee's thread pointer (`TPIDR_EL0`, `NT_ARM_TLS`).
const W_TLS: usize = 12;
/// 1: attached by `PTRACE_SEIZE` (stops it did not ask for are event
/// stops, and `PTRACE_INTERRUPT` and `PTRACE_LISTEN` work).
const W_SEIZED: usize = 13;
/// 1: `PTRACE_INTERRUPT` asked for a stop not yet made.
const W_INTERRUPT: usize = 14;
/// The tracee's signal mask at its stop, and 1 in the next word if the
/// tracer set another (`PTRACE_SETSIGMASK`).
const W_SIGMASK: usize = 15;
const W_SIGMASK_SET: usize = 16;
/// The stop's system call, for `PTRACE_GET_SYSCALL_INFO`: 1 at its entry,
/// 2 at its exit, 0 for a stop of another kind.
const W_SYSCALL: usize = 17;
/// Where the `siginfo`, the general registers and the FP registers are
/// kept, in bytes.
const SIGINFO_AT: usize = 256;
const REGS_AT: usize = 512;
const FPREGS_AT: usize = 1024;
/// Memory the tracer reads or writes through the tracee (`OP_READ`,
/// `OP_WRITE`), a part at a time.
const MEMBUF_AT: usize = 2048;
const MEMBUF_LEN: usize = 2048;
const PAGE: usize = 4096;

/// [`W_STATE`]: running, stopped and not yet reported by `wait`, stopped
/// and reported.
const RUNNING: u64 = 0;
const STOPPED: u64 = 1;
const REPORTED: u64 = 2;
/// Ended, its wait status for a tracer that is not its parent (whose host
/// `wait` does not see it).
const EXITED: u64 = 3;
/// Stopped in a group-stop the tracer listens to (`PTRACE_LISTEN`): not
/// stopped as far as ptrace's requests go, until it reports again.
const LISTENING: u64 = 4;

/// Requests: memory, and going on (the signal in [`W_DATA`]).
const OP_PEEK: u64 = 1;
const OP_POKE: u64 = 2;
const OP_CONT: u64 = 3;
const OP_SYSCALL: u64 = 4;
const OP_DETACH: u64 = 5;
const OP_STEP: u64 = 6;
const OP_LISTEN: u64 = 7;
/// Read or write [`W_DATA`] bytes at [`W_ADDR`] through [`MEMBUF_AT`].
const OP_READ: u64 = 8;
const OP_WRITE: u64 = 9;

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
    crate::host::pid()
}

fn alive(pid: i32) -> bool {
    crate::host::process_exists(pid)
}

// --- the tracee ----------------------------------------------------------------

// A thread is traced, as on Linux: each traced thread has a mailbox of its
// own, named by its tid (the main thread's by the process's pid), and stops
// on its own while the others go on.
std::thread_local! {
    /// Whether this thread is traced, by whom (host pid), and whether it
    /// stops at system calls.
    static TRACED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TRACER: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static SYSCALLS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// How many of this process's threads are traced (the host catches every
/// signal while any is), and which besides the main thread.
static ANY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub(crate) static THREADS: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// Whether this thread is traced.
pub fn traced() -> bool {
    TRACED.with(std::cell::Cell::get)
}

/// Whether any thread of this process is traced.
pub fn any_traced() -> bool {
    ANY.load(Ordering::Acquire) > 0
}

fn tracer() -> i32 {
    TRACER.with(std::cell::Cell::get)
}

/// The host's signal dispositions are to be set again: a thread began or
/// ended being traced ([`crate::Kernel::resync_for_tracing`]).
static RESYNC: AtomicBool = AtomicBool::new(false);

/// This thread traced (or not any more).
fn set_traced(on: bool) {
    if TRACED.with(|t| t.replace(on)) != on {
        RESYNC.store(true, Ordering::Release);
        if on {
            ANY.fetch_add(1, Ordering::AcqRel);
        } else {
            ANY.fetch_sub(1, Ordering::AcqRel);
        }
        let id = self_id();
        if id != me() {
            let mut t = THREADS.lock().unwrap_or_else(|e| e.into_inner());
            t.retain(|&x| x != id);
            if on {
                t.push(id);
            }
        }
    }
}

/// Whether this thread stops at each system call's entry and exit.
pub fn stops_at_syscalls() -> bool {
    traced() && SYSCALLS.with(std::cell::Cell::get)
}

/// What names this thread's mailbox: the process's host pid for its main
/// thread, its tid for another.
fn self_id() -> i32 {
    let tid = crate::thread::tid();
    if tid == 0 || tid == crate::thread::tgid() { me() } else { tid }
}

/// The words a new tracing starts with at 0.
const FRESH: [usize; 10] = [
    W_STATE,
    W_REQ,
    W_DONE,
    W_OPTIONS,
    W_EVENTMSG,
    W_SEIZED,
    W_INTERRUPT,
    W_SIGMASK,
    W_SIGMASK_SET,
    W_SYSCALL,
];

/// This thread is traced by host process `tracer` from now on.
fn begin(tracer: i32) -> Result<(), i32> {
    let id = self_id();
    let mb = open(&mailbox_name(id), true).ok_or(errno::ENOMEM)?;
    for w in FRESH {
        mb.word(w).store(0, Ordering::Release);
    }
    mb.word(W_TRACER).store(tracer as u64, Ordering::Release);
    mb.word(W_PROC).store(me() as u64, Ordering::Release);
    TRACER.with(|t| t.set(tracer));
    SYSCALLS.with(|t| t.set(false));
    set_traced(true);
    // Its tracer looks for its stops in its inbox.
    if let Some(inbox) = open(&inbox_name(tracer), true) {
        let pid = id as u64;
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

/// This thread's tracing ends (detached, or the tracer gone).
fn end() {
    set_traced(false);
    SYSCALLS.with(|t| t.set(false));
    if let Some(c) = path(&mailbox_name(self_id())) {
        // SAFETY: a NUL-terminated path of fwe's.
        unsafe { libc::unlink(c.as_ptr()) };
    }
}

/// In a fork child: not traced (its parent's tracer does not trace it).
pub fn forked_child() {
    let follow = FOLLOW.swap(0, Ordering::AcqRel);
    TRACED.with(|t| t.set(false));
    SYSCALLS.with(|t| t.set(false));
    ANY.store(0, Ordering::Release);
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    PENDING.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // Its parent's tracer follows it (`PTRACE_O_TRACEFORK` and the like):
    // traced from the start, and stopped first, as Linux starts it.
    if follow > 0 && begin(follow).is_ok() {
        let seized = FOLLOW_SEIZED.load(Ordering::Acquire);
        let opts = FOLLOW_OPTIONS.load(Ordering::Acquire);
        let (sig, info) = first_stop(self_id(), opts, seized);
        crate::thread::post_process(sig, info);
    }
}

/// A tracee followed from its start (`id`, with its creator's options
/// `opts`, seized if its creator was): its mailbox set so, and the signal
/// it first stops for: SIGSTOP, or for a seized one fwe's nudge, which
/// stops it with `PTRACE_EVENT_STOP`, as Linux starts each.
fn first_stop(id: i32, opts: u64, seized: bool) -> (u64, crate::thread::SigInfo) {
    use crate::thread::SigInfo;
    if let Some(mb) = open(&mailbox_name(id), false) {
        mb.word(W_OPTIONS).store(opts, Ordering::Release);
        mb.word(W_SEIZED).store(u64::from(seized), Ordering::Release);
        mb.word(W_INTERRUPT).store(u64::from(seized), Ordering::Release);
    }
    let code = if seized { POKE_CODE } else { fwe_abi::signal::SI_USER };
    (fwe_abi::signal::SIGSTOP, SigInfo { code, ..Default::default() })
}

/// Whether this thread was attached by `PTRACE_SEIZE`.
pub fn seized() -> bool {
    traced()
        && open(&mailbox_name(self_id()), false)
            .is_some_and(|mb| mb.word(W_SEIZED).load(Ordering::Acquire) == 1)
}

/// The tracer a fork child is to be traced by (0: none), set by its parent
/// just before it forks ([`fork_event`]).
static FOLLOW: AtomicI32 = AtomicI32::new(0);
static FOLLOW_OPTIONS: AtomicU64 = AtomicU64::new(0);
static FOLLOW_SEIZED: AtomicBool = AtomicBool::new(false);

/// The event a clone with `flags` raises in a traced thread, if its tracer
/// asked for it; the new process or thread is then traced too (a thread
/// once the backend names it, [`new_thread`]).
pub fn fork_event(flags: u64) -> Option<i32> {
    use fwe_abi::clone as cl;
    if !traced() {
        return None;
    }
    if flags & cl::CLONE_THREAD != 0 {
        let opts = options();
        if opts & PTRACE_O_TRACECLONE == 0 {
            return None;
        }
        NEW_THREAD.with(|n| n.set(Some((tracer(), opts, seized()))));
        return Some(PTRACE_EVENT_CLONE);
    }
    let (event, option) = if flags & cl::CLONE_VFORK != 0 {
        (PTRACE_EVENT_VFORK, PTRACE_O_TRACEVFORK)
    } else if flags & cl::CSIGNAL == fwe_abi::signal::SIGCHLD {
        (PTRACE_EVENT_FORK, PTRACE_O_TRACEFORK)
    } else {
        (PTRACE_EVENT_CLONE, PTRACE_O_TRACECLONE)
    };
    let opts = options();
    if opts & option == 0 {
        return None;
    }
    FOLLOW_OPTIONS.store(opts, Ordering::Release);
    FOLLOW_SEIZED.store(seized(), Ordering::Release);
    FOLLOW.store(tracer(), Ordering::Release);
    Some(event)
}

std::thread_local! {
    /// The tracer and options a thread this one is making is to be traced
    /// with, and whether seized ([`fork_event`]).
    static NEW_THREAD: std::cell::Cell<Option<(i32, u64, bool)>> = const { std::cell::Cell::new(None) };
}

/// New threads to be traced as they start, by tid: their tracer, options
/// and whether seized.
pub(crate) static PENDING: std::sync::Mutex<Vec<(i32, i32, u64, bool)>> =
    std::sync::Mutex::new(Vec::new());

/// A backend made thread `tid` for this thread's clone: traced as it
/// starts, if its tracer follows it.
pub fn new_thread(tid: i32) {
    if let Some((tracer, opts, seized)) = NEW_THREAD.with(std::cell::Cell::take) {
        PENDING.lock().unwrap_or_else(|e| e.into_inner()).push((tid, tracer, opts, seized));
    }
}

/// Thread `tid` starts: traced from the start if its tracer follows it,
/// with its creator's options, and stopped first ([`first_stop`]).
pub fn thread_started(tid: i32) {
    let found = {
        let mut p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        let i = p.iter().position(|e| e.0 == tid);
        i.map(|i| p.swap_remove(i))
    };
    let Some((_, tracer, opts, seized)) = found else { return };
    if begin(tracer).is_ok() {
        let (sig, info) = first_stop(self_id(), opts, seized);
        crate::thread::post_thread(tid, sig, info);
    }
}

/// This thread ends (the process going on): a tracer is told, as of any
/// tracee that is not its child.
pub fn thread_exiting() {
    if traced() && self_id() != me() {
        report_end(self_id(), tracer(), 0);
        set_traced(false);
    }
}

/// Tell `tracer` that tracee `id` ended with wait status `status`, through
/// its mailbox, which the tracer then removes ([`take_stop`]).
fn report_end(id: i32, tracer: i32, status: i32) {
    let Some(mb) = open(&mailbox_name(id), false) else { return };
    mb.word(W_STATUS).store(status as u32 as u64, Ordering::Release);
    mb.word(W_STATE).store(EXITED, Ordering::Release);
    if let Some(inbox) = open(&inbox_name(tracer), false) {
        inbox.word(0).fetch_add(1, Ordering::AcqRel);
        wake_word(inbox.word(0));
    }
    crate::host::kill_process(tracer, libc::SIGCHLD);
    crate::host::kill_process(tracer, crate::host::WAKE_SIGNAL);
}

/// Into a fork snapshot (the VM backend's child, a fresh process): the
/// tracer that follows the child, and its options.
pub fn save_fork(e: &mut crate::snapshot::Enc) {
    e.i32(FOLLOW.load(Ordering::Acquire));
    e.u64(FOLLOW_OPTIONS.load(Ordering::Acquire));
    e.bool(FOLLOW_SEIZED.load(Ordering::Acquire));
}

/// From a fork snapshot, in the child: followed as [`forked_child`] is.
pub fn load_fork(d: &mut crate::snapshot::Dec) {
    FOLLOW.store(d.i32(), Ordering::Release);
    FOLLOW_OPTIONS.store(d.u64(), Ordering::Release);
    FOLLOW_SEIZED.store(d.bool(), Ordering::Release);
    forked_child();
}

/// The fork is done (in the parent): no child is to follow any more.
pub fn fork_done() {
    FOLLOW.store(0, Ordering::Release);
    NEW_THREAD.with(std::cell::Cell::take);
}

std::thread_local! {
    /// A fork's event waiting for the call's result to be in the
    /// registers: the event, the clone's flags and the child's pid.
    static NOTED: std::cell::Cell<Option<(i32, u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Note fork event `event` of a clone with `flags` that made `child`, for
/// [`take_noted_fork`] once the call's result is in the registers.
pub fn note_fork(event: i32, flags: u64, child: u64) {
    NOTED.with(|n| n.set(Some((event, flags, child))));
}

/// The fork event [`note_fork`] noted, if any.
pub fn take_noted_fork() -> Option<(i32, u64, u64)> {
    NOTED.with(std::cell::Cell::take)
}

/// As this process ends: its mailbox goes.
pub fn exiting(status: i32) {
    // Its other traced threads end with it: their tracers are told.
    let others = std::mem::take(&mut *THREADS.lock().unwrap_or_else(|e| e.into_inner()));
    for id in others {
        if id == self_id() {
            continue;
        }
        if let Some(mb) = open(&mailbox_name(id), false) {
            let t = mb.word(W_TRACER).load(Ordering::Acquire) as i32;
            drop(mb);
            report_end(id, t, status);
        }
    }
    if traced() {
        let tracer = tracer();
        // SAFETY: getppid cannot fail.
        let parent = unsafe { libc::getppid() };
        // A tracer that is not the parent learns of the end from the
        // mailbox (the parent from the host's `wait`).
        if (tracer != parent || self_id() != me()) && alive(tracer) {
            report_end(self_id(), tracer, status);
            set_traced(false);
        } else {
            end();
        }
    }
    // A tracer that ends takes the tracees that asked it to with it
    // (`PTRACE_O_EXITKILL`).
    if let Some(inbox) = open(&inbox_name(me()), false) {
        for slot in &inbox.0[1..] {
            let pid = slot.load(Ordering::Acquire) as i32;
            if pid <= 0 {
                continue;
            }
            if let Some(mb) = open(&mailbox_name(pid), false)
                && mb.word(W_TRACER).load(Ordering::Acquire) == me() as u64
                && mb.word(W_OPTIONS).load(Ordering::Acquire) & PTRACE_O_EXITKILL != 0
            {
                crate::host::kill_process(pid, libc::SIGKILL);
            }
        }
        drop(inbox);
        if let Some(c) = path(&inbox_name(me())) {
            // SAFETY: a NUL-terminated path of fwe's.
            unsafe { libc::unlink(c.as_ptr()) };
        }
    }
}

/// What a re-executed fwe must know: the tracer (0: none), and whether
/// it stops at system calls.
pub fn exec_state() -> (i32, bool) {
    if traced() { (tracer(), stops_at_syscalls()) } else { (0, false) }
}

/// In a re-executed fwe: traced by `tracer` again, as before `execve`,
/// with its mailbox as it was (its options, whether it was seized), and
/// stopping at system calls if it did (`syscalls`).
pub fn restore(tracer: i32, syscalls: bool) {
    if tracer <= 0 || !alive(tracer) {
        return;
    }
    if open(&mailbox_name(self_id()), false).is_none() {
        let _ = begin(tracer);
    } else {
        TRACER.with(|t| t.set(tracer));
        set_traced(true);
    }
    SYSCALLS.with(|t| t.set(syscalls));
}

/// How a stop ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// Go on, delivering this signal (0: none).
    Cont(u64),
    /// Go on, stopping at the next system call's entry or exit.
    Syscall(u64),
    /// Run one instruction, then stop ([`arm_step`]).
    Step(u64),
}

impl Resume {
    pub fn signal(self) -> u64 {
        match self {
            Resume::Cont(s) | Resume::Syscall(s) | Resume::Step(s) => s,
        }
    }
}

/// The options the tracer set.
pub fn options() -> u64 {
    open(&mailbox_name(self_id()), false).map_or(0, |mb| mb.word(W_OPTIONS).load(Ordering::Acquire))
}

/// Stop for the tracer with wait status `status` and `siginfo` (128
/// bytes), the registers `regs` its to read and change, until it says to
/// go on: how. `syscall` is 1 at a system call's entry, 2 at its exit (for
/// `PTRACE_GET_SYSCALL_INFO`). Not traced, or the tracer gone: `Cont(0)`,
/// or the signal the stop was for.
pub fn stop(
    regs: &mut crate::Regs,
    tls: &mut u64,
    status: i32,
    siginfo: &[u8; 128],
    event: u64,
    syscall: u64,
) -> Resume {
    let sig = ((status >> 8) & 0x7f) as u64;
    let passing = if status >> 16 == 0 && sig != libc::SIGTRAP as u64 { sig } else { 0 };
    let Some(mb) = open(&mailbox_name(self_id()), false) else { return Resume::Cont(passing) };
    let tracer = tracer();
    if !alive(tracer) {
        end();
        return Resume::Cont(passing);
    }
    let (mut status, mut siginfo, mut event, mut syscall) = (status, *siginfo, event, syscall);
    loop {
        report(&mb, tracer, regs, *tls, status, &siginfo, event, syscall);
        let r = match serve(&mb, tracer, regs, tls, passing) {
            Served::Resume(r) => r,
            // Listened to, then continued or interrupted: it reports so.
            Served::Listened => {
                (status, siginfo, event, syscall) = trap_stop();
                continue;
            }
        };
        // An interrupt asked for while it was stopped: it stops again at
        // once.
        if mb.word(W_INTERRUPT).swap(0, Ordering::AcqRel) == 1 && traced() {
            (status, siginfo, event, syscall) = trap_stop();
            continue;
        }
        break r;
    }
}

/// The stop an interrupt makes, or the end of a group-stop a seized
/// tracee was listened to in: `PTRACE_EVENT_STOP` with SIGTRAP.
fn trap_stop() -> (i32, [u8; 128], u64, u64) {
    let trap = fwe_abi::signal::SIGTRAP;
    let info =
        crate::thread::SigInfo { code: trap as i32 | PTRACE_EVENT_STOP << 8, ..Default::default() };
    (stop_status(trap, PTRACE_EVENT_STOP), crate::signal::siginfo_bytes(trap, info), 0, 0)
}

/// Publish a stop in mailbox `mb` and tell `tracer`.
#[allow(clippy::too_many_arguments)]
fn report(
    mb: &Page,
    tracer: i32,
    regs: &crate::Regs,
    tls: u64,
    status: i32,
    siginfo: &[u8; 128],
    event: u64,
    syscall: u64,
) {
    put_regs(mb, regs);
    mb.word(W_TLS).store(tls, Ordering::Release);
    mb.put(SIGINFO_AT, siginfo);
    mb.word(W_EVENTMSG).store(event, Ordering::Release);
    mb.word(W_SYSCALL).store(syscall, Ordering::Release);
    mb.word(W_SIGMASK).store(crate::thread::mask(), Ordering::Release);
    mb.word(W_SIGMASK_SET).store(0, Ordering::Release);
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
}

/// How serving a stop ended.
enum Served {
    Resume(Resume),
    /// Listened to (`PTRACE_LISTEN`), then continued (`SIGCONT`) or
    /// interrupted.
    Listened,
}

/// Whether host signal `sig` is pending for this thread: a stop is served
/// with the host's signals blocked (in fwe's trap handler), so what comes
/// for it waits there.
fn host_pending(sig: libc::c_int) -> bool {
    // SAFETY: an empty set is a valid out-parameter; plain host calls.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut set) == 0 && libc::sigismember(&set, sig) == 1
    }
}

/// Whether a guest's `SIGKILL` waits for this process: its host form
/// ([`crate::host::KILL_RELAY`]) pending, or (where a handler took it, in
/// the VM backend) the guest signal. A stop ends for it, as Linux kills a
/// stopped tracee.
fn killed() -> bool {
    crate::thread::pending() & 1 << (fwe_abi::signal::SIGKILL - 1) != 0
        || host_pending(crate::host::KILL_RELAY)
}

/// Carry out the tracer's requests at a stop, until it says to go on.
fn serve(mb: &Page, tracer: i32, regs: &mut crate::Regs, tls: &mut u64, passing: u64) -> Served {
    loop {
        let req = mb.word(W_REQ).load(Ordering::Acquire);
        if req == mb.word(W_DONE).load(Ordering::Acquire) {
            if !alive(tracer) {
                end();
                break Served::Resume(Resume::Cont(passing));
            }
            if killed() {
                mb.word(W_STATE).store(RUNNING, Ordering::Release);
                break Served::Resume(Resume::Cont(0));
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
            OP_READ => {
                let mut b = vec![0u8; (data as usize).min(MEMBUF_LEN)];
                let n = read_some(addr, &mut b);
                mb.put(MEMBUF_AT, &b[..n]);
                if n == 0 && !b.is_empty() { -(errno::EIO as i64) } else { n as i64 }
            }
            OP_WRITE => {
                let n = (data as usize).min(MEMBUF_LEN);
                let b = mb.bytes(MEMBUF_AT, n.div_ceil(8) * 8);
                match crate::procmem::write_forced(addr, &b[..n]) {
                    Ok(()) => n as i64,
                    Err(e) => -(e as i64),
                }
            }
            OP_CONT | OP_DETACH => {
                resume = Some(Resume::Cont(data));
                0
            }
            OP_SYSCALL => {
                resume = Some(Resume::Syscall(data));
                0
            }
            OP_STEP => {
                resume = Some(Resume::Step(data));
                0
            }
            OP_LISTEN => {
                mb.word(W_STATE).store(LISTENING, Ordering::Release);
                mb.word(W_RESULT).store(0, Ordering::Release);
                mb.word(W_DONE).store(req, Ordering::Release);
                wake_word(mb.word(W_DONE));
                if listen(mb, tracer) {
                    if killed() {
                        mb.word(W_STATE).store(RUNNING, Ordering::Release);
                        return Served::Resume(Resume::Cont(0));
                    }
                    return Served::Listened;
                }
                end();
                return Served::Resume(Resume::Cont(0));
            }
            _ => -(errno::EIO as i64),
        };
        mb.word(W_RESULT).store(result as u64, Ordering::Release);
        if let Some(r) = resume {
            get_regs(mb, regs);
            *tls = mb.word(W_TLS).load(Ordering::Acquire);
            // A signal mask the tracer set (`PTRACE_SETSIGMASK`).
            if mb.word(W_SIGMASK_SET).swap(0, Ordering::AcqRel) == 1 {
                crate::thread::set_mask(mb.word(W_SIGMASK).load(Ordering::Acquire));
            }
            SYSCALLS.with(|t| t.set(matches!(r, Resume::Syscall(_))));
            mb.word(W_STATE).store(RUNNING, Ordering::Release);
            mb.word(W_DONE).store(req, Ordering::Release);
            wake_word(mb.word(W_DONE));
            if op == OP_DETACH {
                end();
            }
            // One instruction to run: the step's breakpoints (none where
            // the instruction cannot be read, which then faults and stops).
            if matches!(r, Resume::Step(_)) {
                arm_step(regs);
            }
            break Served::Resume(r);
        }
        mb.word(W_DONE).store(req, Ordering::Release);
        wake_word(mb.word(W_DONE));
    }
}

/// Stay stopped, listened to (`PTRACE_LISTEN`), until `SIGCONT` (or
/// `SIGKILL`) comes or the tracer interrupts: true then, false if the
/// tracer is gone. A `SIGCONT` is looked for among the host's pending
/// signals ([`host_pending`]), and delivered once the stop is over.
fn listen(mb: &Page, tracer: i32) -> bool {
    let cont = 1u64 << (fwe_abi::signal::SIGCONT - 1);
    loop {
        if mb.word(W_INTERRUPT).swap(0, Ordering::AcqRel) == 1
            || crate::thread::pending() & cont != 0
            || host_pending(libc::SIGCONT)
            || killed()
        {
            return true;
        }
        if !alive(tracer) {
            return false;
        }
        wait_word_for(mb.word(W_INTERRUPT), 0, Duration::from_millis(20));
    }
}

/// Read as much of `buf.len()` bytes at `addr` as is readable from the
/// start: how many.
fn read_some(addr: u64, buf: &mut [u8]) -> usize {
    if crate::procmem::read_forced(addr, buf).is_ok() {
        return buf.len();
    }
    // Up to the first page that cannot be read.
    let mut done = 0;
    while done < buf.len() {
        let at = addr + done as u64;
        let n = (4096 - (at % 4096) as usize).min(buf.len() - done);
        if crate::procmem::read_forced(at, &mut buf[done..done + n]).is_err() {
            break;
        }
        done += n;
    }
    done
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

// --- single-stepping ------------------------------------------------------------
//
// One instruction is run by planting a breakpoint of fwe's (`brk #0x4c59`)
// where it may go next and going on: a branch's target and the next
// instruction for a conditional one, the register's address for one
// through a register, the next instruction for any other. Taking that
// breakpoint puts the instructions back and stops (`TRAP_TRACE`).

/// `brk #0x4c59`.
const STEP_BRK: u32 = 0xd420_0000 | (0x4c59 << 5);
std::thread_local! {
    /// Where breakpoints of this thread's step are, and the instructions
    /// they replaced.
    static STEPS: std::cell::RefCell<Vec<(u64, [u8; 4])>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Where the instruction `insn` at `pc` may go next, with registers `x`.
pub fn next_pcs(insn: u32, pc: u64, x: &[u64; 31]) -> Vec<u64> {
    let sext = |v: u32, bits: u32| ((v as i64) << (64 - bits)) >> (64 - bits);
    let rel = |imm: u32, bits: u32| pc.wrapping_add((sext(imm, bits) * 4) as u64);
    let next = pc.wrapping_add(4);
    let reg = |n: u32| if n == 31 { 0 } else { x[n as usize] };
    // An address with its pointer authentication code taken off.
    let strip = |a: u64| a & 0x0000_ffff_ffff_ffff;
    if insn & 0x7c00_0000 == 0x1400_0000 {
        // B, BL
        vec![rel(insn & 0x03ff_ffff, 26)]
    } else if insn & 0xff00_0010 == 0x5400_0000 || insn & 0x7e00_0000 == 0x3400_0000 {
        // B.cond; CBZ, CBNZ
        vec![next, rel((insn >> 5) & 0x7ffff, 19)]
    } else if insn & 0x7e00_0000 == 0x3600_0000 {
        // TBZ, TBNZ
        vec![next, rel((insn >> 5) & 0x3fff, 14)]
    } else if insn & 0xfe00_0000 == 0xd600_0000 {
        // BR, BLR, RET and their authenticated forms.
        let opc = (insn >> 21) & 0xf;
        let rn = (insn >> 5) & 0x1f;
        match opc {
            // RETAA, RETAB: through x30, which they name by none.
            2 if rn == 31 => vec![strip(x[30])],
            0..=2 | 8 | 9 => vec![strip(reg(rn))],
            _ => vec![next],
        }
    } else {
        vec![next]
    }
}

/// Plant the breakpoints of one step from `regs`: whether it could.
fn arm_step(regs: &crate::Regs) -> bool {
    // A step left unfinished (another stop came first) is put back.
    for (at, orig) in STEPS.with(|s| std::mem::take(&mut *s.borrow_mut())) {
        let _ = crate::procmem::write_forced(at, &orig);
    }
    let mut b = [0u8; 4];
    if crate::procmem::read_forced(regs.pc, &mut b).is_err() {
        return false;
    }
    let insn = u32::from_le_bytes(b);
    let mut steps = Vec::new();
    for at in next_pcs(insn, regs.pc, &regs.x) {
        if steps.iter().any(|&(a, _)| a == at) {
            continue;
        }
        let mut orig = [0u8; 4];
        if crate::procmem::read_forced(at, &mut orig).is_err()
            || crate::procmem::write_forced(at, &STEP_BRK.to_le_bytes()).is_err()
        {
            continue;
        }
        steps.push((at, orig));
    }
    let planted = !steps.is_empty();
    STEPS.with(|s| *s.borrow_mut() = steps);
    planted
}

/// Whether a breakpoint at `pc` is a step's: if so, every one of the step
/// is taken out.
pub fn step_hit(pc: u64) -> bool {
    let steps = STEPS.with(|s| {
        let mut s = s.borrow_mut();
        if s.iter().any(|&(a, _)| a == pc) { std::mem::take(&mut *s) } else { Vec::new() }
    });
    for &(at, orig) in &steps {
        let _ = crate::procmem::write_forced(at, &orig);
    }
    !steps.is_empty()
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

/// Whether `name`, a file in fwe's private directory, is a mailbox or
/// inbox of a process that is gone (left when it was killed).
pub(crate) fn leftover(name: &[u8]) -> bool {
    let Some(name) = std::str::from_utf8(name).ok() else { return false };
    if let Some(tracer) = name.strip_prefix("ptrace-inbox-") {
        return tracer.parse().is_ok_and(|pid: i32| pid > 0 && !alive(pid));
    }
    let Some(id) = name.strip_prefix("ptrace-").and_then(|n| n.parse::<i32>().ok()) else {
        return false;
    };
    // A thread's mailbox is named by its tid: the process it says it is in.
    open(&mailbox_name(id), false).is_some_and(|mb| {
        let pid = proc_of(&mb);
        pid <= 0 || !alive(pid)
    })
}

// --- the tracer ----------------------------------------------------------------

/// The host process a tracee's mailbox says it is in.
fn proc_of(mb: &Page) -> i32 {
    mb.word(W_PROC).load(Ordering::Acquire) as i32
}

/// Tracee `pid`'s mailbox (a process's pid, or a thread's tid), if this
/// process traces it.
fn tracee(pid: i32) -> Result<Page, i32> {
    let mb = open(&mailbox_name(pid), false).ok_or(errno::ESRCH)?;
    if mb.word(W_TRACER).load(Ordering::Acquire) != me() as u64
        || mb.word(W_STATE).load(Ordering::Acquire) == EXITED
        || !alive(proc_of(&mb))
    {
        return Err(errno::ESRCH);
    }
    Ok(mb)
}

/// The tracee a tracer names by `pid` (a traced thread's tid, or a process's
/// pid as the guest names it), as its mailbox is named.
pub fn target_of(pid: i32) -> Option<i32> {
    if pid > 0 && open(&mailbox_name(pid), false).is_some() {
        return Some(pid);
    }
    crate::pidns::to_host(pid)
}

/// The host process tracee `id` is in.
pub fn process_of(id: i32) -> i32 {
    open(&mailbox_name(id), false).map_or(id, |mb| proc_of(&mb))
}

/// The tracee host process `pid`'s mailbox, if this process traces it and
/// it is stopped (`ESRCH` otherwise, as Linux's).
fn stopped(pid: i32) -> Result<Page, i32> {
    let mb = tracee(pid)?;
    if matches!(mb.word(W_STATE).load(Ordering::Acquire), RUNNING | LISTENING) {
        return Err(errno::ESRCH);
    }
    Ok(mb)
}

/// Whether this process traces `pid` (a tracee's id) and it is stopped.
pub fn traces_stopped(pid: i32) -> bool {
    stopped(pid).is_ok()
}

/// Copy between stopped tracee `pid`'s memory at `addr` and `buf` (into
/// it if `write`), a part at a time through its mailbox: the bytes moved
/// up to the first that cannot be (`EIO` if none).
pub fn tracee_memory(pid: i32, addr: u64, buf: &mut [u8], write: bool) -> Result<usize, i32> {
    let mb = stopped(pid)?;
    let mut done = 0;
    while done < buf.len() {
        let n = (buf.len() - done).min(MEMBUF_LEN);
        let at = addr.wrapping_add(done as u64);
        let r = if write {
            mb.put(MEMBUF_AT, &buf[done..done + n]);
            ask(&mb, pid, OP_WRITE, at, n as u64)
        } else {
            ask(&mb, pid, OP_READ, at, n as u64).inspect(|&got| {
                let got = got as usize;
                let b = mb.bytes(MEMBUF_AT, got.div_ceil(8) * 8);
                buf[done..done + got].copy_from_slice(&b[..got]);
            })
        };
        match r {
            Ok(got) if got as usize == n => done += n,
            Ok(got) => return Ok(done + got as usize),
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `PTRACE_SEIZE` of tracee `id` (of host process `proc`) with `options`:
/// traced without stopping it; its nudge sent by the caller.
fn seize(id: i32, proc: i32, options: u64) -> Result<(), i32> {
    attach_id(id, proc)?;
    let mb = open(&mailbox_name(id), false).ok_or(errno::ESRCH)?;
    mb.word(W_OPTIONS).store(options, Ordering::Release);
    mb.word(W_SEIZED).store(1, Ordering::Release);
    Ok(())
}

/// Whether tracee `pid` (traced by this process) was seized.
fn is_seized(mb: &Page) -> bool {
    mb.word(W_SEIZED).load(Ordering::Acquire) == 1
}

/// `PTRACE_INTERRUPT` of seized tracee `pid`: it stops as soon as it can
/// (once resumed, if stopped now; at once, if listened to). Whether it is
/// to be nudged (it runs).
pub fn interrupt(pid: i32) -> Result<bool, i32> {
    let mb = tracee(pid)?;
    if !is_seized(&mb) {
        return Err(errno::EIO);
    }
    mb.word(W_INTERRUPT).store(1, Ordering::Release);
    wake_word(mb.word(W_INTERRUPT));
    Ok(mb.word(W_STATE).load(Ordering::Acquire) == RUNNING)
}

/// `PTRACE_LISTEN` of seized tracee `pid`, in a group-stop: it stays
/// stopped, reporting again when continued or interrupted.
pub fn listen_to(pid: i32) -> Result<(), i32> {
    let mb = stopped(pid)?;
    let status = mb.word(W_STATUS).load(Ordering::Acquire) as i32;
    let sig = ((status >> 8) & 0xff) as u64;
    if !is_seized(&mb) || status >> 16 != PTRACE_EVENT_STOP || sig == fwe_abi::signal::SIGTRAP {
        return Err(errno::EIO);
    }
    ask(&mb, pid, OP_LISTEN, 0, 0).map(|_| ())
}

/// Stopped tracee `pid`'s signal mask.
pub fn sigmask(pid: i32) -> Result<u64, i32> {
    Ok(stopped(pid)?.word(W_SIGMASK).load(Ordering::Acquire))
}

/// Set stopped tracee `pid`'s signal mask (never SIGKILL or SIGSTOP), as
/// it goes on.
pub fn set_sigmask(pid: i32, mask: u64) -> Result<(), i32> {
    use fwe_abi::signal::{SIGKILL, SIGSTOP};
    let mb = stopped(pid)?;
    let mask = mask & !(1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1));
    mb.word(W_SIGMASK).store(mask, Ordering::Release);
    mb.word(W_SIGMASK_SET).store(1, Ordering::Release);
    Ok(())
}

/// Stopped tracee `pid`'s `struct ptrace_syscall_info`: the call it is
/// stopped at the entry (its number and arguments) or exit (its result)
/// of, or the stop's place only.
pub fn syscall_info(pid: i32) -> Result<Vec<u8>, i32> {
    let mb = stopped(pid)?;
    let r = mb.bytes(REGS_AT, PRSTATUS_SIZE);
    let reg = |i: usize| u64::from_le_bytes(r[i * 8..i * 8 + 8].try_into().unwrap());
    let op = mb.word(W_SYSCALL).load(Ordering::Acquire);
    let mut b = vec![op as u8, 0, 0, 0];
    b.extend_from_slice(&AUDIT_ARCH_AARCH64.to_le_bytes());
    b.extend_from_slice(&reg(32).to_le_bytes());
    b.extend_from_slice(&reg(31).to_le_bytes());
    match op {
        1 => {
            b.extend_from_slice(&reg(8).to_le_bytes());
            for i in 0..6 {
                b.extend_from_slice(&reg(i).to_le_bytes());
            }
        }
        2 => {
            let rval = reg(0) as i64;
            b.extend_from_slice(&rval.to_le_bytes());
            b.push(u8::from((-4095..0).contains(&rval)));
        }
        _ => {}
    }
    Ok(b)
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
        if !alive(proc_of(mb)) {
            return Err(errno::ESRCH);
        }
        let _ = pid;
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

/// A stop of a tracee `wanted` accepts (by host pid, or a thread's tid)
/// not yet reported: its id, wait status and whether it is a thread,
/// reported now unless `peek`.
pub fn take_stop(wanted: impl Fn(i32) -> bool, peek: bool) -> Option<(i32, i32, bool)> {
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
        let state = mb.word(W_STATE).load(Ordering::Acquire);
        let thread = proc_of(&mb) != pid;
        if state == EXITED {
            let status = mb.word(W_STATUS).load(Ordering::Acquire) as i32;
            if !peek {
                drop(mb);
                if let Some(c) = path(&mailbox_name(pid)) {
                    // SAFETY: a NUL-terminated path of fwe's.
                    unsafe { libc::unlink(c.as_ptr()) };
                }
                let _ = slot.compare_exchange(pid as u64, 0, Ordering::AcqRel, Ordering::Acquire);
            }
            return Some((pid, status, thread));
        }
        if state == STOPPED {
            if !peek {
                mb.word(W_STATE).store(REPORTED, Ordering::Release);
            }
            return Some((pid, mb.word(W_STATUS).load(Ordering::Acquire) as i32, thread));
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
        PTRACE_SINGLESTEP => OP_STEP,
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
        NT_ARM_SYSTEM_CALL => Ok(mb.bytes(REGS_AT + 8 * 8, 8)[..4].to_vec()),
        NT_ARM_TLS => Ok(mb.word(W_TLS).load(Ordering::Acquire).to_le_bytes().to_vec()),
        NT_ARM_HW_BREAK | NT_ARM_HW_WATCH => Ok(vec![0; 8]),
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
        // `x8`, from the number's 32 bits, sign-extended.
        NT_ARM_SYSTEM_CALL => {
            let n = i32::from_le_bytes(data.get(..4).ok_or(errno::EINVAL)?.try_into().unwrap());
            mb.put(REGS_AT + 8 * 8, &(n as i64 as u64).to_le_bytes());
            return Ok(());
        }
        NT_ARM_TLS => {
            let tp = u64::from_le_bytes(data.get(..8).ok_or(errno::EINVAL)?.try_into().unwrap());
            mb.word(W_TLS).store(tp, Ordering::Release);
            return Ok(());
        }
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
    // (The process's main thread's mailbox.)
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
    attach_id(pid, pid)
}

/// [`attach`] of tracee `id` (a thread's tid, or a process's pid) of host
/// process `proc`.
fn attach_id(pid: i32, proc: i32) -> Result<(), i32> {
    if is_traced(pid) {
        return Err(errno::EPERM);
    }
    let mb = open(&mailbox_name(pid), true).ok_or(errno::ENOMEM)?;
    for w in FRESH {
        mb.word(w).store(0, Ordering::Release);
    }
    mb.word(W_TRACER).store(me() as u64, Ordering::Release);
    mb.word(W_PROC).store(proc as u64, Ordering::Release);
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

/// Whether taking `sig` begins this thread's tracing: a SIGSTOP a tracer
/// sent as it attached, or any signal once seized (its mailbox names a
/// live tracer).
pub fn attached(sig: u64) -> bool {
    if traced() {
        return false;
    }
    if sig != fwe_abi::signal::SIGSTOP {
        return begin_seized();
    }
    let Some(mb) = open(&mailbox_name(self_id()), false) else { return false };
    let tracer = mb.word(W_TRACER).load(Ordering::Acquire) as i32;
    if tracer <= 0 || !alive(tracer) {
        return false;
    }
    if mb.word(W_STATE).load(Ordering::Acquire) == EXITED {
        return false;
    }
    mb.word(W_PROC).store(me() as u64, Ordering::Release);
    TRACER.with(|t| t.set(tracer));
    SYSCALLS.with(|t| t.set(false));
    set_traced(true);
    true
}

/// A thread seized (`PTRACE_SEIZE`) but not yet traced is traced from now
/// on: whether it was.
fn begin_seized() -> bool {
    let Some(mb) = open(&mailbox_name(self_id()), false) else { return false };
    let tracer = mb.word(W_TRACER).load(Ordering::Acquire) as i32;
    if mb.word(W_SEIZED).load(Ordering::Acquire) != 1
        || tracer <= 0
        || !alive(tracer)
        || mb.word(W_STATE).load(Ordering::Acquire) == EXITED
    {
        return false;
    }
    mb.word(W_PROC).store(me() as u64, Ordering::Release);
    TRACER.with(|t| t.set(tracer));
    SYSCALLS.with(|t| t.set(false));
    set_traced(true);
    true
}

impl<P: crate::Platform> crate::Kernel<P> {
    /// Every signal caught on the host while traced, and as before after.
    fn resync_for_tracing(&mut self) {
        for sig in 1..=fwe_abi::signal::NSIG {
            self.sync_host_signal(sig);
        }
    }

    /// [`stop`], with the calling thread's thread pointer, which the tracer
    /// may read and change; the host's signal dispositions set again where
    /// a thread began or ended being traced (the host catches every signal
    /// while one is).
    fn stop_with_tls(
        &mut self,
        regs: &mut crate::Regs,
        status: i32,
        siginfo: &[u8; 128],
        event: u64,
        syscall: u64,
    ) -> Resume {
        if RESYNC.swap(false, Ordering::AcqRel) {
            self.resync_for_tracing();
        }
        let mut tls = self.platform.thread_pointer();
        let before = tls;
        let r = stop(regs, &mut tls, status, siginfo, event, syscall);
        if tls != before {
            self.platform.set_thread_pointer(tls);
        }
        if RESYNC.swap(false, Ordering::AcqRel) {
            self.resync_for_tracing();
        }
        r
    }

    /// A signal-delivery stop for `sig` raised with `info`: the signal to
    /// deliver after it, as the tracer chose (`None`: none).
    pub(crate) fn ptrace_signal_stop(
        &mut self,
        regs: &mut crate::Regs,
        sig: u64,
        info: crate::thread::SigInfo,
    ) -> Option<(u64, crate::thread::SigInfo)> {
        let si = crate::signal::siginfo_bytes(sig, info);
        let r = self.stop_with_tls(regs, stop_status(sig, 0), &si, 0, 0);
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
    /// or the exec event (`PTRACE_O_TRACEEXEC`); a seized one stops only
    /// for the event.
    pub fn ptrace_exec_stop(&mut self, regs: &mut crate::Regs) {
        if !traced() {
            return;
        }
        self.resync_for_tracing();
        let trap = fwe_abi::signal::SIGTRAP;
        let event = if options() & PTRACE_O_TRACEEXEC != 0 { PTRACE_EVENT_EXEC } else { 0 };
        let legacy_trap = event == 0 && !seized();
        let info = crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
        let si = crate::signal::siginfo_bytes(trap, info);
        let msg = crate::thread::tgid() as u64;
        // The exec event comes before the call's exit stop; the SIGTRAP of
        // a tracee without it, a signal, after.
        if event != 0 {
            let r = self.stop_with_tls(regs, stop_status(trap, event), &si, msg, 0);
            if r.signal() != 0 {
                crate::thread::post_process(r.signal(), info);
            }
        }
        if stops_at_syscalls() {
            regs.x[0] = 0;
            self.ptrace_syscall_stop(regs, false);
        }
        if legacy_trap {
            let r = self.stop_with_tls(regs, stop_status(trap, 0), &si, msg, 0);
            if r.signal() != 0 {
                crate::thread::post_process(r.signal(), info);
            }
        }
    }

    /// An event's stop (`event`, `PTRACE_EVENT_*`), with message `msg`
    /// (what `PTRACE_GETEVENTMSG` gives: a new child's pid, an exit
    /// status).
    pub fn ptrace_event_stop(&mut self, regs: &mut crate::Regs, event: i32, msg: u64) {
        if !traced() {
            return;
        }
        let trap = fwe_abi::signal::SIGTRAP;
        let info = crate::thread::SigInfo { code: trap as i32 | event << 8, ..Default::default() };
        let si = crate::signal::siginfo_bytes(trap, info);
        let r = self.stop_with_tls(regs, stop_status(trap, event), &si, msg, 0);
        if r.signal() != 0 {
            let info =
                crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
            crate::thread::post_process(r.signal(), info);
        }
    }

    /// fwe's nudge ([`POKE_CODE`]) taken: a seized thread is traced from
    /// now on, and stops if its tracer asked it to (`PTRACE_INTERRUPT`, or
    /// as it first starts), with `PTRACE_EVENT_STOP` and SIGTRAP.
    pub fn ptrace_poked(&mut self, regs: &mut crate::Regs) {
        if !traced() && !begin_seized() {
            return;
        }
        let Some(mb) = open(&mailbox_name(self_id()), false) else { return };
        if mb.word(W_INTERRUPT).swap(0, Ordering::AcqRel) != 1 {
            return;
        }
        drop(mb);
        let (status, si, _, _) = trap_stop();
        let r = self.stop_with_tls(regs, status, &si, 0, 0);
        if r.signal() != 0 {
            let info =
                crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
            crate::thread::post_process(r.signal(), info);
        }
    }

    /// A stop signal `sig` (with `info`) whose default action stops a
    /// seized thread: a group-stop, which its tracer sees as
    /// `PTRACE_EVENT_STOP` with the signal, and which ends as the tracer
    /// says (or, listened to, at `SIGCONT`).
    pub fn ptrace_group_stop(
        &mut self,
        regs: &mut crate::Regs,
        sig: u64,
        info: crate::thread::SigInfo,
    ) {
        let si = crate::signal::siginfo_bytes(sig, info);
        let r = self.stop_with_tls(regs, stop_status(sig, PTRACE_EVENT_STOP), &si, 0, 0);
        if r.signal() != 0 {
            let info =
                crate::thread::SigInfo { code: fwe_abi::signal::SI_USER, ..Default::default() };
            crate::thread::post_process(r.signal(), info);
        }
    }

    /// The exit event's stop (`PTRACE_O_TRACEEXIT`), as the process ends
    /// with wait status `status`.
    pub fn ptrace_exit_stop(&mut self, status: i32) {
        if traced() && options() & PTRACE_O_TRACEEXIT != 0 {
            let mut regs = crate::Regs::default();
            self.ptrace_event_stop(&mut regs, PTRACE_EVENT_EXIT, status as u32 as u64);
        }
    }

    /// The stops of a fork a backend noted ([`note_fork`]): the parent's
    /// event, and for a vfork the vfork-done event.
    pub fn ptrace_fork_stops(&mut self, regs: &mut crate::Regs) {
        if let Some((event, flags, child)) = take_noted_fork() {
            self.ptrace_event_stop(regs, event, child);
            if flags & fwe_abi::clone::CLONE_VFORK != 0 {
                self.ptrace_vfork_done(regs, child);
            }
        }
    }

    /// The vfork-done event's stop (`PTRACE_O_TRACEVFORKDONE`), the
    /// child `child` having let its parent go on.
    pub fn ptrace_vfork_done(&mut self, regs: &mut crate::Regs, child: u64) {
        if traced() && options() & PTRACE_O_TRACEVFORKDONE != 0 {
            self.ptrace_event_stop(regs, PTRACE_EVENT_VFORK_DONE, child);
        }
    }

    /// A system call's entry stop (`entry`) or exit stop (`PTRACE_SYSCALL`).
    pub fn ptrace_syscall_stop(&mut self, regs: &mut crate::Regs, entry: bool) {
        if !stops_at_syscalls() {
            return;
        }
        let good = options() & PTRACE_O_TRACESYSGOOD != 0;
        let trap = fwe_abi::signal::SIGTRAP | if good { 0x80 } else { 0 };
        let info =
            crate::thread::SigInfo { code: fwe_abi::signal::SIGTRAP as i32, ..Default::default() };
        let si = crate::signal::siginfo_bytes(fwe_abi::signal::SIGTRAP, info);
        let r = self.stop_with_tls(regs, stop_status(trap, 0), &si, 0, if entry { 1 } else { 2 });
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
    pub(crate) fn may_trace(&self, target: i32) -> bool {
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
        // Seizing takes its options, and nothing at `addr`.
        if request == PTRACE_SEIZE && (addr != 0 || data & !KNOWN_OPTIONS != 0) {
            return err(errno::EIO);
        }
        // A thread of another process, attached to on its own: fwe's
        // SIGSTOP for it, through its process's queue (seized: the nudge).
        if matches!(request, PTRACE_ATTACH | PTRACE_SEIZE)
            && let Some(owner) = crate::thread::owner_of_tid(pid as i32)
        {
            if owner == me() || !self.may_trace(owner) {
                return err(errno::EPERM);
            }
            let (r, code) = if request == PTRACE_SEIZE {
                (seize(pid as i32, owner, data), POKE_CODE)
            } else {
                (attach_id(pid as i32, owner), 0)
            };
            if let Err(e) = r {
                return err(e);
            }
            let stop = fwe_abi::signal::SIGSTOP;
            return match crate::signote::queue_thread(owner, pid as i32, stop, code, 0) {
                Ok(()) => crate::host::kill_process(owner, crate::host::WAKE_SIGNAL),
                Err(e) => err(e),
            };
        }
        let Some(target) = target_of(pid as i32).filter(|&t| alive(process_of(t))) else {
            return err(errno::ESRCH);
        };
        if matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
            if target == me() || crate::thread::host_thread(pid as i32).is_some() {
                return err(errno::EPERM);
            }
            if !self.may_trace(target) || crate::procreg::read(target).is_none() {
                return err(errno::EPERM);
            }
            let (r, code) = if request == PTRACE_SEIZE {
                (seize(target, target, data), POKE_CODE)
            } else {
                (attach(target), fwe_abi::signal::SI_USER)
            };
            if let Err(e) = r {
                return err(e);
            }
            return crate::signal::send_unhosted(target, fwe_abi::signal::SIGSTOP, code, 0);
        }
        if request == PTRACE_INTERRUPT {
            return match interrupt(target) {
                Ok(true) => self.nudge(target),
                Ok(false) => 0,
                Err(e) => err(e),
            };
        }
        if request == PTRACE_KILL {
            if !traces(target) {
                return err(errno::ESRCH);
            }
            crate::host::kill_process(process_of(target), libc::SIGKILL);
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
            PTRACE_CONT | PTRACE_SYSCALL | PTRACE_DETACH | PTRACE_SINGLESTEP => {
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
            PTRACE_LISTEN => listen_to(target).map(|()| 0),
            PTRACE_GETSIGMASK | PTRACE_SETSIGMASK if addr != 8 => Err(errno::EINVAL),
            PTRACE_GETSIGMASK => {
                uaccess::write(data, sigmask(target)?)?;
                Ok(0)
            }
            PTRACE_SETSIGMASK => set_sigmask(target, uaccess::read(data)?).map(|()| 0),
            PTRACE_GET_SYSCALL_INFO => {
                let info = syscall_info(target)?;
                let n = info.len().min(addr as usize);
                uaccess::write_from(data, &info[..n])?;
                Ok(info.len() as i64)
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

impl<P: crate::Platform> crate::Kernel<P> {
    /// fwe's nudge ([`POKE_CODE`]) to tracee `id`: a thread through its
    /// process's queue, a process through its own.
    fn nudge(&self, id: i32) -> i64 {
        let proc = process_of(id);
        let stop = fwe_abi::signal::SIGSTOP;
        if proc != id {
            return match crate::signote::queue_thread(proc, id, stop, POKE_CODE, 0) {
                Ok(()) => crate::host::kill_process(proc, crate::host::WAKE_SIGNAL),
                Err(e) => fwe_abi::err(e),
            };
        }
        crate::signal::send_unhosted(id, stop, POKE_CODE, 0)
    }
}

/// The `siginfo` this process's tracer left in its mailbox.
fn get_own_siginfo() -> Option<[u8; 128]> {
    let mb = open(&mailbox_name(self_id()), false)?;
    mb.bytes(SIGINFO_AT, 128).try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gone_process_leaves_its_mailboxes_to_be_collected() {
        use std::os::unix::ffi::OsStrExt;
        // A process that has ended (and been reaped).
        let child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let gone = child.id() as i32;
        let mut child = child;
        child.wait().unwrap();
        assert!(leftover(format!("ptrace-inbox-{gone}").as_bytes()));
        assert!(!leftover(format!("ptrace-inbox-{}", me()).as_bytes()));
        // A thread's mailbox, by the process it says it is in.
        let id = 0x7ff0_0000 + (me() & 0xffff);
        let mb = open(&mailbox_name(id), true).unwrap();
        mb.word(W_PROC).store(me() as u64, Ordering::Release);
        assert!(!leftover(&mailbox_name(id).as_bytes()[1..]));
        mb.word(W_PROC).store(gone as u64, Ordering::Release);
        assert!(leftover(&mailbox_name(id).as_bytes()[1..]));
        let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(
            path(&mailbox_name(id)).unwrap().to_bytes(),
        ));
        assert!(!leftover(b"ptrace-x"));
    }

    #[test]
    fn a_step_follows_every_kind_of_branch() {
        let mut x = [0u64; 31];
        x[3] = 0x9000;
        x[30] = 0x7000;
        let pc = 0x1000;
        // b .+8; bl .-4
        assert_eq!(next_pcs(0x1400_0002, pc, &x), vec![0x1008]);
        assert_eq!(next_pcs(0x97ff_ffff, pc, &x), vec![0xffc]);
        // b.eq .+16; cbz x0, .+8; tbnz w1, #3, .-8
        assert_eq!(next_pcs(0x5400_0080, pc, &x), vec![0x1004, 0x1010]);
        assert_eq!(next_pcs(0xb400_0040, pc, &x), vec![0x1004, 0x1008]);
        assert_eq!(next_pcs(0x371f_ffc1, pc, &x), vec![0x1004, 0xff8]);
        // br x3; ret; retaa (x30, its code taken off); an add
        assert_eq!(next_pcs(0xd61f_0060, pc, &x), vec![0x9000]);
        assert_eq!(next_pcs(0xd65f_03c0, pc, &x), vec![0x7000]);
        x[30] = 0x0012_0000_0000_7000;
        assert_eq!(next_pcs(0xd65f_0bff, pc, &x), vec![0x7000]);
        assert_eq!(next_pcs(0x9100_0400, pc, &x), vec![0x1004]);
    }

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
