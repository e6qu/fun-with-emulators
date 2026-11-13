//! Guest entry and trap handling on macOS arm64.
//!
//! Guest code runs on the host thread that entered it. Rewritten system calls
//! call the gate ([`crate::gate`]), whose Rust half ([`fwe_gate_call`]) runs
//! the plain ones; the rest, and those rewritten as a `brk` where no stub
//! fits, raise `SIGTRAP`: the handler runs on its own signal stack, executes
//! the Linux system call against the guest's saved registers and returns,
//! which resumes the guest after the call with `x0` holding the result.
//!
//! Signals for the guest arrive as host signals too (see
//! `fwe_kernel::signal`): [`on_async`] records each one pending for the
//! guest, and when it interrupted guest code it delivers it at once by
//! rewriting the interrupted context, as a Linux kernel would on the way
//! back to user space. Each guest thread runs under the host signal mask its
//! guest mask calls for ([`fwe_kernel::host::host_mask_for`]): the signals
//! fwe catches are never blocked on the host, and one that lands on a
//! thread whose guest mask blocks it is recorded against the process
//! ([`fwe_kernel::thread::post_landed`]).
//!
//! Every handler here runs with all signals blocked on entry and exit, so
//! [`IN_GUEST`], with the gate's own state ([`guest_interrupted`]), reliably
//! tells whether an interrupted context is guest code;
//! in between it unblocks the guest's mask, so a blocking host call made for
//! the guest is interrupted (`EINTR`) by a signal the guest takes.

use crate::rewrite::TRAP;
use crate::{KERNEL, NativePlatform, X18Abi};
use fwe_kernel::{FpRegs, Kernel, Regs, host, thread};
use std::cell::Cell;
use std::sync::MutexGuard;

/// `__darwin_arm_thread_state64`.
#[repr(C)]
pub struct ThreadState {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
}

/// `__darwin_arm_exception_state64`.
#[repr(C)]
pub struct ExceptionState {
    pub far: u64,
    pub esr: u32,
    pub exception: u32,
}

/// `__darwin_arm_neon_state64`.
#[repr(C, align(16))]
pub struct NeonState {
    pub v: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

/// `__darwin_mcontext64`.
#[repr(C)]
pub struct Mcontext {
    pub es: ExceptionState,
    pub ss: ThreadState,
    pub ns: NeonState,
}

/// `__darwin_ucontext`.
#[repr(C)]
pub struct Ucontext {
    pub uc_onstack: libc::c_int,
    pub uc_sigmask: u32,
    pub uc_stack: libc::stack_t,
    pub uc_link: *mut Ucontext,
    pub uc_mcsize: usize,
    pub uc_mcontext: *mut Mcontext,
}

const SIGNAL_STACK_SIZE: usize = 1 << 20;

fn kernel() -> MutexGuard<'static, Option<Kernel<NativePlatform>>> {
    KERNEL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write a diagnostic directly to the host's standard error.
fn report(message: &str) {
    // SAFETY: `message` is a valid buffer of its length.
    unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
}

/// Read an instruction word, if `addr` is the address of one.
///
/// # Safety
/// `addr` must be mapped if it is 4-byte aligned.
unsafe fn insn(addr: u64) -> Option<u32> {
    // SAFETY: guaranteed by the caller.
    (addr % 4 == 0).then(|| unsafe { (addr as *const u32).read() })
}

thread_local! {
    /// Whether this thread is executing guest code (as opposed to fwe's own
    /// code, including the handlers here).
    static IN_GUEST: Cell<bool> = const { Cell::new(false) };
    /// [`reroute_parked`] is taking a signal parked on this thread: record
    /// it against the process rather than the thread.
    static REROUTING: Cell<bool> = const { Cell::new(false) };
}

/// Whether the host delivers `sig` to [`on_async`] (the guest catches it).
fn caught(sig: libc::c_int) -> bool {
    // SAFETY: zeroed bytes are a valid `sigaction`; this only reads it.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out parameter; no change is made.
    unsafe { libc::sigaction(sig, std::ptr::null(), &mut act) };
    act.sa_sigaction == on_async as *const () as usize
}

/// Hand signals the host parked on this thread back to the whole process.
///
/// Linux keeps a process-wide signal that every thread blocks pending for
/// the process, and the first thread to unblock it takes it. macOS instead
/// parks it on one thread for good, so a signal sent while every thread
/// blocked it for a moment (each does while it is in fwe's handlers) could
/// stay pending on a thread that never unblocks it while another thread
/// accepts it. At a system call, a caught signal pending on the host that
/// this thread's guest mask blocks may be such a signal: unblocking it
/// here, in fwe's code, has the host deliver it to [`take_async`] now,
/// which records it against the process (where Linux keeps it), and the
/// other threads are woken to take it. A signal with the default action
/// or ignored stays where it is: unblocking it would apply that action to
/// a signal Linux keeps pending.
fn reroute_parked() {
    let blocked = thread::mask();
    if blocked == 0 {
        return;
    }
    let parked = host::pending_signals() & blocked;
    if parked == 0 {
        return;
    }
    let parked = (1..=fwe_abi::signal::NSIG)
        .filter(|&sig| parked & (1 << (sig - 1)) != 0)
        .filter(|&sig| host::signal_to_host(sig).is_some_and(caught))
        .fold(0u64, |m, sig| m | 1 << (sig - 1));
    if parked == 0 {
        return;
    }
    let set = host::host_sigset(parked);
    REROUTING.set(true);
    // SAFETY: `set` is an initialized signal set; the pending signals are
    // delivered to this thread between the two calls.
    unsafe {
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    REROUTING.set(false);
    thread::wake_others(host::WAKE_SIGNAL);
}

/// Block every signal the guest can receive on this thread.
fn block_async_signals() {
    let mut all = host::host_sigset(u64::MAX);
    // SAFETY: `all` is an initialized signal set.
    unsafe {
        libc::sigaddset(&mut all, host::WAKE_SIGNAL);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
    UNBLOCKED.with(|u| u.set(false));
}

/// [`block_async_signals`], in a handler's host code: only if
/// [`HostCode`] unblocked them (the handler was entered with them blocked).
fn reblock() {
    if UNBLOCKED.with(Cell::get) {
        block_async_signals();
    }
}

/// Run under the host mask this thread's guest mask calls for.
fn apply_guest_mask() {
    let mask = host::host_mask_for(thread::mask());
    // SAFETY: `mask` is an initialized signal set.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) };
    UNBLOCKED.with(|u| u.set(true));
}

thread_local! {
    /// Whether a handler's host code runs with the guest's signals
    /// unblocked ([`HostCode`]).
    static UNBLOCKED: Cell<bool> = const { Cell::new(false) };
}

/// Whether system call `nr` neither waits nor touches guest memory,
/// whatever its arguments: it runs with signals still blocked as the
/// handler was entered, saving two host calls. A signal that arrives
/// meanwhile is delivered as the handler returns, before the guest's next
/// instruction, as Linux delivers it on the way back from the call. (A
/// fault in guest memory needs `SIGSEGV` unblocked, to be recovered; so
/// does the tracer, which reads arguments.)
fn never_waits(nr: u64) -> bool {
    use fwe_abi::nr::*;
    !TRACING.load(std::sync::atomic::Ordering::Relaxed)
        && matches!(
            nr,
            GETPID
                | GETPPID
                | GETTID
                | GETUID
                | GETEUID
                | GETGID
                | GETEGID
                | GETPGID
                | GETSID
                | BRK
                | MMAP
                | MUNMAP
                | MPROTECT
                | MADVISE
                | SET_TID_ADDRESS
                | UMASK
                | LSEEK
                | SCHED_YIELD
        )
}

/// Whether the run traces its system calls (`--strace`).
static TRACING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Note whether the run traces its system calls.
pub fn set_tracing(on: bool) {
    TRACING.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Make the guest's current mask the one the host restores when the handler
/// owning `ctx` returns to guest code.
///
/// # Safety
/// `ctx` is the ucontext passed to the running handler.
unsafe fn return_with_guest_mask(ctx: *mut libc::c_void) {
    let mask = host::host_mask_for(thread::mask());
    // SAFETY: guaranteed by the caller; macOS's sigset_t is a u32.
    unsafe { (*(ctx as *mut Ucontext)).uc_sigmask = mask };
}

/// Fwe's own code is running on this thread for the life of the value: it
/// leaves the custom x18 ABI, so host code may call macOS libraries, and
/// unblocks the guest's signals so a blocking host call is interruptible. On
/// drop it blocks signals again and restores both. The guest's x18 is part
/// of the saved signal context and is restored when the handler returns.
struct HostCode {
    was_in_guest: bool,
}

impl HostCode {
    fn enter() -> HostCode {
        let h = HostCode::enter_blocked();
        apply_guest_mask();
        h
    }

    /// [`HostCode::enter`] leaving signals blocked, for host code that does
    /// not wait ([`never_waits`]).
    fn enter_blocked() -> HostCode {
        let was_in_guest = IN_GUEST.with(|g| g.replace(false));
        crate::quiesce::leave();
        // Handlers are entered with every signal blocked.
        UNBLOCKED.with(|u| u.set(false));
        HostCode { was_in_guest }
    }
}

impl Drop for HostCode {
    fn drop(&mut self) {
        reblock();
        IN_GUEST.with(|g| g.set(self.was_in_guest));
        if self.was_in_guest {
            // Back to guest code, unless a fork is copying memory.
            crate::quiesce::enter();
        }
    }
}

/// Prepare this thread to jump into guest code (a new program, a forked
/// child, a new thread): it runs guest code from here, under its guest
/// mask.
pub fn prepare_guest_entry() {
    crate::gate::ensure_block();
    block_async_signals();
    IN_GUEST.with(|g| g.set(true));
    crate::quiesce::register();
    crate::quiesce::enter();
    apply_guest_mask();
}

/// Whether the signal whose context is `ctx` interrupted guest code: not
/// fwe's, which the gate is too, from its first instruction to its last
/// ([`crate::gate`]).
fn guest_interrupted(ctx: *mut libc::c_void) -> bool {
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let pc = unsafe { (*(*(ctx as *mut Ucontext)).uc_mcontext).ss.pc };
    IN_GUEST.with(Cell::get) && !crate::gate::in_gate(pc) && !crate::gate::active()
}

/// The Rust half of the system-call gate ([`crate::gate`]): run the call
/// in `b`, if it is a plain one. 0: it ran and changed nothing but `x0`,
/// and nothing is to be delivered (the gate returns to the guest); 1: the
/// trap is to finish it (`b.ran` says whether it ran).
#[unsafe(no_mangle)]
extern "C" fn fwe_gate_call(b: *mut crate::gate::Block) -> u64 {
    use fwe_abi::nr::*;
    use std::sync::atomic::Ordering::SeqCst;
    // SAFETY: the gate passes this thread's block, which only it uses now.
    let b = unsafe { &mut *b };
    IN_GUEST.with(|g| g.set(false));
    crate::quiesce::leave();
    let site = crate::gate::site_of(b.ret);
    b.regs.pc = site;
    b.regs.x[18] = guest_x18();
    b.ran = 0;
    let nr = b.regs.x[8];
    // What the trap runs its own way, or stops at, it runs.
    let plain = !TRACING.load(SeqCst)
        && fwe_kernel::seccomp::mode() == 0
        && !fwe_kernel::ptrace::stops_at_syscalls()
        && !matches!(
            nr,
            EXIT | EXECVE
                | EXECVEAT
                | CLONE
                | CLONE3
                | WAIT4
                | WAITID
                | PIDFD_GETFD
                | RT_SIGTIMEDWAIT
        )
        && !fwe_kernel::ipcops::waits(nr);
    if !plain {
        IN_GUEST.with(|g| g.set(true));
        return 1;
    }
    reroute_parked();
    let mask = thread::mask();
    let before = b.regs;
    let regs = &mut b.regs;
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    // SAFETY: guest pointers in `args` reference guest memory.
    if let Some(r) = unsafe { fwe_kernel::blocking_syscall(nr, args) } {
        kernel().as_mut().unwrap().finish_syscall(regs, nr, &args, r);
    } else {
        kernel().as_mut().unwrap().enter_syscall(regs);
    }
    b.ran = 1;
    // A signal from here on is seen by the gate's way out.
    b.seen = b.signals.load(SeqCst);
    let regs = &b.regs;
    let plain_return = regs.pc == site + 4
        && regs.sp == before.sp
        && regs.x[1..] == before.x[1..]
        && regs.pstate == before.pstate
        && regs.fp == before.fp
        && thread::mask() == mask
        && thread::deliverable() == 0;
    if plain_return {
        crate::quiesce::enter();
    }
    IN_GUEST.with(|g| g.set(true));
    u64::from(!plain_return)
}

/// The TSD key of the guest `x18` slot (see [`crate::x18_slot`]).
fn x18_key() -> libc::pthread_key_t {
    (crate::x18_slot() / 8) as libc::pthread_key_t
}

/// The calling thread's guest `x18`. Rewritten guest code keeps `x18` in a
/// per-thread slot rather than the hardware register (which macOS clears), so
/// the slot, not the saved register, is the guest's value.
pub fn guest_x18() -> u64 {
    // SAFETY: reading this thread's value for a key fwe created.
    unsafe { libc::pthread_getspecific(x18_key()) as u64 }
}

/// Set the calling thread's guest `x18`.
pub fn set_guest_x18(value: u64) {
    // SAFETY: setting this thread's value for a key fwe created.
    unsafe { libc::pthread_setspecific(x18_key(), value as *const libc::c_void) };
}

/// Read the backend thread state into the kernel's register view.
fn regs_from(mc: &Mcontext) -> Regs {
    let ss = &mc.ss;
    let mut regs = Regs { sp: ss.sp, pc: ss.pc, pstate: ss.cpsr as u64, ..Regs::default() };
    regs.x[..29].copy_from_slice(&ss.x);
    regs.x[18] = guest_x18();
    regs.x[29] = ss.fp;
    regs.x[30] = ss.lr;
    regs.fp = FpRegs { v: mc.ns.v, fpsr: mc.ns.fpsr, fpcr: mc.ns.fpcr };
    regs
}

/// Write the kernel's register view back into the backend thread state.
fn regs_to(mc: &mut Mcontext, regs: &Regs) {
    let ss = &mut mc.ss;
    ss.x.copy_from_slice(&regs.x[..29]);
    set_guest_x18(regs.x[18]);
    ss.fp = regs.x[29];
    ss.lr = regs.x[30];
    ss.sp = regs.sp;
    ss.pc = regs.pc;
    ss.cpsr = regs.pstate as u32;
    mc.ns.v = regs.fp.v;
    mc.ns.fpsr = regs.fp.fpsr;
    mc.ns.fpcr = regs.fp.fpcr;
}

/// Whether `word` is a `brk` instruction (any immediate).
fn is_brk(word: u32) -> bool {
    word & 0xffe0_001f == 0xd420_0000
}

/// Deliver what became pending while a handler ran, just before it returns
/// to guest code. A signal can arrive after the handler's own delivery and
/// before it blocks signals to return; recorded but not delivered, it would
/// otherwise wait for the thread's next system call.
fn settle(regs: &mut Regs) {
    reblock();
    if thread::deliverable() != 0 {
        if let Some(k) = kernel().as_mut() {
            k.deliver_pending(regs);
        }
    }
}

extern "C" fn on_sigtrap(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let in_guest = IN_GUEST.with(Cell::get);
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let pc = unsafe { (*(*(ctx as *mut Ucontext)).uc_mcontext).ss.pc };
    // macOS's siginfo does not tell a trap from a sent SIGTRAP (both have
    // code 0), so look at the instruction: anything but a `brk` means the
    // signal was sent by another process, a signal for the guest.
    // SAFETY: the thread was executing at `pc`, so it is mapped.
    if !unsafe { insn(pc) }.is_some_and(is_brk) {
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        take_async(sig, || unsafe { host::signal_info(sig, info) }, ctx, guest_interrupted(ctx));
        return;
    }
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    // The gate's trap: the guest's state is in this thread's block.
    // SAFETY: the thread was executing at `pc`, so it is mapped.
    let from_gate = crate::gate::in_gate(pc) && unsafe { insn(pc) } == Some(crate::gate::GATE_TRAP);
    if from_gate {
        let b = crate::gate::block().expect("the gate's thread has a block");
        let mut regs = b.regs;
        let ran = b.ran != 0;
        b.active.store(0, std::sync::atomic::Ordering::SeqCst);
        if ran {
            // The call ran: what is pending is delivered, and the guest
            // goes on where the call left it.
            let _host = HostCode::enter_blocked();
            settle(&mut regs);
            regs_to(mc, &regs);
            // SAFETY: `ctx` is this handler's ucontext.
            unsafe { return_with_guest_mask(ctx) };
            return;
        }
        // As if the guest had trapped at its system call.
        regs_to(mc, &regs);
    }
    syscall_trap(ctx, in_guest, from_gate);
}

/// The guest at a system call, its state in `ctx` with `pc` on the call's
/// site: run it, as `on_sigtrap` does for its trap. `known`: the site is a
/// system call's whatever its instruction (the gate's, or its stub's);
/// otherwise a `brk` that is not fwe's trap is the guest's own, and
/// `in_guest` says whether guest code ran it.
fn syscall_trap(ctx: *mut libc::c_void, in_guest: bool, known: bool) {
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    // A system call that cannot wait runs with signals still blocked,
    // unless a tracer or a seccomp filter may make it wait.
    let quick = never_waits(mc.ss.x[8])
        && fwe_kernel::seccomp::mode() == 0
        && !fwe_kernel::ptrace::stops_at_syscalls();
    let _host = if quick { HostCode::enter_blocked() } else { HostCode::enter() };
    // The saved pc is the trapping instruction for `brk`.
    // SAFETY: the guest was executing at `pc`, so it is mapped.
    if !known && unsafe { insn(mc.ss.pc) } != Some(TRAP) {
        // Not one of our system call traps: a guest `brk` is a SIGTRAP for
        // the guest; one in fwe's own code is fatal.
        if in_guest {
            let mut regs = regs_from(mc);
            let addr = mc.ss.pc;
            let delivered = kernel()
                .as_mut()
                .is_some_and(|k| k.deliver_fault(&mut regs, fwe_abi::signal::SIGTRAP, addr));
            if delivered {
                settle(&mut regs);
                regs_to(mc, &regs);
                // SAFETY: `ctx` is this handler's ucontext.
                unsafe { return_with_guest_mask(ctx) };
                return;
            }
        }
        restore_default(libc::SIGTRAP);
        return;
    }
    let mut regs = regs_from(mc);
    if kernel().is_none() {
        report("fwe: system call before the kernel was initialized\n");
        // SAFETY: terminating the process.
        unsafe { libc::_exit(127) }
    }
    reroute_parked();
    // A traced process stopping at system calls: the entry's stop, where
    // the tracer may change the registers.
    let syscall_stops = fwe_kernel::ptrace::stops_at_syscalls();
    if syscall_stops {
        kernel().as_mut().unwrap().ptrace_syscall_stop(&mut regs, true);
    }
    let nr = regs.x[8];
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    // The process's seccomp filters decide first, for every call.
    if fwe_kernel::seccomp::mode() != 0 {
        let action = fwe_kernel::seccomp::check(nr, &args, regs.pc);
        if action == fwe_kernel::seccomp::Action::KillThread
            && fwe_kernel::thread::live_threads() > 1
        {
            // The thread ends without the kernel lock, as `exit` does.
            fwe_kernel::thread_exit_cleanup();
            crate::exit_current_thread(128 + fwe_abi::signal::SIGSYS as i32);
        }
        if action != fwe_kernel::seccomp::Action::Allow {
            kernel().as_mut().unwrap().seccomp_refuse(&mut regs, nr, &args, action);
            settle(&mut regs);
            regs_to(mc, &regs);
            // SAFETY: `ctx` is this handler's ucontext.
            unsafe { return_with_guest_mask(ctx) };
            return;
        }
    }

    // `clone` and the blocking system calls run without holding the kernel
    // lock, so a blocked or spawning thread does not stall the others; the
    // kernel is then locked only briefly to record the result and deliver a
    // pending signal.
    if nr == fwe_abi::nr::EXIT {
        // A thread exits without the kernel lock: pthread_exit never returns,
        // so a held lock would never be released.
        fwe_kernel::thread_exit_cleanup();
        crate::exit_current_thread(regs.x[0] as i32);
    }
    if nr == fwe_abi::nr::EXECVE || nr == fwe_abi::nr::EXECVEAT {
        // On success this enters the new program and never returns; on
        // failure it reports an errno the guest can handle.
        let r = if nr == fwe_abi::nr::EXECVE {
            crate::process::do_execve(&regs)
        } else {
            crate::process::do_execveat(&regs)
        };
        match r {
            // Return from the handler into the new program, which also
            // leaves the signal stack and restores the guest's mask; a
            // traced process stops there first.
            Ok(new) => {
                regs = new;
                kernel().as_mut().unwrap().ptrace_exec_stop(&mut regs);
            }
            Err(r) => kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r),
        }
        settle(&mut regs);
        regs_to(mc, &regs);
        // SAFETY: `ctx` is this handler's ucontext.
        unsafe { return_with_guest_mask(ctx) };
        return;
    }
    if nr == fwe_abi::nr::CLONE || nr == fwe_abi::nr::CLONE3 {
        let a = if nr == fwe_abi::nr::CLONE {
            Ok(fwe_kernel::CloneArgs::from_clone(&regs.x))
        } else {
            fwe_kernel::CloneArgs::from_clone3(regs.x[0], regs.x[1])
        };
        let mut event = None;
        let r = match a.and_then(|a| a.check().map(|()| a)) {
            Ok(a) => {
                // A traced parent whose tracer follows its children.
                event = fwe_kernel::ptrace::fork_event(a.flags).map(|e| (e, a.flags));
                let r = crate::threads::do_clone(&regs, a);
                fwe_kernel::ptrace::fork_done();
                r
            }
            Err(e) => fwe_abi::err(e),
        };
        let mut guard = kernel();
        let k = guard.as_mut().unwrap();
        k.finish_syscall(&mut regs, nr, &args, r);
        // The parent's event stop, the child's pid its message.
        if r > 0
            && let Some((e, flags)) = event
        {
            k.ptrace_event_stop(&mut regs, e, r as u64);
            if flags & fwe_abi::clone::CLONE_VFORK != 0 {
                k.ptrace_vfork_done(&mut regs, r as u64);
            }
        }
        drop(guard);
    } else if nr == fwe_abi::nr::WAIT4 {
        // wait4 blocks; run it without the kernel lock.
        let r = crate::process::do_wait4(&regs);
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::WAITID {
        let r = crate::process::do_waitid(&regs);
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::PIDFD_GETFD {
        // The target is asked for its descriptor without the kernel lock.
        let req = kernel().as_ref().unwrap().getfd_request(args[0], args[1], args[2]);
        let r = fwe_kernel::pidfd::getfd(req);
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else if fwe_kernel::ipcops::waits(nr) {
        // A semaphore or message queue wait: what it needs of the kernel is
        // taken under the lock, and it waits without it.
        let ctx = kernel().as_ref().unwrap().ipc_context();
        let r = fwe_kernel::ipcops::blocking(ctx, nr, args);
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::RT_SIGTIMEDWAIT {
        // The awaited signals are caught on the host while the call waits,
        // without the kernel lock.
        // A bad set is reported by the call itself.
        let want: u64 = fwe_kernel::uaccess::read(args[0]).unwrap_or(0);
        kernel().as_mut().unwrap().catch_for_wait(want);
        // SAFETY: guest pointers in `args` reference guest memory.
        let r = unsafe { fwe_kernel::signal::sigtimedwait(args[0], args[1], args[2], args[3]) };
        let mut guard = kernel();
        let k = guard.as_mut().unwrap();
        k.end_wait(want);
        k.finish_syscall(&mut regs, nr, &args, r);
    } else if let Some(r) = {
        // SAFETY: guest pointers in `args` reference guest memory.
        unsafe { fwe_kernel::blocking_syscall(nr, args) }
    } {
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else {
        kernel().as_mut().unwrap().enter_syscall(&mut regs);
    }
    // The exit's stop, its result in `x0`.
    if syscall_stops {
        kernel().as_mut().unwrap().ptrace_syscall_stop(&mut regs, false);
    }
    settle(&mut regs);
    regs_to(mc, &regs);
    // SAFETY: `ctx` is this handler's ucontext.
    unsafe { return_with_guest_mask(ctx) };
}

/// The host handler for every signal the guest catches (and for the wake
/// signal). It records the signal pending against this thread; if it
/// interrupted guest code, it delivers it now, as Linux does on the way back
/// to user space. Otherwise fwe was running a system call for this thread,
/// and the signal is delivered when that call returns — a blocking call was
/// interrupted by it.
extern "C" fn on_async(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: `info` is valid for SA_SIGINFO handlers.
    let sent = || unsafe { host::signal_info(sig, info) };
    take_async(sig, sent, ctx, guest_interrupted(ctx));
}

/// The body of [`on_async`], also used for a fault signal that was sent
/// rather than raised by an instruction. `sent` gives the signal's Linux
/// `siginfo`.
fn take_async(
    sig: libc::c_int,
    sent: impl Fn() -> thread::SigInfo,
    ctx: *mut libc::c_void,
    in_guest: bool,
) {
    if sig == libc::SIGXCPU && !fwe_kernel::rlimits::cpu_signal() {
        // Past the hard CPU limit: the process ends.
        return;
    }
    // A wait this thread is about to begin, or is in, ends for it.
    thread::poke_wait();
    let record = || {
        if sig == host::WAKE_SIGNAL {
            // Signals the host lacks, queued by another process.
            fwe_kernel::signote::drain(|lsig, note| {
                // One for a thread of this process goes to it, if it is there.
                if note.tid != 0 {
                    thread::post_directed(note.tid, lsig, host::sent_info(note));
                } else {
                    thread::post_landed(lsig, host::sent_info(note));
                }
            });
        } else {
            let info = sent();
            let lsig = host::signal_to_linux(sig);
            if REROUTING.with(Cell::get) {
                thread::post_process(lsig, info);
            } else {
                thread::post_landed(lsig, info);
            }
        }
    };
    if !in_guest {
        // fwe's own code was interrupted (a system call being made for the
        // guest, which delivers what is pending as it ends): the signal is
        // only recorded, under the handler's mask, which blocks every
        // signal. Entering `HostCode` would apply the guest's mask and let
        // signals nest in this handler without bound, each frame further
        // down the thread's signal stack until the host cannot deliver one
        // and ends the process.
        record();
        // A system call made through the gate delivers it as it ends; one
        // on its way out starts that again, to look for it.
        crate::gate::note_signal();
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
        if let Some(to) = crate::gate::rewind(ss.pc) {
            ss.pc = to;
        }
        return;
    }
    let _host = HostCode::enter();
    record();
    // Guest code holds none of fwe's locks, so taking the kernel lock here
    // cannot deadlock against this thread.
    let mut guard = kernel();
    let Some(k) = guard.as_mut() else { return };
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    let mut regs = regs_from(mc);
    finish_sp_stub(&mut regs);
    k.deliver_pending(&mut regs);
    drop(guard);
    settle(&mut regs);
    regs_to(mc, &regs);
    // SAFETY: `ctx` is this handler's ucontext.
    unsafe { return_with_guest_mask(ctx) };
}

/// The `T` at host address `addr`, or `None` where nothing readable is,
/// read through the host's copy of this task's memory, which reports a hole
/// rather than fault. Async-signal-safe.
fn read_host<T: Copy + Default>(addr: u64) -> Option<T> {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn mach_vm_read_overwrite(
                task: u32,
                a: u64,
                size: u64,
                data: u64,
                out: *mut u64,
            ) -> i32;
            static mach_task_self_: u32;
        }
        let mut v = T::default();
        let size = std::mem::size_of::<T>() as u64;
        let mut out = 0u64;
        // SAFETY: copying `size` bytes into `v`, which has room for them.
        let r = unsafe {
            mach_vm_read_overwrite(mach_task_self_, addr, size, &mut v as *mut T as u64, &mut out)
        };
        (r == 0 && out == size).then_some(v)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = addr;
        None
    }
}

/// A thread stopped on one of the last two instructions of the stub for an
/// instruction that writes `sp` from `x18` (`rewrite::x18_writes_sp_stub`):
/// `mov sp, s1; ldur s1, [s2, #-16]; ldur s2, [s2, #-32]`. Those loads read
/// the scratch registers back from below the old `sp`, which may be below
/// the new one too, where a signal frame is about to be written: so they
/// are made here first, and the thread goes on after them.
fn finish_sp_stub(regs: &mut Regs) {
    use crate::rewrite::LDUR;
    let pc = regs.pc;
    if !crate::prepare::in_sp_stub_region(pc) {
        return;
    }
    let ldur = |imm: i32, n: u32, t: u32| LDUR | ((imm as u32) & 0x1ff) << 12 | n << 5 | t;
    let mov_to_sp = |n: u32| 0x9100_001f | n << 5;
    // Read as the host copies, which reports a hole rather than fault: a
    // fault here, in a signal handler, would end the process.
    let word = |a: u64| read_host::<u32>(a);
    let Some(here) = word(pc) else { return };
    let (n, t) = ((here >> 5) & 0x1f, here & 0x1f);
    // On the first load: both are left.
    let first = here == ldur(-16, n, t)
        && word(pc.wrapping_sub(4)) == Some(mov_to_sp(t))
        && word(pc + 4) == Some(ldur(-32, n, n));
    // On the second: the first was made.
    let second = t == n
        && here == ldur(-32, n, n)
        && word(pc.wrapping_sub(4)).is_some_and(|w| {
            let s1 = w & 0x1f;
            w == ldur(-16, n, s1) && word(pc.wrapping_sub(8)) == Some(mov_to_sp(s1))
        });
    if !first && !second {
        return;
    }
    let base = regs.x[n as usize];
    let read = read_host::<u64>;
    if first {
        let (Some(a), Some(b)) = (read(base.wrapping_sub(16)), read(base.wrapping_sub(32))) else {
            return;
        };
        regs.x[t as usize] = a;
        regs.x[n as usize] = b;
        regs.pc = pc + 8;
    } else {
        let Some(b) = read(base.wrapping_sub(32)) else { return };
        regs.x[n as usize] = b;
        regs.pc = pc + 4;
    }
}

/// Set the host disposition of relayed Linux signal `sig`.
pub fn set_host_signal(sig: u64, how: fwe_kernel::HostSignal) {
    let Some(h) = host::signal_to_host(sig) else { return };
    // SAFETY: installing a fully initialized sigaction.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigfillset(&mut sa.sa_mask);
        match how {
            fwe_kernel::HostSignal::Default => sa.sa_sigaction = libc::SIG_DFL,
            fwe_kernel::HostSignal::Ignore => sa.sa_sigaction = libc::SIG_IGN,
            fwe_kernel::HostSignal::Catch { flags } => {
                sa.sa_sigaction = on_async as *const () as usize;
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                if sig == fwe_abi::signal::SIGCHLD {
                    if flags & fwe_abi::signal::SA_NOCLDSTOP != 0 {
                        sa.sa_flags |= libc::SA_NOCLDSTOP;
                    }
                    if flags & fwe_abi::signal::SA_NOCLDWAIT != 0 {
                        sa.sa_flags |= libc::SA_NOCLDWAIT;
                    }
                }
            }
        }
        libc::sigaction(h, &sa, std::ptr::null_mut());
    }
}

/// The Linux signal number for a host synchronous fault.
fn fault_signal(host: libc::c_int) -> u64 {
    use fwe_abi::signal::*;
    match host {
        libc::SIGSEGV => SIGSEGV,
        libc::SIGBUS => SIGBUS,
        libc::SIGILL => SIGILL,
        libc::SIGFPE => SIGFPE,
        libc::SIGTRAP => SIGTRAP,
        _ => SIGSEGV,
    }
}

/// The Linux signal of host fault `host` at `addr` (`esr` its syndrome):
/// macOS reports an access the page's protection forbids, on some
/// mappings, as `SIGBUS`, which Linux reports as `SIGSEGV` (keeping
/// `SIGBUS` for memory past a mapped file's end, whose protection allows
/// the access).
fn linux_fault_signal(host: libc::c_int, addr: u64, esr: u32) -> u64 {
    let sig = fault_signal(host);
    #[cfg(target_os = "macos")]
    if host == libc::SIGBUS
        && let Some(r) = fwe_kernel::mm::region::query(addr).filter(|r| r.start <= addr)
    {
        let class = (esr >> 26) & 0x3f;
        let needed = if class == ESR_EC_INSTRUCTION_ABORT_LOWER {
            libc::PROT_EXEC
        } else if esr & (1 << 6) != 0 {
            libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        if r.protection & needed == 0 {
            return fwe_abi::signal::SIGSEGV;
        }
    }
    let _ = (addr, esr);
    sig
}

/// The `ESR_EL1` exception class of an instruction fetch fault at EL0.
const ESR_EC_INSTRUCTION_ABORT_LOWER: u32 = 0x20;

extern "C" fn on_fault(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // A process that sends itself one of these signals has it emulated (see
    // `Kernel::sys_kill`), so here it is a fault, or a signal sent by
    // another process, which macOS's siginfo does not tell apart (it gives
    // a sent one the thread's last fault). Another fwe process leaves a
    // note before it sends one ([`fwe_kernel::signote`]): that one is a
    // signal for the guest, whatever this thread was running. (A genuine
    // fault that coincides with a note faults again, without one.)
    if let Some(note) = fwe_kernel::signote::take(sig) {
        take_async(sig, || host::sent_info(note), ctx, guest_interrupted(ctx));
        return;
    }
    let in_guest = guest_interrupted(ctx);
    if in_guest {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
        // SAFETY: the guest was executing at the pc, and the words after it
        // are read only if it is a stub's first.
        let word = |a: u64| unsafe { insn(a) };
        if let Some(site) = crate::rewrite::syscall_stub_site(word, ss.pc) {
            // A system call's stub could not save registers below the
            // guest's sp (none is needed for a system call: musl's thread
            // exit unmaps its own stack first): it runs as the trap runs it.
            ss.pc = site;
            syscall_trap(ctx, true, true);
            return;
        }
    }
    if !in_guest {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        let addr = unsafe { (*info).si_addr() } as u64;
        if fwe_kernel::mm::write_exec_writable(addr, crate::page_size()) {
            // fwe writing for the guest into a page of its writable and
            // executable memory that was last executed: retry the write.
            return;
        }
        if let Some(resume) = fwe_kernel::uaccess::fixup(ss.pc) {
            // A guest pointer the kernel was copying through was bad: the
            // copy reports EFAULT.
            ss.pc = resume;
            return;
        }
        // Anywhere else in fwe's own code (the kernel lock may be held):
        // fatal.
        restore_default(sig);
        return;
    }
    let _host = HostCode::enter();
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    // SAFETY: `info` is valid for SA_SIGINFO handlers.
    let addr = unsafe { (*info).si_addr() } as u64;

    // `mrs <Xt>, ctr_el0`, which Linux lets user space run and macOS traps:
    // the value is emulated.
    // SAFETY: the guest was executing at `pc`, so it is mapped.
    if let Some(word) = unsafe { insn(mc.ss.pc) }
        .filter(|&w| sig == libc::SIGILL && crate::hwcap::is_mrs_ctr_el0(w))
    {
        let mut regs = regs_from(mc);
        let rt = (word & 31) as usize;
        if rt != 31 {
            regs.x[rt] = crate::hwcap::CTR_EL0;
        }
        regs.pc += 4;
        settle(&mut regs);
        regs_to(mc, &regs);
        // SAFETY: `ctx` is this handler's ucontext.
        unsafe { return_with_guest_mask(ctx) };
        return;
    }

    // Memory the guest mapped writable and executable: the page becomes
    // what this access needs, and the access is retried.
    let exec = (mc.es.esr >> 26) & 0x3f == ESR_EC_INSTRUCTION_ABORT_LOWER;
    if kernel().as_mut().is_some_and(|k| k.write_exec_fault(addr, exec)) {
        return;
    }
    // A page of a private mapping of a file with no name, first written:
    // it becomes a copy, and the write is tried again.
    let write = !exec && mc.es.esr & (1 << 6) != 0;
    if write && kernel().as_mut().is_some_and(|k| k.view_fault(addr)) {
        return;
    }
    // Below a stack that grows down (`MAP_GROWSDOWN`): it grows, and the
    // access is retried.
    if sig == libc::SIGSEGV && !exec && kernel().as_mut().is_some_and(|k| k.stack_fault(addr)) {
        return;
    }

    // Offer the fault to a guest handler; if one is installed, enter it.
    let mut regs = regs_from(mc);
    // Memory `MADV_HWPOISON` poisoned fails with a bus error.
    let lsig = if fwe_kernel::mm::poisoned(addr) {
        fwe_abi::signal::SIGBUS
    } else {
        linux_fault_signal(sig, addr, mc.es.esr)
    };
    let delivered = kernel().as_mut().is_some_and(|k| k.deliver_fault(&mut regs, lsig, addr));
    if delivered {
        settle(&mut regs);
        regs_to(mc, &regs);
        // SAFETY: `ctx` is this handler's ucontext.
        unsafe { return_with_guest_mask(ctx) };
        return;
    }

    // It ends of the fault: its core first, as Linux dumps it.
    if let Some(k) = kernel().as_mut() {
        k.dump_core(lsig, Some(&regs));
    }
    fwe_kernel::procreg::ending(lsig as i32 | fwe_kernel::coredump::status_bit());
    let tracing = kernel().as_ref().is_some_and(|k| k.tracer.enabled);
    if tracing {
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        let addr = unsafe { (*info).si_addr() } as u64;
        // SAFETY: the guest was executing at `pc`, so it is mapped.
        let word = unsafe { insn(mc.ss.pc) }.map_or(String::from("?"), |w| format!("{w:#010x}"));
        report(&format!(
            "[fwe] guest fault: signal {sig} at pc {:#x} (insn {word}), address {addr:#x}, esr {:#x}\n",
            mc.ss.pc, mc.es.esr
        ));
        let mut regs = String::from("[fwe] registers:");
        for (i, x) in mc.ss.x.iter().enumerate() {
            if i % 4 == 0 {
                regs.push_str("\n[fwe]  ");
            }
            regs.push_str(&format!(" x{i:<2}={x:#018x}"));
        }
        regs.push_str(&format!(
            "\n[fwe]   fp={:#018x} lr={:#018x} sp={:#018x}\n",
            mc.ss.fp, mc.ss.lr, mc.ss.sp
        ));
        report(&regs);
        let mut code = String::from("[fwe] code near pc (pc marked *):");
        for off in (-24i64..=8).map(|k| k * 4) {
            let at = mc.ss.pc.wrapping_add(off as u64);
            // Only read within the faulting instruction's page.
            if at & !0x3fff == mc.ss.pc & !0x3fff {
                // SAFETY: same page as the mapped pc.
                if let Some(w) = unsafe { insn(at) } {
                    let mark = if off == 0 { "*" } else { "" };
                    code.push_str(&format!(" {mark}{w:08x}"));
                }
            }
        }
        code.push('\n');
        report(&code);
    }
    // Returning re-executes the faulting instruction under the default action.
    restore_default(sig);
    if lsig != fault_signal(sig) {
        // It dies of the signal Linux would send: taken as the handler
        // returns, before the instruction runs again.
        restore_default(libc::SIGSEGV);
        // SAFETY: plain host call.
        unsafe { libc::raise(libc::SIGSEGV) };
    }
}

extern "C" fn on_probe_signal(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    let mode_was_on = X18Abi::get().is_some_and(|abi| abi.enabled());
    let _host = HostCode::enter();
    // SAFETY: the kernel passes valid siginfo and ucontext for SA_SIGINFO
    // handlers.
    let (code, addr, mc) = unsafe {
        ((*info).si_code, (*info).si_addr() as u64, &*(*(ctx as *mut Ucontext)).uc_mcontext)
    };
    // SAFETY: the thread was executing at `pc`, so it is mapped.
    let word = unsafe { insn(mc.ss.pc) }.map_or(String::from("?"), |w| format!("{w:#010x}"));
    report(&format!(
        "probe: signal {sig} code {code} at pc {:#x} (insn {word}), address {addr:#x}, \
         esr {:#x}, far {:#x}, x18 {:#x}, lr {:#x}, custom x18 ABI on: {mode_was_on}\n",
        mc.ss.pc, mc.es.esr, mc.es.far, mc.ss.x[18], mc.ss.lr
    ));
    // SAFETY: terminating the probe process.
    unsafe { libc::_exit(99) }
}

/// Report synchronous signals during host probes instead of dying silently.
pub fn install_probe_reporter() {
    // SAFETY: a fresh mapping for the signal stack, leaked for the life of
    // the process.
    unsafe {
        let stack = libc::mmap(
            std::ptr::null_mut(),
            SIGNAL_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED, "allocating the signal stack failed");
        let ss = libc::stack_t { ss_sp: stack, ss_size: SIGNAL_STACK_SIZE, ss_flags: 0 };
        assert_eq!(libc::sigaltstack(&ss, std::ptr::null_mut()), 0, "sigaltstack failed");
    }
    for sig in [libc::SIGTRAP, libc::SIGILL, libc::SIGSEGV, libc::SIGBUS, libc::SIGSYS] {
        install(sig, on_probe_signal);
    }
}

fn restore_default(sig: libc::c_int) {
    // SAFETY: resetting a signal disposition.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
}

fn install(
    sig: libc::c_int,
    handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
) {
    // SAFETY: installing a handler with a fully initialized sigaction. All
    // signals are blocked while it starts (see the module comment).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigfillset(&mut sa.sa_mask);
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction({sig}) failed: {}", std::io::Error::last_os_error());
        }
    }
}

/// Give this host thread its own signal stack. Signal dispositions are
/// process-wide, but the alternate stack is per thread, so every thread that
/// runs guest code needs one before it can trap.
/// Give the calling thread a signal stack if it has none. A forked child's
/// thread does not inherit the parent thread's: without one, its handlers
/// would run on the guest stack, which `execve` unmaps.
pub fn ensure_thread_altstack() {
    // SAFETY: querying this thread's signal stack into a zeroed stack_t.
    let disabled = unsafe {
        let mut old: libc::stack_t = std::mem::zeroed();
        libc::sigaltstack(std::ptr::null(), &mut old) == 0 && old.ss_flags & libc::SS_DISABLE != 0
    };
    if disabled {
        install_thread_altstack();
    }
}

pub fn install_thread_altstack() {
    // SAFETY: a fresh mapping for the signal stack, leaked for the life of
    // the thread (which runs until the process or the thread exits).
    unsafe {
        let stack = libc::mmap(
            std::ptr::null_mut(),
            SIGNAL_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED, "allocating the signal stack failed");
        let ss = libc::stack_t { ss_sp: stack, ss_size: SIGNAL_STACK_SIZE, ss_flags: 0 };
        assert_eq!(libc::sigaltstack(&ss, std::ptr::null_mut()), 0, "sigaltstack failed");
    }
}

/// Install the per-thread signal stack and the process-wide handlers for
/// running guest code (called once on the main thread).
pub fn install_handlers() {
    install_thread_altstack();
    install(libc::SIGTRAP, on_sigtrap);
    for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
        install(sig, on_fault);
    }
    install(host::WAKE_SIGNAL, on_async);
}

/// Enter the guest with a full register state (used for a cloned thread).
/// Restores `x0`–`x15` and `x17`–`x30`, the stack pointer, and jumps to `pc`;
/// `x16` is used as the branch scratch and its guest value is not restored
/// (it is a caller-saved temporary a thread entry does not rely on).
///
/// # Safety
/// `regs` must point to a valid [`Regs`] describing a runnable guest context.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_guest_full(regs: *const Regs) -> ! {
    core::arch::naked_asm!(
        "ldr x1, [x0, #248]", // sp
        "mov sp, x1",
        "ldr x2,  [x0, #16]",
        "ldr x3,  [x0, #24]",
        "ldr x4,  [x0, #32]",
        "ldr x5,  [x0, #40]",
        "ldr x6,  [x0, #48]",
        "ldr x7,  [x0, #56]",
        "ldr x8,  [x0, #64]",
        "ldr x9,  [x0, #72]",
        "ldr x10, [x0, #80]",
        "ldr x11, [x0, #88]",
        "ldr x12, [x0, #96]",
        "ldr x13, [x0, #104]",
        "ldr x14, [x0, #112]",
        "ldr x15, [x0, #120]",
        "ldr x17, [x0, #136]",
        "ldr x18, [x0, #144]",
        "ldr x19, [x0, #152]",
        "ldr x20, [x0, #160]",
        "ldr x21, [x0, #168]",
        "ldr x22, [x0, #176]",
        "ldr x23, [x0, #184]",
        "ldr x24, [x0, #192]",
        "ldr x25, [x0, #200]",
        "ldr x26, [x0, #208]",
        "ldr x27, [x0, #216]",
        "ldr x28, [x0, #224]",
        "ldr x29, [x0, #232]",
        "ldr x30, [x0, #240]",
        "ldr x16, [x0, #256]", // pc -> branch scratch
        "ldr x1,  [x0, #8]",
        "ldr x0,  [x0, #0]",
        "br x16",
    )
}

/// Switch this thread to the guest: set `sp`, clear the general-purpose
/// registers as Linux does at `execve`, and jump to `entry`.
#[unsafe(naked)]
pub extern "C" fn enter_guest(sp: u64, entry: u64) -> ! {
    core::arch::naked_asm!(
        "mov sp, x0",
        "mov x17, x1",
        "mov x0, xzr",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "br x17",
    )
}
