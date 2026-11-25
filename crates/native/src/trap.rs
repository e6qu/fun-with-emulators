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
use fwe_kernel::{FpRegs, Regs, host, thread};
use std::cell::Cell;

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

fn kernel() -> fwe_kernel::klock::Exclusive<'static, Option<fwe_kernel::Kernel<NativePlatform>>> {
    KERNEL.lock()
}

/// Write a diagnostic directly to the host's standard error.
fn report(message: &str) {
    // SAFETY: `message` is a valid buffer of its length.
    unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
}

/// Read an instruction word, if `addr` is the address of one.
///
/// # Safety
/// `addr` MUST be mapped if it is 4-byte aligned.
unsafe fn insn(addr: u64) -> Option<u32> {
    // SAFETY: guaranteed by the caller.
    addr.is_multiple_of(4).then(|| unsafe { (addr as *const u32).read() })
}

thread_local! {
    /// Whether this thread is executing guest code (as opposed to fwe's own
    /// code, including the handlers here).
    static IN_GUEST: Cell<bool> = const { Cell::new(false) };
    /// [`reroute_parked`] is taking a signal parked on this thread: record
    /// it against the process rather than the thread.
    static REROUTING: Cell<bool> = const { Cell::new(false) };
    /// When [`reroute_parked`] last looked at this thread's signals pending
    /// on the host, by the virtual counter (0: it has not).
    static LOOKED: Cell<u64> = const { Cell::new(0) };
}

/// How often a thread whose calls only glance ([`glances`]) looks at the
/// signals the host parked on it ([`reroute_parked`]), at most: every
/// 100 µs.
const LOOK_EVERY_PER_SECOND: u64 = 10_000;

/// Whether system call `nr`, with second argument `op`, neither waits nor
/// reads signal state, whatever its other arguments: it reads ids or
/// clocks, yields, or wakes futex waiters.
fn glances(nr: u64, op: u64) -> bool {
    use fwe_abi::futex;
    use fwe_abi::nr::*;
    match nr {
        GETPID | GETPPID | GETTID | GETUID | GETEUID | GETGID | GETEGID | GETPGID | GETSID
        | CLOCK_GETTIME | CLOCK_GETRES | GETTIMEOFDAY | GETCPU | SCHED_YIELD => true,
        FUTEX => matches!(
            op & futex::FUTEX_CMD_MASK,
            futex::FUTEX_WAKE | futex::FUTEX_WAKE_OP | futex::FUTEX_WAKE_BITSET
        ),
        _ => false,
    }
}

/// This host thread starts another guest thread
/// ([`crate::threads::wait_for_next`]): its flags are a new thread's.
pub fn thread_reused() {
    IN_GUEST.with(|g| g.set(false));
    REROUTING.with(|r| r.set(false));
    LOOKED.set(0);
    UNBLOCKED.with(|u| u.set(false));
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
/// this thread's guest mask blocks might be such a signal: unblocking it
/// here, in fwe's code, has the host deliver it to [`take_async`] now,
/// which records it against the process (where Linux keeps it), and the
/// other threads are woken to take it. A signal with the default action
/// or ignored stays where it is: unblocking it would apply that action to
/// a signal Linux keeps pending.
///
/// A caught signal is parked so only if it came while every thread was in
/// fwe's handlers (out of them, the host does not block it: the handler
/// takes it whatever the guest's mask). The look costs a host call, so a
/// call that neither waits nor reads signal state ([`glances`]) looks
/// only once [`LOOK_EVERY_PER_SECOND`] says it is time again: a thread
/// making such calls by the thousand (a runtime timing itself at each
/// step) still looks thousands of times a second. Any other call (one
/// that can wait, or reads what is pending) looks every time.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn reroute_parked(blocked: u64, glance: impl FnOnce() -> bool) {
    let blocked = blocked & fwe_kernel::signal::caught();
    if blocked == 0 {
        return;
    }
    let (now, hz): (u64, u64);
    // SAFETY: reads of the virtual counter and its frequency, which macOS
    // lets every thread read.
    unsafe {
        std::arch::asm!(
            "mrs {}, cntvct_el0",
            "mrs {}, cntfrq_el0",
            out(reg) now,
            out(reg) hz,
            options(nomem, nostack, preserves_flags)
        );
    }
    if now.wrapping_sub(LOOKED.get()) < hz / LOOK_EVERY_PER_SECOND && glance() {
        return;
    }
    LOOKED.set(now);
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
    // The mask as it was is put back, not the signals blocked: a caught
    // signal the host showed pending might be one this thread never blocked
    // (it landed during the look, and is delivered as the look returns),
    // which blocked now would wait unseen on the host.
    // The pending signals are delivered to this thread as they unblock.
    drop(host::MaskGuard::unblock(&set));
    REROUTING.set(false);
    thread::wake_others(host::WAKE_SIGNAL);
}

/// Block every signal the guest can receive on this thread.
fn block_async_signals() {
    let mut all = host::host_sigset(u64::MAX);
    // SAFETY: `all` is an initialized signal set.
    unsafe { libc::sigaddset(&mut all, host::WAKE_SIGNAL) };
    host::block_signals(&all);
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
    host::set_signal_mask(&host::host_mask_for(thread::mask()));
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
/// leaves the custom x18 ABI, so host code can call macOS libraries, and
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
extern "C" fn fwe_gate_call(b: *mut crate::gate::Block) -> u64 {
    use fwe_abi::nr::*;
    use std::sync::atomic::Ordering::SeqCst;
    // SAFETY: the gate passes this thread's block, which only it uses now.
    let b = unsafe { &mut *b };
    // `IN_GUEST` stays as it is: while the block is active, a signal's
    // handler takes the thread for out of guest code ([`guest_interrupted`]).
    if b.slot == 0 {
        b.slot = crate::quiesce::mine_addr();
    }
    crate::quiesce::leave_at(b.slot);
    // A call from a translation is the program's `svc`'s.
    let site = crate::gate::site_of(b.ret);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let site = if crate::jit::in_cache(site) { crate::jit::syscall_site(site) } else { site };
    b.regs.pc = site;
    b.regs.x[18] = guest_x18();
    b.ran = 0;
    // SAFETY: words of the stub that called the gate, mapped.
    if let Some(rt) = crate::rewrite::flush_reg(|a| unsafe { (a as *const u32).read() }, b.ret) {
        flush_line(if rt == 31 { 0 } else { b.regs.x[rt as usize] }, rt == 18);
        b.regs.pc = site + 4;
        b.ran = 1;
        b.seen = b.signals.load(SeqCst);
        let (pending, mask) = thread::state();
        if pending & !mask != 0 {
            return 1;
        }
        crate::quiesce::enter_at(b.slot);
        return 0;
    }
    let nr = b.regs.x[8];
    // A new thread of an untraced one is made here too: the trap would
    // make it from the same registers.
    // A thread's `clone`, or `clone3` (glibc's): its flags in its
    // arguments' structure.
    let clone_flags = match nr {
        CLONE => Some(b.regs.x[0]),
        CLONE3 => fwe_kernel::uaccess::read::<u64>(b.regs.x[0]).ok(),
        _ => None,
    };
    let thread_clone = clone_flags.is_some_and(|f| f & fwe_abi::clone::CLONE_THREAD != 0)
        && !fwe_kernel::ptrace::traced();
    // What the trap runs its own way, or stops at, it runs.
    let plain = fwe_kernel::seccomp::mode() == 0
        && !fwe_kernel::ptrace::stops_at_syscalls()
        && !matches!(nr, EXIT | EXECVE | EXECVEAT | WAIT4 | WAITID | PIDFD_GETFD | RT_SIGTIMEDWAIT)
        && (!matches!(nr, CLONE | CLONE3) || thread_clone);
    // A thread that is not the last ends here, as the trap would end it,
    // with every host signal blocked first: one for the process is then
    // taken by another thread, as when the trap's handler runs.
    if nr == EXIT
        && fwe_kernel::seccomp::mode() == 0
        && !fwe_kernel::ptrace::stops_at_syscalls()
        && !fwe_kernel::ptrace::traced()
    {
        host::block_signals(&host::full_sigset());
        fwe_kernel::thread_exit_cleanup();
        crate::exit_current_thread(b.regs.x[0] as i32, true);
    }
    if !plain {
        return 1;
    }
    let mask = thread::mask();
    reroute_parked(mask, || glances(nr, b.regs.x[1]));
    // What a plain return keeps: the general registers but `x0`, `sp` and
    // the flags (the vector registers change only with the pc, as a
    // signal's delivery or return changes them).
    let (before_x, before_sp, before_pstate) = (b.regs.x, b.regs.sp, b.regs.pstate);
    let regs = &mut b.regs;
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    let began = fwe_kernel::timing::call_began();
    if thread_clone {
        let a = if nr == CLONE {
            Ok(fwe_kernel::CloneArgs::from_clone(&regs.x))
        } else {
            fwe_kernel::CloneArgs::from_clone3(regs.x[0], regs.x[1])
        };
        let r = match a.and_then(|a| a.check().map(|()| a)) {
            Ok(a) => crate::threads::do_clone(regs, a),
            Err(e) => fwe_abi::err(e),
        };
        KERNEL.finish(regs, nr, &args, r);
    } else if fwe_kernel::ipcops::waits(nr) {
        // A semaphore or message queue wait: what it needs of the kernel is
        // taken under the lock, and it waits without it (a guest signal
        // ends the wait as it looks between slices).
        let ctx = kernel().as_ref().unwrap().ipc_context();
        let r = fwe_kernel::ipcops::blocking(ctx, nr, args);
        KERNEL.finish(regs, nr, &args, r);
    // SAFETY: guest pointers in `args` reference guest memory.
    } else if let Some(r) = unsafe { fwe_kernel::blocking_syscall(nr, args) } {
        KERNEL.finish(regs, nr, &args, r);
    } else {
        KERNEL.syscall(regs);
    }
    fwe_kernel::timing::call_done(nr, began);
    b.ran = 1;
    // A changed mask is the host thread's now (the guest's is in force in
    // its code): a signal it unblocks that is pending is seen below.
    let (_, now_mask) = thread::state();
    if now_mask != mask {
        apply_guest_mask();
        UNBLOCKED.with(|u| u.set(false));
    }
    // A signal from here on is seen by the gate's way out.
    b.seen = b.signals.load(SeqCst);
    let regs = &b.regs;
    let plain_return = regs.pc == site + 4
        && regs.sp == before_sp
        && regs.x[1..].iter().zip(&before_x[1..]).fold(0, |d, (a, b)| d | (a ^ b)) == 0
        && regs.pstate == before_pstate
        && {
            let (pending, mask) = thread::state();
            pending & !mask == 0
        };
    if plain_return {
        crate::quiesce::enter_at(b.slot);
    }
    u64::from(!plain_return)
}

/// The program's `ic ivau` of the line at `addr` (its stub ran it, but
/// through `x18`, `native`): the translations made from it go
/// ([`crate::jit::flushed`]).
fn flush_line(addr: u64, native: bool) {
    let line = 4 << (crate::hwcap::CTR_EL0 & 15);
    if native {
        // Code that runs as it is might be there: the host's cache line
        // too, where it is mapped (as the instruction faults elsewhere,
        // which a stub through `x18` leaves to its translations).
        let mapped = !fwe_kernel::maps::record().areas_in(addr, addr + 1).is_empty();
        if mapped {
            // SAFETY: a mapped line of the program's memory.
            unsafe { crate::prepare::flush_icache(addr & !(line - 1), line) };
        }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    crate::jit::flushed(addr);
}

/// A system call's site: the program's `svc` where the call was made from a
/// translation of code made executable at run time.
/// The Rust half of the exit gate ([`crate::gate`]): take the way out of
/// a translation whose state is in `b` (its `pc` the way out), as fwe's
/// trap would. 0: it leads into a translation, which the gate enters (the
/// block says which); 1: the trap is to go on (`b.ran` set: the state in
/// the block is where the way out led, with anything pending delivered).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn fwe_exit_call(b: *mut crate::gate::Block) -> u64 {
    use std::sync::atomic::Ordering::SeqCst;
    // SAFETY: the gate passes this thread's block, which only it uses now.
    let b = unsafe { &mut *b };
    if b.slot == 0 {
        b.slot = crate::quiesce::mine_addr();
    }
    crate::quiesce::leave_at(b.slot);
    b.regs.x[18] = guest_x18();
    let into = crate::jit::gate_exit(&mut b.regs);
    b.ran = 1;
    b.seen = b.signals.load(SeqCst);
    let (pending, mask) = thread::state();
    match into {
        Some((t, g)) if pending & !mask == 0 => {
            (b.jit_t, b.jit_g) = (t, g);
            crate::quiesce::enter_at(b.slot);
            0
        }
        _ => 1,
    }
}

fn guest_site(site: u64) -> u64 {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if crate::jit::in_cache(site) {
        return crate::jit::guest_pc(site).expect("a system call's site in a translation");
    }
    site
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

/// Under `--strace`, an instruction fetch that faulted, with what led
/// there: the registers (the guest's `x18` among them), the code before
/// the return address, and, where that is a call, the code it called. Code
/// is read only where the guest's mappings say it is readable.
fn fetch_fault_report(regs: &Regs) {
    if !kernel().as_ref().is_some_and(|k| k.tracer.enabled) {
        return;
    }
    let readable = |a: u64| {
        fwe_kernel::maps::record()
            .areas_in(a, a + 4)
            .iter()
            .any(|p| p.value.prot & fwe_abi::mman::PROT_READ != 0)
    };
    let word = |a: u64| -> Option<u32> {
        // SAFETY: an address the guest's mappings say is readable.
        readable(a).then(|| unsafe { (a as *const u32).read() })
    };
    let dump = |from: u64, n: u64| -> String {
        (0..n)
            .map(|i| from + 4 * i)
            .map(|a| match word(a) {
                Some(w) => format!("{a:#x}:{w:08x}"),
                None => format!("{a:#x}:-"),
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut r = format!(
        "fetch fault at {:#x} (stub region {:?}); sp {:#x}; x18 {:#x}; regs",
        regs.pc,
        crate::prepare::stub_region(regs.pc),
        regs.sp,
        regs.x[18]
    );
    for (i, x) in regs.x.iter().enumerate() {
        r.push_str(&format!(" x{i}={x:#x}"));
    }
    let lr = regs.x[30];
    r.push_str(&format!("; before lr: {}", dump(lr.wrapping_sub(32), 10)));
    if let Some(w) = word(lr.wrapping_sub(4)) {
        if w & 0xfc00_0000 == 0x9400_0000 {
            let to = lr.wrapping_sub(4).wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
            r.push_str(&format!("; called {to:#x}: {}", dump(to, 48)));
        } else if w & 0xffff_fc1f == 0xd63f_0000 {
            let n = ((w >> 5) & 31) as usize;
            r.push_str(&format!("; called through x{n} = {:#x}", regs.x[n]));
        }
    }
    if let Some(k) = kernel().as_ref() {
        k.tracer.note(&r);
    }
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
        // Going on in a translation (a way out's target): a handler's frame
        // holds the guest's state, as at the instruction it stands for, not
        // fwe's code, which might be gone when the handler returns.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if crate::jit::stands_for_program(regs.pc) {
            crate::jit::to_guest(regs);
        }
        KERNEL.deliver_pending(regs);
    }
}

extern "C" fn on_sigtrap(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    fwe_kernel::timing::signal(sig);
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
    // The exit gate's trap: the state the way out led to is in the block.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    // SAFETY: the thread was executing at `pc`, so it is mapped.
    if crate::gate::in_gate(pc) && unsafe { insn(pc) } == Some(crate::gate::EXIT_GATE_TRAP) {
        fwe_kernel::timing::trapped(fwe_kernel::timing::Trap::ExitGate);
        let b = crate::gate::block().expect("the exit gate's thread has a block");
        let mut regs = b.regs;
        b.active.store(0, std::sync::atomic::Ordering::SeqCst);
        let _host = HostCode::enter_blocked();
        settle(&mut regs);
        regs_to(mc, &regs);
        // SAFETY: `ctx` is this handler's ucontext.
        unsafe { return_with_guest_mask(ctx) };
        return;
    }
    // The gate's trap: the guest's state is in this thread's block.
    // SAFETY: the thread was executing at `pc`, so it is mapped.
    let from_gate = crate::gate::in_gate(pc) && unsafe { insn(pc) } == Some(crate::gate::GATE_TRAP);
    if from_gate {
        let b = crate::gate::block().expect("the gate's thread has a block");
        let mut regs = b.regs;
        let ran = b.ran != 0;
        fwe_kernel::timing::trapped(if ran {
            fwe_kernel::timing::Trap::GateRan
        } else {
            fwe_kernel::timing::Trap::Gate
        });
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
    if !from_gate {
        fwe_kernel::timing::trapped(fwe_kernel::timing::Trap::Call);
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
    // unless a tracer or a seccomp filter can make it wait.
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
            // In a translation: the trap is at the program's own `brk`,
            // with its registers as there.
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if crate::jit::in_cache(regs.pc) {
                crate::jit::to_guest(&mut regs);
            }
            let addr = regs.pc;
            let delivered = KERNEL.deliver_fault(&mut regs, fwe_abi::signal::SIGTRAP, addr, None);
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
    regs.pc = guest_site(regs.pc);
    if kernel().is_none() {
        report("fwe: system call before the kernel was initialized\n");
        // SAFETY: terminating the process.
        unsafe { libc::_exit(127) }
    }
    reroute_parked(thread::mask(), || false);
    // A traced process stopping at system calls: the entry's stop, where
    // the tracer can change the registers.
    let syscall_stops = fwe_kernel::ptrace::stops_at_syscalls();
    if syscall_stops {
        KERNEL.syscall_stop(&mut regs, true);
    }
    let mut nr = regs.x[8];
    let mut args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    // The process's seccomp filters decide first, for every call.
    if fwe_kernel::seccomp::mode() != 0 {
        let mut action = fwe_kernel::seccomp::check(nr, &args, fwe_kernel::SvcSite(regs.pc));
        // A tracer's turn (`SECCOMP_RET_TRACE`): the call as it leaves it.
        if let fwe_kernel::seccomp::Action::Trace(data) = action {
            action = KERNEL.seccomp_trace(&mut regs, data);
            nr = regs.x[8];
            args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
        }
        if action == fwe_kernel::seccomp::Action::KillThread
            && fwe_kernel::thread::live_threads() > 1
        {
            // The thread ends without the kernel lock, as `exit` does.
            fwe_kernel::thread_exit_cleanup();
            crate::exit_current_thread(128 + fwe_abi::signal::SIGSYS as i32, false);
        }
        if action != fwe_kernel::seccomp::Action::Allow {
            kernel().as_mut().unwrap().seccomp_refuse(&mut regs, nr, &args, action);
            KERNEL.deliver_pending(&mut regs);
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
        crate::exit_current_thread(regs.x[0] as i32, false);
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
                KERNEL.exec_stops(&mut regs);
            }
            Err(r) => {
                kernel().as_mut().unwrap().complete_syscall(&mut regs, nr, &args, r);
                KERNEL.deliver_pending(&mut regs);
            }
        }
        settle(&mut regs);
        regs_to(mc, &regs);
        // SAFETY: `ctx` is this handler's ucontext.
        unsafe { return_with_guest_mask(ctx) };
        return;
    }
    let began = fwe_kernel::timing::call_began();
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
        kernel().as_mut().unwrap().complete_syscall(&mut regs, nr, &args, r);
        // The parent's event stop, the child's pid its message, before
        // what is pending is delivered, as Linux's in the call.
        if r > 0
            && let Some((e, flags)) = event
        {
            KERNEL.clone_stops(&mut regs, e, r as u64, flags & fwe_abi::clone::CLONE_VFORK != 0);
        }
        KERNEL.deliver_pending(&mut regs);
    } else if nr == fwe_abi::nr::WAIT4 {
        // wait4 blocks; run it without the kernel lock.
        let r = crate::process::do_wait4(&regs);
        KERNEL.finish(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::WAITID {
        let r = crate::process::do_waitid(&regs);
        KERNEL.finish(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::PIDFD_GETFD {
        // The target is asked for its descriptor without the kernel lock.
        let req = kernel().as_ref().unwrap().getfd_request(args[0], args[1], args[2]);
        let r = fwe_kernel::pidfd::getfd(req);
        KERNEL.finish(&mut regs, nr, &args, r);
    } else if fwe_kernel::ipcops::waits(nr) {
        // A semaphore or message queue wait: what it needs of the kernel is
        // taken under the lock, and it waits without it.
        let ctx = kernel().as_ref().unwrap().ipc_context();
        let r = fwe_kernel::ipcops::blocking(ctx, nr, args);
        KERNEL.finish(&mut regs, nr, &args, r);
    } else if nr == fwe_abi::nr::RT_SIGTIMEDWAIT {
        // The awaited signals are caught on the host while the call waits,
        // without the kernel lock.
        // A bad set is reported by the call itself.
        let want: u64 = fwe_kernel::uaccess::read(args[0]).unwrap_or(0);
        kernel().as_mut().unwrap().catch_for_wait(want);
        // SAFETY: guest pointers in `args` reference guest memory.
        let r = unsafe { fwe_kernel::signal::sigtimedwait(args[0], args[1], args[2], args[3]) };
        {
            let mut guard = kernel();
            let k = guard.as_mut().unwrap();
            k.end_wait(want);
            k.complete_syscall(&mut regs, nr, &args, r);
        }
        KERNEL.deliver_pending(&mut regs);
    } else if let Some(r) = {
        // SAFETY: guest pointers in `args` reference guest memory.
        unsafe { fwe_kernel::blocking_syscall(nr, args) }
    } {
        KERNEL.finish(&mut regs, nr, &args, r);
    } else {
        KERNEL.syscall(&mut regs);
    }
    fwe_kernel::timing::call_done(nr, began);
    // The exit's stop, its result in `x0`.
    if syscall_stops {
        KERNEL.syscall_stop(&mut regs, false);
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
    fwe_kernel::timing::signal(sig);
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
            fwe_kernel::signal::take_notes();
        } else {
            let info = sent();
            let lsig = host::signal_to_linux(sig);
            // A stop signal from the host (its terminal's), or one fwe sends
            // as the host's, is pending as of now.
            if fwe_kernel::signal::stops(lsig) {
                fwe_kernel::signal::stop_sent_now();
            }
            // The host's SIGCONT is the guest's only from outside fwe.
            if lsig == fwe_abi::signal::SIGCONT && !fwe_kernel::signal::host_continued(info.pid) {
                return;
            }
            if in_fork_child() {
                // Kept until the child forgets its parent's signals.
                keep_early(lsig, info);
            } else if REROUTING.with(Cell::get) {
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
        // and ends the process. That code might be in the host allocator.
        let _no_allocation = host::NoAllocation::enter();
        record();
        if thread::foreign() {
            // A thread a host library made (the Mac's Vulkan driver's,
            // started in a guest's call, its mask the guest's): the signal
            // is the process's (posted above), for the guest's threads to
            // take, woken; and this thread takes no more, the host's own
            // mask on it, which the handler's return sets, blocking all.
            thread::wake_others(host::WAKE_SIGNAL);
            // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO
            // handlers.
            unsafe { (*(ctx as *mut Ucontext)).uc_sigmask = !0 };
            return;
        }
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
    if kernel().is_none() {
        return;
    }
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    let mut regs = regs_from(mc);
    // In a stub, or a translation: the guest's state as at the instruction
    // it stands for, which is what a tracer, a handler's frame or a core
    // sees.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if !prepared_to_guest(&mut regs) && crate::jit::stands_for_program(regs.pc) {
        crate::jit::to_guest(&mut regs);
    }
    KERNEL.deliver_pending(&mut regs);
    settle(&mut regs);
    regs_to(mc, &regs);
    // SAFETY: `ctx` is this handler's ucontext.
    unsafe { return_with_guest_mask(ctx) };
}

/// The `T` at host address `addr`, or `None` where nothing readable is,
/// read through the host's copy of this task's memory, which reports a hole
/// rather than fault. Async-signal-safe.
pub(crate) fn read_host<T: Copy + Default>(addr: u64) -> Option<T> {
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

/// `regs` stopped in a stub fwe prepared: the program's state, as at its
/// site or past it ([`crate::prepare::stub_to_guest`]). `false` if
/// `regs.pc` is in none.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepared_to_guest(regs: &mut Regs) -> bool {
    match crate::prepare::stub_to_guest(regs.pc, &mut regs.x) {
        Some(pc) => {
            regs.pc = pc;
            true
        }
        None => false,
    }
}

/// A fault on an access through `x18` (fwe's TSD base, which the host
/// zeroed when it last entered the kernel): its group starts again from
/// its `mrs x18` ([`crate::rewrite::TSD18`]), or the gate from its start
/// ([`crate::gate::restart`]). True if so. Async-signal-safe.
fn x18_restart(ss: &mut ThreadState, addr: u64) -> bool {
    if addr >= 1 << 32 {
        return false;
    }
    if let Some(to) = crate::gate::restart(ss.pc) {
        ss.pc = to;
        return true;
    }
    match crate::rewrite::restart_at(read_host::<u32>, ss.pc) {
        Some(to) => {
            ss.pc = to;
            true
        }
        None => false,
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

/// The Linux signal of host fault `host`, whose access the page's
/// protection allowed (`allowed`, read once for the fault) or not: macOS
/// reports an access the protection forbids, on some mappings, as
/// `SIGBUS`, which Linux reports as `SIGSEGV` (keeping `SIGBUS` for memory
/// past a mapped file's end, whose protection allows the access).
fn linux_fault_signal(host: libc::c_int, allowed: bool) -> u64 {
    if host == libc::SIGBUS && !allowed {
        return fwe_abi::signal::SIGSEGV;
    }
    fault_signal(host)
}

/// Whether the host's protection of the page at `addr` allows the access
/// whose syndrome is `esr`. Below the lowest address the host lets a
/// process map (a null pointer's access, as a JIT's implicit null checks
/// make), nothing is mapped, and the host is not asked.
fn allowed_now(addr: u64, esr: u32) -> bool {
    if addr < crate::loader::host_min_address() {
        return false;
    }
    let Some(r) = fwe_kernel::mm::region::query(addr).filter(|r| r.start <= addr) else {
        return false;
    };
    let needed = if (esr >> 26) & 0x3f == ESR_EC_INSTRUCTION_ABORT_LOWER {
        libc::PROT_EXEC
    } else if esr & (1 << 6) != 0 {
        libc::PROT_WRITE
    } else {
        libc::PROT_READ
    };
    r.protection & needed == needed
}

thread_local! {
    /// The address of the fault this thread last tried again as allowed,
    /// and [`fwe_kernel::mm::protection_changes`] then.
    static RETRIED: Cell<(u64, u64)> = const { Cell::new((0, u64::MAX)) };
}

/// A fault at `addr` that the page allows now is tried again, unless it is
/// the one this thread last tried again and no mapping or protection has
/// changed since.
fn stale_fault(addr: u64) -> bool {
    let now = (addr, fwe_kernel::mm::protection_changes());
    RETRIED.with(|r| r.replace(now)) != now
}

/// The `ESR_EL1` exception class of an instruction fetch fault at EL0.
const ESR_EC_INSTRUCTION_ABORT_LOWER: u32 = 0x20;

/// The pid of a process forking, from before its host `fork` until its
/// child is set up (in the child) or the fork has returned (in the
/// parent); 0 otherwise.
pub static FORKING: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// A signal another process sent a fork child before it was set up (one
/// of those not held across the host `fork`, [`FORKING`]): the Linux
/// signal (0: none), then what it carries.
static EARLY_SIG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EARLY_FROM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EARLY_CODE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EARLY_VALUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Whether this is a fork child not yet set up, whose pending signals are
/// still to be forgotten as its parent's. Async-signal-safe.
fn in_fork_child() -> bool {
    let forking = FORKING.load(std::sync::atomic::Ordering::SeqCst);
    forking != 0 && forking != host::pid_now().get()
}

/// Keep Linux signal `sig`, carrying `info`, for [`post_early`].
/// Async-signal-safe.
fn keep_early(sig: u64, info: thread::SigInfo) {
    use std::sync::atomic::Ordering::SeqCst;
    EARLY_FROM.store(u64::from(info.pid as u32) | u64::from(info.uid) << 32, SeqCst);
    EARLY_CODE.store(u64::from(info.code as u32) | u64::from(info.status as u32) << 32, SeqCst);
    EARLY_VALUE.store(info.value, SeqCst);
    EARLY_SIG.store(sig, SeqCst);
}

/// In a fork child, set up: post the signal it was sent before it was
/// ([`keep_early`]), as the process's.
pub fn post_early() {
    use std::sync::atomic::Ordering::SeqCst;
    FORKING.store(0, SeqCst);
    let sig = EARLY_SIG.swap(0, SeqCst);
    if sig == 0 {
        return;
    }
    let (from, code) = (EARLY_FROM.load(SeqCst), EARLY_CODE.load(SeqCst));
    let info = thread::SigInfo {
        code: code as u32 as i32,
        pid: from as u32 as i32,
        uid: (from >> 32) as u32,
        status: (code >> 32) as u32 as i32,
        value: EARLY_VALUE.load(SeqCst),
        poll: None,
    };
    thread::post_process(sig, info);
}

/// ESR's exception classes for a misaligned `pc` and `sp`.
const ESR_EC_PC_ALIGNMENT: u32 = 0x22;
const ESR_EC_SP_ALIGNMENT: u32 = 0x26;

extern "C" fn on_fault(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    fwe_kernel::timing::signal(sig);
    // A process that sends itself one of these signals has it emulated (see
    // `Kernel::sys_kill`), so here it is a fault, or a signal sent by
    // another process, which macOS's siginfo does not tell apart (it gives
    // a sent one the thread's last fault). Another fwe process leaves a
    // note before it sends one ([`fwe_kernel::signote`]): that one is a
    // signal for the guest, whatever this thread was running. (A genuine
    // fault that coincides with a note faults again, without one.)
    if let Some(note) = fwe_kernel::signote::take(sig) {
        let lsig = host::signal_to_linux(sig);
        take_async(sig, || host::sent_info(lsig, note), ctx, guest_interrupted(ctx));
        return;
    }
    // A fault signal whose syndrome is no abort of the instruction it
    // interrupts was left pending by the host: a thread's instruction
    // faulted as another signal was being delivered to it, and this one
    // came once the handler unblocked signals, somewhere else (in fwe's
    // code, or the guest's handler). The instruction runs again when its
    // thread gets back to it, and faults again if it still does, as if the
    // other signal had come just before it. One another process sent is a
    // signal for the guest.
    if matches!(sig, libc::SIGSEGV | libc::SIGBUS) {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let esr = unsafe { (*(*(ctx as *mut Ucontext)).uc_mcontext).es.esr };
        if !matches!((esr >> 26) & 0x3f, 0x20 | 0x21 | 0x22 | 0x24 | 0x25 | 0x26) {
            // SAFETY: `info` is valid for SA_SIGINFO handlers.
            if unsafe { (*info).si_code } > 0 && unsafe { (*info).si_code } < 0x10000 {
                return;
            }
            // SAFETY: `info` is valid for SA_SIGINFO handlers.
            take_async(
                sig,
                || unsafe { host::signal_info(sig, info) },
                ctx,
                guest_interrupted(ctx),
            );
            return;
        }
    }
    // An access through `x18` that the host zeroed meanwhile: its group
    // runs again (in a stub, a translation or the gate).
    if matches!(sig, libc::SIGSEGV | libc::SIGBUS) {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers;
        // `info` is valid for them.
        let (ss, addr) =
            unsafe { (&mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss, (*info).si_addr() as u64) };
        if x18_restart(ss, addr) {
            return;
        }
    }
    let in_guest = guest_interrupted(ctx);
    if in_guest {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
        // The first run of a page of code whose preparation was left until
        // it runs: finished, and the guest runs on.
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        let addr = unsafe { (*info).si_addr() } as u64;
        if fwe_kernel::lazycode::fault(ss.pc, addr) {
            return;
        }
    }
    if !in_guest {
        // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
        let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
        if let Some(resume) = fwe_kernel::uaccess::fixup(ss.pc) {
            // A guest pointer the kernel was copying through was bad: the
            // copy reports EFAULT.
            ss.pc = resume;
            return;
        }
        // Anywhere else in fwe's own code (the kernel lock might be held):
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
    if let Some(word) = (sig == libc::SIGILL)
        // SAFETY: a SIGILL's instruction was fetched, so `pc` is mapped (a
        // fetch's fault can leave it unmapped).
        .then(|| unsafe { insn(mc.ss.pc) })
        .flatten()
        .filter(|&w| crate::hwcap::is_mrs_ctr_el0(w))
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

    // Code the guest made executable after mapping it runs by translation:
    // a fetch from it goes on at its translation.
    let exec = (mc.es.esr >> 26) & 0x3f == ESR_EC_INSTRUCTION_ABORT_LOWER;
    let held = (0..31)
        .filter(|&r| match r {
            29 => mc.ss.fp,
            30 => mc.ss.lr,
            r => mc.ss.x[r],
        } == addr)
        .fold(0, |m, r| m | 1 << r);
    if exec && let Some(t) = crate::jit::enter(addr, mc.ss.lr, held, (mc.ss.x[16], mc.ss.x[17])) {
        mc.ss.pc = t;
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
    // An access the page allows now: another thread changed its protection
    // (or mapped it) after this one faulted, so it is tried again; one that
    // faults again with nothing changed meanwhile (memory past a mapped
    // file's end) stands.
    let allowed = allowed_now(addr, mc.es.esr);
    if allowed && !fwe_kernel::mm::poisoned(addr) && stale_fault(addr) {
        return;
    }

    // Offer the fault to a guest handler; if one is installed, enter it.
    let mut regs = regs_from(mc);
    if exec {
        fetch_fault_report(&regs);
    }
    // A fault in a stub is the program's own instruction's, at its site
    // (a JIT's null checks fault on purpose, and its handler looks for
    // the instruction it wrote).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if !prepared_to_guest(&mut regs) {
        // In a translation: the guest's instruction it stands for.
        crate::jit::to_guest(&mut regs);
    }
    // Memory `MADV_HWPOISON` poisoned fails with a bus error, and so does
    // a misaligned `sp` or `pc`, at it (macOS gives a `SIGSEGV` without
    // an address for `sp`).
    let ec = (mc.es.esr >> 26) & 0x3f;
    let (lsig, addr) = if ec == ESR_EC_SP_ALIGNMENT {
        (fwe_abi::signal::SIGBUS, regs.sp)
    } else if ec == ESR_EC_PC_ALIGNMENT {
        (fwe_abi::signal::SIGBUS, regs.pc)
    } else if fwe_kernel::mm::poisoned(addr) {
        (fwe_abi::signal::SIGBUS, addr)
    } else {
        (linux_fault_signal(sig, allowed), addr)
    };
    // The fault's syndrome, as the host had it from the processor.
    let esr = Some(u64::from(mc.es.esr));
    let delivered = KERNEL.deliver_fault(&mut regs, lsig, addr, esr);
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
        // Read as the host copies: a fetch's fault leaves `pc` unmapped.
        let word = read_host::<u32>(mc.ss.pc).map_or(String::from("?"), |w| format!("{w:#010x}"));
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
        // Where the program was: pc, lr, and the frames' return addresses.
        let mut places = format!(
            "[fwe] pc in {}, lr in {}",
            fwe_kernel::maps::place_of(mc.ss.pc).as_deref().unwrap_or("?"),
            fwe_kernel::maps::place_of(mc.ss.lr).as_deref().unwrap_or("?")
        );
        let mut fp = mc.ss.fp;
        for _ in 0..16 {
            // A frame record: the caller's fp, then its return address.
            let (Some(next), Some(ret)) = (read_host::<u64>(fp), read_host::<u64>(fp + 8)) else {
                break;
            };
            if ret == 0 {
                break;
            }
            let ret = ret & 0x0000_ffff_ffff_ffff;
            let at = fwe_kernel::maps::place_of(ret);
            places.push_str(&format!(", {ret:#x} in {}", at.as_deref().unwrap_or("?")));
            if next <= fp {
                break;
            }
            fp = next;
        }
        places.push('\n');
        report(&places);
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
    // Read as the host copies: a fetch's fault leaves `pc` unmapped.
    let word = read_host::<u32>(mc.ss.pc).map_or(String::from("?"), |w| format!("{w:#010x}"));
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
    install_thread_altstack();
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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

/// Make the mapping at `stack` (an ended thread's, [`crate::stacks`]) this
/// thread's signal stack.
pub fn use_altstack(stack: u64) {
    let ss = libc::stack_t {
        ss_sp: stack as *mut libc::c_void,
        ss_size: SIGNAL_STACK_SIZE,
        ss_flags: 0,
    };
    // SAFETY: a mapping of the signal stack's size, this thread's alone.
    assert_eq!(unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) }, 0, "sigaltstack failed");
}

/// This thread's signal stack, if it has one.
pub fn altstack_mapping() -> Option<u64> {
    // SAFETY: querying this thread's signal stack into a zeroed stack_t.
    unsafe {
        let mut old: libc::stack_t = std::mem::zeroed();
        (libc::sigaltstack(std::ptr::null(), &mut old) == 0 && old.ss_flags & libc::SS_DISABLE == 0)
            .then_some(old.ss_sp as u64)
    }
}

/// Give the calling thread a fresh signal stack, with a guard below it
/// ([`host::GUARD`]): a handler nested past its room faults there, and the
/// process ends, instead of writing over the mapping below. Kept for the
/// life of the thread, then given to a later one ([`crate::stacks`]).
pub fn install_thread_altstack() {
    let stack = host::map_stack(SIGNAL_STACK_SIZE).expect("allocating the signal stack failed");
    use_altstack(stack as u64);
}

/// Install the per-thread signal stack and the process-wide handlers for
/// running guest code (called once on the main thread).
pub fn install_handlers() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    crate::jit::configure();
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
/// `regs` MUST point to a valid [`Regs`] describing a runnable guest context.
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
