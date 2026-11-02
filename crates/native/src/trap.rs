//! Guest entry and trap handling on macOS arm64.
//!
//! Guest code runs on the host thread that entered it. Rewritten system calls
//! raise `SIGTRAP`; the handler runs on its own signal stack, executes the
//! Linux system call against the guest's saved registers and returns, which
//! resumes the guest after the trap with `x0` holding the result.

use crate::rewrite::TRAP;
use crate::{KERNEL, NativePlatform, X18Abi};
use fwe_kernel::{Kernel, Regs};
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

/// Leaves the custom x18 ABI for the duration of a handler, so host code may
/// call macOS libraries, and re-enters it on drop. The guest's x18 is part of
/// the saved signal context and is restored when the handler returns.
struct HostCode(Option<X18Abi>);

impl HostCode {
    fn enter() -> HostCode {
        let abi = X18Abi::get().filter(|abi| abi.enabled());
        if let Some(abi) = abi {
            abi.set_enabled(false);
        }
        HostCode(abi)
    }
}

impl Drop for HostCode {
    fn drop(&mut self) {
        if let Some(abi) = self.0 {
            abi.set_enabled(true);
        }
    }
}

/// Read the backend thread state into the kernel's register view.
fn regs_from(ss: &ThreadState) -> Regs {
    let mut regs = Regs { sp: ss.sp, pc: ss.pc, pstate: ss.cpsr as u64, ..Regs::default() };
    regs.x[..29].copy_from_slice(&ss.x);
    regs.x[29] = ss.fp;
    regs.x[30] = ss.lr;
    regs
}

/// Write the kernel's register view back into the backend thread state.
fn regs_to(ss: &mut ThreadState, regs: &Regs) {
    ss.x.copy_from_slice(&regs.x[..29]);
    ss.fp = regs.x[29];
    ss.lr = regs.x[30];
    ss.sp = regs.sp;
    ss.pc = regs.pc;
    ss.cpsr = regs.pstate as u32;
}

extern "C" fn on_sigtrap(_sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let _host = HostCode::enter();
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
    // The saved pc is the trapping instruction for `brk`.
    // SAFETY: the guest was executing at `pc`, so it is mapped.
    if unsafe { insn(ss.pc) } != Some(TRAP) {
        // Not one of our system call traps: let it take its default action.
        restore_default(libc::SIGTRAP);
        return;
    }
    let mut regs = regs_from(ss);
    if kernel().is_none() {
        report("fwe: system call before the kernel was initialized\n");
        // SAFETY: terminating the process.
        unsafe { libc::_exit(127) }
    }
    let nr = regs.x[8];
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    crate::dbg(&format!("trap tid={} nr={nr} pc={:#x}", fwe_kernel::thread::tid(), regs.pc));

    // `clone` and the blocking system calls run without holding the kernel
    // lock, so a blocked or spawning thread does not stall the others; the
    // kernel is then locked only briefly to record the result and deliver a
    // pending signal.
    if nr == fwe_abi::nr::EXIT {
        // A thread exits without the kernel lock: pthread_exit never returns,
        // so a held lock would never be released.
        crate::dbg(&format!("exit tid={} code={}", fwe_kernel::thread::tid(), regs.x[0] as i32));
        fwe_kernel::thread_exit_cleanup();
        crate::dbg("exit: cleanup done, ending thread");
        crate::exit_current_thread(regs.x[0] as i32);
    }
    if nr == fwe_abi::nr::CLONE {
        let r = crate::threads::do_clone(&regs);
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else if let Some(r) = {
        // SAFETY: guest pointers in `args` reference guest memory.
        unsafe { fwe_kernel::blocking_syscall(nr, args) }
    } {
        kernel().as_mut().unwrap().finish_syscall(&mut regs, nr, &args, r);
    } else {
        kernel().as_mut().unwrap().enter_syscall(&mut regs);
    }
    regs_to(ss, &regs);
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

extern "C" fn on_fault(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let _host = HostCode::enter();
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &mut *(*(ctx as *mut Ucontext)).uc_mcontext };
    // SAFETY: `info` is valid for SA_SIGINFO handlers.
    let addr = unsafe { (*info).si_addr() } as u64;
    crate::dbg(&format!(
        "fault tid={} sig={sig} pc={:#x} addr={addr:#x}",
        fwe_kernel::thread::tid(),
        mc.ss.pc
    ));

    // Offer the fault to a guest handler; if one is installed, enter it.
    let mut regs = regs_from(&mc.ss);
    let delivered =
        kernel().as_mut().is_some_and(|k| k.deliver_fault(&mut regs, fault_signal(sig), addr));
    if delivered {
        regs_to(&mut mc.ss, &regs);
        return;
    }

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
        let mut code = String::from("[fwe] code before pc:");
        for back in (1..=8u64).rev() {
            let at = mc.ss.pc.wrapping_sub(4 * back);
            // Only read within the faulting instruction's page.
            if at & !0x3fff == mc.ss.pc & !0x3fff {
                // SAFETY: same page as the mapped pc.
                if let Some(w) = unsafe { insn(at) } {
                    code.push_str(&format!(" {w:08x}"));
                }
            }
        }
        code.push('\n');
        report(&code);
    }
    // Returning re-executes the faulting instruction under the default action.
    restore_default(sig);
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
    // SAFETY: installing a handler with a fully initialized sigaction.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction({sig}) failed: {}", std::io::Error::last_os_error());
        }
    }
}

/// Give this host thread its own signal stack. Signal dispositions are
/// process-wide, but the alternate stack is per thread, so every thread that
/// runs guest code needs one before it can trap.
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
    for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
        install(sig, on_fault);
    }
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
