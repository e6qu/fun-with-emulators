//! Guest entry and trap handling on macOS arm64.
//!
//! Guest code runs on the host thread that entered it. Rewritten system calls
//! raise `SIGTRAP`; the handler runs on its own signal stack, executes the
//! Linux system call against the guest's saved registers and returns, which
//! resumes the guest after the trap with `x0` holding the result.

use crate::rewrite::TRAP;
use crate::{KERNEL, NativePlatform};
use fwe_kernel::Kernel;
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

extern "C" fn on_sigtrap(_sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let ss = unsafe { &mut (*(*(ctx as *mut Ucontext)).uc_mcontext).ss };
    // The saved pc is the trapping instruction for `brk`.
    // SAFETY: the guest was executing at `pc`, so it is mapped.
    if unsafe { insn(ss.pc) } != Some(TRAP) {
        // Not one of our system call traps: let it take its default action.
        restore_default(libc::SIGTRAP);
        return;
    }
    let nr = ss.x[8];
    let args = [ss.x[0], ss.x[1], ss.x[2], ss.x[3], ss.x[4], ss.x[5]];
    let result = match kernel().as_mut() {
        Some(k) => k.syscall(nr, args),
        None => {
            report("fwe: system call before the kernel was initialized\n");
            // SAFETY: terminating the process.
            unsafe { libc::_exit(127) }
        }
    };
    ss.x[0] = result as u64;
    ss.pc += 4;
}

extern "C" fn on_fault(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let mc = unsafe { &*(*(ctx as *mut Ucontext)).uc_mcontext };
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
    }
    // Returning re-executes the faulting instruction under the default action.
    restore_default(sig);
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

/// Install the signal stack and handlers for running guest code on this
/// thread.
pub fn install_handlers() {
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
    install(libc::SIGTRAP, on_sigtrap);
    for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
        install(sig, on_fault);
    }
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
