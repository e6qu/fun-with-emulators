//! The Linux kernel layer: Linux system call semantics implemented on top of
//! the host.
//!
//! The kernel is independent of how guest code is executed. An execution
//! backend traps guest system calls and calls [`Kernel::syscall`], and
//! provides the few operations the kernel needs from it through [`Platform`].
//!
//! Guest addresses are host addresses: every backend maps guest memory at the
//! same virtual addresses in the host process, so guest pointers can be used
//! directly and are often handed straight to host system calls, which validate
//! them.

pub mod fs;
mod fsops;
pub mod host;
mod mm;
mod signal;
mod syscalls;
mod trace;

pub use fs::Fs;
pub use mm::Brk;
pub use trace::Tracer;

use fwe_abi::{Sigaction, Stack, signal as absig};

/// The guest's general-purpose register file, as the backend exposes it to
/// the kernel for one trap. `x[30]` is the link register; `pstate` is the
/// condition/execution state (`cpsr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// Services the kernel needs from the execution backend.
pub trait Platform {
    /// Make guest code in `[addr, addr + len)` safe to execute.
    ///
    /// The memory is readable and writable when this is called; the kernel
    /// applies the final protections afterwards. Fails with a Linux errno.
    fn prepare_exec(&mut self, addr: u64, len: u64) -> Result<(), i32>;

    /// Terminate the guest with `code` as its exit status.
    fn exit(&mut self, code: i32) -> !;

    /// Terminate the guest as if killed by host signal `sig`.
    fn kill_self(&mut self, sig: libc::c_int) -> !;
}

/// Kernel state for one guest process.
pub struct Kernel<P: Platform> {
    pub platform: P,
    pub tracer: Tracer,
    /// Host page size; guest-visible page size is the same.
    pub page_size: u64,
    pub brk: Brk,
    /// The guest's filesystem, when configured.
    pub fs: Option<Fs>,
    pub(crate) sigactions: [Sigaction; absig::NSIG as usize],
    pub(crate) sigmask: u64,
    pub(crate) altstack: Stack,
    /// Signals raised against this process, awaiting delivery.
    pub(crate) pending: u64,
    /// Guest address of the `rt_sigreturn` trampoline, set by the backend.
    pub(crate) sigreturn_tramp: u64,
    pub(crate) clear_child_tid: u64,
    pub(crate) robust_list: (u64, u64),
}

impl<P: Platform> Kernel<P> {
    pub fn new(platform: P, page_size: u64, brk: Brk, fs: Option<Fs>, tracer: Tracer) -> Self {
        Kernel {
            platform,
            tracer,
            page_size,
            brk,
            fs,
            sigactions: [Sigaction::default(); absig::NSIG as usize],
            sigmask: 0,
            altstack: Stack { ss_flags: libc::SS_DISABLE, ..Stack::default() },
            pending: 0,
            sigreturn_tramp: 0,
            clear_child_tid: 0,
            robust_list: (0, 0),
        }
    }

    /// Point the kernel at the guest `rt_sigreturn` trampoline (a few
    /// instructions ending in the `rt_sigreturn` system call) used as the
    /// return address for handlers without their own `sa_restorer`.
    pub fn set_sigreturn_trampoline(&mut self, addr: u64) {
        self.sigreturn_tramp = addr;
    }

    /// Execute Linux system call `nr` with `args` and return the raw result:
    /// a value, or a negated Linux errno. Does not deliver signals; used by
    /// callers that do not expose a register file.
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> i64 {
        let result = self.dispatch(nr, args);
        self.tracer.syscall(nr, &args, result);
        result
    }

    /// Run the system call named in `regs` (number in `x8`, arguments in
    /// `x0`–`x5`), store its result and advance past the trap, then deliver a
    /// pending signal if one is ready. `rt_sigreturn` restores `regs` from the
    /// signal frame instead.
    pub fn enter_syscall(&mut self, regs: &mut Regs) {
        if regs.x[8] == fwe_abi::nr::RT_SIGRETURN {
            self.sys_rt_sigreturn(regs);
            self.tracer.syscall(regs.x[8], &[0; 6], regs.x[0] as i64);
            return;
        }
        let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
        let nr = regs.x[8];
        let result = self.dispatch(nr, args);
        self.tracer.syscall(nr, &args, result);
        regs.x[0] = result as u64;
        regs.pc = regs.pc.wrapping_add(4);
        self.deliver_pending(regs);
    }

    /// Deliver synchronous fault signal `sig` (at `addr`) to a guest handler,
    /// returning `true` if a handler was entered. When `false`, the caller
    /// takes the default action (terminate).
    pub fn deliver_fault(&mut self, regs: &mut Regs, sig: u64, addr: u64) -> bool {
        self.deliver_to_handler(regs, sig, fwe_abi::signal::SI_KERNEL, addr)
    }
}
