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

pub mod host;
mod mm;
mod syscalls;
mod trace;

pub use mm::Brk;
pub use trace::Tracer;

use fwe_abi::{Sigaction, Stack, signal};

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
    pub(crate) sigactions: [Sigaction; signal::NSIG as usize],
    pub(crate) sigmask: u64,
    pub(crate) altstack: Stack,
    pub(crate) clear_child_tid: u64,
    pub(crate) robust_list: (u64, u64),
}

impl<P: Platform> Kernel<P> {
    pub fn new(platform: P, page_size: u64, brk: Brk, tracer: Tracer) -> Self {
        Kernel {
            platform,
            tracer,
            page_size,
            brk,
            sigactions: [Sigaction::default(); signal::NSIG as usize],
            sigmask: 0,
            altstack: Stack { ss_flags: libc::SS_DISABLE, ..Stack::default() },
            clear_child_tid: 0,
            robust_list: (0, 0),
        }
    }

    /// Execute Linux system call `nr` with `args` and return the raw result:
    /// a value, or a negated Linux errno.
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> i64 {
        let result = self.dispatch(nr, args);
        self.tracer.syscall(nr, &args, result);
        result
    }
}
