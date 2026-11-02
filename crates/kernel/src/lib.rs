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

pub mod epoll;
pub mod fs;
mod fsops;
pub mod futex;
pub mod host;
mod mm;
pub mod net;
pub mod procfs;
mod signal;
pub mod specialfd;
mod syscalls;
pub mod thread;
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

    /// Terminate the whole process with `code` as its exit status
    /// (`exit_group`).
    fn exit(&mut self, code: i32) -> !;

    /// Terminate just the calling thread (`exit`); ends the process when it is
    /// the last thread.
    fn exit_thread(&mut self, code: i32) -> !;

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

    /// Reset the signal and per-thread state across a successful `execve`:
    /// handlers return to default, pending signals and the alternate stack are
    /// cleared, and the `set_tid_address`/robust-list words are forgotten. The
    /// blocked mask is preserved, as Linux does.
    pub fn exec_reset(&mut self) {
        self.sigactions = [Sigaction::default(); absig::NSIG as usize];
        self.pending = 0;
        self.altstack = Stack { ss_flags: libc::SS_DISABLE, ..Stack::default() };
        thread::set_clear_child_tid(0);
        thread::set_robust_list(0, 0);
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

    /// Record the result of a system call for `--strace`, then store it into
    /// `regs` and advance past the trap. Used by the backend for system calls
    /// it runs outside the kernel lock (the blocking ones and `clone`).
    pub fn finish_syscall(&mut self, regs: &mut Regs, nr: u64, args: &[u64; 6], result: i64) {
        self.tracer.syscall(nr, args, result);
        regs.x[0] = result as u64;
        regs.pc = regs.pc.wrapping_add(4);
        self.deliver_pending(regs);
    }

    /// Per-thread cleanup when a thread exits: clear and wake the
    /// `set_tid_address` futex word so `pthread_join` completes.
    pub fn thread_cleanup(&mut self) {
        thread_exit_cleanup();
    }
}

/// Clear and wake this thread's `set_tid_address` futex word, so a joiner
/// wakes. Touches only thread-local state and guest memory, so the backend
/// calls it on thread exit without holding the kernel lock.
pub fn thread_exit_cleanup() {
    let addr = thread::clear_child_tid();
    if addr != 0 {
        // SAFETY: the guest registered this address with set_tid_address.
        unsafe { (addr as *mut u32).write(0) };
        wake_futex(addr, 1);
    }
}

/// Wake up to `count` waiters on the futex word at `addr`.
pub fn wake_futex(addr: u64, count: u32) {
    // SAFETY: `addr` is a guest futex word; wake only reads waiter counts.
    unsafe {
        futex::op(addr, fwe_abi::futex::FUTEX_WAKE, count, 0);
    }
}

/// Run a system call that must not hold the kernel lock because it can block
/// (`futex`, `nanosleep`, `clock_nanosleep`). Returns `None` for any other
/// call, which the backend runs under the lock through [`Kernel::enter_syscall`].
///
/// # Safety
/// Pointer arguments must reference valid guest memory for the call.
pub unsafe fn blocking_syscall(nr: u64, a: [u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    Some(match nr {
        // SAFETY: caller guarantees the futex word and timeout are valid.
        n::FUTEX => unsafe { futex::op(a[0], a[1], a[2] as u32, a[3]) },
        n::NANOSLEEP => {
            // SAFETY: `struct timespec` has the same layout; the host validates it.
            host::ret(unsafe { libc::nanosleep(a[0] as *const _, a[1] as *mut _) })
        }
        // SAFETY: caller guarantees the request/remain pointers are valid.
        n::CLOCK_NANOSLEEP => unsafe { syscalls::clock_nanosleep(a[0], a[1], a[2], a[3]) },
        // SAFETY: caller guarantees the events and sigmask pointers are valid.
        n::EPOLL_PWAIT => unsafe { epoll::pwait(a[0], a[1], a[2], a[3], a[4], a[5]) },
        // read/write on an eventfd/timerfd can block and must not hold the
        // kernel lock; `try_*` returns None for any other descriptor, so a
        // normal read/write falls through to the locked host path.
        // SAFETY: caller guarantees the buffer spans the length.
        n::READ => return unsafe { specialfd::try_read(a[0] as i32, a[1], a[2]) },
        // SAFETY: caller guarantees the buffer spans the length.
        n::WRITE => return unsafe { specialfd::try_write(a[0] as i32, a[1], a[2]) },
        // Socket calls that can block run without the kernel lock, so a thread
        // waiting in accept/recv does not stall the threads meant to feed it.
        // SAFETY: caller guarantees the sockaddr pointer.
        n::CONNECT => unsafe { net::connect(a[0], a[1], a[2]) },
        // SAFETY: caller guarantees the out pointers.
        n::ACCEPT => unsafe { net::accept4(a[0], a[1], a[2], 0) },
        // SAFETY: caller guarantees the out pointers.
        n::ACCEPT4 => unsafe { net::accept4(a[0], a[1], a[2], a[3]) },
        // SAFETY: caller guarantees the buffer and sockaddr.
        n::SENDTO => unsafe { net::sendto(a[0], a[1], a[2], a[3], a[4], a[5]) },
        // SAFETY: caller guarantees the buffer and out pointers.
        n::RECVFROM => unsafe { net::recvfrom(a[0], a[1], a[2], a[3], a[4], a[5]) },
        // SAFETY: caller guarantees the msghdr.
        n::SENDMSG => unsafe { net::sendmsg(a[0], a[1], a[2]) },
        // SAFETY: caller guarantees the msghdr.
        n::RECVMSG => unsafe { net::recvmsg(a[0], a[1], a[2]) },
        _ => return None,
    })
}
