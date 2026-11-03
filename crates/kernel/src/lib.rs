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

pub mod creds;
pub mod epoll;
pub mod fdtable;
pub mod fs;
mod fsops;
pub mod futex;
pub mod host;
pub mod mm;
pub mod net;
pub mod procfs;
pub mod pty;
pub mod signal;
pub mod signalfd;
pub mod specialfd;
pub mod synthdir;
mod syscalls;
pub mod term;
pub mod thread;
mod trace;
pub mod uaccess;

pub use fs::Fs;
pub use mm::Brk;
pub use trace::Tracer;

use fwe_abi::{Sigaction, Stack, signal as absig};

/// The guest's register file, as the backend exposes it to the kernel for one
/// trap. `x[30]` is the link register; `pstate` is the condition/execution
/// state (`cpsr`). The general-purpose registers come first, at fixed offsets
/// the backend's entry code relies on.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// Floating-point and SIMD state, saved and restored across a signal
    /// handler.
    pub fp: FpRegs,
}

/// The `v0`–`v31` registers and the floating-point status and control
/// registers.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FpRegs {
    pub v: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
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

    /// Stop the process, as the default action of `SIGTSTP` and friends
    /// does, until it is continued.
    fn stop_self(&mut self) {}

    /// Set how the host treats Linux signal `sig` (one with a host
    /// equivalent; see [`signal::relayed`]) so that signals sent to this
    /// process by other processes, the terminal or the host itself reach
    /// the guest as the guest asked.
    fn set_host_signal(&mut self, _sig: u64, _how: HostSignal) {}
}

/// How the host should treat one signal on the guest's behalf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSignal {
    /// The host's default action, which matches Linux's for every relayed
    /// signal (terminate, ignore, stop or continue).
    Default,
    /// Discard it.
    Ignore,
    /// Catch it and record it pending for the guest (with
    /// [`thread::post_self`]): the guest has a handler, or a `signalfd`
    /// reads it. `flags` are the guest's `sa_flags`, for `SA_NOCLDSTOP` and
    /// `SA_NOCLDWAIT`.
    Catch { flags: u64 },
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
    /// The guest's virtual user/group identity.
    pub creds: creds::Creds,
    /// Signal dispositions, shared by all threads. The blocked mask, the
    /// alternate stack and pending signals are per thread (see [`thread`]).
    pub(crate) sigactions: [Sigaction; absig::NSIG as usize],
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
            creds: creds::Creds::default(),
            sigactions: [Sigaction::default(); absig::NSIG as usize],
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
    /// caught signals return to their default action, the alternate stack is
    /// disabled, and the `set_tid_address`/robust-list words are forgotten.
    /// Ignored signals stay ignored, and the blocked mask and pending signals
    /// are kept, as Linux does.
    pub fn exec_reset(&mut self) {
        for action in &mut self.sigactions {
            let ignored = action.handler == absig::SIG_IGN;
            *action = Sigaction::default();
            if ignored {
                action.handler = absig::SIG_IGN;
            }
        }
        self.sync_all_host_signals();
        thread::set_altstack(Stack { ss_flags: absig::SS_DISABLE, ..Stack::default() });
        thread::set_clear_child_tid(0);
        thread::set_robust_list(0, 0);
    }

    /// Adopt the dispositions this process inherited: a signal the host
    /// ignores at startup (`nohup`, a shell's background job) starts out
    /// ignored in the guest too, as it would across a Linux `execve`. Every
    /// other relayed signal is put back to its default action on the host.
    /// `SIGPIPE` is always reset: the Rust runtime ignores it before `main`,
    /// so its inherited disposition is lost.
    pub fn adopt_host_signals(&mut self) {
        for sig in 1..=absig::NSIG {
            if !signal::relayed(sig) || sig == absig::SIGPIPE {
                continue;
            }
            if host::signal_is_ignored(sig) {
                self.sigactions[(sig - 1) as usize].handler = absig::SIG_IGN;
            }
        }
        self.sync_all_host_signals();
    }

    /// Close every descriptor marked close-on-exec, as `execve` does before
    /// entering the new program. fwe's own descriptors carry the flag too,
    /// but sit above the guest's range ([`fdtable`]), so they are kept.
    pub fn close_on_exec(&mut self) {
        for fd in fdtable::open_fds() {
            // SAFETY: plain host call on an open guest descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
                self.dispatch(fwe_abi::nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            }
        }
    }

    /// Run the system call named in `regs` (number in `x8`, arguments in
    /// `x0`–`x5`), store its result and advance past the trap, then deliver a
    /// pending signal if one is ready. `rt_sigreturn` restores `regs` from the
    /// signal frame instead.
    pub fn enter_syscall(&mut self, regs: &mut Regs) {
        if regs.x[8] == fwe_abi::nr::RT_SIGRETURN {
            if !self.sys_rt_sigreturn(regs) {
                // A frame the guest cannot read back: Linux kills it.
                self.terminate_by(absig::SIGSEGV);
            }
            self.tracer.syscall(regs.x[8], &[0; 6], regs.x[0] as i64);
            return;
        }
        let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
        let nr = regs.x[8];
        let result = self.dispatch(nr, args);
        self.finish_syscall(regs, nr, &args, result);
    }

    /// Record the result of a system call for `--strace`, then store it into
    /// `regs` and advance past the trap, and deliver a pending signal. Used
    /// directly by the backend for the system calls it runs outside the
    /// kernel lock (the blocking ones and `clone`).
    ///
    /// A call the host interrupted (`EINTR`) is handled as Linux does: if no
    /// guest handler is about to run, the signal that interrupted it was one
    /// the guest does not see (blocked for a `signalfd`, or ignored), so the
    /// call runs again; if the handler has `SA_RESTART` and the call is one
    /// Linux restarts, it runs again after the handler returns; otherwise the
    /// guest gets `EINTR` once the handler returns.
    pub fn finish_syscall(&mut self, regs: &mut Regs, nr: u64, args: &[u64; 6], result: i64) {
        self.tracer.syscall(nr, args, result);
        if result == fwe_abi::err(fwe_abi::errno::EINTR) {
            signal::drain_to_signalfd();
            let rerun = match self.next_handler() {
                None => true,
                Some(action) => {
                    action.flags & absig::SA_RESTART != 0 && signal::restartable(nr, args)
                }
            };
            if rerun {
                // Leave pc on the trap and x0 holding the first argument, so
                // the call is made again (after any handler returns).
                self.deliver_pending(regs);
                return;
            }
        }
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
    thread::unregister_current();
    let addr = thread::clear_child_tid();
    if addr != 0 {
        // Linux ignores a fault here too: the word is simply not cleared.
        if uaccess::write(addr, 0u32).is_ok() {
            wake_futex(addr, 1);
        }
    }
}

/// Host `fork` with every lock the kernel's own registries use held, so that
/// in a multithreaded guest the child cannot inherit one locked by a thread
/// that does not exist in it. The caller holds the kernel lock itself. The
/// locks are released in both processes.
pub fn fork_locked() -> libc::pid_t {
    signalfd::hold(|| {
        specialfd::hold(|| {
            synthdir::hold(|| {
                pty::hold(|| {
                    net::hold(|| {
                        futex::hold(|| {
                            mm::hold(|| {
                                // SAFETY: plain host call; the child continues
                                // with only the calling thread, as on Linux.
                                thread::hold(|| unsafe { libc::fork() })
                            })
                        })
                    })
                })
            })
        })
    })
}

/// Wake up to `count` waiters on the futex word at `addr`.
pub fn wake_futex(addr: u64, count: u32) {
    // SAFETY: `addr` is a guest futex word; wake only reads waiter counts.
    unsafe {
        futex::op(addr, fwe_abi::futex::FUTEX_WAKE, count, 0);
    }
}

/// Run a system call that must not hold the kernel lock because it can block:
/// `futex`, the sleeps, `epoll_pwait`, `ppoll`, `rt_sigsuspend`, the socket
/// calls that wait,
/// and `read`/`write` and their vectored and positioned forms (a pipe, socket
/// or terminal blocks until the other side acts, and the other side may be a
/// guest thread that needs the lock). Returns `None` for any other call,
/// which the backend runs under the lock through [`Kernel::enter_syscall`].
///
/// # Safety
/// Pointer arguments must reference valid guest memory for the call.
pub unsafe fn blocking_syscall(nr: u64, a: [u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    if let Err(e) = fdtable::check_args(nr, &a) {
        return Some(e);
    }
    Some(match nr {
        // SAFETY: caller guarantees the futex word and timeout are valid.
        n::FUTEX => unsafe { futex::op(a[0], a[1], a[2] as u32, a[3]) },
        // On macOS `nanosleep` reads and writes its arguments in the C
        // library, unchecked, so it goes through `clock_nanosleep`'s copies.
        // SAFETY: the arguments are checked guest pointers.
        n::NANOSLEEP => unsafe {
            syscalls::clock_nanosleep(fwe_abi::clock::CLOCK_MONOTONIC, 0, a[0], a[1])
        },
        // SAFETY: caller guarantees the request/remain pointers are valid.
        n::CLOCK_NANOSLEEP => unsafe { syscalls::clock_nanosleep(a[0], a[1], a[2], a[3]) },
        // SAFETY: caller guarantees the events and sigmask pointers are valid.
        n::EPOLL_PWAIT => unsafe {
            signal::with_call_mask(a[4], || epoll::pwait(a[0], a[1], a[2], a[3], 0, 0))
        },
        // read/write on an eventfd/timerfd/signalfd can block and must not hold
        // the kernel lock; `try_*` returns None for any other descriptor, so a
        // normal read/write falls through to the locked host path.
        n::READ => {
            let (fd, buf, len) = (a[0] as i32, a[1], a[2]);
            // SAFETY: caller guarantees the buffer spans the length.
            if let Some(r) = unsafe { specialfd::try_read(fd, buf, len) } {
                return Some(r);
            }
            // SAFETY: caller guarantees the buffer spans the length.
            if let Some(r) = unsafe { signalfd::try_read(fd, buf, len) } {
                return Some(r);
            }
            // SAFETY: the host validates the guest buffer.
            host::ret(unsafe { libc::read(fd, buf as *mut _, len as usize) } as i64)
        }
        n::WRITE => {
            let (fd, buf, len) = (a[0] as i32, a[1], a[2]);
            // SAFETY: caller guarantees the buffer spans the length.
            if let Some(r) = unsafe { specialfd::try_write(fd, buf, len) } {
                return Some(r);
            }
            // SAFETY: the host validates the guest buffer.
            host::ret(unsafe { libc::write(fd, buf as *const _, len as usize) } as i64)
        }
        n::READV => {
            // SAFETY: `struct iovec` has the same layout; the host validates it.
            host::ret(unsafe { libc::readv(a[0] as i32, a[1] as *const _, a[2] as i32) } as i64)
        }
        n::WRITEV => {
            // SAFETY: `struct iovec` has the same layout; the host validates it.
            host::ret(unsafe { libc::writev(a[0] as i32, a[1] as *const _, a[2] as i32) } as i64)
        }
        // SAFETY: the host validates the guest buffer.
        n::PREAD64 => host::ret(unsafe {
            libc::pread(a[0] as i32, a[1] as *mut _, a[2] as usize, a[3] as libc::off_t)
        } as i64),
        // SAFETY: the host validates the guest buffer.
        n::PWRITE64 => host::ret(unsafe {
            libc::pwrite(a[0] as i32, a[1] as *const _, a[2] as usize, a[3] as libc::off_t)
        } as i64),
        // SAFETY: caller guarantees the pollfd array and timeout pointers.
        n::PPOLL => unsafe { signal::with_call_mask(a[3], || syscalls::ppoll(a[0], a[1], a[2])) },
        // SAFETY: caller guarantees the signal set pointer.
        n::RT_SIGSUSPEND => unsafe { signal::sigsuspend(a[0], a[1]) },

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
