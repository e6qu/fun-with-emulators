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

pub mod cloneargs;
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
pub mod snapshot;
pub mod specialfd;
pub mod synthdir;
mod syscalls;
pub mod term;
pub mod thread;
mod trace;
pub mod uaccess;

pub use cloneargs::CloneArgs;
pub use fs::Fs;
pub use mm::Brk;
pub use trace::Tracer;

use fwe_abi::{Sigaction, Stack, signal as absig};
use std::os::fd::AsRawFd;

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

    /// The guest now has `[addr, addr + len)` mapped with Linux protections
    /// `prot`. A backend that runs the guest in an address space of its own
    /// (a VM) maps the same host memory there; the native backend, where the
    /// guest's address space is the host process's, has nothing to do. Fails
    /// with a Linux errno.
    fn map_guest(&mut self, _addr: u64, _len: u64, _prot: u64) -> Result<(), i32> {
        Ok(())
    }

    /// The guest unmapped `[addr, addr + len)`, or is about to replace it.
    /// The kernel calls this *before* it unmaps or replaces the host memory
    /// behind the range, so a VM never maps memory the host is freeing.
    fn unmap_guest(&mut self, _addr: u64, _len: u64) {}

    /// The guest changed the protections of `[addr, addr + len)` to `prot`.
    fn protect_guest(&mut self, _addr: u64, _len: u64, _prot: u64) {}

    /// The host memory behind `[addr, addr + len)` is about to be replaced
    /// by fresh pages (`MADV_DONTNEED`): a VM stops mapping it, keeping the
    /// mapping's record for [`Platform::remapped_guest`].
    fn replacing_guest(&mut self, _addr: u64, _len: u64) {}

    /// The host memory behind `[addr, addr + len)` was replaced by fresh
    /// pages (`MADV_DONTNEED`); a VM mapping of it must follow.
    fn remapped_guest(&mut self, _addr: u64, _len: u64) {}

    /// Where to put a guest mapping of `len` bytes the guest did not place
    /// itself, or `None` to let the host choose. A backend that keeps guest
    /// memory in a range of its own returns an address there.
    fn place_mapping(&mut self, _len: u64) -> Option<u64> {
        None
    }

    /// Give host memory `[addr, addr + len)` of the guest back (`munmap`, a
    /// shrinking `mremap`, a failed `mmap`). A backend that keeps guest
    /// memory in a range of its own turns it back into reserved space there
    /// in one step, so the host never reuses it, and returns true; with
    /// false the kernel unmaps it.
    fn release_host(&mut self, _addr: u64, _len: u64) -> bool {
        false
    }

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

    /// Write everything a `fork` child started as a fresh process needs to
    /// continue as this process's copy: the kernel's fields, the calling
    /// thread's signal mask and alternate stack, the descriptor registries
    /// and the guest's address-space bookkeeping. The caller holds the
    /// kernel lock; each registry is read under its own.
    pub fn save_for_fork(&self, e: &mut snapshot::Enc) {
        e.u64(self.page_size);
        e.u64(self.brk.start);
        e.u64(self.brk.current);
        e.u64(self.brk.limit);
        e.bool(self.tracer.enabled);
        match &self.fs {
            Some(fs) => {
                e.bool(true);
                fs.save(e);
            }
            None => e.bool(false),
        }
        let c = &self.creds;
        for v in [c.uid, c.euid, c.suid, c.fsuid, c.gid, c.egid, c.sgid, c.fsgid] {
            e.u32(v);
        }
        e.u64(c.groups.len() as u64);
        for &g in &c.groups {
            e.u32(g);
        }
        for a in &self.sigactions {
            for v in [a.handler, a.flags, a.restorer, a.mask] {
                e.u64(v);
            }
        }
        e.u64(self.sigreturn_tramp);
        e.u64(thread::mask());
        let ss = thread::altstack();
        e.u64(ss.ss_sp);
        e.i32(ss.ss_flags);
        e.u64(ss.ss_size);
        let (guest, len, host) = uaccess::translation();
        for v in [guest, len, host] {
            e.u64(v);
        }
        e.map(&mm::guest_ranges());
        fdtable::save(e);
        specialfd::save(e);
        signalfd::save(e);
        synthdir::save(e);
        pty::save(e);
        epoll::save(e);
    }

    /// The kernel [`Kernel::save_for_fork`] described, in the fork child,
    /// which has inherited the parent's descriptors and mapped its memory.
    /// The calling thread takes the parent thread's signal state, and the
    /// guest's signal dispositions are applied to the host.
    pub fn restore_for_fork(platform: P, d: &mut snapshot::Dec) -> Kernel<P> {
        let page_size = d.u64();
        let brk = Brk { start: d.u64(), current: d.u64(), limit: d.u64() };
        let tracer = Tracer { enabled: d.bool() };
        let fs = if d.bool() { Some(Fs::restore(d)) } else { None };
        let mut k = Kernel::new(platform, page_size, brk, fs, tracer);
        let c = &mut k.creds;
        for v in [
            &mut c.uid,
            &mut c.euid,
            &mut c.suid,
            &mut c.fsuid,
            &mut c.gid,
            &mut c.egid,
            &mut c.sgid,
            &mut c.fsgid,
        ] {
            *v = d.u32();
        }
        let n = d.count(4);
        c.groups = (0..n).map(|_| d.u32()).collect();
        for a in &mut k.sigactions {
            *a = Sigaction { handler: d.u64(), flags: d.u64(), restorer: d.u64(), mask: d.u64() };
        }
        k.sigreturn_tramp = d.u64();
        thread::set_mask(d.u64());
        thread::set_altstack(Stack {
            ss_sp: d.u64(),
            ss_flags: d.i32(),
            _pad: 0,
            ss_size: d.u64(),
        });
        let (guest, len, host) = (d.u64(), d.u64(), d.u64());
        if len != 0 {
            uaccess::set_translation(guest, len, host);
        }
        mm::set_guest_ranges(d.map());
        fdtable::restore(d);
        specialfd::restore(d);
        signalfd::restore(d);
        synthdir::restore(d);
        pty::restore(d);
        epoll::restore(d);
        if let Some(fs) = &k.fs {
            net::set_rootfs(fs.root_host_path());
        }
        k.sync_all_host_signals();
        k
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

    /// Run system call `nr` with `args` and return its raw result, without
    /// tracing it or touching registers: for a backend that records the
    /// result itself with [`Kernel::finish_syscall`].
    pub fn run_call(&mut self, nr: u64, args: [u64; 6]) -> i64 {
        self.dispatch(nr, args)
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
        // The saved IDs become the effective ones, as Linux's execve sets
        // them (no set-user-ID programs here).
        self.creds.suid = self.creds.euid;
        self.creds.sgid = self.creds.egid;
    }

    /// The guest path `execveat(dirfd, path, .., flags)` executes: `path`
    /// itself if absolute, else relative to `dirfd` (or the working
    /// directory for `AT_FDCWD`); with `AT_EMPTY_PATH` and an empty `path`,
    /// the file `dirfd` is open on. `AT_SYMLINK_NOFOLLOW` refuses a final
    /// symbolic link with `ELOOP`. Fails with a Linux errno.
    pub fn execveat_path(&self, dirfd: i32, path: &[u8], flags: u64) -> Result<Vec<u8>, i32> {
        use fwe_abi::{errno, fcntl};
        if flags & !(fcntl::AT_EMPTY_PATH | fcntl::AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(errno::EINVAL);
        }
        let fs = self.fs.as_ref().ok_or(errno::ENOENT)?;
        let at_cwd = dirfd == fcntl::AT_FDCWD as i32;
        // The guest path of an open descriptor, if it names a file.
        let fd_path = |fd: i32| -> Result<Vec<u8>, i32> {
            // SAFETY: F_GETFD only queries the descriptor.
            if !fdtable::guest_visible(fd) || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                return Err(errno::EBADF);
            }
            let p = fs.fd_target(fd);
            if p.first() == Some(&b'/') { Ok(p) } else { Err(errno::EACCES) }
        };
        let target = if path.is_empty() {
            if flags & fcntl::AT_EMPTY_PATH == 0 {
                return Err(errno::ENOENT);
            }
            if at_cwd { fs.cwd().to_vec() } else { fd_path(dirfd)? }
        } else if path.first() == Some(&b'/') {
            path.to_vec()
        } else {
            let mut base = if at_cwd { fs.cwd().to_vec() } else { fd_path(dirfd)? };
            if !base.ends_with(b"/") {
                base.push(b'/');
            }
            base.extend_from_slice(path);
            base
        };
        if flags & fcntl::AT_SYMLINK_NOFOLLOW != 0 && !path.is_empty() {
            let r = fs.resolve(fcntl::AT_FDCWD as i32, &target, false)?;
            let name = r.name_c()?;
            // SAFETY: an all-zero stat is a valid out-parameter.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a valid directory descriptor, name and out-parameter.
            let ok = unsafe {
                libc::fstatat(r.dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
            } == 0;
            if ok && st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(errno::ELOOP);
            }
        }
        Ok(target)
    }

    /// What an `execve` that re-executes fwe carries into the new process
    /// beyond what the host keeps: the credentials, the descriptor limit and
    /// the umask (see [`Kernel::restore_exec_state`]).
    pub fn exec_state(&self) -> Vec<u8> {
        let mut e = snapshot::Enc::new();
        e.u64(EXEC_STATE_MAGIC);
        let c = &self.creds;
        for v in [c.uid, c.euid, c.suid, c.fsuid, c.gid, c.egid, c.sgid, c.fsgid] {
            e.u32(v);
        }
        e.u64(c.groups.len() as u64);
        for &g in &c.groups {
            e.u32(g);
        }
        let (soft, hard) = fdtable::limit();
        e.u64(soft);
        e.u64(hard);
        e.u32(self.fs.as_ref().map_or(0o022, |fs| fs.umask()));
        e.into_bytes()
    }

    /// Take the state [`Kernel::exec_state`] recorded in the process that
    /// exec'd this one. Fails, changing nothing, on a malformed record.
    pub fn restore_exec_state(&mut self, state: &[u8]) -> Result<(), String> {
        let mut d = snapshot::Dec::new(state);
        if d.u64() != EXEC_STATE_MAGIC {
            return Err("the exec state is not fwe's".into());
        }
        let mut ids = [0u32; 8];
        for v in &mut ids {
            *v = d.u32();
        }
        let n = d.count(4);
        let groups: Vec<u32> = (0..n).map(|_| d.u32()).collect();
        let (soft, hard) = (d.u64(), d.u64());
        let umask = d.u32();
        d.finish()?;
        // The saved IDs become the effective ones, as across any execve.
        let [uid, euid, _, fsuid, gid, egid, _, fsgid] = ids;
        self.creds =
            creds::Creds { uid, euid, suid: euid, fsuid, gid, egid, sgid: egid, fsgid, groups };
        // The limit was the guest's own, so it fits the new process's range
        // (the host limit is inherited); keep the default if it does not.
        let _ = fdtable::set_limit(soft, hard);
        if let Some(fs) = self.fs.as_mut() {
            fs.set_umask(umask);
        }
        Ok(())
    }

    /// Adopt the dispositions this process inherited: a signal the host
    /// ignores at startup (`nohup`, a shell's background job) starts out
    /// ignored in the guest too, as it would across a Linux `execve`. Every
    /// other relayed signal is put back to its default action on the host.
    /// `SIGPIPE` is always reset: the Rust runtime ignores it before `main`,
    /// so its inherited disposition is lost.
    pub fn adopt_host_signals(&mut self) {
        // The blocked mask survives execve: take the one fwe started with.
        thread::set_mask(host::blocked_signals());
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

/// Host `fork` is refused (see [`forbid_fork`]).
static NO_FORK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Leads an exec state record ([`Kernel::exec_state`]).
const EXEC_STATE_MAGIC: u64 = 0x6677_652d_6578_6563;

/// Refuse every host `fork` from now on: a process running its guest in a
/// Hypervisor.framework VM must never fork, as the child would inherit a VM
/// it cannot own.
pub fn forbid_fork() {
    NO_FORK.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Run `fork` (a host `fork`, perhaps wrapped by the backend) with every lock
/// the kernel's own registries use held, so that in a multithreaded guest
/// the child cannot inherit one locked by a thread that does not exist in
/// it. The caller holds the kernel lock itself. The locks are released in
/// both processes.
pub fn fork_locked(fork: impl FnOnce() -> libc::pid_t) -> libc::pid_t {
    if NO_FORK.load(std::sync::atomic::Ordering::SeqCst) {
        // SAFETY: setting this thread's errno.
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = libc::ENOSYS
        };
        // SAFETY: as above.
        #[cfg(not(target_os = "macos"))]
        unsafe {
            *libc::__errno_location() = libc::ENOSYS
        };
        return -1;
    }
    signalfd::hold(|| {
        specialfd::hold(|| {
            synthdir::hold(|| {
                pty::hold(|| net::hold(|| futex::hold(|| mm::hold(|| thread::hold(fork)))))
            })
        })
    })
}

/// The kqueues behind the guest's `epoll` and `timerfd` descriptors, which
/// the host does not pass on to a child (their descriptors are closed
/// there), recorded before a host `fork` for [`restore_kqueues`].
pub fn kqueue_state() -> Vec<u8> {
    let mut e = snapshot::Enc::new();
    specialfd::save(&mut e);
    epoll::save(&mut e);
    e.into_bytes()
}

/// In the child of a host `fork`: rebuild the kqueues [`kqueue_state`]
/// recorded.
pub fn restore_kqueues(state: &[u8]) {
    let mut d = snapshot::Dec::new(state);
    specialfd::restore(&mut d);
    epoll::restore(&mut d);
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
        n::READV => match uaccess::host_iovecs(a[1], a[2]) {
            Ok(iov) => {
                // SAFETY: the iovecs are translated host buffers; the host
                // checks them.
                let r = unsafe { libc::readv(a[0] as i32, iov.as_ptr(), iov.len() as i32) };
                host::ret(r as i64)
            }
            Err(e) => fwe_abi::err(e),
        },
        n::WRITEV => match uaccess::host_iovecs(a[1], a[2]) {
            Ok(iov) => {
                // SAFETY: as for readv.
                let r = unsafe { libc::writev(a[0] as i32, iov.as_ptr(), iov.len() as i32) };
                host::ret(r as i64)
            }
            Err(e) => fwe_abi::err(e),
        },
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
