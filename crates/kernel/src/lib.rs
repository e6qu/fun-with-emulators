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

pub mod bpf;
pub mod caps;
pub mod cgroupfs;
pub mod cloneargs;
pub mod creds;
pub mod devnodes;
pub mod epoll;
pub mod fdmarks;
pub mod fdtable;
pub mod fs;
mod fsops;
pub mod futex;
pub mod host;
pub mod memfd;
pub mod mm;
mod mountops;
pub mod mounts;
pub mod net;
pub mod netns;
pub mod ns;
pub mod nsops;
pub mod pidns;
pub mod procfs;
pub mod procpid;
pub mod procreg;
pub mod pty;
pub mod seccomp;
pub mod shared;
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
pub mod userns;
pub mod vmas;

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
/// A memory system call, for a backend that manages the guest's memory
/// itself ([`Platform::memory`]). Addresses are guest addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemCall {
    Brk { addr: u64 },
    Mmap { addr: u64, len: u64, prot: u64, flags: u64, fd: i32, offset: u64 },
    Munmap { addr: u64, len: u64 },
    Mprotect { addr: u64, len: u64, prot: u64 },
    Madvise { addr: u64, len: u64, advice: u64 },
    Msync { addr: u64, len: u64, flags: u64 },
    Mremap { old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64 },
}

/// Why [`Platform::prepare_exec`] failed: the errno the guest gets, and the
/// reason, which the trace records (`ld.so` reports only that a segment
/// could not be mapped).
#[derive(Debug)]
pub struct PrepareFailed {
    pub errno: i32,
    pub why: String,
}

pub trait Platform {
    /// Carry out a memory system call, for a backend whose guest has an
    /// address space of its own that it manages (the hypervisor backend);
    /// `None` leaves it to the kernel, which maps host memory at the
    /// guest's addresses. `brk` is the program break, which `Brk` moves.
    fn memory(&mut self, _call: MemCall, _brk: &mut mm::Brk) -> Option<i64> {
        None
    }

    /// Make guest code in `[addr, addr + len)` safe to execute. `known`,
    /// when given, is the address ranges the file's unwind table says hold
    /// code; other bytes of the range may be data placed among the code.
    ///
    /// The memory is readable and writable when this is called; the kernel
    /// applies the final protections afterwards. A failure carries the
    /// Linux errno for the guest and why, for the trace.
    fn prepare_exec(
        &mut self,
        addr: u64,
        len: u64,
        known: Option<&[(u64, u64)]>,
    ) -> Result<(), PrepareFailed>;

    /// Terminate the whole process with `code` as its exit status
    /// (`exit_group`).
    fn exit(&mut self, code: i32) -> !;

    /// Terminate just the calling thread (`exit`); ends the process when it is
    /// the last thread.
    fn exit_thread(&mut self, code: i32) -> !;

    /// Terminate the guest as if killed by host signal `sig`.
    fn kill_self(&mut self, sig: libc::c_int) -> !;

    /// Stop the process with host signal `sig`, as the default action of
    /// `SIGTSTP` and friends does, until it is continued.
    fn stop_self(&mut self, _sig: libc::c_int) {}

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
        e.bool(self.tracer.failures_only);
        fdmarks::save(e);
        seccomp::save(e);
        e.bool(syscalls::NO_NEW_PRIVS.load(std::sync::atomic::Ordering::Relaxed));
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
        c.caps.encode(e);
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
        let translations = uaccess::translations();
        e.u64(translations.len() as u64);
        for (guest, len, host) in translations {
            for v in [guest, len, host] {
                e.u64(v);
            }
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
        let tracer = Tracer { enabled: d.bool(), failures_only: d.bool() };
        fdmarks::load(d);
        seccomp::load_state(d);
        syscalls::NO_NEW_PRIVS.store(d.bool(), std::sync::atomic::Ordering::Relaxed);
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
        c.caps = caps::Caps::decode(d);
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
        let n = d.count(24);
        let translations: Vec<(u64, u64, u64)> =
            (0..n).map(|_| (d.u64(), d.u64(), d.u64())).collect();
        uaccess::set_translations(&translations);
        mm::set_guest_ranges(d.map());
        fdtable::restore(d);
        specialfd::restore(d);
        signalfd::restore(d);
        synthdir::restore(d);
        pty::restore(d);
        epoll::restore(d);
        if let Some(fs) = &k.fs {
            fs.publish();
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
        let (uid, euid) = (self.creds.uid, self.creds.euid);
        self.creds.caps.on_exec(uid, euid);
    }

    /// The guest path `execveat(dirfd, path, .., flags)` executes: `path`
    /// itself if absolute, else relative to `dirfd` (or the working
    /// directory for `AT_FDCWD`); with `AT_EMPTY_PATH` and an empty `path`,
    /// the file `dirfd` is open on (`/dev/fd/N`, as Linux names it, for a
    /// file with no path, such as a memfd). `AT_SYMLINK_NOFOLLOW` refuses a
    /// final symbolic link with `ELOOP`. Fails with a Linux errno.
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
            if at_cwd {
                fs.cwd().to_vec()
            } else {
                // Run through the descriptor, under the name Linux gives it.
                fd_path(dirfd)?;
                format!("/dev/fd/{dirfd}").into_bytes()
            }
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
    /// beyond what the host keeps: the mount namespace and root (first, so
    /// that the new process finds its program in them, see
    /// [`Fs::adopt_exec_view`]), the credentials, the descriptor limit and
    /// the umask (see [`Kernel::restore_exec_state`]).
    pub fn exec_state(&self) -> Vec<u8> {
        let mut e = snapshot::Enc::new();
        e.u64(EXEC_STATE_MAGIC);
        match self.fs.as_ref() {
            Some(fs) => {
                e.bool(true);
                fs.save_view(&mut e);
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
        c.caps.encode(&mut e);
        let (soft, hard) = fdtable::limit();
        e.u64(soft);
        e.u64(hard);
        e.u32(self.fs.as_ref().map_or(0o022, |fs| fs.umask()));
        // Which mount each open file came through (a record whose
        // descriptor does not survive is never trusted, see `fdmarks`).
        fdmarks::save(&mut e);
        // Kept across execve, as on Linux.
        seccomp::save(&mut e);
        e.bool(syscalls::NO_NEW_PRIVS.load(std::sync::atomic::Ordering::Relaxed));
        e.into_bytes()
    }

    /// Take the state [`Kernel::exec_state`] recorded in the process that
    /// exec'd this one. Fails, changing nothing, on a malformed record.
    pub fn restore_exec_state(&mut self, state: &[u8]) -> Result<(), String> {
        let mut d = snapshot::Dec::new(state);
        if d.u64() != EXEC_STATE_MAGIC {
            return Err("the exec state is not fwe's".into());
        }
        // The view, which the filesystem took when it was opened.
        if d.bool() {
            fs::Fs::skip_view(&mut d);
        }
        let mut ids = [0u32; 8];
        for v in &mut ids {
            *v = d.u32();
        }
        let n = d.count(4);
        let groups: Vec<u32> = (0..n).map(|_| d.u32()).collect();
        let mut caps = caps::Caps::decode(&mut d);
        let (soft, hard) = (d.u64(), d.u64());
        let umask = d.u32();
        fdmarks::load(&mut d);
        seccomp::load_state(&mut d);
        let nnp = d.bool();
        d.finish()?;
        syscalls::NO_NEW_PRIVS.store(nnp, std::sync::atomic::Ordering::Relaxed);
        // The saved IDs become the effective ones, and the capabilities
        // what an exec makes of them, as across any execve.
        let [uid, euid, _, fsuid, gid, egid, _, fsgid] = ids;
        caps.on_exec(uid, euid);
        self.creds = creds::Creds {
            uid,
            euid,
            suid: euid,
            fsuid,
            gid,
            egid,
            sgid: egid,
            fsgid,
            groups,
            caps,
        };
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
            // Traced after the frame is restored: `x8` is the interrupted
            // code's now.
            self.tracer.syscall(fwe_abi::nr::RT_SIGRETURN, &[0; 6], regs.x[0] as i64);
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
    // A thread's number in the pid namespace is free again (the main
    // thread's is the process's, freed when it is reaped).
    if pidns::nested() && thread::tid() != thread::tgid() {
        pidns::release_thread(thread::tid());
    }
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
pub(crate) const EXEC_STATE_MAGIC: u64 = 0x6677_652d_6578_6563;

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
                pty::hold(|| fs::hold(|| futex::hold(|| mm::hold(|| thread::hold(fork)))))
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
/// calls that wait, `flock` and `fcntl`'s `F_SETLKW` (waiting for another
/// process's lock), and `read`/`write` and their vectored and positioned forms (a pipe, socket
/// or terminal blocks until the other side acts, and the other side may be a
/// guest thread that needs the lock). Returns `None` for any other call,
/// which the backend runs under the lock through [`Kernel::enter_syscall`].
///
/// # Safety
/// Pointer arguments must reference valid guest memory for the call.
pub unsafe fn blocking_syscall(nr: u64, a: [u64; 6]) -> Option<i64> {
    // SAFETY: the caller's guarantee, passed on.
    let r = unsafe { blocking_call(nr, a) }?;
    // A write the host refused to a sealed memfd, and what a socket that
    // stands in for another kind reports, as Linux reports them.
    Some(linux_result(nr, &a, r))
}

/// The result of system call `nr` as Linux reports it where the host's
/// differs: a write refused to a sealed memfd, a socket that stands in for
/// another kind, and the `SIGPIPE` a socket write to a closed peer raises.
pub(crate) fn linux_result(nr: u64, a: &[u64; 6], r: i64) -> i64 {
    let r = fdmarks::linux_result(nr, a, memfd::linux_write_error(nr, a, r));
    if r == fwe_abi::err(fwe_abi::errno::EPIPE) {
        sigpipe_for_socket(nr, a);
    }
    r
}

/// `sendfile` (`both_files` false) and `copy_file_range` (true): copy up to
/// `count` bytes from `input` to `output`, from the offset at `in_off` (a
/// guest pointer, updated, leaving the file's own offset alone) or the
/// file's, and for `copy_file_range` to the one at `out_off` likewise.
/// The input must be a regular file, as Linux has it; `copy_file_range`
/// needs both to be. Returns the bytes copied, or an errno when none were.
fn copy_between(
    input: i32,
    in_off: u64,
    output: i32,
    out_off: u64,
    count: u64,
    both_files: bool,
) -> i64 {
    use fwe_abi::{err, errno};
    let regular = |fd: i32| {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        let r = unsafe { libc::fstat(fd, &mut st) };
        if r != 0 {
            Err(host::errno_to_linux(host::last_errno()))
        } else {
            Ok(st.st_mode & libc::S_IFMT == libc::S_IFREG)
        }
    };
    match (regular(input), regular(output)) {
        (Err(e), _) | (_, Err(e)) => return err(e),
        (Ok(false), _) => return err(errno::EINVAL),
        (_, Ok(false)) if both_files => return err(errno::EINVAL),
        _ => {}
    }
    let read_off = |p: u64| -> Result<Option<i64>, i32> {
        if p == 0 { Ok(None) } else { uaccess::read::<i64>(p).map(Some) }
    };
    let (mut ipos, mut opos) = match (read_off(in_off), read_off(out_off)) {
        (Ok(i), Ok(o)) => (i, o),
        (Err(e), _) | (_, Err(e)) => return err(e),
    };
    if ipos.is_some_and(|p| p < 0) || opos.is_some_and(|p| p < 0) {
        return err(errno::EINVAL);
    }
    let mut buf = vec![0u8; 1 << 16];
    let mut done: u64 = 0;
    let mut failure = 0;
    while done < count {
        let want = (count - done).min(buf.len() as u64) as usize;
        // SAFETY: `buf` holds at least `want` bytes.
        let n = unsafe {
            match ipos {
                Some(p) => libc::pread(input, buf.as_mut_ptr().cast(), want, p),
                None => libc::read(input, buf.as_mut_ptr().cast(), want),
            }
        };
        if n < 0 {
            failure = host::errno_to_linux(host::last_errno());
            break;
        }
        if n == 0 {
            break;
        }
        let mut sent = 0usize;
        while sent < n as usize {
            // SAFETY: the first `n` bytes of `buf` are initialized.
            let w = unsafe {
                match opos {
                    Some(p) => libc::pwrite(
                        output,
                        buf[sent..].as_ptr().cast(),
                        n as usize - sent,
                        p + sent as i64,
                    ),
                    None => libc::write(output, buf[sent..].as_ptr().cast(), n as usize - sent),
                }
            };
            if w <= 0 {
                failure = if w < 0 { host::errno_to_linux(host::last_errno()) } else { errno::EIO };
                break;
            }
            sent += w as usize;
        }
        // What was read and not written goes back to the input.
        if sent < n as usize && ipos.is_none() {
            // SAFETY: plain host call on the input.
            unsafe { libc::lseek(input, -((n as usize - sent) as i64), libc::SEEK_CUR) };
        }
        done += sent as u64;
        if let Some(p) = ipos.as_mut() {
            *p += sent as i64;
        }
        if let Some(p) = opos.as_mut() {
            *p += sent as i64;
        }
        if failure != 0 || sent < n as usize {
            break;
        }
    }
    for (ptr, pos) in [(in_off, ipos), (out_off, opos)] {
        if let (true, Some(p)) = (ptr != 0, pos)
            && uaccess::write(ptr, p).is_err()
        {
            return err(errno::EFAULT);
        }
    }
    if done == 0 && failure != 0 { err(failure) } else { done as i64 }
}

/// A write to a socket whose peer has gone raises `SIGPIPE`, unless the send
/// said `MSG_NOSIGNAL`. fwe's sockets never let the host raise it (they are
/// all `SO_NOSIGPIPE`, so that the flag can be honoured), so it does.
fn sigpipe_for_socket(nr: u64, a: &[u64; 6]) {
    use fwe_abi::nr as n;
    const MSG_NOSIGNAL: u64 = 0x4000;
    let quiet = match nr {
        n::WRITE | n::WRITEV | n::PWRITE64 | n::SENDFILE => false,
        n::SENDTO => a[3] & MSG_NOSIGNAL != 0,
        n::SENDMSG => a[2] & MSG_NOSIGNAL != 0,
        _ => return,
    };
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    let socket = unsafe { libc::fstat(a[0] as i32, &mut st) } == 0
        && st.st_mode & libc::S_IFMT == libc::S_IFSOCK;
    if socket && !quiet {
        signal::raise_self(absig::SIGPIPE);
    }
}

/// [`blocking_syscall`]'s calls.
///
/// # Safety
/// As for [`blocking_syscall`].
unsafe fn blocking_call(nr: u64, a: [u64; 6]) -> Option<i64> {
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
            if let Some(r) = cgroupfs::try_write(fd, buf, len) {
                return Some(r);
            }
            if fdmarks::any_marks()
                && let Some(r) = userns::try_write(fd, buf, len)
            {
                return Some(r);
            }
            // SAFETY: the host validates the guest buffer.
            host::ret(unsafe { libc::write(fd, buf as *const _, len as usize) } as i64)
        }
        n::READV => match uaccess::host_iovecs(a[1], a[2], true) {
            Ok(iov) => {
                // SAFETY: the iovecs are translated host buffers; the host
                // checks them.
                let r = unsafe { libc::readv(a[0] as i32, iov.as_ptr(), iov.len() as i32) };
                host::ret(r as i64)
            }
            Err(e) => fwe_abi::err(e),
        },
        n::WRITEV => match uaccess::host_iovecs(a[1], a[2], false) {
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
        n::SENDFILE => copy_between(a[1] as i32, a[2], a[0] as i32, 0, a[3], false),
        n::COPY_FILE_RANGE if a[5] != 0 => fwe_abi::err(fwe_abi::errno::EINVAL),
        n::COPY_FILE_RANGE => copy_between(a[0] as i32, a[1], a[2] as i32, a[3], a[4], true),
        // SAFETY: caller guarantees the pollfd array and timeout pointers.
        n::PPOLL => unsafe { signal::with_call_mask(a[3], || syscalls::ppoll(a[0], a[1], a[2])) },
        // The sixth argument points to `{ const sigset_t *ss; size_t len }`.
        n::PSELECT6 => {
            let mask = if a[5] == 0 {
                0
            } else {
                match uaccess::read::<[u64; 2]>(a[5]) {
                    Ok([ss, _]) => ss,
                    Err(e) => return Some(fwe_abi::err(e)),
                }
            };
            // SAFETY: caller guarantees the set, timeout and mask pointers.
            unsafe {
                signal::with_call_mask(mask, || syscalls::pselect6(a[0], [a[1], a[2], a[3]], a[4]))
            }
        }
        // SAFETY: caller guarantees the signal set pointer.
        n::RT_SIGSUSPEND => unsafe { signal::sigsuspend(a[0], a[1]) },
        n::FLOCK => syscalls::flock(a[0], a[1]),
        n::FCNTL if a[1] == fwe_abi::fcntl::F_SETLKW => {
            syscalls::set_record_lock(a[0] as i32, a[1], a[2])
        }

        // Socket calls that can block run without the kernel lock, so a thread
        // waiting in accept/recv does not stall the threads meant to feed it.
        // SAFETY: caller guarantees the sockaddr pointer.
        n::CONNECT => unsafe { net::connect(a[0], a[1], a[2]) },
        n::ACCEPT | n::ACCEPT4 => {
            let flags = if nr == n::ACCEPT4 { a[3] } else { 0 };
            // SAFETY: caller guarantees the out pointers.
            let r = unsafe { net::accept4(a[0], a[1], a[2], flags) };
            let made = fdtable::made(nr, &a, r);
            if fdtable::over_limit(&made) {
                // A socket: nothing of fwe's to drop with it.
                // SAFETY: closing the descriptor just accepted.
                unsafe { libc::close(r as i32) };
                fwe_abi::err(fwe_abi::errno::EMFILE)
            } else {
                r
            }
        }
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
