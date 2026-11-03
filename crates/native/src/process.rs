//! Process system calls for the native backend: `execve`, `fork` (and the
//! `vfork`-style `clone`), `wait4` and `waitid`.

use crate::{
    KERNEL, LIVE_THREADS, NativePlatform, load_image, page_size, thread_pointer_slot, trap,
    x18_slot,
};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::mm::region;
use fwe_kernel::{Platform, Regs, host, thread};
use std::sync::atomic::Ordering;

/// `execve(path, argv, envp)`: replace the current program image with a new
/// one and start it. Returns a negative errno on failure; on success it does
/// not return (it enters the new program).
///
/// The new program is checked first, so a bad one leaves the caller running
/// with an error; then the old program's memory is unmapped (every guest
/// mapping is tracked, see `fwe_kernel::mm::track`) and the new one loaded
/// in its place, so a program can exec one linked at the same addresses —
/// itself, for instance. A failure after that point is fatal, as on Linux.
/// Descriptors marked close-on-exec are closed. A program only the VM can
/// run, or an `execve` from a process with other live threads, re-executes
/// fwe instead ([`crate::reexec`]).
pub fn do_execve(regs: &Regs) -> Result<Regs, i64> {
    use fwe_kernel::uaccess;
    let path = uaccess::read_cstr(regs.x[0], uaccess::PATH_MAX).map_err(err)?;
    let (args, env) = read_exec_args(regs.x[1], regs.x[2])?;
    exec_program(path, args, env)
}

/// Linux's limit on one argument or environment string.
const ARG_MAX: usize = 128 * 1024;

/// An `execve`'s argument and environment strings.
type ExecArgs = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// The argument and environment arrays of an `execve`.
fn read_exec_args(argv: u64, envp: u64) -> Result<ExecArgs, i64> {
    use fwe_kernel::uaccess;
    let args = uaccess::read_cstr_array(argv, ARG_MAX).map_err(err)?;
    let env = uaccess::read_cstr_array(envp, ARG_MAX).map_err(err)?;
    Ok((args, env))
}

/// `execveat(dirfd, path, argv, envp, flags)`: `execve` of the program
/// `dirfd`, `path` and `flags` name ([`fwe_kernel::Kernel::execveat_path`]).
pub fn do_execveat(regs: &Regs) -> Result<Regs, i64> {
    use fwe_kernel::uaccess;
    let rel = uaccess::read_cstr(regs.x[1], uaccess::PATH_MAX).map_err(err)?;
    let (args, env) = read_exec_args(regs.x[2], regs.x[3])?;
    let path = {
        let guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().unwrap().execveat_path(regs.x[0] as i32, &rel, regs.x[4]).map_err(err)?
    };
    exec_program(path, args, env)
}

/// Replace the program with `path` (a guest path), given its arguments and
/// environment. Returns the new program's registers, or a negated errno
/// while the old program is still intact.
fn exec_program(path: Vec<u8>, args: Vec<Vec<u8>>, env: Vec<Vec<u8>>) -> Result<Regs, i64> {
    let mut guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let k = guard.as_mut().unwrap();
    let page = page_size();
    let strace = k.tracer.enabled;
    let platform =
        NativePlatform { tp_slot: thread_pointer_slot(), x18_slot: x18_slot(), page_size: page };
    let fs = k.fs.as_ref().expect("filesystem configured");

    let file = fs.read(&path).map_err(err)?;
    // A program only the VM can run, or an exec from a process with other
    // threads (which must end): replace this process with a fresh fwe.
    if crate::needs_vm(&file) || LIVE_THREADS.load(Ordering::SeqCst) > 1 {
        let state = k.exec_state();
        return Err(crate::reexec(&path, &args, &env, fs, strace, &state, || {}));
    }
    // The old image is untouched on failure, so the guest can handle it.
    crate::check_image(&file, fs).map_err(err)?;
    let arg_refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env_refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    // The point of no return: the old program's memory goes, and a vfork
    // parent may resume.
    fwe_kernel::mm::release_guest_memory();
    let done = VFORK_DONE.swap(-1, Ordering::SeqCst);
    if done >= 0 {
        // SAFETY: closing the pipe end this child holds for its parent.
        unsafe { libc::close(done) };
    }
    let out = match load_image(&file, &path, &arg_refs, &env_refs, fs, &platform, page, strace) {
        Ok(out) => out,
        Err(e) => {
            let msg = format!("fwe: execve {}: {e}\n", String::from_utf8_lossy(&path));
            // SAFETY: writing a diagnostic to standard error.
            unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
            k.platform.kill_self(libc::SIGSEGV)
        }
    };

    k.close_on_exec();
    k.exec_reset();
    k.brk = out.brk;
    if let Some(fs) = k.fs.as_mut() {
        fs.set_proc_info(path.clone(), crate::cmdline(&arg_refs), crate::ncpu(), crate::hostname());
        fwe_kernel::net::set_rootfs(fs.root_host_path());
    }
    // The new program starts with every register zero, as Linux leaves it;
    // the trap handler returns into it.
    Ok(Regs { sp: out.sp, pc: out.entry, ..Regs::default() })
}

/// In a `vfork` child, the write end of the pipe its parent waits on
/// (see [`do_fork`]), or -1. It is fwe's, so close-on-exec does not reach
/// it; `execve` closes it once the new program is certain to load.
static VFORK_DONE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// `fork` (a non-thread `clone`): duplicate the process with host `fork`.
/// The child continues with `x0` = 0 (on `child_stack` if one was given);
/// the parent gets the child pid.
///
/// A multithreaded guest forks with the kernel lock and every kernel
/// registry lock held ([`fwe_kernel::fork_locked`]), so the child, which has
/// only the forking thread, cannot inherit a lock another thread held, and
/// with the other threads that run guest code stopped
/// ([`crate::quiesce`]), so the child sees one instant of memory.
///
/// With `vfork` (`CLONE_VM | CLONE_VFORK`, as `posix_spawn` and `vfork` use)
/// the child shares the guest's memory with the parent, and the parent
/// waits until the child has called `execve` or exited, as Linux suspends
/// it; what the child writes before then (glibc's `posix_spawn` reporting an
/// exec failure, say) the parent sees. Its own mappings are its own: an
/// `mmap` or `munmap` in the child does not reach the parent.
pub fn do_fork(parent: &Regs, a: fwe_kernel::CloneArgs, vfork: bool) -> i64 {
    let fwe_kernel::CloneArgs { flags, stack: child_stack, parent_tid, child_tid, .. } = a;

    // A pipe whose write end only the child holds: it closes when the child
    // execs (it is close-on-exec) or exits, which ends the parent's wait.
    let mut done = [-1i32; 2];
    if vfork {
        // SAFETY: plain host call with a 2-element array.
        if unsafe { libc::pipe(done.as_mut_ptr()) } != 0 {
            return fwe_kernel::host::last_error();
        }
        done = [fwe_kernel::fdtable::reserve(done[0]), fwe_kernel::fdtable::reserve(done[1])];
    }

    let (pid, kqueues) = {
        let _kernel = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        let kqueues = fwe_kernel::kqueue_state();
        // A vfork child shares the guest's memory: its private parts are
        // shared for the fork, then copied again by any later one (in either
        // process). The kernel lock keeps the guest's mappings as they are.
        let share =
            if vfork { region::private_parts(&fwe_kernel::mm::tracked()) } else { Vec::new() };
        let set_shared = |on: bool| {
            for &(start, len) in &share {
                region::set_shared_on_fork(start, len, on);
            }
        };
        let pid = fwe_kernel::fork_locked(|| {
            set_shared(true);
            // SAFETY: plain host call; the child continues with only the
            // calling thread, as on Linux.
            let pid = crate::quiesce::fork_stopped(|| unsafe { libc::fork() });
            set_shared(false);
            pid
        });
        (pid, kqueues)
    };
    if pid < 0 {
        let e = fwe_kernel::host::last_error();
        for fd in done.into_iter().filter(|&fd| fd >= 0) {
            // SAFETY: closing the pipe opened above.
            unsafe { libc::close(fd) };
        }
        return e;
    }
    if pid == 0 {
        // Child: a new process with only this thread, inside a copy of the
        // parent's trap handler. Returning through that handler does not
        // work: macOS does not restore the signal mask from a frame the child
        // did not take itself, so SIGTRAP would stay blocked and the next
        // trap be fatal. Instead enter the guest directly with the parent's
        // register state (x0 = 0), as a cloned thread does, with a signal
        // stack of its own (the host thread's is not inherited). The guest's
        // blocked mask and alternate stack carry over; pending signals do
        // not.
        trap::ensure_thread_altstack();
        if vfork {
            // SAFETY: closing the read end the parent uses.
            unsafe { libc::close(done[0]) };
            VFORK_DONE.store(done[1], Ordering::SeqCst);
        } else {
            VFORK_DONE.store(-1, Ordering::SeqCst);
        }
        thread::init_main(host::getpid() as i32);
        fwe_kernel::restore_kqueues(&kqueues);
        LIVE_THREADS.store(1, Ordering::SeqCst);
        if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
            // Best effort, as for Linux's own write of the word.
            let _ = fwe_kernel::uaccess::write(child_tid, thread::tid());
        }
        if flags & cl::CLONE_CHILD_CLEARTID != 0 && child_tid != 0 {
            thread::set_clear_child_tid(child_tid);
        }
        let mut regs = *parent;
        regs.x[0] = 0;
        regs.pc = parent.pc.wrapping_add(4);
        if child_stack != 0 {
            regs.sp = child_stack;
        }
        trap::prepare_guest_entry();
        // SAFETY: `regs` is the parent's runnable context with x0 cleared.
        unsafe { trap::enter_guest_full(&regs) }
    }
    // Parent: the child's pid.
    if flags & cl::CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        let _ = fwe_kernel::uaccess::write(parent_tid, pid);
    }
    if vfork {
        // SAFETY: plain host calls on the pipe opened above.
        unsafe {
            libc::close(done[1]);
            let mut b = 0u8;
            while libc::read(done[0], (&mut b as *mut u8).cast(), 1) < 0
                && host::last_errno() == libc::EINTR
            {}
            libc::close(done[0]);
        }
    }
    pid as i64
}

/// Encode a host `wait` status into the Linux layout a guest expects.
fn linux_wstatus(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        (libc::WEXITSTATUS(status) & 0xff) << 8
    } else if libc::WIFSIGNALED(status) {
        let sig = host::signal_to_linux(libc::WTERMSIG(status)) as i32;
        let core = if libc::WCOREDUMP(status) { 0x80 } else { 0 };
        sig | core
    } else if libc::WIFSTOPPED(status) {
        (host::signal_to_linux(libc::WSTOPSIG(status)) as i32) << 8 | 0x7f
    } else {
        0xffff // continued
    }
}

/// `wait4(pid, wstatus, options, rusage)`: reap a child. Blocks, so it runs
/// without the kernel lock.
pub fn do_wait4(regs: &Regs) -> i64 {
    let pid = regs.x[0] as i32;
    let wstatus = regs.x[1];
    let options = regs.x[2];
    let rusage = regs.x[3];

    // WNOHANG and WUNTRACED share values with Linux; WCONTINUED does not
    // (8 on Linux, 0x10 on macOS).
    let mut host_options = 0;
    for (linux, host) in [
        (fwe_abi::wait::WNOHANG, libc::WNOHANG),
        (fwe_abi::wait::WUNTRACED, libc::WUNTRACED),
        (fwe_abi::wait::WCONTINUED, libc::WCONTINUED),
    ] {
        if options & linux != 0 {
            host_options |= host;
        }
    }
    let mut status: libc::c_int = 0;
    // SAFETY: an all-zero rusage is a valid out-parameter.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `status` and `usage` are valid out-parameters.
    let r = unsafe { libc::wait4(pid, &mut status, host_options, &mut usage) };
    if r < 0 {
        return fwe_kernel::host::last_error();
    }
    if r > 0 && wstatus != 0 && fwe_kernel::uaccess::write(wstatus, linux_wstatus(status)).is_err()
    {
        return err(errno::EFAULT);
    }
    if r > 0 && host::write_rusage(rusage, &usage).is_err() {
        return err(errno::EFAULT);
    }
    r as i64
}

/// `waitid(idtype, id, infop, options, rusage)`: wait for a child state
/// change and report it as a `siginfo_t`. Blocks, so it runs without the
/// kernel lock. The host's `waitid` reports no resource usage, so `rusage`
/// is zero-filled.
pub fn do_waitid(regs: &Regs) -> i64 {
    use fwe_abi::wait as w;
    let (idtype, id, infop, options, rusage) =
        (regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4]);
    let (idtype, id) = match idtype {
        w::P_ALL => (libc::P_ALL, 0),
        w::P_PID => (libc::P_PID, id as libc::id_t),
        // SAFETY: plain host call.
        w::P_PGID if id == 0 => (libc::P_PGID, unsafe { libc::getpgrp() } as libc::id_t),
        w::P_PGID => (libc::P_PGID, id as libc::id_t),
        _ => return err(errno::EINVAL),
    };
    if options & (w::WEXITED | w::WSTOPPED | w::WCONTINUED) == 0 {
        return err(errno::EINVAL);
    }
    let mut host_options = 0;
    for (linux, host) in [
        (w::WNOHANG, libc::WNOHANG),
        (w::WSTOPPED, libc::WSTOPPED),
        (w::WEXITED, libc::WEXITED),
        (w::WCONTINUED, libc::WCONTINUED),
        (w::WNOWAIT, libc::WNOWAIT),
    ] {
        if options & linux != 0 {
            host_options |= host;
        }
    }
    // SAFETY: an all-zero siginfo is a valid out-parameter.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `si` is a valid out-parameter.
    if unsafe { libc::waitid(idtype, id, &mut si, host_options) } != 0 {
        return fwe_kernel::host::last_error();
    }
    if infop != 0 {
        let mut words = [0i32; 32]; // a 128-byte siginfo_t
        // SAFETY: `si` was filled by the host.
        let (pid, uid, status) = unsafe { (si.si_pid(), si.si_uid(), si.si_status()) };
        if pid != 0 {
            let code = si.si_code;
            let status = if matches!(code, w::CLD_KILLED | w::CLD_DUMPED | w::CLD_STOPPED) {
                host::signal_to_linux(status) as i32
            } else {
                status
            };
            words[0] = fwe_abi::signal::SIGCHLD as i32; // si_signo
            words[2] = code; // si_code
            words[4] = pid; // si_pid
            words[5] = uid as i32; // si_uid
            words[6] = status; // si_status
        }
        if fwe_kernel::uaccess::write(infop, words).is_err() {
            return err(errno::EFAULT);
        }
    }
    if rusage != 0
        && fwe_kernel::uaccess::zero(rusage, fwe_abi::resource_usage::RUSAGE_SIZE).is_err()
    {
        return err(errno::EFAULT);
    }
    0
}
