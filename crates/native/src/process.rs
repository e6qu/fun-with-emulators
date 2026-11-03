//! Process system calls for the native backend: `execve`, `fork` (and the
//! `vfork`-style `clone`), `wait4` and `waitid`.

use crate::{
    KERNEL, LIVE_THREADS, NativePlatform, load_image, page_size, thread_pointer_slot, trap,
    x18_slot,
};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::{Platform, Regs, host, thread};
use std::sync::atomic::Ordering;

/// Read a NUL-terminated string from guest memory.
///
/// # Safety
/// `addr` points to a NUL-terminated string in guest memory.
unsafe fn read_cstr(addr: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = addr;
    loop {
        // SAFETY: the caller guarantees a NUL-terminated string.
        let b = unsafe { (p as *const u8).read() };
        if b == 0 {
            return out;
        }
        out.push(b);
        p += 1;
    }
}

/// Read a NULL-terminated array of string pointers (`argv`/`envp`).
///
/// # Safety
/// `addr` points to a NULL-terminated array of pointers, each to a C string.
unsafe fn read_cstr_array(addr: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if addr == 0 {
        return out;
    }
    let mut p = addr;
    loop {
        // SAFETY: the caller guarantees a NULL-terminated pointer array.
        let ptr = unsafe { (p as *const u64).read() };
        if ptr == 0 {
            return out;
        }
        // SAFETY: each non-null entry points to a C string.
        out.push(unsafe { read_cstr(ptr) });
        p += 8;
    }
}

/// `execve(path, argv, envp)`: replace the current program image with a new
/// one and start it. Returns a negative errno on failure; on success it does
/// not return (it enters the new program).
///
/// The new program is checked first, so a bad one leaves the caller running
/// with an error; then the old program's memory is unmapped (every guest
/// mapping is tracked, see `fwe_kernel::mm::track`) and the new one loaded
/// in its place, so a program can exec one linked at the same addresses —
/// itself, for instance. A failure after that point is fatal, as on Linux.
/// Descriptors marked close-on-exec are closed. `execve` in a process with
/// other live threads is not supported yet.
pub fn do_execve(regs: &Regs) -> Result<Regs, i64> {
    // SAFETY: the guest passed a path and argv/envp pointers.
    let (path, args, env) =
        unsafe { (read_cstr(regs.x[0]), read_cstr_array(regs.x[1]), read_cstr_array(regs.x[2])) };

    let mut guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let k = guard.as_mut().unwrap();
    let page = page_size();
    let strace = k.tracer.enabled;
    let platform =
        NativePlatform { tp_slot: thread_pointer_slot(), x18_slot: x18_slot(), page_size: page };
    let fs = k.fs.as_ref().expect("filesystem configured");

    let file = fs.read(&path).map_err(err)?;
    // The old image is untouched on failure, so the guest can handle it.
    crate::check_image(&file, fs).map_err(err)?;
    let arg_refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env_refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    // The point of no return: the old program's memory goes.
    fwe_kernel::mm::release_guest_memory();
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

/// Move host descriptor `fd` to a high number, close-on-exec, so a
/// descriptor fwe holds for itself in the guest's table stays out of the way
/// of the numbers the guest expects to get.
fn high_fd(fd: i32) -> i32 {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `lim` is a valid out-parameter.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    let floor = (lim.rlim_cur.min(1 << 16) as i32 - 64).max(10);
    // SAFETY: plain host calls on a descriptor this module opened.
    unsafe {
        let high = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor);
        if high < 0 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            return fd;
        }
        libc::close(fd);
        high
    }
}

/// `fork` (a non-thread `clone`): duplicate the process with host `fork`.
/// The child continues with `x0` = 0 (on `child_stack` if one was given);
/// the parent gets the child pid.
///
/// A multithreaded guest forks with the kernel lock and every kernel
/// registry lock held ([`fwe_kernel::fork_locked`]), so the child, which has
/// only the forking thread, cannot inherit a lock another thread held.
///
/// With `vfork` (`CLONE_VM | CLONE_VFORK`, as `posix_spawn` and `vfork` use)
/// the child gets a copy of the address space rather than sharing it, and
/// the parent waits until the child has called `execve` or exited, as Linux
/// suspends it. That suits the spawn helpers, which only exec or exit in the
/// child; a child that writes to memory the parent later reads (glibc's
/// `posix_spawn` reporting an exec failure) is not seen by the parent.
pub fn do_fork(parent: &Regs, vfork: bool) -> i64 {
    let flags = parent.x[0];
    let child_stack = parent.x[1];
    let parent_tid = parent.x[2];
    let child_tid = parent.x[4];

    // A pipe whose write end only the child holds: it closes when the child
    // execs (it is close-on-exec) or exits, which ends the parent's wait.
    let mut done = [-1i32; 2];
    if vfork {
        // SAFETY: plain host call with a 2-element array.
        if unsafe { libc::pipe(done.as_mut_ptr()) } != 0 {
            return fwe_kernel::host::last_error();
        }
        done = [high_fd(done[0]), high_fd(done[1])];
    }

    let pid = {
        let _kernel = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        fwe_kernel::fork_locked()
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
        }
        thread::init_main(host::getpid() as i32);
        LIVE_THREADS.store(1, Ordering::SeqCst);
        if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
            // SAFETY: the guest supplied a writable int pointer.
            unsafe { (child_tid as *mut i32).write(thread::tid()) };
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
        // SAFETY: the guest supplied a writable int pointer.
        unsafe { (parent_tid as *mut i32).write(pid) };
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
    if r > 0 && wstatus != 0 {
        // SAFETY: the guest passed a writable int for the status.
        unsafe { (wstatus as *mut i32).write(linux_wstatus(status)) };
    }
    if r > 0 {
        // SAFETY: the guest passed a buffer for a `struct rusage`, or null.
        unsafe { host::write_rusage(rusage, &usage) };
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
        // SAFETY: the guest passed a buffer for a `siginfo_t` (128 bytes);
        // `si` was filled by the host.
        unsafe {
            std::ptr::write_bytes(infop as *mut u8, 0, 128);
            if si.si_pid() != 0 {
                let code = si.si_code;
                let status = if matches!(code, w::CLD_KILLED | w::CLD_DUMPED | w::CLD_STOPPED) {
                    host::signal_to_linux(si.si_status()) as i32
                } else {
                    si.si_status()
                };
                let p = infop as *mut i32;
                p.write(fwe_abi::signal::SIGCHLD as i32); // si_signo
                p.add(2).write(code); // si_code
                p.add(4).write(si.si_pid()); // si_pid
                p.add(5).write(si.si_uid() as i32); // si_uid
                p.add(6).write(status); // si_status
            }
        }
    }
    if rusage != 0 {
        // SAFETY: the guest passed a buffer for a `struct rusage`.
        unsafe {
            std::ptr::write_bytes(rusage as *mut u8, 0, fwe_abi::resource_usage::RUSAGE_SIZE)
        };
    }
    0
}
