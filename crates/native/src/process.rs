//! Process system calls for the native backend: `execve`, `fork` and `wait`.

use crate::{
    KERNEL, LIVE_THREADS, NativePlatform, load_image, page_size, thread_pointer_slot, trap,
};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::{Regs, host, thread};
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
/// The old image's mappings are not reclaimed (full address-space teardown
/// needs mapping tracking), so this suits the common fork-then-exec and
/// exec-chain cases. `execve` in a process with other live threads is not
/// supported yet.
pub fn do_execve(regs: &Regs) -> i64 {
    // SAFETY: the guest passed a path and argv/envp pointers.
    let (path, args, env) =
        unsafe { (read_cstr(regs.x[0]), read_cstr_array(regs.x[1]), read_cstr_array(regs.x[2])) };

    let mut guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let k = guard.as_mut().unwrap();
    let page = page_size();
    let strace = k.tracer.enabled;
    let platform = NativePlatform { tp_slot: thread_pointer_slot(), page_size: page };
    let fs = k.fs.as_ref().expect("filesystem configured");

    let file = match fs.read(&path) {
        Ok(f) => f,
        Err(e) => return err(e),
    };
    let arg_refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env_refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    let out = match load_image(&file, &path, &arg_refs, &env_refs, fs, &platform, page, strace) {
        Ok(out) => out,
        // The old image is untouched on failure, so the guest can handle the
        // error; report it as "not an executable".
        Err(_) => return err(errno::ENOEXEC),
    };

    k.exec_reset();
    k.brk = out.brk;
    let (sp, entry) = (out.sp, out.entry);
    drop(guard);

    // We jump straight into the new program instead of returning through the
    // signal handler, so the handled SIGTRAP is still masked; unblock it (and
    // everything else) so the new program's traps are delivered.
    trap::unblock_all_signals();
    // Enter the new program with a fresh register state.
    trap::enter_guest(sp, entry)
}

/// `fork` (a non-thread `clone`): duplicate the process with host `fork`.
/// The child continues with `x0` = 0; the parent gets the child pid. Only a
/// single-threaded guest can fork safely (another thread could hold a lock
/// across the fork), so a multithreaded fork returns `ENOSYS`.
pub fn do_fork(parent: &Regs) -> i64 {
    let flags = parent.x[0];
    let parent_tid = parent.x[2];
    let child_tid = parent.x[4];

    if LIVE_THREADS.load(Ordering::SeqCst) != 1 {
        return err(errno::ENOSYS);
    }

    // SAFETY: fork with no kernel lock held; the child re-initializes its
    // process-global state below before running any guest code.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return fwe_kernel::host::last_error();
    }
    if pid == 0 {
        // Child: a new process. It returns through the signal handler, which
        // restores the mask, but reset it explicitly to be safe. Reset
        // identity and the live-thread count, and honor the child tid flags
        // into the (copied) guest memory.
        trap::unblock_all_signals();
        thread::init_main(host::getpid() as i32);
        LIVE_THREADS.store(1, Ordering::SeqCst);
        if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
            // SAFETY: the guest supplied a writable int pointer.
            unsafe { (child_tid as *mut i32).write(thread::tid()) };
        }
        if flags & cl::CLONE_CHILD_CLEARTID != 0 && child_tid != 0 {
            thread::set_clear_child_tid(child_tid);
        }
        0
    } else {
        // Parent: the child's pid.
        if flags & cl::CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
            // SAFETY: the guest supplied a writable int pointer.
            unsafe { (parent_tid as *mut i32).write(pid) };
        }
        pid as i64
    }
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
/// without the kernel lock. `rusage` is zero-filled (not yet translated).
pub fn do_wait4(regs: &Regs) -> i64 {
    let pid = regs.x[0] as i32;
    let wstatus = regs.x[1];
    let options = regs.x[2] as libc::c_int;
    let rusage = regs.x[3];

    // WNOHANG | WUNTRACED | WCONTINUED share values with Linux.
    let host_options = options & (libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED);
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is a valid out-parameter; no guest rusage is passed to
    // the host (layouts differ), so pass null and zero the guest copy below.
    let r = unsafe { libc::wait4(pid, &mut status, host_options, std::ptr::null_mut()) };
    if r < 0 {
        return fwe_kernel::host::last_error();
    }
    if r > 0 && wstatus != 0 {
        // SAFETY: the guest passed a writable int for the status.
        unsafe { (wstatus as *mut i32).write(linux_wstatus(status)) };
    }
    if r > 0 && rusage != 0 {
        // `struct rusage` is 144 bytes on arm64 Linux; zero it for now.
        // SAFETY: the guest passed a buffer for a `struct rusage`.
        unsafe { std::ptr::write_bytes(rusage as *mut u8, 0, 144) };
    }
    r as i64
}
