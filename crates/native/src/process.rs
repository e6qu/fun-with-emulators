//! Process system calls for the native backend: `execve`, `fork` (and the
//! `vfork`-style `clone`), `wait4` and `waitid`.

use crate::{
    KERNEL, LIVE_THREADS, NativePlatform, load_image, page_size, thread_pointer_slot, trap,
    x18_slot,
};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::mm::region;
use fwe_kernel::reaper;
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
    let mut args = uaccess::read_cstr_array(argv, ARG_MAX).map_err(err)?;
    let env = uaccess::read_cstr_array(envp, ARG_MAX).map_err(err)?;
    // No arguments at all: the program gets one empty one, as Linux gives
    // it, so its `argv[0]` is a string.
    if args.is_empty() {
        args.push(Vec::new());
    }
    Ok((args, env))
}

/// `execveat(dirfd, path, argv, envp, flags)`: `execve` of the program
/// `dirfd`, `path` and `flags` name ([`fwe_kernel::Kernel::execveat_path`]).
pub fn do_execveat(regs: &Regs) -> Result<Regs, i64> {
    use fwe_kernel::uaccess;
    let rel = uaccess::read_cstr(regs.x[1], uaccess::PATH_MAX).map_err(err)?;
    let (args, env) = read_exec_args(regs.x[2], regs.x[3])?;
    let path = {
        let guard = KERNEL.lock();
        guard.as_ref().unwrap().execveat_path(regs.x[0] as i32, &rel, regs.x[4]).map_err(err)?
    };
    exec_program(path, args, env)
}

/// Replace the program with `path` (a guest path), given its arguments and
/// environment. Returns the new program's registers, or a negated errno
/// while the old program is still intact.
fn exec_program(path: Vec<u8>, args: Vec<Vec<u8>>, env: Vec<Vec<u8>>) -> Result<Regs, i64> {
    let mut guard = KERNEL.lock();
    let k = guard.as_mut().unwrap();
    let page = page_size();
    let strace = k.tracer;
    let platform =
        NativePlatform { tp_slot: thread_pointer_slot(), x18_slot: x18_slot(), page_size: page };
    // The calling thread's view is what the program runs with.
    k.adopt_thread_view();
    // A script runs its interpreter; the path run by names the program.
    let run_by = path.clone();
    let (path, args) = k.exec_target(path, args).map_err(err)?;
    let fs = k.fs.as_ref().expect("filesystem configured");
    let (file, file_id) = match k.take_exec_file(&path) {
        Some(file) => file,
        None => fs.read_identified(&path).map_err(err)?,
    };
    fwe_kernel::timing::mark("exec: read");
    let vm_reason = crate::vm_reason(&file);
    if let Some(why) = &vm_reason {
        k.tracer.note(&format!("runs in the VM: {why}"));
    }
    let vm = vm_reason.is_some();
    // A program only the VM can run, where there is none: the exec fails
    // while the caller is intact (podman's pause process then waits in a
    // loop of its own, say), rather than once it has gone.
    if vm && !crate::hv::usable() {
        return Err(err(fwe_abi::errno::ENOEXEC));
    }
    // A program only the VM can run, an exec from a process with other
    // threads (which the exec ends), or from one with the Mac's Vulkan driver in
    // its memory (its threads and objects cannot be carried over): replace
    // this process with a fresh fwe.
    if vm
        || LIVE_THREADS.load(Ordering::SeqCst) > 1
        || fwe_kernel::vulkan::device::driver_in_memory()
    {
        fwe_kernel::release_robust_lists();
        let state = k.exec_state();
        crate::jitcount::write_seen();
        crate::jit::keep_made();
        // Named as the new fwe will name it (a descriptor's file, by its name).
        let exe = fs.exec_fd(&path).map_or_else(|| path.clone(), |fd| fs.fd_target(fd));
        let named = fwe_kernel::fs::exec_name(&run_by, &exe);
        return Err(crate::reexec(
            crate::Program { path: &path, named: &named, args: &args, env: &env },
            fs,
            strace,
            &state,
            || {},
        ));
    }
    // The old image is untouched on failure, so the guest can handle it.
    fwe_kernel::timing::mark("exec: checked for re-exec");
    fwe_kernel::timing::mark("backend: native");
    crate::check_image(&file, fs).map_err(err)?;
    // A program run through a descriptor (a memfd, `/proc/self/exe`) is
    // held through it, for `/proc/self/exe`: the descriptor it was run
    // through might close on exec. Another is opened once loaded.
    let exe_fd = match fs.exec_fd(&path) {
        Some(fd) => {
            let held = fwe_kernel::fdtable::dup_reserved(fd).map_err(err)?;
            fwe_kernel::fdmarks::duplicated(fd, held);
            Some(held)
        }
        None => None,
    };
    let arg_refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env_refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    // The credentials the program starts with, as `exec_reset` makes them.
    let ids = k.exec_aux_ids();
    // The point of no return: the old program's memory goes, and a vfork
    // parent can resume. The robust futexes its threads hold are released
    // first.
    fwe_kernel::release_robust_lists();
    fwe_kernel::timing::mark("exec: checked");
    fwe_kernel::mm::release_guest_memory();
    crate::jit::reset();
    crate::prepare::reset();
    let done = VFORK_DONE.swap(-1, Ordering::SeqCst);
    if done >= 0 {
        // SAFETY: closing the pipe end this child holds for its parent.
        unsafe { libc::close(done) };
    }
    let out = match load_image(
        (&file, file_id),
        &path,
        &arg_refs,
        &env_refs,
        fs,
        &platform,
        page,
        strace,
        fwe_kernel::rlimits::get(fwe_abi::resource::RLIMIT_STACK).0,
        ids,
    ) {
        Ok(out) => out,
        Err(e) => {
            let msg = format!("fwe: execve {}: {e}\n", String::from_utf8_lossy(&path));
            // SAFETY: writing a diagnostic to standard error.
            unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
            k.platform.kill_self(libc::SIGSEGV)
        }
    };

    fwe_kernel::timing::mark("exec: loaded");
    k.close_on_exec();
    k.exec_reset();
    k.brk = out.brk;
    if let Some(fs) = k.fs.as_mut() {
        fs.set_exe_fd(exe_fd);
        let exe = fs.exe_fd_target().unwrap_or_else(|| path.clone());
        let named = fwe_kernel::fs::exec_name(&run_by, &exe);
        // What the process's record tells of it, written once.
        fwe_kernel::procreg::batch(|| {
            fs.set_proc_info(
                exe,
                &named,
                crate::cmdline(&arg_refs),
                crate::ncpu(),
                crate::hostname(),
            );
            // The program's file, held for `/proc/self/exe`.
            if exe_fd.is_none()
                && let Some(fd) = fs.open_program(&path)
            {
                fs.set_exe_fd(Some(fd));
            }
            fs.set_auxv(out.auxv);
            fs.publish();
        });
    }
    fwe_kernel::timing::mark("exec: published");
    // The new program starts with every register zero, as Linux leaves it;
    // the trap handler returns into it.
    Ok(Regs { sp: out.sp, pc: out.entry, ..Regs::default() })
}

/// In a `vfork` child, the write end of the pipe its parent waits on
/// (see [`do_fork`]), or -1. It is fwe's, so close-on-exec does not reach
/// it; `execve` closes it once the new program is certain to load.
static VFORK_DONE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Both ends of a new pipe moved into fwe's reserved range, or both closed
/// and the error (`EAGAIN`: the range is full).
pub(crate) fn reserve_pair(fds: [i32; 2]) -> Result<[i32; 2], i32> {
    let r = fwe_kernel::fdtable::reserve(fds[0]);
    let w = fwe_kernel::fdtable::reserve(fds[1]);
    match (r, w) {
        (Ok(r), Ok(w)) => Ok([r, w]),
        (r, w) => {
            for fd in [r, w].into_iter().flatten() {
                // SAFETY: closing a descriptor made by the caller.
                unsafe { libc::close(fd) };
            }
            Err(fwe_abi::errno::EAGAIN)
        }
    }
}

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
/// With `share` (`CLONE_VM`) the child shares the guest's memory, as it is
/// mapped at the fork, with the parent: what either writes there the other
/// sees. Its own mappings are its own: an `mmap` or `munmap` in the child
/// does not reach the parent, nor one in the parent the child. With `wait`
/// (`CLONE_VFORK`, as `posix_spawn` and `vfork` use) the parent waits until
/// the child has called `execve` or exited, as Linux suspends it; what the
/// child writes before then (glibc's `posix_spawn` reporting an exec
/// failure, say) the parent sees.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn do_fork(parent: &Regs, a: fwe_kernel::CloneArgs, share: bool, wait: bool) -> i64 {
    let fwe_kernel::CloneArgs { flags, stack: child_stack, parent_tid, child_tid, .. } = a;

    let mut done = [-1i32; 2];
    let (pid, shown) = {
        let mut kernel = KERNEL.lock();
        // A pipe whose write end only the child holds: it closes when the
        // child execs or exits, which ends the parent's wait. It is made,
        // and the parent's write end closed, under the kernel lock, where
        // every fork is: no other thread's child inherits the write end (the
        // parent would wait for that child too, which might never end: Go's
        // runtime starts processes from two threads at once).
        if wait {
            // SAFETY: plain host call with a 2-element array.
            if unsafe { libc::pipe(done.as_mut_ptr()) } != 0 {
                return fwe_kernel::host::last_error();
            }
            done = match reserve_pair(done) {
                Ok(d) => d,
                Err(e) => return fwe_abi::err(e),
            };
        }
        let k = kernel.as_mut().unwrap();
        fwe_kernel::timing::mark("fork: begins");
        // The child's namespaces, which it inherits from this view.
        let mut token = match k.fork_begin(&a) {
            Ok(t) => t,
            Err(e) => {
                for fd in done.into_iter().filter(|&fd| fd >= 0) {
                    // SAFETY: closing the pipe opened above.
                    unsafe { libc::close(fd) };
                }
                return fwe_abi::err(e);
            }
        };
        fwe_kernel::timing::mark("fork: namespaces and limits checked");
        // The child writes its whole record as it starts.
        k.fork_child_writes(&mut token);
        let kqueues = fwe_kernel::kqueue_state();
        // A child of CLONE_VM shares the guest's memory: its private parts
        // are shared for the fork, then copied again by any later one (in
        // either process). The kernel lock keeps the guest's mappings as
        // they are.
        let share =
            if share { region::private_parts(&fwe_kernel::mm::tracked()) } else { Vec::new() };
        let set_shared = |on: bool| {
            for &(start, len) in &share {
                region::set_shared_on_fork(start, len, on);
            }
        };
        fwe_kernel::timing::mark("fork: prepared");
        // A fault signal sent to the child before it is set up is kept
        // for it (`trap::post_early`).
        trap::FORKING.store(host::pid().get(), Ordering::SeqCst);
        // The translations whole in the child.
        let mut jit = crate::jit::hold();
        let pid = fwe_kernel::fork_locked(|| {
            fwe_kernel::timing::mark("fork: locked");
            set_shared(true);
            let pid = crate::quiesce::fork_stopped(|| {
                let (pid, b) = fork_with_signals_held(
                    // SAFETY: plain host call; the child continues with only
                    // the calling thread, as on Linux.
                    || unsafe { libc::fork() },
                    // Before the parent takes signals again: a child that
                    // ends at once is told of with its own signal.
                    // A foster child's end is its parent's to hear of
                    // (see `reaper`), not this process's.
                    |child| {
                        let sig =
                            if flags & cl::CLONE_PARENT != 0 { 0 } else { flags & cl::CSIGNAL };
                        reaper::set_exit_signal(child, sig);
                        // Its record written here, where every page is
                        // mapped already, before it goes on.
                        if k.fork_write_child(&token, child) { WROTE } else { GO }
                    },
                );
                if pid == 0 {
                    token.set_written(b == WROTE);
                }
                pid
            });
            set_shared(false);
            pid
        });
        // The child's code cache's views, its own.
        if pid == 0 {
            crate::jit::forked(&mut jit);
        }
        drop(jit);
        if pid != 0 {
            trap::FORKING.store(0, Ordering::SeqCst);
        }
        fwe_kernel::timing::mark(if pid == 0 { "fork: child" } else { "fork: parent" });
        let e = fwe_kernel::host::last_error();
        // The child's pid: in the child, its own namespace's; in the
        // parent, as the parent sees it.
        let shown = if pid == 0 {
            // The parent's pending signals are not the child's: forgotten
            // before any is taken (they stay blocked until the child enters
            // guest code), once the locks held across the fork are free.
            thread::forked();
            fwe_kernel::timing::mark("fork: child's threads forgotten");
            // A signal sent to it as it was being made is its own.
            trap::post_early();
            // The code pages its parent wrote are the parent's to keep.
            fwe_kernel::lazycode::forked();
            // The parent's threads' stacks are none of the child's to reuse.
            crate::stacks::forked();
            // Nor are its waiting threads.
            crate::pool::forked();
            // The kqueues first, at their numbers, before anything the child
            // starts (a reaper's thread) makes descriptors of its own.
            fwe_kernel::restore_kqueues(&kqueues);
            fwe_kernel::timing::mark("fork: child's kqueues restored");
            let r = k.fork_child(token);
            fwe_kernel::timing::mark("fork: child's record written");
            r
        } else {
            k.fork_parent(token, pid)
        };
        // A child with memory of its own has none of what was to be wiped.
        if pid == 0 && share.is_empty() {
            fwe_kernel::mm::forked_child();
        }
        if pid > 0 && done[1] >= 0 {
            // SAFETY: the child holds its own copy of the write end.
            unsafe { libc::close(done[1]) };
            done[1] = -1;
        }
        // Nor any of what was not to be inherited.
        if pid == 0 && share.is_empty() {
            kernel.as_mut().unwrap().unmap_dont_fork();
        }
        fwe_kernel::timing::mark("fork: what is not inherited unmapped");
        if pid == 0 {
            // SAFETY: this is the child, its only thread the caller, which
            // holds the lock.
            unsafe { KERNEL.forked_child(&kernel) };
        }
        (if pid < 0 { e } else { pid as i64 }, shown)
    };
    if pid < 0 {
        let e = pid;
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
        if wait {
            // SAFETY: closing the read end the parent uses.
            unsafe { libc::close(done[0]) };
            VFORK_DONE.store(done[1], Ordering::SeqCst);
        } else {
            VFORK_DONE.store(-1, Ordering::SeqCst);
        }
        thread::init_main(shown);
        LIVE_THREADS.store(1, Ordering::SeqCst);
        // The GPU device's opens, and the Mac's driver, are the parent's.
        fwe_kernel::vulkan::device::forked_child();
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
        // Its waits from here on are the program's.
        fwe_kernel::procstore::entered();
        trap::prepare_guest_entry();
        fwe_kernel::timing::mark("fork: child enters the guest");
        // SAFETY: `regs` is the parent's runnable context with x0 cleared.
        unsafe { trap::enter_guest_full(&regs) }
    }
    // Parent: the child's pid.
    if flags & cl::CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        let _ = fwe_kernel::uaccess::write(parent_tid, shown);
    }
    if wait {
        // SAFETY: plain host calls on the pipe opened above.
        unsafe {
            let mut b = 0u8;
            while libc::read(done[0], (&mut b as *mut u8).cast(), 1) < 0
                && host::last_errno().is(libc::EINTR)
            {}
            libc::close(done[0]);
        }
    }
    shown as i64
}

/// Run `fork` with every asynchronous signal blocked on this thread. The parent
/// unblocks them again at once; the child keeps them blocked until it sets
/// the guest's mask as it enters guest code (`trap::prepare_guest_entry`),
/// so no handler runs in it before its state is its own. Inside `fork`,
/// before the child's libc has caught up, its `getpid` still answers with
/// the parent's pid: the relayed form of a guest's `SIGKILL` arriving then
/// would have the child kill its parent.
///
/// The child goes on only once the parent has unblocked them: a signal the
/// child sends its parent sooner would be left pending, and macOS empties
/// the `siginfo` of a signal it holds blocked, so its sender would be lost.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn fork_with_signals_held(
    fork: impl FnOnce() -> libc::pid_t,
    in_parent: impl FnOnce(libc::pid_t) -> u8,
) -> (libc::pid_t, u8) {
    let mut go = [-1i32; 2];
    // SAFETY: a valid out-array; on failure the fork goes on without it.
    if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
        go = [-1, -1];
    }
    // SAFETY: plain host calls on initialized signal sets and the pipe
    // opened above, each end closed once in each process.
    unsafe {
        let mut all = host::full_sigset();
        // Memory faults stay deliverable: the child's checked copies of
        // guest memory recover from them, and a blocked one would end it.
        // The other fault signals fwe raises nowhere before the child
        // enters guest code, so they are held like the rest: one sent the
        // moment the child exists arrives when it is ready for it (inside
        // the host `fork` its handler would read the parent's mailbox, and
        // take the signal for a fault).
        for sig in [libc::SIGSEGV, libc::SIGBUS] {
            libc::sigdelset(&mut all, sig);
        }
        libc::sigdelset(&mut all, libc::SIGSYS);
        let held = host::MaskGuard::block(&all);
        let pid = fork();
        fwe_kernel::timing::mark("fork: host fork returned");
        // What a failed fork left, kept for the caller across the calls below.
        let saved = host::last_errno();
        let mut b = GO;
        if pid > 0 {
            b = in_parent(pid);
        }
        if pid != 0 {
            drop(held);
            if go[1] >= 0 {
                libc::write(go[1], (&b as *const u8).cast(), 1);
            }
        } else {
            // The child goes on with them held, until it takes its own mask.
            held.keep();
            if go[0] >= 0 {
                libc::close(go[1]);
                // Until the parent's byte, or its end (if it is gone:
                // then [`GO`], nothing written for it).
                while libc::read(go[0], (&mut b as *mut u8).cast(), 1) < 0
                    && host::last_errno().is(libc::EINTR)
                {}
                fwe_kernel::timing::mark("fork: child let go");
            }
        }
        for fd in go.into_iter().filter(|&fd| fd >= 0) {
            if pid == 0 && fd == go[1] {
                continue;
            }
            libc::close(fd);
        }
        host::set_errno(saved);
        (pid, b)
    }
}

/// The byte a forking parent lets its child go on with: [`WROTE`] when it
/// wrote the child's record for it, [`GO`] otherwise.
const GO: u8 = b'g';
const WROTE: u8 = b'w';

/// A `wait` reaped host process `pid`, which ended with Linux wait status
/// `wstatus`: its `SIGCHLD` given now if the host's has not landed, as
/// Linux sends it before `wait` returns ([`reaper::reaped_child_signal`]).
fn reaped_signal(pid: i32, wstatus: i32) {
    use fwe_abi::wait as w;
    // What a process descriptor of it reports from now on.
    fwe_kernel::pidfd::reaped(pid, wstatus);
    let (code, status) = match wstatus & 0x7f {
        0 => (w::CLD_EXITED, (wstatus >> 8) & 0xff),
        sig if wstatus & 0x80 != 0 => (w::CLD_DUMPED, sig),
        sig => (w::CLD_KILLED, sig),
    };
    // The child's real user, as its record keeps it until the reap is
    // done; a child fwe did not start is the host user's.
    // SAFETY: getuid cannot fail.
    let host_user = host::uid_to_initial(unsafe { libc::getuid() });
    let uid = fwe_kernel::ids::HostPid::new(pid)
        .and_then(fwe_kernel::procreg::kept_uid)
        .unwrap_or(host_user);
    let info = thread::SigInfo { code, pid, uid, status, value: 0, poll: None };
    reaper::reaped_child_signal(pid, info);
}

/// Encode a host `wait` status into the Linux layout a guest expects.
/// Host process `pid` ended so.
fn linux_wstatus(pid: i32, status: libc::c_int) -> i32 {
    if (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
        && let Some(s) =
            fwe_kernel::ids::HostPid::new(pid).and_then(fwe_kernel::procreg::end_status)
    {
        // It ended of a Linux signal, as it recorded: one the host lacks,
        // ignores by default, or with the core fwe dumped.
        return s;
    }
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

/// Which children a `wait4` of host pid argument `pid` waits for.
fn select_of(pid: i32) -> reaper::Select {
    match pid {
        -1 => reaper::Select::Any,
        // SAFETY: plain host call.
        0 => reaper::Select::Pgid(unsafe { libc::getpgrp() }),
        p if p > 0 => reaper::Select::Pid(p),
        p => reaper::Select::Pgid(-p),
    }
}

/// `wait4(pid, wstatus, options, rusage)`: reap a child. Blocks, so it runs
/// without the kernel lock.
pub fn do_wait4(regs: &Regs) -> i64 {
    // Options Linux does not know are refused first: besides those that
    // pick what to report, the ones that pick which children (all are
    // fwe's processes, so they change nothing).
    let options = regs.x[2];
    let known = fwe_abi::wait::WNOHANG
        | fwe_abi::wait::WUNTRACED
        | fwe_abi::wait::WCONTINUED
        | fwe_abi::wait::WNOTHREAD
        | fwe_abi::wait::WALL
        | fwe_abi::wait::WCLONE;
    if options & !known != 0 {
        return err(errno::EINVAL);
    }
    // The least pid has no group to name (Linux refuses it so).
    if regs.x[0] as i32 == i32::MIN {
        return err(errno::ESRCH);
    }
    // The child or group in the guest's pid namespace, as the host's.
    let pid = match regs.x[0] as i32 {
        p if p > 0 => match fwe_kernel::pidns::host_arg(p) {
            Ok(h) => h,
            Err(_) => return err(errno::ECHILD),
        },
        p if p < -1 => match fwe_kernel::pidns::host_arg(-p) {
            Ok(h) => -h,
            Err(_) => return err(errno::ECHILD),
        },
        p => p,
    };
    let wstatus = regs.x[1];
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
    if fwe_kernel::ptrace::tracing() {
        // A tracee named alone, as its mailbox is named (a thread's number
        // is its process's to the host).
        let guest = regs.x[0] as i32;
        let tracee = if guest > 0 { fwe_kernel::ptrace::target_of(guest) } else { None };
        return wait4_tracer(pid, tracee, host_options, wstatus, rusage);
    }
    start_watcher_if_wanted();
    let want = Want {
        exited: true,
        stopped: options & fwe_abi::wait::WUNTRACED != 0,
        continued: options & fwe_abi::wait::WCONTINUED != 0,
    };
    // Ends alone are the host's to report; stops and continues of fwe's,
    // and an adopted child's anything, are looked for too.
    if !reaper::active() && !want.stopped && !want.continued {
        let r = wait4_host(pid, host_options, wstatus, rusage);
        // A child that began to be traced while this waited, and stopped.
        if r == err(errno::EINTR) && fwe_kernel::ptrace::tracing() {
            let guest = regs.x[0] as i32;
            let tracee = if guest > 0 { fwe_kernel::ptrace::target_of(guest) } else { None };
            return wait4_tracer(pid, tracee, host_options, wstatus, rusage);
        }
        return r;
    }
    // Its own children, and those it adopted.
    let sel = select_of(pid);
    reaper_wait(
        sel,
        host_options & libc::WNOHANG != 0,
        want,
        || wait4_host(pid, host_options | libc::WNOHANG, wstatus, rusage),
        |e| {
            if wstatus != 0 && fwe_kernel::uaccess::write(wstatus, e.status).is_err() {
                return err(errno::EFAULT);
            }
            if rusage != 0
                && fwe_kernel::uaccess::zero(rusage, fwe_abi::resource_usage::RUSAGE_SIZE).is_err()
            {
                return err(errno::EFAULT);
            }
            i64::from(reaper::guest_pid(e))
        },
        false,
    )
}

/// What a `wait` reports: ends, stops, continues.
#[derive(Clone, Copy)]
struct Want {
    exited: bool,
    stopped: bool,
    continued: bool,
}

/// A `wait` for the children `sel` picks: `own` checks its own children
/// as the host reports them (without blocking; `ECHILD` when it has none),
/// then `adopted` reports one it adopted that ended, stopped or continued,
/// or an own child's stop or continue of fwe's, as `want` says (taken,
/// unless `peek`); until one is found, or there are none, or a signal
/// arrives (`EINTR`), unless `nohang`.
fn reaper_wait(
    sel: reaper::Select,
    nohang: bool,
    want: Want,
    own: impl Fn() -> i64,
    adopted: impl Fn(&fwe_kernel::procreg::Ended) -> i64,
    peek: bool,
) -> i64 {
    // One look at the own children, then the adopted ones: what to return,
    // if anything.
    let look = || {
        let r = own();
        if r != 0 && r != err(errno::ECHILD) {
            return Some(r);
        }
        reaper::busy(|| {
            // The living ones before the ended: a process records how it
            // ended before it forgets its record, so one ending meanwhile
            // is seen in one or the other.
            let live = reaper::has_live_adopted(sel);
            if want.exited
                && let Some(e) = reaper::take_adopted(sel, peek)
            {
                return Some(adopted(&e));
            }
            if (want.stopped || want.continued)
                && let Some(e) = reaper::take_own_change(sel, peek, want.stopped, want.continued)
            {
                return Some(adopted(&e));
            }
            if let Some(e) = reaper::take_change(sel, peek, want.stopped, want.continued) {
                return Some(adopted(&e));
            }
            (r == err(errno::ECHILD) && !live).then_some(r)
        })
    };
    loop {
        // Registered, with signals held, before looking: a change after
        // the look wakes the sleep below.
        let waiter = reaper::Waiter::new();
        if let Some(r) = look() {
            return r;
        }
        if nohang {
            return 0;
        }
        if fwe_kernel::thread::deliverable() != 0 {
            // A child ready is reported though a signal is pending, as
            // Linux's `wait` does: the reaper raises an adopted one's
            // SIGCHLD as it records its end, which can be after the look.
            return look().unwrap_or(err(errno::EINTR));
        }
        waiter.sleep();
    }
}

/// `wait4` of the host's children (`pid` is the host's), the result
/// written in Linux's layout.
/// `wait4` of a tracer: a stop of one of its tracees first (which the host
/// does not see: a tracee stops in fwe, [`fwe_kernel::ptrace`]), then its
/// Start the watcher this process was told it wants (it has a foster
/// child, see `reaper`), under the kernel lock, before a `wait` that would
/// otherwise ask only the host.
fn start_watcher_if_wanted() {
    if reaper::watcher_wanted() {
        let _kernel = KERNEL.lock();
        reaper::start_if_reaper();
    }
}

/// children as the host reports them, looking again as tracees stop.
/// `wait4` of a tracer: `pid` as the host names the child or group, and
/// `tracee` the one it names alone, as its mailbox is named.
fn wait4_tracer(
    pid: i32,
    tracee: Option<i32>,
    host_options: i32,
    wstatus: u64,
    rusage: u64,
) -> i64 {
    use fwe_kernel::ptrace::Tracee;
    // SAFETY: plain host calls.
    let pgid_of = |t: Tracee| unsafe { libc::getpgid(t.process.get()) };
    // SAFETY: as above.
    let my_pgid = unsafe { libc::getpgrp() };
    let wanted = |t: Tracee| match pid {
        -1 => true,
        0 => pgid_of(t) == my_pgid,
        p if p > 0 => Some(t.id) == tracee,
        p => pgid_of(t) == -p,
    };
    // A thread is no host child: only its stops are looked for.
    let thread =
        tracee.filter(|&i| fwe_kernel::ptrace::process_of(i).is_some_and(|p| p.get() != i));
    loop {
        let seen = fwe_kernel::ptrace::inbox_generation();
        if let Some((t, status)) = fwe_kernel::ptrace::take_stop(wanted, false) {
            if wstatus != 0 && fwe_kernel::uaccess::write(wstatus, status).is_err() {
                return err(errno::EFAULT);
            }
            if rusage != 0 && fwe_kernel::uaccess::write(rusage, [0u64; 18]).is_err() {
                return err(errno::EFAULT);
            }
            return i64::from(t.number());
        }
        if let Some(i) = thread {
            if !fwe_kernel::ptrace::traces(i) {
                return err(errno::ECHILD);
            }
            if host_options & libc::WNOHANG != 0 {
                return 0;
            }
            if fwe_kernel::thread::deliverable() != 0 {
                return err(errno::EINTR);
            }
            fwe_kernel::ptrace::wait_for_stop(seen, std::time::Duration::from_millis(20));
            continue;
        }
        // An own child's stop or continue of fwe's (one it does not trace).
        let (stopped, continued) =
            (host_options & libc::WUNTRACED != 0, host_options & libc::WCONTINUED != 0);
        if (stopped || continued)
            && let Some(e) = reaper::take_own_change(select_of(pid), false, stopped, continued)
        {
            if wstatus != 0 && fwe_kernel::uaccess::write(wstatus, e.status).is_err() {
                return err(errno::EFAULT);
            }
            if rusage != 0 && fwe_kernel::uaccess::write(rusage, [0u64; 18]).is_err() {
                return err(errno::EFAULT);
            }
            return i64::from(reaper::guest_pid(&e));
        }
        let r = wait4_host(pid, host_options | libc::WNOHANG, wstatus, rusage);
        // A traced process that is not a child is no host child to wait for.
        let traced_other = r == err(errno::ECHILD)
            && (pid > 0 && tracee.is_some_and(fwe_kernel::ptrace::traces) || pid == -1);
        if r != 0 && !(traced_other && pid > 0) {
            return r;
        }
        if host_options & libc::WNOHANG != 0 {
            return 0;
        }
        if fwe_kernel::thread::deliverable() != 0 {
            return err(errno::EINTR);
        }
        fwe_kernel::ptrace::wait_for_stop(seen, std::time::Duration::from_millis(20));
    }
}

/// `waitid` of a tracer: a stop of one of its tracees first, reported as
/// `CLD_TRAPPED` with the stop's signal (and event) as its status, then its
/// children as the host reports them, looking again as tracees stop.
///
/// `idtype` and `id` as the host names the child or group, and `tracee`
/// the one `P_PID` names, as its mailbox is named.
fn waitid_tracer(
    idtype: libc::idtype_t,
    id: libc::id_t,
    tracee: Option<i32>,
    host_options: i32,
    infop: u64,
    options: u64,
) -> i64 {
    use fwe_kernel::ptrace::Tracee;
    const CLD_TRAPPED: i32 = 4;
    // SAFETY: plain host call.
    let pgid_of = |t: Tracee| unsafe { libc::getpgid(t.process.get()) };
    let wanted = |t: Tracee| match idtype {
        libc::P_PID => Some(t.id) == tracee,
        libc::P_PGID => pgid_of(t) == id as i32,
        _ => true,
    };
    // A thread is no host child: only its stops are looked for.
    let thread = tracee.filter(|&i| {
        idtype == libc::P_PID && fwe_kernel::ptrace::process_of(i).is_some_and(|p| p.get() != i)
    });
    let peek = options & fwe_abi::wait::WNOWAIT != 0;
    loop {
        let seen = fwe_kernel::ptrace::inbox_generation();
        if let Some((t, status)) = fwe_kernel::ptrace::take_stop(wanted, peek) {
            if infop != 0 {
                let mut words = [0i32; 32];
                words[0] = fwe_abi::signal::SIGCHLD as i32;
                words[2] = CLD_TRAPPED;
                words[4] = t.number();
                // Its process's real user, as the sender.
                words[5] = fwe_kernel::procreg::ids(t.process)[0] as i32;
                words[6] = (status >> 8) & 0xffff;
                if fwe_kernel::uaccess::write(infop, words).is_err() {
                    return err(errno::EFAULT);
                }
            }
            return 0;
        }
        if let Some(i) = thread {
            if !fwe_kernel::ptrace::traces(i) {
                return err(errno::ECHILD);
            }
            if host_options & libc::WNOHANG != 0 {
                // None to report: `si_pid` 0, as Linux leaves it.
                if infop != 0 && fwe_kernel::uaccess::write(infop, [0i32; 32]).is_err() {
                    return err(errno::EFAULT);
                }
                return 0;
            }
            if fwe_kernel::thread::deliverable() != 0 {
                return err(errno::EINTR);
            }
            fwe_kernel::ptrace::wait_for_stop(seen, std::time::Duration::from_millis(20));
            continue;
        }
        // An own child's stop or continue of fwe's (one it does not trace).
        let (stopped, continued) =
            (options & fwe_abi::wait::WSTOPPED != 0, options & fwe_abi::wait::WCONTINUED != 0);
        let sel = match idtype {
            libc::P_PID => reaper::Select::Pid(id as i32),
            libc::P_PGID => reaper::Select::Pgid(id as i32),
            _ => reaper::Select::Any,
        };
        if (stopped || continued)
            && let Some(e) = reaper::take_own_change(sel, peek, stopped, continued)
        {
            if infop != 0 {
                let (code, status) = reaper::child_code(e.status);
                let mut words = [0i32; 32];
                words[0] = fwe_abi::signal::SIGCHLD as i32;
                words[2] = code;
                words[4] = reaper::guest_pid(&e);
                words[5] = fwe_kernel::procreg::ids(e.pid)[0] as i32;
                words[6] = status;
                if fwe_kernel::uaccess::write(infop, words).is_err() {
                    return err(errno::EFAULT);
                }
            }
            return 0;
        }
        let r = waitid_host(idtype, id, host_options | libc::WNOHANG, infop, options);
        let reported = r == 0
            && infop != 0
            && fwe_kernel::uaccess::read::<i32>(infop + 16).is_ok_and(|pid| pid != 0);
        let traced_other = r == err(errno::ECHILD)
            && idtype == libc::P_PID
            && tracee.is_some_and(fwe_kernel::ptrace::traces);
        if (r < 0 && !traced_other) || reported || host_options & libc::WNOHANG != 0 {
            return r.min(0);
        }
        if fwe_kernel::thread::deliverable() != 0 {
            return err(errno::EINTR);
        }
        fwe_kernel::ptrace::wait_for_stop(seen, std::time::Duration::from_millis(20));
    }
}

fn wait4_host(pid: i32, host_options: i32, wstatus: u64, rusage: u64) -> i64 {
    if host_options & libc::WNOHANG != 0 && pid > 0 && reaper::init_unreapable(pid) {
        return 0;
    }
    let mut status: libc::c_int = 0;
    // SAFETY: an all-zero rusage is a valid out-parameter.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    fwe_kernel::timing::mark("wait: begins");
    // SAFETY: `status` and `usage` are valid out-parameters.
    let mut r = unsafe { libc::wait4(pid, &mut status, host_options, &mut usage) };
    fwe_kernel::timing::mark("wait: host wait returned");
    if r < 0 && host::last_errno().is(libc::EINTR) && host_options & libc::WNOHANG == 0 {
        // The child's own SIGCHLD can interrupt the wait before the host
        // reports the child: Linux reports a child that is ready over the
        // signal, so it is looked for once more.
        // SAFETY: as above.
        let again =
            unsafe { libc::wait4(pid, &mut status, host_options | libc::WNOHANG, &mut usage) };
        if again > 0 {
            r = again;
        } else {
            host::set_errno(host::HostErrno::new(libc::EINTR));
        }
    }
    if r < 0 {
        return fwe_kernel::host::last_error();
    }
    if r > 0
        && wstatus != 0
        && fwe_kernel::uaccess::write(wstatus, linux_wstatus(r, status)).is_err()
    {
        return err(errno::EFAULT);
    }
    if r > 0 && host::write_rusage(rusage, &usage).is_err() {
        return err(errno::EFAULT);
    }
    let guest = fwe_kernel::pidns::guest_ret(r as i64);
    if r > 0 && !libc::WIFSTOPPED(status) && !libc::WIFCONTINUED(status) {
        reaped_signal(r, linux_wstatus(r, status));
        // Reaped: its numbers are free again, and its records go.
        reaper::busy(|| {
            fwe_kernel::pidns::reaped(r);
            if let Some(p) = fwe_kernel::ids::HostPid::new(r) {
                fwe_kernel::procreg::reaped(p);
            }
            reaper::reaped_own_child(r);
        });
        reaper::reaped_child(r);
    }
    fwe_kernel::timing::mark("wait: reaped");
    guest
}

/// `waitid(idtype, id, infop, options, rusage)`: wait for a child state
/// change and report it as a `siginfo_t`. Blocks, so it runs without the
/// kernel lock. The host's `waitid` reports no resource usage, so `rusage`
/// is zero-filled.
pub fn do_waitid(regs: &Regs) -> i64 {
    use fwe_abi::wait as w;
    let (idtype, id, infop, options, rusage) =
        (regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4]);
    // In Linux's order: the options, then what they name.
    let known = w::WNOHANG
        | w::WNOWAIT
        | w::WEXITED
        | w::WSTOPPED
        | w::WCONTINUED
        | w::WNOTHREAD
        | w::WALL
        | w::WCLONE;
    if options & !known != 0 || options & (w::WEXITED | w::WSTOPPED | w::WCONTINUED) == 0 {
        return err(errno::EINVAL);
    }
    // A process descriptor names its process; one made non-blocking waits
    // as `WNOHANG` does, failing with `EAGAIN` when nothing has changed.
    let mut nonblock = false;
    // A tracee named alone, as its mailbox is named (a thread's number is
    // its process's to the host).
    let mut tracee = match idtype {
        w::P_PID if id as i32 > 0 => fwe_kernel::ptrace::target_of(id as i32),
        _ => None,
    };
    let (idtype, id) = match idtype {
        w::P_PIDFD => match fwe_kernel::pidfd::wait_target(id as i32) {
            Ok((host, nb)) => {
                nonblock = nb;
                tracee = Some(host);
                (libc::P_PID, host as libc::id_t)
            }
            Err(e) => return err(e),
        },
        w::P_ALL => (libc::P_ALL, 0),
        w::P_PID if id as i32 <= 0 => return err(errno::EINVAL),
        w::P_PGID if (id as i32) < 0 => return err(errno::EINVAL),
        w::P_PID => match fwe_kernel::pidns::host_arg(id as i32) {
            Ok(h) => (libc::P_PID, h as libc::id_t),
            Err(_) => return err(errno::ECHILD),
        },
        // SAFETY: plain host call.
        w::P_PGID if id == 0 => (libc::P_PGID, unsafe { libc::getpgrp() } as libc::id_t),
        w::P_PGID => match fwe_kernel::pidns::host_arg(id as i32) {
            Ok(h) => (libc::P_PGID, h as libc::id_t),
            Err(_) => return err(errno::ECHILD),
        },
        _ => return err(errno::EINVAL),
    };
    let options = if nonblock { options | w::WNOHANG } else { options };
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
    let zero_rusage = || {
        if rusage != 0
            && fwe_kernel::uaccess::zero(rusage, fwe_abi::resource_usage::RUSAGE_SIZE).is_err()
        {
            return err(errno::EFAULT);
        }
        0
    };
    if fwe_kernel::ptrace::tracing() {
        let r = waitid_tracer(idtype, id, tracee, host_options, infop, options);
        return if r < 0 { r } else { zero_rusage() };
    }
    start_watcher_if_wanted();
    // Ends alone are the host's to report (see `do_wait4`).
    if !reaper::active() && options & (w::WSTOPPED | w::WCONTINUED) == 0 {
        let r = waitid_host(idtype, id, host_options, infop, options);
        if nonblock && r == 0 {
            return err(errno::EAGAIN);
        }
        return if r < 0 { r } else { zero_rusage() };
    }
    let sel = match idtype {
        libc::P_PID => reaper::Select::Pid(id as i32),
        libc::P_PGID => reaper::Select::Pgid(id as i32),
        _ => reaper::Select::Any,
    };
    let own = || waitid_host(idtype, id, host_options | libc::WNOHANG, infop, options);
    let want = Want {
        exited: options & w::WEXITED != 0,
        stopped: options & w::WSTOPPED != 0,
        continued: options & w::WCONTINUED != 0,
    };
    let r = reaper_wait(
        sel,
        options & w::WNOHANG != 0,
        want,
        own,
        |e| {
            let (code, status) = reaper::child_code(e.status);
            let mut words = [0i32; 32];
            words[0] = fwe_abi::signal::SIGCHLD as i32;
            words[2] = code;
            words[4] = reaper::guest_pid(e);
            // The child's real user, as its record keeps it.
            // SAFETY: getuid cannot fail.
            let host_user = host::uid_to_linux(unsafe { libc::getuid() });
            words[5] = fwe_kernel::procreg::kept_uid(e.pid)
                .map_or(host_user, |u| fwe_kernel::userns::to_ns(u, false))
                as i32;
            words[6] = status;
            if infop != 0 && fwe_kernel::uaccess::write(infop, words).is_err() {
                return err(errno::EFAULT);
            }
            1
        },
        options & w::WNOWAIT != 0,
    );
    if nonblock && r == 0 {
        return err(errno::EAGAIN);
    }
    if r < 0 { r } else { zero_rusage() }
}

/// `waitid` of the host's children (`idtype` and `id` are the host's), the
/// report written to `infop` in Linux's layout (all zero when `WNOHANG`
/// found none). Returns the child's host pid, 0 for none, or an error.
fn waitid_host(
    idtype: libc::idtype_t,
    id: libc::id_t,
    host_options: i32,
    infop: u64,
    options: u64,
) -> i64 {
    use fwe_abi::wait as w;
    if host_options & libc::WNOHANG != 0
        && idtype == libc::P_PID
        && reaper::init_unreapable(id as i32)
    {
        if infop != 0 && fwe_kernel::uaccess::write(infop, [0i32; 32]).is_err() {
            return err(errno::EFAULT);
        }
        return 0;
    }
    // SAFETY: an all-zero siginfo is a valid out-parameter.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `si` is a valid out-parameter.
    let mut r = unsafe { libc::waitid(idtype, id, &mut si, host_options) };
    if r != 0 && host::last_errno().is(libc::EINTR) && host_options & libc::WNOHANG == 0 {
        // As for `wait4`: a child ready is reported over its own signal.
        // SAFETY: as above.
        r = unsafe { libc::waitid(idtype, id, &mut si, host_options | libc::WNOHANG) };
        // SAFETY: `si` was filled by the host.
        if r != 0 || unsafe { si.si_pid() } == 0 {
            host::set_errno(host::HostErrno::new(libc::EINTR));
            r = -1;
        }
    }
    if r != 0 {
        return fwe_kernel::host::last_error();
    }
    let mut words = [0i32; 32]; // a 128-byte siginfo_t
    // SAFETY: `si` was filled by the host.
    let (pid, host_uid, status) = unsafe { (si.si_pid(), si.si_uid(), si.si_status()) };
    // The child's real user, as its record keeps it (the host names the
    // host user).
    let uid = fwe_kernel::ids::HostPid::new(pid)
        .and_then(fwe_kernel::procreg::kept_uid)
        .map_or_else(|| host::uid_to_linux(host_uid), |u| fwe_kernel::userns::to_ns(u, false));
    if pid != 0 {
        // It ended of a Linux signal, as it recorded (see `linux_wstatus`).
        let ended = matches!(si.si_code, w::CLD_EXITED | w::CLD_KILLED | w::CLD_DUMPED)
            .then(|| fwe_kernel::ids::HostPid::new(pid).and_then(fwe_kernel::procreg::end_status))
            .flatten();
        let code = match ended {
            Some(s) if s & 0x80 != 0 => w::CLD_DUMPED,
            Some(_) => w::CLD_KILLED,
            None => si.si_code,
        };
        let status = match code {
            _ if ended.is_some() => ended.unwrap_or(0) & 0x7f,
            w::CLD_KILLED | w::CLD_DUMPED | w::CLD_STOPPED => host::signal_to_linux(status) as i32,
            // What continued it, as Linux reports (the host gives the
            // signal that had stopped it).
            w::CLD_CONTINUED => fwe_abi::signal::SIGCONT as i32,
            _ => status,
        };
        words[0] = fwe_abi::signal::SIGCHLD as i32; // si_signo
        words[2] = code; // si_code
        words[4] = fwe_kernel::pidns::guest_ret(pid as i64) as i32; // si_pid
        words[5] = uid as i32; // si_uid
        words[6] = status; // si_status
        if options & w::WNOWAIT == 0
            && matches!(code, w::CLD_EXITED | w::CLD_KILLED | w::CLD_DUMPED)
        {
            let wstatus = if code == w::CLD_EXITED {
                (status & 0xff) << 8
            } else {
                status | if code == w::CLD_DUMPED { 0x80 } else { 0 }
            };
            reaped_signal(pid, wstatus);
            // Reaped: its numbers are free again, and its records go.
            reaper::busy(|| {
                fwe_kernel::pidns::reaped(pid);
                if let Some(p) = fwe_kernel::ids::HostPid::new(pid) {
                    fwe_kernel::procreg::reaped(p);
                }
                reaper::reaped_own_child(pid);
            });
            reaper::reaped_child(pid);
        }
    }
    if infop != 0 && fwe_kernel::uaccess::write(infop, words).is_err() {
        return err(errno::EFAULT);
    }
    i64::from(pid)
}
