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
    // A script runs its interpreter.
    let (path, args) = k.exec_target(path, args).map_err(err)?;
    let fs = k.fs.as_ref().expect("filesystem configured");
    let (file, file_id) = match k.take_exec_file(&path) {
        Some(file) => file,
        None => fs.read_identified(&path).map_err(err)?,
    };
    fwe_kernel::timing::mark("exec: read");
    let vm = crate::needs_vm(&file);
    // A program only the VM can run, where there is none: the exec fails
    // while the caller is intact (podman's pause process then waits in a
    // loop of its own, say), rather than once it has gone.
    if vm && !crate::hv::usable() {
        return Err(err(fwe_abi::errno::ENOEXEC));
    }
    // A program only the VM can run, or an exec from a process with other
    // threads (which must end): replace this process with a fresh fwe.
    if vm || LIVE_THREADS.load(Ordering::SeqCst) > 1 {
        fwe_kernel::release_robust_lists();
        let state = k.exec_state();
        return Err(crate::reexec(&path, &args, &env, fs, strace, &state, || {}));
    }
    // The old image is untouched on failure, so the guest can handle it.
    fwe_kernel::timing::mark("exec: checked for re-exec");
    crate::check_image(&file, fs).map_err(err)?;
    // A program with no path (a memfd) is held, for `/proc/self/exe`: the
    // descriptor it was run through may close on exec.
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
    // The point of no return: the old program's memory goes, and a vfork
    // parent may resume. The robust futexes its threads hold are released
    // first.
    fwe_kernel::release_robust_lists();
    fwe_kernel::timing::mark("exec: checked");
    fwe_kernel::mm::release_guest_memory();
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
        // What the process's record tells of it, written once.
        fwe_kernel::procreg::batch(|| {
            fs.set_proc_info(exe, crate::cmdline(&arg_refs), crate::ncpu(), crate::hostname());
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
pub fn do_fork(parent: &Regs, a: fwe_kernel::CloneArgs, share: bool, wait: bool) -> i64 {
    let fwe_kernel::CloneArgs { flags, stack: child_stack, parent_tid, child_tid, .. } = a;

    let mut done = [-1i32; 2];
    let (pid, shown) = {
        let mut kernel = KERNEL.lock();
        // A pipe whose write end only the child holds: it closes when the
        // child execs or exits, which ends the parent's wait. It is made,
        // and the parent's write end closed, under the kernel lock, where
        // every fork is: no other thread's child inherits the write end (the
        // parent would wait for that child too, which may never end: Go's
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
        // The child's namespaces, which it inherits from this view.
        let token = match k.fork_begin(&a) {
            Ok(t) => t,
            Err(e) => {
                for fd in done.into_iter().filter(|&fd| fd >= 0) {
                    // SAFETY: closing the pipe opened above.
                    unsafe { libc::close(fd) };
                }
                return fwe_abi::err(e);
            }
        };
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
        let pid = fwe_kernel::fork_locked(|| {
            set_shared(true);
            let pid = crate::quiesce::fork_stopped(|| {
                fork_with_signals_held(
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
                        reaper::set_exit_signal(child, sig)
                    },
                )
            });
            set_shared(false);
            pid
        });
        fwe_kernel::timing::mark(if pid == 0 { "fork: child" } else { "fork: parent" });
        let e = fwe_kernel::host::last_error();
        // The child's pid: in the child, its own namespace's; in the
        // parent, as the parent sees it.
        let shown = if pid == 0 {
            // The parent's pending signals are not the child's: forgotten
            // before any is taken (they stay blocked until the child enters
            // guest code), once the locks held across the fork are free.
            thread::forked();
            // The parent's threads' stacks are none of the child's to reuse.
            crate::stacks::forked();
            // The kqueues first, at their numbers, before anything the child
            // starts (a reaper's thread) makes descriptors of its own.
            fwe_kernel::restore_kqueues(&kqueues);
            k.fork_child(token)
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
        let _ = fwe_kernel::uaccess::write(parent_tid, shown);
    }
    if wait {
        // SAFETY: plain host calls on the pipe opened above.
        unsafe {
            let mut b = 0u8;
            while libc::read(done[0], (&mut b as *mut u8).cast(), 1) < 0
                && host::last_errno() == libc::EINTR
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
fn fork_with_signals_held(
    fork: impl FnOnce() -> libc::pid_t,
    in_parent: impl FnOnce(libc::pid_t),
) -> libc::pid_t {
    let mut go = [-1i32; 2];
    // SAFETY: a valid out-array; on failure the fork goes on without it.
    if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
        go = [-1, -1];
    }
    // SAFETY: plain host calls on initialized signal sets and the pipe
    // opened above, each end closed once in each process.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
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
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        let pid = fork();
        // What a failed fork left, kept for the caller across the calls below.
        let saved = host::last_errno();
        if pid > 0 {
            in_parent(pid);
        }
        if pid != 0 {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            if go[1] >= 0 {
                libc::write(go[1], b"g".as_ptr().cast(), 1);
            }
        } else if go[0] >= 0 {
            libc::close(go[1]);
            // Until the parent's byte, or its end (should it be gone).
            let mut b = 0u8;
            while libc::read(go[0], (&mut b as *mut u8).cast(), 1) < 0
                && host::last_errno() == libc::EINTR
            {}
        }
        for fd in go.into_iter().filter(|&fd| fd >= 0) {
            if pid == 0 && fd == go[1] {
                continue;
            }
            libc::close(fd);
        }
        host::set_errno(saved);
        pid
    }
}

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
    // SAFETY: getuid cannot fail; a child of fwe's is this user's.
    let uid = host::uid_to_initial(unsafe { libc::getuid() });
    let info = thread::SigInfo { code, pid, uid, status, value: 0, poll: None };
    reaper::reaped_child_signal(pid, info);
}

/// Encode a host `wait` status into the Linux layout a guest expects.
/// Host process `pid` ended so.
fn linux_wstatus(pid: i32, status: libc::c_int) -> i32 {
    if (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
        && let Some(s) = fwe_kernel::procreg::end_status(pid)
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
        return wait4_tracer(pid, host_options, wstatus, rusage);
    }
    start_watcher_if_wanted();
    if !reaper::active() {
        let r = wait4_host(pid, host_options, wstatus, rusage);
        // A child that began to be traced while this waited, and stopped.
        if r == err(errno::EINTR) && fwe_kernel::ptrace::tracing() {
            return wait4_tracer(pid, host_options, wstatus, rusage);
        }
        return r;
    }
    // A reaper: its own children, and those it adopted.
    let sel = match pid {
        -1 => reaper::Select::Any,
        // SAFETY: plain host call.
        0 => reaper::Select::Pgid(unsafe { libc::getpgrp() }),
        p if p > 0 => reaper::Select::Pid(p),
        p => reaper::Select::Pgid(-p),
    };
    let want = Want {
        exited: true,
        stopped: options & fwe_abi::wait::WUNTRACED != 0,
        continued: options & fwe_abi::wait::WCONTINUED != 0,
    };
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

/// A reaper's `wait` for the children `sel` picks: `own` checks its own
/// children (without blocking; `ECHILD` when it has none), then `adopted`
/// reports one it adopted that ended, stopped or continued, as `want`
/// says (taken, unless `peek`); until one is found, or there are none, or
/// a signal arrives (`EINTR`), unless `nohang`.
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
            // SIGCHLD as it records its end, which may be after the look.
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
fn wait4_tracer(pid: i32, host_options: i32, wstatus: u64, rusage: u64) -> i64 {
    // SAFETY: plain host calls.
    let pgid_of = |p: i32| unsafe { libc::getpgid(p) };
    // SAFETY: as above.
    let my_pgid = unsafe { libc::getpgrp() };
    let wanted = |p: i32| match pid {
        -1 => true,
        0 => pgid_of(p) == my_pgid,
        p if p > 0 => p == pid,
        p => pgid_of(p) == -p,
    };
    loop {
        let seen = fwe_kernel::ptrace::inbox_generation();
        if let Some((p, status, thread)) = fwe_kernel::ptrace::take_stop(wanted, false) {
            if wstatus != 0 && fwe_kernel::uaccess::write(wstatus, status).is_err() {
                return err(errno::EFAULT);
            }
            if rusage != 0 && fwe_kernel::uaccess::write(rusage, [0u64; 18]).is_err() {
                return err(errno::EFAULT);
            }
            // A thread is named by its tid, a process as the guest knows it.
            return if thread { p as i64 } else { fwe_kernel::pidns::guest_ret(p as i64) };
        }
        let r = wait4_host(pid, host_options | libc::WNOHANG, wstatus, rusage);
        // A traced process that is not a child is no host child to wait for.
        let traced_other =
            r == err(errno::ECHILD) && (pid > 0 && fwe_kernel::ptrace::traces(pid) || pid == -1);
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
fn waitid_tracer(
    idtype: libc::idtype_t,
    id: libc::id_t,
    host_options: i32,
    infop: u64,
    options: u64,
) -> i64 {
    const CLD_TRAPPED: i32 = 4;
    // SAFETY: plain host call.
    let pgid_of = |p: i32| unsafe { libc::getpgid(p) };
    let wanted = |p: i32| match idtype {
        libc::P_PID => p == id as i32,
        libc::P_PGID => pgid_of(p) == id as i32,
        _ => true,
    };
    let peek = options & fwe_abi::wait::WNOWAIT != 0;
    loop {
        let seen = fwe_kernel::ptrace::inbox_generation();
        if let Some((p, status, thread)) = fwe_kernel::ptrace::take_stop(wanted, peek) {
            if infop != 0 {
                let mut words = [0i32; 32];
                words[0] = fwe_abi::signal::SIGCHLD as i32;
                words[2] = CLD_TRAPPED;
                words[4] =
                    if thread { p } else { fwe_kernel::pidns::guest_ret(i64::from(p)) as i32 };
                words[5] = fwe_kernel::procreg::ids(p)[0] as i32;
                words[6] = (status >> 8) & 0xffff;
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
            && fwe_kernel::ptrace::traces(id as i32);
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
    // SAFETY: `status` and `usage` are valid out-parameters.
    let mut r = unsafe { libc::wait4(pid, &mut status, host_options, &mut usage) };
    if r < 0 && host::last_errno() == libc::EINTR && host_options & libc::WNOHANG == 0 {
        // The child's own SIGCHLD may interrupt the wait before the host
        // reports the child: Linux reports a child that is ready over the
        // signal, so it is looked for once more.
        // SAFETY: as above.
        let again =
            unsafe { libc::wait4(pid, &mut status, host_options | libc::WNOHANG, &mut usage) };
        if again > 0 {
            r = again;
        } else {
            host::set_errno(libc::EINTR);
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
            fwe_kernel::procreg::reaped(r);
            reaper::reaped_own_child(r);
        });
        reaper::reaped_child(r);
    }
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
    let (idtype, id) = match idtype {
        w::P_PIDFD => match fwe_kernel::pidfd::wait_target(id as i32) {
            Ok((host, nb)) => {
                nonblock = nb;
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
        let r = waitid_tracer(idtype, id, host_options, infop, options);
        return if r < 0 { r } else { zero_rusage() };
    }
    start_watcher_if_wanted();
    if !reaper::active() {
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
            // SAFETY: getuid cannot fail.
            words[5] = host::uid_to_linux(unsafe { libc::getuid() }) as i32;
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
    if r != 0 && host::last_errno() == libc::EINTR && host_options & libc::WNOHANG == 0 {
        // As for `wait4`: a child ready is reported over its own signal.
        // SAFETY: as above.
        r = unsafe { libc::waitid(idtype, id, &mut si, host_options | libc::WNOHANG) };
        // SAFETY: `si` was filled by the host.
        if r != 0 || unsafe { si.si_pid() } == 0 {
            host::set_errno(libc::EINTR);
            r = -1;
        }
    }
    if r != 0 {
        return fwe_kernel::host::last_error();
    }
    let mut words = [0i32; 32]; // a 128-byte siginfo_t
    // SAFETY: `si` was filled by the host.
    let (pid, uid, status) =
        unsafe { (si.si_pid(), host::uid_to_linux(si.si_uid()), si.si_status()) };
    if pid != 0 {
        // It ended of a Linux signal, as it recorded (see `linux_wstatus`).
        let ended = matches!(si.si_code, w::CLD_EXITED | w::CLD_KILLED | w::CLD_DUMPED)
            .then(|| fwe_kernel::procreg::end_status(pid))
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
                fwe_kernel::procreg::reaped(pid);
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
