//! Thread creation (`clone`) for the native backend.
//!
//! A guest thread is a host thread that runs guest code directly. The child
//! shares the whole address space and the single global kernel; the kernel's
//! per-thread state (tid, `set_tid_address` word, signal mask and pending
//! signals) lives in host thread-locals.

use crate::{LIVE_THREADS, thread_pointer_slot, trap};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::{Regs, thread};
use std::sync::atomic::Ordering;

/// What a freshly spawned host thread needs to become a guest thread.
struct Spawn {
    regs: Regs,
    tid: i32,
    /// Guest thread pointer (`CLONE_SETTLS`), or `None` to inherit.
    tls: Option<u64>,
    /// `set_tid_address` word (`CLONE_CHILD_CLEARTID`), or 0.
    clear_child_tid: u64,
    /// The creating thread's blocked mask, which the new thread inherits.
    sigmask: u64,
    /// The thread's pending signals, registered before it starts.
    pending: std::sync::Arc<thread::Pending>,
}

/// Flags fwe supports for `clone`: the thread-creation set used by pthreads.
const SUPPORTED: u64 = cl::CLONE_VM
    | cl::CLONE_FS
    | cl::CLONE_FILES
    | cl::CLONE_SIGHAND
    | cl::CLONE_THREAD
    | cl::CLONE_SYSVSEM
    | cl::CLONE_SETTLS
    | cl::CLONE_PARENT_SETTID
    | cl::CLONE_CHILD_CLEARTID
    | cl::CLONE_CHILD_SETTID
    | cl::CLONE_DETACHED;

/// Handle a guest `clone` or `clone3` asking for `a`, from the thread whose
/// registers are `parent`. Returns the child tid to the parent, or a
/// negative errno.
pub fn do_clone(parent: &Regs, a: fwe_kernel::CloneArgs) -> i64 {
    let fwe_kernel::CloneArgs { flags, stack: child_stack, parent_tid, tls, child_tid, .. } = a;

    // A clone without CLONE_THREAD is a new process (fork); with CLONE_VM it
    // shares the guest's memory with it, and with CLONE_VFORK the parent
    // waits for the child to exec or exit.
    if flags & cl::CLONE_THREAD == 0 {
        let (share, wait) = (flags & cl::CLONE_VM != 0, flags & cl::CLONE_VFORK != 0);
        return crate::process::do_fork(parent, a, share, wait);
    }
    // A thread shares the memory: `CloneArgs::check` refused `CLONE_THREAD`
    // without `CLONE_SIGHAND` and `CLONE_VM` (`EINVAL`), as Linux does.
    if flags & !SUPPORTED & !cl::CSIGNAL != 0 {
        return err(errno::ENOSYS);
    }
    if child_stack == 0 {
        return err(errno::EINVAL);
    }

    let tid = thread::alloc_tid();
    // Traced from its start if the tracer follows new threads.
    fwe_kernel::ptrace::new_thread(tid);
    if flags & cl::CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        let _ = fwe_kernel::uaccess::write(parent_tid, tid);
    }
    if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        let _ = fwe_kernel::uaccess::write(child_tid, tid);
    }

    // The child resumes just after the clone, with x0 = 0 and its own stack.
    let mut regs = *parent;
    regs.x[0] = 0;
    regs.sp = child_stack;
    regs.pc = parent.pc.wrapping_add(4);

    let spawn = Box::new(Spawn {
        regs,
        tid,
        tls: (flags & cl::CLONE_SETTLS != 0).then_some(tls),
        clear_child_tid: if flags & cl::CLONE_CHILD_CLEARTID != 0 { child_tid } else { 0 },
        sigmask: thread::mask(),
        pending: thread::register(tid),
    });
    let pending = spawn.pending.clone();

    LIVE_THREADS.fetch_add(1, Ordering::SeqCst);
    match spawn_host_thread(spawn) {
        Some(handle) => {
            thread::set_host_thread(&pending, handle);
            tid as i64
        }
        None => {
            LIVE_THREADS.fetch_sub(1, Ordering::SeqCst);
            thread::unregister(&pending);
            err(errno::EAGAIN)
        }
    }
}

/// Create a detached host thread that becomes the guest thread. It starts
/// with every signal blocked, whatever the caller's mask (a system call
/// runs with the guest's unblocked; see `host::with_signals_blocked`), and
/// `child_main` takes the guest's mask once it is set up.
fn spawn_host_thread(spawn: Box<Spawn>) -> Option<libc::pthread_t> {
    let arg = Box::into_raw(spawn).cast::<libc::c_void>();
    // SAFETY: a detached pthread with the default stack; `child_main` takes
    // ownership of the boxed `Spawn` passed as its argument.
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        libc::pthread_attr_init(&mut attr);
        libc::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED);
        let mut handle: libc::pthread_t = 0;
        let r = fwe_kernel::host::with_signals_blocked(|| {
            libc::pthread_create(&mut handle, &attr, child_main, arg)
        });
        libc::pthread_attr_destroy(&mut attr);
        if r != 0 {
            // Reclaim the box the thread never received.
            drop(Box::from_raw(arg.cast::<Spawn>()));
            return None;
        }
        Some(handle)
    }
}

extern "C" fn child_main(arg: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: `arg` is the `Spawn` box handed to `pthread_create`.
    let spawn = unsafe { Box::from_raw(arg.cast::<Spawn>()) };

    // Stacks an ended thread gave back, or fresh ones.
    match crate::stacks::take() {
        Some((gate, alt)) => {
            crate::gate::adopt_block(gate);
            trap::use_altstack(alt);
        }
        None => trap::install_thread_altstack(),
    }
    crate::interactive();
    thread::set_tid(spawn.tid);
    thread::adopt(&spawn.pending);
    thread::set_mask(spawn.sigmask);
    thread::set_clear_child_tid(spawn.clear_child_tid);
    if let Some(tls) = spawn.tls {
        set_thread_pointer(tls);
    }
    // The guest's x18 lives in a per-thread slot; the child inherits the
    // parent's value as it would any other register.
    trap::set_guest_x18(spawn.regs.x[18]);

    let regs = spawn.regs;
    drop(spawn);
    // The thread started with every signal blocked (`spawn_host_thread`):
    // switch to the guest mask (and the x18 ABI) for guest code.
    trap::prepare_guest_entry();
    // SAFETY: `regs` describes a runnable guest context on the child stack.
    unsafe { trap::enter_guest_full(&regs) }
}

/// Set this thread's guest thread pointer into its TSD slot, where the
/// rewritten `TPIDR_EL0` accesses read and write it.
fn set_thread_pointer(tls: u64) {
    let key = (thread_pointer_slot() / 8) as libc::pthread_key_t;
    // SAFETY: `key` is the process-wide key fwe allocated for the slot.
    unsafe { libc::pthread_setspecific(key, tls as *const libc::c_void) };
}
