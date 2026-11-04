//! Stopping the guest's other threads for the instant a host `fork` copies
//! memory, so the child sees one instant of the process as on Linux.
//!
//! A host `fork` on macOS copies the address space while the parent's other
//! threads keep running, so a thread writing two words in turn can leave
//! the child with the second write and not the first. Linux never shows
//! that: a thread touching memory the fork has already copied waits until
//! the fork is done.
//!
//! Every guest thread has a [`Slot`]: its Mach thread port and whether it is
//! running guest code. [`fork_stopped`] suspends each other thread with
//! `thread_suspend`, waits until it is off the CPU, and keeps it suspended
//! across the fork only if it was in guest code, which holds none of fwe's
//! or the host libraries' locks (a thread suspended inside `malloc`, say,
//! would deadlock the fork). A thread in fwe's own code is resumed at once;
//! it cannot get back into guest code during the fork, because the way back
//! ([`enter`]) waits while a fork is under way. The flag and the fork's
//! marker are each written before the other is read, so either the fork sees
//! the thread in guest code (and keeps it stopped) or the thread sees the
//! fork (and waits).

use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};

/// One guest thread, or a free entry (`port` 0) for the next to start.
struct Slot {
    port: AtomicU32,
    in_guest: AtomicBool,
}

/// Every slot handed out. Slots are never freed, only reused.
static SLOTS: Mutex<Vec<&'static Slot>> = Mutex::new(Vec::new());

/// A fork is copying memory: threads wait before entering guest code.
static FORKING: AtomicBool = AtomicBool::new(false);

thread_local! {
    static MINE: Cell<Option<&'static Slot>> = const { Cell::new(None) };
}

/// `ARM_THREAD_STATE64` and its size in words.
const ARM_THREAD_STATE64: i32 = 6;
const ARM_THREAD_STATE64_COUNT: u32 = 68;

unsafe extern "C" {
    fn thread_suspend(thread: u32) -> i32;
    fn thread_resume(thread: u32) -> i32;
    fn thread_get_state(thread: u32, flavor: i32, state: *mut u32, count: *mut u32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn mach_thread_self() -> u32;
    /// This task's port (`mach_task_self()` is a macro over it).
    static mach_task_self_: u32;
}

fn slots() -> std::sync::MutexGuard<'static, Vec<&'static Slot>> {
    SLOTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// This thread's slot, registered on first use.
fn mine() -> &'static Slot {
    if let Some(slot) = MINE.get() {
        return slot;
    }
    // SAFETY: plain Mach call; the send right it returns is kept in the
    // slot until the thread ends.
    let port = unsafe { mach_thread_self() };
    let slot = {
        let mut slots = slots();
        let free = slots.iter().copied().find(|s| s.port.load(SeqCst) == 0);
        let slot = free.unwrap_or_else(|| {
            let s: &'static Slot = Box::leak(Box::new(Slot {
                port: AtomicU32::new(0),
                in_guest: AtomicBool::new(false),
            }));
            slots.push(s);
            s
        });
        slot.in_guest.store(false, SeqCst);
        slot.port.store(port, SeqCst);
        slot
    };
    MINE.set(Some(slot));
    slot
}

/// Register this thread if it is not yet, before it first runs guest code.
pub fn register() {
    mine();
}

/// This thread is about to run guest code. Waits while a fork is copying
/// memory.
pub fn enter() {
    let Some(slot) = MINE.get() else { return };
    loop {
        slot.in_guest.store(true, SeqCst);
        if !FORKING.load(SeqCst) {
            return;
        }
        slot.in_guest.store(false, SeqCst);
        while FORKING.load(SeqCst) {
            std::thread::yield_now();
        }
    }
}

/// This thread has left guest code for fwe's.
pub fn leave() {
    if let Some(slot) = MINE.get() {
        slot.in_guest.store(false, SeqCst);
    }
}

/// This thread is ending: free its slot.
pub fn forget_current() {
    let Some(slot) = MINE.take() else { return };
    let _slots = slots();
    slot.in_guest.store(false, SeqCst);
    let port = slot.port.swap(0, SeqCst);
    // SAFETY: dropping the send right `mine` took for this thread.
    unsafe { mach_port_deallocate(mach_task_self_, port) };
}

/// Wait until suspended thread `port` is off the CPU: Mach reads a thread's
/// state only once it has stopped.
fn wait_stopped(port: u32) {
    let mut state = [0u32; ARM_THREAD_STATE64_COUNT as usize];
    let mut count = ARM_THREAD_STATE64_COUNT;
    // SAFETY: `state` has room for `count` words.
    unsafe { thread_get_state(port, ARM_THREAD_STATE64, state.as_mut_ptr(), &mut count) };
}

/// Run `fork` (a host `fork`) with every other thread that is running guest
/// code stopped. In the child, which has only this thread, the other slots
/// are freed.
pub fn fork_stopped(fork: impl FnOnce() -> libc::pid_t) -> libc::pid_t {
    let me = mine();
    let slots = slots();
    FORKING.store(true, SeqCst);
    let mut stopped = Vec::new();
    for slot in slots.iter().filter(|s| !std::ptr::eq(**s, me)) {
        let port = slot.port.load(SeqCst);
        // SAFETY: a thread of this task, registered in its slot (the slot
        // lock keeps it from being freed meanwhile).
        if port == 0 || unsafe { thread_suspend(port) } != 0 {
            continue;
        }
        wait_stopped(port);
        if slot.in_guest.load(SeqCst) {
            stopped.push(port);
        } else {
            // SAFETY: resuming the thread suspended above.
            unsafe { thread_resume(port) };
        }
    }
    let pid = fork();
    FORKING.store(false, SeqCst);
    if pid == 0 {
        for slot in slots.iter() {
            slot.in_guest.store(false, SeqCst);
            slot.port.store(0, SeqCst);
        }
        // SAFETY: plain Mach call; this thread's port in the new task.
        me.port.store(unsafe { mach_thread_self() }, SeqCst);
    } else {
        for port in stopped {
            // SAFETY: resuming a thread suspended above.
            unsafe { thread_resume(port) };
        }
    }
    pid
}
