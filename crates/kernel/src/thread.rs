//! Per-thread guest state and thread-id allocation.
//!
//! A guest thread is a host thread. State that Linux keeps per thread — the
//! thread id, `set_tid_address`'s clear-on-exit word, the robust-futex list —
//! lives in host thread-locals, not in the shared [`crate::Kernel`].

use std::cell::Cell;
use std::sync::atomic::{AtomicI32, Ordering};

/// The process (thread-group) id, shared by all threads. Set once at startup.
static TGID: AtomicI32 = AtomicI32::new(0);
/// Next thread id to hand out. Thread ids are unique within the process.
static NEXT_TID: AtomicI32 = AtomicI32::new(0);

thread_local! {
    static TID: Cell<i32> = const { Cell::new(0) };
    /// `set_tid_address`: futex word cleared and woken when the thread exits.
    static CLEAR_CHILD_TID: Cell<u64> = const { Cell::new(0) };
    static ROBUST_LIST: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

/// Initialize the thread-group id and the main thread's id (both the host
/// pid, as Linux gives the main thread a tid equal to the pid).
pub fn init_main(pid: i32) {
    TGID.store(pid, Ordering::SeqCst);
    NEXT_TID.store(pid + 1, Ordering::SeqCst);
    TID.with(|t| t.set(pid));
}

/// The thread-group id (what `getpid` returns).
pub fn tgid() -> i32 {
    TGID.load(Ordering::SeqCst)
}

/// Allocate a fresh thread id for a new thread.
pub fn alloc_tid() -> i32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Record this host thread's guest thread id (called when a thread starts).
pub fn set_tid(tid: i32) {
    TID.with(|t| t.set(tid));
}

/// This thread's guest thread id (`gettid`).
pub fn tid() -> i32 {
    TID.with(Cell::get)
}

pub fn set_clear_child_tid(addr: u64) {
    CLEAR_CHILD_TID.with(|c| c.set(addr));
}

pub fn clear_child_tid() -> u64 {
    CLEAR_CHILD_TID.with(Cell::get)
}

pub fn set_robust_list(head: u64, len: u64) {
    ROBUST_LIST.with(|c| c.set((head, len)));
}

pub fn robust_list() -> (u64, u64) {
    ROBUST_LIST.with(Cell::get)
}
