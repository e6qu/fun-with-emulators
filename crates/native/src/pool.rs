//! Host threads kept from guest threads that ended, for guest threads that
//! start. A host thread's start and end (its stack, its signal stack, its
//! Mach port, the host's own bookkeeping) cost more than the rest of a
//! guest thread's `clone` and exit together; a thread that ends through the
//! system-call gate waits here instead, with every host signal blocked and
//! none of fwe's locks held, and the next `clone` gives it the new thread.
//!
//! The pool is a few slots, each empty or naming a waiting thread's
//! [`Parked`] (on that thread's stack): taking one is a swap, so a fork
//! child, which has none of its parent's other threads, empties it with
//! stores and no lock.

use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering::SeqCst};

/// A waiting thread: its host thread, the word it waits on (0 while it
/// waits) and the new thread it is given.
pub struct Parked<T> {
    host: libc::pthread_t,
    word: AtomicU32,
    given: AtomicPtr<T>,
}

/// How many host threads wait at most; a thread that ends past that ends
/// its host thread too.
const SLOTS: usize = 16;

/// The waiting threads.
static POOL: [AtomicPtr<()>; SLOTS] = [const { AtomicPtr::new(std::ptr::null_mut()) }; SLOTS];

unsafe extern "C" {
    fn __ulock_wait(operation: u32, addr: *mut libc::c_void, value: u64, timeout: u32) -> i32;
    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> i32;
}

/// `UL_COMPARE_AND_WAIT` and `ULF_NO_ERRNO`.
const UL_COMPARE_AND_WAIT: u32 = 1;
const ULF_NO_ERRNO: u32 = 0x0100_0000;

/// A waiting host thread, if there is one: given `job` (a `Box` leaked to
/// it), it runs it. Its host thread is returned; `None` hands `job` back.
pub fn give<T>(job: Box<T>) -> Result<libc::pthread_t, Box<T>> {
    for slot in &POOL {
        let p = slot.swap(std::ptr::null_mut(), SeqCst).cast::<Parked<T>>();
        if p.is_null() {
            continue;
        }
        // SAFETY: a waiting thread's `Parked`, which stays on its stack
        // until its word is set (below), and only this caller took it.
        let parked = unsafe { &*p };
        let (host, word) = (parked.host, parked.word.as_ptr());
        parked.given.store(Box::into_raw(job), SeqCst);
        parked.word.store(1, SeqCst);
        // SAFETY: waking the thread waiting on the word, by its address
        // alone: the thread may have gone on, its `Parked` with it.
        unsafe { __ulock_wake(UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, word.cast(), 0) };
        return Ok(host);
    }
    Err(job)
}

/// Wait here for a new thread to run, if there is room: `Some` with it
/// once given, `None` at once if the pool is full (the caller ends its
/// host thread). The caller holds no lock and blocks every host signal.
pub fn wait<T>() -> Option<Box<T>> {
    let parked = Parked::<T> {
        // SAFETY: plain host call.
        host: unsafe { libc::pthread_self() },
        word: AtomicU32::new(0),
        given: AtomicPtr::new(std::ptr::null_mut()),
    };
    let me = std::ptr::from_ref(&parked).cast_mut().cast::<()>();
    POOL.iter().find(|s| s.compare_exchange(std::ptr::null_mut(), me, SeqCst, SeqCst).is_ok())?;
    while parked.word.load(SeqCst) == 0 {
        // SAFETY: waits while the word is 0; returns early on a spurious
        // wake, which the loop takes again.
        unsafe {
            __ulock_wait(UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, parked.word.as_ptr().cast(), 0, 0)
        };
    }
    // SAFETY: the `Box` the giver leaked to this thread.
    Some(unsafe { Box::from_raw(parked.given.load(SeqCst)) })
}

/// In a fork child: the parent's waiting threads are not here.
pub fn forked() {
    for slot in &POOL {
        slot.store(std::ptr::null_mut(), SeqCst);
    }
}
