//! Waiting across processes on a word of the store's shared memory, until
//! another process changes it and wakes its waiters ([`wake_all`]): what a
//! file lock's waiter sleeps on.

use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::time::Duration;

#[cfg(target_os = "macos")]
mod host {
    pub const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
    pub const ULF_WAKE_ALL: u32 = 0x100;
    pub const ULF_NO_ERRNO: u32 = 0x0100_0000;

    unsafe extern "C" {
        pub fn __ulock_wait2(
            op: u32,
            addr: *mut libc::c_void,
            value: u64,
            timeout_ns: u64,
            value2: u64,
        ) -> libc::c_int;
        pub fn __ulock_wake(op: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
    }
}

/// Wake every process waiting on `w`, a word of shared memory.
pub fn wake_all(w: &AtomicU32) {
    let addr = w.as_ptr().cast::<libc::c_void>();
    #[cfg(target_os = "macos")]
    // SAFETY: a word of shared memory the caller keeps mapped.
    unsafe {
        host::__ulock_wake(
            host::UL_COMPARE_AND_WAIT_SHARED | host::ULF_WAKE_ALL | host::ULF_NO_ERRNO,
            addr,
            0,
        );
    }
    #[cfg(not(target_os = "macos"))]
    // SAFETY: a word of shared memory the caller keeps mapped.
    unsafe {
        libc::syscall(libc::SYS_futex, addr, libc::FUTEX_WAKE, i32::MAX);
    }
}

/// Sleep while `w` reads `seen`, for `slice` at most (a wake, a change, a
/// signal to the thread or the slice's end ends it).
pub fn wait(w: &AtomicU32, seen: u32, slice: Duration) {
    if w.load(SeqCst) != seen {
        return;
    }
    let addr = w.as_ptr().cast::<libc::c_void>();
    #[cfg(target_os = "macos")]
    // SAFETY: a word of shared memory the caller keeps mapped; the host
    // sleeps while it reads `seen`.
    unsafe {
        host::__ulock_wait2(
            host::UL_COMPARE_AND_WAIT_SHARED | host::ULF_NO_ERRNO,
            addr,
            seen as u64,
            slice.as_nanos().max(1) as u64,
            0,
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let ts = libc::timespec {
            tv_sec: slice.as_secs() as libc::time_t,
            tv_nsec: slice.subsec_nanos() as libc::c_long,
        };
        // SAFETY: as above.
        unsafe {
            libc::syscall(libc::SYS_futex, addr, libc::FUTEX_WAIT, seen, &ts);
        }
    }
}
