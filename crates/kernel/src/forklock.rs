//! The locks a host `fork` must not copy held.
//!
//! A child of a host `fork` has only the forking thread, and a copy of the
//! parent's memory: a lock another thread held at that instant stays held
//! in the child, which then waits on it for good. [`crate::fork_locked`]
//! holds the kernel lock and the registry locks across the fork for that;
//! the locks listed here are those threads also take outside the kernel
//! lock (a wait without it, as `epoll_pwait` and `read` are made, or an id
//! translated on another thread) that no module's own `hold` covers.
//!
//! They are taken all at once or not at all ([`hold`]): each is tried, and
//! with one busy, those taken are let go and all tried again. So the order
//! code elsewhere takes two of them in never matters.
//!
//! A `Mutex` the child lets go of only tells the host kernel, which knows
//! none of the parent's waiters. A `RwLock` on macOS queues its waiters
//! in their own threads' memory, which the child has a copy of but no
//! thread for, and letting it go walks that queue: so one shared with a
//! fork is a [`ForkRwLock`], which the child replaces with a new lock.

use std::any::Any;
use std::cell::UnsafeCell;
use std::sync::{Mutex, RwLock, RwLockWriteGuard};

/// A lock [`hold`] can take without waiting.
pub(crate) trait ForkLock: Sync {
    /// The lock, held until the box is dropped, or `None` while another
    /// thread holds it.
    fn try_take(&'static self) -> Option<Box<dyn Any>>;

    /// Let go of the lock in the child of a fork, given what
    /// [`try_take`](ForkLock::try_take) returned.
    fn release_in_child(&'static self, taken: Box<dyn Any>) {
        drop(taken);
    }
}

impl<T: Send + 'static> ForkLock for Mutex<T> {
    fn try_take(&'static self) -> Option<Box<dyn Any>> {
        match self.try_lock() {
            Ok(g) => Some(Box::new(g)),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(Box::new(p.into_inner())),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }
}

/// A `RwLock` a fork's child can let go of: it gets a new lock with the
/// same data, the copy of the parent's left as it was.
pub(crate) struct ForkRwLock<T>(UnsafeCell<RwLock<T>>);

// SAFETY: the inner lock is only ever replaced by the child of a fork,
// whose only thread holds it for writing (`hold`); otherwise it is shared
// as a `RwLock`, which is `Sync` for these `T`.
unsafe impl<T: Send + Sync> Sync for ForkRwLock<T> {}

impl<T> ForkRwLock<T> {
    pub(crate) const fn new(value: T) -> Self {
        ForkRwLock(UnsafeCell::new(RwLock::new(value)))
    }
}

impl<T> std::ops::Deref for ForkRwLock<T> {
    type Target = RwLock<T>;

    fn deref(&self) -> &RwLock<T> {
        // SAFETY: replaced only as `release_in_child` says, with no other
        // reference to it alive.
        unsafe { &*self.0.get() }
    }
}

impl<T: Send + Sync + 'static> ForkLock for ForkRwLock<T> {
    fn try_take(&'static self) -> Option<Box<dyn Any>> {
        // For writing: no reader is mid-read in the child either.
        match self.try_write() {
            Ok(g) => Some(Box::new(g)),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(Box::new(p.into_inner())),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn release_in_child(&'static self, taken: Box<dyn Any>) {
        let Ok(guard) = taken.downcast::<RwLockWriteGuard<'static, T>>() else {
            return;
        };
        // SAFETY: the guard is the write lock of this lock, held by the
        // child's only thread, so nothing else refers to the lock or its
        // data. The data is moved out and the guard forgotten (its unlock
        // would walk the parent's waiters), then the lock is overwritten
        // with a new one holding the data, the old one never dropped.
        unsafe {
            let value = std::ptr::read(&**guard);
            std::mem::forget(guard);
            std::ptr::write(self.0.get(), RwLock::new(value));
        }
    }
}

/// The locks, as [`hold`] takes them.
fn locks() -> Vec<&'static dyn ForkLock> {
    use crate::*;
    let mut v: Vec<&'static dyn ForkLock> = Vec::with_capacity(58);
    // The host's kqueue behind `epoll` (macOS).
    #[cfg(not(target_os = "linux"))]
    v.extend([
        &epoll::INTEREST as &'static dyn ForkLock,
        &epoll::BPF_WATCHED,
        &epoll::EDGES,
        &epoll::HELD,
        &epoll::WRITES,
    ]);
    v.extend([
        &fdstate::STATES as &'static dyn ForkLock,
        &fdstate::PIPES,
        &fdstate::WRITE_ENDS,
        &fdstate::BUFFERS,
        &fdmarks::RECORDS,
        &pidfd::EXITS,
        &uaccess::TABLE,
        &userns::CURRENT,
        &netns::CURRENT,
        &pidns::CURRENT,
        &pidns::RECENT,
        &pidns::THREAD_NUMS,
        &sysvipc::ATTACHED,
        &sysvipc::CURRENT,
        &inotify::INSTANCES,
        &rlimits::LIMITS,
        &seccomp::STATE,
        &creds::ACCESS,
        &net::CORKED,
        &net::KEPT_VALUES,
        &net::MEMBERSHIPS,
        &net::NAMES,
        &net::SOCKET_MODES,
        &netlink::SOCKS,
        &nsfd::FDS,
        &memfd::READ_ONLY,
        &atime::NOATIME_FDS,
        &modes::SETID_FDS,
        &tmpfile::NAMES,
        &tmpfs::HELD,
        &aio::CTXS,
        &bpf::FILTERS,
        &bpf::PROG_MAPS,
        &landlock::DOMAIN,
        &landlock::NO_TRUNCATE,
        &landlock::RULESETS,
        &mountapi::CONTEXTS,
        &mountapi::TREES,
        &mountwatch::WATCHES,
        &posixtimer::NOTIFY,
        &ptrace::PENDING,
        &ptrace::THREADS,
        &syscalls::AFFINITY,
        &fdtable::LIMIT,
        &keys::INHERIT,
        &fs::PREOPENED,
        &maps::OUTBOX,
        &mm::DONT_DUMP,
        &mm::GROWS_DOWN,
        &mm::POISONED,
        &mm::WIPE_ON_FORK,
        &thread::PUBLISHED,
        &thread::TID_BLOCK_LEFT,
    ]);
    v
}

/// Run `fork` holding every lock of [`locks`], taken all at once.
pub(crate) fn hold<R>(fork: impl FnOnce() -> R) -> R {
    let all = locks();
    loop {
        let mut held: Vec<Box<dyn Any>> = Vec::with_capacity(all.len());
        for &l in &all {
            match l.try_take() {
                Some(g) => held.push(g),
                None => break,
            }
        }
        if held.len() == all.len() {
            let parent = crate::host::pid();
            let r = fork();
            // SAFETY: as above.
            if crate::host::pid() != parent {
                for (&l, g) in all.iter().zip(held) {
                    l.release_in_child(g);
                }
            } else {
                drop(held);
            }
            return r;
        }
        drop(held);
        std::thread::yield_now();
    }
}
