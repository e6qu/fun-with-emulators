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

use std::any::Any;
use std::sync::{Mutex, RwLock};

/// A lock [`hold`] can take without waiting.
pub(crate) trait ForkLock: Sync {
    /// The lock, held until the box is dropped, or `None` while another
    /// thread holds it.
    fn try_take(&'static self) -> Option<Box<dyn Any>>;
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

impl<T: Send + Sync + 'static> ForkLock for RwLock<T> {
    fn try_take(&'static self) -> Option<Box<dyn Any>> {
        // For writing: no reader is mid-read in the child either.
        match self.try_write() {
            Ok(g) => Some(Box::new(g)),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(Box::new(p.into_inner())),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }
}

/// The locks, as [`hold`] takes them.
fn locks() -> Vec<&'static dyn ForkLock> {
    use crate::*;
    let mut v: Vec<&'static dyn ForkLock> = Vec::with_capacity(56);
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
            let r = fork();
            drop(held);
            return r;
        }
        drop(held);
        std::thread::yield_now();
    }
}
