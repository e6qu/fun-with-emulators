//! System call dispatch and the non-memory system calls.

use crate::host::{self, last_error, ret};
use crate::{Kernel, Platform, guest, thread, uaccess};
use fwe_abi::{
    Pollfd, Rlimit, Sigaction, Stack, Timespec, UTSNAME_LEN, Utsname, Winsize, clock, err, errno,
    fcntl, ioctl, nr, resource, signal,
};
use std::mem::size_of;

/// Kernel release reported by `uname`.
pub const RELEASE: &str = "6.12.0-fwe";

fn fill(field: &mut [u8; UTSNAME_LEN], s: &[u8]) {
    let n = s.len().min(UTSNAME_LEN - 1);
    field[..n].copy_from_slice(&s[..n]);
}

/// `clock_nanosleep`, as a free function so the backend can run it without
/// the kernel lock (it blocks).
///
/// # Safety
/// `req` and, when non-zero, `rem` must point to valid guest `Timespec`s.
/// `flock(fd, op)`. Waiting for the lock blocks, so the backends run it
/// without the kernel lock ([`crate::blocking_syscall`]).
pub(crate) fn flock(fd: u64, op: u64) -> i64 {
    // A message queue's descriptor holds the host lock that keeps the
    // queue alive ([`crate::mqueue`]): the guest's lock is not taken there.
    if crate::fdmarks::any_marks()
        && crate::fdmarks::marked(fd as i32) == Some(crate::fdmarks::Mark::Mq)
    {
        return match host::flock_op_to_host(op) {
            Some(_) => 0,
            None => err(errno::EINVAL),
        };
    }
    match host::flock_op_to_host(op) {
        // SAFETY: plain host call on a guest descriptor.
        Some(op) => ret(unsafe { libc::flock(fd as i32, op) }),
        None => err(errno::EINVAL),
    }
}

/// `fcntl(fd, F_SETLK or F_SETLKW, lock)`: a record lock in Linux layout.
/// `F_SETLKW` waits for a conflicting lock to go, so it runs without the
/// kernel lock ([`crate::blocking_syscall`]).
pub(crate) fn set_record_lock(fd: i32, cmd: u64, arg: u64) -> i64 {
    let lock: fwe_abi::Flock = guest!(uaccess::read(arg));
    let lock = match host::flock_to_host(&lock) {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let hcmd = if cmd == fcntl::F_SETLKW { libc::F_SETLKW } else { libc::F_SETLK };
    // SAFETY: `lock` is a valid host `struct flock`.
    ret(unsafe { libc::fcntl(fd, hcmd, &lock) })
}

pub(crate) unsafe fn clock_nanosleep(id: u64, flags: u64, req: u64, rem: u64) -> i64 {
    const TIMER_ABSTIME: u64 = 1;
    if matches!(id, clock::CLOCK_THREAD_CPUTIME_ID) {
        return err(errno::EINVAL);
    }
    let Some(hid) = host::clock_to_host(id) else {
        return err(errno::EINVAL);
    };
    let mut ts: Timespec = guest!(uaccess::read(req));
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return err(errno::EINVAL);
    }
    if flags & TIMER_ABSTIME != 0 {
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `now` is a valid out-parameter.
        unsafe { libc::clock_gettime(hid, &mut now) };
        let mut sec = ts.tv_sec - now.tv_sec;
        let mut nsec = ts.tv_nsec - now.tv_nsec;
        if nsec < 0 {
            nsec += 1_000_000_000;
            sec -= 1;
        }
        if sec < 0 {
            return 0;
        }
        ts = Timespec { tv_sec: sec, tv_nsec: nsec };
    }
    let host_ts = libc::timespec { tv_sec: ts.tv_sec, tv_nsec: ts.tv_nsec };
    let mut left = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid in- and out-parameters.
    if unsafe { libc::nanosleep(&host_ts, &mut left) } == 0 {
        return 0;
    }
    let e = last_error();
    if rem != 0 && flags & TIMER_ABSTIME == 0 {
        guest!(uaccess::write(rem, Timespec { tv_sec: left.tv_sec, tv_nsec: left.tv_nsec }));
    }
    e
}

/// The host process whose `/proc/<pid>/maps` descriptor `fd` is open on,
/// if it is one.
fn maps_of_fd(fd: i32) -> Option<i32> {
    let o = crate::fdmarks::origin(fd)?;
    if o.fstype != crate::mounts::FsType::Proc {
        return None;
    }
    let who = o.ns_path.strip_suffix(b"/maps")?.rsplit(|&b| b == b'/').next()?;
    if who == b"self" {
        // SAFETY: getpid cannot fail.
        return Some(unsafe { libc::getpid() });
    }
    let pid: i32 = std::str::from_utf8(who).ok()?.parse().ok()?;
    crate::pidns::to_host(pid)
}

impl<P: Platform> Kernel<P> {
    pub(crate) fn dispatch(&mut self, n: u64, a: [u64; 6]) -> i64 {
        if let Err(e) = crate::fdtable::check_args(n, &a) {
            return e;
        }
        if let Err(e) = crate::fdtable::check_limit(n, &a) {
            return e;
        }
        let plan = self.inotify_before(n, &a);
        let noted = crate::atime::before(n, &a);
        let r = crate::linux_result(n, &a, self.dispatch_call(n, a));
        crate::atime::after(noted, r);
        self.inotify_after(n, &a, r, plan);
        // Descriptors past the guest's soft limit are ones Linux would not
        // have given: closed again (by the guest's `close`, which also drops
        // what fwe keeps for one), and the call fails.
        let made = crate::fdtable::made(n, &a, r);
        if crate::fdtable::over_limit(&made) {
            for fd in made {
                self.dispatch_call(nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            }
            return fwe_abi::err(fwe_abi::errno::EMFILE);
        }
        r
    }

    fn dispatch_call(&mut self, n: u64, a: [u64; 6]) -> i64 {
        match n {
            // Files and I/O.
            // The backends run these without the lock
            // ([`crate::blocking_syscall`]); the same, reached here (the
            // plain `syscall` helper).
            nr::READ
            | nr::WRITE
            | nr::READV
            | nr::WRITEV
            | nr::PREAD64
            | nr::PWRITE64
            | nr::PREADV
            | nr::PWRITEV
            | nr::PREADV2
            | nr::PWRITEV2
            | nr::SPLICE
            | nr::TEE
            | nr::VMSPLICE => {
                // SAFETY: the backend's guarantee for the guest pointers.
                unsafe { crate::blocking_call(n, a) }.unwrap_or(err(errno::ENOSYS))
            }
            nr::LSEEK => {
                if let Some(r) = crate::synthdir::lseek(a[0] as i32, a[1] as i64, a[2] as i32) {
                    r
                } else if let Some(r) = crate::loopdev::lseek(a[0] as i32, a[1] as i64, a[2] as i32)
                {
                    r
                } else if crate::fdmarks::origin(a[0] as i32).is_some_and(|o| o.ovl.is_some())
                    && is_dir_fd(a[0] as i32)
                {
                    crate::overlay::lseek(a[0] as i32, a[1] as i64, a[2] as i32)
                } else {
                    // SAFETY: plain host call; SEEK_SET/CUR/END match.
                    ret(unsafe { libc::lseek(a[0] as i32, a[1] as libc::off_t, a[2] as i32) })
                }
            }
            nr::CLOSE => {
                let fd = a[0] as i32;
                crate::epoll::closed(fd);
                // A port bound in a network namespace is free once its
                // socket is.
                let mark = crate::fdmarks::marked(fd);
                if matches!(mark, Some(crate::fdmarks::Mark::NetBound { .. }))
                    && !crate::fdmarks::shared_elsewhere(fd)
                {
                    crate::netns::closed(fd, mark);
                }
                crate::netlink::closed(fd);
                crate::mountapi::closed(fd);
                crate::nsfd::closed(fd);
                crate::inotify::closed(fd);
                let queue = crate::mqueue::closing(fd, &self.creds);
                crate::fdmarks::closed(fd);
                if let Some(after) = queue {
                    // SAFETY: plain host call.
                    let r = ret(unsafe { libc::close(fd) });
                    after();
                    r
                } else if let Some(r) = crate::specialfd::try_close(fd) {
                    r
                } else if let Some(r) = crate::signalfd::try_close(fd) {
                    r
                } else if let Some(r) = crate::pty::try_close(fd) {
                    r
                } else if let Some(r) = crate::synthdir::try_close(fd) {
                    r
                } else {
                    // SAFETY: plain host call.
                    ret(unsafe { libc::close(fd) })
                }
            }
            nr::DUP => {
                // SAFETY: plain host call.
                let r = ret(unsafe { libc::dup(a[0] as i32) });
                if r >= 0 {
                    crate::fdmarks::duplicated(a[0] as i32, r as i32);
                }
                r
            }
            nr::DUP3 => self.sys_dup3(a[0], a[1], a[2]),
            nr::CLOSE_RANGE => self.sys_close_range(a[0] as u32, a[1] as u32, a[2]),
            nr::FCNTL => self.sys_fcntl(a[0], a[1], a[2]),
            nr::FLOCK => flock(a[0], a[1]),
            nr::IOCTL => self.sys_ioctl(a[0], a[1], a[2]),
            nr::PPOLL => self.sys_ppoll(a[0], a[1], a[2]),
            nr::SIGNALFD4 => self.sys_signalfd4(a[0], a[1], a[2], a[3]),
            // SAFETY: epoll_create1 takes no pointers.
            nr::EPOLL_CREATE1 => unsafe { crate::epoll::create1(a[0]) },
            // SAFETY: the host validates the epoll_event pointer.
            nr::EPOLL_CTL => unsafe { crate::epoll::ctl(a[0], a[1], a[2], a[3]) },
            nr::MEMFD_CREATE => match uaccess::read_cstr(a[0], fwe_abi::memfd::NAME_MAX) {
                Ok(name) => crate::memfd::create(&name, a[1]),
                Err(errno::ENAMETOOLONG) => err(errno::EINVAL),
                Err(e) => err(e),
            },
            // SAFETY: eventfd2 takes no pointers.
            nr::EVENTFD2 => unsafe { crate::specialfd::eventfd2(a[0], a[1]) },
            // SAFETY: timerfd_create takes no pointers.
            nr::TIMERFD_CREATE => unsafe { crate::specialfd::timerfd_create(a[0], a[1]) },
            // SAFETY: the itimerspec pointers are validated by the host/impl.
            nr::TIMERFD_SETTIME => unsafe {
                crate::specialfd::timerfd_settime(a[0], a[1], a[2], a[3])
            },
            // SAFETY: the itimerspec pointer is validated by the host/impl.
            nr::TIMERFD_GETTIME => unsafe { crate::specialfd::timerfd_gettime(a[0], a[1]) },

            // Sockets. The blocking calls (connect, accept, send*, recv*) are
            // handled lock-free in `blocking_syscall`; these set up or query.
            nr::SOCKET if a[0] == crate::netlink::AF_NETLINK => {
                crate::netlink::socket(a[1], a[2], self.creds.has(crate::caps::CAP_NET_ADMIN))
            }
            // SAFETY: socket takes no pointers.
            nr::SOCKET => unsafe { crate::net::socket(a[0], a[1], a[2]) },
            // SAFETY: the sv pointer is validated by the host/impl.
            nr::SOCKETPAIR => unsafe { crate::net::socketpair(a[0], a[1], a[2], a[3]) },
            nr::BIND if crate::netlink::is(a[0] as i32) => {
                crate::netlink::bind(a[0] as i32, a[1], a[2])
            }
            // SAFETY: the sockaddr pointer is validated by the host/impl.
            nr::BIND => unsafe {
                crate::net::bind(
                    a[0],
                    a[1],
                    a[2],
                    self.creds.has(crate::caps::CAP_NET_BIND_SERVICE),
                    self.fs().umask(),
                )
            },
            // SAFETY: no pointers.
            nr::LISTEN => unsafe { crate::net::listen(a[0], a[1]) },
            nr::GETSOCKNAME if crate::netlink::is(a[0] as i32) => {
                crate::netlink::getname(a[0] as i32, a[1], a[2], false)
            }
            nr::GETPEERNAME if crate::netlink::is(a[0] as i32) => {
                crate::netlink::getname(a[0] as i32, a[1], a[2], true)
            }
            // SAFETY: the out pointers are validated by the host/impl.
            nr::GETSOCKNAME => unsafe { crate::net::getname(a[0], a[1], a[2], false) },
            // SAFETY: the out pointers are validated by the host/impl.
            nr::GETPEERNAME => unsafe { crate::net::getname(a[0], a[1], a[2], true) },
            // A netlink socket's own options change nothing fwe does.
            nr::SETSOCKOPT
                if a[1] == crate::netlink::SOL_NETLINK && crate::netlink::is(a[0] as i32) =>
            {
                0
            }
            // SAFETY: the option buffer is validated by the host/impl.
            nr::SETSOCKOPT => unsafe { crate::net::setsockopt(a[0], a[1], a[2], a[3], a[4]) },
            // SAFETY: the out buffers are validated by the host/impl.
            nr::GETSOCKOPT => unsafe { crate::net::getsockopt(a[0], a[1], a[2], a[3], a[4]) },
            // SAFETY: no pointers.
            nr::SHUTDOWN => unsafe { crate::net::shutdown(a[0], a[1]) },

            // Files and directories.
            nr::OPENAT => self.sys_openat(a[0], a[1], a[2], a[3]),
            nr::FACCESSAT => self.sys_faccessat(a[0], a[1], a[2], 0),
            nr::FACCESSAT2 => self.sys_faccessat(a[0], a[1], a[2], a[3]),
            nr::NEWFSTATAT => self.sys_newfstatat(a[0], a[1], a[2], a[3]),
            nr::STATFS => self.sys_statfs(a[0], a[1]),
            nr::FSTATFS => self.sys_fstatfs(a[0], a[1]),
            nr::FSTAT => self.sys_fstat(a[0], a[1]),
            nr::STATX => self.sys_statx(a[0], a[1], a[2], a[3], a[4]),
            nr::GETDENTS64 => self.sys_getdents64(a[0], a[1], a[2]),
            nr::GETCWD => self.sys_getcwd(a[0], a[1]),
            nr::CHDIR => self.sys_chdir(a[0]),
            nr::FCHDIR => self.sys_fchdir(a[0]),
            nr::READLINKAT => self.sys_readlinkat(a[0], a[1], a[2], a[3]),
            nr::MKDIRAT => self.sys_mkdirat(a[0], a[1], a[2]),
            nr::MKNODAT => self.sys_mknodat(a[0], a[1], a[2], a[3]),
            nr::UNLINKAT => self.sys_unlinkat(a[0], a[1], a[2]),
            // arm64 keeps the flagless form, which glibc's `rename` uses.
            nr::RENAMEAT => self.sys_renameat2(a[0], a[1], a[2], a[3], 0),
            nr::RENAMEAT2 => self.sys_renameat2(a[0], a[1], a[2], a[3], a[4]),
            nr::SYMLINKAT => self.sys_symlinkat(a[0], a[1], a[2]),
            nr::LINKAT => self.sys_linkat(a[0], a[1], a[2], a[3], a[4]),
            nr::FCHMODAT => self.sys_fchmodat(a[0], a[1], a[2], 0),
            nr::SETXATTR => self.sys_setxattr(a[0], a[1], a[2], a[3], a[4], true),
            nr::LSETXATTR => self.sys_setxattr(a[0], a[1], a[2], a[3], a[4], false),
            nr::FSETXATTR => self.sys_fsetxattr(a[0], a[1], a[2], a[3], a[4]),
            nr::GETXATTR => self.sys_getxattr(None, a[0], a[1], a[2], a[3], true),
            nr::LGETXATTR => self.sys_getxattr(None, a[0], a[1], a[2], a[3], false),
            nr::FGETXATTR => self.sys_getxattr(Some(a[0] as i32), 0, a[1], a[2], a[3], true),
            nr::LISTXATTR => self.sys_listxattr(None, a[0], a[1], a[2], true),
            nr::LLISTXATTR => self.sys_listxattr(None, a[0], a[1], a[2], false),
            nr::FLISTXATTR => self.sys_listxattr(Some(a[0] as i32), 0, a[1], a[2], true),
            nr::REMOVEXATTR => self.sys_removexattr(None, a[0], a[1], true),
            nr::LREMOVEXATTR => self.sys_removexattr(None, a[0], a[1], false),
            nr::FREMOVEXATTR => self.sys_removexattr(Some(a[0] as i32), 0, a[1], true),
            nr::FCHMOD => self.sys_fchmod(a[0], a[1]),
            nr::FCHOWNAT => self.sys_fchownat(a[0], a[1], a[2], a[3], a[4]),
            nr::FCHOWN => self.sys_fchown(a[0], a[1], a[2]),
            nr::TRUNCATE => self.sys_truncate(a[0], a[1]),
            nr::FTRUNCATE => self.sys_ftruncate(a[0], a[1]),
            nr::FALLOCATE => self.sys_fallocate(a[0], a[1], a[2], a[3]),
            nr::FADVISE64 => self.sys_fadvise(a[0], a[1], a[2], a[3]),
            nr::UMASK => self.sys_umask(a[0]),
            nr::PIPE2 => self.sys_pipe2(a[0], a[1]),
            nr::UTIMENSAT => self.sys_utimensat(a[0], a[1], a[2], a[3]),
            nr::FSYNC | nr::FDATASYNC => match crate::loopdev::fsync(a[0] as i32) {
                Some(r) => r,
                // SAFETY: plain host call on a guest fd.
                None => ret(unsafe { libc::fsync(a[0] as i32) }),
            },

            // Memory.
            nr::BRK => self.sys_brk(a[0]),
            nr::UNSHARE => self.sys_unshare(a[0]),
            nr::SETHOSTNAME => self.sys_setname(a[0], a[1], true),
            nr::SETDOMAINNAME => self.sys_setname(a[0], a[1], false),
            nr::MOUNT => self.sys_mount(a[0], a[1], a[2], a[3], a[4]),
            nr::UMOUNT2 => self.sys_umount2(a[0], a[1]),
            nr::PIVOT_ROOT => self.sys_pivot_root(a[0], a[1]),
            nr::CHROOT => self.sys_chroot(a[0]),
            nr::MMAP => self.sys_mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
            nr::MUNMAP => self.sys_munmap(a[0], a[1]),
            nr::MPROTECT => self.sys_mprotect(a[0], a[1], a[2]),
            nr::MADVISE => self.sys_madvise(a[0], a[1], a[2]),
            nr::MSYNC => self.sys_msync(a[0], a[1], a[2]),
            nr::MINCORE => self.sys_mincore(a[0], a[1], a[2]),
            nr::MREMAP => self.sys_mremap(a[0], a[1], a[2], a[3], a[4]),

            // Process and thread identity.
            nr::EXIT_GROUP => self.platform.exit(a[0] as i32),
            nr::EXIT => {
                self.thread_cleanup();
                self.platform.exit_thread(a[0] as i32)
            }
            // Job control / sessions. These act on host process groups and
            // sessions, whose ids are host pids: the guest's are its pid
            // namespace's (the host's in the initial one).
            nr::SETPGID => {
                let (pid, pgid) = match (
                    crate::pidns::host_arg(a[0] as i32),
                    crate::pidns::host_arg(a[1] as i32),
                ) {
                    (Ok(p), Ok(g)) => (p, g),
                    // A group that does not exist here is not one to join.
                    (Ok(_), Err(_)) => return err(errno::EPERM),
                    (Err(e), _) => return err(e),
                };
                // SAFETY: plain host call.
                let r = ret(unsafe { libc::setpgid(pid, pgid) });
                if r == 0 {
                    // SAFETY: getpid cannot fail.
                    let me = unsafe { libc::getpid() };
                    crate::procreg::record_pgid(if pid == 0 { me } else { pid });
                }
                r
            }
            nr::GETPGID => match crate::pidns::host_arg(a[0] as i32) {
                // SAFETY: plain host call.
                Ok(p) => crate::pidns::guest_ret(ret(unsafe { libc::getpgid(p) } as i64)),
                Err(e) => err(e),
            },
            nr::GETSID => match crate::pidns::host_arg(a[0] as i32) {
                // SAFETY: plain host call.
                Ok(p) => crate::pidns::guest_ret(ret(unsafe { libc::getsid(p) } as i64)),
                Err(e) => err(e),
            },
            nr::SETSID => {
                // SAFETY: plain host call.
                let r = ret(unsafe { libc::setsid() } as i64);
                if r > 0 {
                    // SAFETY: getpid cannot fail.
                    crate::procreg::record_pgid(unsafe { libc::getpid() });
                }
                crate::pidns::guest_ret(r)
            }
            nr::GETPID => thread::tgid() as i64,
            nr::GETTID => thread::tid() as i64,
            // A parent outside the namespace is 0, as Linux reports it.
            nr::GETPPID => {
                // SAFETY: getpid cannot fail.
                let me = unsafe { libc::getpid() };
                let parent = crate::reaper::parent_of(me, host::getppid() as i32);
                crate::pidns::guest_ret(i64::from(parent))
            }
            // Virtual credentials (see crates/kernel/src/creds.rs).
            // Kept as the initial namespace's ids, seen through the user
            // namespace's maps (see `userns`).
            nr::GETUID => uid_out(self.creds.uid, false),
            nr::GETEUID => uid_out(self.creds.euid, false),
            nr::GETGID => uid_out(self.creds.gid, true),
            nr::GETEGID => uid_out(self.creds.egid, true),
            nr::SETUID => match uid_in(a[0], false) {
                Ok(u) => {
                    let r = self.creds.setuid(u);
                    self.ids_changed(r)
                }
                Err(e) => err(e),
            },
            nr::SETREUID => match (uid_in(a[0], false), uid_in(a[1], false)) {
                (Ok(r), Ok(e)) => {
                    let r = self.creds.setreuid(r, e);
                    self.ids_changed(r)
                }
                (Err(x), _) | (_, Err(x)) => err(x),
            },
            nr::SETRESUID => {
                match (uid_in(a[0], false), uid_in(a[1], false), uid_in(a[2], false)) {
                    (Ok(r), Ok(e), Ok(s)) => {
                        let r = self.creds.setresuid(r, e, s);
                        self.ids_changed(r)
                    }
                    (Err(x), _, _) | (_, Err(x), _) | (_, _, Err(x)) => err(x),
                }
            }
            nr::SETFSUID => match uid_in(a[0], false) {
                Ok(u) => {
                    let old = self.creds.setfsuid(u) as u32;
                    self.ids_changed(0);
                    uid_out(old, false)
                }
                // Unmapped: no change, and the old one back.
                Err(_) => uid_out(self.creds.fsuid, false),
            },
            nr::GETRESUID => self.sys_getresuid(a[0], a[1], a[2]),
            nr::SETGID => match uid_in(a[0], true) {
                Ok(g) => {
                    let r = self.creds.setgid(g);
                    self.ids_changed(r)
                }
                Err(e) => err(e),
            },
            nr::SETREGID => match (uid_in(a[0], true), uid_in(a[1], true)) {
                (Ok(r), Ok(e)) => {
                    let r = self.creds.setregid(r, e);
                    self.ids_changed(r)
                }
                (Err(x), _) | (_, Err(x)) => err(x),
            },
            nr::SETRESGID => match (uid_in(a[0], true), uid_in(a[1], true), uid_in(a[2], true)) {
                (Ok(r), Ok(e), Ok(s)) => {
                    let r = self.creds.setresgid(r, e, s);
                    self.ids_changed(r)
                }
                (Err(x), _, _) | (_, Err(x), _) | (_, _, Err(x)) => err(x),
            },
            nr::SETFSGID => match uid_in(a[0], true) {
                Ok(g) => {
                    let old = self.creds.setfsgid(g) as u32;
                    self.ids_changed(0);
                    uid_out(old, true)
                }
                Err(_) => uid_out(self.creds.fsgid, true),
            },
            nr::GETRESGID => self.sys_getresgid(a[0], a[1], a[2]),
            nr::GETGROUPS => self.sys_getgroups(a[0], a[1]),
            nr::SETGROUPS => self.sys_setgroups(a[0], a[1]),
            nr::SET_TID_ADDRESS => {
                thread::set_clear_child_tid(a[0]);
                thread::tid() as i64
            }
            nr::SET_ROBUST_LIST => {
                if a[1] != 24 {
                    return err(errno::EINVAL);
                }
                thread::set_robust_list(a[0], a[1]);
                0
            }
            // The caller's own list; another thread's or process's needs a
            // tracer's standing, which nothing has.
            nr::GET_ROBUST_LIST => {
                let pid = a[0] as i32;
                if pid != 0 && pid != thread::tid() {
                    return err(
                        if crate::pidns::to_host(pid).is_some()
                            || thread::host_thread(pid).is_some()
                        {
                            errno::EPERM
                        } else {
                            errno::ESRCH
                        },
                    );
                }
                let (head, len) = thread::robust_list();
                guest!(uaccess::write(a[1], head));
                guest!(uaccess::write(a[2], len));
                0
            }
            nr::UNAME => self.sys_uname(a[0]),
            nr::SYSINFO => self.sys_sysinfo(a[0]),
            nr::PRCTL => self.sys_prctl(a[0], a[1], a[2]),
            nr::SHMGET => self.sys_shmget(a[0], a[1], a[2]),
            nr::SHMAT => self.sys_shmat(a[0], a[1], a[2]),
            nr::SHMDT => self.sys_shmdt(a[0]),
            nr::SHMCTL => self.sys_shmctl(a[0], a[1], a[2]),
            nr::SEMGET => self.sys_semget(a[0], a[1], a[2]),
            // The backends run these without the lock (they wait); the same,
            // reached here (the plain `syscall` helper).
            nr::SEMOP
            | nr::SEMTIMEDOP
            | nr::MSGSND
            | nr::MSGRCV
            | nr::MQ_TIMEDSEND
            | nr::MQ_TIMEDRECEIVE => crate::ipcops::blocking(self.ipc_context(), n, a),
            nr::MQ_OPEN => self.sys_mq_open(a[0], a[1], a[2], a[3]),
            nr::SETNS => self.sys_setns(a[0], a[1]),
            nr::INOTIFY_INIT1 => self.sys_inotify_init1(a[0]),
            nr::INOTIFY_ADD_WATCH => self.sys_inotify_add_watch(a[0], a[1], a[2]),
            nr::INOTIFY_RM_WATCH => self.sys_inotify_rm_watch(a[0], a[1]),
            nr::FSOPEN => self.sys_fsopen(a[0], a[1]),
            nr::FSCONFIG => self.sys_fsconfig(a[0], a[1], a[2], a[3], a[4]),
            nr::FSMOUNT => self.sys_fsmount(a[0], a[1], a[2]),
            nr::FSPICK => self.sys_fspick(a[0], a[1], a[2]),
            nr::OPEN_TREE => self.sys_open_tree(a[0], a[1], a[2]),
            nr::MOVE_MOUNT => self.sys_move_mount(a[0], a[1], a[2], a[3], a[4]),
            nr::MOUNT_SETATTR => self.sys_mount_setattr(a[0], a[1], a[2], a[3], a[4]),
            nr::STATMOUNT => self.sys_statmount(a[0], a[1], a[2], a[3]),
            nr::LISTMOUNT => self.sys_listmount(a[0], a[1], a[2], a[3]),
            nr::MQ_UNLINK => self.sys_mq_unlink(a[0]),
            nr::MQ_NOTIFY => self.sys_mq_notify(a[0], a[1]),
            nr::MQ_GETSETATTR => self.sys_mq_getsetattr(a[0], a[1], a[2]),
            nr::SEMCTL => self.sys_semctl(a[0], a[1], a[2], a[3]),
            nr::MSGGET => self.sys_msgget(a[0], a[1]),
            nr::MSGCTL => self.sys_msgctl(a[0], a[1], a[2]),
            nr::MLOCK => self.sys_mlock(a[0], a[1], 0, true),
            nr::MLOCK2 => self.sys_mlock(a[0], a[1], a[2], true),
            nr::MUNLOCK => self.sys_mlock(a[0], a[1], 0, false),
            nr::MLOCKALL => self.sys_mlockall(Some(a[0])),
            nr::MUNLOCKALL => self.sys_mlockall(None),
            nr::GETPRIORITY => self.sys_getpriority(a[0], a[1] as i32),
            nr::SETPRIORITY => self.sys_setpriority(a[0], a[1] as i32, a[2] as i32),
            nr::CAPGET => self.sys_capget(a[0], a[1]),
            nr::SECCOMP => self.sys_seccomp(a[0], a[1], a[2]),
            nr::BPF if !self.creds.has_admin() => err(errno::EPERM),
            nr::BPF => crate::bpf::sys_bpf(a[0], a[1], a[2]),
            nr::CAPSET => self.sys_capset(a[0], a[1]),
            nr::SCHED_YIELD => {
                std::thread::yield_now();
                0
            }
            nr::SCHED_GETAFFINITY => self.sys_sched_getaffinity(a[0], a[1], a[2]),
            nr::PERSONALITY => personality(a[0]),
            nr::SCHED_SETSCHEDULER => self.sys_sched_setscheduler(a[0], Some(a[1]), a[2]),
            nr::SCHED_SETPARAM => self.sys_sched_setscheduler(a[0], None, a[1]),
            nr::SCHED_GETSCHEDULER => self.sys_sched_getscheduler(a[0]),
            nr::SCHED_GETPARAM => self.sys_sched_getparam(a[0], a[1]),
            nr::SCHED_SETATTR => self.sys_sched_setattr(a[0], a[1], a[2]),
            nr::SCHED_GETATTR => self.sys_sched_getattr(a[0], a[1], a[2], a[3]),
            nr::SCHED_GET_PRIORITY_MAX => crate::sched::priority_bound(a[0], true),
            nr::SCHED_GET_PRIORITY_MIN => crate::sched::priority_bound(a[0], false),
            nr::SCHED_RR_GET_INTERVAL => self.sys_sched_rr_get_interval(a[0], a[1]),
            nr::SCHED_SETAFFINITY => self.sys_sched_setaffinity(a[0], a[1], a[2]),
            nr::GETRUSAGE => {
                use fwe_abi::resource_usage as ru;
                let who = match a[0] as i32 as i64 {
                    // The host has no per-thread usage; report the process's.
                    ru::RUSAGE_SELF | ru::RUSAGE_THREAD => libc::RUSAGE_SELF,
                    ru::RUSAGE_CHILDREN => libc::RUSAGE_CHILDREN,
                    _ => return err(errno::EINVAL),
                };
                // SAFETY: an all-zero rusage is a valid out-parameter.
                let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                // SAFETY: `usage` is a valid out-parameter.
                if unsafe { libc::getrusage(who, &mut usage) } != 0 {
                    return last_error();
                }
                guest!(host::write_rusage(a[1], &usage));
                0
            }
            nr::PRLIMIT64 => self.sys_prlimit(a[0], a[1], a[2], a[3]),
            nr::GETRLIMIT => self.sys_prlimit(0, a[0], 0, a[1]),
            nr::SETRLIMIT => self.sys_prlimit(0, a[0], a[1], 0),

            // Time.
            nr::CLOCK_GETTIME => self.sys_clock_gettime(a[0], a[1]),
            nr::CLOCK_GETRES => self.sys_clock_getres(a[0], a[1]),
            nr::CLOCK_SETTIME => self.sys_clock_settime(a[0], a[1]),
            nr::CLOCK_ADJTIME => self.sys_clock_adjtime(a[0], a[1]),
            nr::SETTIMEOFDAY => self.sys_settimeofday(a[0], a[1]),
            nr::ADJTIMEX => self.sys_adjtimex(a[0]),
            nr::GETTIMEOFDAY => {
                // The C library fills these in itself, unchecked: copy out.
                let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
                // SAFETY: `tv` is a valid out-parameter.
                unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
                if a[0] != 0 {
                    guest!(uaccess::write(a[0], [tv.tv_sec, host::usec(tv)]));
                }
                if a[1] != 0 {
                    // struct timezone: always zero, as on Linux today.
                    guest!(uaccess::write(a[1], [0i32; 2]));
                }
                0
            }
            nr::NANOSLEEP => {
                // SAFETY: the arguments are checked guest pointers.
                unsafe { clock_nanosleep(clock::CLOCK_MONOTONIC, 0, a[0], a[1]) }
            }
            nr::CLOCK_NANOSLEEP => self.sys_clock_nanosleep(a[0], a[1], a[2], a[3]),

            // Signals.
            nr::RT_SIGACTION => self.sys_rt_sigaction(a[0], a[1], a[2], a[3]),
            nr::RT_SIGPROCMASK => self.sys_rt_sigprocmask(a[0], a[1], a[2], a[3]),
            nr::SIGALTSTACK => self.sys_sigaltstack(a[0], a[1]),
            nr::KILL => self.sys_kill(a[0] as i32 as i64, a[1]),
            nr::TKILL => self.sys_tgkill(-1, a[0] as i32 as i64, a[1]),
            nr::TGKILL => self.sys_tgkill(a[0] as i32 as i64, a[1] as i32 as i64, a[2]),
            nr::RT_SIGPENDING => self.sys_rt_sigpending(a[0], a[1]),
            nr::SETITIMER => self.sys_setitimer(a[0], a[1], a[2]),
            nr::GETITIMER => match itimer::get(a[0]) {
                Ok(v) => {
                    guest!(uaccess::write(a[1], v));
                    0
                }
                Err(e) => err(e),
            },

            // futex and the sleeps can block, so the backend runs them
            // outside the kernel lock via `blocking_syscall`; reaching them
            // here (e.g. through the plain `syscall` helper) is unsupported.

            // Randomness.
            nr::GETRANDOM => self.sys_getrandom(a[0], a[1]),

            // Not implemented yet. rseq and membarrier are optional for libc.
            _ => {
                self.tracer.note(&format!("unimplemented syscall {n}"));
                err(errno::ENOSYS)
            }
        }
    }

    /// Shared `chown` policy against the virtual credentials. `chown(-1, -1)`
    /// is always a no-op; otherwise only a virtual root may change ownership,
    /// and it is a no-op on the host file (we do not run as root, and tracking
    /// shadow ownership is not yet implemented).
    pub(crate) fn chown_check(&self, uid: u32, gid: u32) -> i64 {
        if uid == u32::MAX && gid == u32::MAX {
            return 0;
        }
        if self.creds.has(crate::caps::CAP_CHOWN) { 0 } else { err(errno::EPERM) }
    }

    fn sys_getresuid(&self, rp: u64, ep: u64, sp: u64) -> i64 {
        if rp == 0 || ep == 0 || sp == 0 {
            return err(errno::EFAULT);
        }
        let (r, e, s) = self.creds.resuid();
        let v = |id| crate::userns::to_ns(id, false);
        guest!(uaccess::write(rp, v(r)));
        guest!(uaccess::write(ep, v(e)));
        guest!(uaccess::write(sp, v(s)));
        0
    }

    fn sys_getresgid(&self, rp: u64, ep: u64, sp: u64) -> i64 {
        if rp == 0 || ep == 0 || sp == 0 {
            return err(errno::EFAULT);
        }
        let (r, e, s) = self.creds.resgid();
        let v = |id| crate::userns::to_ns(id, true);
        guest!(uaccess::write(rp, v(r)));
        guest!(uaccess::write(ep, v(e)));
        guest!(uaccess::write(sp, v(s)));
        0
    }

    fn sys_getgroups(&self, size: u64, list: u64) -> i64 {
        let groups = self.creds.groups();
        let n = groups.len();
        if size == 0 {
            return n as i64;
        }
        if (size as usize) < n {
            return err(errno::EINVAL);
        }
        for (i, &g) in groups.iter().enumerate() {
            guest!(uaccess::write(list + (i * 4) as u64, crate::userns::to_ns(g, true)));
        }
        n as i64
    }

    fn sys_setgroups(&mut self, size: u64, list: u64) -> i64 {
        let n = size as usize;
        if n > 65536 {
            return err(errno::EINVAL);
        }
        // Denied in a user namespace whose setgroups says so, or whose
        // gid_map is not yet written.
        if crate::userns::nested() && !crate::userns::setgroups_allowed() {
            return err(errno::EPERM);
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let g = guest!(uaccess::read::<u32>(list + (i * 4) as u64));
            match crate::userns::from_ns(g, true) {
                Some(k) => v.push(k),
                None => return err(errno::EINVAL),
            }
        }
        self.creds.setgroups(v)
    }

    fn sys_dup3(&mut self, old: u64, new: u64, flags: u64) -> i64 {
        if old == new || flags & !fcntl::O_CLOEXEC != 0 {
            return err(errno::EINVAL);
        }
        // `new` is closed first, as by `close`, so an emulated descriptor
        // there leaves its registry (and an epoll interest list); only if
        // `old` is open, since a failed dup3 leaves `new` alone.
        // SAFETY: F_GETFD only queries the descriptor.
        if unsafe { libc::fcntl(old as i32, libc::F_GETFD) } >= 0 {
            self.dispatch(nr::CLOSE, [new, 0, 0, 0, 0, 0]);
        }
        // SAFETY: plain host calls.
        let r = unsafe { libc::dup2(old as i32, new as i32) };
        if r >= 0 {
            crate::fdmarks::duplicated(old as i32, r);
        }
        if r >= 0 && flags & fcntl::O_CLOEXEC != 0 {
            // SAFETY: plain host call on the descriptor just created.
            unsafe { libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        ret(r)
    }

    /// `close_range(first, last, flags)`: close (or, with
    /// `CLOSE_RANGE_CLOEXEC`, mark close-on-exec) the guest's open
    /// descriptors in `[first, last]`. fwe's own are outside the guest range.
    fn sys_close_range(&mut self, first: u32, last: u32, flags: u64) -> i64 {
        const CLOSE_RANGE_UNSHARE: u64 = 2;
        const CLOSE_RANGE_CLOEXEC: u64 = 4;
        if first > last || flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
            return err(errno::EINVAL);
        }
        for fd in crate::fdtable::open_fds() {
            if (fd as u32) < first || fd as u32 > last {
                continue;
            }
            if flags & CLOSE_RANGE_CLOEXEC != 0 {
                // SAFETY: plain host call on an open guest descriptor.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            } else {
                self.dispatch(nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            }
        }
        0
    }

    fn sys_fcntl(&mut self, fd: u64, cmd: u64, arg: u64) -> i64 {
        let fd = fd as i32;
        // The descriptor first, whatever the command, as Linux checks.
        // SAFETY: F_GETFD only queries.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return err(errno::EBADF);
        }
        // SAFETY: every arm is a plain host call on a guest descriptor.
        unsafe {
            match cmd {
                fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC
                    if arg >= crate::fdtable::limit().0
                        || !crate::fdtable::guest_visible(arg as i32) =>
                {
                    err(errno::EINVAL)
                }
                fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC => {
                    let how =
                        if cmd == fcntl::F_DUPFD { libc::F_DUPFD } else { libc::F_DUPFD_CLOEXEC };
                    let r = ret(libc::fcntl(fd, how, arg as i32));
                    if r >= 0 {
                        crate::fdmarks::duplicated(fd, r as i32);
                    }
                    r
                }
                fcntl::F_GETFD => {
                    let r = libc::fcntl(fd, libc::F_GETFD);
                    if r < 0 {
                        last_error()
                    } else {
                        (if r & libc::FD_CLOEXEC != 0 { fcntl::FD_CLOEXEC } else { 0 }) as i64
                    }
                }
                fcntl::F_SETFD => {
                    let v = if arg & fcntl::FD_CLOEXEC != 0 { libc::FD_CLOEXEC } else { 0 };
                    ret(libc::fcntl(fd, libc::F_SETFD, v))
                }
                fcntl::F_GETFL => {
                    let r = libc::fcntl(fd, libc::F_GETFL);
                    if r < 0 {
                        last_error()
                    } else if crate::fdmarks::is_path(fd) {
                        // An `O_PATH` descriptor's flags: that, and the
                        // large-file flag every arm64 open has.
                        (fcntl::O_PATH | fcntl::O_LARGEFILE) as i64
                    } else if crate::memfd::write_refused(fd) {
                        // Read-only on the host since it was sealed (see
                        // `memfd`), but open for writing as far as Linux goes.
                        let r = (r & !libc::O_ACCMODE) | libc::O_RDWR;
                        host::status_flags_to_linux(r) as i64
                    } else {
                        host::status_flags_to_linux(r) as i64
                    }
                }
                fcntl::F_SETFL => {
                    ret(libc::fcntl(fd, libc::F_SETFL, host::settable_flags_to_host(arg)))
                }
                fcntl::F_GETLK => {
                    let asked: fwe_abi::Flock = guest!(uaccess::read(arg));
                    let mut lock = match host::flock_to_host(&asked) {
                        Ok(l) => l,
                        Err(e) => return err(e),
                    };
                    if libc::fcntl(fd, libc::F_GETLK, &mut lock) < 0 {
                        return last_error();
                    }
                    // Nothing in the way: Linux changes only the type (the
                    // host makes the range absolute too).
                    let found = host::flock_to_linux(&lock);
                    let answer = if found.l_type == fcntl::F_UNLCK {
                        fwe_abi::Flock { l_type: fcntl::F_UNLCK, ..asked }
                    } else {
                        found
                    };
                    guest!(uaccess::write(arg, answer));
                    0
                }
                fcntl::F_SETLK | fcntl::F_SETLKW => set_record_lock(fd, cmd, arg),
                fcntl::F_ADD_SEALS => crate::memfd::add_seals(fd, arg),
                fcntl::F_GET_SEALS => crate::memfd::get_seals(fd),
                fcntl::F_SETOWN => {
                    crate::fdstate::update(fd, |s| s.owner_tid = None);
                    self.set_owner(fd, arg as i32)
                }
                fcntl::F_GETOWN => match crate::fdstate::get(fd).owner_tid {
                    Some(tid) => tid as i64,
                    None => self.owner(fd),
                },
                fcntl::F_SETOWN_EX => {
                    let [kind, pid]: [i32; 2] = guest!(uaccess::read(arg));
                    let r = match kind {
                        fcntl::F_OWNER_TID if pid != 0 && !thread::tids().contains(&pid) => {
                            // A thread of another process: its process.
                            self.set_owner(fd, pid)
                        }
                        fcntl::F_OWNER_TID if pid != 0 => self.set_owner(fd, thread::tgid()),
                        fcntl::F_OWNER_TID | fcntl::F_OWNER_PID => self.set_owner(fd, pid),
                        fcntl::F_OWNER_PGRP => self.set_owner(fd, pid.wrapping_neg()),
                        _ => return err(errno::EINVAL),
                    };
                    if r == 0 {
                        let tid = (kind == fcntl::F_OWNER_TID && pid != 0).then_some(pid);
                        crate::fdstate::update(fd, |s| s.owner_tid = tid);
                    }
                    r
                }
                fcntl::F_GETOWN_EX => {
                    let owner = match crate::fdstate::get(fd).owner_tid {
                        Some(tid) => [fcntl::F_OWNER_TID, tid],
                        None => match self.owner(fd) {
                            o if o < 0 => [fcntl::F_OWNER_PGRP, -o as i32],
                            o => [fcntl::F_OWNER_PID, o as i32],
                        },
                    };
                    guest!(uaccess::write(arg, owner));
                    0
                }
                fcntl::F_SETSIG if arg > signal::NSIG => err(errno::EINVAL),
                fcntl::F_SETSIG => {
                    crate::fdstate::update(fd, |s| s.sig = arg as u32);
                    0
                }
                fcntl::F_GETSIG => crate::fdstate::get(fd).sig as i64,
                fcntl::F_SETLEASE => self.set_lease(fd, arg),
                fcntl::F_GETLEASE => {
                    i64::from(crate::fdstate::get(fd).lease.unwrap_or(fcntl::F_UNLCK))
                }
                fcntl::F_GETPIPE_SZ | fcntl::F_SETPIPE_SZ => self.pipe_size(fd, cmd, arg),
                _ => err(errno::EINVAL),
            }
        }
    }

    /// `F_SETOWN`'s owner `who` (a pid, or a process group negated) for
    /// the host, which sends it `SIGIO`.
    fn set_owner(&self, fd: i32, who: i32) -> i64 {
        let host = match who {
            0 => 0,
            p if p > 0 => match crate::pidns::to_host(p) {
                Some(h) => h,
                None => return err(errno::ESRCH),
            },
            p => match crate::pidns::to_host(p.wrapping_neg()) {
                Some(h) => -h,
                None => return err(errno::ESRCH),
            },
        };
        // SAFETY: plain host call on the guest's descriptor.
        ret(unsafe { libc::fcntl(fd, libc::F_SETOWN, host) })
    }

    /// `F_GETOWN`: the owner, a pid or a process group negated, in the
    /// guest's pid namespace.
    fn owner(&self, fd: i32) -> i64 {
        // SAFETY: plain host call on the guest's descriptor.
        let h = unsafe { libc::fcntl(fd, libc::F_GETOWN) };
        match h {
            0 => 0,
            p if p > 0 => crate::pidns::guest_ret(p as i64),
            p => -crate::pidns::guest_ret(-(p as i64)),
        }
    }

    /// `F_SETLEASE`: a lease on a regular file, as Linux grants it: by its
    /// owner or with `CAP_LEASE`, a read lease only on a descriptor not open
    /// for writing, a write lease only while no other descriptor has the
    /// file open (of those fwe can see: its own).
    fn set_lease(&self, fd: i32, arg: u64) -> i64 {
        let kind = arg as i16;
        if arg > 2 || !matches!(kind, fcntl::F_RDLCK | fcntl::F_WRLCK | fcntl::F_UNLCK) {
            return err(errno::EINVAL);
        }
        let st = match crate::fsops::linux_fstat(fd) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        if st.st_mode & fwe_abi::stat::S_IFMT != fwe_abi::stat::S_IFREG {
            return err(errno::EINVAL);
        }
        if st.st_uid != self.creds.fsuid && !self.creds.has(crate::caps::CAP_LEASE) {
            return err(errno::EACCES);
        }
        // SAFETY: plain host call on the guest's descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let writable = fl & libc::O_ACCMODE != libc::O_RDONLY;
        if (kind == fcntl::F_RDLCK && writable)
            || (kind == fcntl::F_WRLCK && crate::fdmarks::shared_elsewhere(fd))
        {
            return err(errno::EAGAIN);
        }
        crate::fdstate::update(fd, |s| s.lease = (kind != fcntl::F_UNLCK).then_some(kind));
        0
    }

    /// `F_GETPIPE_SZ` and `F_SETPIPE_SZ` of a pipe or FIFO: its capacity, and
    /// a new one, rounded as Linux rounds it and held to `pipe-max-size`
    /// without `CAP_SYS_RESOURCE`, and never below what the pipe holds.
    fn pipe_size(&self, fd: i32, cmd: u64, arg: u64) -> i64 {
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::fstat(fd, &mut st) } < 0 || st.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return err(errno::EBADF);
        }
        let id = (st.st_dev as u64, st.st_ino);
        if cmd == fcntl::F_GETPIPE_SZ {
            return crate::fdstate::pipe_size(id) as i64;
        }
        let Some(size) = crate::fdstate::round_pipe_size(arg) else {
            return err(errno::EINVAL);
        };
        /// `/proc/sys/fs/pipe-max-size`.
        const PIPE_MAX: u64 = 1_048_576;
        if size > PIPE_MAX && !self.creds.has(crate::caps::CAP_SYS_RESOURCE) {
            return err(errno::EPERM);
        }
        let mut held: libc::c_int = 0;
        // SAFETY: a valid out-parameter for FIONREAD.
        unsafe { libc::ioctl(fd, libc::FIONREAD, &mut held) };
        if (held as u64) > size {
            return err(errno::EBUSY);
        }
        crate::fdstate::set_pipe_size(id, size);
        size as i64
    }

    fn sys_ioctl(&mut self, fd: u64, req: u64, arg: u64) -> i64 {
        let fd = fd as i32;
        // The request is 32 bits (an `unsigned int`); a C library passing
        // an `int` sign-extends it.
        let req = req as u32 as u64;
        if let Some(r) = self.loop_ioctl(fd, req, arg) {
            return r;
        }
        if let Some(r) = self.ns_ioctl(fd, req, arg) {
            return r;
        }
        // SAFETY: in every arm the argument layouts match the host's; the host
        // validates guest pointers.
        unsafe {
            match req {
                ioctl::TIOCGWINSZ => {
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) < 0 {
                        return host::tty_error();
                    }
                    let ws = Winsize {
                        ws_row: ws.ws_row,
                        ws_col: ws.ws_col,
                        ws_xpixel: ws.ws_xpixel,
                        ws_ypixel: ws.ws_ypixel,
                    };
                    guest!(uaccess::write(arg, ws));
                    0
                }
                ioctl::TCGETS => crate::term::tcgetattr(fd, arg),
                ioctl::PROCMAP_QUERY if let Some(pid) = maps_of_fd(fd) => {
                    self.procmap_query(pid, arg)
                }
                ioctl::SIOCGIFFLAGS
                | ioctl::SIOCSIFFLAGS
                | ioctl::SIOCGIFINDEX
                | ioctl::SIOCGIFMTU
                | ioctl::SIOCGIFNAME => self.interface_ioctl(fd, req, arg),
                ioctl::TCSETS | ioctl::TCSETSW | ioctl::TCSETSF => {
                    crate::term::tcsetattr(fd, req, arg)
                }
                ioctl::TIOCSWINSZ => {
                    let ws: Winsize = guest!(uaccess::read(arg));
                    let mut h: libc::winsize = std::mem::zeroed();
                    h.ws_row = ws.ws_row;
                    h.ws_col = ws.ws_col;
                    h.ws_xpixel = ws.ws_xpixel;
                    h.ws_ypixel = ws.ws_ypixel;
                    ret(libc::ioctl(fd, libc::TIOCSWINSZ, &h))
                }
                ioctl::TIOCGPGRP => {
                    let pg = libc::tcgetpgrp(fd);
                    if pg < 0 {
                        return last_error();
                    }
                    guest!(uaccess::write(arg, crate::pidns::guest_ret(pg as i64) as i32));
                    0
                }
                ioctl::TIOCSPGRP => {
                    let pg: i32 = guest!(uaccess::read(arg));
                    match crate::pidns::host_arg(pg) {
                        Ok(pg) => ret(libc::tcsetpgrp(fd, pg)),
                        Err(_) => err(errno::EPERM),
                    }
                }
                ioctl::TIOCSCTTY => ret(libc::ioctl(fd, libc::TIOCSCTTY as _, arg as libc::c_int)),
                ioctl::TIOCNOTTY => ret(libc::ioctl(fd, libc::TIOCNOTTY as _)),
                ioctl::TIOCGPTN => match crate::pty::ptsnum(fd) {
                    Some(n) => {
                        guest!(uaccess::write(arg, n));
                        0
                    }
                    None => err(errno::ENOTTY),
                },
                // The slave is unlocked at allocation; accept the lock request.
                ioctl::TIOCSPTLCK => 0,
                ioctl::FIONREAD => ret(libc::ioctl(fd, libc::FIONREAD, arg as *mut libc::c_int)),
                ioctl::FIONBIO => ret(libc::ioctl(fd, libc::FIONBIO, arg as *mut libc::c_int)),
                ioctl::FIOCLEX => ret(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC)),
                ioctl::FIONCLEX => ret(libc::fcntl(fd, libc::F_SETFD, 0)),
                // `O_ASYNC` on or off, as `fcntl` sets it.
                ioctl::FIOASYNC => {
                    let on: i32 = guest!(uaccess::read(arg));
                    let fl = self.sys_fcntl(fd as u64, fcntl::F_GETFL, 0);
                    if fl < 0 {
                        return fl;
                    }
                    let fl = fl as u64 & !fcntl::O_ASYNC;
                    let fl = if on != 0 { fl | fcntl::O_ASYNC } else { fl };
                    self.sys_fcntl(fd as u64, fcntl::F_SETFL, fl).min(0)
                }
                _ => {
                    if libc::fcntl(fd, libc::F_GETFD) < 0 {
                        last_error()
                    } else {
                        err(errno::ENOTTY)
                    }
                }
            }
        }
    }

    fn sys_ppoll(&mut self, fds: u64, nfds: u64, timeout: u64) -> i64 {
        // SAFETY: the guest passed the array and timeout pointers.
        unsafe { ppoll(fds, nfds, timeout) }
    }

    fn sys_uname(&mut self, buf: u64) -> i64 {
        // SAFETY: zeroed bytes are a valid `Utsname`.
        let mut u: Utsname = unsafe { std::mem::zeroed() };
        fill(&mut u.sysname, b"Linux");
        let (host, domain) = match self.fs.as_ref() {
            Some(fs) => (fs.ns.hostname(), fs.ns.domainname()),
            None => (crate::ns::host_name(), b"(none)".to_vec()),
        };
        fill(&mut u.nodename, &host);
        fill(&mut u.release, release().as_bytes());
        fill(&mut u.version, b"#1 SMP PREEMPT");
        fill(&mut u.machine, b"aarch64");
        fill(&mut u.domainname, &domain);
        guest!(uaccess::write(buf, u));
        0
    }

    /// `prctl(option, arg2, ...)` for the options programs commonly use; any
    /// other fails with `EINVAL`, as an unknown option does on Linux.
    fn sys_prctl(&mut self, option: u64, arg2: u64, arg3: u64) -> i64 {
        use fwe_abi::prctl::*;
        use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
        /// `PR_SET_DUMPABLE`.
        static UNDUMPABLE: AtomicBool = AtomicBool::new(false);
        match option {
            PR_SET_NAME => {
                let mut name = [0u8; TASK_COMM_LEN];
                let s = guest!(uaccess::read_cstr(arg2, 4096));
                let n = s.len().min(TASK_COMM_LEN - 1);
                name[..n].copy_from_slice(&s[..n]);
                thread::set_name(name);
                if thread::tid() == thread::tgid() {
                    // What /proc/<pid>/comm shows of the process.
                    crate::procreg::own_comm(&name[..n]);
                }
                0
            }
            PR_GET_NAME => {
                // A thread not yet named has the program's file name.
                let name = thread::name().unwrap_or_else(|| {
                    let exe = self.fs().exe();
                    let base = exe.rsplit(|&b| b == b'/').next().unwrap_or(exe);
                    let mut name = [0u8; TASK_COMM_LEN];
                    let n = base.len().min(TASK_COMM_LEN - 1);
                    name[..n].copy_from_slice(&base[..n]);
                    name
                });
                guest!(uaccess::write(arg2, name));
                0
            }
            PR_CAPBSET_READ if arg2 <= CAP_LAST_CAP => {
                i64::from(self.creds.caps.bounding & (1 << arg2) != 0)
            }
            PR_CAPBSET_READ => err(errno::EINVAL),
            PR_CAPBSET_DROP => match self.creds.caps.drop_bounding(arg2) {
                Ok(()) => 0,
                Err(e) => err(e),
            },
            PR_CAP_AMBIENT => match self.creds.caps.ambient_op(arg2, arg3) {
                Ok(r) => r,
                Err(e) => err(e),
            },
            PR_GET_KEEPCAPS => {
                i64::from(self.creds.caps.securebits & crate::caps::SECBIT_KEEP_CAPS != 0)
            }
            PR_SET_KEEPCAPS => match self.creds.caps.set_keepcaps(arg2) {
                Ok(()) => 0,
                Err(e) => err(e),
            },
            PR_GET_SECUREBITS => i64::from(self.creds.caps.securebits),
            PR_SET_SECUREBITS => match self.creds.caps.set_securebits(arg2) {
                Ok(()) => 0,
                Err(e) => err(e),
            },
            // In the process's record, where its descendants look for it;
            // fwe keeps the adoption (see `reaper`).
            PR_SET_CHILD_SUBREAPER => {
                crate::reaper::set_subreaper(arg2 != 0);
                crate::reaper::start_if_reaper();
                0
            }
            PR_GET_CHILD_SUBREAPER => {
                guest!(uaccess::write(arg2, i32::from(crate::procreg::own_subreaper())));
                0
            }
            PR_SET_NO_NEW_PRIVS if arg2 == 1 => {
                NO_NEW_PRIVS.store(true, Relaxed);
                0
            }
            PR_SET_NO_NEW_PRIVS => err(errno::EINVAL),
            PR_GET_NO_NEW_PRIVS => i64::from(NO_NEW_PRIVS.load(Relaxed)),
            PR_GET_SECCOMP => i64::from(crate::seccomp::mode()),
            PR_SET_SECCOMP => self.sys_seccomp(
                if arg2 == 1 { 0 } else { arg2 - 1 },
                0,
                if arg2 == 1 { 0 } else { arg3 },
            ),
            PR_SET_DUMPABLE if arg2 <= 1 => {
                UNDUMPABLE.store(arg2 == 0, Relaxed);
                0
            }
            PR_SET_DUMPABLE => err(errno::EINVAL),
            PR_GET_DUMPABLE => i64::from(!UNDUMPABLE.load(Relaxed)),
            PR_SET_PDEATHSIG if arg2 <= signal::NSIG => {
                thread::set_pdeathsig(arg2);
                0
            }
            PR_SET_PDEATHSIG => err(errno::EINVAL),
            PR_GET_PDEATHSIG => {
                guest!(uaccess::write(arg2, thread::pdeathsig() as i32));
                0
            }
            _ => err(errno::EINVAL),
        }
    }

    /// The data words a `capget`/`capset` header's version asks for, or
    /// `EINVAL` after writing the version fwe prefers into the header.
    fn cap_words(&self, hdr: u64) -> Result<(usize, i32), i64> {
        use crate::caps::*;
        let h: [u32; 2] = uaccess::read(hdr).map_err(err)?;
        match h[0] {
            VERSION_1 => Ok((1, h[1] as i32)),
            VERSION_2 | VERSION_3 => Ok((2, h[1] as i32)),
            _ => {
                uaccess::write(hdr, [VERSION_3, h[1]]).map_err(err)?;
                Err(err(errno::EINVAL))
            }
        }
    }

    /// `capget(hdr, data)`: the caller's capabilities (another process's
    /// fwe does not hold: `ESRCH`).
    fn sys_capget(&mut self, hdr: u64, data: u64) -> i64 {
        let (words, pid) = match self.cap_words(hdr) {
            Ok(v) => v,
            Err(e) => return if data == 0 && e == err(errno::EINVAL) { 0 } else { e },
        };
        if pid < 0 {
            return err(errno::EINVAL);
        }
        if pid != 0 && pid != thread::tgid() {
            return err(errno::ESRCH);
        }
        if data == 0 {
            return 0;
        }
        let c = &self.creds.caps;
        let mut out = [0u32; 6];
        for w in 0..words {
            let shift = 32 * w as u64;
            out[w * 3] = (c.effective >> shift) as u32;
            out[w * 3 + 1] = (c.permitted >> shift) as u32;
            out[w * 3 + 2] = (c.inheritable >> shift) as u32;
        }
        guest!(uaccess::write_from(data, &bytemuck_u32(&out[..words * 3])));
        0
    }

    /// `capset(hdr, data)`: the caller's own sets only.
    fn sys_capset(&mut self, hdr: u64, data: u64) -> i64 {
        let (words, pid) = match self.cap_words(hdr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if pid != 0 && pid != thread::tgid() {
            return err(errno::EPERM);
        }
        let mut raw = [0u8; 24];
        guest!(uaccess::read_into(data, &mut raw[..words * 12]));
        let word = |i: usize| u32::from_ne_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
        let (mut e, mut p, mut i) = (word(0), word(1), word(2));
        if words == 2 {
            e |= word(3) << 32;
            p |= word(4) << 32;
            i |= word(5) << 32;
        }
        match self.creds.caps.set(e, p, i) {
            Ok(()) => 0,
            Err(x) => err(x),
        }
    }

    /// The network interface requests on a socket (`struct ifreq`: a
    /// 16-byte name, then the value). In a network namespace of fwe's the
    /// one interface is `lo`, index 1, up as the namespace says; in the
    /// initial one they are the host's, with Linux's `lo` for its `lo0`.
    fn interface_ioctl(&mut self, fd: i32, req: u64, arg: u64) -> i64 {
        use ioctl::*;
        let mut ifr = [0u8; 40];
        guest!(uaccess::read_into(arg, &mut ifr));
        let name_end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = ifr[..name_end].to_vec();
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            // SAFETY: F_GETFD only queries the descriptor.
            let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            return err(if open { errno::ENOTTY } else { errno::EBADF });
        }
        let put16 = |v: u16| uaccess::write(arg + 16, v);
        let put32 = |v: i32| uaccess::write(arg + 16, v);
        if let Some(net) = self.fs().ns.net.clone() {
            let is_lo = name == b"lo";
            return match req {
                SIOCGIFNAME => {
                    let index = u32::from_ne_bytes(ifr[16..20].try_into().unwrap());
                    if index != 1 {
                        return err(errno::ENODEV);
                    }
                    let mut out = [0u8; 16];
                    out[..2].copy_from_slice(b"lo");
                    guest!(uaccess::write(arg, out));
                    0
                }
                _ if !is_lo => err(errno::ENODEV),
                SIOCGIFFLAGS => {
                    let up = net.get().lo_up;
                    let flags = IFF_LOOPBACK | if up { IFF_UP | IFF_RUNNING } else { 0 };
                    guest!(put16(flags));
                    0
                }
                SIOCSIFFLAGS => {
                    if !self.creds.has(crate::caps::CAP_NET_ADMIN) {
                        return err(errno::EPERM);
                    }
                    let flags = u16::from_ne_bytes(ifr[16..18].try_into().unwrap());
                    match net.update(|n| {
                        n.lo_up = flags & IFF_UP != 0;
                        Ok(())
                    }) {
                        Ok(()) => 0,
                        Err(e) => err(e),
                    }
                }
                SIOCGIFINDEX => {
                    guest!(put32(1));
                    0
                }
                SIOCGIFMTU => {
                    guest!(put32(65536));
                    0
                }
                _ => err(errno::EINVAL),
            };
        }
        // The host's interfaces, named as on Linux.
        let host_name: Vec<u8> = if name == b"lo" { b"lo0".to_vec() } else { name.clone() };
        let Ok(cname) = std::ffi::CString::new(host_name) else { return err(errno::ENODEV) };
        match req {
            SIOCGIFINDEX => {
                // SAFETY: a NUL-terminated name.
                let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
                if index == 0 {
                    return err(errno::ENODEV);
                }
                guest!(put32(index as i32));
                0
            }
            SIOCGIFNAME => {
                let index = u32::from_ne_bytes(ifr[16..20].try_into().unwrap());
                let mut buf = [0u8; libc::IF_NAMESIZE];
                // SAFETY: `buf` holds IF_NAMESIZE bytes.
                if unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) }.is_null() {
                    return err(errno::ENODEV);
                }
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                let shown: &[u8] = if &buf[..end] == b"lo0" { b"lo" } else { &buf[..end] };
                let mut out = [0u8; 16];
                out[..shown.len().min(15)].copy_from_slice(&shown[..shown.len().min(15)]);
                guest!(uaccess::write(arg, out));
                0
            }
            SIOCGIFFLAGS | SIOCGIFMTU => {
                // macOS's `struct ifreq` has the same name and the value
                // after it.
                let mut h = [0u8; 32];
                h[..cname.as_bytes().len()].copy_from_slice(cname.as_bytes());
                let host_req = if req == SIOCGIFFLAGS { 0xc020_6911u64 } else { 0xc020_6933u64 };
                // SAFETY: a 32-byte ifreq for the host call.
                if unsafe { libc::ioctl(fd, host_req as libc::c_ulong, h.as_mut_ptr()) } < 0 {
                    return host::last_error();
                }
                let v = u16::from_ne_bytes([h[16], h[17]]);
                if req == SIOCGIFFLAGS {
                    guest!(put16(v & (IFF_UP | IFF_LOOPBACK | IFF_RUNNING | 0x2 | 0x10 | 0x1000)));
                } else {
                    guest!(put32(i32::from_ne_bytes(h[16..20].try_into().unwrap())));
                }
                0
            }
            // The host's interfaces are not the guest's to change.
            _ => err(errno::EPERM),
        }
    }

    /// A call the seccomp filters refused with `action` (not `Allow`): its
    /// errno, a `SIGSYS`, or the end of the thread or process.
    pub fn seccomp_refuse(
        &mut self,
        regs: &mut crate::Regs,
        nr: u64,
        args: &[u64; 6],
        action: crate::seccomp::Action,
    ) {
        use crate::seccomp::Action;
        match action {
            Action::Allow => self.enter_syscall(regs),
            Action::Errno(e) => self.finish_syscall(regs, nr, args, err(e)),
            Action::Trap(data) => {
                crate::signal::raise_sigsys(regs.pc, nr, data);
                // The call is not made; a handler may set what it returns.
                let x0 = regs.x[0] as i64;
                self.finish_syscall(regs, nr, args, x0);
            }
            // The backends end a thread of several before taking the
            // kernel lock; the last one takes the process with it.
            Action::KillThread | Action::KillProcess => self.terminate_by(signal::SIGSYS),
        }
    }

    /// `seccomp(op, flags, args)`.
    fn sys_seccomp(&mut self, op: u64, flags: u64, args: u64) -> i64 {
        use crate::seccomp::*;
        let allowed = NO_NEW_PRIVS.load(std::sync::atomic::Ordering::Relaxed)
            || self.creds.has(crate::caps::CAP_SYS_ADMIN);
        let r = match op {
            SET_MODE_STRICT if flags != 0 || args != 0 => Err(errno::EINVAL),
            SET_MODE_STRICT => set_strict(),
            SET_MODE_FILTER => install_filter(args, flags, allowed),
            GET_ACTION_AVAIL if flags != 0 => Err(errno::EINVAL),
            GET_ACTION_AVAIL => uaccess::read::<u32>(args).and_then(action_available),
            GET_NOTIF_SIZES if flags != 0 => Err(errno::EINVAL),
            // struct seccomp_notif_sizes: seccomp_notif, seccomp_notif_resp
            // and seccomp_data.
            GET_NOTIF_SIZES => uaccess::write(args, [80u16, 24, 64]).map(|()| 0),
            _ => Err(errno::EINVAL),
        };
        match r {
            Ok(v) => v,
            Err(e) => err(e),
        }
    }

    /// A call that may have changed the caller's ids returned `r`: other
    /// processes see the ids it now has ([`crate::procreg::ProcRecord::ids`]).
    pub(crate) fn ids_changed(&self, r: i64) -> i64 {
        if r >= 0 {
            let c = &self.creds;
            crate::procreg::set_own_ids([
                c.uid, c.euid, c.suid, c.fsuid, c.gid, c.egid, c.sgid, c.fsgid,
            ]);
        }
        r
    }

    /// `/proc/self/status`: the host's view of the process with the
    /// kernel's own of its credentials, capabilities and restrictions.
    /// `/proc/self/task/<tid>/status`: the process's, as thread `tid` of
    /// it shows it (its own id as `Pid`).
    pub(crate) fn task_status(&self, tid: i32) -> Vec<u8> {
        let status = String::from_utf8_lossy(&self.self_status()).into_owned();
        status
            .lines()
            .map(
                |l| {
                    if l.starts_with("Pid:\t") {
                        format!("Pid:\t{tid}\n")
                    } else {
                        format!("{l}\n")
                    }
                },
            )
            .collect::<String>()
            .into_bytes()
    }

    pub(crate) fn self_status(&self) -> Vec<u8> {
        // SAFETY: getpid cannot fail.
        let host = unsafe { libc::getpid() };
        let comm = thread::name()
            .map(|n| n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())].to_vec())
            .unwrap_or_else(|| {
                let exe = self.fs().exe();
                exe.rsplit(|&b| b == b'/').next().unwrap_or(exe).iter().take(15).copied().collect()
            });
        let h = crate::procpid::host_info(host).unwrap_or_default();
        let c = &self.creds;
        let u = |id| crate::userns::to_ns(id, false);
        let g = |id| crate::userns::to_ns(id, true);
        let creds = crate::procpid::Creds {
            uids: [u(c.uid), u(c.euid), u(c.suid), u(c.fsuid)],
            gids: [g(c.gid), g(c.egid), g(c.sgid), g(c.fsgid)],
            groups: c.groups.iter().map(|&x| g(x)).collect(),
            caps: Some(c.caps),
            no_new_privs: NO_NEW_PRIVS.load(std::sync::atomic::Ordering::Relaxed),
            seccomp: crate::seccomp::mode(),
            umask: self.fs().umask(),
            locked: crate::maps::record().locked_bytes(),
        };
        crate::procpid::status(thread::tgid(), &comm, &h, &creds)
    }

    /// `sysinfo`: the host's uptime and load, and the memory `/proc/meminfo`
    /// reports.
    fn sys_sysinfo(&mut self, buf: u64) -> i64 {
        let scale = (1u64 << fwe_abi::SI_LOAD_SHIFT) as f64;
        let info = fwe_abi::Sysinfo {
            uptime: host::uptime() as i64,
            loads: host::load_averages().map(|l| (l * scale) as u64),
            totalram: crate::procfs::MEM_TOTAL_KB * 1024,
            freeram: crate::procfs::MEM_FREE_KB * 1024,
            procs: 1,
            mem_unit: 1,
            ..Default::default()
        };
        guest!(uaccess::write(buf, info));
        0
    }

    fn sys_sched_getaffinity(&mut self, pid: u64, len: u64, mask: u64) -> i64 {
        // The caller, the process, or one of its threads: glibc's
        // `pthread_getattr_np` asks with the thread's own id.
        let id = pid as i32;
        if id != 0 && id != thread::tgid() && thread::host_thread(id).is_none() {
            return err(errno::ESRCH);
        }
        let online = online_cpus();
        let size = online.len() as u64 * 8;
        if len < size || len % 8 != 0 {
            return err(errno::EINVAL);
        }
        let set = AFFINITY.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or(online);
        for (word, value) in set.iter().enumerate() {
            guest!(uaccess::write(mask + word as u64 * 8, *value));
        }
        size as i64
    }

    /// `sched_setaffinity(pid, len, mask)`: checked as Linux checks it (the
    /// mask must name an online CPU) and remembered for the caller, which
    /// `sched_getaffinity` then reports. The host has no affinity to set:
    /// threads still run on any CPU, and another process's is not kept.
    fn sys_sched_setaffinity(&mut self, pid: u64, len: u64, mask: u64) -> i64 {
        let online = online_cpus();
        let mut want = vec![0u64; online.len()];
        let take = (len as usize).min(want.len() * 8);
        let mut bytes = vec![0u8; take];
        guest!(uaccess::read_into(mask, &mut bytes));
        for (i, b) in bytes.iter().enumerate() {
            want[i / 8] |= u64::from(*b) << (8 * (i % 8));
        }
        for (w, o) in want.iter_mut().zip(&online) {
            *w &= o;
        }
        if want.iter().all(|&w| w == 0) {
            return err(errno::EINVAL);
        }
        let id = pid as i32;
        if id == 0 || id == thread::tgid() || thread::host_thread(id).is_some() {
            *AFFINITY.lock().unwrap_or_else(|e| e.into_inner()) = Some(want);
            return 0;
        }
        match crate::pidns::host_arg(id) {
            // SAFETY: a signal 0 only checks that the process exists.
            Ok(h) if unsafe { libc::kill(h, 0) } == 0 || host::last_errno() == libc::EPERM => {
                // Another user's process, without CAP_SYS_NICE: refused.
                let owner = crate::procreg::ids(h);
                if !self.creds.has(crate::caps::CAP_SYS_NICE)
                    && ![owner[0], owner[1]].contains(&self.creds.euid)
                {
                    return err(errno::EPERM);
                }
                0
            }
            _ => err(errno::ESRCH),
        }
    }

    fn sys_prlimit(&mut self, pid: u64, res: u64, new: u64, old: u64) -> i64 {
        self.take_pending_limits();
        if res >= resource::RLIM_NLIMITS {
            return err(errno::EINVAL);
        }
        let target = match crate::pidns::host_arg(pid as i32) {
            Ok(0) => host::getpid() as i32,
            Ok(h) => h,
            Err(e) => return err(e),
        };
        if target != host::getpid() as i32 {
            return self.prlimit_other(target, res, new, old);
        }
        if old != 0 {
            match own_limit(res) {
                Ok((cur, max)) => {
                    guest!(uaccess::write(old, Rlimit { rlim_cur: cur, rlim_max: max }))
                }
                Err(e) => return err(e),
            }
        }
        if res == resource::RLIMIT_NOFILE {
            if new != 0 {
                let n: Rlimit = guest!(uaccess::read(new));
                if let Err(e) = crate::fdtable::set_limit(n.rlim_cur, n.rlim_max) {
                    return err(e);
                }
            }
            return 0;
        }
        if crate::rlimits::kept(res) {
            if new != 0 {
                let n: Rlimit = guest!(uaccess::read(new));
                let privileged = self.creds.has(crate::caps::CAP_SYS_RESOURCE);
                if let Err(e) = crate::rlimits::set(res, n.rlim_cur, n.rlim_max, privileged) {
                    return err(e);
                }
            }
            return 0;
        }
        let Some(hres) = host::rlimit_to_host(res) else {
            return 0;
        };
        if new != 0 {
            let n: Rlimit = guest!(uaccess::read(new));
            let r = libc::rlimit {
                rlim_cur: host::rlim_to_host(n.rlim_cur),
                rlim_max: host::rlim_to_host(n.rlim_max),
            };
            // SAFETY: `r` is a valid in-parameter.
            if unsafe { libc::setrlimit(hres as _, &r) } != 0 {
                return last_error();
            }
        }
        0
    }

    /// `prlimit` of another process, host process `target`: the limit it
    /// was left (or, none left, the caller's own, which a child inherits:
    /// fwe cannot read another's), and a new one left for it to take up
    /// ([`crate::procreg::push_limit`]), for a caller of its ids or with
    /// `CAP_SYS_RESOURCE`.
    fn prlimit_other(&mut self, target: i32, res: u64, new: u64, old: u64) -> i64 {
        if crate::procreg::read(target).is_none() {
            return err(errno::ESRCH);
        }
        // As Linux: another process's limits are the caller's to see and
        // set if its real, effective and saved ids are all the caller's
        // real ones, or with CAP_SYS_RESOURCE.
        let privileged = self.creds.has(crate::caps::CAP_SYS_RESOURCE);
        let ids = crate::procreg::ids(target);
        let (uid, gid) = (self.creds.uid, self.creds.gid);
        if !(ids[..3].iter().all(|&u| u == uid) && ids[4..7].iter().all(|&g| g == gid))
            && !privileged
        {
            return err(errno::EPERM);
        }
        let n: Option<Rlimit> = if new != 0 { Some(guest!(uaccess::read(new))) } else { None };
        if let Some(n) = &n
            && n.rlim_cur > n.rlim_max
        {
            return err(errno::EINVAL);
        }
        // Raising the hard limit takes CAP_SYS_RESOURCE (the other's limit
        // as fwe knows it: what was set for it, else the caller's own).
        if let Some(n) = &n
            && !privileged
        {
            let hard = match crate::procreg::pending_limit(target, res as u32) {
                Some((_, max)) => max,
                None => own_limit(res).map_or(resource::RLIM_INFINITY, |(_, max)| max),
            };
            if n.rlim_max > hard {
                return err(errno::EPERM);
            }
        }
        // A descriptor limit past what fwe leaves the guest (every fwe
        // process the same range): refused now, as Linux refuses one past
        // `nr_open`, rather than when the other takes it up.
        if let Some(n) = &n
            && res == resource::RLIMIT_NOFILE
            && n.rlim_max != resource::RLIM_INFINITY
            && n.rlim_max > crate::fdtable::guest_max() as u64
        {
            return err(errno::EPERM);
        }
        if old != 0 {
            let had = match crate::procreg::pending_limit(target, res as u32) {
                Some(l) => l,
                None => match own_limit(res) {
                    Ok(l) => l,
                    Err(e) => return err(e),
                },
            };
            guest!(uaccess::write(old, Rlimit { rlim_cur: had.0, rlim_max: had.1 }));
        }
        if let Some(n) = n
            && let Err(e) = crate::procreg::push_limit(target, res as u32, n.rlim_cur, n.rlim_max)
        {
            return err(e);
        }
        0
    }

    /// Take up the resource limits another process set for this one.
    pub(crate) fn take_pending_limits(&mut self) {
        for (res, soft, hard) in crate::procreg::take_limits() {
            let value = Rlimit { rlim_cur: soft, rlim_max: hard };
            if u64::from(res) == resource::RLIMIT_NOFILE {
                let _ = crate::fdtable::set_limit(soft, hard);
            } else if crate::rlimits::kept(u64::from(res)) {
                // The setter was allowed to (`prlimit_other`).
                let _ = crate::rlimits::set(u64::from(res), soft, hard, true);
            } else if let Some(hres) = host::rlimit_to_host(u64::from(res)) {
                let r = libc::rlimit {
                    rlim_cur: host::rlim_to_host(value.rlim_cur),
                    rlim_max: host::rlim_to_host(value.rlim_max),
                };
                // SAFETY: `r` is a valid in-parameter.
                unsafe { libc::setrlimit(hres as _, &r) };
            }
        }
    }

    fn sys_clock_gettime(&mut self, id: u64, tp: u64) -> i64 {
        if let Some(ns) = cpu_clock_ns(id) {
            let ns = match ns {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            let ts = Timespec {
                tv_sec: (ns / 1_000_000_000) as i64,
                tv_nsec: (ns % 1_000_000_000) as i64,
            };
            guest!(uaccess::write(tp, ts));
            return 0;
        }
        let Some(hid) = host::clock_to_host(id) else {
            return err(errno::EINVAL);
        };
        // The C library computes the time itself and writes it unchecked, so
        // read it into fwe's memory and copy it out.
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid out-parameter.
        if unsafe { libc::clock_gettime(hid, &mut ts) } != 0 {
            return last_error();
        }
        guest!(uaccess::write(tp, Timespec { tv_sec: ts.tv_sec, tv_nsec: ts.tv_nsec }));
        0
    }

    fn sys_clock_nanosleep(&mut self, id: u64, flags: u64, req: u64, rem: u64) -> i64 {
        // SAFETY: the guest passed valid request/remain pointers.
        unsafe { clock_nanosleep(id, flags, req, rem) }
    }

    fn sys_clock_getres(&mut self, id: u64, tp: u64) -> i64 {
        if let Some(ns) = cpu_clock_ns(id) {
            if let Err(e) = ns {
                return err(e);
            }
            if tp != 0 {
                // Linux's: a nanosecond for the scheduler's clock, a tick
                // (HZ 250) for the others.
                let res = if id & 3 == 2 { 1 } else { 4_000_000 };
                guest!(uaccess::write(tp, Timespec { tv_sec: 0, tv_nsec: res }));
            }
            return 0;
        }
        if host::clock_to_host(id).is_none() {
            return err(errno::EINVAL);
        }
        if tp == 0 {
            return 0;
        }
        // Linux's: a nanosecond for the high-resolution clocks, a tick (HZ
        // 250, as `/proc/config.gz` says) for the coarse ones, which read
        // the time as of the last tick. (The host's is a microsecond, which
        // a program that sizes its timers by it would take too short.)
        let coarse = matches!(id, clock::CLOCK_REALTIME_COARSE | clock::CLOCK_MONOTONIC_COARSE);
        let res = if coarse { 4_000_000 } else { 1 };
        guest!(uaccess::write(tp, Timespec { tv_sec: 0, tv_nsec: res }));
        0
    }

    fn sys_rt_sigaction(&mut self, sig: u64, act: u64, old: u64, size: u64) -> i64 {
        if size != signal::SIGSET_SIZE || sig == 0 || sig > signal::NSIG {
            return err(errno::EINVAL);
        }
        let slot = (sig - 1) as usize;
        if old != 0 {
            guest!(uaccess::write(old, self.sigactions[slot]));
        }
        if act != 0 {
            if sig == signal::SIGKILL || sig == signal::SIGSTOP {
                return err(errno::EINVAL);
            }
            self.sigactions[slot] = guest!(uaccess::read::<Sigaction>(act));
            self.sync_host_signal(sig);
        }
        0
    }

    fn sys_rt_sigprocmask(&mut self, how: u64, set: u64, old: u64, size: u64) -> i64 {
        if size != signal::SIGSET_SIZE {
            return err(errno::EINVAL);
        }
        let previous = thread::mask();
        if set != 0 {
            let s: u64 = guest!(uaccess::read(set));
            thread::set_mask(match how {
                signal::SIG_BLOCK => previous | s,
                signal::SIG_UNBLOCK => previous & !s,
                signal::SIG_SETMASK => s,
                _ => return err(errno::EINVAL),
            });
        }
        if old != 0 {
            guest!(uaccess::write(old, previous));
        }
        0
    }

    fn sys_sigaltstack(&mut self, ss: u64, old: u64) -> i64 {
        if old != 0 {
            guest!(uaccess::write(old, thread::altstack()));
        }
        if ss != 0 {
            let s: Stack = guest!(uaccess::read(ss));
            if s.ss_flags & !libc::SS_DISABLE != 0 {
                return err(errno::EINVAL);
            }
            if s.ss_flags & libc::SS_DISABLE == 0 && s.ss_size < signal::MINSIGSTKSZ {
                return err(errno::ENOMEM);
            }
            thread::set_altstack(s);
        }
        0
    }

    fn sys_signalfd4(&mut self, fd: u64, mask: u64, sizemask: u64, flags: u64) -> i64 {
        if sizemask < 8 {
            return err(errno::EINVAL);
        }
        let set = guest!(uaccess::read::<u64>(mask));
        let r = crate::signalfd::signalfd4(fd as i32, set, flags);
        // A watched signal must reach the backend even when its disposition
        // would let the host drop it.
        self.sync_all_host_signals();
        r
    }

    fn sys_getrandom(&mut self, buf: u64, len: u64) -> i64 {
        // Linux returns at most 32 MiB per call.
        let len = len.min(32 << 20) as usize;
        let mut out = vec![0u8; len];
        host::fill_random(&mut out);
        guest!(uaccess::write_from(buf, &out));
        len as i64
    }
}

/// `ppoll(fds, nfds, timeout)`; the caller applies the signal mask. Blocks, so
/// the backend runs it without the kernel lock through
/// [`crate::blocking_syscall`]; it touches no kernel state.
///
/// # Safety
/// `fds` must point to `nfds` guest `pollfd`s and `timeout`, when non-null, to
/// a guest `Timespec`.
/// `pselect6(nfds, readfds, writefds, exceptfds, timeout, _)`, by way of the
/// host's `poll`: each set bit below `nfds` becomes a `pollfd`, and the sets
/// are rewritten with what is ready (the signal mask is the caller's, see
/// [`crate::blocking_syscall`]). Linux's `fd_set` is a bitmap of 64-bit
/// words, as fwe reads it. The timeout is not updated with the time left,
/// which POSIX allows and glibc's `select` does not rely on.
///
/// # Safety
/// The set and timeout pointers are null or reference guest memory.
pub(crate) unsafe fn pselect6(nfds: u64, sets: [u64; 3], timeout: u64) -> i64 {
    // SAFETY: the caller's guarantee, passed on.
    with_remaining(timeout, || unsafe { pselect6_wait(nfds, sets, timeout) })
}

/// [`pselect6`]'s wait.
///
/// # Safety
/// As for [`pselect6`].
unsafe fn pselect6_wait(nfds: u64, sets: [u64; 3], timeout: u64) -> i64 {
    const FD_SETSIZE: u64 = 1024;
    if nfds > FD_SETSIZE {
        return err(errno::EINVAL);
    }
    let words = nfds.div_ceil(64) as usize;
    let mut bits = [[0u64; (FD_SETSIZE / 64) as usize]; 3];
    for (set, ptr) in bits.iter_mut().zip(sets) {
        if ptr != 0 {
            for (i, w) in set.iter_mut().take(words).enumerate() {
                *w = guest!(uaccess::read(ptr + 8 * i as u64));
            }
        }
    }
    let is_set = |set: &[u64; 16], fd: u64| set[(fd / 64) as usize] >> (fd % 64) & 1 == 1;
    // fwe's own descriptors are not open as far as the guest can tell.
    if (0..nfds)
        .any(|fd| bits.iter().any(|s| is_set(s, fd)) && !crate::fdtable::guest_visible(fd as i32))
    {
        return err(errno::EBADF);
    }
    let events = [libc::POLLIN, libc::POLLOUT, libc::POLLPRI];
    let mut fds: Vec<libc::pollfd> = (0..nfds)
        .filter_map(|fd| {
            let ev = (0..3).filter(|&k| is_set(&bits[k], fd)).fold(0, |e, k| e | events[k]);
            (ev != 0).then_some(libc::pollfd { fd: fd as i32, events: ev, revents: 0 })
        })
        .collect();
    let ms = if timeout == 0 {
        -1
    } else {
        let ts: Timespec = guest!(uaccess::read(timeout));
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return err(errno::EINVAL);
        }
        let ms = ts.tv_sec.saturating_mul(1000).saturating_add((ts.tv_nsec + 999_999) / 1_000_000);
        ms.min(i32::MAX as i64) as i32
    };
    // SAFETY: `fds` is a valid array of its length.
    let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    if r < 0 {
        return last_error();
    }
    if fds.iter().any(|p| p.revents & libc::POLLNVAL != 0) {
        return err(errno::EBADF);
    }
    // Which revents mark a descriptor ready for each set, as Linux counts.
    let ready = [
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        libc::POLLOUT | libc::POLLERR,
        libc::POLLPRI,
    ];
    let mut out = [[0u64; (FD_SETSIZE / 64) as usize]; 3];
    let mut count = 0;
    for p in &fds {
        let fd = p.fd as u64;
        for k in 0..3 {
            if p.events & events[k] != 0 && p.revents & ready[k] != 0 {
                out[k][(fd / 64) as usize] |= 1 << (fd % 64);
                count += 1;
            }
        }
    }
    for (set, ptr) in out.iter().zip(sets) {
        if ptr != 0 {
            for (i, w) in set.iter().take(words).enumerate() {
                guest!(uaccess::write(ptr + 8 * i as u64, *w));
            }
        }
    }
    count
}

pub(crate) unsafe fn ppoll(fds: u64, nfds: u64, timeout: u64) -> i64 {
    // SAFETY: the caller's guarantee, passed on.
    with_remaining(timeout, || unsafe { ppoll_wait(fds, nfds, timeout) })
}

/// [`ppoll`]'s wait.
///
/// # Safety
/// As for [`ppoll`].
unsafe fn ppoll_wait(fds: u64, nfds: u64, timeout: u64) -> i64 {
    const _: () = assert!(size_of::<Pollfd>() == size_of::<libc::pollfd>());
    let ms = if timeout == 0 {
        -1
    } else {
        let ts: Timespec = guest!(uaccess::read(timeout));
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return err(errno::EINVAL);
        }
        let ms = ts.tv_sec.saturating_mul(1000).saturating_add((ts.tv_nsec + 999_999) / 1_000_000);
        ms.min(i32::MAX as i64) as i32
    };
    // The read ends of named FIFOs it watches, whose writers' end the
    // host does not report ([`crate::fifo`]): waited for in slices,
    // looked at between them.
    let fifos: Vec<usize> = if nfds as usize <= 4096 {
        (0..nfds as usize)
            .filter(|&i| {
                uaccess::read::<Pollfd>(fds + (i * size_of::<Pollfd>()) as u64)
                    .is_ok_and(|p| p.events & libc::POLLIN != 0 && crate::fifo::is_reader(p.fd))
            })
            .collect()
    } else {
        Vec::new()
    };
    if fifos.is_empty() {
        // SAFETY: `struct pollfd` and the POLL* bits match the host's; the
        // host validates the guest array.
        return ret(unsafe { libc::poll(fds as *mut libc::pollfd, nfds as libc::nfds_t, ms) });
    }
    let deadline =
        (ms >= 0).then(|| std::time::Instant::now() + std::time::Duration::from_millis(ms as u64));
    loop {
        let slice = match deadline {
            None => crate::fifo::SLICE_MS,
            Some(d) => {
                let left =
                    d.saturating_duration_since(std::time::Instant::now()).as_millis() as i32;
                left.min(crate::fifo::SLICE_MS)
            }
        };
        // SAFETY: as above.
        let n = unsafe { libc::poll(fds as *mut libc::pollfd, nfds as libc::nfds_t, 0) };
        if n < 0 {
            return last_error();
        }
        let mut ready = n as i64;
        for &i in &fifos {
            let at = fds + (i * size_of::<Pollfd>()) as u64;
            let mut p: Pollfd = guest!(uaccess::read(at));
            let extra = match crate::fifo::probe(p.fd) {
                crate::fifo::Probe::HungUp => libc::POLLHUP,
                _ => 0,
            };
            if extra != 0 {
                if p.revents == 0 {
                    ready += 1;
                }
                p.revents |= extra;
                guest!(uaccess::write(at, p));
            }
        }
        if ready > 0 || deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return ready;
        }
        // A signal that came between slices interrupts the wait.
        if crate::thread::deliverable() != 0 {
            return err(errno::EINTR);
        }
        // SAFETY: as above.
        let n = unsafe { libc::poll(fds as *mut libc::pollfd, nfds as libc::nfds_t, slice) };
        if n != 0 {
            return if n < 0 { last_error() } else { n as i64 };
        }
    }
}

/// The calling process's own limit of Linux resource `res` (soft, hard):
/// the descriptor limit fwe keeps, the host's, or for a limit the host does
/// not have, Linux's default.
impl<P: Platform> Kernel<P> {
    /// The host processes `getpriority`/`setpriority`'s `which` and `who`
    /// name, among those the caller sees: a process, a process group or a
    /// user's processes (`who` 0: the caller's own).
    fn prio_targets(&self, which: u64, who: i32) -> Result<Vec<i32>, i32> {
        use fwe_abi::prio;
        // SAFETY: plain host calls.
        let (me, my_group) = unsafe { (libc::getpid(), libc::getpgrp()) };
        let seen = || {
            crate::procpid::listed()
                .into_iter()
                .filter_map(crate::pidns::to_host)
                .collect::<Vec<_>>()
        };
        Ok(match which {
            prio::PROCESS if who == 0 => vec![me],
            prio::PROCESS => crate::pidns::to_host(who)
                .filter(|&h| h == me || crate::procreg::start_time(h).is_some())
                .into_iter()
                .collect(),
            prio::PGRP => {
                let group = if who == 0 {
                    my_group
                } else {
                    match crate::pidns::to_host(who) {
                        Some(g) => g,
                        None => return Ok(Vec::new()),
                    }
                };
                // SAFETY: plain host call.
                seen().into_iter().filter(|&h| unsafe { libc::getpgid(h) } == group).collect()
            }
            prio::USER => {
                let uid = if who == 0 { self.creds.uid } else { who as u32 };
                let own = |h: i32| if h == me { self.creds.uid } else { crate::procreg::ids(h)[0] };
                seen().into_iter().filter(|&h| own(h) == uid).collect()
            }
            _ => return Err(errno::EINVAL),
        })
    }

    /// `getpriority(which, who)`: the highest priority (least nice value)
    /// of the processes named, as the system call returns it (20 less the
    /// nice value, 1 to 40; the C library turns it back).
    fn sys_getpriority(&mut self, which: u64, who: i32) -> i64 {
        match self.prio_targets(which, who) {
            Ok(t) => t
                .iter()
                .map(|&h| crate::procreg::nice(h))
                .min()
                .map_or(err(errno::ESRCH), |n| (20 - n) as i64),
            Err(e) => err(e),
        }
    }

    /// `setpriority(which, who, nice)`: the processes named take nice
    /// value `nice` (clamped to -20..19), as Linux allows it: another
    /// user's needs `CAP_SYS_NICE` (`EPERM`), and so does lowering one's
    /// own beyond what `RLIMIT_NICE` lets (`EACCES`). As on Linux, a
    /// failure stands whatever the other processes take.
    fn sys_setpriority(&mut self, which: u64, who: i32, nice: i32) -> i64 {
        let targets = match self.prio_targets(which, who) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        let nice = nice.clamp(-20, 19);
        let privileged = self.creds.has(crate::caps::CAP_SYS_NICE);
        // `RLIMIT_NICE` bounds the least nice value as 20 less it.
        let floor =
            20 - own_limit(resource::RLIMIT_NICE).map_or(0, |(soft, _)| soft.min(40) as i32);
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let mut result = err(errno::ESRCH);
        for h in targets {
            let ids = if h == me {
                [self.creds.uid, self.creds.euid]
            } else {
                let i = crate::procreg::ids(h);
                [i[0], i[1]]
            };
            let r = if !privileged && !ids.contains(&self.creds.euid) {
                err(errno::EPERM)
            } else if nice < crate::procreg::nice(h) && !privileged && nice < floor {
                err(errno::EACCES)
            } else if h != me && crate::procreg::read(h).is_none() {
                // A process fwe did not start: as far as the host lets.
                // SAFETY: plain host call.
                ret(unsafe { libc::setpriority(libc::PRIO_PROCESS, h as libc::id_t, nice) })
            } else if crate::procreg::set_nice(h, nice).is_err() {
                err(errno::ESRCH)
            } else {
                0
            };
            if r != 0 || result == err(errno::ESRCH) {
                result = r;
            }
        }
        result
    }
}

/// For a clock id Linux's CPU-time clocks encode (negative: a pid or tid,
/// complemented, above whether it is a thread's and which time), that
/// time in nanoseconds: user and system time (`CPUCLOCK_PROF`, and
/// `CPUCLOCK_SCHED`, the time run), or user time alone (`CPUCLOCK_VIRT`).
/// A thread's clock is of a thread of this process; 0 is the caller (or
/// its process). `None` for any other clock id.
pub(crate) fn cpu_clock_ns(id: u64) -> Option<Result<u64, i32>> {
    let id = id as i32;
    if id >= 0 {
        return None;
    }
    let which = id & 3;
    if which == 3 {
        // A clock of a descriptor (a PTP device): none here.
        return Some(Err(errno::EINVAL));
    }
    let thread = id & 4 != 0;
    let who = !(id >> 3);
    let me = thread::tgid();
    let sample = if thread {
        let tid = if who == 0 { thread::tid() } else { who };
        thread::host_state(tid).map(|(user, system, _)| (user, system))
    } else if who == 0 || who == me {
        // SAFETY: getpid cannot fail.
        crate::procpid::cpu_ns(unsafe { libc::getpid() })
    } else {
        crate::pidns::to_host(who).and_then(crate::procpid::cpu_ns)
    };
    Some(match sample {
        Some((user, _)) if which == 1 => Ok(user),
        Some((user, system)) => Ok(user + system),
        None => Err(errno::EINVAL),
    })
}

impl<P: Platform> Kernel<P> {
    /// `setitimer(which, new, old)`: the host's interval timer, which
    /// sends the host signal of Linux's (`SIGALRM`, `SIGVTALRM`, `SIGPROF`).
    fn sys_setitimer(&mut self, which: u64, new: u64, old: u64) -> i64 {
        // As Linux reads it: no new value is a zero one.
        let value: fwe_abi::Itimerval =
            if new == 0 { Default::default() } else { guest!(uaccess::read(new)) };
        match itimer::set(which, value) {
            Ok(previous) => {
                if old != 0 {
                    guest!(uaccess::write(old, previous));
                }
                0
            }
            Err(e) => err(e),
        }
    }
}

/// The interval timers. The host keeps them, but takes no value past
/// 100,000,000 seconds (Linux takes any): a longer one is given the
/// host's longest, and what was asked is kept, so the time left reads as
/// on Linux (`alarm(INT_MAX)` then `alarm(0)`).
mod itimer {
    use fwe_abi::{Itimerval, Timeval, errno};
    use std::sync::Mutex;

    /// The longest value the host takes, in seconds.
    const HOST_MAX: i64 = 100_000_000;

    /// For each timer given less than asked: (asked, given).
    static CLAMPED: Mutex<[Option<(Itimerval, Itimerval)>; 3]> = Mutex::new([None; 3]);

    fn valid(t: &Timeval) -> bool {
        t.tv_sec >= 0 && (0..1_000_000).contains(&t.tv_usec)
    }

    fn clamp(t: Timeval) -> Timeval {
        if t.tv_sec > HOST_MAX { Timeval { tv_sec: HOST_MAX, tv_usec: 0 } } else { t }
    }

    fn micros(t: &Timeval) -> i128 {
        t.tv_sec as i128 * 1_000_000 + t.tv_usec as i128
    }

    fn from_micros(us: i128) -> Timeval {
        let us = us.max(0);
        Timeval { tv_sec: (us / 1_000_000) as i64, tv_usec: (us % 1_000_000) as i64 }
    }

    fn to_host(v: &Itimerval) -> libc::itimerval {
        let tv = |t: Timeval| libc::timeval {
            tv_sec: t.tv_sec,
            tv_usec: t.tv_usec as libc::suseconds_t,
        };
        libc::itimerval { it_interval: tv(v.it_interval), it_value: tv(v.it_value) }
    }

    // `suseconds_t` is 32 bits on macOS, 64 on Linux.
    #[allow(clippy::unnecessary_cast)]
    fn from_host(v: &libc::itimerval) -> Itimerval {
        let tv = |t: libc::timeval| Timeval { tv_sec: t.tv_sec, tv_usec: t.tv_usec as i64 };
        Itimerval { it_interval: tv(v.it_interval), it_value: tv(v.it_value) }
    }

    /// What timer `which` has left, as asked: the host's, or for one the
    /// host was given less, what was asked less what has passed.
    fn as_asked(
        which: usize,
        host: Itimerval,
        clamped: &mut [Option<(Itimerval, Itimerval)>; 3],
    ) -> Itimerval {
        match clamped[which] {
            Some((asked, given)) if micros(&host.it_value) > 0 => {
                let passed = micros(&given.it_value) - micros(&host.it_value);
                Itimerval {
                    it_interval: asked.it_interval,
                    it_value: from_micros(micros(&asked.it_value) - passed),
                }
            }
            _ => {
                clamped[which] = None;
                host
            }
        }
    }

    /// `getitimer(which)`.
    pub fn get(which: u64) -> Result<Itimerval, i32> {
        if which > 2 {
            return Err(errno::EINVAL);
        }
        // SAFETY: a valid out-parameter.
        let mut h: libc::itimerval = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::getitimer(which as i32, &mut h) } != 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let mut clamped = CLAMPED.lock().unwrap_or_else(|e| e.into_inner());
        Ok(as_asked(which as usize, from_host(&h), &mut clamped))
    }

    /// `setitimer(which, value)`: the timer's previous value.
    pub fn set(which: u64, value: Itimerval) -> Result<Itimerval, i32> {
        if which > 2 || !valid(&value.it_value) || !valid(&value.it_interval) {
            return Err(errno::EINVAL);
        }
        let given =
            Itimerval { it_interval: clamp(value.it_interval), it_value: clamp(value.it_value) };
        // SAFETY: zeroed bytes are a valid `itimerval`, which the host fills.
        let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
        let mut clamped = CLAMPED.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: valid in- and out-parameters.
        if unsafe { libc::setitimer(which as i32, &to_host(&given), &mut old) } != 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let previous = as_asked(which as usize, from_host(&old), &mut clamped);
        clamped[which as usize] = (given != value).then_some((value, given));
        Ok(previous)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A real timer longer than the host takes reads back as asked,
        /// less what has passed; one that fits is the host's own.
        #[test]
        fn a_timer_longer_than_the_host_takes_reads_back_as_asked() {
            let long = Itimerval {
                it_interval: Timeval::default(),
                it_value: Timeval { tv_sec: i32::MAX as i64, tv_usec: 0 },
            };
            set(0, long).unwrap();
            let left = get(0).unwrap();
            assert!(left.it_value.tv_sec > i32::MAX as i64 - 5, "{left:?}");
            let previous = set(0, Itimerval::default()).unwrap();
            assert!(previous.it_value.tv_sec > i32::MAX as i64 - 5, "{previous:?}");
            assert_eq!(get(0).unwrap(), Itimerval::default());
            assert_eq!(set(3, long), Err(errno::EINVAL));
            let bad = Itimerval { it_interval: Timeval { tv_sec: 0, tv_usec: 1_000_000 }, ..long };
            assert_eq!(set(0, bad), Err(errno::EINVAL));
        }
    }
}

/// The caller's soft limit of resource `res`.
pub(crate) fn own_limit_of(res: u64) -> u64 {
    own_limit(res).map_or(resource::RLIM_INFINITY, |(soft, _)| soft)
}

fn own_limit(res: u64) -> Result<(u64, u64), i32> {
    if res == resource::RLIMIT_NOFILE {
        // Virtual: the host's limit also covers fwe's own descriptors.
        return Ok(crate::fdtable::limit());
    }
    if crate::rlimits::kept(res) {
        return Ok(crate::rlimits::get(res));
    }
    let Some(hres) = host::rlimit_to_host(res) else {
        return Err(errno::EINVAL);
    };
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `r` is a valid out-parameter.
    if unsafe { libc::getrlimit(hres as _, &mut r) } != 0 {
        return Err(host::errno_to_linux(host::last_errno()));
    }
    Ok((host::rlim_to_linux(r.rlim_cur), host::rlim_to_linux(r.rlim_max)))
}

/// `u32` words as their native-endian bytes.
fn bytemuck_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

/// `PR_SET_NO_NEW_PRIVS`: fwe grants no privileges an exec could raise, so
/// it only has to be remembered (and shown), as it is kept across `execve`.
pub(crate) static NO_NEW_PRIVS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The process's personality (`personality`), kept across `fork` and
/// `execve` as Linux keeps a task's. Linux keeps one per thread; fwe one
/// per process, which a program setting it before an `execve` (`setarch`)
/// cannot tell apart.
pub(crate) static PERSONALITY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Personality flags fwe acts on: `select`'s timeout left as given, and
/// `uname` reporting a 2.6 release. The others (address-space layout,
/// `READ_IMPLIES_EXEC`) are kept and reported only.
const STICKY_TIMEOUTS: u32 = 0x400_0000;
const UNAME26: u32 = 0x2_0000;
/// `PER_LINUX32`, which needs 32-bit execution, which the host lacks.
const PER_LINUX32: u32 = 0x0008;

/// `personality(persona)`: the old personality, the new one set unless
/// `persona` is `0xffffffff`.
fn personality(persona: u64) -> i64 {
    use std::sync::atomic::Ordering::SeqCst;
    let persona = persona as u32;
    let old = PERSONALITY.load(SeqCst);
    if persona != 0xffff_ffff {
        if persona & 0xff == PER_LINUX32 {
            return err(errno::EINVAL);
        }
        PERSONALITY.store(persona, SeqCst);
    }
    old as i64
}

/// The kernel release `uname` reports: as a 2.6 one (`2.6.(60 + minor)`
/// and the rest) with the `UNAME26` personality, for programs that cannot
/// parse a later one.
fn release() -> String {
    if PERSONALITY.load(std::sync::atomic::Ordering::SeqCst) & UNAME26 == 0 {
        return RELEASE.to_string();
    }
    // As Linux's `override_release`: the version's numbers (up to its
    // third dot) replaced, what follows them kept.
    let mut dots = 0;
    let end = RELEASE
        .char_indices()
        .find(|&(_, c)| {
            if c == '.' {
                dots += 1;
            }
            dots >= 3 || !(c.is_ascii_digit() || c == '.')
        })
        .map_or(RELEASE.len(), |(i, _)| i);
    let minor: u32 = RELEASE.split('.').nth(1).and_then(|m| m.parse().ok()).unwrap_or(0);
    format!("2.6.{}{}", 60 + minor, &RELEASE[end..])
}

/// The remaining time of a `pselect6` or `ppoll` wait, run by `f`, whose
/// timeout is at guest `timeout`, written back there as Linux does (not
/// with the `STICKY_TIMEOUTS` personality, nor for no timeout or a zero
/// one; a failed write is not the call's).
fn with_remaining(timeout: u64, f: impl FnOnce() -> i64) -> i64 {
    let start = std::time::Instant::now();
    let given = if timeout == 0 { None } else { uaccess::read::<Timespec>(timeout).ok() };
    let r = f();
    let sticky = PERSONALITY.load(std::sync::atomic::Ordering::SeqCst) & STICKY_TIMEOUTS != 0;
    if let Some(ts) = given.filter(|t| (t.tv_sec, t.tv_nsec) != (0, 0))
        && !sticky
        && r != err(errno::EINVAL)
        && ts.tv_sec >= 0
        && (0..1_000_000_000).contains(&ts.tv_nsec)
    {
        let total = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        let left = total.saturating_sub(start.elapsed());
        let left = Timespec { tv_sec: left.as_secs() as i64, tv_nsec: left.subsec_nanos() as i64 };
        let _ = uaccess::write(timeout, left);
    }
    r
}

/// The affinity `sched_setaffinity` set for this process, if it did.
static AFFINITY: std::sync::Mutex<Option<Vec<u64>>> = std::sync::Mutex::new(None);

/// The online CPUs, as a mask of 64-bit words.
fn online_cpus() -> Vec<u64> {
    // SAFETY: plain host call.
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as u64;
    (0..cpus.div_ceil(64))
        .map(|word| {
            let bits = (cpus - word * 64).min(64);
            if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }
        })
        .collect()
}

/// An id the process holds (the initial namespace's) as it sees it.
fn uid_out(id: u32, gid: bool) -> i64 {
    i64::from(crate::userns::to_ns(id, gid))
}

/// An id argument (in the process's user namespace) as the initial
/// namespace's, `-1` (leave alone) kept: `EINVAL` for one with no mapping.
fn uid_in(arg: u64, gid: bool) -> Result<u32, i32> {
    let id = arg as u32;
    if id == u32::MAX {
        return Ok(id);
    }
    crate::userns::from_ns(id, gid).ok_or(errno::EINVAL)
}

/// Whether `fd` is open on a directory.
fn is_dir_fd(fd: i32) -> bool {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Tracer};

    struct TestPlatform {
        exec: Vec<(u64, u64)>,
    }

    impl Platform for TestPlatform {
        fn prepare_exec(
            &mut self,
            addr: u64,
            len: u64,
            _known: Option<&[(u64, u64)]>,
        ) -> Result<(), crate::PrepareFailed> {
            self.exec.push((addr, len));
            Ok(())
        }
        fn exit(&mut self, code: i32) -> ! {
            panic!("exit({code})")
        }
        fn exit_thread(&mut self, code: i32) -> ! {
            panic!("exit_thread({code})")
        }
        fn kill_self(&mut self, sig: libc::c_int) -> ! {
            panic!("killed by {sig}")
        }
    }

    fn kernel() -> Kernel<TestPlatform> {
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        Kernel::new(
            TestPlatform { exec: vec![] },
            page,
            Brk { start: 0, current: 0, limit: 0 },
            None,
            Tracer::default(),
        )
    }

    /// The credentials survive an `execve` that re-executes fwe, with the
    /// saved IDs becoming the effective ones, and a bad record is refused.
    #[test]
    fn exec_state_carries_credentials() {
        let mut k = kernel();
        // Groups first: once the user IDs drop root, they cannot change.
        assert_eq!(k.creds.setgroups(vec![5, 6]), 0);
        assert_eq!(k.creds.setresgid(2000, 2001, 2002), 0);
        assert_eq!(k.creds.setresuid(1000, 1001, 1002), 0);
        let state = k.exec_state();
        let mut new = kernel();
        new.restore_exec_state(&state).unwrap();
        assert_eq!(new.creds.resuid(), (1000, 1001, 1001));
        assert_eq!(new.creds.resgid(), (2000, 2001, 2001));
        assert_eq!(new.creds.groups(), &[5, 6]);
        let mut bad = kernel();
        assert!(bad.restore_exec_state(&state[..state.len() - 1]).is_err());
        assert!(bad.restore_exec_state(b"garbage!").is_err());
        assert_eq!(bad.creds.resuid(), kernel().creds.resuid());
    }

    #[test]
    fn unknown_syscalls_fail_with_enosys() {
        assert_eq!(kernel().syscall(4000, [0; 6]), err(errno::ENOSYS));
    }

    #[test]
    fn write_to_bad_fd_translates_errno() {
        let b = b"x";
        assert_eq!(
            kernel().syscall(nr::WRITE, [9999, b.as_ptr() as u64, 1, 0, 0, 0]),
            err(errno::EBADF)
        );
    }

    #[test]
    fn uname_reports_linux() {
        // SAFETY: zeroed bytes are a valid `Utsname`.
        let mut u: Utsname = unsafe { std::mem::zeroed() };
        assert_eq!(kernel().syscall(nr::UNAME, [&mut u as *mut _ as u64, 0, 0, 0, 0, 0]), 0);
        assert!(u.sysname.starts_with(b"Linux\0"));
        assert!(u.machine.starts_with(b"aarch64\0"));
    }

    /// Terminal requests on something that is not a terminal fail with
    /// `ENOTTY`, as on Linux, whatever the host says.
    #[test]
    fn terminal_requests_on_dev_null_are_enotty() {
        use std::os::fd::AsRawFd;
        let null = std::fs::File::open("/dev/null").unwrap();
        let fd = null.as_raw_fd() as u64;
        let mut buf = [0u8; 64];
        let mut k = kernel();
        for req in [ioctl::TCGETS, ioctl::TIOCGWINSZ] {
            let r = k.syscall(nr::IOCTL, [fd, req, buf.as_mut_ptr() as u64, 0, 0, 0]);
            assert_eq!(r, err(errno::ENOTTY), "ioctl {req:#x}");
        }
    }

    /// An ioctl request is 32 bits: one the C library sign-extended (an
    /// `int` with its top bit set) is the same request.
    #[test]
    fn ioctl_requests_are_32_bits() {
        use std::os::fd::AsRawFd;
        let null = std::fs::File::open("/dev/null").unwrap();
        let fd = null.as_raw_fd() as u64;
        let mut n = 0u32;
        let mut k = kernel();
        let extended = ioctl::TIOCGPTN as u32 as i32 as i64 as u64;
        assert_ne!(extended, ioctl::TIOCGPTN);
        // Not a pseudo-terminal master: the request is recognised, and fails
        // as `TIOCGPTN` does there.
        let r = k.syscall(nr::IOCTL, [fd, extended, &mut n as *mut u32 as u64, 0, 0, 0]);
        assert_eq!(
            r,
            k.syscall(nr::IOCTL, [fd, ioctl::TIOCGPTN, &mut n as *mut u32 as u64, 0, 0, 0])
        );
    }

    #[cfg(target_os = "macos")]
    fn pipe() -> [i32; 2] {
        let mut p = [0i32; 2];
        // SAFETY: a valid out-parameter.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        p
    }

    #[cfg(target_os = "macos")]
    fn close_all(fds: &[i32]) {
        for &fd in fds {
            // SAFETY: closing descriptors the test made.
            unsafe { libc::close(fd) };
        }
    }

    /// `splice` moves a file's bytes from an offset into a pipe and on
    /// into another file, leaving the file's own position; it refuses two
    /// non-pipes, an offset for a pipe, an empty pipe asked not to wait,
    /// and both ends of one pipe. (A host pipe's contents are as macOS
    /// reports them.)
    #[cfg(target_os = "macos")]
    #[test]
    fn splice_moves_through_pipes() {
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsRawFd;
        let mut src = tempfile_in_tmp();
        src.write_all(b"0123456789").unwrap();
        let mut dst = tempfile_in_tmp();
        let [r, w] = pipe();
        let mut k = kernel();
        let (s, d) = (src.as_raw_fd() as u64, dst.as_raw_fd() as u64);
        let mut off: i64 = 2;
        let n = k.syscall(nr::SPLICE, [s, &mut off as *mut i64 as u64, w as u64, 0, 5, 0]);
        assert_eq!((n, off), (5, 7));
        assert_eq!(src.stream_position().unwrap(), 10, "its own position is left");
        assert_eq!(k.syscall(nr::SPLICE, [r as u64, 0, d, 0, 100, 0]), 5);
        let mut got = String::new();
        dst.rewind().unwrap();
        dst.read_to_string(&mut got).unwrap();
        assert_eq!(got, "23456");
        // Neither end a pipe; an offset of a pipe; nothing in it, not waiting.
        assert_eq!(k.syscall(nr::SPLICE, [s, 0, d, 0, 1, 0]), err(errno::EINVAL));
        assert_eq!(
            k.syscall(nr::SPLICE, [r as u64, &mut off as *mut i64 as u64, d, 0, 1, 0]),
            err(errno::ESPIPE)
        );
        assert_eq!(k.syscall(nr::SPLICE, [r as u64, 0, d, 0, 1, 2]), err(errno::EAGAIN));
        assert_eq!(k.syscall(nr::SPLICE, [r as u64, 0, w as u64, 0, 1, 0]), err(errno::EINVAL));
        close_all(&[r, w]);
    }

    /// `tee` copies a pipe's bytes into another and leaves them; `vmsplice`
    /// fills a pipe from memory and refuses a full one asked not to wait.
    #[cfg(target_os = "macos")]
    #[test]
    fn tee_and_vmsplice() {
        let ([r1, w1], [r2, w2]) = (pipe(), pipe());
        let mut k = kernel();
        let data = *b"hello";
        let iov = [data.as_ptr() as u64, data.len() as u64];
        assert_eq!(k.syscall(nr::VMSPLICE, [w1 as u64, iov.as_ptr() as u64, 1, 0, 0, 0]), 5);
        assert_eq!(k.syscall(nr::TEE, [r1 as u64, w2 as u64, 3, 0, 0, 0]), 3);
        let mut buf = [0u8; 8];
        // SAFETY: valid buffers of their lengths.
        let (a, b) = unsafe {
            (
                libc::read(r1, buf.as_mut_ptr().cast(), 8),
                libc::read(r2, buf[5..].as_mut_ptr().cast(), 3),
            )
        };
        assert_eq!((a, b, &buf), (5, 3, b"hellohel"));
        // A pipe filled to its capacity takes nothing more without waiting.
        let big = vec![0u8; 65_536];
        let iov = [big.as_ptr() as u64, big.len() as u64];
        assert_eq!(k.syscall(nr::VMSPLICE, [w1 as u64, iov.as_ptr() as u64, 1, 0, 0, 0]), 65_536);
        assert_eq!(
            k.syscall(nr::VMSPLICE, [w1 as u64, iov.as_ptr() as u64, 1, 2, 0, 0]),
            err(errno::EAGAIN)
        );
        // Both ends of one pipe.
        assert_eq!(k.syscall(nr::TEE, [r1 as u64, w1 as u64, 1, 0, 0, 0]), err(errno::EINVAL));
        close_all(&[r1, w1, r2, w2]);
    }

    /// `FIOASYNC` turns `O_ASYNC` on and off, as on any Linux descriptor.
    #[test]
    fn fioasync_sets_o_async() {
        let mut fds = [0i32; 2];
        // SAFETY: a valid out-parameter.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let fd = fds[0] as u64;
        let mut k = kernel();
        for on in [1i32, 0] {
            let r = k.syscall(nr::IOCTL, [fd, ioctl::FIOASYNC, &on as *const i32 as u64, 0, 0, 0]);
            assert_eq!(r, 0);
            let fl = k.syscall(nr::FCNTL, [fd, fcntl::F_GETFL, 0, 0, 0, 0]);
            assert_eq!(fl as u64 & fcntl::O_ASYNC != 0, on != 0);
        }
        // SAFETY: closing the pipe just made.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// `fadvise64` checks its descriptor and advice as Linux does.
    #[test]
    fn fadvise_checks_descriptor_and_advice() {
        use fwe_abi::fadvise::*;
        use std::os::fd::AsRawFd;
        let file = tempfile_in_tmp();
        let fd = file.as_raw_fd() as u64;
        let mut k = kernel();
        let call = |k: &mut Kernel<TestPlatform>, fd: u64, len: u64, advice: u64| {
            k.syscall(nr::FADVISE64, [fd, 0, len, advice, 0, 0])
        };
        for advice in
            [POSIX_FADV_NORMAL, POSIX_FADV_WILLNEED, POSIX_FADV_DONTNEED, POSIX_FADV_NOREUSE]
        {
            assert_eq!(call(&mut k, fd, 0, advice), 0, "advice {advice}");
        }
        assert_eq!(call(&mut k, fd, 0, 6), err(errno::EINVAL));
        assert_eq!(call(&mut k, fd, -1i64 as u64, POSIX_FADV_NORMAL), err(errno::EINVAL));
        assert_eq!(call(&mut k, 9999, 0, POSIX_FADV_NORMAL), err(errno::EBADF));
        let mut p = [0i32; 2];
        // SAFETY: a valid out-parameter.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        assert_eq!(call(&mut k, p[0] as u64, 0, POSIX_FADV_NORMAL), err(errno::ESPIPE));
        // SAFETY: closing the pipe made above.
        unsafe {
            libc::close(p[0]);
            libc::close(p[1]);
        }
    }

    /// `POSIX_FADV_DONTNEED` drops a file's pages from the host's cache,
    /// after writing back what was written to it.
    #[cfg(target_os = "macos")]
    #[test]
    fn fadvise_dontneed_drops_the_cache() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        let file = tempfile_in_tmp();
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = 8 * page;
        file.write_all_at(&vec![b'a'; len], 0).unwrap();
        file.write_all_at(b"kept", 100).unwrap();
        let resident = || {
            // SAFETY: a fresh read-only shared mapping of the file.
            let m = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(m, libc::MAP_FAILED);
            let mut v = vec![0 as libc::c_char; 8];
            // SAFETY: one byte for each page of the mapping.
            unsafe { libc::mincore(m, len, v.as_mut_ptr()) };
            // SAFETY: unmapping the mapping made above.
            unsafe { libc::munmap(m, len) };
            v.iter().filter(|&&b| b & 1 != 0).count()
        };
        assert!(resident() > 0);
        let fd = file.as_raw_fd() as u64;
        let dontneed = fwe_abi::fadvise::POSIX_FADV_DONTNEED;
        assert_eq!(kernel().syscall(nr::FADVISE64, [fd, 0, 0, dontneed, 0, 0]), 0);
        assert_eq!(resident(), 0);
        let mut b = [0u8; 4];
        file.read_exact_at(&mut b, 100).unwrap();
        assert_eq!(&b, b"kept");
    }

    fn tempfile_in_tmp() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("fwe-fadvise-{}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let _ = std::fs::remove_file(&path);
        f
    }

    /// `mincore` reports a touched page as in memory, and refuses an
    /// unaligned start and an unmapped range. (A bad vector's `EFAULT`
    /// needs a backend's fault handling: LTP's `mincore01` checks it.)
    #[test]
    fn mincore_reports_residency() {
        let mut k = kernel();
        let page = k.page_size;
        // SAFETY: a fresh anonymous mapping for the test.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let p = p as u64;
        // SAFETY: writing inside the mapping.
        unsafe { (p as *mut u8).write(1) };
        let mut vec = [0xffu8; 2];
        let v = vec.as_mut_ptr() as u64;
        assert_eq!(k.syscall(nr::MINCORE, [p, 2 * page, v, 0, 0, 0]), 0);
        assert_eq!(vec[0] & 1, 1);
        assert_eq!(vec[0] & !1, 0);
        assert_eq!(k.syscall(nr::MINCORE, [p + 1, page, v, 0, 0, 0]), err(errno::EINVAL));
        // SAFETY: unmapping the second page of the test's mapping.
        unsafe { libc::munmap((p + page) as *mut libc::c_void, page as usize) };
        let r = k.syscall(nr::MINCORE, [p, 2 * page, v, 0, 0, 0]);
        // Unless another test's thread has mapped the freed page since.
        if !crate::mm::mapped(p + page, page) {
            assert_eq!(r, err(errno::ENOMEM));
        }
        // SAFETY: unmapping the rest.
        unsafe { libc::munmap(p as *mut libc::c_void, page as usize) };
    }

    /// `sched_getaffinity` names the caller (0), the process, or any of its
    /// threads by id — glibc's `pthread_getattr_np` asks with a thread's own
    /// — and nothing else.
    #[test]
    fn affinity_of_a_thread_of_the_process() {
        const TID: i32 = 900_001; // high enough that no test uses it
        let pending = crate::thread::register(TID);
        let mut mask = [0u64; 16];
        let p = mask.as_mut_ptr() as u64;
        let mut k = kernel();
        let size = k.syscall(nr::SCHED_GETAFFINITY, [TID as u64, 128, p, 0, 0, 0]);
        assert!(size > 0 && mask[0] & 1 == 1, "{size}");
        crate::thread::unregister(&pending);
        assert_eq!(
            k.syscall(nr::SCHED_GETAFFINITY, [TID as u64, 128, p, 0, 0, 0]),
            err(errno::ESRCH)
        );
    }

    /// `pselect6` through the host's `poll`: a pipe's write end is ready, its
    /// read end becomes ready once a byte is written, and the sets come back
    /// holding only what is ready.
    #[test]
    fn pselect6_reports_ready_descriptors() {
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0] as u64, fds[1] as u64);
        let nfds = rd.max(wr) + 1;
        let bit = |fd: u64| -> [u64; 16] {
            let mut s = [0u64; 16];
            s[(fd / 64) as usize] |= 1 << (fd % 64);
            s
        };
        let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
        let t = &zero as *const _ as u64;
        let (mut r, mut w) = (bit(rd), bit(wr));
        let sets = [r.as_mut_ptr() as u64, w.as_mut_ptr() as u64, 0];
        // SAFETY: valid sets and timeout.
        assert_eq!(unsafe { pselect6(nfds, sets, t) }, 1);
        assert_eq!((r, w), ([0; 16], bit(wr)));
        // SAFETY: writing one byte.
        assert_eq!(unsafe { libc::write(wr as i32, b"x".as_ptr().cast(), 1) }, 1);
        r = bit(rd);
        // SAFETY: valid set and timeout.
        assert_eq!(unsafe { pselect6(nfds, [r.as_mut_ptr() as u64, 0, 0], t) }, 1);
        assert_eq!(r, bit(rd));
        // SAFETY: closing the pipe.
        unsafe {
            libc::close(rd as i32);
            libc::close(wr as i32);
        }
    }

    #[test]
    fn fstatfs_reports_the_filesystem() {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(std::env::temp_dir()).unwrap();
        let mut st = fwe_abi::Statfs::default();
        let p = &mut st as *mut _ as u64;
        assert_eq!(kernel().syscall(nr::FSTATFS, [f.as_raw_fd() as u64, p, 0, 0, 0, 0]), 0);
        assert!(st.f_bsize > 0 && st.f_blocks > 0 && st.f_namelen > 0, "{st:?}");
        assert_eq!(kernel().syscall(nr::FSTATFS, [9999, p, 0, 0, 0, 0]), err(errno::EBADF));
    }

    #[test]
    fn msync_syncs_a_mapping() {
        use fwe_abi::statfs::{MS_ASYNC, MS_SYNC};
        let mut k = kernel();
        let len = k.page_size;
        // SAFETY: a fresh anonymous mapping, unmapped below.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        } as u64;
        assert_eq!(k.syscall(nr::MSYNC, [p, len, MS_SYNC, 0, 0, 0]), 0);
        assert_eq!(k.syscall(nr::MSYNC, [p, len, MS_SYNC | MS_ASYNC, 0, 0, 0]), err(errno::EINVAL));
        assert_eq!(k.syscall(nr::MSYNC, [p + 1, len, MS_SYNC, 0, 0, 0]), err(errno::EINVAL));
        // SAFETY: unmapping the mapping made above.
        unsafe { libc::munmap(p as *mut _, len as usize) };
    }

    /// The `prctl` options in use: a thread name, the capability bounding
    /// set, `no_new_privs`, and `EINVAL` for anything unknown.
    #[test]
    fn prctl_options() {
        use fwe_abi::prctl::*;
        let mut k = kernel();
        let mut call = |opt, arg| k.syscall(nr::PRCTL, [opt, arg, 0, 0, 0, 0]);
        let name = std::ffi::CString::new("a-long-thread-name").unwrap();
        assert_eq!(call(PR_SET_NAME, name.as_ptr() as u64), 0);
        let mut got = [0xffu8; TASK_COMM_LEN];
        assert_eq!(call(PR_GET_NAME, got.as_mut_ptr() as u64), 0);
        assert_eq!(&got, b"a-long-thread-n\0");
        assert_eq!(call(PR_CAPBSET_READ, 0), 1);
        assert_eq!(call(PR_CAPBSET_READ, CAP_LAST_CAP + 1), err(errno::EINVAL));
        assert_eq!(call(PR_SET_NO_NEW_PRIVS, 1), 0);
        assert_eq!(call(PR_GET_NO_NEW_PRIVS, 0), 1);
        assert_eq!(call(PR_SET_PDEATHSIG, 9), 0);
        let mut sig = 0i32;
        assert_eq!(call(PR_GET_PDEATHSIG, &mut sig as *mut _ as u64), 0);
        assert_eq!(sig, 9);
        assert_eq!(call(1000, 0), err(errno::EINVAL));
    }

    #[test]
    fn sysinfo_reports_uptime_and_memory() {
        let mut info = fwe_abi::Sysinfo::default();
        let p = &mut info as *mut _ as u64;
        assert_eq!(kernel().syscall(nr::SYSINFO, [p, 0, 0, 0, 0, 0]), 0);
        assert!(info.uptime > 0);
        assert_eq!(info.totalram, crate::procfs::MEM_TOTAL_KB * 1024);
        assert!(info.freeram <= info.totalram);
        assert_eq!(info.mem_unit, 1);
    }

    /// A scratch file, opened twice: two open file descriptions.
    fn two_opens(name: &str) -> (std::fs::File, std::fs::File, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("fwe-{name}-{}", std::process::id()));
        let a = std::fs::File::create(&path).unwrap();
        let b = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        (a, b, path)
    }

    /// `fcntl` record locks in Linux layout: set, query (a process's own
    /// lock never conflicts with it, so the query reports none) and release;
    /// a bad lock type is refused.
    #[test]
    fn fcntl_record_locks() {
        use std::os::fd::AsRawFd;
        let (a, _b, path) = two_opens("fcntl-lock");
        let fd = a.as_raw_fd() as u64;
        let mut k = kernel();
        let mut lock = |cmd, l_type| {
            let mut lock = fwe_abi::Flock { l_type, l_len: 10, ..Default::default() };
            let r = k.syscall(nr::FCNTL, [fd, cmd, &mut lock as *mut _ as u64, 0, 0, 0]);
            (r, lock.l_type)
        };
        assert_eq!(lock(fcntl::F_SETLK, fcntl::F_WRLCK), (0, fcntl::F_WRLCK));
        assert_eq!(lock(fcntl::F_GETLK, fcntl::F_WRLCK), (0, fcntl::F_UNLCK));
        assert_eq!(lock(fcntl::F_SETLKW, fcntl::F_UNLCK), (0, fcntl::F_UNLCK));
        assert_eq!(lock(fcntl::F_SETLK, 7).0, err(errno::EINVAL));
        let _ = std::fs::remove_file(path);
    }

    /// `flock` locks belong to an open file description, so a second open of
    /// the same file is refused an exclusive lock until the first lets go.
    #[test]
    fn flock_conflicts_between_open_descriptions() {
        use std::os::fd::AsRawFd;
        let (a, b, path) = two_opens("flock");
        let (a, b) = (a.as_raw_fd() as u64, b.as_raw_fd() as u64);
        let mut k = kernel();
        let mut flock = |fd, op| k.syscall(nr::FLOCK, [fd, op, 0, 0, 0, 0]);
        assert_eq!(flock(a, fcntl::LOCK_EX), 0);
        assert_eq!(flock(b, fcntl::LOCK_EX | fcntl::LOCK_NB), err(errno::EAGAIN));
        assert_eq!(flock(b, fcntl::LOCK_SH | fcntl::LOCK_NB), err(errno::EAGAIN));
        assert_eq!(flock(a, fcntl::LOCK_UN), 0);
        assert_eq!(flock(b, fcntl::LOCK_EX | fcntl::LOCK_NB), 0);
        assert_eq!(flock(a, 0), err(errno::EINVAL));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn executable_mappings_are_prepared() {
        let mut k = kernel();
        let len = k.page_size;
        let p = k.syscall(nr::MMAP, [0, len, 5 /* R|X */, 0x22 /* PRIVATE|ANON */, u64::MAX, 0]);
        assert!(p > 0, "mmap failed: {p}");
        assert_eq!(k.platform.exec, vec![(p as u64, len)]);
        assert_eq!(k.syscall(nr::MUNMAP, [p as u64, len, 0, 0, 0, 0]), 0);
    }

    #[test]
    fn brk_grows_and_shrinks() {
        let mut k = kernel();
        let size = 64 * k.page_size;
        // Find free address space for the reservation. Other tests map memory
        // concurrently, so the range can be taken in between; try again.
        let mut probe = 0;
        for _ in 0..20 {
            // SAFETY: plain host calls on a fresh mapping.
            probe = unsafe {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    size as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                libc::munmap(p, size as usize);
                p as u64
            };
            k.brk = Brk::reserve(probe, size);
            if k.brk.limit != k.brk.start {
                break;
            }
        }
        assert_eq!(k.brk.limit, probe + size);
        assert_eq!(k.syscall(nr::BRK, [0; 6]), probe as i64);
        let top = probe + 3 * k.page_size + 5;
        assert_eq!(k.syscall(nr::BRK, [top, 0, 0, 0, 0, 0]), top as i64);
        // SAFETY: the break was just extended over this byte.
        unsafe { ((top - 1) as *mut u8).write(7) };
        assert_eq!(k.syscall(nr::BRK, [probe, 0, 0, 0, 0, 0]), probe as i64);
        assert_eq!(k.syscall(nr::BRK, [top, 0, 0, 0, 0, 0]), top as i64);
        // SAFETY: the break covers this byte again; released pages are zeroed.
        assert_eq!(unsafe { ((top - 1) as *const u8).read() }, 0);
        // Beyond the reservation the break stays put.
        assert_eq!(k.syscall(nr::BRK, [probe + size + 1, 0, 0, 0, 0, 0]), top as i64);
    }

    #[test]
    fn signal_mask_round_trip() {
        let mut k = kernel();
        let set: u64 = 1 << (signal::SIGUSR1 - 1) | 1 << (signal::SIGKILL - 1);
        let mut old: u64 = 0;
        let a = [signal::SIG_BLOCK, &set as *const _ as u64, &mut old as *mut _ as u64, 8, 0, 0];
        assert_eq!(k.syscall(nr::RT_SIGPROCMASK, a), 0);
        assert_eq!(old, 0);
        let a = [signal::SIG_BLOCK, 0, &mut old as *mut _ as u64, 8, 0, 0];
        assert_eq!(k.syscall(nr::RT_SIGPROCMASK, a), 0);
        assert_eq!(old, 1 << (signal::SIGUSR1 - 1));
    }

    #[test]
    fn affinity_reports_online_cpus() {
        let mut k = kernel();
        let mut mask = [0u64; 16];
        let r = k.syscall(nr::SCHED_GETAFFINITY, [0, 128, mask.as_mut_ptr() as u64, 0, 0, 0]);
        assert!(r >= 8);
        assert_ne!(mask[0], 0);
    }

    #[test]
    fn clock_nanosleep_relative_and_absolute() {
        let mut k = kernel();
        let req = Timespec { tv_sec: 0, tv_nsec: 5_000_000 };
        let start = std::time::Instant::now();
        let a = [clock::CLOCK_MONOTONIC, 0, &req as *const _ as u64, 0, 0, 0];
        assert_eq!(k.syscall(nr::CLOCK_NANOSLEEP, a), 0);
        assert!(start.elapsed() >= std::time::Duration::from_millis(5));
        // An absolute time in the past returns immediately.
        let past = Timespec { tv_sec: 1, tv_nsec: 0 };
        let a = [clock::CLOCK_MONOTONIC, 1, &past as *const _ as u64, 0, 0, 0];
        assert_eq!(k.syscall(nr::CLOCK_NANOSLEEP, a), 0);
        let bad = Timespec { tv_sec: 0, tv_nsec: 2_000_000_000 };
        let a = [clock::CLOCK_MONOTONIC, 0, &bad as *const _ as u64, 0, 0, 0];
        assert_eq!(k.syscall(nr::CLOCK_NANOSLEEP, a), err(errno::EINVAL));
    }

    #[test]
    fn getrandom_fills_buffer() {
        let mut k = kernel();
        let mut buf = [0u8; 64];
        assert_eq!(k.syscall(nr::GETRANDOM, [buf.as_mut_ptr() as u64, 64, 0, 0, 0, 0]), 64);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
