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

/// `fcntl(fd, F_SETLK or F_SETLKW, lock)`, or their open-file-description
/// forms (`F_OFD_SETLK`, `F_OFD_SETLKW`, whose lock names no pid): a record
/// lock in Linux layout. The waiting forms wait for a conflicting lock to
/// go, so they run without the kernel lock ([`crate::blocking_syscall`]).
pub(crate) fn set_record_lock(fd: i32, cmd: u64, arg: u64) -> i64 {
    let lock: fwe_abi::Flock = guest!(uaccess::read(arg));
    if matches!(cmd, fcntl::F_OFD_SETLK | fcntl::F_OFD_SETLKW) && lock.l_pid != 0 {
        return err(errno::EINVAL);
    }
    let lock = match host::flock_to_host(&lock) {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let Some(hcmd) = host::lock_cmd(cmd) else { return err(errno::EINVAL) };
    // SAFETY: `lock` is a valid host `struct flock`.
    ret(unsafe { libc::fcntl(fd, hcmd, &lock) })
}

pub(crate) unsafe fn clock_nanosleep(id: u64, flags: u64, req: u64, rem: u64) -> i64 {
    const TIMER_ABSTIME: u64 = 1;
    // A thread's CPU-time clock cannot be slept on (a C library turns
    // this into `EINVAL`).
    if matches!(id, clock::CLOCK_THREAD_CPUTIME_ID) {
        return err(errno::EOPNOTSUPP);
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
    // On time, as Linux wakes within its timer slack (the host's own
    // sleeps can end a millisecond late), and ended by a signal however
    // soon it lands ([`crate::thread::wait_ready_ns`]).
    let ns = ts.tv_sec.saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec);
    let start = std::time::Instant::now();
    match crate::thread::wait_ready_ns(&mut [], ns) {
        Ok(_) => 0,
        Err(e) => {
            if rem != 0 && flags & TIMER_ABSTIME == 0 {
                let spent = start.elapsed().as_nanos().min(i64::MAX as u128) as i64;
                let left = (ns - spent).max(0);
                let left = Timespec { tv_sec: left / 1_000_000_000, tv_nsec: left % 1_000_000_000 };
                guest!(uaccess::write(rem, left));
            }
            err(e)
        }
    }
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
        // Mappings changed by memory calls are published before any other
        // call ([`crate::maps::publish`]).
        crate::maps::flush_before(n);
        if let Err(e) = crate::fdtable::check_args(n, &a) {
            return e;
        }
        if let Err(e) = crate::fdtable::check_limit(n, &a) {
            return e;
        }
        let plan = self.inotify_before(n, &a);
        let noted = crate::atime::before(n, &a);
        let r = crate::linux_result(n, &a, self.dispatch_call(n, a));
        crate::creds::publish(&self.creds);
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
                let r = unsafe { crate::blocking_call(n, a) }.unwrap_or(err(errno::ENOSYS));
                crate::after_write(n, &a, r);
                r
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
                    // SEEK_SET, CUR and END match; Linux's SEEK_DATA and
                    // SEEK_HOLE are 3 and 4, the host's the other way round.
                    let whence = match a[2] {
                        0..=2 => a[2] as i32,
                        3 => libc::SEEK_DATA,
                        4 => libc::SEEK_HOLE,
                        _ => return err(errno::EINVAL),
                    };
                    // SAFETY: plain host call.
                    ret(unsafe { libc::lseek(a[0] as i32, a[1] as libc::off_t, whence) })
                }
            }
            nr::CLOSE => {
                let fd = a[0] as i32;
                crate::epoll::closed(fd);
                crate::mountwatch::closed(fd);
                crate::atime::closed(fd);
                crate::memfd::closed(fd);
                crate::tmpfile::closed(fd);
                crate::modes::closed(fd);
                // A port bound in a network namespace is free once its
                // socket is.
                let mark = crate::fdmarks::marked(fd);
                if matches!(mark, Some(crate::fdmarks::Mark::NetBound { .. }))
                    && !crate::fdmarks::shared_elsewhere(fd)
                {
                    crate::netns::closed(fd, mark);
                }
                crate::netlink::closed(fd);
                crate::net::closed(fd);
                crate::mountapi::closed(fd);
                crate::nsfd::closed(fd);
                crate::inotify::closed(fd);
                crate::dnotify::closed(fd);
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
            nr::TIMER_CREATE => self.sys_timer_create(a[0], a[1], a[2]),
            nr::TIMER_SETTIME => self.sys_timer_settime(a[0], a[1], a[2], a[3]),
            nr::TIMER_GETTIME => self.sys_timer_gettime(a[0], a[1]),
            nr::TIMER_GETOVERRUN => self.sys_timer_getoverrun(a[0]),
            nr::TIMER_DELETE => self.sys_timer_delete(a[0]),
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
            nr::SETSOCKOPT => unsafe {
                let admin = self.creds.has(crate::caps::CAP_NET_ADMIN);
                crate::net::setsockopt(a[0], a[1], a[2], a[3], a[4], admin)
            },
            // SAFETY: the out buffers are validated by the host/impl.
            nr::GETSOCKOPT => unsafe { crate::net::getsockopt(a[0], a[1], a[2], a[3], a[4]) },
            // SAFETY: no pointers.
            nr::SHUTDOWN => unsafe { crate::net::shutdown(a[0], a[1]) },

            // Files and directories.
            nr::OPENAT => self.sys_openat(a[0], a[1], a[2], a[3]),
            nr::OPENAT2 => self.sys_openat2(a[0], a[1], a[2], a[3]),
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
            nr::FCHMODAT2 => self.sys_fchmodat2(a[0], a[1], a[2], a[3]),
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
            // Every file system's writes, the host's `sync`: a file
            // system of a descriptor is the host's too.
            nr::SYNC => {
                // SAFETY: plain host call.
                unsafe { libc::sync() };
                0
            }
            nr::SYNCFS => {
                // SAFETY: plain host call on a guest fd.
                if unsafe { libc::fcntl(a[0] as i32, libc::F_GETFD) } < 0 {
                    return err(errno::EBADF);
                }
                let _ = crate::loopdev::fsync(a[0] as i32);
                // SAFETY: plain host call.
                unsafe { libc::sync() };
                0
            }
            nr::FSYNC | nr::FDATASYNC => match crate::loopdev::fsync(a[0] as i32) {
                Some(r) => r,
                None => {
                    // A pipe, socket or character device has nothing to
                    // sync: `EINVAL`, as Linux has it.
                    // SAFETY: an all-zero `stat` is a valid out-parameter.
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: as above.
                    let ok = unsafe { libc::fstat(a[0] as i32, &mut st) } == 0;
                    let kind = st.st_mode & libc::S_IFMT;
                    if ok && matches!(kind, libc::S_IFIFO | libc::S_IFSOCK | libc::S_IFCHR) {
                        return err(errno::EINVAL);
                    }
                    // SAFETY: plain host call on a guest fd.
                    ret(unsafe { libc::fsync(a[0] as i32) })
                }
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
            nr::MSEAL => self.sys_mseal(a[0], a[1], a[2]),
            nr::REMAP_FILE_PAGES => self.sys_remap_file_pages(a[0], a[1], a[2], a[3], a[4]),
            nr::MPROTECT => self.sys_mprotect(a[0], a[1], a[2]),
            nr::MADVISE => self.sys_madvise(a[0], a[1], a[2]),
            nr::MSYNC => self.sys_msync(a[0], a[1], a[2]),
            nr::MINCORE => self.sys_mincore(a[0], a[1], a[2]),
            nr::MREMAP => self.sys_mremap(a[0], a[1], a[2], a[3], a[4]),

            // Process and thread identity.
            nr::EXIT_GROUP => {
                // A traced process tells its tracer it is ending first.
                self.ptrace_exit_stop(((a[0] as i32) & 0xff) << 8);
                self.platform.exit(a[0] as i32)
            }
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
                // A child of the caller's session that has run a program of
                // its own may not be moved (`EACCES`), whatever the group:
                // Linux tells that before the group's checks, the host after.
                // SAFETY: plain host calls.
                let (me, sid) = unsafe { (libc::getpid(), libc::getsid(0)) };
                if pid != 0
                    && pid != me
                    // SAFETY: as above.
                    && unsafe { libc::getsid(pid) } == sid
                    && crate::procreg::read(pid).is_some_and(|r| {
                        r.execed && r.lineage.first().is_some_and(|&(p, _)| p == me)
                    })
                {
                    return err(errno::EACCES);
                }
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
            // Any thread's list, another process's to a caller that may
            // trace it; the length is always the head's size, as Linux's.
            nr::GET_ROBUST_LIST => {
                let pid = a[0] as i32;
                let head = if pid == 0 || pid == thread::tid() {
                    thread::robust_list().0
                } else if let Some(head) = thread::robust_list_of(pid) {
                    head
                } else {
                    // Another process's thread: its host process and, for
                    // one not its main thread, its number.
                    let target = match thread::owner_of_tid(pid) {
                        Some(owner) => Some((owner, Some(pid))),
                        None => crate::pidns::to_host(pid)
                            .filter(|&h| host::process_exists(h))
                            .map(|h| (h, None)),
                    };
                    let Some((owner, tid)) = target else {
                        return err(errno::ESRCH);
                    };
                    if !self.may_trace(owner) {
                        return err(errno::EPERM);
                    }
                    thread::published_robust(owner, tid).unwrap_or(0)
                };
                guest!(uaccess::write(a[1], head));
                guest!(uaccess::write(a[2], 24u64));
                0
            }
            nr::REBOOT => self.sys_reboot(a[0], a[1], a[2]),
            nr::ACCT => self.sys_acct(a[0]),
            nr::IO_SETUP => self.sys_io_setup(a[0], a[1]),
            nr::IO_DESTROY => self.sys_io_destroy(a[0]),
            #[cfg(target_os = "macos")]
            nr::FILE_GETATTR | nr::FILE_SETATTR => self.sys_file_attr(n == nr::FILE_SETATTR, a),
            nr::PTRACE => self.sys_ptrace(a[0], a[1], a[2], a[3]),
            nr::UNAME => self.sys_uname(a[0]),
            nr::SYSINFO => self.sys_sysinfo(a[0]),
            nr::PRCTL => self.sys_prctl(a[0], a[1], a[2], a[3], a[4]),
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
            nr::SETNS => match crate::pidfd::of(a[0] as i32) {
                Some(t) => self.setns_pidfd(a[0] as i32, t, a[1]),
                None => self.sys_setns(a[0], a[1]),
            },
            nr::PIDFD_OPEN => self.sys_pidfd_open(a[0], a[1]),
            nr::PIDFD_SEND_SIGNAL => self.sys_pidfd_send_signal(a[0], a[1], a[2], a[3]),
            // The backends finish it without the lock (it waits for the
            // target); the same, reached here.
            nr::PIDFD_GETFD => crate::pidfd::getfd(self.getfd_request(a[0], a[1], a[2])),
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
            nr::ADD_KEY => self.sys_add_key(a[0], a[1], a[2], a[3], a[4]),
            nr::REQUEST_KEY => self.sys_request_key(a[0], a[1], a[2], a[3]),
            nr::KEYCTL => self.sys_keyctl(a[0], [a[1], a[2], a[3], a[4]]),
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
            // `CAP_BPF` or `CAP_SYS_ADMIN`, as Linux's `bpf_capable`.
            nr::BPF if !self.creds.has_admin() && !self.creds.has(crate::caps::CAP_BPF) => {
                err(errno::EPERM)
            }
            nr::BPF => crate::bpf::sys_bpf(a[0], a[1], a[2]),
            nr::CAPSET => self.sys_capset(a[0], a[1]),
            nr::SCHED_YIELD => {
                std::thread::yield_now();
                0
            }
            nr::SCHED_GETAFFINITY => self.sys_sched_getaffinity(a[0], a[1], a[2]),
            nr::GETCPU => self.sys_getcpu(a[0], a[1]),
            nr::VHANGUP => self.sys_vhangup(),
            nr::READAHEAD => self.sys_readahead(a[0]),
            nr::SYNC_FILE_RANGE => self.sys_sync_file_range(a[0], a[1], a[2], a[3]),
            nr::DELETE_MODULE => self.sys_delete_module(a[0]),
            nr::SYSLOG => self.sys_syslog(a[0], a[1], a[2]),
            nr::MEMBARRIER => self.sys_membarrier(a[0], a[1]),
            nr::IOPRIO_GET => self.sys_ioprio_get(a[0], a[1]),
            nr::IOPRIO_SET => self.sys_ioprio_set(a[0], a[1], a[2]),
            nr::CACHESTAT => self.sys_cachestat(a[0], a[1], a[2], a[3]),
            // Protection keys: the CPU has none (arm64's need FEAT_S1POE),
            // so none can be allocated, as Linux answers without them.
            nr::PKEY_ALLOC => match (a[0], a[1] & !3) {
                (0, 0) => err(errno::ENOSPC),
                _ => err(errno::EINVAL),
            },
            nr::PKEY_FREE => err(errno::EINVAL),
            nr::PKEY_MPROTECT if a[3] as i32 == -1 => self.sys_mprotect(a[0], a[1], a[2]),
            nr::PKEY_MPROTECT => err(errno::EINVAL),
            nr::LSM_LIST_MODULES => self.sys_lsm_list_modules(a[0], a[1], a[2]),
            nr::LSM_GET_SELF_ATTR => self.sys_lsm_get_self_attr(a[0], a[2], a[3]),
            nr::LSM_SET_SELF_ATTR => self.sys_lsm_set_self_attr(a[1], a[2], a[3]),
            nr::RT_SIGQUEUEINFO => self.sys_rt_sigqueueinfo(a[0], a[1], a[2]),
            nr::RT_TGSIGQUEUEINFO => self.sys_rt_tgsigqueueinfo(a[0], a[1], a[2], a[3]),
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
            nr::TIMES => {
                // The process's and its reaped children's times in clock
                // ticks (`USER_HZ`, 100 a second), and the ticks since boot.
                let ticks = |tv: libc::timeval| {
                    (tv.tv_sec.max(0) as u64) * 100 + (host::usec(tv).max(0) as u64) / 10_000
                };
                let usage = |who| {
                    // SAFETY: an all-zero rusage is a valid out-parameter.
                    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
                    // SAFETY: as above.
                    unsafe { libc::getrusage(who, &mut u) };
                    u
                };
                if a[0] != 0 {
                    let (me, children) = (usage(libc::RUSAGE_SELF), usage(libc::RUSAGE_CHILDREN));
                    let tms = [
                        ticks(me.ru_utime),
                        ticks(me.ru_stime),
                        ticks(children.ru_utime),
                        ticks(children.ru_stime),
                    ];
                    guest!(uaccess::write(a[0], tms));
                }
                (host::uptime() * 100.0) as i64
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
            // A tgid must name a process (`tkill` passes -1 for any).
            nr::TGKILL if (a[0] as i32) <= 0 => err(errno::EINVAL),
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
            nr::NAME_TO_HANDLE_AT => self.sys_name_to_handle_at(a[0], a[1], a[2], a[3], a[4]),
            nr::OPEN_BY_HANDLE_AT => self.sys_open_by_handle_at(a[0], a[1], a[2]),
            nr::GETRANDOM => {
                // GRND_NONBLOCK, GRND_RANDOM and GRND_INSECURE, but not the
                // last two at once.
                let flags = a[2] as u32;
                if flags & !7 != 0 || flags & 6 == 6 {
                    return err(errno::EINVAL);
                }
                self.sys_getrandom(a[0], a[1])
            }

            // Any other call: `ENOSYS`, as Linux gives a call it lacks.
            _ => {
                self.tracer.note(&format!("unimplemented syscall {n}"));
                err(errno::ENOSYS)
            }
        }
    }

    /// `acct(path)`: process accounting to the regular file at `path`, or
    /// off for a null one; the file is opened as Linux opens it (for
    /// appending), so it fails as that open would.
    fn sys_acct(&mut self, path: u64) -> i64 {
        if !self.creds.has(crate::caps::CAP_SYS_PACCT) {
            return err(errno::EPERM);
        }
        if path == 0 {
            return match crate::acct::set(None) {
                Ok(()) => 0,
                Err(e) => err(e),
            };
        }
        let flags = fwe_abi::fcntl::O_WRONLY | fwe_abi::fcntl::O_APPEND;
        let fd = self.sys_openat(fwe_abi::fcntl::AT_FDCWD as u64, path, flags, 0);
        if fd < 0 {
            return fd;
        }
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a plain host call on the descriptor just opened, with a
        // valid out-parameter.
        let regular = unsafe { libc::fstat(fd as i32, &mut st) } == 0
            && st.st_mode & libc::S_IFMT == libc::S_IFREG;
        let named = crate::fs::host_path_of(fd as i32);
        self.dispatch_call(nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
        if !regular {
            return err(errno::EACCES);
        }
        let Some(host) = named else { return err(errno::EIO) };
        match crate::acct::set(Some(&host)) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
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
        // The size is an int: a negative one is refused.
        if (size as i32) < 0 {
            return err(errno::EINVAL);
        }
        let size = u64::from(size as u32);
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
                    } else if let Some(nb) = crate::specialfd::timer_nonblock(fd) {
                        (fcntl::O_RDWR | if nb { fcntl::O_NONBLOCK } else { 0 }) as i64
                    } else if let Some(t) = crate::pidfd::of(fd) {
                        // Read-write, and non-blocking as it was made or set.
                        (fcntl::O_RDWR | if t.nonblock { fcntl::O_NONBLOCK } else { 0 }) as i64
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
                fcntl::F_SETFL if crate::specialfd::timer_nonblock(fd).is_some() => {
                    crate::specialfd::set_timer_nonblock(fd, arg & fcntl::O_NONBLOCK != 0);
                    0
                }
                fcntl::F_SETFL if crate::pidfd::of(fd).is_some() => {
                    crate::pidfd::set_nonblock(fd, arg & fcntl::O_NONBLOCK != 0);
                    0
                }
                fcntl::F_SETFL => {
                    ret(libc::fcntl(fd, libc::F_SETFL, host::settable_flags_to_host(arg)))
                }
                fcntl::F_GETLK | fcntl::F_OFD_GETLK => {
                    let asked: fwe_abi::Flock = guest!(uaccess::read(arg));
                    if cmd == fcntl::F_OFD_GETLK && asked.l_pid != 0 {
                        return err(errno::EINVAL);
                    }
                    let mut lock = match host::flock_to_host(&asked) {
                        Ok(l) => l,
                        Err(e) => return err(e),
                    };
                    let hcmd = host::lock_cmd(cmd).unwrap_or(libc::F_GETLK);
                    if libc::fcntl(fd, hcmd, &mut lock) < 0 {
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
                fcntl::F_SETLK | fcntl::F_SETLKW | fcntl::F_OFD_SETLK | fcntl::F_OFD_SETLKW => {
                    set_record_lock(fd, cmd, arg)
                }
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
                    crate::leases::signal_set(fd, arg as u32);
                    0
                }
                fcntl::F_GETSIG => crate::fdstate::get(fd).sig as i64,
                fcntl::F_NOTIFY => match crate::dnotify::set(fd, arg) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                },
                fcntl::F_SETLEASE => self.set_lease(fd, arg),
                fcntl::F_GETLEASE => i64::from(crate::leases::get(fd)),
                fcntl::F_GETPIPE_SZ | fcntl::F_SETPIPE_SZ => self.pipe_size(fd, cmd, arg),
                fcntl::F_CREATED_QUERY => i64::from(crate::fdstate::get(fd).created),
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
        // The file as the host knows it, as opens find it.
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut host: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above, on the guest's descriptor.
        if unsafe { libc::fstat(fd, &mut host) } != 0 {
            return last_error();
        }
        match crate::leases::set(fd, host.st_dev as u64, host.st_ino, kind) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
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
        let Some(size) = crate::fdstate::round_pipe_size(arg, self.page_size) else {
            return err(errno::EINVAL);
        };
        if size > crate::fdstate::pipe_max_size() && !self.creds.has(crate::caps::CAP_SYS_RESOURCE)
        {
            return err(errno::EPERM);
        }
        // What the pipe holds, which the host gives through either end.
        if st.st_size as u64 > size {
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
        if let Some(r) = self.pidfd_ioctl(fd, req, arg) {
            return r;
        }
        // `FICLONE`, `FICLONERANGE` and `FIDEDUPERANGE` between files: no
        // file system fwe mounts shares extents (`EOPNOTSUPP`, as Linux's
        // tmpfs and ext4 answer).
        if matches!(req, 0x4004_9409 | 0x4020_940d | 0xc018_9436) && is_regular_fd(fd) {
            return err(errno::EOPNOTSUPP);
        }
        // `FS_IOC_GETFLAGS` and `FS_IOC_SETFLAGS`: the immutable and
        // append-only flags, which the host has (and enforces) too.
        #[cfg(target_os = "macos")]
        if req == 0x8008_6601 || req == 0x4008_6602 {
            return self.inode_flags(fd, req == 0x4008_6602, arg);
        }
        // `RNDGETENTCNT` on `/dev/random` or `/dev/urandom`: the entropy
        // count, full as Linux's is (`kernel.random.entropy_avail`).
        if req == 0x8004_5200 && is_random_device(fd) {
            guest!(uaccess::write(arg, 256i32));
            return 0;
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
                ioctl::TCGETA => crate::term::tcgeta(fd, arg),
                ioctl::PROCMAP_QUERY if let Some(pid) = maps_of_fd(fd) => {
                    self.procmap_query(pid, arg)
                }
                ioctl::SIOCGIFFLAGS
                | ioctl::SIOCSIFFLAGS
                | ioctl::SIOCGIFINDEX
                | ioctl::SIOCGIFMTU
                | ioctl::SIOCSIFMTU
                | ioctl::SIOCGIFADDR
                | ioctl::SIOCGIFNETMASK
                | ioctl::SIOCGIFCONF
                | ioctl::SIOCATMARK
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
                // A pipe's either end counts what the pipe holds (the
                // host's write end counts nothing).
                ioctl::FIONREAD if crate::splice::pipe_ends(fd).is_some() => {
                    let held = crate::splice::held(fd).min(i32::MAX as u64) as i32;
                    guest!(uaccess::write(arg, held));
                    0
                }
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
    fn sys_prctl(&mut self, option: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
        use fwe_abi::prctl::*;
        use std::sync::atomic::Ordering::Relaxed;
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
            PR_SET_NO_NEW_PRIVS if arg2 == 1 && arg3 | arg4 | arg5 == 0 => {
                NO_NEW_PRIVS.store(true, Relaxed);
                0
            }
            PR_SET_NO_NEW_PRIVS => err(errno::EINVAL),
            PR_GET_NO_NEW_PRIVS if arg2 | arg3 | arg4 | arg5 != 0 => err(errno::EINVAL),
            PR_GET_NO_NEW_PRIVS => i64::from(NO_NEW_PRIVS.load(Relaxed)),
            // Transparent huge pages are the host's; the choice is kept, as
            // a fork child and an exec keep it.
            PR_SET_THP_DISABLE if arg3 | arg4 | arg5 != 0 => err(errno::EINVAL),
            PR_SET_THP_DISABLE => {
                THP_DISABLE.store(arg2 != 0, Relaxed);
                0
            }
            PR_GET_THP_DISABLE if arg2 | arg3 | arg4 | arg5 != 0 => err(errno::EINVAL),
            PR_GET_THP_DISABLE => i64::from(THP_DISABLE.load(Relaxed)),
            // The CPU's speculation is the host's to control: no misfeature
            // is reported as one the process may change.
            PR_GET_SPECULATION_CTRL if arg3 | arg4 | arg5 != 0 => err(errno::EINVAL),
            PR_GET_SPECULATION_CTRL => match arg2 {
                PR_SPEC_STORE_BYPASS | PR_SPEC_INDIRECT_BRANCH | PR_SPEC_L1D_FLUSH => {
                    PR_SPEC_NOT_AFFECTED
                }
                _ => err(errno::ENODEV),
            },
            PR_SET_SPECULATION_CTRL if arg4 | arg5 != 0 => err(errno::EINVAL),
            PR_SET_SPECULATION_CTRL => match arg2 {
                PR_SPEC_STORE_BYPASS | PR_SPEC_INDIRECT_BRANCH | PR_SPEC_L1D_FLUSH => {
                    err(errno::ENXIO)
                }
                _ => err(errno::ENODEV),
            },
            PR_GET_SECCOMP => i64::from(crate::seccomp::mode()),
            PR_SET_SECCOMP => self.sys_seccomp(
                if arg2 == 1 { 0 } else { arg2 - 1 },
                0,
                if arg2 == 1 { 0 } else { arg3 },
            ),
            // Kept, as the host's timers have no slack to set.
            PR_SET_TIMERSLACK => {
                thread::set_slack(arg2);
                0
            }
            PR_GET_TIMERSLACK => thread::slack() as i64,
            PR_SET_DUMPABLE if arg2 <= 1 => {
                crate::coredump::UNDUMPABLE.store(arg2 == 0, Relaxed);
                0
            }
            PR_SET_DUMPABLE => err(errno::EINVAL),
            PR_GET_DUMPABLE => i64::from(!crate::coredump::UNDUMPABLE.load(Relaxed)),
            PR_SET_PDEATHSIG if arg2 <= signal::NSIG => {
                crate::pdeath::set(arg2);
                0
            }
            PR_SET_PDEATHSIG => err(errno::EINVAL),
            PR_GET_PDEATHSIG => {
                guest!(uaccess::write(arg2, crate::pdeath::get() as i32));
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
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            // SAFETY: F_GETFD only queries the descriptor.
            let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            return err(if open { errno::ENOTTY } else { errno::EBADF });
        }
        if req == SIOCATMARK {
            return crate::net::at_mark(fd, arg);
        }
        let net = self.fs().ns.net.clone();
        if req == SIOCGIFCONF {
            let addrs = match &net {
                Some(n) if n.get().lo_up => vec![(b"lo".to_vec(), [127, 0, 0, 1], [255, 0, 0, 0])],
                Some(_) => Vec::new(),
                None => host_ipv4_addrs(),
            };
            return ifconf(arg, &addrs);
        }
        let mut ifr = [0u8; 40];
        guest!(uaccess::read_into(arg, &mut ifr));
        let name_end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = ifr[..name_end].to_vec();
        let put16 = |v: u16| uaccess::write(arg + 16, v);
        let put32 = |v: i32| uaccess::write(arg + 16, v);
        // An address (`SIOCGIFADDR`) or mask as a `sockaddr_in` in the
        // request.
        let put_addr = |a: [u8; 4]| {
            let mut sin = [0u8; 16];
            sin[..2].copy_from_slice(&(fwe_abi::socket::AF_INET as u16).to_ne_bytes());
            sin[4..8].copy_from_slice(&a);
            uaccess::write(arg + 16, sin)
        };
        if let Some(net) = net {
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
                    let mtu = net.get().lo_mtu;
                    guest!(put32(if mtu == 0 { 65536 } else { mtu as i32 }));
                    0
                }
                SIOCSIFMTU => {
                    if !self.creds.has(crate::caps::CAP_NET_ADMIN) {
                        return err(errno::EPERM);
                    }
                    // At least an Ethernet frame's minimum (ETH_MIN_MTU).
                    let mtu = i32::from_ne_bytes(ifr[16..20].try_into().unwrap());
                    if mtu < 68 {
                        return err(errno::EINVAL);
                    }
                    match net.update(|n| {
                        n.lo_mtu = mtu as u32;
                        Ok(())
                    }) {
                        Ok(()) => 0,
                        Err(e) => err(e),
                    }
                }
                // An interface down has no address.
                SIOCGIFADDR | SIOCGIFNETMASK if !net.get().lo_up => err(errno::EADDRNOTAVAIL),
                SIOCGIFADDR => {
                    guest!(put_addr([127, 0, 0, 1]));
                    0
                }
                SIOCGIFNETMASK => {
                    guest!(put_addr([255, 0, 0, 0]));
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
            SIOCGIFADDR | SIOCGIFNETMASK => {
                let shown: &[u8] = &name;
                match host_ipv4_addrs().into_iter().find(|(n, ..)| n == shown) {
                    Some((_, addr, mask)) => {
                        guest!(put_addr(if req == SIOCGIFADDR { addr } else { mask }));
                        0
                    }
                    None if host_index(&cname) == 0 => err(errno::ENODEV),
                    None => err(errno::EADDRNOTAVAIL),
                }
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
            Action::KillStrict => self.terminate_by(signal::SIGKILL),
        }
    }

    /// `reboot(magic, magic2, cmd)`, checked as Linux checks it: the
    /// caller's `CAP_SYS_BOOT` (`EPERM`), the magic numbers and the command
    /// (`EINVAL`). Ctrl-Alt-Del's setting is taken (there is no console to
    /// press it on); a restart, halt or power off is refused (`EPERM`):
    /// fwe's processes never stop the host.
    fn sys_reboot(&mut self, magic: u64, magic2: u64, cmd: u64) -> i64 {
        const MAGIC1: u32 = 0xfee1_dead;
        const MAGIC2: [u32; 4] = [672_274_793, 85_072_278, 369_367_448, 537_993_216];
        const CAD_ON: u32 = 0x89ab_cdef;
        const CAD_OFF: u32 = 0;
        const STOPS: [u32; 6] =
            [0x0123_4567, 0xcdef_0123, 0x4321_fedc, 0xa1b2_c3d4, 0xd000_fce2, 0x4558_4543];
        if !self.creds.has(crate::caps::CAP_SYS_BOOT) {
            return err(errno::EPERM);
        }
        if magic as u32 != MAGIC1 || !MAGIC2.contains(&(magic2 as u32)) {
            return err(errno::EINVAL);
        }
        match cmd as u32 {
            CAD_ON | CAD_OFF => {}
            c if STOPS.contains(&c) => return err(errno::EPERM),
            _ => return err(errno::EINVAL),
        }
        0
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
        // Nor past `fs.nr_open`.
        if let Some(n) = &n
            && res == resource::RLIMIT_NOFILE
            && crate::sysctl::number(b"fs/nr_open")
                .is_some_and(|max| n.rlim_max > max.max(0) as u64)
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
            let mut s: Stack = guest!(uaccess::read(ss));
            // Linux's modes: none, `SS_ONSTACK` (the same) or `SS_DISABLE`,
            // with `SS_AUTODISARM` beside them.
            let autodisarm = s.ss_flags & signal::SS_AUTODISARM;
            let mode = s.ss_flags & !signal::SS_AUTODISARM;
            if ![0, signal::SS_ONSTACK, signal::SS_DISABLE].contains(&mode) {
                return err(errno::EINVAL);
            }
            if mode == signal::SS_DISABLE {
                s = Stack { ss_flags: signal::SS_DISABLE | autodisarm, ..Stack::default() };
            } else if s.ss_size < signal::MINSIGSTKSZ {
                return err(errno::ENOMEM);
            } else {
                s.ss_flags = autodisarm;
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

/// `pselect6(nfds, readfds, writefds, exceptfds, timeout, _)`, by way of the
/// host's `poll`: each set bit below `nfds` becomes a `pollfd`, and the sets
/// are rewritten with what is ready (the signal mask is the caller's, see
/// [`crate::blocking_syscall`]). Linux's `fd_set` is a bitmap of 64-bit
/// words, as fwe reads it. The time left is written back to the timeout,
/// as Linux does ([`with_remaining`]).
///
/// # Safety
/// The set and timeout pointers are null or reference guest memory.
pub(crate) unsafe fn pselect6(nfds: u64, sets: [u64; 3], timeout: u64) -> i64 {
    // SAFETY: the caller's guarantee, passed on.
    with_remaining(timeout, || unsafe { pselect6_wait(nfds, sets, timeout) })
}

/// A wait of up to `ns` nanoseconds (-1: without bound) for `set`
/// ([`crate::thread::wait_ready_ns`]), with what is ready as Linux reports
/// it ([`linux_revents`]): how many descriptors are. A pipe given less than
/// the host's capacity is not writable while full, which the host does not
/// know: it is looked at each millisecond until it has room.
fn poll_linux(set: &mut [libc::pollfd], ns: i64) -> Result<i32, i32> {
    use std::time::{Duration, Instant};
    let deadline = (ns >= 0).then(|| Instant::now() + Duration::from_nanos(ns as u64));
    loop {
        let mut ask = set.to_vec();
        let mut full = false;
        // An eventfd that may be written to is writable: its pipe's read
        // end, which the host watches, never is.
        let writable: Vec<bool> = set
            .iter()
            .map(|p| p.events & libc::POLLOUT != 0 && crate::specialfd::eventfd_writable(p.fd))
            .collect();
        for p in &mut ask {
            if p.events & libc::POLLOUT != 0 && crate::fdstate::pipe_full(p.fd) {
                p.events &= !libc::POLLOUT;
                full = true;
            }
            // A mounts file's change is fwe's to tell, in slices: the host
            // would report its urgent data at once.
            if crate::mountwatch::is(p.fd) {
                p.events &= !libc::POLLPRI;
                full = true;
            }
        }
        let left =
            deadline.map_or(-1, |d| d.saturating_duration_since(Instant::now()).as_nanos() as i64);
        let wait = if writable.contains(&true) {
            0
        } else if full && !(0..1_000_000).contains(&left) {
            1_000_000
        } else {
            left
        };
        crate::thread::wait_ready_ns(&mut ask, wait)?;
        for ((p, a), &w) in set.iter_mut().zip(&ask).zip(&writable) {
            p.revents = a.revents | if w { libc::POLLOUT } else { 0 };
            linux_revents(p);
            if crate::mountwatch::changed(p.fd) == Some(true) {
                p.revents |= libc::POLLERR | (p.events & libc::POLLPRI);
            }
        }
        let n = set.iter().filter(|p| p.revents != 0).count() as i32;
        if n > 0 || !full || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(n);
        }
    }
}

/// Linux's inode flags fwe keeps: immutable and append-only, as the
/// host's user flags; `noatime` and `nodump`, which tmpfs takes, are
/// accepted and not kept.
#[cfg(target_os = "macos")]
const FS_IMMUTABLE_FL: u32 = 0x10;
#[cfg(target_os = "macos")]
const FS_APPEND_FL: u32 = 0x20;
#[cfg(target_os = "macos")]
const FS_NODUMP_FL: u32 = 0x40;
#[cfg(target_os = "macos")]
const FS_NOATIME_FL: u32 = 0x80;

#[cfg(target_os = "macos")]
impl<P: Platform> Kernel<P> {
    /// `FS_IOC_GETFLAGS` (`set` false) or `FS_IOC_SETFLAGS` of the file
    /// open as `fd`, the flags at `arg`.
    fn inode_flags(&mut self, fd: i32, set: bool, arg: u64) -> i64 {
        if !set {
            return match get_inode_flags(fd) {
                Ok(f) => {
                    guest!(uaccess::write(arg, f));
                    0
                }
                Err(e) => err(e),
            };
        }
        let f: u32 = guest!(uaccess::read(arg));
        match self.set_inode_flags(fd, f) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// Set the inode flags `f` of the file open as `fd` (`ENOTTY` for one
    /// that has none).
    fn set_inode_flags(&mut self, fd: i32, f: u32) -> Result<(), i32> {
        let st = file_kind_for_flags(fd)?;
        let host = st.st_flags;
        if f & !(FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL) != 0 {
            return Err(errno::EOPNOTSUPP);
        }
        // The file's owner's to change, and the immutable and append-only
        // flags only with `CAP_LINUX_IMMUTABLE`.
        let owner = crate::owners::of_fd(fd, &st).0;
        if owner != self.creds.fsuid && !self.creds.has(crate::caps::CAP_FOWNER) {
            return Err(errno::EPERM);
        }
        let fixed = libc::UF_IMMUTABLE | libc::UF_APPEND;
        let mut want = host & !(fixed | libc::UF_NODUMP);
        if f & FS_IMMUTABLE_FL != 0 {
            want |= libc::UF_IMMUTABLE;
        }
        if f & FS_APPEND_FL != 0 {
            want |= libc::UF_APPEND;
        }
        // The flag also marks a kept mode, which stays marked.
        let kept = crate::modes::marked(&st) && !crate::modes::nodump_fd(fd, &st);
        if f & FS_NODUMP_FL != 0 || kept {
            want |= libc::UF_NODUMP;
        }
        if (want ^ host) & fixed != 0 && !self.creds.has(crate::caps::CAP_LINUX_IMMUTABLE) {
            return Err(errno::EPERM);
        }
        if want == host {
            return Ok(());
        }
        // SAFETY: plain host call on the guest's descriptor.
        if unsafe { libc::fchflags(fd, want) } != 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        Ok(())
    }

    /// `file_getattr(dfd, path, attr, size, at_flags)` (`set` false) or
    /// `file_setattr`: a file's attributes as `struct file_attr` (24
    /// bytes), the inode flags as `fa_xflags`; what only XFS keeps
    /// (extent sizes, projects) is `EOPNOTSUPP` to set.
    fn sys_file_attr(&mut self, set: bool, a: [u64; 6]) -> i64 {
        const VER0: u64 = 24;
        let (dfd, path, attr, size, at) = (a[0] as i32, a[1], a[2], a[3], a[4]);
        if at & !(fcntl::AT_SYMLINK_NOFOLLOW | fcntl::AT_EMPTY_PATH) != 0 {
            return err(errno::EINVAL);
        }
        if size > 4096 {
            return err(errno::E2BIG);
        }
        if size < VER0 {
            return err(errno::EINVAL);
        }
        // `file_setattr` takes the attributes first: those past the 24
        // bytes it knows must be zero.
        let wanted = if set {
            let given = guest!(uaccess::read_bytes(attr, size as usize));
            if given[VER0 as usize..].iter().any(|&b| b != 0) {
                return err(errno::E2BIG);
            }
            let word = |at: usize| u32::from_ne_bytes(given[at..at + 4].try_into().unwrap());
            let xflags = u64::from_ne_bytes(given[..8].try_into().unwrap());
            // Linux's `FS_XFLAG_*` bits, `FS_XFLAG_HASATTR` aside.
            if xflags & !0x1_ffff != 0 {
                return err(errno::EINVAL);
            }
            // Beyond what every file system with flags has (immutable,
            // append-only, sync, no-atime, no-dump, DAX), XFS's.
            if xflags & !(0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x8000) != 0
                || word(8) != 0
                || word(16) != 0
                || word(20) != 0
            {
                Some(Err(errno::EOPNOTSUPP))
            } else {
                Some(Ok(xflags))
            }
        } else {
            None
        };
        // The file: `dfd` itself for a null or empty path with
        // `AT_EMPTY_PATH`, else the path from it.
        let name = if path == 0 && at & fcntl::AT_EMPTY_PATH != 0 {
            Vec::new()
        } else {
            guest!(uaccess::read_cstr(path, uaccess::PATH_MAX))
        };
        let file = if name.is_empty() && at & fcntl::AT_EMPTY_PATH != 0 {
            // SAFETY: plain host call on a guest descriptor.
            let fd = unsafe { libc::fcntl(dfd, libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return err(errno::EBADF);
            }
            fd
        } else {
            let follow = at & fcntl::AT_SYMLINK_NOFOLLOW == 0;
            let r = match self.fs().resolve(dfd, &name, follow) {
                Ok(r) => r,
                Err(e) => return err(e),
            };
            if set && r.mount_flags & crate::mounts::ms::RDONLY != 0 {
                return err(errno::EROFS);
            }
            let Ok(c) = std::ffi::CString::new(r.name.clone()) else {
                return err(errno::ENOENT);
            };
            let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
            // SAFETY: a NUL-terminated name in a directory descriptor.
            let fd =
                unsafe { libc::openat(std::os::fd::AsRawFd::as_raw_fd(&r.dir), c.as_ptr(), flags) };
            if fd < 0 {
                // A symbolic link has no attributes.
                return err(match host::last_errno() {
                    libc::ELOOP => errno::EOPNOTSUPP,
                    e => host::errno_to_linux(e),
                });
            }
            fd
        };
        let r = (|| {
            if let Some(w) = wanted {
                let x = w?;
                let mut f = 0;
                for (xf, fl) in [
                    (0x8, FS_IMMUTABLE_FL),
                    (0x10, FS_APPEND_FL),
                    (0x20, 0x8),
                    (0x40, FS_NOATIME_FL),
                    (0x80, FS_NODUMP_FL),
                ] {
                    if x & xf != 0 {
                        f |= fl;
                    }
                }
                return self.set_inode_flags(file, f).map(|()| 0);
            }
            let f = get_inode_flags(file)?;
            let mut x = 0u64;
            for (fl, xf) in [(FS_IMMUTABLE_FL, 0x8), (FS_APPEND_FL, 0x10), (FS_NODUMP_FL, 0x80)] {
                if f & fl != 0 {
                    x |= xf;
                }
            }
            let mut out = vec![0u8; size as usize];
            out[..8].copy_from_slice(&x.to_ne_bytes());
            uaccess::write_from(attr, &out)?;
            Ok(0)
        })();
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(file) };
        match r {
            Ok(v) => v,
            Err(errno::ENOTTY) => err(errno::EOPNOTSUPP),
            Err(e) => err(e),
        }
    }
}

/// The host status of `fd` if its file has inode flags (a regular file or
/// directory), else `ENOTTY`.
#[cfg(target_os = "macos")]
fn file_kind_for_flags(fd: i32) -> Result<libc::stat, i32> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(host::errno_to_linux(host::last_errno()));
    }
    let kind = st.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        return Err(errno::ENOTTY);
    }
    Ok(st)
}

/// The inode flags (`FS_IOC_GETFLAGS`) of the file open as `fd`.
#[cfg(target_os = "macos")]
fn get_inode_flags(fd: i32) -> Result<u32, i32> {
    let st = file_kind_for_flags(fd)?;
    let host = st.st_flags;
    let mut f = 0u32;
    if host & libc::UF_IMMUTABLE != 0 {
        f |= FS_IMMUTABLE_FL;
    }
    if host & libc::UF_APPEND != 0 {
        f |= FS_APPEND_FL;
    }
    if crate::modes::nodump_fd(fd, &st) {
        f |= FS_NODUMP_FL;
    }
    Ok(f)
}

/// Whether `fd` is a regular file.
fn is_regular_fd(fd: i32) -> bool {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG }
}

/// Whether `fd` is `/dev/random` or `/dev/urandom` (Linux's 1:8, 1:9).
fn is_random_device(fd: i32) -> bool {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    ok && crate::devnodes::linux_numbers_of_host(&st)
        .is_some_and(|n| n.major == 1 && (n.minor == 8 || n.minor == 9))
}

/// What the host reported ready on `p` as Linux reports it: a regular
/// file is readable and writable but has no urgent data (`POLLPRI`, which
/// the host gives it), and a pipe or FIFO whose writers have gone with
/// nothing left to read has hung up (`POLLHUP`) but is not readable.
fn linux_revents(p: &mut libc::pollfd) {
    if p.revents == 0 || p.revents & libc::POLLNVAL != 0 {
        return;
    }
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(p.fd, &mut st) } != 0 {
        return;
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => p.revents &= !libc::POLLPRI,
        libc::S_IFIFO if p.revents & libc::POLLHUP != 0 => {
            let mut queued: libc::c_int = 0;
            // SAFETY: a valid out-parameter for FIONREAD.
            if unsafe { libc::ioctl(p.fd, libc::FIONREAD, &mut queued) } == 0 && queued == 0 {
                p.revents &= !libc::POLLIN;
            }
        }
        _ => {}
    }
}

/// A `struct timespec` timeout at guest `timeout` in nanoseconds (-1 for a
/// null pointer: without bound), or the call's error for a bad one.
fn timeout_ns(timeout: u64) -> Result<i64, i64> {
    if timeout == 0 {
        return Ok(-1);
    }
    let ts: Timespec = uaccess::read(timeout).map_err(err)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(err(errno::EINVAL));
    }
    Ok(ts.tv_sec.saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec))
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
    let ns = match timeout_ns(timeout) {
        Ok(ns) => ns,
        Err(e) => return e,
    };
    // On time, and ended by a signal however soon it lands.
    if let Err(e) = poll_linux(&mut fds, ns) {
        return err(e);
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

/// `ppoll(fds, nfds, timeout)`; the caller applies the signal mask. Blocks, so
/// the backend runs it without the kernel lock through
/// [`crate::blocking_syscall`]; it touches no kernel state.
///
/// # Safety
/// `fds` must point to `nfds` guest `pollfd`s and `timeout`, when non-null, to
/// a guest `Timespec`, where the time left is written back.
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
    // More than a process may have open, before the array is read.
    if nfds > crate::fdtable::limit().0 {
        return err(errno::EINVAL);
    }
    let ns = match timeout_ns(timeout) {
        Ok(ns) => ns,
        Err(e) => return e,
    };
    let ms = if ns < 0 { -1 } else { (ns as u64).div_ceil(1_000_000).min(i32::MAX as u64) as i32 };
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
        // `struct pollfd` and the POLL* bits match the host's.
        let mut set = vec![libc::pollfd { fd: 0, events: 0, revents: 0 }; nfds as usize];
        // SAFETY: a `pollfd` is plain data, as many bytes as the guest's.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                set.as_mut_ptr().cast::<u8>(),
                set.len() * size_of::<libc::pollfd>(),
            )
        };
        guest!(uaccess::read_into(fds, bytes));
        return match poll_linux(&mut set, ns) {
            Ok(n) => {
                for (i, p) in set.iter().enumerate() {
                    let at = fds + (i * size_of::<Pollfd>() + 6) as u64;
                    guest!(uaccess::write(at, p.revents));
                }
                i64::from(n)
            }
            Err(e) => err(e),
        };
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

/// The host's interfaces' IPv4 addresses, as (name as Linux has it, its
/// address, its mask): `lo0` is Linux's `lo`.
fn host_ipv4_addrs() -> Vec<(Vec<u8>, [u8; 4], [u8; 4])> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills the list, freed below; each entry's
    // pointers are valid until then.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut at = list;
        while !at.is_null() {
            let i = &*at;
            if !i.ifa_addr.is_null() && i32::from((*i.ifa_addr).sa_family) == libc::AF_INET {
                let name = std::ffi::CStr::from_ptr(i.ifa_name).to_bytes();
                let name = if name == b"lo0" { b"lo".to_vec() } else { name.to_vec() };
                let sin = &*(i.ifa_addr as *const libc::sockaddr_in);
                let mask = if i.ifa_netmask.is_null() {
                    [0; 4]
                } else {
                    (*(i.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr.to_ne_bytes()
                };
                out.push((name, sin.sin_addr.s_addr.to_ne_bytes(), mask));
            }
            at = i.ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

/// The host interface index of `name` (0: none).
fn host_index(name: &std::ffi::CStr) -> u32 {
    // SAFETY: a NUL-terminated name.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// `SIOCGIFCONF` into the guest's `struct ifconf` at `arg`: an `ifreq` of
/// name and `sockaddr_in` for each of `addrs`, as many as its buffer
/// holds, and the bytes they take; with no buffer, the bytes all would.
fn ifconf(arg: u64, addrs: &[(Vec<u8>, [u8; 4], [u8; 4])]) -> i64 {
    const IFREQ: usize = 40;
    let len: i32 = guest!(uaccess::read(arg));
    let buf: u64 = guest!(uaccess::read(arg + 8));
    if buf == 0 {
        guest!(uaccess::write(arg, (addrs.len() * IFREQ) as i32));
        return 0;
    }
    let room = len.max(0) as usize / IFREQ;
    let mut out = Vec::new();
    for (name, addr, _) in addrs.iter().take(room) {
        let mut r = [0u8; IFREQ];
        let n = name.len().min(15);
        r[..n].copy_from_slice(&name[..n]);
        r[16..18].copy_from_slice(&(fwe_abi::socket::AF_INET as u16).to_ne_bytes());
        r[20..24].copy_from_slice(addr);
        out.extend_from_slice(&r);
    }
    guest!(uaccess::write_from(buf, &out));
    guest!(uaccess::write(arg, out.len() as i32));
    0
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
                .filter(|&h| h > 0 && (h == me || crate::host::process_exists(h)))
                .into_iter()
                .collect(),
            prio::PGRP => {
                let group = if who == 0 {
                    my_group
                } else {
                    match crate::pidns::to_host(who).filter(|&g| g > 0) {
                        Some(g) => g,
                        None => return Ok(Vec::new()),
                    }
                };
                // (A process gone meanwhile has no group: -1, never one's.)
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

/// `PR_SET_THP_DISABLE`: remembered (and shown), kept across `fork` and
/// `execve` as Linux keeps it.
pub(crate) static THP_DISABLE: std::sync::atomic::AtomicBool =
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

/// The CPU the caller is taken to run on: the first of its affinity (the
/// host's scheduler places it where it will).
pub(crate) fn own_cpu() -> usize {
    let set = AFFINITY.lock().unwrap_or_else(|e| e.into_inner()).clone();
    set.and_then(|words| {
        words
            .iter()
            .enumerate()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| i * 64 + w.trailing_zeros() as usize)
    })
    .unwrap_or(0)
}

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
        /// How many code preparations to refuse, as a host with no room
        /// for stubs near the code would.
        refuse: u32,
    }

    impl Platform for TestPlatform {
        fn prepare_exec(
            &mut self,
            addr: u64,
            len: u64,
            _known: Option<&[(u64, u64)]>,
        ) -> Result<(), crate::PrepareFailed> {
            if self.refuse > 0 {
                self.refuse -= 1;
                return Err(crate::PrepareFailed { errno: errno::ENOMEM, why: "no room".into() });
            }
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

    /// Held by a test that maps memory through the kernel: the tests share
    /// the process's address space and its record of the guest's mappings,
    /// and one that unmaps, moves or probes an address it gave up (as
    /// `mremap` of a moved range does) must not reach another's mapping the
    /// host put there meanwhile.
    fn mapping_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn kernel() -> Kernel<TestPlatform> {
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        Kernel::new(
            TestPlatform { exec: vec![], refuse: 0 },
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

    /// A new unnamed file in the host's temporary directory: a name of its
    /// own each time, as tests run at once.
    fn tempfile_in_tmp() -> std::fs::File {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fwe-test-{}-{n}", std::process::id()));
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
        let _mapping = mapping_lock();
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
        let before = crate::mm::mapped(p + page, page);
        let r = k.syscall(nr::MINCORE, [p, 2 * page, v, 0, 0, 0]);
        // Unless another test's thread mapped the freed page meanwhile.
        if !before && !crate::mm::mapped(p + page, page) {
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
        let _mapping = mapping_lock();
        use fwe_abi::statfs::{MS_ASYNC, MS_SYNC};
        let mut k = kernel();
        let len = k.page_size;
        // A shared anonymous mapping the guest made (PROT_READ | WRITE,
        // MAP_SHARED | MAP_ANONYMOUS).
        let p = k.syscall(nr::MMAP, [0, len, 3, 0x21, u64::MAX, 0]) as u64;
        assert_eq!(k.syscall(nr::MSYNC, [p, len, MS_SYNC, 0, 0, 0]), 0);
        assert_eq!(k.syscall(nr::MSYNC, [p, len, MS_SYNC | MS_ASYNC, 0, 0, 0]), err(errno::EINVAL));
        assert_eq!(k.syscall(nr::MSYNC, [p + 1, len, MS_SYNC, 0, 0, 0]), err(errno::EINVAL));
        // Unmapped, a hole.
        assert_eq!(k.syscall(nr::MUNMAP, [p, len, 0, 0, 0, 0]), 0);
        assert_eq!(k.syscall(nr::MSYNC, [p, len, MS_SYNC, 0, 0, 0]), err(errno::ENOMEM));
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
        // None again: the test's process is sent nothing as its parent ends.
        assert_eq!(call(PR_SET_PDEATHSIG, 0), 0);
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
        let _mapping = mapping_lock();
        let mut k = kernel();
        let len = k.page_size;
        let p = k.syscall(nr::MMAP, [0, len, 5 /* R|X */, 0x22 /* PRIVATE|ANON */, u64::MAX, 0]);
        assert!(p > 0, "mmap failed: {p}");
        assert_eq!(k.platform.exec, vec![(p as u64, len)]);
        assert_eq!(k.syscall(nr::MUNMAP, [p as u64, len, 0, 0, 0, 0]), 0);
    }

    #[test]
    fn brk_grows_and_shrinks() {
        let _mapping = mapping_lock();
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

    /// A pid that names no single process never reaches the host: the
    /// host's -1 is every process of the user. None of these sends a
    /// signal.
    #[test]
    fn no_guest_pid_signals_the_hosts_processes() {
        let mut k = kernel();
        let info = [0u8; 128];
        for pid in [-1i64, 0, -5] {
            let r = k.syscall(nr::RT_SIGQUEUEINFO, [pid as u64, 10, info.as_ptr() as u64, 0, 0, 0]);
            assert_eq!(r, err(errno::ESRCH), "rt_sigqueueinfo to {pid}");
        }
        assert_eq!(host::kill(-1, libc::SIGUSR1), err(errno::ESRCH));
        for pid in [-1, 0, -5] {
            assert_eq!(host::kill_process(pid, libc::SIGUSR1), err(errno::ESRCH));
        }
        // tgkill's thread group must be a process.
        assert_eq!(k.syscall(nr::TGKILL, [-1i64 as u64, 1, 0, 0, 0, 0]), err(errno::EINVAL));
    }

    /// Code the host placed with no room for its stubs near it is mapped
    /// again where there is, when the guest left the place to fwe; a fixed
    /// mapping cannot move, and fails.
    #[test]
    fn code_without_room_for_stubs_moves_unless_fixed() {
        let _mapping = mapping_lock();
        use fwe_abi::mman::*;
        let mut k = kernel();
        let len = k.page_size;
        k.platform.refuse = 1;
        let anon = MAP_PRIVATE | MAP_ANONYMOUS;
        let p = k.syscall(nr::MMAP, [0, len, PROT_READ | PROT_EXEC, anon, u64::MAX, 0]);
        assert!(p > 0, "mmap: {p}");
        assert_eq!(k.platform.exec.last().map(|e| e.0), Some(p as u64));
        assert_eq!(k.syscall(nr::MUNMAP, [p as u64, len, 0, 0, 0, 0]), 0);
        // At a fixed address it stays, or fails.
        let at = k.syscall(nr::MMAP, [0, len, PROT_READ | PROT_WRITE, anon, u64::MAX, 0]) as u64;
        k.platform.refuse = 1;
        let r =
            k.syscall(nr::MMAP, [at, len, PROT_READ | PROT_EXEC, anon | MAP_FIXED, u64::MAX, 0]);
        assert_eq!(r, err(errno::ENOMEM));
        let _ = k.syscall(nr::MUNMAP, [at, len, 0, 0, 0, 0]);
    }

    /// `mremap`: checked as Linux checks it; a range grows in place with
    /// its contents, or moves with them (`MREMAP_MAYMOVE`, or to a place
    /// asked for with `MREMAP_FIXED`), the grown part zero.
    #[test]
    fn mappings_grow_and_move_with_their_contents() {
        let _mapping = mapping_lock();
        use fwe_abi::mman::*;
        let mut k = kernel();
        let page = k.page_size;
        let anon = MAP_PRIVATE | MAP_ANONYMOUS;
        let rw = PROT_READ | PROT_WRITE;
        let p = k.syscall(nr::MMAP, [0, 2 * page, rw, anon, u64::MAX, 0]) as u64;
        // SAFETY: the two pages just mapped.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0x5a, 2 * page as usize) };
        let mut remap = |a: [u64; 5]| k.syscall(nr::MREMAP, [a[0], a[1], a[2], a[3], a[4], 0]);
        assert_eq!(remap([p + 1, page, page, 0, 0]), err(errno::EINVAL));
        assert_eq!(remap([p, page, page, MREMAP_FIXED, p + 8 * page]), err(errno::EINVAL));
        assert_eq!(
            remap([p, 2 * page, 2 * page, MREMAP_MAYMOVE | MREMAP_FIXED, p + page]),
            err(errno::EINVAL)
        );
        let q = remap([p, 2 * page, 4 * page, MREMAP_MAYMOVE, 0]) as u64;
        assert!(q as i64 > 0, "mremap: {}", q as i64);
        // SAFETY: the four pages it now has.
        let bytes = unsafe { std::slice::from_raw_parts(q as *const u8, 4 * page as usize) };
        assert!(bytes[..2 * page as usize].iter().all(|&b| b == 0x5a));
        assert!(bytes[2 * page as usize..].iter().all(|&b| b == 0));
        // Moved where asked, the old place no longer mapped.
        let to = k.syscall(nr::MMAP, [0, 4 * page, rw, anon, u64::MAX, 0]) as u64;
        let mut remap = |a: [u64; 5]| k.syscall(nr::MREMAP, [a[0], a[1], a[2], a[3], a[4], 0]);
        assert_eq!(remap([q, 4 * page, 4 * page, MREMAP_MAYMOVE | MREMAP_FIXED, to]), to as i64);
        // SAFETY: the first page at its new place.
        assert_eq!(unsafe { *(to as *const u8) }, 0x5a);
        assert_eq!(remap([q, page, page, MREMAP_MAYMOVE, 0]), err(errno::EFAULT));
        let _ = k.syscall(nr::MUNMAP, [to, 4 * page, 0, 0, 0, 0]);
    }

    /// A process descriptor: refused for what names no process or with
    /// flags Linux lacks; one of this process, non-blocking as asked, has
    /// not ended, and reads as pidfs shows one.
    #[test]
    fn process_descriptors_are_checked() {
        use fwe_abi::pidfd::PIDFD_NONBLOCK;
        let mut k = kernel();
        let mut call = |n: u64, a: [u64; 4]| k.syscall(n, [a[0], a[1], a[2], a[3], 0, 0]);
        assert_eq!(call(nr::PIDFD_OPEN, [-1i64 as u64, 0, 0, 0]), err(errno::EINVAL));
        assert_eq!(call(nr::PIDFD_OPEN, [1, 1, 0, 0]), err(errno::EINVAL));
        assert_eq!(call(nr::PIDFD_SEND_SIGNAL, [0, 0, 0, 8]), err(errno::EINVAL));
        assert_eq!(call(nr::PIDFD_SEND_SIGNAL, [0, 0, 0, 3]), err(errno::EINVAL));
        assert_eq!(call(nr::PIDFD_GETFD, [0, 0, 1, 0]), err(errno::EINVAL));
        #[cfg(target_os = "macos")]
        {
            let fd = call(nr::PIDFD_OPEN, [u64::from(std::process::id()), PIDFD_NONBLOCK, 0, 0]);
            assert!(fd >= 0, "pidfd_open: {fd}");
            assert!(!crate::pidfd::ended(fd as i32));
            let fl = call(nr::FCNTL, [fd as u64, fcntl::F_GETFL, 0, 0]) as u64;
            assert_eq!(fl, fcntl::O_RDWR | fcntl::O_NONBLOCK);
            assert_eq!(call(nr::FCNTL, [fd as u64, fcntl::F_SETFL, 0, 0]), 0);
            assert_eq!(call(nr::FCNTL, [fd as u64, fcntl::F_GETFL, 0, 0]) as u64, fcntl::O_RDWR);
            // Not a process descriptor: a waitid on it names nothing.
            assert_eq!(crate::pidfd::wait_target(0), Err(errno::EBADF));
            assert_eq!(
                crate::pidfd::wait_target(fd as i32),
                Ok((std::process::id() as i32, false))
            );
            assert_eq!(call(nr::CLOSE, [fd as u64, 0, 0, 0]), 0);
        }
        let _ = PIDFD_NONBLOCK;
    }

    /// `prctl`'s options that take no further arguments refuse them, and
    /// the transparent-huge-page choice and speculation controls answer
    /// as Linux does.
    #[test]
    fn prctl_arguments_are_checked() {
        use fwe_abi::prctl::*;
        let mut k = kernel();
        let mut call = |a: [u64; 5]| k.syscall(nr::PRCTL, [a[0], a[1], a[2], a[3], a[4], 0]);
        assert_eq!(call([PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0]), err(errno::EINVAL));
        assert_eq!(call([PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0]), err(errno::EINVAL));
        assert_eq!(call([PR_SET_THP_DISABLE, 1, 0, 0, 0]), 0);
        assert_eq!(call([PR_GET_THP_DISABLE, 0, 0, 0, 0]), 1);
        assert_eq!(call([PR_GET_THP_DISABLE, 1, 0, 0, 0]), err(errno::EINVAL));
        assert_eq!(call([PR_SET_THP_DISABLE, 0, 0, 0, 0]), 0);
        assert_eq!(call([PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0]), 0);
        assert_eq!(call([PR_GET_SPECULATION_CTRL, 0, 1, 0, 0]), err(errno::EINVAL));
        assert_eq!(call([PR_GET_SPECULATION_CTRL, 9, 0, 0, 0]), err(errno::ENODEV));
        assert_eq!(call([PR_SET_SPECULATION_CTRL, 0, 0, 0, 0]), err(errno::ENXIO));
    }
}
