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

impl<P: Platform> Kernel<P> {
    pub(crate) fn dispatch(&mut self, n: u64, a: [u64; 6]) -> i64 {
        if let Err(e) = crate::fdtable::check_args(n, &a) {
            return e;
        }
        match n {
            // Files and I/O.
            nr::READ => {
                // SAFETY: the host validates the guest buffer.
                ret(unsafe { libc::read(a[0] as i32, a[1] as *mut _, a[2] as usize) } as i64)
            }
            nr::WRITE => {
                // SAFETY: the host validates the guest buffer.
                ret(unsafe { libc::write(a[0] as i32, a[1] as *const _, a[2] as usize) } as i64)
            }
            nr::READV => {
                let iov = guest!(uaccess::host_iovecs(a[1], a[2]));
                // SAFETY: the iovecs are translated host buffers; the host checks them.
                ret(unsafe { libc::readv(a[0] as i32, iov.as_ptr(), iov.len() as i32) } as i64)
            }
            nr::WRITEV => {
                let iov = guest!(uaccess::host_iovecs(a[1], a[2]));
                // SAFETY: the iovecs are translated host buffers; the host checks them.
                ret(unsafe { libc::writev(a[0] as i32, iov.as_ptr(), iov.len() as i32) } as i64)
            }
            nr::PREAD64 => {
                // SAFETY: the host validates the guest buffer.
                ret(unsafe {
                    libc::pread(a[0] as i32, a[1] as *mut _, a[2] as usize, a[3] as libc::off_t)
                } as i64)
            }
            nr::PWRITE64 => {
                // SAFETY: the host validates the guest buffer.
                ret(unsafe {
                    libc::pwrite(a[0] as i32, a[1] as *const _, a[2] as usize, a[3] as libc::off_t)
                } as i64)
            }
            nr::LSEEK => {
                if let Some(r) = crate::synthdir::lseek(a[0] as i32, a[1] as i64, a[2] as i32) {
                    r
                } else {
                    // SAFETY: plain host call; SEEK_SET/CUR/END match.
                    ret(unsafe { libc::lseek(a[0] as i32, a[1] as libc::off_t, a[2] as i32) })
                }
            }
            nr::CLOSE => {
                let fd = a[0] as i32;
                crate::epoll::closed(fd);
                if let Some(r) = crate::specialfd::try_close(fd) {
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
                ret(unsafe { libc::dup(a[0] as i32) })
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
            // SAFETY: socket takes no pointers.
            nr::SOCKET => unsafe { crate::net::socket(a[0], a[1], a[2]) },
            // SAFETY: the sv pointer is validated by the host/impl.
            nr::SOCKETPAIR => unsafe { crate::net::socketpair(a[0], a[1], a[2], a[3]) },
            // SAFETY: the sockaddr pointer is validated by the host/impl.
            nr::BIND => unsafe { crate::net::bind(a[0], a[1], a[2]) },
            // SAFETY: no pointers.
            nr::LISTEN => unsafe { crate::net::listen(a[0], a[1]) },
            // SAFETY: the out pointers are validated by the host/impl.
            nr::GETSOCKNAME => unsafe { crate::net::getname(a[0], a[1], a[2], false) },
            // SAFETY: the out pointers are validated by the host/impl.
            nr::GETPEERNAME => unsafe { crate::net::getname(a[0], a[1], a[2], true) },
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
            nr::FSTAT => self.sys_fstat(a[0], a[1]),
            nr::STATX => self.sys_statx(a[0], a[1], a[2], a[3], a[4]),
            nr::GETDENTS64 => self.sys_getdents64(a[0], a[1], a[2]),
            nr::GETCWD => self.sys_getcwd(a[0], a[1]),
            nr::CHDIR => self.sys_chdir(a[0]),
            nr::FCHDIR => self.sys_fchdir(a[0]),
            nr::READLINKAT => self.sys_readlinkat(a[0], a[1], a[2], a[3]),
            nr::MKDIRAT => self.sys_mkdirat(a[0], a[1], a[2]),
            nr::UNLINKAT => self.sys_unlinkat(a[0], a[1], a[2]),
            // arm64 keeps the flagless form, which glibc's `rename` uses.
            nr::RENAMEAT => self.sys_renameat2(a[0], a[1], a[2], a[3], 0),
            nr::RENAMEAT2 => self.sys_renameat2(a[0], a[1], a[2], a[3], a[4]),
            nr::SYMLINKAT => self.sys_symlinkat(a[0], a[1], a[2]),
            nr::LINKAT => self.sys_linkat(a[0], a[1], a[2], a[3], a[4]),
            nr::FCHMODAT => self.sys_fchmodat(a[0], a[1], a[2], 0),
            nr::FCHMOD => {
                // SAFETY: plain host call on a guest fd.
                ret(unsafe { libc::fchmod(a[0] as i32, a[1] as libc::mode_t) })
            }
            nr::FCHOWNAT => self.sys_fchownat(a[0], a[1], a[2], a[3], a[4]),
            // Ownership is virtual: honor the guest's credentials rather than
            // changing the backing host file (fwe does not run as root).
            nr::FCHOWN => self.chown_check(a[1] as u32, a[2] as u32),
            nr::TRUNCATE => self.sys_truncate(a[0], a[1]),
            nr::FTRUNCATE => self.sys_ftruncate(a[0], a[1]),
            nr::UMASK => self.sys_umask(a[0]),
            nr::PIPE2 => self.sys_pipe2(a[0], a[1]),
            nr::UTIMENSAT => self.sys_utimensat(a[0], a[1], a[2], a[3]),
            nr::FSYNC => {
                // SAFETY: plain host call on a guest fd.
                ret(unsafe { libc::fsync(a[0] as i32) })
            }
            nr::FDATASYNC => {
                // SAFETY: plain host call on a guest fd.
                ret(unsafe { libc::fsync(a[0] as i32) })
            }

            // Memory.
            nr::BRK => self.sys_brk(a[0]),
            nr::MMAP => self.sys_mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
            nr::MUNMAP => self.sys_munmap(a[0], a[1]),
            nr::MPROTECT => self.sys_mprotect(a[0], a[1], a[2]),
            nr::MADVISE => self.sys_madvise(a[0], a[1], a[2]),
            nr::MREMAP => self.sys_mremap(a[0], a[1], a[2], a[3]),

            // Process and thread identity.
            nr::EXIT_GROUP => self.platform.exit(a[0] as i32),
            nr::EXIT => {
                self.thread_cleanup();
                self.platform.exit_thread(a[0] as i32)
            }
            // Job control / sessions. These act on host process groups and
            // sessions; a guest "pid" of 0 (self) always works, and child pids
            // from fork are host pids, so setpgid(child, ...) works too.
            // SAFETY: plain host calls.
            nr::SETPGID => ret(unsafe { libc::setpgid(a[0] as libc::pid_t, a[1] as libc::pid_t) }),
            // SAFETY: plain host call.
            nr::GETPGID => ret(unsafe { libc::getpgid(a[0] as libc::pid_t) } as i64),
            // SAFETY: plain host call.
            nr::GETSID => ret(unsafe { libc::getsid(a[0] as libc::pid_t) } as i64),
            // SAFETY: plain host call.
            nr::SETSID => ret(unsafe { libc::setsid() } as i64),
            nr::GETPID => thread::tgid() as i64,
            nr::GETTID => thread::tid() as i64,
            nr::GETPPID => host::getppid(),
            // Virtual credentials (see crates/kernel/src/creds.rs).
            nr::GETUID => self.creds.getuid(),
            nr::GETEUID => self.creds.geteuid(),
            nr::GETGID => self.creds.getgid(),
            nr::GETEGID => self.creds.getegid(),
            nr::SETUID => self.creds.setuid(a[0] as u32),
            nr::SETREUID => self.creds.setreuid(a[0] as u32, a[1] as u32),
            nr::SETRESUID => self.creds.setresuid(a[0] as u32, a[1] as u32, a[2] as u32),
            nr::SETFSUID => self.creds.setfsuid(a[0] as u32),
            nr::GETRESUID => self.sys_getresuid(a[0], a[1], a[2]),
            nr::SETGID => self.creds.setgid(a[0] as u32),
            nr::SETREGID => self.creds.setregid(a[0] as u32, a[1] as u32),
            nr::SETRESGID => self.creds.setresgid(a[0] as u32, a[1] as u32, a[2] as u32),
            nr::SETFSGID => self.creds.setfsgid(a[0] as u32),
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
            nr::UNAME => self.sys_uname(a[0]),
            nr::SCHED_YIELD => {
                std::thread::yield_now();
                0
            }
            nr::SCHED_GETAFFINITY => self.sys_sched_getaffinity(a[0], a[1], a[2]),
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
            nr::SETITIMER => {
                // SAFETY: `struct itimerval` has the same layout and timer
                // numbers on both hosts; the host validates the pointers.
                ret(unsafe { libc::setitimer(a[0] as i32, a[1] as *const _, a[2] as *mut _) })
            }
            nr::GETITIMER => {
                // SAFETY: as for setitimer.
                ret(unsafe { libc::getitimer(a[0] as i32, a[1] as *mut _) })
            }

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
        if self.creds.euid == 0 { 0 } else { err(errno::EPERM) }
    }

    fn sys_getresuid(&self, rp: u64, ep: u64, sp: u64) -> i64 {
        if rp == 0 || ep == 0 || sp == 0 {
            return err(errno::EFAULT);
        }
        let (r, e, s) = self.creds.resuid();
        guest!(uaccess::write(rp, r));
        guest!(uaccess::write(ep, e));
        guest!(uaccess::write(sp, s));
        0
    }

    fn sys_getresgid(&self, rp: u64, ep: u64, sp: u64) -> i64 {
        if rp == 0 || ep == 0 || sp == 0 {
            return err(errno::EFAULT);
        }
        let (r, e, s) = self.creds.resgid();
        guest!(uaccess::write(rp, r));
        guest!(uaccess::write(ep, e));
        guest!(uaccess::write(sp, s));
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
            guest!(uaccess::write(list + (i * 4) as u64, g));
        }
        n as i64
    }

    fn sys_setgroups(&mut self, size: u64, list: u64) -> i64 {
        let n = size as usize;
        if n > 65536 {
            return err(errno::EINVAL);
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(guest!(uaccess::read::<u32>(list + (i * 4) as u64)));
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
        // SAFETY: every arm is a plain host call on a guest descriptor.
        unsafe {
            match cmd {
                fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC
                    if !crate::fdtable::guest_visible(arg as i32) =>
                {
                    err(errno::EINVAL)
                }
                fcntl::F_DUPFD => ret(libc::fcntl(fd, libc::F_DUPFD, arg as i32)),
                fcntl::F_DUPFD_CLOEXEC => ret(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, arg as i32)),
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
                    if r < 0 { last_error() } else { host::status_flags_to_linux(r) as i64 }
                }
                fcntl::F_SETFL => {
                    ret(libc::fcntl(fd, libc::F_SETFL, host::settable_flags_to_host(arg)))
                }
                fcntl::F_GETLK => {
                    let lock: fwe_abi::Flock = guest!(uaccess::read(arg));
                    let mut lock = match host::flock_to_host(&lock) {
                        Ok(l) => l,
                        Err(e) => return err(e),
                    };
                    if libc::fcntl(fd, libc::F_GETLK, &mut lock) < 0 {
                        return last_error();
                    }
                    guest!(uaccess::write(arg, host::flock_to_linux(&lock)));
                    0
                }
                fcntl::F_SETLK | fcntl::F_SETLKW => set_record_lock(fd, cmd, arg),
                _ => err(errno::EINVAL),
            }
        }
    }

    fn sys_ioctl(&mut self, fd: u64, req: u64, arg: u64) -> i64 {
        let fd = fd as i32;
        // SAFETY: in every arm the argument layouts match the host's; the host
        // validates guest pointers.
        unsafe {
            match req {
                ioctl::TIOCGWINSZ => {
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) < 0 {
                        return last_error();
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
                    guest!(uaccess::write(arg, pg));
                    0
                }
                ioctl::TIOCSPGRP => {
                    let pg: i32 = guest!(uaccess::read(arg));
                    ret(libc::tcsetpgrp(fd, pg))
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
        let mut host = [0u8; 256];
        // SAFETY: `host` is a valid buffer of its length.
        if unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) } == 0 {
            let end = host.iter().position(|&c| c == 0).unwrap_or(host.len());
            fill(&mut u.nodename, &host[..end]);
        }
        fill(&mut u.release, RELEASE.as_bytes());
        fill(&mut u.version, b"#1 SMP PREEMPT");
        fill(&mut u.machine, b"aarch64");
        fill(&mut u.domainname, b"(none)");
        guest!(uaccess::write(buf, u));
        0
    }

    fn sys_sched_getaffinity(&mut self, pid: u64, len: u64, mask: u64) -> i64 {
        // SAFETY: plain host call.
        if pid != 0 && pid as i32 != unsafe { libc::getpid() } {
            return err(errno::ESRCH);
        }
        // SAFETY: plain host call.
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as u64;
        let size = cpus.div_ceil(64) * 8;
        if len < size || len % 8 != 0 {
            return err(errno::EINVAL);
        }
        for word in 0..size / 8 {
            let bits = (cpus - word * 64).min(64);
            let value = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
            guest!(uaccess::write(mask + word * 8, value));
        }
        size as i64
    }

    fn sys_prlimit(&mut self, pid: u64, res: u64, new: u64, old: u64) -> i64 {
        // SAFETY: plain host call.
        if pid != 0 && pid as i32 != unsafe { libc::getpid() } {
            return err(errno::ESRCH);
        }
        if res >= resource::RLIM_NLIMITS {
            return err(errno::EINVAL);
        }
        if res == resource::RLIMIT_NOFILE {
            // Virtual: the host's limit also covers fwe's own descriptors.
            let (cur, max) = crate::fdtable::limit();
            if old != 0 {
                guest!(uaccess::write(old, Rlimit { rlim_cur: cur, rlim_max: max }));
            }
            if new != 0 {
                let n: Rlimit = guest!(uaccess::read(new));
                if let Err(e) = crate::fdtable::set_limit(n.rlim_cur, n.rlim_max) {
                    return err(e);
                }
            }
            return 0;
        }
        let Some(hres) = host::rlimit_to_host(res) else {
            // Limits the host does not have: report Linux defaults.
            if old != 0 {
                let v = match res {
                    resource::RLIMIT_SIGPENDING => 63_432,
                    resource::RLIMIT_MSGQUEUE => 819_200,
                    resource::RLIMIT_NICE | resource::RLIMIT_RTPRIO => 0,
                    _ => resource::RLIM_INFINITY,
                };
                guest!(uaccess::write(old, Rlimit { rlim_cur: v, rlim_max: v }));
            }
            return 0;
        };
        if old != 0 {
            let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: `r` is a valid out-parameter.
            if unsafe { libc::getrlimit(hres as _, &mut r) } != 0 {
                return last_error();
            }
            let value = Rlimit {
                rlim_cur: host::rlim_to_linux(r.rlim_cur),
                rlim_max: host::rlim_to_linux(r.rlim_max),
            };
            guest!(uaccess::write(old, value));
        }
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

    fn sys_clock_gettime(&mut self, id: u64, tp: u64) -> i64 {
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
        let Some(hid) = host::clock_to_host(id) else {
            return err(errno::EINVAL);
        };
        if tp == 0 {
            return 0;
        }
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid out-parameter.
        if unsafe { libc::clock_getres(hid, &mut ts) } != 0 {
            return last_error();
        }
        guest!(uaccess::write(tp, Timespec { tv_sec: ts.tv_sec, tv_nsec: ts.tv_nsec }));
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
pub(crate) unsafe fn ppoll(fds: u64, nfds: u64, timeout: u64) -> i64 {
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
    // SAFETY: `struct pollfd` and the POLL* bits match the host's; the host
    // validates the guest array.
    ret(unsafe { libc::poll(fds as *mut libc::pollfd, nfds as libc::nfds_t, ms) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Tracer};

    struct TestPlatform {
        exec: Vec<(u64, u64)>,
    }

    impl Platform for TestPlatform {
        fn prepare_exec(&mut self, addr: u64, len: u64) -> Result<(), i32> {
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
