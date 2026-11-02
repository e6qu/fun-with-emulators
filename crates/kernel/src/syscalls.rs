//! System call dispatch and the non-memory system calls.

use crate::host::{self, last_error, ret};
use crate::{Kernel, Platform, thread};
use fwe_abi::{
    Pollfd, Rlimit, Sigaction, Stack, Timespec, UTSNAME_LEN, Utsname, Winsize, clock, err, errno,
    fcntl, ioctl, nr, resource, signal,
};
use std::mem::size_of;

/// Kernel release reported by `uname`.
pub const RELEASE: &str = "6.12.0-fwe";

/// Read a value from guest memory.
///
/// # Safety
/// `addr` must point to readable guest memory holding a `T`.
unsafe fn read<T: Copy>(addr: u64) -> T {
    // SAFETY: guaranteed by the caller.
    unsafe { (addr as *const T).read_unaligned() }
}

/// Write a value to guest memory.
///
/// # Safety
/// `addr` must point to writable guest memory with room for a `T`.
unsafe fn write<T: Copy>(addr: u64, value: T) {
    // SAFETY: guaranteed by the caller.
    unsafe { (addr as *mut T).write_unaligned(value) }
}

fn fill(field: &mut [u8; UTSNAME_LEN], s: &[u8]) {
    let n = s.len().min(UTSNAME_LEN - 1);
    field[..n].copy_from_slice(&s[..n]);
}

/// `clock_nanosleep`, as a free function so the backend can run it without
/// the kernel lock (it blocks).
///
/// # Safety
/// `req` and, when non-zero, `rem` must point to valid guest `Timespec`s.
pub(crate) unsafe fn clock_nanosleep(id: u64, flags: u64, req: u64, rem: u64) -> i64 {
    const TIMER_ABSTIME: u64 = 1;
    if matches!(id, clock::CLOCK_THREAD_CPUTIME_ID) {
        return err(errno::EINVAL);
    }
    let Some(hid) = host::clock_to_host(id) else {
        return err(errno::EINVAL);
    };
    // SAFETY: the caller guarantees a valid request pointer.
    let mut ts: Timespec = unsafe { read(req) };
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
        // SAFETY: the caller guarantees a valid remain buffer.
        unsafe { write(rem, Timespec { tv_sec: left.tv_sec, tv_nsec: left.tv_nsec }) };
    }
    e
}

impl<P: Platform> Kernel<P> {
    pub(crate) fn dispatch(&mut self, n: u64, a: [u64; 6]) -> i64 {
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
                // SAFETY: `struct iovec` has the same layout; the host validates it.
                ret(unsafe { libc::readv(a[0] as i32, a[1] as *const _, a[2] as i32) } as i64)
            }
            nr::WRITEV => {
                // SAFETY: `struct iovec` has the same layout; the host validates it.
                ret(unsafe { libc::writev(a[0] as i32, a[1] as *const _, a[2] as i32) } as i64)
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
                // SAFETY: plain host call; SEEK_SET/CUR/END match.
                ret(unsafe { libc::lseek(a[0] as i32, a[1] as libc::off_t, a[2] as i32) })
            }
            nr::CLOSE => match crate::specialfd::try_close(a[0] as i32) {
                Some(r) => r,
                // SAFETY: plain host call.
                None => ret(unsafe { libc::close(a[0] as i32) }),
            },
            nr::DUP => {
                // SAFETY: plain host call.
                ret(unsafe { libc::dup(a[0] as i32) })
            }
            nr::DUP3 => self.sys_dup3(a[0], a[1], a[2]),
            nr::FCNTL => self.sys_fcntl(a[0], a[1], a[2]),
            nr::IOCTL => self.sys_ioctl(a[0], a[1], a[2]),
            nr::PPOLL => self.sys_ppoll(a[0], a[1], a[2]),
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
            nr::RENAMEAT2 => self.sys_renameat2(a[0], a[1], a[2], a[3], a[4]),
            nr::SYMLINKAT => self.sys_symlinkat(a[0], a[1], a[2]),
            nr::LINKAT => self.sys_linkat(a[0], a[1], a[2], a[3], a[4]),
            nr::FCHMODAT => self.sys_fchmodat(a[0], a[1], a[2], 0),
            nr::FCHMOD => {
                // SAFETY: plain host call on a guest fd.
                ret(unsafe { libc::fchmod(a[0] as i32, a[1] as libc::mode_t) })
            }
            nr::FCHOWNAT => self.sys_fchownat(a[0], a[1], a[2], a[3], a[4]),
            nr::FCHOWN => {
                // SAFETY: plain host call on a guest fd.
                ret(unsafe { libc::fchown(a[0] as i32, a[1] as libc::uid_t, a[2] as libc::gid_t) })
            }
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
            nr::GETPID => thread::tgid() as i64,
            nr::GETTID => thread::tid() as i64,
            nr::GETPPID => host::getppid(),
            nr::GETUID => host::ids().0,
            nr::GETEUID => host::ids().1,
            nr::GETGID => host::ids().2,
            nr::GETEGID => host::ids().3,
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
                // `struct rusage` is 144 bytes on arm64; report it zeroed.
                if a[1] != 0 {
                    // SAFETY: the guest passed a buffer for a `struct rusage`.
                    unsafe { std::ptr::write_bytes(a[1] as *mut u8, 0, 144) };
                }
                0
            }
            nr::PRLIMIT64 => self.sys_prlimit(a[0], a[1], a[2], a[3]),
            nr::GETRLIMIT => self.sys_prlimit(0, a[0], 0, a[1]),
            nr::SETRLIMIT => self.sys_prlimit(0, a[0], a[1], 0),

            // Time.
            nr::CLOCK_GETTIME => self.sys_clock_gettime(a[0], a[1]),
            nr::CLOCK_GETRES => self.sys_clock_getres(a[0], a[1]),
            nr::GETTIMEOFDAY => {
                // SAFETY: `struct timeval` has the same layout on both 64-bit ABIs.
                ret(unsafe { libc::gettimeofday(a[0] as *mut _, std::ptr::null_mut()) })
            }
            nr::NANOSLEEP => {
                // SAFETY: `struct timespec` has the same layout; the host validates it.
                ret(unsafe { libc::nanosleep(a[0] as *const _, a[1] as *mut _) })
            }
            nr::CLOCK_NANOSLEEP => self.sys_clock_nanosleep(a[0], a[1], a[2], a[3]),

            // Signals.
            nr::RT_SIGACTION => self.sys_rt_sigaction(a[0], a[1], a[2], a[3]),
            nr::RT_SIGPROCMASK => self.sys_rt_sigprocmask(a[0], a[1], a[2], a[3]),
            nr::SIGALTSTACK => self.sys_sigaltstack(a[0], a[1]),
            nr::KILL => self.sys_kill_self(a[0] as i64, a[1]),
            nr::TKILL => self.sys_kill_self(0, a[1]),
            nr::TGKILL => self.sys_kill_self(a[0] as i64, a[2]),

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

    fn sys_dup3(&mut self, old: u64, new: u64, flags: u64) -> i64 {
        if old == new || flags & !fcntl::O_CLOEXEC != 0 {
            return err(errno::EINVAL);
        }
        // SAFETY: plain host calls.
        let r = unsafe { libc::dup2(old as i32, new as i32) };
        if r >= 0 && flags & fcntl::O_CLOEXEC != 0 {
            // SAFETY: plain host call on the descriptor just created.
            unsafe { libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        ret(r)
    }

    fn sys_fcntl(&mut self, fd: u64, cmd: u64, arg: u64) -> i64 {
        let fd = fd as i32;
        // SAFETY: every arm is a plain host call on a guest descriptor.
        unsafe {
            match cmd {
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
                    write(
                        arg,
                        Winsize {
                            ws_row: ws.ws_row,
                            ws_col: ws.ws_col,
                            ws_xpixel: ws.ws_xpixel,
                            ws_ypixel: ws.ws_ypixel,
                        },
                    );
                    0
                }
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
        const _: () = assert!(size_of::<Pollfd>() == size_of::<libc::pollfd>());
        let ms = if timeout == 0 {
            -1
        } else {
            // SAFETY: the guest passed a pointer to its timeout.
            let ts: Timespec = unsafe { read(timeout) };
            if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
                return err(errno::EINVAL);
            }
            let ms =
                ts.tv_sec.saturating_mul(1000).saturating_add((ts.tv_nsec + 999_999) / 1_000_000);
            ms.min(i32::MAX as i64) as i32
        };
        // SAFETY: `struct pollfd` and the POLL* bits match the host's; the host
        // validates the guest array.
        ret(unsafe { libc::poll(fds as *mut libc::pollfd, nfds as libc::nfds_t, ms) })
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
        // SAFETY: the guest passed a buffer for a `struct new_utsname`.
        unsafe { write(buf, u) };
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
            // SAFETY: the guest passed a buffer of `len >= size` bytes.
            unsafe { write(mask + word * 8, value) };
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
        let Some(hres) = host::rlimit_to_host(res) else {
            // Limits the host does not have: report Linux defaults.
            if old != 0 {
                let v = match res {
                    resource::RLIMIT_SIGPENDING => 63_432,
                    resource::RLIMIT_MSGQUEUE => 819_200,
                    resource::RLIMIT_NICE | resource::RLIMIT_RTPRIO => 0,
                    _ => resource::RLIM_INFINITY,
                };
                // SAFETY: the guest passed a buffer for a `struct rlimit64`.
                unsafe { write(old, Rlimit { rlim_cur: v, rlim_max: v }) };
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
            // SAFETY: the guest passed a buffer for a `struct rlimit64`.
            unsafe { write(old, value) };
        }
        if new != 0 {
            // SAFETY: the guest passed a pointer to a `struct rlimit64`.
            let n: Rlimit = unsafe { read(new) };
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
        // SAFETY: `struct timespec` has the same layout; the host validates it.
        ret(unsafe { libc::clock_gettime(hid, tp as *mut libc::timespec) })
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
        // SAFETY: `struct timespec` has the same layout; the host validates it.
        ret(unsafe { libc::clock_getres(hid, tp as *mut libc::timespec) })
    }

    fn sys_rt_sigaction(&mut self, sig: u64, act: u64, old: u64, size: u64) -> i64 {
        if size != signal::SIGSET_SIZE || sig == 0 || sig > signal::NSIG {
            return err(errno::EINVAL);
        }
        let slot = (sig - 1) as usize;
        if old != 0 {
            // SAFETY: the guest passed a buffer for a `struct sigaction`.
            unsafe { write(old, self.sigactions[slot]) };
        }
        if act != 0 {
            if sig == signal::SIGKILL || sig == signal::SIGSTOP {
                return err(errno::EINVAL);
            }
            // SAFETY: the guest passed a pointer to a `struct sigaction`.
            self.sigactions[slot] = unsafe { read::<Sigaction>(act) };
        }
        0
    }

    fn sys_rt_sigprocmask(&mut self, how: u64, set: u64, old: u64, size: u64) -> i64 {
        if size != signal::SIGSET_SIZE {
            return err(errno::EINVAL);
        }
        let previous = self.sigmask;
        if set != 0 {
            // SAFETY: the guest passed a pointer to a `sigset_t`.
            let s: u64 = unsafe { read(set) };
            let unblockable = (1 << (signal::SIGKILL - 1)) | (1 << (signal::SIGSTOP - 1));
            self.sigmask = match how {
                signal::SIG_BLOCK => previous | s,
                signal::SIG_UNBLOCK => previous & !s,
                signal::SIG_SETMASK => s,
                _ => return err(errno::EINVAL),
            } & !unblockable;
        }
        if old != 0 {
            // SAFETY: the guest passed a buffer for a `sigset_t`.
            unsafe { write(old, previous) };
        }
        0
    }

    fn sys_sigaltstack(&mut self, ss: u64, old: u64) -> i64 {
        if old != 0 {
            // SAFETY: the guest passed a buffer for a `stack_t`.
            unsafe { write(old, self.altstack) };
        }
        if ss != 0 {
            // SAFETY: the guest passed a pointer to a `stack_t`.
            let s: Stack = unsafe { read(ss) };
            if s.ss_flags & !libc::SS_DISABLE != 0 {
                return err(errno::EINVAL);
            }
            if s.ss_flags & libc::SS_DISABLE == 0 && s.ss_size < signal::MINSIGSTKSZ {
                return err(errno::ENOMEM);
            }
            self.altstack = s;
        }
        0
    }

    /// `kill`, `tkill` and `tgkill` aimed at the calling process.
    fn sys_kill_self(&mut self, pid: i64, sig: u64) -> i64 {
        // SAFETY: plain host call.
        let me = unsafe { libc::getpid() } as i64;
        if pid != 0 && pid != me {
            return err(errno::ESRCH);
        }
        if sig == 0 {
            return 0;
        }
        if sig > signal::NSIG {
            return err(errno::EINVAL);
        }
        // SIGKILL and SIGSTOP cannot be caught; act now.
        if sig == signal::SIGKILL {
            self.terminate_by(sig);
        }
        // Record it; delivery happens on return to the guest, after this
        // system call, in `deliver_pending`.
        self.raise_pending(sig);
        0
    }

    fn sys_getrandom(&mut self, buf: u64, len: u64) -> i64 {
        let len = len.min(i32::MAX as u64) as usize;
        // SAFETY: the guest passed a buffer of `len` bytes.
        let out = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, len) };
        host::fill_random(out);
        len as i64
    }
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
