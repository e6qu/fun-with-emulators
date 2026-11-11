//! The guest's view of the descriptor table.
//!
//! Guest descriptors are host descriptors, but fwe holds some for itself —
//! the root filesystem directory, the pipe ends behind eventfd and signalfd,
//! the pipe a `vfork` parent waits on, and in the VM backend the file of
//! each file mapping. Those live in a reserved range at the top of the
//! host's descriptor space, above the highest number the guest may use: the
//! guest's `RLIMIT_NOFILE` is virtual.
//! Loops that close everything up to the limit, `close_range`, and
//! `/proc/self/fd` never reach the reserved range, and a system call naming
//! a descriptor there fails with `EBADF`, as for a descriptor that is not
//! open. A descriptor of fwe's never goes below the range: when it is full,
//! what needed one fails. The limit may be raised past the range, up to
//! `fs.nr_open`, as Linux allows; the descriptors the guest gets stay below
//! it.

use fwe_abi::resource::RLIM_INFINITY;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};

/// The least number of descriptors kept for fwe's own use, above the
/// guest's range; it takes a quarter of the host's descriptors when there
/// are more ([`init`]).
pub const RESERVED: i32 = 64;

/// The first descriptor the guest may not use (the guest's hard limit).
static GUEST_MAX: AtomicI32 = AtomicI32::new(1024);
/// The guest's virtual `RLIMIT_NOFILE`.
static LIMIT: Mutex<(u64, u64)> = Mutex::new((1024, 1024));
/// Where the next reserved descriptor is looked for.
static NEXT: AtomicI32 = AtomicI32::new(0);

/// The guest's default soft limit, Linux's.
const DEFAULT_SOFT: u64 = 1024;

#[cfg(target_os = "macos")]
fn max_files_per_proc() -> u64 {
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>();
    // SAFETY: reading an int sysctl into a correctly sized buffer.
    let r = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r == 0 && v > 0 { v as u64 } else { 10240 }
}

#[cfg(not(target_os = "macos"))]
fn max_files_per_proc() -> u64 {
    1 << 20
}

/// Raise the host's soft descriptor limit as far as it goes and place the
/// guest's range below it. Called once at startup, before any descriptor is
/// reserved.
pub fn init() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `lim` is a valid out-parameter.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    let cap = lim.rlim_max.min(max_files_per_proc()).min(1 << 20);
    // macOS may refuse a soft limit above OPEN_MAX (10240) however high the
    // hard limit is; settle for the largest it accepts.
    for want in [cap, 10240, 4096, 2048, 1024 + RESERVED as u64] {
        if want > cap || want <= lim.rlim_cur {
            continue;
        }
        let new = libc::rlimit { rlim_cur: want, rlim_max: lim.rlim_max };
        // SAFETY: a valid in-parameter; failure keeps the current limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
            lim.rlim_cur = want;
            break;
        }
    }
    // Descriptors stop at the lower of the soft limit and the per-process cap.
    let host = lim.rlim_cur.min(cap).max(2 * RESERVED as u64) as i32;
    // The guest keeps at least Linux's default soft limit.
    let reserved = (host / 4).max(RESERVED).min(host - DEFAULT_SOFT as i32).max(RESERVED);
    let guest_max = host - reserved;
    GUEST_MAX.store(guest_max, Ordering::SeqCst);
    NEXT.store(guest_max, Ordering::SeqCst);
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner()) =
        (DEFAULT_SOFT.min(guest_max as u64), guest_max as u64);
}

/// Write the descriptor-table limits into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    e.i32(GUEST_MAX.load(Ordering::SeqCst));
    e.i32(NEXT.load(Ordering::SeqCst));
    let (soft, hard) = limit();
    e.u64(soft);
    e.u64(hard);
}

/// Take the limits [`save`] wrote, in a fork child (which inherits the
/// parent's host limit, so its reserved range is the parent's).
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    GUEST_MAX.store(d.i32(), Ordering::SeqCst);
    NEXT.store(d.i32(), Ordering::SeqCst);
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner()) = (d.u64(), d.u64());
}

/// One past the highest descriptor the guest may use.
pub fn guest_max() -> i32 {
    GUEST_MAX.load(Ordering::SeqCst)
}

/// Whether `fd` names a descriptor the guest may hold: below the reserved
/// range (negative values, such as `AT_FDCWD`, are left to the call).
pub fn guest_visible(fd: i32) -> bool {
    fd < guest_max()
}

/// Move `fd` into the reserved range, close-on-exec, and return its new
/// number. If the range is full, `fd` is closed and the result is
/// `EMFILE`.
pub fn reserve(fd: i32) -> Result<i32, i32> {
    if fd < 0 {
        return Err(fwe_abi::errno::EBADF);
    }
    if !guest_visible(fd) {
        return Ok(fd);
    }
    let high = dup_reserved(fd);
    // SAFETY: closing the caller's descriptor, now moved (or not wanted).
    unsafe { libc::close(fd) };
    high
}

/// A close-on-exec duplicate of `fd`, a descriptor fwe holds only for the
/// call it is in, at the lowest free number of the reserved range (or
/// `EMFILE` when the range is full).
pub fn dup_transient(fd: i32) -> Result<i32, i32> {
    // SAFETY: plain host call on a descriptor the caller holds.
    let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, guest_max()) };
    if high < 0 { Err(fwe_abi::errno::EMFILE) } else { Ok(high) }
}

/// A close-on-exec duplicate of `fd` in the reserved range, or `EMFILE`
/// when the range is full (`EBADF` if `fd` is not open).
pub fn dup_reserved(fd: i32) -> Result<i32, i32> {
    let floor = NEXT.load(Ordering::SeqCst).max(guest_max());
    // SAFETY: plain host calls on a descriptor the caller holds.
    unsafe {
        if libc::fcntl(fd, libc::F_GETFD) < 0 {
            return Err(fwe_abi::errno::EBADF);
        }
        let mut high = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor);
        if high < 0 {
            // The range above `floor` is full; reuse any freed slot.
            high = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, guest_max());
        }
        if high < 0 {
            return Err(fwe_abi::errno::EMFILE);
        }
        NEXT.store(high + 1, Ordering::SeqCst);
        Ok(high)
    }
}

/// The guest's `RLIMIT_NOFILE` as `(soft, hard)`.
pub fn limit() -> (u64, u64) {
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner())
}

/// Set the guest's `RLIMIT_NOFILE`. Fails with `EINVAL` if soft exceeds
/// hard, and `EPERM` above the range the host leaves the guest.
pub fn set_limit(soft: u64, hard: u64) -> Result<(), i32> {
    let max = guest_max() as u64;
    let hard = if hard == RLIM_INFINITY { max } else { hard };
    let soft = if soft == RLIM_INFINITY { hard } else { soft };
    if soft > hard {
        return Err(fwe_abi::errno::EINVAL);
    }
    // Up to `fs.nr_open`, as on Linux (container runtimes set 1048576):
    // the limit is a ceiling, and descriptors are given below fwe's range
    // whatever it is.
    let nr_open = (crate::sysctl::number(b"fs/nr_open").unwrap_or(1 << 20) as u64).max(max);
    if hard > nr_open {
        return Err(fwe_abi::errno::EPERM);
    }
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner()) = (soft, hard);
    Ok(())
}

/// The guest's open descriptors, in order.
pub fn open_fds() -> Vec<i32> {
    #[cfg(target_os = "macos")]
    {
        // The host lists them in one call, where asking after each number
        // in the guest's range would take thousands.
        let size = std::mem::size_of::<libc::proc_fdinfo>();
        let mut n = 64usize;
        loop {
            // SAFETY: zeroed bytes are valid `proc_fdinfo`s.
            let mut buf: Vec<libc::proc_fdinfo> = vec![unsafe { std::mem::zeroed() }; n];
            // SAFETY: a valid out-buffer of `n` entries.
            let got = unsafe {
                libc::proc_pidinfo(
                    libc::getpid(),
                    libc::PROC_PIDLISTFDS,
                    0,
                    buf.as_mut_ptr().cast(),
                    (n * size) as i32,
                )
            };
            if got <= 0 {
                break;
            }
            let count = got as usize / size;
            if count < n {
                let mut fds: Vec<i32> = buf[..count]
                    .iter()
                    .map(|f| f.proc_fd)
                    .filter(|&fd| guest_visible(fd))
                    .collect();
                fds.sort_unstable();
                return fds;
            }
            n *= 2;
        }
    }
    (0..guest_max())
        // SAFETY: F_GETFD only queries the descriptor.
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0)
        .collect()
}

/// Whether system call `nr` takes a descriptor as its first argument, so a
/// reserved one is refused before the call runs.
pub fn first_arg_is_fd(nr: u64) -> bool {
    use fwe_abi::nr as n;
    matches!(
        nr,
        n::READ
            | n::WRITE
            | n::READV
            | n::WRITEV
            | n::PREAD64
            | n::PWRITE64
            | n::PREADV
            | n::PWRITEV
            | n::PREADV2
            | n::PWRITEV2
            | n::CLOSE
            | n::DUP
            | n::DUP3
            | n::FCNTL
            | n::IOCTL
            | n::FSTAT
            | n::LSEEK
            | n::GETDENTS64
            | n::FSYNC
            | n::FDATASYNC
            | n::SYNCFS
            | n::FTRUNCATE
            | n::FCHMOD
            | n::FCHOWN
            | n::FCHDIR
            | n::FLOCK
            | n::FSTATFS
            | n::SENDFILE
            | n::EPOLL_CTL
            | n::EPOLL_PWAIT
            | n::EPOLL_PWAIT2
            | n::BIND
            | n::CONNECT
            | n::LISTEN
            | n::ACCEPT
            | n::ACCEPT4
            | n::SENDTO
            | n::RECVFROM
            | n::SENDMSG
            | n::RECVMSG
            | n::SHUTDOWN
            | n::GETSOCKNAME
            | n::GETPEERNAME
            | n::SETSOCKOPT
            | n::GETSOCKOPT
            | n::OPENAT
            | n::OPENAT2
            | n::NEWFSTATAT
            | n::FACCESSAT
            | n::FACCESSAT2
            | n::MKDIRAT
            | n::MKNODAT
            | n::UNLINKAT
            | n::LINKAT
            | n::RENAMEAT
            | n::RENAMEAT2
            | n::READLINKAT
            | n::FCHMODAT
            | n::FCHOWNAT
            | n::UTIMENSAT
            | n::STATX
            | n::TIMERFD_SETTIME
            | n::TIMERFD_GETTIME
    )
}

/// `EBADF` if a call would name one of fwe's own descriptors.
pub fn check_args(nr: u64, a: &[u64; 6]) -> Result<(), i64> {
    let bad = |fd: u64| !guest_visible(fd as i32);
    if (first_arg_is_fd(nr) && bad(a[0]))
        || (nr == fwe_abi::nr::DUP3 && bad(a[1]))
        || (nr == fwe_abi::nr::EPOLL_CTL && bad(a[2]))
        || (nr == fwe_abi::nr::SENDFILE && bad(a[1]))
        || (nr == fwe_abi::nr::SYMLINKAT && bad(a[1]))
        || (nr == fwe_abi::nr::MMAP && a[3] & fwe_abi::mman::MAP_ANONYMOUS == 0 && bad(a[4]))
        || crate::fdmarks::refuses_path(nr, a)
    {
        return Err(fwe_abi::err(fwe_abi::errno::EBADF));
    }
    // An inotify descriptor is no socket to the guest.
    if let Some(e) = crate::inotify::refused(nr, a) {
        return Err(e);
    }
    Ok(())
}

/// Linux's checks against the guest's soft `RLIMIT_NOFILE` made before a
/// call runs: `dup3` onto a descriptor at or above it fails with `EBADF`,
/// `F_DUPFD` from one with `EINVAL`.
pub fn check_limit(nr: u64, a: &[u64; 6]) -> Result<(), i64> {
    use fwe_abi::{errno, fcntl, nr as n};
    let soft = limit().0;
    if nr == n::DUP3 && a[1] >= soft {
        return Err(fwe_abi::err(errno::EBADF));
    }
    if nr == n::FCNTL && matches!(a[1], fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC) && a[2] >= soft {
        return Err(fwe_abi::err(errno::EINVAL));
    }
    Ok(())
}

/// The descriptors call `nr` (arguments `a`) made, given its `result`.
pub fn made(nr: u64, a: &[u64; 6], result: i64) -> Vec<i32> {
    use fwe_abi::{fcntl, nr as n};
    if result < 0 {
        return Vec::new();
    }
    match nr {
        n::OPENAT
        | n::OPENAT2
        | n::DUP
        | n::EPOLL_CREATE1
        | n::EVENTFD2
        | n::TIMERFD_CREATE
        | n::SOCKET
        | n::ACCEPT
        | n::ACCEPT4
        | n::MEMFD_CREATE
        | n::INOTIFY_INIT1 => vec![result as i32],
        // A command that makes a descriptor (loading a program, or one by
        // its identity).
        n::BPF if matches!(a[0], crate::bpf::BPF_PROG_LOAD | crate::bpf::BPF_PROG_GET_FD_BY_ID) => {
            vec![result as i32]
        }
        // A new signalfd, not an existing one changed.
        n::SIGNALFD4 if a[0] as i32 == -1 => vec![result as i32],
        n::FCNTL if matches!(a[1], fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC) => {
            vec![result as i32]
        }
        n::PIPE2 | n::SOCKETPAIR => {
            let at = if nr == n::PIPE2 { a[0] } else { a[3] };
            crate::uaccess::read::<[i32; 2]>(at).map(Vec::from).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Whether any of `fds` is at or above the guest's soft `RLIMIT_NOFILE`:
/// one Linux would not have had to give, so the call that made them is to
/// fail with `EMFILE`, its descriptors closed again. (The host gives the
/// lowest free number, as Linux does, so only a guest holding as many
/// descriptors as its limit gets one.)
pub fn over_limit(fds: &[i32]) -> bool {
    let soft = limit().0;
    fds.iter().any(|&fd| fd as u64 >= soft)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_descriptors_sit_above_the_guest_range() {
        init();
        let mut fds = [0; 2];
        // SAFETY: a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let high = reserve(fds[1]).unwrap();
        assert!(high >= guest_max(), "{high} below {}", guest_max());
        assert!(!guest_visible(high));
        assert!(!open_fds().contains(&high));
        assert!(open_fds().contains(&fds[0]));
        // The descriptor still works where it moved.
        // SAFETY: writing one byte to the pipe and reading it back.
        unsafe {
            assert_eq!(libc::write(high, b"x".as_ptr().cast(), 1), 1);
            let mut b = 0u8;
            assert_eq!(libc::read(fds[0], (&mut b as *mut u8).cast(), 1), 1);
            libc::close(high);
            libc::close(fds[0]);
        }
        let a = [high as u64, 0, 0, 0, 0, 0];
        assert!(check_args(fwe_abi::nr::CLOSE, &a).is_err());
        assert!(check_args(fwe_abi::nr::KILL, &a).is_ok());
    }

    #[test]
    fn limit_is_virtual_and_bounded_by_nr_open() {
        init();
        let (_, hard) = limit();
        assert_eq!(hard, guest_max() as u64);
        // Past the range, up to `fs.nr_open`, as Linux allows.
        set_limit(hard + 1, hard + 1).unwrap();
        assert_eq!(set_limit(1 << 20, (1 << 20) + 1), Err(fwe_abi::errno::EPERM));
        assert_eq!(set_limit(200, 100), Err(fwe_abi::errno::EINVAL));
        set_limit(512, hard).unwrap();
        assert_eq!(limit(), (512, hard));
        set_limit(DEFAULT_SOFT.min(hard), hard).unwrap();
    }
}
