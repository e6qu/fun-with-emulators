//! The guest's view of the descriptor table.
//!
//! Guest descriptors are host descriptors, but fwe holds some for itself —
//! the root filesystem directory, the pipe ends behind eventfd and signalfd,
//! the pipe a `vfork` parent waits on, and in the VM backend the file of
//! each file mapping. Those live in a reserved range above the highest
//! number the guest can use, up to the host's limit: the guest's
//! `RLIMIT_NOFILE` is virtual. The guest's range ends at [`GUEST_CAP`] at
//! most, so the range starts low: the host's table grows only as far as
//! the descriptors in use, and a host `fork` copies all of it.
//! Loops that close everything up to the limit, `close_range`, and
//! `/proc/self/fd` never reach the reserved range, and a system call naming
//! a descriptor there fails with `EBADF`, as for a descriptor that is not
//! open. A descriptor of fwe's never goes below the range: when it is full,
//! what needed one fails. The limit can be raised past the range, up to
//! `fs.nr_open`, as Linux allows; the descriptors the guest gets stay below
//! it.
//!
//! The process's root directory descriptor, which every process holds, sits
//! lower ([`reserve_root`]): at or above the guest's soft limit, where no
//! descriptor of the guest's can be made (a new one at or above it fails,
//! [`over_limit`], [`check_limit`]), and below the reserved range, so a
//! process that holds nothing else of fwe's forks with a small table. A
//! raise of the soft limit past it moves it above the new limit first
//! (`Fs::keep_root_above`).

use fwe_abi::resource::RLIM_INFINITY;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

/// The least number of descriptors kept for fwe's own use, above the
/// guest's range; it takes a quarter of the host's descriptors when there
/// are more ([`init`]).
pub const RESERVED: i32 = 64;

/// The first descriptor the guest cannot use (the guest's hard limit).
static GUEST_MAX: AtomicI32 = AtomicI32::new(1024);
/// The guest's virtual `RLIMIT_NOFILE`.
pub(crate) static LIMIT: Mutex<(u64, u64)> = Mutex::new((1024, 1024));
/// The process's root directory descriptor (-1 for none), out of the
/// guest's reach wherever it is ([`reserve_root`]).
static ROOT: AtomicI32 = AtomicI32::new(-1);

/// The guest's default soft limit, Linux's.
const DEFAULT_SOFT: u64 = 1024;

/// The most descriptors the guest can have open at once: as many as
/// programs a Linux distribution runs count on (LTP's `pipe15` opens
/// 8195). A host `fork` copies the descriptor table as far as its highest
/// descriptor, fwe's reserved range just above this: a fork, exit and
/// wait takes about 6% longer than with the range from 4096 (from 69120,
/// the host's, far more).
pub const GUEST_CAP: i32 = 16384;

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
    // macOS can refuse a soft limit above OPEN_MAX (10240) however high the
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
    let guest_max = (host - reserved).min(GUEST_CAP);
    GUEST_MAX.store(guest_max, Ordering::SeqCst);
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner()) =
        (DEFAULT_SOFT.min(guest_max as u64), guest_max as u64);
    hold_floor(guest_max);
}

/// Hold a descriptor at `floor`, the reserved range's first, for the
/// process's life. The host's `close` of a process's highest descriptor
/// looks down, slot by slot, for the next one open: without it, closing
/// one of fwe's (the guest's are far below) costs the host microseconds
/// for every thousand slots between. (fwe's own are each taken at the
/// lowest number free above it, so they stay close to it too.)
fn hold_floor(floor: i32) {
    // SAFETY: plain host calls; the descriptor is kept, close-on-exec (the
    // next fwe holds its own).
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if null < 0 {
            return;
        }
        libc::fcntl(null, libc::F_DUPFD_CLOEXEC, floor);
        libc::close(null);
    }
}

/// Write the descriptor-table limits into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    e.i32(GUEST_MAX.load(Ordering::SeqCst));
    let (soft, hard) = limit();
    e.u64(soft);
    e.u64(hard);
}

/// Take the limits [`save`] wrote, in a fork child (which inherits the
/// parent's host limit, so its reserved range is the parent's).
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    GUEST_MAX.store(d.i32(), Ordering::SeqCst);
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner()) = (d.u64(), d.u64());
}

/// One past the highest descriptor the guest can use.
pub fn guest_max() -> i32 {
    GUEST_MAX.load(Ordering::SeqCst)
}

/// Whether `fd` names a descriptor the guest can hold: below the reserved
/// range, and not the process's root (negative values, such as
/// `AT_FDCWD`, are left to the call).
pub fn guest_visible(fd: i32) -> bool {
    fd < guest_max() && fd != ROOT.load(Ordering::Relaxed)
}

/// A close-on-exec duplicate of `fd`, the process's root directory, at the
/// lowest free number at or above the guest's soft limit (or `floor`, if
/// higher): out of the guest's reach, and, while below the reserved
/// range, out of the way of a host `fork`, which copies the table as far
/// as the highest descriptor. In the reserved range when the limit reaches
/// it. `EMFILE` when there is no room.
pub fn reserve_root(fd: i32, floor: u64) -> Result<i32, i32> {
    let at = limit().0.max(floor);
    let root = if at >= guest_max() as u64 {
        dup_reserved(fd)?
    } else {
        // SAFETY: plain host call on a descriptor the caller holds.
        let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, at as i32) };
        if r < 0 {
            return Err(fwe_abi::errno::EMFILE);
        }
        r
    };
    ROOT.store(root, Ordering::SeqCst);
    Ok(root)
}

/// The process's root directory descriptor, `fd`, inherited at its number
/// (a fork snapshot taken up).
pub(crate) fn root_is(fd: i32) {
    ROOT.store(fd, Ordering::SeqCst);
}

/// `fd`, the process's root directory descriptor if it is, closed.
pub(crate) fn root_closed(fd: i32) {
    let _ = ROOT.compare_exchange(fd, -1, Ordering::SeqCst, Ordering::SeqCst);
}

/// Whether the process's root directory descriptor, `fd`, is below `soft`
/// (a soft limit to be set) and the reserved range: then to be moved
/// before the limit is, or the guest could be given its number.
pub(crate) fn root_below(fd: i32, soft: u64) -> bool {
    fd == ROOT.load(Ordering::SeqCst) && fd < guest_max() && (fd as u64) < soft
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

/// A close-on-exec duplicate of `fd` at the lowest free number of the
/// reserved range, or `EMFILE` when the range is full (`EBADF` if `fd` is
/// not open).
pub fn dup_reserved(fd: i32) -> Result<i32, i32> {
    // SAFETY: a plain host call on a descriptor the caller holds.
    let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, guest_max()) };
    if high >= 0 {
        Ok(high)
    } else if crate::host::last_errno().is(libc::EBADF) {
        Err(fwe_abi::errno::EBADF)
    } else {
        Err(fwe_abi::errno::EMFILE)
    }
}

/// A plug is in place ([`plugged`]).
static PLUGGED: AtomicBool = AtomicBool::new(false);
/// The plugs made, the numbers they took and their nanoseconds, for
/// `FWE_TIMING` ([`plugs`]).
static PLUGS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Run `f` with every free number of the guest's range taken, so the
/// descriptors anything opens meanwhile land out of the guest's reach (in
/// the reserved range): for a host library that opens descriptors of its
/// own (the Mac's Vulkan driver's caches). The caller holds the kernel lock,
/// so no call under it makes a descriptor meanwhile; a call without it
/// that does moves it into the guest's range once the plug is gone
/// ([`into_range`]). Each number is taken as the lowest free one, so none
/// another thread is making is taken over. `EMFILE` if the host's table
/// has no room left for the plugs.
pub fn plugged<R>(f: impl FnOnce() -> R) -> Result<R, i32> {
    let began = std::time::Instant::now();
    // SAFETY: a constant NUL-terminated path.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if null < 0 {
        return Err(fwe_abi::errno::EMFILE);
    }
    PLUGGED.store(true, Ordering::SeqCst);
    let max = guest_max();
    let mut plugs = Vec::new();
    let full = loop {
        // SAFETY: a plain host call on fwe's own descriptor.
        let fd = unsafe { libc::fcntl(null, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            break false;
        }
        if fd >= max {
            // SAFETY: the duplicate just made, fwe's own.
            unsafe { libc::close(fd) };
            break true;
        }
        plugs.push(fd);
    };
    let r = full.then(f);
    for fd in plugs.iter().copied().chain([null]) {
        // SAFETY: the plugs made above, fwe's own.
        unsafe { libc::close(fd) };
    }
    PLUGGED.store(false, Ordering::SeqCst);
    if crate::timing::on() {
        PLUGS[0].fetch_add(1, Ordering::Relaxed);
        PLUGS[1].fetch_add(plugs.len() as u64 + u64::from(null < max), Ordering::Relaxed);
        PLUGS[2].fetch_add(began.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    r.ok_or(fwe_abi::errno::EMFILE)
}

/// The plugs made ([`plugged`]): how many, the numbers they took, and their
/// time, as text, if any were.
pub fn plugs() -> Option<String> {
    let n = PLUGS[0].load(Ordering::Relaxed);
    (n > 0).then(|| {
        format!(
            "descriptor plugs {n} ({} numbers, {} us)",
            PLUGS[1].load(Ordering::Relaxed),
            PLUGS[2].load(Ordering::Relaxed) / 1000
        )
    })
}

/// Descriptor `fd`, which a call made without the kernel lock for the guest
/// (an `accept`, a received one), in the guest's range: where a plug
/// ([`plugged`]) put it out of it, moved to the lowest free number once
/// the plug is gone (a copy of it, the same description, its
/// close-on-exec kept). Any other is itself.
pub fn into_range(fd: i32) -> i32 {
    if fd < 0 || guest_visible(fd) {
        return fd;
    }
    while PLUGGED.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    // SAFETY: plain host calls on the descriptor the caller made.
    unsafe {
        let cloexec = libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0;
        let low = libc::fcntl(fd, if cloexec { libc::F_DUPFD_CLOEXEC } else { libc::F_DUPFD }, 0);
        if low < 0 || !guest_visible(low) {
            // The guest's range is full: the descriptor stays as it is,
            // for the call to refuse as one past the limit.
            if low >= 0 {
                libc::close(low);
            }
            return fd;
        }
        libc::close(fd);
        low
    }
}

/// The guest's `RLIMIT_NOFILE` as `(soft, hard)`.
pub fn limit() -> (u64, u64) {
    *LIMIT.lock().unwrap_or_else(|e| e.into_inner())
}

/// The guest's `RLIMIT_NOFILE` as `(soft, hard)` would be set from
/// `soft` and `hard` ([`set_limit`]), or `EINVAL` if soft exceeds hard and
/// `EPERM` above `fs.nr_open`.
pub fn limit_of(soft: u64, hard: u64) -> Result<(u64, u64), i32> {
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
    Ok((soft, hard))
}

/// Set the guest's `RLIMIT_NOFILE` ([`limit_of`]). Only through
/// `Kernel::set_nofile`, which first moves the process's root directory
/// descriptor at or above the new soft limit.
pub(crate) fn set_limit(soft: u64, hard: u64) -> Result<(), i32> {
    let (soft, hard) = limit_of(soft, hard)?;
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

/// `EBADF` if a call would name one of fwe's own descriptors, or Linux's
/// error for one a descriptor's mark refuses.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
    // (The limit's lock taken only for the calls it is checked for.)
    if nr == n::DUP3 && a[1] >= limit().0 {
        return Err(fwe_abi::err(errno::EBADF));
    }
    if nr == n::FCNTL
        && matches!(a[1], fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC)
        && a[2] >= limit().0
    {
        return Err(fwe_abi::err(errno::EINVAL));
    }
    Ok(())
}

/// The descriptors call `nr` (arguments `a`) made, given its `result`.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
    if fds.is_empty() {
        return false;
    }
    let soft = limit().0;
    fds.iter().any(|&fd| fd as u64 >= soft)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test at a time that sets the process's limits or places
    /// descriptors by them: a soft limit another sets past the guest's
    /// range would move a root into the reserved one.
    fn alone() -> std::sync::MutexGuard<'static, ()> {
        static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ONE.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn reserved_descriptors_sit_above_the_guest_range() {
        let _one = alone();
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
    fn the_root_sits_at_or_above_the_soft_limit_out_of_reach() {
        let _one = alone();
        init();
        // SAFETY: opening a directory by path.
        let dir = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(dir >= 0);
        let floor = 2000;
        let root = reserve_root(dir, floor).unwrap();
        assert!(root as u64 >= floor && root < guest_max(), "{root}");
        assert!(!guest_visible(root));
        // To be moved for a soft limit past it, not for one at it.
        assert!(root_below(root, root as u64 + 1));
        assert!(!root_below(root, root as u64));
        let a = [root as u64, 0, 0, 0, 0, 0];
        assert!(check_args(fwe_abi::nr::CLOSE, &a).is_err());
        root_closed(root);
        assert!(guest_visible(root));
        // SAFETY: closing the descriptors opened above.
        unsafe {
            libc::close(root);
            libc::close(dir);
        }
    }

    #[test]
    fn limit_is_virtual_and_bounded_by_nr_open() {
        let _one = alone();
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
