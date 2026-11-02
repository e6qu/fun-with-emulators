//! Translation between Linux ABI values and host (macOS) values.
//!
//! Host values come from the `libc` crate, so this module compiles on any
//! Unix host; on Linux hosts most translations are the identity.

use fwe_abi::{clock, errno as le, fcntl, resource, signal};

/// The calling thread's host `errno`.
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// (host errno, Linux errno). Searched in order, first match wins.
const ERRNO_TABLE: &[(i32, i32)] = &[
    (libc::EPERM, le::EPERM),
    (libc::ENOENT, le::ENOENT),
    (libc::ESRCH, le::ESRCH),
    (libc::EINTR, le::EINTR),
    (libc::EIO, le::EIO),
    (libc::ENXIO, le::ENXIO),
    (libc::E2BIG, le::E2BIG),
    (libc::ENOEXEC, le::ENOEXEC),
    (libc::EBADF, le::EBADF),
    (libc::ECHILD, le::ECHILD),
    (libc::EAGAIN, le::EAGAIN),
    (libc::ENOMEM, le::ENOMEM),
    (libc::EACCES, le::EACCES),
    (libc::EFAULT, le::EFAULT),
    (libc::ENOTBLK, le::ENOTBLK),
    (libc::EBUSY, le::EBUSY),
    (libc::EEXIST, le::EEXIST),
    (libc::EXDEV, le::EXDEV),
    (libc::ENODEV, le::ENODEV),
    (libc::ENOTDIR, le::ENOTDIR),
    (libc::EISDIR, le::EISDIR),
    (libc::EINVAL, le::EINVAL),
    (libc::ENFILE, le::ENFILE),
    (libc::EMFILE, le::EMFILE),
    (libc::ENOTTY, le::ENOTTY),
    (libc::ETXTBSY, le::ETXTBSY),
    (libc::EFBIG, le::EFBIG),
    (libc::ENOSPC, le::ENOSPC),
    (libc::ESPIPE, le::ESPIPE),
    (libc::EROFS, le::EROFS),
    (libc::EMLINK, le::EMLINK),
    (libc::EPIPE, le::EPIPE),
    (libc::EDOM, le::EDOM),
    (libc::ERANGE, le::ERANGE),
    (libc::EDEADLK, le::EDEADLK),
    (libc::ENAMETOOLONG, le::ENAMETOOLONG),
    (libc::ENOLCK, le::ENOLCK),
    (libc::ENOSYS, le::ENOSYS),
    (libc::ENOTEMPTY, le::ENOTEMPTY),
    (libc::ELOOP, le::ELOOP),
    (libc::ENOMSG, le::ENOMSG),
    (libc::EIDRM, le::EIDRM),
    (libc::ENOSTR, le::ENOSTR),
    (libc::ENODATA, le::ENODATA),
    (libc::ETIME, le::ETIME),
    (libc::ENOSR, le::ENOSR),
    (libc::EREMOTE, le::EREMOTE),
    (libc::ENOLINK, le::ENOLINK),
    (libc::EPROTO, le::EPROTO),
    (libc::EMULTIHOP, le::EMULTIHOP),
    (libc::EBADMSG, le::EBADMSG),
    (libc::EOVERFLOW, le::EOVERFLOW),
    (libc::EILSEQ, le::EILSEQ),
    (libc::EUSERS, le::EUSERS),
    (libc::ENOTSOCK, le::ENOTSOCK),
    (libc::EDESTADDRREQ, le::EDESTADDRREQ),
    (libc::EMSGSIZE, le::EMSGSIZE),
    (libc::EPROTOTYPE, le::EPROTOTYPE),
    (libc::ENOPROTOOPT, le::ENOPROTOOPT),
    (libc::EPROTONOSUPPORT, le::EPROTONOSUPPORT),
    (libc::ESOCKTNOSUPPORT, le::ESOCKTNOSUPPORT),
    (libc::EOPNOTSUPP, le::EOPNOTSUPP),
    (libc::ENOTSUP, le::EOPNOTSUPP),
    (libc::EPFNOSUPPORT, le::EPFNOSUPPORT),
    (libc::EAFNOSUPPORT, le::EAFNOSUPPORT),
    (libc::EADDRINUSE, le::EADDRINUSE),
    (libc::EADDRNOTAVAIL, le::EADDRNOTAVAIL),
    (libc::ENETDOWN, le::ENETDOWN),
    (libc::ENETUNREACH, le::ENETUNREACH),
    (libc::ENETRESET, le::ENETRESET),
    (libc::ECONNABORTED, le::ECONNABORTED),
    (libc::ECONNRESET, le::ECONNRESET),
    (libc::ENOBUFS, le::ENOBUFS),
    (libc::EISCONN, le::EISCONN),
    (libc::ENOTCONN, le::ENOTCONN),
    (libc::ESHUTDOWN, le::ESHUTDOWN),
    (libc::ETOOMANYREFS, le::ETOOMANYREFS),
    (libc::ETIMEDOUT, le::ETIMEDOUT),
    (libc::ECONNREFUSED, le::ECONNREFUSED),
    (libc::EHOSTDOWN, le::EHOSTDOWN),
    (libc::EHOSTUNREACH, le::EHOSTUNREACH),
    (libc::EALREADY, le::EALREADY),
    (libc::EINPROGRESS, le::EINPROGRESS),
    (libc::ESTALE, le::ESTALE),
    (libc::EDQUOT, le::EDQUOT),
    (libc::ECANCELED, le::ECANCELED),
    (libc::EOWNERDEAD, le::EOWNERDEAD),
    (libc::ENOTRECOVERABLE, le::ENOTRECOVERABLE),
    #[cfg(target_os = "macos")]
    (libc::ENOATTR, le::ENODATA),
];

/// Translate a host errno into the Linux errno with the same meaning.
pub fn errno_to_linux(host: i32) -> i32 {
    ERRNO_TABLE.iter().find(|(h, _)| *h == host).map(|(_, l)| *l).unwrap_or(le::EIO)
}

/// The raw Linux return value for the current host `errno`.
pub fn last_error() -> i64 {
    -(errno_to_linux(last_errno()) as i64)
}

/// Turn a host call result into a raw Linux return value.
pub fn ret(r: impl Into<i64>) -> i64 {
    let r = r.into();
    if r < 0 { last_error() } else { r }
}

/// Host clock for a Linux clock id.
pub fn clock_to_host(id: u64) -> Option<libc::clockid_t> {
    Some(match id {
        clock::CLOCK_REALTIME
        | clock::CLOCK_REALTIME_COARSE
        | clock::CLOCK_REALTIME_ALARM
        | clock::CLOCK_TAI => libc::CLOCK_REALTIME,
        clock::CLOCK_MONOTONIC
        | clock::CLOCK_MONOTONIC_COARSE
        | clock::CLOCK_BOOTTIME
        | clock::CLOCK_BOOTTIME_ALARM => libc::CLOCK_MONOTONIC,
        clock::CLOCK_MONOTONIC_RAW => libc::CLOCK_MONOTONIC_RAW,
        clock::CLOCK_PROCESS_CPUTIME_ID => libc::CLOCK_PROCESS_CPUTIME_ID,
        clock::CLOCK_THREAD_CPUTIME_ID => libc::CLOCK_THREAD_CPUTIME_ID,
        _ => return None,
    })
}

/// Host resource for a Linux resource limit, if the host has it.
pub fn rlimit_to_host(resource: u64) -> Option<libc::c_int> {
    Some(match resource {
        resource::RLIMIT_CPU => libc::RLIMIT_CPU as libc::c_int,
        resource::RLIMIT_FSIZE => libc::RLIMIT_FSIZE as libc::c_int,
        resource::RLIMIT_DATA => libc::RLIMIT_DATA as libc::c_int,
        resource::RLIMIT_STACK => libc::RLIMIT_STACK as libc::c_int,
        resource::RLIMIT_CORE => libc::RLIMIT_CORE as libc::c_int,
        resource::RLIMIT_NPROC => libc::RLIMIT_NPROC as libc::c_int,
        resource::RLIMIT_NOFILE => libc::RLIMIT_NOFILE as libc::c_int,
        resource::RLIMIT_MEMLOCK => libc::RLIMIT_MEMLOCK as libc::c_int,
        resource::RLIMIT_AS => libc::RLIMIT_AS as libc::c_int,
        _ => return None,
    })
}

pub fn rlim_to_linux(v: libc::rlim_t) -> u64 {
    if v == libc::RLIM_INFINITY { resource::RLIM_INFINITY } else { v }
}

pub fn rlim_to_host(v: u64) -> libc::rlim_t {
    if v == resource::RLIM_INFINITY { libc::RLIM_INFINITY } else { v }
}

/// Host signal for a Linux signal number, if the host has an equivalent.
pub fn signal_to_host(sig: u64) -> Option<libc::c_int> {
    Some(match sig {
        signal::SIGHUP => libc::SIGHUP,
        signal::SIGINT => libc::SIGINT,
        signal::SIGQUIT => libc::SIGQUIT,
        signal::SIGILL => libc::SIGILL,
        signal::SIGTRAP => libc::SIGTRAP,
        signal::SIGABRT => libc::SIGABRT,
        signal::SIGBUS => libc::SIGBUS,
        signal::SIGFPE => libc::SIGFPE,
        signal::SIGKILL => libc::SIGKILL,
        signal::SIGUSR1 => libc::SIGUSR1,
        signal::SIGSEGV => libc::SIGSEGV,
        signal::SIGUSR2 => libc::SIGUSR2,
        signal::SIGPIPE => libc::SIGPIPE,
        signal::SIGALRM => libc::SIGALRM,
        signal::SIGTERM => libc::SIGTERM,
        signal::SIGCHLD => libc::SIGCHLD,
        signal::SIGCONT => libc::SIGCONT,
        signal::SIGSTOP => libc::SIGSTOP,
        signal::SIGTSTP => libc::SIGTSTP,
        signal::SIGTTIN => libc::SIGTTIN,
        signal::SIGTTOU => libc::SIGTTOU,
        signal::SIGURG => libc::SIGURG,
        signal::SIGXCPU => libc::SIGXCPU,
        signal::SIGXFSZ => libc::SIGXFSZ,
        signal::SIGVTALRM => libc::SIGVTALRM,
        signal::SIGPROF => libc::SIGPROF,
        signal::SIGWINCH => libc::SIGWINCH,
        signal::SIGIO => libc::SIGIO,
        signal::SIGSYS => libc::SIGSYS,
        _ => return None,
    })
}

/// Linux signal number for a host signal, if there is an equivalent. The
/// inverse of [`signal_to_host`], used to translate a child's `wait` status.
pub fn signal_to_linux(host: libc::c_int) -> u64 {
    for sig in 1..=signal::NSIG {
        if signal_to_host(sig) == Some(host) {
            return sig;
        }
    }
    signal::SIGABRT
}

/// File status flags (`F_GETFL`) from host to Linux.
pub fn status_flags_to_linux(host: libc::c_int) -> u64 {
    let mut f = match host & libc::O_ACCMODE {
        libc::O_WRONLY => fcntl::O_WRONLY,
        libc::O_RDWR => fcntl::O_RDWR,
        _ => fcntl::O_RDONLY,
    };
    for (h, l) in [
        (libc::O_APPEND, fcntl::O_APPEND),
        (libc::O_NONBLOCK, fcntl::O_NONBLOCK),
        (libc::O_ASYNC, fcntl::O_ASYNC),
        (libc::O_DSYNC, fcntl::O_DSYNC),
    ] {
        if host & h != 0 {
            f |= l;
        }
    }
    // Linux reports O_LARGEFILE on 64-bit for every open file.
    f | fcntl::O_LARGEFILE
}

/// Settable file status flags (`F_SETFL`) from Linux to host.
pub fn settable_flags_to_host(linux: u64) -> libc::c_int {
    let mut f = 0;
    for (l, h) in [
        (fcntl::O_APPEND, libc::O_APPEND),
        (fcntl::O_NONBLOCK, libc::O_NONBLOCK),
        (fcntl::O_ASYNC, libc::O_ASYNC),
    ] {
        if linux & l != 0 {
            f |= h;
        }
    }
    f
}

/// Translate Linux `open` flags to host flags.
///
/// Symlinks are resolved by the filesystem layer, so the final open always
/// uses the host `O_NOFOLLOW`. Flags with no host equivalent (`O_PATH`,
/// `O_TMPFILE`, `O_DIRECT`, `O_NOATIME`, `O_LARGEFILE`) are dropped.
pub fn open_flags_to_host(linux: u64) -> libc::c_int {
    let mut f = match linux & fcntl::O_ACCMODE {
        fcntl::O_WRONLY => libc::O_WRONLY,
        fcntl::O_RDWR => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };
    f |= libc::O_NOFOLLOW;
    for (l, h) in [
        (fcntl::O_CREAT, libc::O_CREAT),
        (fcntl::O_EXCL, libc::O_EXCL),
        (fcntl::O_NOCTTY, libc::O_NOCTTY),
        (fcntl::O_TRUNC, libc::O_TRUNC),
        (fcntl::O_APPEND, libc::O_APPEND),
        (fcntl::O_NONBLOCK, libc::O_NONBLOCK),
        (fcntl::O_DSYNC, libc::O_DSYNC),
        (fcntl::O_SYNC, libc::O_SYNC),
        (fcntl::O_DIRECTORY, libc::O_DIRECTORY),
        (fcntl::O_CLOEXEC, libc::O_CLOEXEC),
    ] {
        if linux & l == l {
            f |= h;
        }
    }
    f
}

/// Fill `out` with cryptographically secure random bytes.
#[cfg(target_os = "macos")]
pub fn fill_random(out: &mut [u8]) {
    // SAFETY: `out` is a valid buffer of its length.
    unsafe { libc::arc4random_buf(out.as_mut_ptr().cast(), out.len()) }
}

/// Fill `out` with cryptographically secure random bytes.
#[cfg(not(target_os = "macos"))]
pub fn fill_random(out: &mut [u8]) {
    let mut done = 0;
    while done < out.len() {
        // SAFETY: the remaining part of `out` is a valid buffer.
        let r = unsafe { libc::getrandom(out[done..].as_mut_ptr().cast(), out.len() - done, 0) };
        if r > 0 {
            done += r as usize;
        }
    }
}

/// Why an exact-address reservation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveError {
    /// Something is already mapped in the range.
    Occupied,
    /// The range is outside the addresses the host lets this process use.
    OutOfRange,
    /// Another host error (Mach `kern_return_t` or errno).
    Other(i32),
}

impl std::fmt::Display for ReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveError::Occupied => write!(f, "already in use"),
            ReserveError::OutOfRange => write!(f, "outside the process address space"),
            ReserveError::Other(code) => write!(f, "host error {code}"),
        }
    }
}

/// Reserve `[addr, addr + len)` as inaccessible memory, exactly at `addr`,
/// without disturbing anything already mapped.
#[cfg(target_os = "macos")]
pub fn reserve_fixed(addr: u64, len: u64) -> Result<(), ReserveError> {
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: i32) -> i32;
    }
    const VM_FLAGS_FIXED: i32 = 0;
    const KERN_INVALID_ADDRESS: i32 = 1;
    const KERN_NO_SPACE: i32 = 3;
    let mut at = addr;
    // SAFETY: allocating fresh memory in our own task; VM_FLAGS_FIXED without
    // VM_FLAGS_OVERWRITE fails rather than replacing existing mappings.
    let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut at, len, VM_FLAGS_FIXED) };
    match kr {
        0 => {
            // SAFETY: the range was just allocated by us.
            unsafe { libc::mprotect(addr as *mut libc::c_void, len as usize, libc::PROT_NONE) };
            Ok(())
        }
        KERN_NO_SPACE => Err(ReserveError::Occupied),
        KERN_INVALID_ADDRESS => Err(ReserveError::OutOfRange),
        other => Err(ReserveError::Other(other)),
    }
}

/// Reserve `[addr, addr + len)` as inaccessible memory, exactly at `addr`,
/// without disturbing anything already mapped.
#[cfg(not(target_os = "macos"))]
pub fn reserve_fixed(addr: u64, len: u64) -> Result<(), ReserveError> {
    // SAFETY: MAP_FIXED_NOREPLACE never replaces existing mappings.
    let p = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(match last_errno() {
            libc::EEXIST => ReserveError::Occupied,
            libc::ENOMEM | libc::EINVAL => ReserveError::OutOfRange,
            e => ReserveError::Other(e),
        });
    }
    Ok(())
}

pub fn getpid() -> i64 {
    // SAFETY: plain host call.
    unsafe { libc::getpid() as i64 }
}

pub fn getppid() -> i64 {
    // SAFETY: plain host call.
    unsafe { libc::getppid() as i64 }
}

/// (uid, euid, gid, egid) of the host process.
pub fn ids() -> (i64, i64, i64, i64) {
    // SAFETY: plain host calls.
    unsafe {
        (
            libc::getuid() as i64,
            libc::geteuid() as i64,
            libc::getgid() as i64,
            libc::getegid() as i64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_translation() {
        assert_eq!(errno_to_linux(libc::EAGAIN), le::EAGAIN);
        assert_eq!(errno_to_linux(libc::ENOSYS), le::ENOSYS);
        assert_eq!(errno_to_linux(libc::ECONNREFUSED), le::ECONNREFUSED);
        assert_eq!(errno_to_linux(libc::ENOTSUP), le::EOPNOTSUPP);
        assert_eq!(errno_to_linux(100_000), le::EIO);
    }

    #[test]
    fn clock_translation() {
        assert_eq!(clock_to_host(clock::CLOCK_MONOTONIC), Some(libc::CLOCK_MONOTONIC));
        assert_eq!(clock_to_host(clock::CLOCK_BOOTTIME), Some(libc::CLOCK_MONOTONIC));
        assert_eq!(clock_to_host(99), None);
    }

    #[test]
    fn flag_translation() {
        let host = libc::O_RDWR | libc::O_NONBLOCK | libc::O_APPEND;
        let linux = status_flags_to_linux(host);
        assert_eq!(linux & fcntl::O_ACCMODE, fcntl::O_RDWR);
        assert_ne!(linux & fcntl::O_NONBLOCK, 0);
        assert_ne!(linux & fcntl::O_APPEND, 0);
        assert_eq!(settable_flags_to_host(linux), libc::O_NONBLOCK | libc::O_APPEND);
    }

    #[test]
    fn signal_translation() {
        assert_eq!(signal_to_host(signal::SIGABRT), Some(libc::SIGABRT));
        assert_eq!(signal_to_host(signal::SIGUSR1), Some(libc::SIGUSR1));
        assert_eq!(signal_to_host(signal::SIGRTMIN), None);
    }
}
