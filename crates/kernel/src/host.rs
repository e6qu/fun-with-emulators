//! Translation between Linux ABI values and host (macOS) values.
//!
//! Host values come from the `libc` crate, so this module compiles on any
//! Unix host; on Linux hosts most translations are the identity.

use fwe_abi::{clock, errno as le, fcntl, resource, signal, wait};

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

/// The id Linux reports for an id that has no mapping into a user namespace
/// (`/proc/sys/kernel/overflowuid`): `nobody`.
pub const OVERFLOW_ID: u32 = 65534;

/// The guest's view of host user id `uid` (a file's owner, a signal's
/// sender): as in a rootless container's user namespace, the host user fwe
/// runs as is root in the guest, whose default identity is root too, and
/// every other user is [`OVERFLOW_ID`].
/// In a user namespace of fwe's, that id as the namespace sees it.
pub fn uid_to_linux(uid: u32) -> u32 {
    crate::userns::to_ns(uid_to_initial(uid), false)
}

/// [`uid_to_linux`] in the initial user namespace's terms: what a signal
/// handler may compute (it takes no lock), translated when the guest is
/// given it.
pub fn uid_to_initial(uid: u32) -> u32 {
    // SAFETY: plain host call.
    if uid == unsafe { libc::geteuid() } { 0 } else { OVERFLOW_ID }
}

/// [`uid_to_linux`] for group ids: fwe's own group is the guest's root
/// group.
pub fn gid_to_linux(gid: u32) -> u32 {
    // SAFETY: plain host call.
    let id = if gid == unsafe { libc::getegid() } { 0 } else { OVERFLOW_ID };
    crate::userns::to_ns(id, true)
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

/// The host signal the backend uses to interrupt a guest thread blocked in a
/// host call, so it notices a signal recorded for it (one with no host
/// equivalent). Never one a Linux signal maps to.
#[cfg(target_os = "macos")]
pub const WAKE_SIGNAL: libc::c_int = libc::SIGEMT;
#[cfg(not(target_os = "macos"))]
pub const WAKE_SIGNAL: libc::c_int = libc::SIGPWR;

/// What a guest's `SIGKILL` to an fwe process is sent as. `SIGKILL` itself
/// cannot be caught, and a hypervisor-backend process must never die with
/// its VM alive, so fwe processes are sent this instead (a host signal with
/// no Linux counterpart): a VM process takes it as the guest's `SIGKILL`,
/// tearing its VM down before it dies of `SIGKILL`, and a native one
/// simply dies of `SIGKILL`. Other processes get the real `SIGKILL`.
#[cfg(target_os = "macos")]
pub const KILL_RELAY: libc::c_int = libc::SIGINFO;

/// The executable of process `pid`, if it can be read.
#[cfg(target_os = "macos")]
fn exe_of(pid: libc::pid_t) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: a buffer of the size given.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| {
        buf.truncate(n as usize);
        buf
    })
}

/// The pids of a process group (`pgid` > 0) or, for 0, of every process.
#[cfg(target_os = "macos")]
fn pids_of(pgid: libc::pid_t) -> Vec<libc::pid_t> {
    // <sys/proc_info.h>: PROC_ALL_PIDS, PROC_PGRP_ONLY.
    let (kind, arg): (u32, u32) = if pgid > 0 { (2, pgid as u32) } else { (1, 0) };
    // SAFETY: sizing, then filling, a buffer of pids.
    unsafe {
        let n = libc::proc_listpids(kind, arg, std::ptr::null_mut(), 0);
        if n <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0 as libc::pid_t; n as usize / size_of::<libc::pid_t>() + 64];
        let n = libc::proc_listpids(
            kind,
            arg,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<libc::pid_t>()) as i32,
        );
        pids.truncate(n.max(0) as usize / size_of::<libc::pid_t>());
        pids.retain(|&p| p > 0);
        pids
    }
}

/// `kill(pid, sig)` for a host signal and a `kill`-style `pid` (a process,
/// 0 for the caller's group, `-pgid`, or -1 for every process but the
/// caller and init). A `SIGKILL` reaches fwe processes as [`KILL_RELAY`].
/// Returns 0 or a negated Linux errno.
pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> i64 {
    #[cfg(target_os = "macos")]
    if sig == libc::SIGKILL {
        // SAFETY: plain host calls.
        let (me, group) = unsafe { (libc::getpid(), libc::getpgrp()) };
        let mut targets = match pid {
            p if p > 0 => vec![p],
            0 => pids_of(group),
            -1 => pids_of(0).into_iter().filter(|&p| p != me && p != 1).collect(),
            p => pids_of(-p),
        };
        if targets.is_empty() {
            return fwe_abi::err(fwe_abi::errno::ESRCH);
        }
        // This process last: it may be among them.
        targets.sort_by_key(|&p| p == me);
        let fwe = exe_of(me);
        let mut result = fwe_abi::err(fwe_abi::errno::ESRCH);
        for t in targets {
            let s = if fwe.is_some() && exe_of(t) == fwe { KILL_RELAY } else { libc::SIGKILL };
            // SAFETY: plain host call.
            if unsafe { libc::kill(t, s) } == 0 {
                result = 0;
            } else if result != 0 {
                result = last_error();
            }
        }
        return result;
    }
    // SAFETY: plain host call.
    ret(unsafe { libc::kill(pid, sig) })
}

pub fn empty_sigset() -> libc::sigset_t {
    // SAFETY: an all-zero sigset_t is valid storage; sigemptyset initializes it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        set
    }
}

/// The host signal set holding the relayed signals in Linux set `mask`.
pub fn host_sigset(mask: u64) -> libc::sigset_t {
    let mut set = empty_sigset();
    for sig in 1..=signal::NSIG {
        if mask & (1 << (sig - 1)) != 0 && crate::signal::relayed(sig) {
            if let Some(h) = signal_to_host(sig) {
                // SAFETY: `set` is an initialized signal set.
                unsafe { libc::sigaddset(&mut set, h) };
            }
        }
    }
    set
}

/// The host mask a guest thread with blocked mask `mask` runs under: its
/// relayed signals, except those the backend's handler catches (see
/// [`crate::signal::caught`]): the handler records one the guest blocks as
/// pending, with its sender, which macOS forgets of a signal it holds
/// blocked. A `signalfd` reads them from there too. What stays blocked on
/// the host is the signals whose default action or ignoring the host
/// applies itself, which must wait while the guest blocks them.
pub fn host_mask_for(mask: u64) -> libc::sigset_t {
    host_sigset(mask & !(crate::signal::caught() | crate::signalfd::watched()))
}

/// Stop the process with host stop signal `sig` (`SIGTSTP`, `SIGTTIN`,
/// `SIGTTOU`, `SIGSTOP`) until it is continued, so the parent's `waitpid`
/// reports that signal, as on Linux: raised on this thread with its default
/// action and unblocked for the moment, then put back.
pub fn stop_with(sig: libc::c_int) {
    // SAFETY: plain host calls on initialized values; the disposition and
    // the mask are restored as they were.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, &dfl, &mut old);
        let mut set = empty_sigset();
        libc::sigaddset(&mut set, sig);
        let mut mask = empty_sigset();
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, &mut mask);
        // Delivered before raise returns: the process stops here.
        libc::raise(sig);
        libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
        libc::sigaction(sig, &old, std::ptr::null_mut());
    }
}

/// Before a host `execve` that re-executes fwe: block the guest's whole
/// mask on the host, which the new process reads back as the guest's
/// ([`crate::Kernel::adopt_host_signals`]), and hand the signals pending in
/// fwe that the guest blocks to the host, pending on this thread, which
/// `execve` keeps (Linux keeps a blocked signal pending across `execve`).
/// Their senders do not survive: the host records this process as the
/// sender. If the `execve` fails, the guest's host mask is put back by the
/// next system call, and they are taken again as they arrive.
pub fn hand_over_for_exec() {
    let mask = crate::thread::mask();
    let set = host_sigset(mask);
    // SAFETY: an initialized signal set; changing this thread's mask.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) };
    let pending = crate::thread::pending() & mask;
    for sig in 1..=signal::NSIG {
        if pending & (1 << (sig - 1)) == 0 || !crate::signal::relayed(sig) {
            continue;
        }
        let Some(h) = signal_to_host(sig) else { continue };
        if crate::thread::take_pending(sig).is_some() {
            // SAFETY: raising a signal this thread blocks, on itself.
            unsafe { libc::pthread_kill(libc::pthread_self(), h) };
        }
    }
}

/// The relayed signals the calling thread blocks on the host, as a Linux
/// set.
pub fn blocked_signals() -> u64 {
    let mut set = empty_sigset();
    // SAFETY: `set` is a valid out-parameter; no change is made.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set) };
    let mut out = 0;
    for sig in 1..=signal::NSIG {
        if let Some(h) = signal_to_host(sig).filter(|_| crate::signal::relayed(sig)) {
            // SAFETY: `set` is an initialized signal set.
            if unsafe { libc::sigismember(&set, h) } == 1 {
                out |= 1 << (sig - 1);
            }
        }
    }
    out
}

/// Relayed signals pending in the host for the calling thread or process
/// (those the guest blocks), as a Linux set.
pub fn pending_signals() -> u64 {
    let mut set = empty_sigset();
    // SAFETY: `set` is a valid out-parameter.
    unsafe { libc::sigpending(&mut set) };
    let mut out = 0;
    for sig in 1..=signal::NSIG {
        if let Some(h) = signal_to_host(sig).filter(|_| crate::signal::relayed(sig)) {
            // SAFETY: `set` is an initialized signal set.
            if unsafe { libc::sigismember(&set, h) } == 1 {
                out |= 1 << (sig - 1);
            }
        }
    }
    out
}

/// Whether the host currently ignores Linux signal `sig`.
pub fn signal_is_ignored(sig: u64) -> bool {
    let Some(h) = signal_to_host(sig) else { return false };
    // SAFETY: querying a disposition into a zeroed sigaction.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(h, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// Whether the host's `SIGCHLD` action has `SA_NOCLDSTOP` (the guest's
/// does): no `SIGCHLD` for a child that stops or continues.
pub fn sigchld_nocldstop() -> bool {
    // SAFETY: zeroed bytes are a valid `sigaction`; the call only reads.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter; no new action.
    unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    old.sa_flags & libc::SA_NOCLDSTOP != 0
}

/// Whether the host reaps this process's children as they end, leaving no
/// zombie for `wait`: it ignores `SIGCHLD`, or set `SA_NOCLDWAIT`.
pub fn children_reaped_by_host() -> bool {
    // SAFETY: querying a disposition into a zeroed sigaction.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) == 0
            && (old.sa_sigaction == libc::SIG_IGN || old.sa_flags & libc::SA_NOCLDWAIT != 0)
    }
}

/// Translate a host `si_code` into Linux's. The `SIGCHLD` codes and the
/// fault codes are the same; the codes for user-sent signals differ.
pub fn si_code_to_linux(code: i32) -> i32 {
    #[cfg(target_os = "macos")]
    {
        match code {
            0x10001 => return signal::SI_USER,
            0x10002 => return signal::SI_QUEUE,
            0x10003 => return signal::SI_TIMER,
            0x10004 => return signal::SI_ASYNCIO,
            0x10005 => return signal::SI_MESGQ,
            _ => {}
        }
    }
    code
}

/// The Linux `siginfo` fields `(si_code, si_pid, si_uid, si_status)` of
/// host signal `sig` delivered with `info`.
///
/// macOS empties the `siginfo` of a signal left pending while blocked. For
/// `SIGCHLD` the child it is about is then found with a `waitid` that
/// neither blocks nor reaps (`WNOHANG | WNOWAIT`), so the guest still learns
/// which child changed state and how, as Linux tells it.
///
/// # Safety
/// `info` is the `siginfo_t` the host passed a `SA_SIGINFO` handler.
pub unsafe fn signal_info(sig: libc::c_int, info: *const libc::siginfo_t) -> (i32, i32, u32, i32) {
    // SAFETY: guaranteed by the caller.
    let (mut code, mut pid, mut uid, mut status) =
        unsafe { ((*info).si_code, (*info).si_pid(), (*info).si_uid(), (*info).si_status()) };
    // A `SIGCHLD` this process sent itself with `kill` comes with no
    // information when macOS held it pending (`si_code` and `si_pid` 0),
    // and else may name this process as its sender: either way not a
    // child's (no process is its own child), so the reaper's report.
    // SAFETY: getpid cannot fail.
    let sent_self = (code == 0 && pid == 0) || pid == unsafe { libc::getpid() };
    if sig == libc::SIGCHLD
        && sent_self
        && let Some((c, p, s)) = crate::reaper::take_report()
    {
        // An adopted process's end, which fwe's reaper sent this process
        // (`si_code` and `si_status` already Linux's).
        // SAFETY: getuid cannot fail.
        return (c, p, uid_to_initial(unsafe { libc::getuid() }), s);
    }
    if sig == libc::SIGCHLD && pid == 0 {
        let saved = last_errno();
        // SAFETY: an all-zero siginfo_t is a valid out-parameter; the call
        // only inspects children.
        let child = unsafe {
            let mut si: libc::siginfo_t = std::mem::zeroed();
            let how = libc::WEXITED | libc::WSTOPPED | libc::WCONTINUED;
            (libc::waitid(libc::P_ALL, 0, &mut si, how | libc::WNOHANG | libc::WNOWAIT) == 0
                && si.si_pid() != 0)
                .then_some(si)
        };
        if let Some(si) = child {
            // SAFETY: filled in by the host.
            (code, pid, uid, status) =
                unsafe { (si.si_code, si.si_pid(), si.si_uid(), si.si_status()) };
        }
        set_errno(saved);
    }
    // A signal sent by another fwe process left a note of its sender, for
    // when it comes with none ([`crate::signote`]).
    #[cfg(target_os = "macos")]
    {
        /// macOS's `SI_USER`.
        const SENT: i32 = 0x10001;
        if code == 0 && pid == 0 {
            if let Some((p, u)) = crate::signote::take(sig) {
                (code, pid, uid) = (SENT, p, u);
            }
        } else if code == SENT {
            crate::signote::clear(sig, pid);
        }
    }
    let code = si_code_to_linux(code);
    let killed = matches!(code, wait::CLD_KILLED | wait::CLD_DUMPED | wait::CLD_STOPPED);
    if sig == libc::SIGCHLD && killed {
        status = signal_to_linux(status) as i32;
    }
    (code, pid, uid_to_initial(uid), status)
}

/// Set the calling thread's host `errno`.
pub fn set_errno(value: i32) {
    // SAFETY: writing this thread's errno.
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = value
    };
    // SAFETY: as above.
    #[cfg(not(target_os = "macos"))]
    unsafe {
        *libc::__errno_location() = value
    };
}

/// The microseconds of a host `timeval`: `i32` on macOS, `i64` on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn usec(t: libc::timeval) -> i64 {
    t.tv_usec as i64
}

/// Write host resource usage into a guest `struct rusage` (two `timeval`s
/// and fourteen `long`s on both hosts). macOS reports `ru_maxrss` in bytes,
/// Linux in kilobytes. A zero `out` writes nothing.
pub fn write_rusage(out: u64, usage: &libc::rusage) -> crate::uaccess::Result<()> {
    if out == 0 {
        return Ok(());
    }
    let maxrss = if cfg!(target_os = "macos") { usage.ru_maxrss / 1024 } else { usage.ru_maxrss };
    let words: [i64; 18] = [
        usage.ru_utime.tv_sec,
        usec(usage.ru_utime),
        usage.ru_stime.tv_sec,
        usec(usage.ru_stime),
        maxrss,
        usage.ru_ixrss,
        usage.ru_idrss,
        usage.ru_isrss,
        usage.ru_minflt,
        usage.ru_majflt,
        usage.ru_nswap,
        usage.ru_inblock,
        usage.ru_oublock,
        usage.ru_msgsnd,
        usage.ru_msgrcv,
        usage.ru_nsignals,
        usage.ru_nvcsw,
        usage.ru_nivcsw,
    ];
    const _: () = assert!(18 * 8 == fwe_abi::resource_usage::RUSAGE_SIZE);
    crate::uaccess::write(out, words)
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

/// A Linux `struct flock` in host layout, or `EINVAL` for an unknown lock
/// type or `whence`.
pub fn flock_to_host(lock: &fwe_abi::Flock) -> Result<libc::flock, i32> {
    let l_type = match lock.l_type {
        fcntl::F_RDLCK => libc::F_RDLCK,
        fcntl::F_WRLCK => libc::F_WRLCK,
        fcntl::F_UNLCK => libc::F_UNLCK,
        _ => return Err(le::EINVAL),
    };
    if !(0..=2).contains(&lock.l_whence) {
        return Err(le::EINVAL);
    }
    // SAFETY: `flock` is plain data; every field is set below.
    let mut host: libc::flock = unsafe { std::mem::zeroed() };
    host.l_type = l_type as _;
    // SEEK_SET, SEEK_CUR and SEEK_END are 0, 1 and 2 on both.
    host.l_whence = lock.l_whence as _;
    host.l_start = lock.l_start;
    host.l_len = lock.l_len;
    host.l_pid = lock.l_pid;
    Ok(host)
}

/// A host `struct flock` (as `F_GETLK` fills it) in Linux layout.
// The host lock constants are `short` on macOS and `int` on Linux, so the
// casts below are redundant on one of them.
#[allow(clippy::unnecessary_cast)]
pub fn flock_to_linux(host: &libc::flock) -> fwe_abi::Flock {
    let l_type = match host.l_type as i32 {
        t if t == libc::F_RDLCK as i32 => fcntl::F_RDLCK,
        t if t == libc::F_WRLCK as i32 => fcntl::F_WRLCK,
        _ => fcntl::F_UNLCK,
    };
    fwe_abi::Flock {
        l_type,
        l_whence: host.l_whence,
        l_start: host.l_start,
        l_len: host.l_len,
        l_pid: host.l_pid,
    }
}

/// `flock` operation bits from Linux to host (the same values on both, but
/// named here so a stray bit is refused rather than passed on).
pub fn flock_op_to_host(op: u64) -> Option<libc::c_int> {
    let lock = match op & !fcntl::LOCK_NB {
        fcntl::LOCK_SH => libc::LOCK_SH,
        fcntl::LOCK_EX => libc::LOCK_EX,
        fcntl::LOCK_UN => libc::LOCK_UN,
        _ => return None,
    };
    Some(if op & fcntl::LOCK_NB != 0 { lock | libc::LOCK_NB } else { lock })
}

/// The host `openat`, without macOS's spurious `ENOENT` for `O_CREAT`.
///
/// On macOS an `O_CREAT` open fails with `ENOENT` when another process is
/// unlinking the same name at that moment (SQLite's processes do this to
/// a `-wal` file as each closes). Linux creates the file instead, and fails
/// an `O_CREAT` open with `ENOENT` only when the directory itself has been
/// removed, so the open is retried while the directory still exists.
///
/// # Safety
/// `dir` is an open directory descriptor.
pub unsafe fn openat(
    dir: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> libc::c_int {
    let mut tries = 0;
    loop {
        // SAFETY: `name` is NUL-terminated; the caller vouches for `dir`.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags, mode) };
        if fd >= 0 || flags & libc::O_CREAT == 0 || last_errno() != libc::ENOENT || tries == 100 {
            return fd;
        }
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and out parameter.
        if unsafe { libc::fstat(dir, &mut st) } != 0 || st.st_nlink == 0 {
            set_errno(libc::ENOENT);
            return -1;
        }
        tries += 1;
        std::thread::yield_now();
    }
}

/// The error of a failed terminal request (`tcgetattr` and the like): Linux
/// answers `ENOTTY` for anything that is not a terminal, where macOS gives
/// `ENODEV` for some devices (`/dev/null`) and `EOPNOTSUPP` for others.
pub fn tty_error() -> i64 {
    match last_errno() {
        libc::ENODEV | libc::EOPNOTSUPP => -(le::ENOTTY as i64),
        _ => last_error(),
    }
}

/// A host `struct statfs` in Linux layout. The filesystem type is reported
/// as ext4, which is what a Linux rootfs would most likely be; the sizes
/// and counts are the host's.
#[cfg(target_os = "macos")]
pub fn statfs_to_linux(s: &libc::statfs) -> fwe_abi::Statfs {
    use fwe_abi::statfs::*;
    let mut flags = 0;
    if s.f_flags & libc::MNT_RDONLY as u32 != 0 {
        flags |= ST_RDONLY;
    }
    if s.f_flags & libc::MNT_NOSUID as u32 != 0 {
        flags |= ST_NOSUID;
    }
    fwe_abi::Statfs {
        f_type: EXT4_SUPER_MAGIC,
        f_bsize: i64::from(s.f_bsize),
        f_blocks: s.f_blocks,
        f_bfree: s.f_bfree,
        f_bavail: s.f_bavail,
        f_files: s.f_files,
        f_ffree: s.f_ffree,
        f_fsid: fsid(&s.f_fsid),
        f_namelen: 255,
        f_frsize: i64::from(s.f_bsize),
        f_flags: flags,
        f_spare: [0; 4],
    }
}

/// A host `struct statfs` in arm64 layout (a Linux host has it already,
/// but its `f_fsid` is opaque).
#[cfg(target_os = "linux")]
pub fn statfs_to_linux(s: &libc::statfs) -> fwe_abi::Statfs {
    fwe_abi::Statfs {
        f_type: s.f_type,
        f_bsize: s.f_bsize,
        f_blocks: s.f_blocks,
        f_bfree: s.f_bfree,
        f_bavail: s.f_bavail,
        f_files: s.f_files,
        f_ffree: s.f_ffree,
        f_fsid: fsid(&s.f_fsid),
        f_namelen: s.f_namelen,
        f_frsize: s.f_frsize,
        f_flags: 0,
        f_spare: [0; 4],
    }
}

/// A filesystem id's two words (the libc crate keeps them private).
fn fsid(id: &libc::fsid_t) -> [i32; 2] {
    const _: () = assert!(size_of::<libc::fsid_t>() == 8);
    // SAFETY: `fsid_t` is two 32-bit integers on both hosts.
    unsafe { std::mem::transmute_copy(id) }
}

/// `msync` flags from Linux to host, or `None` for an unknown bit or for
/// both `MS_ASYNC` and `MS_SYNC`.
pub fn msync_flags_to_host(flags: u64) -> Option<libc::c_int> {
    use fwe_abi::statfs::*;
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & MS_ASYNC != 0 && flags & MS_SYNC != 0
    {
        return None;
    }
    let mut h = 0;
    for (l, hb) in
        [(MS_ASYNC, libc::MS_ASYNC), (MS_INVALIDATE, libc::MS_INVALIDATE), (MS_SYNC, libc::MS_SYNC)]
    {
        if flags & l != 0 {
            h |= hb;
        }
    }
    Some(h)
}

/// Seconds since the host booted (macOS's `CLOCK_MONOTONIC` counts sleep,
/// as Linux's boot-time clock does).
pub fn uptime() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid out parameter.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// Each host CPU's time so far, in clock ticks (100 a second, Linux's
/// `USER_HZ`): user, nice, system and idle. Empty if unavailable.
pub fn cpu_times() -> Vec<[u64; 4]> {
    #[cfg(target_os = "macos")]
    {
        // `PROCESSOR_CPU_LOAD_INFO`, and the order of `cpu_ticks`.
        const LOAD_INFO: i32 = 2;
        const USER: usize = 0;
        const SYSTEM: usize = 1;
        const IDLE: usize = 2;
        const NICE: usize = 3;
        unsafe extern "C" {
            fn host_processor_info(
                host: u32,
                flavor: i32,
                count: *mut u32,
                info: *mut *mut i32,
                info_count: *mut u32,
            ) -> i32;
            fn mach_host_self() -> u32;
            fn vm_deallocate(task: u32, addr: usize, size: usize) -> i32;
            static mach_task_self_: u32;
        }
        let (mut cpus, mut info, mut words) = (0u32, std::ptr::null_mut::<i32>(), 0u32);
        // SAFETY: valid out-parameters; the kernel allocates `info`.
        if unsafe {
            host_processor_info(mach_host_self(), LOAD_INFO, &mut cpus, &mut info, &mut words)
        } != 0
        {
            return Vec::new();
        }
        // SAFETY: `info` holds `words` integers, four per CPU.
        let ticks = unsafe { std::slice::from_raw_parts(info, words as usize) };
        let out = ticks
            .chunks_exact(4)
            .take(cpus as usize)
            .map(|t| {
                let v = |i: usize| u64::from(t[i] as u32);
                [v(USER), v(NICE), v(SYSTEM), v(IDLE)]
            })
            .collect();
        // SAFETY: freeing what the kernel allocated, in this task.
        unsafe { vm_deallocate(mach_task_self_, info as usize, words as usize * 4) };
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
        stat.lines()
            .filter(|l| l.starts_with("cpu") && !l.starts_with("cpu "))
            .map(|l| {
                let f: Vec<u64> =
                    l.split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect();
                [
                    f.first().copied().unwrap_or(0),
                    f.get(1).copied().unwrap_or(0),
                    f.get(2).copied().unwrap_or(0),
                    f.get(3).copied().unwrap_or(0),
                ]
            })
            .collect()
    }
}

/// The host's 1, 5 and 15 minute load averages (zero if unavailable).
pub fn load_averages() -> [f64; 3] {
    let mut loads = [0f64; 3];
    // SAFETY: `loads` has room for the three values asked for.
    if unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) } != 3 {
        return [0.0; 3];
    }
    loads
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

/// `fallocate(fd, mode, offset, len)` on the host, returning a Linux errno
/// on failure. Mode 0 reserves the space and extends the file to cover the
/// range, `FALLOC_FL_KEEP_SIZE` only reserves it, and with
/// `FALLOC_FL_PUNCH_HOLE` too the range reads as zeros and its blocks are
/// freed. macOS reserves space only past the end of a file, so a hole
/// inside a sparse file is not filled. Other modes are `EOPNOTSUPP`, as on
/// a Linux filesystem without them.
pub fn fallocate(fd: i32, mode: u64, offset: i64, len: i64) -> Result<(), i32> {
    use fwe_abi::falloc::{FALLOC_FL_KEEP_SIZE as KEEP, FALLOC_FL_PUNCH_HOLE as PUNCH};
    if offset < 0 || len <= 0 {
        return Err(le::EINVAL);
    }
    let end = offset.checked_add(len).ok_or(le::EFBIG)?;
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(errno_to_linux(last_errno()));
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => {}
        libc::S_IFIFO | libc::S_IFSOCK => return Err(le::ESPIPE),
        _ => return Err(le::ENODEV),
    }
    // SAFETY: F_GETFL only reads the descriptor's flags.
    if unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE == libc::O_RDONLY {
        return Err(le::EBADF);
    }
    let fail = || Err(errno_to_linux(last_errno()));
    match mode {
        0 | KEEP => {
            if end > st.st_size {
                reserve_past_end(fd, end - st.st_size)?;
                // SAFETY: plain host call on the caller's descriptor.
                if mode == 0 && unsafe { libc::ftruncate(fd, end) } != 0 {
                    return fail();
                }
            }
            Ok(())
        }
        m if m == PUNCH | KEEP => {
            let end = end.min(st.st_size);
            if offset >= end {
                return Ok(());
            }
            // SAFETY: zeroed bytes are a valid `statfs`; `fstatfs` fills it.
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            // SAFETY: `fs` is a valid out-parameter.
            if unsafe { libc::fstatfs(fd, &mut fs) } != 0 {
                return fail();
            }
            // The host frees whole blocks; the partial ones at either end
            // are written with zeros.
            // `f_bsize` is a `u32` on macOS and already an `i64` on Linux.
            #[allow(clippy::useless_conversion)]
            let block = i64::from(fs.f_bsize).max(1);
            let lo = (offset + block - 1) / block * block;
            let hi = end / block * block;
            if lo < hi {
                punch_hole(fd, lo, hi - lo)?;
                write_zeros(fd, offset, lo)?;
                write_zeros(fd, hi, end)
            } else {
                write_zeros(fd, offset, end)
            }
        }
        _ => Err(le::EOPNOTSUPP),
    }
}

/// Reserve `len` bytes past the end of the file.
#[cfg(target_os = "macos")]
fn reserve_past_end(fd: i32, len: i64) -> Result<(), i32> {
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: len,
        fst_bytesalloc: 0,
    };
    // SAFETY: `store` is a valid `fstore_t`.
    if unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) } != 0 {
        return Err(errno_to_linux(last_errno()));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn reserve_past_end(fd: i32, len: i64) -> Result<(), i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: plain host calls on the caller's descriptor.
    let r = unsafe {
        libc::fstat(fd, &mut st);
        libc::fallocate(fd, libc::FALLOC_FL_KEEP_SIZE, st.st_size, len)
    };
    if r != 0 {
        return Err(errno_to_linux(last_errno()));
    }
    Ok(())
}

/// Free the blocks of `[offset, offset + len)`, which is block-aligned.
#[cfg(target_os = "macos")]
fn punch_hole(fd: i32, offset: i64, len: i64) -> Result<(), i32> {
    let mut hole =
        libc::fpunchhole_t { fp_flags: 0, reserved: 0, fp_offset: offset, fp_length: len };
    // SAFETY: `hole` is a valid `fpunchhole_t`.
    if unsafe { libc::fcntl(fd, libc::F_PUNCHHOLE, &mut hole) } != 0 {
        return Err(errno_to_linux(last_errno()));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn punch_hole(fd: i32, offset: i64, len: i64) -> Result<(), i32> {
    let mode = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
    // SAFETY: plain host call on the caller's descriptor.
    if unsafe { libc::fallocate(fd, mode, offset, len) } != 0 {
        return Err(errno_to_linux(last_errno()));
    }
    Ok(())
}

/// Write zeros over `[from, to)` of the file.
fn write_zeros(fd: i32, mut from: i64, to: i64) -> Result<(), i32> {
    let zeros = [0u8; 4096];
    while from < to {
        let n = ((to - from) as usize).min(zeros.len());
        // SAFETY: `zeros` holds at least `n` bytes.
        let w = unsafe { libc::pwrite(fd, zeros.as_ptr().cast(), n, from) };
        if w <= 0 {
            return Err(if w == 0 { le::EIO } else { errno_to_linux(last_errno()) });
        }
        from += w as i64;
    }
    Ok(())
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

    /// `fallocate`: mode 0 extends the file, `KEEP_SIZE` does not, a
    /// punched hole reads as zeros (partial blocks included) and leaves the
    /// size; bad arguments, descriptors and modes fail as on Linux.
    #[test]
    fn fallocate_extends_keeps_and_punches() {
        use fwe_abi::falloc::{FALLOC_FL_KEEP_SIZE as KEEP, FALLOC_FL_PUNCH_HOLE as PUNCH};
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("fwe-fallocate-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let fd = f.as_raw_fd();
        assert_eq!(fallocate(fd, 0, 0, 10000), Ok(()));
        assert_eq!(f.metadata().unwrap().len(), 10000);
        assert_eq!(fallocate(fd, KEEP, 0, 50000), Ok(()));
        assert_eq!(f.metadata().unwrap().len(), 10000);
        f.write_all(&vec![7u8; 10000]).unwrap();
        // A range across several blocks, starting and ending inside one.
        assert_eq!(fallocate(fd, PUNCH | KEEP, 100, 9000), Ok(()));
        assert_eq!(f.metadata().unwrap().len(), 10000);
        let mut back = Vec::new();
        f.rewind().unwrap();
        f.read_to_end(&mut back).unwrap();
        assert!(back[..100].iter().all(|&b| b == 7));
        assert!(back[100..9100].iter().all(|&b| b == 0));
        assert!(back[9100..].iter().all(|&b| b == 7));
        assert_eq!(fallocate(fd, PUNCH, 0, 1), Err(le::EOPNOTSUPP));
        assert_eq!(fallocate(fd, 0, -1, 1), Err(le::EINVAL));
        assert_eq!(fallocate(fd, 0, 0, 0), Err(le::EINVAL));
        let ro = std::fs::File::open(&path).unwrap();
        assert_eq!(fallocate(ro.as_raw_fd(), 0, 0, 1), Err(le::EBADF));
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(fallocate(fds[1], 0, 0, 1), Err(le::ESPIPE));
        // SAFETY: closing the pipe made above.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// What [`rename_at`] does about a file already at the new name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rename {
    /// Replaces it, as `rename` does.
    Replace,
    /// Fails with `EEXIST` (Linux's `RENAME_NOREPLACE`), atomically.
    NoReplace,
    /// Swaps the two, both of which must exist (`RENAME_EXCHANGE`).
    Exchange,
}

/// Rename `on` in directory `od` to `nn` in `nd`, atomically in each
/// mode: macOS's `renameatx_np` with `RENAME_EXCL` or `RENAME_SWAP`,
/// Linux's `renameat2`. A filesystem that cannot is `EINVAL`, as on Linux.
pub fn rename_at(
    od: i32,
    on: &std::ffi::CStr,
    nd: i32,
    nn: &std::ffi::CStr,
    how: Rename,
) -> Result<(), i32> {
    #[cfg(target_os = "macos")]
    let r = {
        let flags = match how {
            Rename::Replace => 0,
            Rename::NoReplace => libc::RENAME_EXCL,
            Rename::Exchange => libc::RENAME_SWAP,
        };
        // SAFETY: names NUL-terminated; the caller's directories.
        unsafe { libc::renameatx_np(od, on.as_ptr(), nd, nn.as_ptr(), flags) }
    };
    #[cfg(not(target_os = "macos"))]
    let r = {
        let flags: libc::c_uint = match how {
            Rename::Replace => 0,
            Rename::NoReplace => 1,
            Rename::Exchange => 2,
        };
        // SAFETY: names NUL-terminated; the caller's directories.
        let r =
            unsafe { libc::syscall(libc::SYS_renameat2, od, on.as_ptr(), nd, nn.as_ptr(), flags) };
        r as i32
    };
    if r == 0 {
        return Ok(());
    }
    match last_errno() {
        #[cfg(target_os = "macos")]
        libc::ENOTSUP if how != Rename::Replace => Err(le::EINVAL),
        e => Err(errno_to_linux(e)),
    }
}

/// Make `dst` in directory `dst_dir` a copy of the regular file open as
/// `src` that shares its blocks until either is written (an APFS clone),
/// with its mode, flags and extended attributes. `EOPNOTSUPP` where the
/// host cannot (another filesystem, or not macOS): the caller copies.
pub fn clone_at(src: i32, dst_dir: i32, dst: &std::ffi::CStr) -> Result<(), i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: a NUL-terminated name; the caller's descriptors.
        if unsafe { libc::fclonefileat(src, dst_dir, dst.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        match last_errno() {
            libc::ENOTSUP | libc::EXDEV => Err(le::EOPNOTSUPP),
            e => Err(errno_to_linux(e)),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (src, dst_dir, dst);
        Err(le::EOPNOTSUPP)
    }
}
