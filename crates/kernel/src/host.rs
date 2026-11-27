//! Translation between Linux ABI values and host (macOS) values.
//!
//! Host values come from the `libc` crate, so this module compiles on any
//! Unix host; on Linux hosts most translations are the identity.

use crate::ids::HostPid;
use fwe_abi::{clock, errno as le, fcntl, resource, signal, wait};

/// A host `errno`: the host's numbering, which is not Linux's (`EAGAIN`
/// is 35 on macOS, 11 on Linux). It is never handed to the guest as it is:
/// [`HostErrno::linux`] is the Linux errno of the same meaning, and it
/// compares only with a host constant ([`HostErrno::is`]). The bare number
/// in memory (`#[repr(transparent)]`).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostErrno(i32);

impl HostErrno {
    /// Host errno `e` (a `libc` constant, or a number the host gave).
    #[inline]
    pub const fn new(e: i32) -> HostErrno {
        HostErrno(e)
    }

    /// Whether it is host errno `e` (a `libc` constant).
    #[inline]
    pub const fn is(self, e: i32) -> bool {
        self.0 == e
    }

    /// The Linux errno of the same meaning.
    #[inline]
    pub fn linux(self) -> i32 {
        errno_to_linux(self)
    }

    /// The host's number, for the host's own interfaces
    /// (`std::io::Error::from_raw_os_error`, a host call's result).
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for HostErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::io::Error::from_raw_os_error(self.0).fmt(f)
    }
}

/// The calling thread's host `errno`.
pub fn last_errno() -> HostErrno {
    HostErrno(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
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
pub fn errno_to_linux(host: HostErrno) -> i32 {
    ERRNO_TABLE.iter().find(|(h, _)| *h == host.0).map(|(_, l)| *l).unwrap_or(le::EIO)
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
/// handler can compute (it takes no lock), translated when the guest is
/// given it.
pub fn uid_to_initial(uid: u32) -> u32 {
    if uid == euid() { 0 } else { OVERFLOW_ID }
}

/// [`uid_to_linux`] for group ids: fwe's own group is the guest's root
/// group.
pub fn gid_to_linux(gid: u32) -> u32 {
    crate::userns::to_ns(gid_to_initial(gid), true)
}

/// [`gid_to_linux`] in the initial user namespace's terms.
pub fn gid_to_initial(gid: u32) -> u32 {
    if gid == egid() { 0 } else { OVERFLOW_ID }
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

/// The CPU time host thread `t` of this process has used, user and
/// system, in nanoseconds.
pub fn thread_cpu_ns(t: libc::pthread_t) -> Option<(u64, u64)> {
    thread_state(t).map(|(user, system, _)| (user, system))
}

/// Host thread `t` of this process: its CPU time, user and system, in
/// nanoseconds, and whether it runs (or waits only for a processor).
pub fn thread_state(t: libc::pthread_t) -> Option<(u64, u64, bool)> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: a live thread of this process (the caller's guarantee:
        // fwe's record of it); zeroed bytes are a valid info structure,
        // which the call fills, `count` words of it.
        unsafe {
            let port = libc::pthread_mach_thread_np(t);
            let mut info: libc::thread_extended_info = std::mem::zeroed();
            let mut count = libc::THREAD_EXTENDED_INFO_COUNT;
            let kr = libc::thread_info(
                port,
                libc::THREAD_EXTENDED_INFO as libc::thread_flavor_t,
                (&mut info as *mut libc::thread_extended_info).cast(),
                &mut count,
            );
            (kr == 0).then_some((
                info.pth_user_time,
                info.pth_system_time,
                info.pth_run_state == libc::TH_STATE_RUNNING,
            ))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = t;
        None
    }
}

/// Host resource for a Linux resource limit, if the host has it.
pub fn rlimit_to_host(resource: u64) -> Option<libc::c_int> {
    Some(match resource {
        resource::RLIMIT_FSIZE => libc::RLIMIT_FSIZE as libc::c_int,
        resource::RLIMIT_NOFILE => libc::RLIMIT_NOFILE as libc::c_int,
        _ => return None,
    })
}

pub fn rlim_to_linux(v: libc::rlim_t) -> u64 {
    if v == libc::RLIM_INFINITY { resource::RLIM_INFINITY } else { v }
}

pub fn rlim_to_host(v: u64) -> libc::rlim_t {
    // Linux's infinity, or past the host's largest (its infinity, 2^63 - 1
    // on macOS), which Linux takes: no limit.
    #[cfg(target_os = "macos")]
    let past = v > i64::MAX as u64;
    #[cfg(not(target_os = "macos"))]
    let past = false;
    if v == resource::RLIM_INFINITY || past { libc::RLIM_INFINITY } else { v }
}

/// Host signal for a Linux signal number, if the host has an equivalent.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
/// cannot be caught, and a hypervisor-backend process MUST NOT die with
/// its VM alive, so fwe processes are sent this instead (a host signal with
/// no Linux counterpart): a VM process takes it as the guest's `SIGKILL`,
/// tearing its VM down before it dies of `SIGKILL`, and a native one
/// simply dies of `SIGKILL`. Other processes get the real `SIGKILL`.
#[cfg(target_os = "macos")]
pub const KILL_RELAY: libc::c_int = libc::SIGINFO;
#[cfg(not(target_os = "macos"))]
pub const KILL_RELAY: libc::c_int = libc::SIGKILL;

/// In the handler of [`KILL_RELAY`]: whether it is a guest's `SIGKILL`
/// relayed by an fwe process, which leaves a note first, rather than the
/// host's own `SIGINFO` (macOS's Ctrl-T status key, a `kill -INFO`), which
/// Linux has no counterpart of and is dropped. Async-signal-safe.
pub fn kill_relayed() -> bool {
    crate::signote::take(KILL_RELAY).is_some()
}

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

/// The host's latest pid, as near as the host tells it: on macOS, which
/// keeps no count of it, the highest pid in use; on Linux, the initial pid
/// namespace's `ns_last_pid`.
#[cfg(target_os = "macos")]
pub fn last_pid() -> i32 {
    // <sys/proc_info.h>: PROC_ALL_PIDS.
    // SAFETY: sizing, then filling, a buffer of pids.
    unsafe {
        let n = libc::proc_listpids(1, 0, std::ptr::null_mut(), 0);
        if n <= 0 {
            return 0;
        }
        let mut pids = vec![0 as libc::pid_t; n as usize / size_of::<libc::pid_t>() + 64];
        let n = libc::proc_listpids(
            1,
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<libc::pid_t>()) as i32,
        );
        pids.truncate(n.max(0) as usize / size_of::<libc::pid_t>());
        pids.into_iter().max().unwrap_or(0)
    }
}

/// The host's latest pid: on Linux, its `ns_last_pid`.
#[cfg(not(target_os = "macos"))]
pub fn last_pid() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/ns_last_pid")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The processes of host process group `pgid`, fwe's and others.
#[cfg(target_os = "macos")]
pub fn group_members(pgid: HostPid) -> Vec<HostPid> {
    // <sys/proc_info.h>: PROC_PGRP_ONLY.
    let (kind, arg): (u32, u32) = (2, pgid.get() as u32);
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
        pids.into_iter().filter_map(HostPid::new).collect()
    }
}

/// The processes of host process group `pgid`, fwe's and others, read
/// from `/proc`.
#[cfg(not(target_os = "macos"))]
pub fn group_members(pgid: HostPid) -> Vec<HostPid> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
    dir.filter_map(|e| HostPid::new(e.ok()?.file_name().to_str()?.parse().ok()?))
        .filter(|&p| {
            // The group is the fifth field, after the name in parentheses.
            std::fs::read_to_string(format!("/proc/{}/stat", p.get())).ok().is_some_and(|st| {
                st.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().nth(2)?.parse().ok())
                    == Some(pgid.get())
            })
        })
        .collect()
}

/// Whether host descriptor `fd` is of a file with no name left (a memfd's,
/// or one unlinked after it was opened): one kept to share memory.
pub fn unlinked(fd: i32) -> bool {
    // SAFETY: a zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: plain host call into `st`.
    unsafe { libc::fstat(fd, &mut st) == 0 && st.st_nlink == 0 }
}

/// `kill` of host process `pid` with host signal `sig`, for
/// [`kill_process`] and [`signal_named`]: one process, never a group or
/// every process (no [`HostPid`] names one). A `SIGKILL` reaches an fwe
/// process as [`KILL_RELAY`], with a note of its sender
/// ([`kill_relayed`]). Returns 0 or a negated Linux errno.
///
/// [`WAKE_SIGNAL`] goes only to a live fwe process (`ESRCH` otherwise):
/// any other process takes the host's default action for it, which ends
/// it.
fn kill(pid: HostPid, sig: libc::c_int) -> i64 {
    if sig == WAKE_SIGNAL && !is_fwe(pid) {
        return fwe_abi::err(fwe_abi::errno::ESRCH);
    }
    #[cfg(target_os = "macos")]
    if sig == libc::SIGKILL {
        let fwe = exe_of(pid_now().get());
        if fwe.is_some() && exe_of(pid.get()) == fwe {
            // The relay is taken only with a note of its sender: the
            // host's own SIGINFO (macOS's Ctrl-T) is no kill.
            crate::signote::note(pid, KILL_RELAY);
            return ret(raw_kill(pid.get(), KILL_RELAY));
        }
    }
    ret(raw_kill(pid.get(), sig))
}

/// The host's `kill(pid, sig)` itself, for this module's typed callers and
/// a process's signal to itself ([`kill_self`]). Async-signal-safe.
#[allow(clippy::disallowed_methods)] // the one call of the host's `kill`
fn raw_kill(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int {
    // SAFETY: plain host call; every caller names its target by type.
    unsafe { libc::kill(pid, sig) }
}

/// Host signal `sig` to this process itself. Async-signal-safe.
pub fn kill_self(sig: libc::c_int) {
    raw_kill(pid_now().get(), sig);
}

/// The host's `SIGKILL` to `child`, a child of this process it reaps next
/// (one it could not finish setting up): the host's own, never relayed, as
/// the child might not take fwe's relay yet.
pub fn kill_child(child: HostPid) {
    raw_kill(child.get(), libc::SIGKILL);
}

/// What the host says of a process asked whether it is there (its `kill`
/// with signal 0).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    /// There, and this user can signal it.
    Live,
    /// There (a zombie is), but not this user's to signal.
    NoPermission,
    Gone,
}

impl Probe {
    /// Whether the process is there, whoever's it is.
    pub fn exists(self) -> bool {
        self != Probe::Gone
    }
}

/// Whether host process `pid` is there. Async-signal-safe.
pub fn probe(pid: HostPid) -> Probe {
    if raw_kill(pid.get(), 0) == 0 {
        return Probe::Live;
    }
    match last_errno().raw() {
        libc::EPERM => Probe::NoPermission,
        _ => Probe::Gone,
    }
}

/// Mark the open file description of `fd` as opened without a right a
/// Landlock domain withheld for its kind ([`crate::landlock`]): truncating
/// a regular file, `ioctl` on a device. The mark is the description's
/// no-`SIGPIPE` flag (`F_SETNOSIGPIPE`), kept with the description and so
/// with every descriptor of it in any process, and unused by a regular
/// file or a device, which raise no `SIGPIPE`; a descriptor of another
/// kind on the host (a socket fwe makes for a device) is not marked.
#[cfg(target_os = "macos")]
pub fn mark_landlock_denied(fd: i32) {
    if markable(fd) {
        // SAFETY: plain host call on the guest's descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETNOSIGPIPE, 1) };
    }
}

/// Whether the open file description of `fd` carries the mark of
/// [`mark_landlock_denied`].
#[cfg(target_os = "macos")]
pub fn landlock_denied(fd: i32) -> bool {
    // SAFETY: plain host call on the guest's descriptor.
    markable(fd) && unsafe { libc::fcntl(fd, libc::F_GETNOSIGPIPE) } == 1
}

/// Another host keeps no such mark: guests run on macOS only.
#[cfg(not(target_os = "macos"))]
pub fn mark_landlock_denied(_fd: i32) {}

/// Another host keeps no such mark: guests run on macOS only.
#[cfg(not(target_os = "macos"))]
pub fn landlock_denied(_fd: i32) -> bool {
    false
}

/// Whether `fd` is a regular file or a device on the host.
#[cfg(target_os = "macos")]
fn markable(fd: i32) -> bool {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe { libc::fstat(fd, &mut st) == 0 };
    ok && matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFCHR | libc::S_IFBLK)
}

/// A host `stat`'s device number as Linux's: macOS's `dev_t` is a signed
/// 32-bit word, and a number of Linux's encoding with a minor of `0x80000`
/// or more (a tmpfs's of fwe's store) has its top bit set, which widened
/// as a signed number would be no device's.
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
pub fn dev_of(st: &libc::stat) -> u64 {
    #[cfg(target_os = "macos")]
    return st.st_dev as u32 as u64;
    #[cfg(not(target_os = "macos"))]
    return st.st_dev as u64;
}

/// `kill` of one host process `pid` for fwe's own ends (a pid it keeps:
/// a stop's end, a tracer's `SIGCHLD`, a cgroup's kill, a lease's or a
/// message queue's notice, a wake): only to one of fwe's processes
/// ([`is_fwe`]: its record's, of a process that started when this one
/// did), as a pid kept from a process that ended might be the host's now
/// (`ESRCH`). One refused is told on the standard error, with where it
/// was sent from. A guest's own signal to a process it names goes by
/// [`signal_named`]; whether a process is there, by [`probe`].
#[track_caller]
pub fn kill_process(pid: HostPid, sig: libc::c_int) -> i64 {
    // ([`kill`] looks for its wake signal itself.)
    if sig != WAKE_SIGNAL && !is_fwe(pid) {
        refused_signal(pid.get(), sig, std::panic::Location::caller());
        return fwe_abi::err(fwe_abi::errno::ESRCH);
    }
    kill(pid, sig)
}

/// A guest's signal `sig` to host process `pid`, which it named (`kill`,
/// `rt_sigqueueinfo`) and can signal: one of fwe's or one of the host's,
/// as a Linux process signals any it can.
pub fn signal_named(pid: HostPid, sig: libc::c_int) -> i64 {
    kill(pid, sig)
}

/// Tell that host signal `sig` to host process `pid`, not one of fwe's,
/// sent from `from`, was refused ([`kill_process`]). Async-signal-safe.
fn refused_signal(pid: libc::pid_t, sig: libc::c_int, from: &std::panic::Location<'_>) {
    let line = signal_line(b"fwe: host signal ", pid, sig, from, b", not one of fwe's, refused");
    // SAFETY: a valid buffer of the length given.
    unsafe { libc::write(2, line.buf.as_ptr().cast(), line.len) };
}

/// "`what` `sig` to host process `pid``why` (sent from `from`)", a line.
fn signal_line(
    what: &[u8],
    pid: libc::pid_t,
    sig: libc::c_int,
    from: &std::panic::Location<'_>,
    why: &[u8],
) -> Line {
    let mut line = Line::new();
    line.put(what);
    line.num(sig as u64);
    line.put(b" to host process ");
    line.num(pid as u64);
    line.put(why);
    line.put(b" (sent from ");
    line.put(from.file().as_bytes());
    line.put(b":");
    line.num(u64::from(from.line()));
    line.put(b")\n");
    line
}

/// A line put together without allocating (in a signal handler, say).
struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line { buf: [0; 512], len: 0 }
    }

    fn put(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn num(&mut self, mut v: u64) {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&digits[i..]);
    }
}

/// Host process `pid`'s nice value as the host has it (0 for one that
/// is not there).
pub fn nice_of(pid: HostPid) -> i32 {
    // SAFETY: plain host call; -1 is a valid value, so errno is not
    // consulted (an absent process reads as 0).
    let v = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid.get() as libc::id_t) };
    v.clamp(-20, 19)
}

/// Give host process `pid` (one of fwe's) nice value `nice`, which the
/// host scheduler then applies. The host lets a user raise a process's
/// nice value but not lower it (only its root can), so a guest's lowering
/// stands in fwe's record while the host process keeps the value it had:
/// Linux's result is the guest's, the host's limit is the host's.
pub fn set_nice(pid: HostPid, nice: i32) {
    // SAFETY: plain host call on one process of this user's.
    unsafe { libc::setpriority(libc::PRIO_PROCESS, pid.get() as libc::id_t, nice) };
}

/// Whether host process `pid` is a live fwe process (one with a record):
/// the only kind that takes fwe's internal signals ([`WAKE_SIGNAL`]) and
/// serves requests left in its mailbox.
pub fn is_fwe(pid: HostPid) -> bool {
    crate::procreg::read(pid).is_some()
}

thread_local! {
    /// How many [`NoAllocation`] marks the thread is under.
    static NO_ALLOCATION: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// While one lives, the calling thread is in a host signal handler that
/// interrupted fwe's own code, which might be inside the host allocator:
/// the thread MUST NOT allocate or free. A debug build's allocator ends the
/// process if something does ([`allocation_forbidden`]), so the tests find
/// it. Neither `Send` nor `Sync`: the mark is its thread's.
pub struct NoAllocation(std::marker::PhantomData<*const ()>);

impl NoAllocation {
    #[inline]
    pub fn enter() -> NoAllocation {
        NO_ALLOCATION.with(|n| n.set(n.get() + 1));
        NoAllocation(std::marker::PhantomData)
    }
}

impl Drop for NoAllocation {
    #[inline]
    fn drop(&mut self) {
        NO_ALLOCATION.with(|n| n.set(n.get() - 1));
    }
}

/// Whether the calling thread is under a [`NoAllocation`] mark.
#[inline]
pub fn allocation_forbidden() -> bool {
    NO_ALLOCATION.try_with(std::cell::Cell::get).is_ok_and(|n| n != 0)
}

/// A change of the calling thread's host signal mask, undone as it is
/// dropped: the mask goes back to what it was on every path out of the
/// scope that holds it. A mask is its thread's, so this stays on the thread
/// that made it (neither `Send` nor `Sync`). Async-signal-safe.
#[must_use = "dropped at once, it puts the mask back at once"]
pub struct MaskGuard {
    old: libc::sigset_t,
    _thread: std::marker::PhantomData<*const ()>,
}

impl MaskGuard {
    /// Block `set` too.
    #[inline(always)]
    pub fn block(set: &libc::sigset_t) -> MaskGuard {
        MaskGuard::change(libc::SIG_BLOCK, set)
    }

    /// Unblock `set`.
    #[inline(always)]
    pub fn unblock(set: &libc::sigset_t) -> MaskGuard {
        MaskGuard::change(libc::SIG_UNBLOCK, set)
    }

    /// Make `set` the mask.
    #[inline(always)]
    pub fn set(set: &libc::sigset_t) -> MaskGuard {
        MaskGuard::change(libc::SIG_SETMASK, set)
    }

    #[inline(always)]
    fn change(how: libc::c_int, set: &libc::sigset_t) -> MaskGuard {
        let mut old = empty_sigset();
        // SAFETY: initialized signal sets; only this thread's mask changes.
        unsafe { mask_call(how, set, &mut old) };
        MaskGuard { old, _thread: std::marker::PhantomData }
    }

    /// The mask as it was.
    pub fn old(&self) -> &libc::sigset_t {
        &self.old
    }

    /// Keep the change: the mask is not put back (a fork child that goes on
    /// with it, and sets its own later).
    #[inline(always)]
    pub fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for MaskGuard {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: the mask this thread had, as the change read it.
        unsafe { mask_call(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }
}

/// The host's `pthread_sigmask`, which only this module calls: a change
/// that lasts past its scope goes through [`set_signal_mask`],
/// [`block_signals`] or [`unblock_signals`], one undone as it ends through
/// a [`MaskGuard`].
///
/// # Safety
/// `set` null or an initialized set, `old` null or writable.
#[inline(always)]
#[allow(clippy::disallowed_methods)] // the one call of it
unsafe fn mask_call(how: libc::c_int, set: *const libc::sigset_t, old: *mut libc::sigset_t) {
    // SAFETY: as the caller promises; only this thread's mask changes.
    unsafe { libc::pthread_sigmask(how, set, old) };
}

/// Make `set` the calling thread's host mask from now on (a thread taking
/// on its guest mask). Async-signal-safe.
#[inline(always)]
pub fn set_signal_mask(set: &libc::sigset_t) {
    // SAFETY: an initialized set.
    unsafe { mask_call(libc::SIG_SETMASK, set, std::ptr::null_mut()) };
}

/// Block `set` on the calling thread from now on. Async-signal-safe.
#[inline(always)]
pub fn block_signals(set: &libc::sigset_t) {
    // SAFETY: an initialized set.
    unsafe { mask_call(libc::SIG_BLOCK, set, std::ptr::null_mut()) };
}

/// Unblock `set` on the calling thread from now on (one the process dies
/// of). Async-signal-safe.
#[inline(always)]
pub fn unblock_signals(set: &libc::sigset_t) {
    // SAFETY: an initialized set.
    unsafe { mask_call(libc::SIG_UNBLOCK, set, std::ptr::null_mut()) };
}

/// The calling thread's host mask. Async-signal-safe.
#[inline(always)]
pub fn signal_mask() -> libc::sigset_t {
    let mut set = empty_sigset();
    // SAFETY: no change; `set` is written.
    unsafe { mask_call(libc::SIG_BLOCK, std::ptr::null(), &mut set) };
    set
}

/// A host signal set of every signal.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn full_sigset() -> libc::sigset_t {
    // SAFETY: an all-zero sigset_t is valid storage; sigfillset fills it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut set);
        set
    }
}

#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn empty_sigset() -> libc::sigset_t {
    // SAFETY: an all-zero sigset_t is valid storage; sigemptyset initializes it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        set
    }
}

/// The host signal set holding the relayed signals in Linux set `mask`.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn host_sigset(mask: u64) -> libc::sigset_t {
    let mut set = empty_sigset();
    for sig in 1..=signal::NSIG {
        if mask & (1 << (sig - 1)) != 0
            && crate::signal::relayed(sig)
            && let Some(h) = signal_to_host(sig)
        {
            // SAFETY: `set` is an initialized signal set.
            unsafe { libc::sigaddset(&mut set, h) };
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
/// applies itself, which need to wait while the guest blocks them.
pub fn host_mask_for(mask: u64) -> libc::sigset_t {
    host_sigset(mask & !(crate::signal::caught() | crate::signalfd::watched()))
}

/// Stop the process on the host with host stop signal `sig` (`SIGTSTP`,
/// `SIGTTIN`, `SIGTTOU`, `SIGSTOP`) until it is continued, so that its
/// parent, a process that is not fwe's (a shell), sees it stop: raised on
/// this thread with its default action and unblocked for the moment, then
/// put back. Not if a `SIGCONT` came since the stop signal was sent
/// ([`crate::signal::stop_stands`]). The host's `SIGCONT` that ends it is
/// caught as it does ([`crate::signal::host_continued`]).
pub fn stop_with(sig: libc::c_int) {
    if crate::signal::stop_stands() {
        raise_stop(sig);
    }
}

/// [`stop_with`]'s stop.
fn raise_stop(sig: libc::c_int) {
    // SAFETY: plain host calls on initialized values; the disposition and
    // the mask are restored as they were.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, &dfl, &mut old);
        let mut set = empty_sigset();
        libc::sigaddset(&mut set, sig);
        let unblocked = MaskGuard::unblock(&set);
        // Delivered before raise returns: the process stops here.
        libc::raise(sig);
        drop(unblocked);
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
    set_signal_mask(&host_sigset(mask));
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
    let set = signal_mask();
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
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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
/// This process's parent on the host (none once it is reparented to no
/// process, which the host never does: launchd's is 1). Async-signal-safe.
pub fn parent_pid() -> Option<HostPid> {
    // SAFETY: plain host call.
    HostPid::new(unsafe { libc::getppid() })
}

/// Whether this process ignores `SIGCHLD` on the host (as the guest
/// does). Async-signal-safe.
pub fn sigchld_ignored() -> bool {
    // SAFETY: zeroed bytes are a valid `sigaction`; the call only reads.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter; no new action.
    unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    old.sa_sigaction == libc::SIG_IGN
}

pub fn sigchld_nocldstop() -> bool {
    // SAFETY: zeroed bytes are a valid `sigaction`; the call only reads.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter; no new action.
    unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    old.sa_flags & libc::SA_NOCLDSTOP != 0
}

/// Whether the host reaps this process's children as they end, leaving no
/// zombie for `wait`: it ignores `SIGCHLD`, or set `SA_NOCLDWAIT`.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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

/// The Linux `siginfo` of host signal `sig` delivered with `info`.
///
/// macOS empties the `siginfo` of a signal left pending while blocked. For
/// `SIGCHLD` the child it is about is then found with a `waitid` that
/// neither blocks nor reaps (`WNOHANG | WNOWAIT`), so the guest still learns
/// which child changed state and how, as Linux tells it.
///
/// # Safety
/// `info` is the `siginfo_t` the host passed a `SA_SIGINFO` handler.
pub unsafe fn signal_info(
    sig: libc::c_int,
    info: *const libc::siginfo_t,
) -> crate::thread::SigInfo {
    // SAFETY: guaranteed by the caller.
    let (mut code, mut pid, mut uid, mut status) =
        unsafe { ((*info).si_code, (*info).si_pid(), (*info).si_uid(), (*info).si_status()) };
    if let Some(slot) = LAST_HOST_INFO.get(sig as usize) {
        slot.store(
            ((code as u32 as u64) << 32) | pid as u32 as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
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
    // when it comes with none, and of what it carries ([`crate::signote`]),
    // with the sender's guest user id.
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut value = 0;
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut guest_uid = None;
    #[cfg(target_os = "macos")]
    {
        /// macOS's `SI_USER`.
        const SENT: i32 = 0x10001;
        // A signal another process sent can come with its sender and a
        // code of 0, with no sender (as when the sender has ended), or with
        // the code and pid of the sender's exit when it ended right after
        // sending. A note names its sender, so one that sender left is
        // taken whatever the code; with no sender, a note is taken for a
        // signal sent (not one the host raised, as for a fault).
        let note = if pid != 0 {
            crate::signote::take_from(sig, pid)
        } else if code == SENT || code == 0 {
            crate::signote::take(sig)
        } else {
            None
        };
        // The host's own SIGIO, for a descriptor's readiness: Linux's is the
        // kernel's, from no process. Every fwe process that sends one leaves
        // a note, so one without is the host's, whatever code and sender it
        // comes with: macOS can give it those of a SIGCHLD just raised (a
        // child that wrote to the pipe and ended).
        if sig == libc::SIGIO && note.is_none() && code != SENT {
            return crate::thread::SigInfo { code: signal::SI_KERNEL, ..Default::default() };
        }
        if let Some(n) = note {
            (code, pid, guest_uid) = (SENT, n.pid, Some(n.uid));
            if n.code != 0 {
                // A lease break carries the leased descriptor.
                let poll = (n.code == crate::leases::POLL_MSG && sig != libc::SIGCHLD)
                    .then_some((n.value as i32, crate::leases::POLL_MSG_BAND));
                return crate::thread::SigInfo {
                    code: n.code,
                    pid,
                    uid: n.uid,
                    status: 0,
                    value: if poll.is_some() { 0 } else { n.value },
                    poll,
                };
            }
            value = n.value;
        }
    }
    let mut code = si_code_to_linux(code);
    // A child that ended of a Linux signal, as it recorded
    // ([`crate::procreg::ending`]).
    let ended = (sig == libc::SIGCHLD
        && matches!(code, wait::CLD_EXITED | wait::CLD_KILLED | wait::CLD_DUMPED))
    .then(|| HostPid::new(pid).and_then(crate::procreg::end_status))
    .flatten();
    if let Some(s) = ended {
        code = if s & 0x80 != 0 { wait::CLD_DUMPED } else { wait::CLD_KILLED };
    }
    let killed = matches!(code, wait::CLD_KILLED | wait::CLD_DUMPED | wait::CLD_STOPPED);
    if let Some(s) = ended {
        status = s & 0x7f;
    } else if sig == libc::SIGCHLD && killed {
        status = signal_to_linux(status) as i32;
    } else if sig == libc::SIGCHLD && code == wait::CLD_CONTINUED {
        // What continued it, as Linux reports (the host gives the signal
        // that had stopped it).
        status = signal::SIGCONT as i32;
    }
    // One this process sent itself carries its own guest user; one from a
    // process that is not fwe's, the host user's.
    let uid = guest_uid.unwrap_or_else(|| {
        if pid != 0 && pid == pid_now().get() {
            crate::creds::real_uid()
        } else {
            uid_to_initial(uid)
        }
    });
    crate::thread::SigInfo { code, pid, uid, status, value, poll: None }
}

/// The code and sender the host last gave each host signal, as
/// `(code << 32) | pid`, for the trace of a signal's delivery.
static LAST_HOST_INFO: [std::sync::atomic::AtomicU64; 32] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 32];

/// What the host last gave host signal `sig`: its code and sender.
pub fn last_host_info(sig: libc::c_int) -> (i32, i32) {
    let v =
        LAST_HOST_INFO.get(sig as usize).map_or(0, |s| s.load(std::sync::atomic::Ordering::SeqCst));
    ((v >> 32) as u32 as i32, v as u32 as i32)
}

/// The siginfo of a signal another fwe process sent, as its note
/// ([`crate::signote`]) gives it, which [`signal_info`] gives: for a
/// fault signal, which comes with the receiving thread's last fault in its
/// siginfo instead (macOS fills a sent `SIGSEGV`, `SIGBUS`, `SIGILL` or
/// `SIGFPE` so).
pub fn sent_info(sig: u64, note: crate::signote::Note) -> crate::thread::SigInfo {
    let code = if note.code != 0 { note.code } else { signal::SI_USER };
    // A child's stop or continue ([`crate::signal::take_notes`]): its
    // status the value.
    let child = sig == signal::SIGCHLD
        && matches!(code, fwe_abi::wait::CLD_STOPPED | fwe_abi::wait::CLD_CONTINUED);
    crate::thread::SigInfo {
        code,
        pid: note.pid,
        uid: note.uid,
        status: if child { note.value as i32 } else { 0 },
        value: if child { 0 } else { note.value },
        poll: None,
    }
}

/// Set the calling thread's host `errno`.
pub fn set_errno(value: HostErrno) {
    let value = value.raw();
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

/// File status flags (`F_GETFL`) from host to Linux: the access mode and
/// the modes the host keeps.
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
    // (`O_LARGEFILE`, which Linux sets on what `open` made only, is the
    // caller's: [`crate::fdmarks::status_flags`].)
    f
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

/// The host command for Linux record-lock command `cmd`: `F_GETLK`,
/// `F_SETLK`, `F_SETLKW` and their open-file-description forms (`F_OFD_*`,
/// which macOS has under private numbers).
pub fn lock_cmd(cmd: u64) -> Option<libc::c_int> {
    #[cfg(target_os = "macos")]
    const OFD: [libc::c_int; 3] = [92, 90, 91];
    #[cfg(not(target_os = "macos"))]
    const OFD: [libc::c_int; 3] = [libc::F_OFD_GETLK, libc::F_OFD_SETLK, libc::F_OFD_SETLKW];
    Some(match cmd {
        fcntl::F_GETLK => libc::F_GETLK,
        fcntl::F_SETLK => libc::F_SETLK,
        fcntl::F_SETLKW => libc::F_SETLKW,
        fcntl::F_OFD_GETLK => OFD[0],
        fcntl::F_OFD_SETLK => OFD[1],
        fcntl::F_OFD_SETLKW => OFD[2],
        _ => return None,
    })
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
        if fd >= 0 || flags & libc::O_CREAT == 0 || !last_errno().is(libc::ENOENT) || tries == 100 {
            return fd;
        }
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and out parameter.
        if unsafe { libc::fstat(dir, &mut st) } != 0 || st.st_nlink == 0 {
            set_errno(HostErrno::new(libc::ENOENT));
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
    match last_errno().raw() {
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
    let mut flags = ST_VALID;
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
        f_flags: fwe_abi::statfs::ST_VALID,
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
/// When the host started, in seconds since the epoch (0 if unknown).
pub fn boot_time() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let mut len = std::mem::size_of::<libc::timeval>();
        // SAFETY: a valid out-parameter of the size given.
        let r = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                (&mut tv as *mut libc::timeval).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 { tv.tv_sec as u64 } else { 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// The host's memory, in bytes: what `/proc/meminfo` and `sysinfo`
/// report of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    pub total: u64,
    /// Not in use at all.
    pub free: u64,
    /// What could be had without swapping: free, inactive and purgeable
    /// pages.
    pub available: u64,
    /// File-backed pages (the page cache).
    pub cached: u64,
    pub active: u64,
    pub inactive: u64,
    /// Wired (Linux's unevictable) pages.
    pub wired: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

/// The integer sysctl `name` (of up to 8 bytes), if the host has it.
#[cfg(target_os = "macos")]
pub fn sysctl_u64(name: &std::ffi::CStr) -> Option<u64> {
    let mut v = [0u8; 8];
    let mut len = v.len();
    // SAFETY: a valid out-buffer of the size given.
    let r = unsafe {
        libc::sysctlbyname(name.as_ptr(), v.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0)
    };
    match (r, len) {
        (0, 4) => Some(u64::from(u32::from_ne_bytes(v[..4].try_into().ok()?))),
        (0, 8) => Some(u64::from_ne_bytes(v)),
        _ => None,
    }
}

/// The host's memory now (`hw.memsize`, the VM statistics, `vm.swapusage`).
pub fn memory() -> Memory {
    #[cfg(target_os = "macos")]
    {
        let total = sysctl_u64(c"hw.memsize").unwrap_or(0);
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
        // SAFETY: zeroed bytes are a valid `vm_statistics64`, which the
        // call fills up to the count it is given.
        let mut s: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
        let mut count = libc::HOST_VM_INFO64_COUNT;
        // SAFETY: a valid out-buffer of `count` words; the host port is
        // this task's send right, kept for its life.
        #[allow(deprecated)]
        let r = unsafe {
            libc::host_statistics64(
                libc::mach_host_self(),
                libc::HOST_VM_INFO64,
                (&mut s as *mut libc::vm_statistics64).cast(),
                &mut count,
            )
        };
        let mut m = Memory { total, ..Default::default() };
        if r == 0 {
            let p = |n: u32| u64::from(n) * page;
            m.free = p(s.free_count.saturating_sub(s.speculative_count));
            m.available = (p(s.free_count) + p(s.inactive_count) + p(s.purgeable_count)).min(total);
            m.cached = p(s.external_page_count);
            m.active = p(s.active_count);
            m.inactive = p(s.inactive_count);
            m.wired = p(s.wire_count);
        }
        // SAFETY: zeroed bytes are a valid `xsw_usage`.
        let mut sw: libc::xsw_usage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::xsw_usage>();
        // SAFETY: a valid out-parameter of the size given.
        let r = unsafe {
            libc::sysctlbyname(
                c"vm.swapusage".as_ptr(),
                (&mut sw as *mut libc::xsw_usage).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 {
            m.swap_total = sw.xsu_total;
            m.swap_free = sw.xsu_avail;
        }
        m
    }
    #[cfg(not(target_os = "macos"))]
    {
        Memory::default()
    }
}

/// What `/proc/cpuinfo` says of each CPU: BogoMIPS (twice the timer's
/// frequency in MHz, as Linux computes it on arm64), and the implementer,
/// variant, part and revision of the `MIDR_EL1` of the efficiency and
/// the performance cores, and how many efficiency cores there are (Linux
/// numbers them first on Apple's chips), where the host's chip is one
/// Linux knows.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CpuIdentity {
    pub bogomips: f64,
    pub implementer: u32,
    pub variant: u32,
    pub parts: (u32, u32),
    pub revision: u32,
    pub efficiency_cores: u32,
}

/// The host CPU's identity ([`CpuIdentity`]).
pub fn cpu_identity() -> CpuIdentity {
    #[cfg(target_os = "macos")]
    {
        let tb = sysctl_u64(c"hw.tbfrequency").unwrap_or(24_000_000);
        let family = sysctl_u64(c"hw.cpufamily").unwrap_or(0) as u32;
        let sub = sysctl_u64(c"hw.cpusubfamily").unwrap_or(0) as u32;
        // `CPUFAMILY_ARM_*` and `CPUSUBFAMILY_ARM_*` (`mach/machine.h`), and
        // the parts Linux's `cputype.h` gives Apple's cores.
        let base = match family {
            0x1b58_8bb3 => Some(0x022),
            0xda33_d83d => Some(0x032),
            _ => None,
        };
        let parts = base.map(|b: u32| {
            let b = match sub {
                4 => b + 2,
                5 => b + 6,
                _ => b,
            };
            (b, b + 1)
        });
        CpuIdentity {
            bogomips: tb as f64 * 2.0 / 1e6,
            implementer: 0x61,
            variant: 0,
            parts: parts.unwrap_or((0, 0)),
            revision: 0,
            efficiency_cores: sysctl_u64(c"hw.perflevel1.logicalcpu").unwrap_or(0) as u32,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        CpuIdentity { bogomips: 48.0, implementer: 0x61, ..Default::default() }
    }
}

/// One kind of the host's cores: how many, and the caches each has (bytes;
/// 0 where the host does not say), the L2 shared by `per_l2` of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreKind {
    pub cpus: u32,
    pub l1i: u64,
    pub l1d: u64,
    pub l2: u64,
    pub per_l2: u32,
}

/// The host's cores by kind, efficiency cores first (as `/proc/cpuinfo`
/// numbers them, from `hw.perflevel<n>`, 0 the fastest), and the cache
/// line's size; one kind of `ncpu` cores where the host has no levels.
pub fn core_kinds(ncpu: u32) -> (Vec<CoreKind>, u64) {
    #[cfg(target_os = "macos")]
    {
        let line = sysctl_u64(c"hw.cachelinesize").unwrap_or(64);
        let levels = sysctl_u64(c"hw.nperflevels").unwrap_or(0);
        let level = |i: u64, what: &str| {
            std::ffi::CString::new(format!("hw.perflevel{i}.{what}"))
                .ok()
                .and_then(|c| sysctl_u64(&c))
        };
        let kinds: Vec<CoreKind> = (0..levels)
            .rev()
            .map(|i| CoreKind {
                cpus: level(i, "logicalcpu").unwrap_or(0) as u32,
                l1i: level(i, "l1icachesize").unwrap_or(0),
                l1d: level(i, "l1dcachesize").unwrap_or(0),
                l2: level(i, "l2cachesize").unwrap_or(0),
                per_l2: level(i, "cpusperl2").unwrap_or(0) as u32,
            })
            .filter(|k| k.cpus > 0)
            .collect();
        if kinds.iter().map(|k| k.cpus).sum::<u32>() == ncpu {
            return (kinds, line);
        }
        (vec![CoreKind { cpus: ncpu, ..CoreKind::default() }], line)
    }
    #[cfg(not(target_os = "macos"))]
    {
        (vec![CoreKind { cpus: ncpu, ..CoreKind::default() }], 64)
    }
}

/// A route of the host's own table, as Linux's main table would hold it
/// ([`routes`]): its family (`AF_INET`, `AF_INET6` as Linux numbers
/// them), destination and prefix, gateway (`None`: the destination is on
/// the link) and interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRoute {
    pub family: u16,
    pub dst: Vec<u8>,
    pub prefix: u8,
    pub gateway: Option<Vec<u8>>,
    pub index: u32,
}

/// A routing-table dump of the host's (`sysctl` `[CTL_NET, PF_ROUTE, 0,
/// family, op, arg]`): its messages.
#[cfg(target_os = "macos")]
fn route_sysctl(family: i32, op: i32, arg: i32) -> Option<Vec<u8>> {
    let mib = [libc::CTL_NET, libc::PF_ROUTE, 0, family, op, arg];
    let mut len = 0usize;
    // SAFETY: a size query: no buffer.
    let r = unsafe {
        libc::sysctl(
            mib.as_ptr().cast_mut(),
            6,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 || len == 0 {
        return None;
    }
    // Room for entries added meanwhile.
    len += len / 2;
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has `len` writable bytes, which the call fills.
    let r = unsafe {
        libc::sysctl(
            mib.as_ptr().cast_mut(),
            6,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// The messages of a routing-table dump: each header, and the addresses
/// that follow it, by their bit (`RTAX_DST`, `RTAX_GATEWAY`,
/// `RTAX_NETMASK`...).
#[cfg(target_os = "macos")]
fn route_messages(buf: &[u8]) -> Vec<(libc::rt_msghdr, [Option<&[u8]>; 8])> {
    let header = size_of::<libc::rt_msghdr>();
    let mut out = Vec::new();
    let mut at = 0;
    while at + header <= buf.len() {
        // SAFETY: `header` bytes are there; an unaligned read of plain data.
        let m: libc::rt_msghdr = unsafe { std::ptr::read_unaligned(buf[at..].as_ptr().cast()) };
        let len = m.rtm_msglen as usize;
        if len < header || at + len > buf.len() {
            break;
        }
        let msg = &buf[at..at + len];
        at += len;
        // Each address padded to 4 bytes.
        let mut addrs: [Option<&[u8]>; 8] = [None; 8];
        let mut p = header;
        for (bit, slot) in addrs.iter_mut().enumerate() {
            if m.rtm_addrs & (1 << bit) == 0 {
                continue;
            }
            let Some(&sa_len) = msg.get(p) else { break };
            let end = (p + sa_len as usize).min(msg.len());
            *slot = Some(&msg[p..end]);
            p += if sa_len == 0 { 4 } else { (sa_len as usize).div_ceil(4) * 4 };
        }
        out.push((m, addrs));
    }
    out
}

/// An address's `n` bytes from a `sockaddr_in` (at 4) or `sockaddr_in6`
/// (at 8): a mask can be cut short, its rest zero.
#[cfg(target_os = "macos")]
fn sockaddr_bytes(sa: &[u8], n: usize) -> Vec<u8> {
    let off = if n == 4 { 4 } else { 8 };
    let mut a = vec![0u8; n];
    for (i, b) in sa.iter().skip(off).take(n).enumerate() {
        a[i] = *b;
    }
    a
}

/// An IP address of `n` bytes from its socket address: a link-local IPv6
/// address carries its interface in its third and fourth bytes (KAME's),
/// which are not the address's.
#[cfg(target_os = "macos")]
fn sockaddr_ip(sa: &[u8], n: usize) -> Vec<u8> {
    let mut a = sockaddr_bytes(sa, n);
    if n == 16 && a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
        a[2] = 0;
        a[3] = 0;
    }
    a
}

/// The host's routes (`sysctl` `NET_RT_DUMP`) that Linux's main table
/// would hold. What macOS keeps there and Linux does not is left out: the
/// loopback's (Linux's are made of its own), the link layer's entries
/// and their clones, multicast and broadcast routes, the default routes
/// of interfaces other than the primary one (`RTF_IFSCOPE`), and a host
/// route to an address of the host's own (Linux's local table holds
/// those). A gateway that is the interface's own address, or a link,
/// makes a route on the link.
pub fn routes() -> Vec<HostRoute> {
    #[cfg(target_os = "macos")]
    {
        let ifs = interfaces();
        let lo = ifs.iter().find(|i| i.name == b"lo").map(|i| i.index);
        let own: Vec<Vec<u8>> =
            ifs.into_iter().flat_map(|i| i.addrs.into_iter().map(|a| a.addr)).collect();
        let mut out = Vec::new();
        for (family, linux) in [(libc::AF_INET, 2u16), (libc::AF_INET6, 10u16)] {
            if let Some(buf) = route_sysctl(family, libc::NET_RT_DUMP, 0) {
                out.extend(parse_routes(&buf, linux, &own, lo));
            }
        }
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// The routes of a `NET_RT_DUMP` of `family` (Linux's number), as
/// [`routes`] keeps them; `own` the host's addresses, `lo` its loopback's
/// index.
#[cfg(target_os = "macos")]
fn parse_routes(buf: &[u8], family: u16, own: &[Vec<u8>], lo: Option<u32>) -> Vec<HostRoute> {
    let n = if family == 2 { 4 } else { 16 };
    let af = if n == 4 { libc::AF_INET } else { libc::AF_INET6 };
    let mut out = Vec::new();
    for (m, [dst, gateway, mask, ..]) in route_messages(buf) {
        let skip =
            libc::RTF_WASCLONED | libc::RTF_LLINFO | libc::RTF_MULTICAST | libc::RTF_BROADCAST;
        if m.rtm_flags & libc::RTF_UP == 0 || m.rtm_flags & skip != 0 {
            continue;
        }
        let Some(dst) = dst.filter(|d| d.get(1).is_some_and(|&f| i32::from(f) == af)) else {
            continue;
        };
        let dst = sockaddr_ip(dst, n);
        let prefix = if m.rtm_flags & libc::RTF_HOST != 0 {
            (n * 8) as u8
        } else {
            mask.map_or(0, |m| ip_mask_len(&sockaddr_bytes(m, n)))
        };
        let index = u32::from(m.rtm_index);
        let loopback = Some(index) == lo;
        let own_dst = prefix as usize == n * 8 && own.contains(&dst);
        let scoped_default = prefix == 0 && m.rtm_flags & libc::RTF_IFSCOPE != 0;
        let limited = n == 4 && dst == [255; 4];
        if loopback
            || own_dst
            || scoped_default
            || limited
            || (n == 4 && dst[0] >= 224 && dst[0] < 240)
        {
            continue;
        }
        let gateway = gateway
            .filter(|g| g.get(1).is_some_and(|&f| i32::from(f) != libc::AF_LINK))
            .map(|g| sockaddr_ip(g, n))
            .filter(|g| !own.contains(g));
        out.push(HostRoute { family, dst, prefix, gateway, index });
    }
    out
}

/// A neighbour of the host's (an ARP or neighbour discovery entry): its
/// family (Linux's number), address, link-layer address (empty while it
/// is being resolved), interface and whether it was set by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNeighbour {
    pub family: u16,
    pub addr: Vec<u8>,
    pub lladdr: Vec<u8>,
    pub index: u32,
    pub permanent: bool,
}

/// The host's neighbours (`sysctl` `NET_RT_FLAGS` of `RTF_LLINFO`), as
/// Linux's neighbour tables hold them: not the host's own addresses, nor
/// broadcast or multicast entries, nor the loopback's.
pub fn neighbours() -> Vec<HostNeighbour> {
    #[cfg(target_os = "macos")]
    {
        let ifs = interfaces();
        let lo = ifs.iter().find(|i| i.name == b"lo").map(|i| i.index);
        let own: Vec<Vec<u8>> =
            ifs.into_iter().flat_map(|i| i.addrs.into_iter().map(|a| a.addr)).collect();
        let mut out = Vec::new();
        for (family, linux, n) in [(libc::AF_INET, 2u16, 4), (libc::AF_INET6, 10u16, 16)] {
            let Some(buf) = route_sysctl(family, libc::NET_RT_FLAGS, libc::RTF_LLINFO) else {
                continue;
            };
            for (m, [dst, gateway, ..]) in route_messages(&buf) {
                if m.rtm_flags & (libc::RTF_BROADCAST | libc::RTF_MULTICAST) != 0 {
                    continue;
                }
                let Some(dst) = dst.filter(|d| d.get(1).is_some_and(|&f| i32::from(f) == family))
                else {
                    continue;
                };
                let addr = sockaddr_ip(dst, n);
                let index = u32::from(m.rtm_index);
                if own.contains(&addr) || Some(index) == lo || (n == 16 && addr[0] == 0xff) {
                    continue;
                }
                // A `sockaddr_dl`: its name's and address's lengths at 5
                // and 6, the name then the address from 8.
                let lladdr = gateway
                    .filter(|g| g.len() >= 8 && i32::from(g[1]) == libc::AF_LINK)
                    .map(|g| {
                        let (nlen, alen) = (g[5] as usize, g[6] as usize);
                        g.get(8 + nlen..8 + nlen + alen).unwrap_or_default().to_vec()
                    })
                    .unwrap_or_default();
                let permanent = m.rtm_flags & libc::RTF_STATIC != 0;
                out.push(HostNeighbour { family: linux, addr, lladdr, index, permanent });
            }
        }
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// The length of the prefix mask `m` sets.
#[cfg(target_os = "macos")]
fn ip_mask_len(m: &[u8]) -> u8 {
    m.iter().map(|b| b.leading_ones()).take_while(|&o| o == 8).count() as u8 * 8
        + m.iter().map(|b| b.leading_ones() as u8).find(|&o| o < 8).unwrap_or(0)
}

/// The bytes host process `pid` had read from and written to storage.
pub fn disk_io(pid: i32) -> (u64, u64) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are a valid `rusage_info_v2`, which the call
        // fills.
        let mut r: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-buffer of the flavour's size.
        let ok = unsafe {
            libc::proc_pid_rusage(
                pid,
                libc::RUSAGE_INFO_V2,
                (&mut r as *mut libc::rusage_info_v2).cast(),
            )
        } == 0;
        if ok { (r.ri_diskio_bytesread, r.ri_diskio_byteswritten) } else { (0, 0) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        (0, 0)
    }
}

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
            .as_chunks::<4>()
            .0
            .iter()
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
        return Err(match last_errno().raw() {
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

/// A host network interface as Linux describes one: its name (the host's
/// `lo0` is `lo`), index, `IFF_*` flags, MTU, hardware type (`ARPHRD_*`)
/// and address, and its IP addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: Vec<u8>,
    pub index: u32,
    pub flags: u32,
    pub mtu: u32,
    pub hw_type: u16,
    pub hw_addr: Vec<u8>,
    pub addrs: Vec<IfAddr>,
}

/// An IP address of an interface: 4 bytes for IPv4, 16 for IPv6, its
/// prefix length, and an IPv4 broadcast address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub addr: Vec<u8>,
    pub prefix: u8,
    pub broadcast: Option<[u8; 4]>,
}

/// `ARPHRD_ETHER`, `ARPHRD_LOOPBACK` and `ARPHRD_NONE` (a tunnel or
/// another kind Linux would name otherwise).
#[cfg(target_os = "macos")]
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_NONE: u16 = 0xfffe;

/// `IFF_LOWER_UP`, Linux's alone: an interface whose carrier is up.
const IFF_LOWER_UP: u32 = 0x1_0000;

/// Linux's interface flags for the host's `flags`: those the two number
/// alike (up to `IFF_ALLMULTI`, 0x200), `IFF_MULTICAST` moved from the
/// BSD's 0x8000 to Linux's 0x1000 (where the BSD's is Linux's
/// `IFF_DYNAMIC`), and `IFF_LOWER_UP` while the interface runs. A loopback
/// interface is Linux's `lo`, which takes no multicast. The BSD's own
/// (`IFF_OACTIVE`, `IFF_SIMPLEX`, `IFF_LINK*`) have no Linux meaning.
#[cfg(target_os = "macos")]
pub fn iface_flags_to_linux(flags: u32) -> u32 {
    const LINUX_MULTICAST: u32 = 0x1000;
    let mut out = flags & 0x3ff;
    let loopback = flags & libc::IFF_LOOPBACK as u32 != 0;
    if flags & libc::IFF_MULTICAST as u32 != 0 && !loopback {
        out |= LINUX_MULTICAST;
    }
    if flags & libc::IFF_RUNNING as u32 != 0 {
        out |= IFF_LOWER_UP;
    }
    out
}

/// On a Linux host the flags are Linux's already, but for the carrier,
/// which `getifaddrs` leaves out.
#[cfg(not(target_os = "macos"))]
pub fn iface_flags_to_linux(flags: u32) -> u32 {
    if flags & libc::IFF_RUNNING as u32 != 0 { flags | IFF_LOWER_UP } else { flags }
}

/// The prefix length of netmask `mask`.
fn prefix_of(mask: &[u8]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

/// The host's network interfaces, in index order, as the guest sees the
/// initial network namespace's (`getifaddrs`).
pub fn interfaces() -> Vec<Interface> {
    let mut out: Vec<Interface> = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills the list, freed below; each entry's
    // pointers are valid until then, and an address is read as its own
    // family's structure.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut at = list;
        while !at.is_null() {
            let i = &*at;
            at = i.ifa_next;
            let host_name = std::ffi::CStr::from_ptr(i.ifa_name);
            let name = match host_name.to_bytes() {
                b"lo0" => b"lo".to_vec(),
                n => n.to_vec(),
            };
            let pos = match out.iter().position(|f| f.name == name) {
                Some(p) => p,
                None => {
                    let flags = iface_flags_to_linux(i.ifa_flags);
                    let loopback = flags & libc::IFF_LOOPBACK as u32 != 0;
                    out.push(Interface {
                        name,
                        index: libc::if_nametoindex(host_name.as_ptr()),
                        flags,
                        mtu: if loopback { 16384 } else { 1500 },
                        hw_type: if loopback { ARPHRD_LOOPBACK } else { ARPHRD_NONE },
                        hw_addr: vec![0; 6],
                        addrs: Vec::new(),
                    });
                    out.len() - 1
                }
            };
            if i.ifa_addr.is_null() {
                continue;
            }
            let f = &mut out[pos];
            let mask = |len: usize, off: usize| -> Vec<u8> {
                if i.ifa_netmask.is_null() {
                    return vec![0xff; len];
                }
                std::slice::from_raw_parts((i.ifa_netmask as *const u8).add(off), len).to_vec()
            };
            match i32::from((*i.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(i.ifa_addr as *const libc::sockaddr_in);
                    // The broadcast address (the destination address's
                    // field, which the hosts name apart).
                    #[cfg(target_os = "linux")]
                    let other = i.ifa_ifu;
                    #[cfg(not(target_os = "linux"))]
                    let other = i.ifa_dstaddr;
                    let broadcast = (f.flags & libc::IFF_BROADCAST as u32 != 0 && !other.is_null())
                        .then(|| {
                            (*(other as *const libc::sockaddr_in)).sin_addr.s_addr.to_ne_bytes()
                        });
                    f.addrs.push(IfAddr {
                        addr: sin.sin_addr.s_addr.to_ne_bytes().to_vec(),
                        prefix: prefix_of(&mask(4, 4)),
                        broadcast,
                    });
                }
                libc::AF_INET6 => {
                    let sin6 = &*(i.ifa_addr as *const libc::sockaddr_in6);
                    let mut addr = sin6.sin6_addr.s6_addr;
                    // The host keeps a link-local address's scope in its
                    // third and fourth bytes, which Linux shows as zero.
                    if addr[0] == 0xfe && addr[1] & 0xc0 == 0x80 {
                        addr[2] = 0;
                        addr[3] = 0;
                    }
                    f.addrs.push(IfAddr {
                        addr: addr.to_vec(),
                        prefix: prefix_of(&mask(16, 8)),
                        broadcast: None,
                    });
                }
                #[cfg(target_os = "macos")]
                libc::AF_LINK => {
                    let dl = &*(i.ifa_addr as *const libc::sockaddr_dl);
                    if !i.ifa_data.is_null() {
                        let data = &*(i.ifa_data as *const libc::if_data);
                        f.mtu = data.ifi_mtu;
                        // IFT_ETHER: an Ethernet (or Wi-Fi) interface.
                        if data.ifi_type == 6 {
                            f.hw_type = ARPHRD_ETHER;
                        }
                    }
                    if f.hw_type == ARPHRD_ETHER && dl.sdl_alen == 6 {
                        let base = dl.sdl_data.as_ptr() as *const u8;
                        let mac = std::slice::from_raw_parts(base.add(dl.sdl_nlen as usize), 6);
                        f.hw_addr = mac.to_vec();
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(list);
    }
    out.sort_by_key(|f| f.index);
    out
}

/// The protocol socket `fd` was made with, as the host knows it (the one
/// it chose for 0: TCP or UDP), if it is a socket.
pub fn socket_protocol(fd: i32) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // `PROC_PIDFDSOCKETINFO`'s `struct socket_fdinfo` (792 bytes): the
        // socket's protocol at 180, as `<sys/proc_info.h>` lays it out.
        const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
        const SIZE: usize = 792;
        const PROTOCOL: usize = 180;
        let mut info = [0u8; SIZE];
        // SAFETY: a buffer of the size the call fills, for this process.
        let n = unsafe {
            libc::proc_pidfdinfo(
                libc::getpid(),
                fd,
                PROC_PIDFDSOCKETINFO,
                info.as_mut_ptr().cast(),
                SIZE as libc::c_int,
            )
        };
        (n as usize == SIZE)
            .then(|| i32::from_ne_bytes(info[PROTOCOL..PROTOCOL + 4].try_into().unwrap()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut v: libc::c_int = 0;
        let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid out-parameters.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PROTOCOL,
                (&mut v as *mut i32).cast(),
                &mut l,
            )
        };
        (r == 0).then_some(v)
    }
}

/// `poll` events Linux and the host number alike: `POLLIN`, `POLLPRI`,
/// `POLLOUT`, `POLLERR`, `POLLHUP`, `POLLNVAL`, `POLLRDNORM`, `POLLRDBAND`.
const POLL_SHARED: i16 = 0xff;
/// Linux's `POLLWRNORM`, `POLLWRBAND` (macOS's `POLLWRBAND` is 0x100, its
/// `POLLWRNORM` its `POLLOUT`), `POLLMSG` and `POLLRDHUP`, which the host
/// has not.
pub const POLLWRNORM: i16 = 0x100;
pub const POLLWRBAND: i16 = 0x200;
pub const POLLMSG: i16 = 0x400;
pub const POLLRDHUP: i16 = 0x2000;

/// Linux `poll` events `linux` as the host's: those numbered alike as
/// they are, `POLLWRNORM` and `POLLWRBAND` as the host numbers them, and
/// what the host has not (`POLLMSG`, `POLLRDHUP`, which fwe looks for
/// itself) left out.
pub fn poll_events_to_host(linux: i16) -> i16 {
    let mut h = linux & POLL_SHARED;
    if linux & POLLWRNORM != 0 {
        h |= libc::POLLWRNORM;
    }
    if linux & POLLWRBAND != 0 {
        h |= libc::POLLWRBAND;
    }
    h
}

/// The host's `revents` `host` for a descriptor the guest asked `asked`
/// (Linux events) of, as Linux reports them: each ready event the guest
/// asked for under its Linux number, and an error, hang-up or invalid
/// descriptor always.
pub fn poll_revents_to_linux(host: i16, asked: i16) -> i16 {
    let mut l = host & POLL_SHARED;
    if host & libc::POLLOUT != 0 {
        l |= POLLWRNORM;
    }
    if host & libc::POLLWRBAND != 0 {
        l |= POLLWRBAND;
    }
    l & (asked | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
}

/// Run `call`, a host call that takes only a path (the attribute calls,
/// `truncate`, `chflags`), on `name` in directory `dir`, without opening
/// the file: macOS drops every record lock a process holds on a file when
/// it closes any descriptor of it, so fwe never opens a guest's file for
/// its own ends. `call` gets the file's full path, or where that is too
/// long for the host, `name` itself from the thread's working directory
/// set to `dir` for the call (`pthread_fchdir_np`); with `dir` the working
/// directory (`AT_FDCWD`), `name` itself. Linux hosts (the unit tests)
/// reach it through `/proc/self/fd`.
pub fn at_path<T>(
    dir: i32,
    name: &std::ffi::CStr,
    call: impl FnOnce(&std::ffi::CStr) -> T,
) -> Result<T, i32> {
    // From the working directory, or absolute: the name is the path.
    if dir == libc::AT_FDCWD {
        return Ok(call(name));
    }
    let full = crate::fs::fd_path(dir).and_then(|mut p| {
        p.push(b'/');
        p.extend_from_slice(name.to_bytes());
        (p.len() < libc::PATH_MAX as usize).then(|| std::ffi::CString::new(p).ok()).flatten()
    });
    if let Some(full) = full {
        return Ok(call(&full));
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn pthread_fchdir_np(fd: libc::c_int) -> libc::c_int;
        }
        // SAFETY: sets only this thread's working directory, to a live
        // directory descriptor.
        if unsafe { pthread_fchdir_np(dir) } != 0 {
            return Err(errno_to_linux(last_errno()));
        }
        let r = call(name);
        let e = last_errno();
        // SAFETY: back to the process's working directory.
        unsafe { pthread_fchdir_np(-1) };
        // SAFETY: the call's errno, kept for its caller to read.
        unsafe { *libc::__error() = e.raw() };
        Ok(r)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut p = format!("/proc/self/fd/{dir}/").into_bytes();
        p.extend_from_slice(name.to_bytes());
        let p = std::ffi::CString::new(p).map_err(|_| le::EINVAL)?;
        Ok(call(&p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How a forked child that writes a byte at `addr` ends: `None` if it
    /// exits, else the signal that ends it.
    fn write_in_child(addr: usize) -> Option<i32> {
        // SAFETY: the child only writes and exits; the parent waits for it.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                std::ptr::write_volatile(addr as *mut u8, 1);
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status))
        }
    }

    /// Below a stack is its guard, which a write past its foot faults in;
    /// a shared object has one on each side.
    #[test]
    fn stacks_and_shared_memory_are_guarded() {
        let size = 1 << 20;
        let low = map_stack(size).unwrap();
        assert_eq!(write_in_child(low), None);
        assert_eq!(write_in_child(low + size - 1), None);
        assert!(write_in_child(low - 1).is_some(), "a write below the stack");
        assert!(write_in_child(low - GUARD).is_some(), "a write at the guard's foot");

        let name = std::ffi::CString::new(format!("/fwe-g{}", std::process::id())).unwrap();
        // SAFETY: plain host calls on an object of the test's own.
        let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
        assert!(fd >= 0);
        // SAFETY: as above.
        unsafe {
            libc::shm_unlink(name.as_ptr());
            assert_eq!(libc::ftruncate(fd, size as libc::off_t), 0);
        }
        let base = map_shared_guarded(fd, size).unwrap();
        // SAFETY: the descriptor is no longer needed.
        unsafe { libc::close(fd) };
        assert_eq!(write_in_child(base), None);
        assert_eq!(write_in_child(base + size - 1), None);
        assert!(write_in_child(base - 1).is_some(), "a write below the object");
        assert!(write_in_child(base + size).is_some(), "a write above the object");
    }

    /// A guard puts the mask back as it goes, nested ones in turn; one
    /// kept leaves its change.
    #[test]
    fn mask_guards_put_the_mask_back() {
        // A signal nothing else here blocks or sends.
        let member = |sig| {
            let set = signal_mask();
            // SAFETY: an initialized set.
            unsafe { libc::sigismember(&set, sig) == 1 }
        };
        let one = |sig| {
            let mut set = empty_sigset();
            // SAFETY: an initialized set.
            unsafe { libc::sigaddset(&mut set, sig) };
            set
        };
        // Run on a thread of its own: the mask is the thread's.
        std::thread::spawn(move || {
            assert!(!member(libc::SIGXCPU) && !member(libc::SIGXFSZ));
            {
                let _outer = MaskGuard::block(&one(libc::SIGXCPU));
                assert!(member(libc::SIGXCPU));
                {
                    let inner = MaskGuard::block(&one(libc::SIGXFSZ));
                    // SAFETY: an initialized set.
                    assert_eq!(unsafe { libc::sigismember(inner.old(), libc::SIGXCPU) }, 1);
                    assert!(member(libc::SIGXFSZ));
                }
                assert!(member(libc::SIGXCPU) && !member(libc::SIGXFSZ));
            }
            assert!(!member(libc::SIGXCPU));
            MaskGuard::block(&one(libc::SIGXFSZ)).keep();
            assert!(member(libc::SIGXFSZ));
            unblock_signals(&one(libc::SIGXFSZ));
            assert!(!member(libc::SIGXFSZ));
        })
        .join()
        .unwrap();
    }

    /// A device number with its top bit set (a store tmpfs's `0:minor` of
    /// `0x80000` or more) is read back as the number it was made from.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_device_number_with_its_top_bit_is_kept_whole() {
        let dev = crate::devnodes::makedev(0, 0xf_9741);
        assert!(dev & (1 << 31) != 0);
        // SAFETY: an all-zero `stat` is a valid value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_dev = dev as libc::dev_t;
        assert_eq!(dev_of(&st), dev);
        assert_eq!(crate::fsops::major(dev_of(&st)), 0);
        assert_eq!(crate::fsops::minor(dev_of(&st)), 0xf_9741);
    }

    /// The BSD's interface flags as Linux's: the loopback `lo` with its
    /// carrier up and no multicast; another interface's multicast moved.
    #[cfg(target_os = "macos")]
    #[test]
    fn interface_flags_are_linuxs() {
        // lo0: UP, LOOPBACK, RUNNING, MULTICAST (0x8049).
        assert_eq!(iface_flags_to_linux(0x8049), 0x10049);
        // en0: UP, BROADCAST, SMART, RUNNING, SIMPLEX, MULTICAST (0x8863).
        assert_eq!(iface_flags_to_linux(0x8863), 0x11063);
    }

    /// Linux's write events reach the host by its numbers, never as
    /// others (`POLLWRBAND` 0x200 is macOS's `POLLEXTEND`, `POLLMSG` its
    /// `POLLATTRIB`), and come back by Linux's, only as asked.
    #[test]
    fn poll_events_are_translated() {
        assert_eq!(poll_events_to_host(POLLWRNORM), libc::POLLWRNORM);
        assert_eq!(poll_events_to_host(POLLWRBAND), libc::POLLWRBAND);
        assert_eq!(poll_events_to_host(POLLMSG | POLLRDHUP), 0);
        assert_eq!(
            poll_events_to_host(libc::POLLIN | libc::POLLRDNORM),
            libc::POLLIN | libc::POLLRDNORM
        );
        assert_eq!(poll_revents_to_linux(libc::POLLOUT, POLLWRNORM), POLLWRNORM);
        assert_eq!(poll_revents_to_linux(libc::POLLWRBAND, POLLWRBAND), POLLWRBAND);
        assert_eq!(
            poll_revents_to_linux(libc::POLLOUT | libc::POLLHUP, libc::POLLIN),
            libc::POLLHUP
        );
    }

    /// A path call reaches a name in a directory, also where the whole path
    /// is longer than the host takes, and the thread's working directory
    /// is the process's again after.
    #[test]
    fn a_path_call_reaches_a_name_past_the_hosts_length() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let base = std::env::temp_dir().join(format!("fwe-at-path-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let mut dir: OwnedFd = std::fs::File::open(&base).unwrap().into();
        // Made a name at a time: the whole path is past the host's limit.
        let name = c"directory-with-a-name-of-many-bytes-to-make-a-long-path-of";
        for _ in 0..20 {
            // SAFETY: a NUL-terminated name in a live directory; the new
            // descriptor is owned.
            dir = unsafe {
                libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755);
                let fd = libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY);
                assert!(fd >= 0);
                OwnedFd::from_raw_fd(fd)
            };
        }
        let dir = dir.as_raw_fd();
        assert!(crate::fs::fd_path(dir).is_none_or(|p| p.len() >= 1024));
        // SAFETY: a NUL-terminated name in a live directory.
        let fd = unsafe { libc::openat(dir, c"f".as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        assert!(fd >= 0);
        // SAFETY: the descriptor just opened.
        unsafe { libc::close(fd) };
        let cut = |p: &std::ffi::CStr| {
            // SAFETY: a NUL-terminated path.
            unsafe { libc::truncate(p.as_ptr(), 7) }
        };
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(at_path(dir, c"f", cut), Ok(0));
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        // SAFETY: zeroed bytes are a valid `stat`; a NUL-terminated name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::fstatat(dir, c"f".as_ptr(), &mut st, 0) }, 0);
        assert_eq!(st.st_size, 7);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn errno_translation() {
        assert_eq!(errno_to_linux(HostErrno::new(libc::EAGAIN)), le::EAGAIN);
        assert_eq!(errno_to_linux(HostErrno::new(libc::ENOSYS)), le::ENOSYS);
        assert_eq!(errno_to_linux(HostErrno::new(libc::ECONNREFUSED)), le::ECONNREFUSED);
        assert_eq!(errno_to_linux(HostErrno::new(libc::ENOTSUP)), le::EOPNOTSUPP);
        assert_eq!(errno_to_linux(HostErrno::new(100_000)), le::EIO);
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
    /// Swaps the two, both of which need to exist (`RENAME_EXCHANGE`).
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
    match last_errno().raw() {
        #[cfg(target_os = "macos")]
        libc::ENOTSUP if how != Rename::Replace => Err(le::EINVAL),
        e => Err(errno_to_linux(HostErrno::new(e))),
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
        match last_errno().raw() {
            libc::ENOTSUP | libc::EXDEV => Err(le::EOPNOTSUPP),
            e => Err(errno_to_linux(HostErrno::new(e))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (src, dst_dir, dst);
        Err(le::EOPNOTSUPP)
    }
}

/// [`clone_at`] of the regular file `src` in directory `src_dir` (not
/// followed), never opened ([`crate::reclocks`]).
pub fn clone_name_at(
    src_dir: i32,
    src: &std::ffi::CStr,
    dst_dir: i32,
    dst: &std::ffi::CStr,
) -> Result<(), i32> {
    #[cfg(target_os = "macos")]
    {
        /// `<sys/clonefile.h>`'s: a link itself, not what it leads to.
        const CLONE_NOFOLLOW: u32 = 1;
        // SAFETY: NUL-terminated names in the caller's directories.
        let r = unsafe {
            libc::clonefileat(src_dir, src.as_ptr(), dst_dir, dst.as_ptr(), CLONE_NOFOLLOW)
        };
        if r == 0 {
            return Ok(());
        }
        match last_errno().raw() {
            libc::ENOTSUP | libc::EXDEV => Err(le::EOPNOTSUPP),
            e => Err(errno_to_linux(HostErrno::new(e))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (src_dir, src, dst_dir, dst);
        Err(le::EOPNOTSUPP)
    }
}

/// The inaccessible room kept beside fwe's own stacks and shared memory
/// ([`map_stack`], [`map_shared_guarded`]): a stack that overflows (a
/// handler nested without bound, a guest thread's stack made with no guard
/// of its own) faults in it, and its process ends, instead of writing over
/// the next mapping, which might be memory every fwe process shares.
pub const GUARD: usize = 64 << 10;

/// A new stack of `size` bytes (a multiple of the host page) with
/// [`GUARD`] inaccessible bytes below it, kept for the process's life: its
/// lowest usable address, or `None` if the host has no room.
pub fn map_stack(size: usize) -> Option<usize> {
    // SAFETY: a fresh anonymous mapping, then its lowest part made
    // inaccessible; nothing else refers to either yet.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            GUARD + size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return None;
        }
        if libc::mprotect(p, GUARD, libc::PROT_NONE) != 0 {
            libc::munmap(p, GUARD + size);
            return None;
        }
        Some(p as usize + GUARD)
    }
}

/// `size` bytes of shared memory object `fd`, read and written, mapped
/// between two [`GUARD`]s of inaccessible room: its address, or the host's
/// error.
pub fn map_shared_guarded(fd: i32, size: usize) -> Result<usize, HostErrno> {
    // SAFETY: room reserved inaccessible, then the object mapped over its
    // middle, which nothing else uses: the guards stay around it.
    unsafe {
        let room = libc::mmap(
            std::ptr::null_mut(),
            size + 2 * GUARD,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if room == libc::MAP_FAILED {
            return Err(last_errno());
        }
        let at = room as usize + GUARD;
        let p = libc::mmap(
            at as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_FIXED,
            fd,
            0,
        );
        if p == libc::MAP_FAILED {
            let e = last_errno();
            libc::munmap(room, size + 2 * GUARD);
            return Err(e);
        }
        Ok(at)
    }
}

/// Run `f` with every signal blocked on the calling thread, its mask put
/// back after. A thread `f` creates starts with them all blocked: one of
/// fwe's own keeps them so (a guest's signal is a guest thread's to take),
/// and a guest thread takes the guest's mask once its thread-local storage
/// is made. A signal handled before then would have the host make that
/// storage in the handler, in `malloc`, which the thread might be in
/// already, making it for the thread's own first access.
pub fn with_signals_blocked<R>(f: impl FnOnce() -> R) -> R {
    let _blocked = MaskGuard::set(&full_sigset());
    f()
}

/// This process's host pid as the kernel has it now, asked each time: in
/// a signal handler, which can run in a fork child before its
/// `pthread_atfork` handlers have forgotten the parent's [`pid`] (or
/// libc its own copy). Async-signal-safe.
pub fn pid_now() -> HostPid {
    #[cfg(target_os = "macos")]
    // SAFETY: the `getpid` system call (20), which cannot fail.
    #[allow(deprecated)]
    let p = unsafe { libc::syscall(20) } as libc::pid_t;
    #[cfg(not(target_os = "macos"))]
    // SAFETY: plain host call.
    let p = unsafe { libc::getpid() };
    // SAFETY: a process's own pid is above 0.
    unsafe { HostPid::new_unchecked(p) }
}

/// Whether the calling thread is its process's only host thread, as the
/// host counts them.
#[cfg(target_os = "macos")]
pub fn only_thread() -> bool {
    // SAFETY: zeroed bytes are a valid `proc_taskinfo`, which the call fills.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: a buffer of the size given.
    let n = unsafe {
        libc::proc_pidinfo(
            pid().get(),
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    n == size && info.pti_threadnum == 1
}

/// Another host than macOS, where fwe runs only the kernel's unit tests:
/// a fork there takes every lock ([`crate::fork_locked`]).
#[cfg(not(target_os = "macos"))]
pub fn only_thread() -> bool {
    false
}

/// This process's host pid, kept: asked of the host once, and again in a
/// fork child (a `pthread_atfork` handler forgets it).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn pid() -> HostPid {
    use std::sync::atomic::Ordering::Relaxed;
    let p = PID.load(Relaxed);
    if p != 0 {
        // SAFETY: only a pid from `getpid` (above 0) is stored.
        return unsafe { HostPid::new_unchecked(p) };
    }
    static FORGET: std::sync::Once = std::sync::Once::new();
    FORGET.call_once(|| {
        extern "C" fn forget() {
            PID.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        // SAFETY: registering a handler that only stores to an atomic.
        unsafe { libc::pthread_atfork(None, None, Some(forget)) };
    });
    // SAFETY: getpid cannot fail.
    let p = unsafe { libc::getpid() };
    PID.store(p, Relaxed);
    // SAFETY: a process's own pid is above 0.
    unsafe { HostPid::new_unchecked(p) }
}

static PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// fwe's effective user id on the host, kept: fwe never changes it. Safe in
/// a signal handler.
pub fn euid() -> u32 {
    kept_id(&EUID, || {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    })
}

/// fwe's effective group id on the host, as [`euid`].
pub fn egid() -> u32 {
    kept_id(&EGID, || {
        // SAFETY: getegid cannot fail.
        unsafe { libc::getegid() }
    })
}

static EUID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static EGID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

fn kept_id(slot: &std::sync::atomic::AtomicU64, ask: impl FnOnce() -> u32) -> u32 {
    use std::sync::atomic::Ordering::Relaxed;
    let v = slot.load(Relaxed);
    if v != u64::MAX {
        return v as u32;
    }
    let id = ask();
    slot.store(u64::from(id), Relaxed);
    id
}

/// Milliseconds on a monotonic clock that is cheap to read and coarse:
/// for checks made at most so often on every call, where reading the
/// precise clock costs more than the check (it does in a virtual machine).
pub fn coarse_ms() -> u64 {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn clock_gettime_nsec_np(clock: libc::clockid_t) -> u64;
        }
        // SAFETY: plain host call; the approximate clock is read from
        // memory the kernel keeps current.
        unsafe { clock_gettime_nsec_np(libc::CLOCK_MONOTONIC_RAW_APPROX) / 1_000_000 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
    }
}
