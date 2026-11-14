//! Process descriptors: `pidfd_open`, `CLONE_PIDFD`, and what is done
//! with one (`pidfd_send_signal`, `pidfd_getfd`, `waitid(P_PIDFD)`,
//! `setns`, the `PIDFD_GET_*` requests, `poll` and `epoll` for the
//! process's end).
//!
//! A descriptor is a host `kqueue` watching the process's exit
//! (`EVFILT_PROC` with `NOTE_EXIT`), so it is readable once the process has
//! ended, as Linux's is; one opened for a process that has already ended
//! (a zombie, whose exit the host will not report again) is made readable
//! at once with a user event. The descriptor is marked with what it names
//! ([`Mark::Pid`]): the process's host pid, the thread for a
//! `PIDFD_THREAD` one of this process's other threads (readable once that
//! thread has exited), and `PIDFD_NONBLOCK`. Nothing is read from the
//! kqueue, so it stays readable.
//!
//! The host passes no kqueue on to a fork child, nor over a Unix socket: a
//! fork child gets a new one at each marked number ([`restore`]), and
//! one sent with `SCM_RIGHTS` fails (`EINVAL`).
//!
//! An ended process's wait status, which `PIDFD_GET_INFO` gives once it
//! has been reaped, is what this process's `wait` reaped ([`reaped`]).
//!
//! `pidfd_getfd` asks the target for its descriptor: the request is queued
//! in its signal mailbox ([`crate::signote::request_fd`]) and it is woken;
//! its wake handler sends the descriptor over a datagram socket the caller
//! bound ([`crate::signote::fd_reply_socket`]), as `SCM_RIGHTS`.

use crate::fdmarks::{self, Mark};
use crate::{Kernel, Platform, guest, thread, uaccess};

use fwe_abi::pidfd::*;
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// What a process descriptor names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// The process's host pid.
    pub host: i32,
    /// For a `PIDFD_THREAD` descriptor of one of this process's other
    /// threads: its tid (0 for a process).
    pub tid: i32,
    pub nonblock: bool,
}

/// The wait statuses of the processes this process reaped and holds a
/// descriptor of, by host pid.
pub(crate) static EXITS: Mutex<Option<HashMap<i32, i32>>> = Mutex::new(None);

/// How many thread descriptors were made, so that a thread's exit looks
/// for one only once there are any.
static THREAD_FDS: AtomicUsize = AtomicUsize::new(0);

/// The process descriptor `fd` is, if it is one.
pub fn of(fd: i32) -> Option<Target> {
    if !fdmarks::any_marks() {
        return None;
    }
    match fdmarks::marked(fd)? {
        Mark::Pid { host, tid, nonblock } => Some(Target { host, tid, nonblock }),
        _ => None,
    }
}

/// Whether the process (or thread) descriptor `fd` names has ended.
pub fn ended(fd: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: one valid pollfd; no waiting.
    unsafe { libc::poll(&mut p, 1, 0) > 0 }
}

/// Host process `host`, which ended with Linux wait status `wstatus`, was
/// reaped by this process: kept if a descriptor here names it.
pub fn reaped(host: i32, wstatus: i32) {
    if !fdmarks::marks().iter().any(|(_, m)| matches!(m, Mark::Pid { host: h, .. } if *h == host)) {
        return;
    }
    EXITS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(host, wstatus);
}

fn exit_status(host: i32) -> Option<i32> {
    EXITS.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(&host).copied()
}

/// A new kqueue that becomes readable when `t` ends.
fn watch(t: Target) -> Result<i32, i32> {
    imp::watch(t)
}

/// A new descriptor of `t`, close-on-exec if `cloexec`, at a number the
/// guest may hold.
pub fn open(t: Target, cloexec: bool) -> Result<i32, i32> {
    let fd = watch(t)?;
    if fd as u64 >= crate::fdtable::limit().0 {
        // SAFETY: the kqueue made above.
        unsafe { libc::close(fd) };
        return Err(errno::EMFILE);
    }
    if cloexec {
        // SAFETY: plain host call on the kqueue made above.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    if t.tid != 0 {
        THREAD_FDS.fetch_add(1, Ordering::Relaxed);
    }
    fdmarks::mark(fd, Mark::Pid { host: t.host, tid: t.tid, nonblock: t.nonblock });
    Ok(fd)
}

/// A descriptor made ready for a `CLONE_PIDFD` child before the fork
/// (close-on-exec, at a number the guest may hold), which [`attach`] makes
/// the child's.
pub fn reserve() -> Result<i32, i32> {
    let fd = imp::reserve()?;
    if fd as u64 >= crate::fdtable::limit().0 {
        // SAFETY: the kqueue made above.
        unsafe { libc::close(fd) };
        return Err(errno::EMFILE);
    }
    // SAFETY: plain host call on the kqueue made above.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(fd)
}

/// Descriptor `fd` ([`reserve`]) names host process `host`, the child just
/// forked.
pub fn attach(fd: i32, host: i32) {
    imp::attach(fd, host);
    fdmarks::mark(fd, Mark::Pid { host, tid: 0, nonblock: false });
}

/// This process's thread `tid` is exiting: its descriptors become
/// readable.
pub fn thread_gone(tid: i32) {
    if THREAD_FDS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let me = crate::host::pid();
    for (fd, m) in fdmarks::marks() {
        if m == (Mark::Pid { host: me, tid, nonblock: false })
            || m == (Mark::Pid { host: me, tid, nonblock: true })
        {
            imp::trigger(fd);
        }
    }
}

/// The lines `/proc/self/fdinfo/<fd>` adds for a process descriptor: the
/// process's pid in the reader's pid namespace (-1 once it has ended and
/// gone, 0 if the reader cannot see it), as `/proc/<pid>/status` gives
/// `NSpid`.
pub fn fdinfo(fd: i32) -> Option<String> {
    let t = of(fd)?;
    let me = crate::host::pid();
    let pid = if t.host == me {
        thread::tgid()
    } else if ended(fd) && !crate::host::process_exists(t.host) {
        -1
    } else {
        crate::pidns::to_guest(t.host)
    };
    Some(format!("Pid:\t{pid}\nNSpid:\t{pid}\n"))
}

/// `PIDFD_NONBLOCK` set or cleared on `fd` (`F_SETFL`).
pub fn set_nonblock(fd: i32, on: bool) {
    if let Some(t) = of(fd) {
        fdmarks::mark(fd, Mark::Pid { host: t.host, tid: t.tid, nonblock: on });
    }
}

/// Write this process's process descriptors and records of reaped
/// processes into a fork snapshot or exec state.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    let exits = EXITS.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
    e.u64(exits.len() as u64);
    for (h, s) in exits {
        e.i32(h);
        e.i32(s);
    }
    let fds: Vec<(i32, Target, bool)> = fdmarks::marks()
        .into_iter()
        .filter_map(|(fd, m)| match m {
            Mark::Pid { host, tid, nonblock } => {
                // SAFETY: F_GETFD only queries the descriptor.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                (flags >= 0).then_some((
                    fd,
                    Target { host, tid, nonblock },
                    flags & libc::FD_CLOEXEC != 0,
                ))
            }
            _ => None,
        })
        .collect();
    e.u64(fds.len() as u64);
    for (fd, t, cloexec) in fds {
        e.i32(fd);
        e.i32(t.host);
        e.i32(t.tid);
        e.bool(t.nonblock);
        e.bool(cloexec);
    }
}

/// What [`save`] wrote, in a fork child (`exec` false) or a process fwe
/// re-executed (true): a new kqueue at the number of each process
/// descriptor, as the host passes none on (across an exec, of those not
/// close-on-exec).
pub(crate) fn restore(d: &mut crate::snapshot::Dec, exec: bool) {
    let n = d.count(8);
    let exits: HashMap<i32, i32> = (0..n).map(|_| (d.i32(), d.i32())).collect();
    *EXITS.lock().unwrap_or_else(|e| e.into_inner()) = Some(exits);
    let n = d.count(14);
    let me = crate::host::pid();
    for _ in 0..n {
        let (fd, host, tid, nonblock, cloexec) = (d.i32(), d.i32(), d.i32(), d.bool(), d.bool());
        if exec && cloexec {
            // Closed by the exec: its record goes, so that no later kqueue
            // at its number (which the host gives no identity either) is
            // taken for it.
            fdmarks::closed(fd);
            continue;
        }
        // Another process's thread now (a fork child's view of its
        // parent's): watched as its process.
        let watched = Target { host, tid: if host == me { tid } else { 0 }, nonblock };
        let Ok(kq) = watch(watched) else { continue };
        // SAFETY: the kqueue made above, moved to the descriptor's number.
        unsafe {
            if kq != fd {
                libc::dup2(kq, fd);
                libc::close(kq);
            }
            libc::fcntl(fd, libc::F_SETFD, if cloexec { libc::FD_CLOEXEC } else { 0 });
        }
        if tid != 0 {
            THREAD_FDS.fetch_add(1, Ordering::Relaxed);
        }
        fdmarks::mark(fd, Mark::Pid { host, tid, nonblock });
    }
}

/// `waitid(P_PIDFD, fd, ...)`: the host pid `fd` names, and whether a wait
/// on it must not block (`PIDFD_NONBLOCK`).
pub fn wait_target(fd: i32) -> Result<(i32, bool), i32> {
    // SAFETY: F_GETFD only queries the descriptor.
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(errno::EBADF);
    }
    let t = of(fd).ok_or(errno::EBADF)?;
    Ok((t.host, t.nonblock))
}

/// The host process a `/proc/<pid>` directory descriptor names (which
/// `pidfd_send_signal` takes as Linux does), if `fd` is one.
fn proc_dir_target(fd: i32) -> Option<i32> {
    let path = crate::synthdir::path_of(fd)?;
    let rest = path.strip_prefix(b"/proc/")?;
    if rest == b"self" || rest == b"thread-self" {
        return Some(crate::host::pid());
    }
    let pid: i32 = std::str::from_utf8(rest).ok()?.parse().ok()?;
    if pid == thread::tgid() {
        return Some(crate::host::pid());
    }
    crate::pidns::to_host(pid)
}

impl<P: Platform> Kernel<P> {
    /// `pidfd_open(pid, flags)`.
    pub(crate) fn sys_pidfd_open(&mut self, pid: u64, flags: u64) -> i64 {
        let pid = pid as i32;
        if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || pid <= 0 {
            return err(errno::EINVAL);
        }
        let nonblock = flags & PIDFD_NONBLOCK != 0;
        let me = crate::host::pid();
        let t = if thread::host_thread(pid).is_some() || pid == thread::tid() {
            // One of this process's threads: the main one names the
            // process; another only as a thread.
            if pid == thread::tgid() {
                Target { host: me, tid: 0, nonblock }
            } else if flags & PIDFD_THREAD != 0 {
                Target { host: me, tid: pid, nonblock }
            } else {
                return err(errno::EINVAL);
            }
        } else {
            let Some(host) = crate::pidns::to_host(pid) else { return err(errno::ESRCH) };
            if !crate::host::process_exists(host) {
                return err(errno::ESRCH);
            }
            Target { host, tid: 0, nonblock }
        };
        match open(t, true) {
            Ok(fd) => fd as i64,
            Err(e) => err(e),
        }
    }

    /// `pidfd_send_signal(pidfd, sig, info, flags)`: as `kill`, or with the
    /// `siginfo` the caller made as `rt_sigqueueinfo`, to the process (or
    /// thread, or process group, as `flags` says) the descriptor names;
    /// a `/proc/<pid>` directory names its process too.
    pub(crate) fn sys_pidfd_send_signal(
        &mut self,
        fd: u64,
        sig: u64,
        info: u64,
        flags: u64,
    ) -> i64 {
        let fd = fd as i32;
        let scopes = PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP;
        if flags & !scopes != 0 || (flags & scopes).count_ones() > 1 {
            return err(errno::EINVAL);
        }
        // SAFETY: F_GETFD only queries the descriptor.
        if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return err(errno::EBADF);
        }
        let (t, gone) = match of(fd) {
            Some(t) => (t, ended(fd)),
            None => match proc_dir_target(fd) {
                Some(host) => (Target { host, tid: 0, nonblock: false }, false),
                None => return err(errno::EBADF),
            },
        };
        if sig > fwe_abi::signal::NSIG {
            return err(errno::EINVAL);
        }
        // The information given is checked before the process is: one
        // for another signal is refused whether or not it has ended.
        let raw: Option<[u8; 128]> =
            if info != 0 { Some(guest!(uaccess::read(info))) } else { None };
        if raw.is_some_and(|r| u64::from(u32::from_ne_bytes(r[0..4].try_into().unwrap())) != sig) {
            return err(errno::EINVAL);
        }
        if gone {
            return err(errno::ESRCH);
        }
        let me = crate::host::pid();
        let pid = if t.host == me { thread::tgid() } else { crate::pidns::to_guest(t.host) };
        if pid == 0 {
            // Not in the caller's pid namespace or one below it.
            return err(errno::EINVAL);
        }
        let thread_scope = flags & PIDFD_SIGNAL_THREAD != 0 || (flags == 0 && t.tid != 0);
        if raw.is_some() {
            let tid = thread_scope.then_some(if t.tid != 0 { t.tid } else { pid });
            return self.queue_info(pid, tid, sig, info);
        }
        if flags & PIDFD_SIGNAL_PROCESS_GROUP != 0 {
            // SAFETY: plain host call.
            let pgid = unsafe { libc::getpgid(t.host) };
            if pgid < 0 {
                return err(errno::ESRCH);
            }
            return self.sys_kill(-i64::from(crate::pidns::to_guest(pgid)), sig);
        }
        if thread_scope {
            let tid = if t.tid != 0 { t.tid } else { pid };
            return self.sys_tgkill(i64::from(pid), i64::from(tid), sig);
        }
        self.sys_kill(i64::from(pid), sig)
    }

    /// `pidfd_getfd(pidfd, targetfd, flags)`, the part under the kernel
    /// lock: the target process and that the caller may take its
    /// descriptors (`PTRACE_MODE_ATTACH_REALCREDS`). For this process
    /// itself, the duplicate made at once.
    pub fn getfd_request(&self, fd: u64, target_fd: u64, flags: u64) -> Result<GetFd, i64> {
        let fd = fd as i32;
        if flags != 0 {
            return Err(err(errno::EINVAL));
        }
        let t = of(fd).ok_or(err(errno::EBADF))?;
        let target_fd = target_fd as i32;
        if target_fd < 0 {
            return Err(err(errno::EBADF));
        }
        if ended(fd) {
            return Err(err(errno::ESRCH));
        }
        let me = crate::host::pid();
        if t.host == me {
            if !crate::fdtable::guest_visible(target_fd) {
                return Err(err(errno::EBADF));
            }
            // SAFETY: plain host call on a guest descriptor.
            let r = unsafe { libc::fcntl(target_fd, libc::F_DUPFD_CLOEXEC, 0) };
            if r < 0 {
                return Err(crate::host::last_error());
            }
            fdmarks::duplicated(target_fd, r);
            return Err(i64::from(r));
        }
        if !self.may_attach(t.host) {
            return Err(err(errno::EPERM));
        }
        Ok(GetFd { host: t.host, fd: target_fd, pidfd: fd })
    }

    /// Whether the caller may act on host process `target` as a tracer
    /// may (Linux's `PTRACE_MODE_ATTACH_REALCREDS`): with
    /// `CAP_SYS_PTRACE`, or when its real user and group ids are each of
    /// the target's.
    fn may_attach(&self, target: i32) -> bool {
        if self.creds.has(crate::caps::CAP_SYS_PTRACE) {
            return true;
        }
        let ids = crate::procreg::ids(target);
        let c = &self.creds;
        ids[..3].iter().all(|&u| u == c.uid) && ids[4..7].iter().all(|&g| g == c.gid)
    }

    /// `ioctl` on a process descriptor: `PIDFD_GET_INFO` and the
    /// `PIDFD_GET_*_NAMESPACE` requests (a descriptor of the namespace).
    /// `None` when `fd` is not one.
    pub(crate) fn pidfd_ioctl(&mut self, fd: i32, req: u64, arg: u64) -> Option<i64> {
        let t = of(fd)?;
        let (kind, nr, size) = ((req >> 8) & 0xff, req & 0xff, (req >> 16) & 0x3fff);
        if kind != PIDFS_IOCTL_MAGIC {
            return Some(err(errno::ENOTTY));
        }
        if nr == PIDFD_GET_INFO {
            if arg == 0 || size < PIDFD_INFO_SIZE_VER0 {
                return Some(err(errno::EINVAL));
            }
            return Some(self.pidfd_info(fd, t, arg, size));
        }
        if (PIDFD_GET_CGROUP_NAMESPACE..=PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE).contains(&nr)
            && size == 0
        {
            return Some(self.pidfd_namespace(fd, t, nr));
        }
        Some(err(errno::ENOTTY))
    }

    /// `PIDFD_GET_INFO`: the process's ids, or once it has been reaped by
    /// this process its wait status (`PIDFD_INFO_EXIT`), into the
    /// caller's `struct pidfd_info` of `size` bytes.
    fn pidfd_info(&self, fd: i32, t: Target, arg: u64, size: u64) -> i64 {
        let asked: u64 = guest!(uaccess::read(arg));
        // As the caller's pid namespace numbers it: none outside it.
        let me = crate::host::pid();
        let pid = if t.host == me { thread::tgid() } else { crate::pidns::to_guest(t.host) };
        if pid == 0 {
            return err(errno::ESRCH);
        }
        let mut info = [0u8; PIDFD_INFO_SIZE_VER1 as usize];
        let put =
            |info: &mut [u8], at: usize, v: u32| info[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        let mut mask = 0u64;
        let gone = ended(fd) && !crate::host::process_exists(t.host);
        if gone {
            let status = exit_status(t.host).filter(|_| asked & PIDFD_INFO_EXIT != 0);
            let Some(status) = status else { return err(errno::ESRCH) };
            mask |= PIDFD_INFO_EXIT;
            put(&mut info, 60, status as u32);
        } else {
            let ids = crate::procreg::ids(t.host);
            let host_ppid = crate::procreg::host_parent(t.host).unwrap_or(0);
            let ppid = crate::reaper::parent_of(t.host, host_ppid);
            put(&mut info, 16, pid as u32);
            put(&mut info, 20, pid as u32);
            put(&mut info, 24, crate::pidns::to_guest(ppid) as u32);
            // Real, effective, saved and filesystem ids, users then groups.
            for (i, at) in [(0, 28), (4, 32), (1, 36), (5, 40), (2, 44), (6, 48), (3, 52), (7, 56)]
            {
                let id = if i < 4 {
                    crate::userns::to_ns(ids[i], false)
                } else {
                    crate::userns::to_ns(ids[i], true)
                };
                put(&mut info, at, id);
            }
            mask |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;
        }
        info[..8].copy_from_slice(&mask.to_ne_bytes());
        let n = size.min(PIDFD_INFO_SIZE_VER1) as usize;
        guest!(uaccess::write_from(arg, &info[..n]));
        0
    }

    /// `PIDFD_GET_*_NAMESPACE`: a descriptor of the process's namespace
    /// of that kind (`EOPNOTSUPP` for a time namespace, which fwe has
    /// none of).
    fn pidfd_namespace(&self, fd: i32, t: Target, nr: u64) -> i64 {
        let name: &[u8] = match nr {
            1 => b"cgroup",
            2 => b"ipc",
            3 => b"mnt",
            4 => b"net",
            5 => b"pid",
            6 => b"pid_for_children",
            9 => b"user",
            10 => b"uts",
            _ => return err(errno::EOPNOTSUPP),
        };
        if ended(fd) {
            return err(errno::ESRCH);
        }
        let me = crate::host::pid();
        if t.host != me && !self.may_attach(t.host) {
            return err(errno::EPERM);
        }
        let dirs = if t.host == me {
            self.fs().ns_dirs()
        } else {
            match crate::procreg::read(t.host) {
                Some(r) => r.ns,
                None => return err(errno::ESRCH),
            }
        };
        let link = crate::procpid::ns_link_of(name, &dirs);
        self.open_ns(name, &dirs, &link, fwe_abi::fcntl::O_CLOEXEC)
    }

    /// `setns(pidfd, flags)`: join the namespaces of the kinds `flags`
    /// names that the process `t` is in, the user namespace first.
    pub(crate) fn setns_pidfd(&mut self, fd: i32, t: Target, flags: u64) -> i64 {
        use fwe_abi::clone::*;
        let kinds = [
            (CLONE_NEWUSER, &b"user"[..]),
            (CLONE_NEWNS, b"mnt"),
            (CLONE_NEWUTS, b"uts"),
            (CLONE_NEWIPC, b"ipc"),
            (CLONE_NEWNET, b"net"),
            (CLONE_NEWCGROUP, b"cgroup"),
            (CLONE_NEWPID, b"pid"),
        ];
        let all = kinds.iter().fold(0, |a, (k, _)| a | k);
        if flags == 0 || flags & !all != 0 {
            return err(errno::EINVAL);
        }
        if ended(fd) {
            return err(errno::ESRCH);
        }
        let me = crate::host::pid();
        let dirs = if t.host == me {
            self.fs().ns_dirs()
        } else {
            match crate::procreg::read(t.host) {
                Some(r) => r.ns,
                None => return err(errno::ESRCH),
            }
        };
        // Each namespace's descriptor first, so that none is joined unless
        // all can be.
        let mut fds = Vec::new();
        let close = |fds: &[i32]| {
            for &f in fds {
                fdmarks::closed(f);
                crate::nsfd::closed(f);
                // SAFETY: a descriptor opened here.
                unsafe { libc::close(f) };
            }
        };
        for (kind, name) in kinds.iter().filter(|(k, _)| flags & k != 0) {
            let link = crate::procpid::ns_link_of(name, &dirs);
            let r = self.open_ns(name, &dirs, &link, fwe_abi::fcntl::O_CLOEXEC);
            if r < 0 {
                close(&fds);
                return r;
            }
            fds.push(r as i32);
            let _ = kind;
        }
        let mut r = 0;
        for (&f, (kind, _)) in fds.iter().zip(kinds.iter().filter(|(k, _)| flags & k != 0)) {
            r = self.sys_setns(f as u64, *kind);
            if r < 0 {
                break;
            }
        }
        close(&fds);
        r
    }
}

/// A `pidfd_getfd` of another process's descriptor, to finish without the
/// kernel lock ([`getfd`]).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct GetFd {
    host: i32,
    fd: i32,
    pidfd: i32,
}

/// The rest of `pidfd_getfd`: ask process `g.host` for its descriptor
/// `g.fd`, and wait for it (or for the process's end, `ESRCH`, or a
/// signal, `EINTR`). The descriptor received is close-on-exec.
pub fn getfd(g: Result<GetFd, i64>) -> i64 {
    let g = match g {
        Ok(g) => g,
        Err(r) => return r,
    };
    imp::getfd(g)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{GetFd, Target};
    use fwe_abi::{err, errno};

    /// The user event a descriptor of an ended process (or thread) is made
    /// readable with.
    const ENDED: libc::uintptr_t = 1;

    fn change(kq: i32, ev: libc::kevent) -> i32 {
        // SAFETY: one valid change, no events read.
        unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) }
    }

    fn user(flags: u16, fflags: u32) -> libc::kevent {
        libc::kevent {
            ident: ENDED,
            filter: libc::EVFILT_USER,
            flags,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        }
    }

    /// A kqueue with the user event a descriptor of an ended process is
    /// made readable with.
    pub(super) fn reserve() -> Result<i32, i32> {
        // SAFETY: plain host call.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        if change(kq, user(libc::EV_ADD | libc::EV_CLEAR, 0)) != 0 {
            let e = crate::host::errno_to_linux(crate::host::last_errno());
            // SAFETY: the kqueue made above.
            unsafe { libc::close(kq) };
            return Err(e);
        }
        Ok(kq)
    }

    /// Kqueue `kq` ([`reserve`]) watches host process `host`'s exit.
    pub(super) fn attach(kq: i32, host: i32) {
        let ev = libc::kevent {
            ident: host as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // A process already ended, a zombie, cannot be watched (`ESRCH`).
        if change(kq, ev) != 0 {
            trigger(kq);
        }
    }

    pub(super) fn watch(t: Target) -> Result<i32, i32> {
        let kq = reserve()?;
        if t.tid != 0 {
            // One of this process's threads: its exit triggers the event.
            if crate::thread::host_thread(t.tid).is_none() && t.tid != crate::thread::tid() {
                trigger(kq);
            }
        } else {
            attach(kq, t.host);
        }
        Ok(kq)
    }

    pub(super) fn trigger(kq: i32) {
        change(kq, user(0, libc::NOTE_TRIGGER));
    }

    pub(super) fn getfd(g: GetFd) -> i64 {
        let Some(reply) = crate::signote::fd_reply_socket() else {
            return err(errno::EMFILE);
        };
        if let Err(e) = crate::signote::request_fd(g.host, g.fd, reply.token) {
            return err(e);
        }
        if crate::host::kill_process(g.host, crate::host::WAKE_SIGNAL) != 0 {
            return err(errno::ESRCH);
        }
        loop {
            let mut p = [
                libc::pollfd { fd: reply.sock, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: g.pidfd, events: libc::POLLIN, revents: 0 },
            ];
            // SAFETY: two valid pollfds.
            let n = unsafe { libc::poll(p.as_mut_ptr(), 2, 100) };
            if n > 0 && p[0].revents != 0 {
                break;
            }
            if n > 0 && p[1].revents != 0 {
                return err(errno::ESRCH);
            }
            if crate::thread::deliverable() != 0 {
                return err(errno::EINTR);
            }
        }
        let (r, fd) = crate::signote::receive_fd(reply.sock);
        if r != 0 {
            return err(crate::host::errno_to_linux(r));
        }
        if fd < 0 {
            return err(errno::EBADF);
        }
        if fd as u64 >= crate::fdtable::limit().0 {
            // SAFETY: the descriptor received.
            unsafe { libc::close(fd) };
            return err(errno::EMFILE);
        }
        // SAFETY: the descriptor received.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        crate::seqpacket::adopt(fd);
        i64::from(fd)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{GetFd, Target};
    use fwe_abi::{err, errno};

    pub(super) fn watch(_: Target) -> Result<i32, i32> {
        Err(errno::ENOSYS)
    }

    pub(super) fn reserve() -> Result<i32, i32> {
        Err(errno::ENOSYS)
    }

    pub(super) fn attach(_: i32, _: i32) {}

    pub(super) fn trigger(_: i32) {}

    pub(super) fn getfd(_: GetFd) -> i64 {
        err(errno::ENOSYS)
    }
}
