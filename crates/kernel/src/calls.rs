//! Small system calls with little state of their own: `getcpu`,
//! `vhangup`, `readahead`, `sync_file_range`, `syslog`,
//! `membarrier`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo`, `kcmp`,
//! `process_madvise`, and the LSM calls (`lsm_list_modules`,
//! `lsm_get_self_attr`, `lsm_set_self_attr`), each checked as Linux checks
//! its arguments.

use crate::{Kernel, Platform, guest, thread, uaccess};
use fwe_abi::{err, errno, signal as sig};
use std::sync::atomic::Ordering::SeqCst;

/// `kcmp`'s kinds of resource.
const KCMP_FILE: u64 = 0;
const KCMP_VM: u64 = 1;
const KCMP_SYSVSEM: u64 = 6;
const KCMP_EPOLL_TFD: u64 = 7;

/// `process_madvise`'s advice for another process: the hints that change
/// nothing a program sees (`MADV_WILLNEED`, `MADV_COLD`, `MADV_PAGEOUT`,
/// `MADV_COLLAPSE`).
const REMOTE_ADVICE: [u64; 4] = [3, 20, 21, 25];

/// What one of a process's descriptors is, for `kcmp`: the kind of thing
/// and its identity, as far as fwe can tell (two descriptors of the same
/// object have the same).
type FileKey = (u8, u64, Vec<u8>);

/// `kcmp`'s answer for two resources whose identities are `x` and `y`: 0
/// if the same, else 1 or 2 by their order.
fn order<T: Ord>(x: &T, y: &T) -> i64 {
    match x.cmp(y) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Greater => 2,
    }
}

/// The identity of descriptor `fd` of host process `host` ([`FileKey`]),
/// if it has that descriptor.
fn file_key(host: i32, fd: i32) -> Option<FileKey> {
    use crate::procpid::FdTarget;
    let (_, t) = crate::procpid::fds(host).into_iter().find(|(f, _)| *f == fd)?;
    Some(match t {
        FdTarget::Socket(id) => (1, id, Vec::new()),
        FdTarget::Pipe(id) => (2, id, Vec::new()),
        FdTarget::Path(p) => (3, 0, p),
        FdTarget::Anon(name) => (4, 0, name.as_bytes().to_vec()),
    })
}

/// Whether this process's descriptors `a` and `b` (of the same file) are
/// one open file: a status flag changed through one shows through the
/// other. `O_NONBLOCK` is turned and turned back, which changes nothing
/// for a regular file or directory; another kind is taken to be one.
fn same_description(a: i32, b: i32) -> bool {
    // SAFETY: zeroed bytes are a valid `stat`; plain host calls on the
    // caller's descriptors, each flag restored.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(a, &mut st) != 0
            || !matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
        {
            return true;
        }
        let (fa, fb) = (libc::fcntl(a, libc::F_GETFL), libc::fcntl(b, libc::F_GETFL));
        if fa < 0 || fb < 0 {
            return true;
        }
        libc::fcntl(a, libc::F_SETFL, fa ^ libc::O_NONBLOCK);
        let shared = libc::fcntl(b, libc::F_GETFL) != fb;
        libc::fcntl(a, libc::F_SETFL, fa);
        shared
    }
}

/// `sync_file_range`'s flags.
const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
const SYNC_FILE_RANGE_WRITE: u64 = 2;
const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;

/// The security modules fwe has: Linux's capabilities, Landlock and Yama
/// (`LSM_ID_CAPABILITY`, `LSM_ID_LANDLOCK`, `LSM_ID_YAMA`), which keep no
/// attributes of a process.
const LSM_IDS: [u64; 3] = [100, 110, 111];

/// `struct lsm_ctx`'s header: `id`, `flags`, `len` and `ctx_len`.
const LSM_CTX_HEADER: u64 = 32;

/// The I/O priority `ioprio_set` gave this process ((none, 0) until one
/// is set, as Linux reports a task with none).
static IOPRIO: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// `membarrier`'s commands.
const MEMBARRIER_CMD_QUERY: u64 = 0;
const MEMBARRIER_CMD_GLOBAL: u64 = 1;
const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u64 = 2;
const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u64 = 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u64 = 8;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 16;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 64;
const MEMBARRIER_CMD_GET_REGISTRATIONS: u64 = 512;

/// The commands `membarrier` has (no `rseq`, which is not built).
const MEMBARRIER_SUPPORTED: u64 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

/// The process's `membarrier` registrations (the `REGISTER_*` commands).
static MEMBARRIER_REGISTERED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `syslog`'s actions.
const SYSLOG_ACTION_CLOSE: u64 = 0;
const SYSLOG_ACTION_OPEN: u64 = 1;
const SYSLOG_ACTION_READ: u64 = 2;
const SYSLOG_ACTION_READ_ALL: u64 = 3;
const SYSLOG_ACTION_READ_CLEAR: u64 = 4;
const SYSLOG_ACTION_CLEAR: u64 = 5;
const SYSLOG_ACTION_CONSOLE_OFF: u64 = 6;
const SYSLOG_ACTION_CONSOLE_ON: u64 = 7;
const SYSLOG_ACTION_CONSOLE_LEVEL: u64 = 8;
const SYSLOG_ACTION_SIZE_UNREAD: u64 = 9;
const SYSLOG_ACTION_SIZE_BUFFER: u64 = 10;

impl<P: Platform> Kernel<P> {
    /// `getcpu(cpu, node, cache)`: the CPU the caller runs on, as far as
    /// fwe can tell (the first of its affinity, which it is held to), on
    /// node 0.
    pub(crate) fn sys_getcpu(&self, cpu: u64, node: u64) -> i64 {
        let n = crate::syscalls::own_cpu() as u32;
        if cpu != 0 {
            guest!(uaccess::write(cpu, n));
        }
        if node != 0 {
            guest!(uaccess::write(node, 0u32));
        }
        0
    }

    /// `vhangup()`: the controlling terminal hung up, which needs
    /// `CAP_SYS_TTY_CONFIG`. fwe's terminals are the host's, which are not
    /// hung up.
    pub(crate) fn sys_vhangup(&mut self) -> i64 {
        if !self.creds.has(crate::caps::CAP_SYS_TTY_CONFIG) {
            return err(errno::EPERM);
        }
        0
    }

    /// `readahead(fd, offset, count)`: of a file open for reading; one
    /// that is not a regular file is refused (`EINVAL`). The host reads
    /// ahead by its own rule.
    pub(crate) fn sys_readahead(&mut self, fd: u64) -> i64 {
        let fd = fd as i32;
        // SAFETY: F_GETFL only queries the descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 || fl & libc::O_ACCMODE == libc::O_WRONLY {
            return err(errno::EBADF);
        }
        match crate::fsops::linux_fstat(fd) {
            Ok(st) if st.st_mode & fwe_abi::stat::S_IFMT == fwe_abi::stat::S_IFREG => 0,
            Ok(_) => err(errno::EINVAL),
            Err(e) => err(e),
        }
    }

    /// `sync_file_range(fd, offset, nbytes, flags)`: the file's changes
    /// written (all of them, on the host) when it asks to write or wait.
    pub(crate) fn sys_sync_file_range(
        &mut self,
        fd: u64,
        offset: u64,
        nbytes: u64,
        flags: u64,
    ) -> i64 {
        let valid =
            SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
        let (offset, nbytes) = (offset as i64, nbytes as i64);
        if flags & !valid != 0 || offset < 0 || nbytes < 0 || offset.checked_add(nbytes).is_none() {
            return err(errno::EINVAL);
        }
        let fd = fd as i32;
        let st = match crate::fsops::linux_fstat(fd) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        use fwe_abi::stat::*;
        if !matches!(st.st_mode & S_IFMT, S_IFREG | S_IFBLK | S_IFDIR | S_IFLNK) {
            return err(errno::ESPIPE);
        }
        if flags != 0 {
            // SAFETY: plain host call on the guest's descriptor.
            unsafe { libc::fsync(fd) };
        }
        0
    }

    /// `kcmp(pid1, pid2, type, idx1, idx2)`: whether the two processes (or
    /// threads) share a resource: 0 if they do, else 1 or 2 by an order of
    /// the two that stays the same. Both must be the caller's to read as a
    /// tracer would (`EPERM`). A process shares its memory, descriptor
    /// table, filesystem view, handlers, I/O context and semaphore undo
    /// list only with its own threads (a fork child has copies); two
    /// descriptors are the same open file if they name the same socket or
    /// pipe, or the same file and, in the caller, share their status flags
    /// (one is a copy of the other).
    pub(crate) fn sys_kcmp(&mut self, pid1: u64, pid2: u64, ty: u64, i1: u64, i2: u64) -> i64 {
        let host = |p: u64| -> Result<i32, i32> {
            let p = p as i32;
            if p <= 0 {
                return Err(errno::ESRCH);
            }
            if p == thread::tgid() || thread::tids().contains(&p) {
                return Ok(crate::host::pid());
            }
            if let Some(owner) = thread::owner_of_tid(p) {
                return Ok(owner);
            }
            let h = crate::pidns::host_arg(p)?;
            if crate::procreg::read(h).is_none() {
                return Err(errno::ESRCH);
            }
            Ok(h)
        };
        let (a, b) = match (host(pid1), host(pid2)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return err(e),
        };
        let me = crate::host::pid();
        // Linux's `PTRACE_MODE_READ_REALCREDS`.
        if [a, b].iter().any(|&h| h != me && !self.may_access(h, false, false)) {
            return err(errno::EPERM);
        }
        match ty {
            KCMP_FILE | KCMP_EPOLL_TFD => {
                let (fd1, fd2) = if ty == KCMP_FILE {
                    (i1 as i32, i2 as i32)
                } else {
                    // `struct kcmp_epoll_slot`: the epoll descriptor of the
                    // second process, a descriptor in its interest list.
                    let slot: [u32; 3] = guest!(uaccess::read(i2));
                    let (efd, tfd) = (slot[0] as i32, slot[1] as i32);
                    if b != me {
                        // Another process's interest lists are its own.
                        return err(errno::ENOENT);
                    }
                    match crate::epoll::watches(efd, tfd) {
                        Some(true) => {}
                        Some(false) => return err(errno::ENOENT),
                        None => return err(errno::EINVAL),
                    }
                    (i1 as i32, tfd)
                };
                let (Some(k1), Some(k2)) = (file_key(a, fd1), file_key(b, fd2)) else {
                    return err(errno::EBADF);
                };
                if k1 != k2 {
                    return order(&k1, &k2);
                }
                if a == me && b == me && fd1 != fd2 && !same_description(fd1, fd2) {
                    return if fd1 < fd2 { 1 } else { 2 };
                }
                0
            }
            KCMP_VM..=KCMP_SYSVSEM => order(&a, &b),
            _ => err(errno::EINVAL),
        }
    }

    /// `process_madvise(pidfd, iov, vlen, advice, flags)`: `madvise` of
    /// each range on the process the descriptor names. The caller's own
    /// takes any advice `madvise` takes; another process's only the hints
    /// that change nothing it sees (`EINVAL` for the rest), with
    /// `CAP_SYS_NICE` and the standing of a tracer (`EPERM`): fwe checks
    /// its ranges are mapped and gives the host nothing to act on, as the
    /// host's memory of another process is not fwe's to advise. The bytes
    /// advised.
    pub(crate) fn sys_process_madvise(
        &mut self,
        pidfd: u64,
        iov: u64,
        vlen: u64,
        advice: u64,
        flags: u64,
    ) -> i64 {
        if flags != 0 || vlen > uaccess::UIO_MAXIOV {
            return err(errno::EINVAL);
        }
        let raw = guest!(uaccess::read_bytes(iov, vlen as usize * 16));
        let ranges: Vec<(u64, u64)> = raw
            .as_chunks::<16>()
            .0
            .iter()
            .map(|v| {
                let w = |o: usize| u64::from_ne_bytes(v[o..o + 8].try_into().unwrap_or([0; 8]));
                (w(0), w(8))
            })
            .collect();
        let Some(t) = crate::pidfd::of(pidfd as i32) else { return err(errno::EBADF) };
        if crate::pidfd::ended(pidfd as i32) {
            return err(errno::ESRCH);
        }
        if !REMOTE_ADVICE.contains(&advice) {
            return err(errno::EINVAL);
        }
        let mut done = 0u64;
        if t.host == crate::host::pid() {
            for (addr, len) in ranges {
                let r = self.sys_madvise(addr, len, advice);
                if r < 0 {
                    return if done > 0 { done as i64 } else { r };
                }
                done += len;
            }
            return done as i64;
        }
        // Linux's `PTRACE_MODE_READ_FSCREDS`, and `CAP_SYS_NICE`.
        if !self.may_access(t.host, false, true) || !self.creds.has(crate::caps::CAP_SYS_NICE) {
            return err(errno::EPERM);
        }
        let Some(view) = crate::mm::MapsView::of(t.host) else { return err(errno::ESRCH) };
        let page = view.page.max(1);
        for (addr, len) in ranges {
            let end = addr.checked_add(len.div_ceil(page) * page);
            let Some(end) = end.filter(|_| addr % page == 0) else {
                return if done > 0 { done as i64 } else { err(errno::EINVAL) };
            };
            // Every page of the range mapped, else `ENOMEM` for it; none
            // locked for `MADV_COLD` or `MADV_PAGEOUT` (`EINVAL`).
            let mut at = addr;
            let mut hole = false;
            for p in view.areas.iter().filter(|p| p.end > addr && p.start < end) {
                if p.value.locked && matches!(advice, 20 | 21) {
                    return if done > 0 { done as i64 } else { err(errno::EINVAL) };
                }
                hole |= p.start > at;
                at = at.max(p.end);
            }
            let at = if hole { addr } else { at };
            if at < end {
                return if done > 0 { done as i64 } else { err(errno::ENOMEM) };
            }
            done += len;
        }
        done as i64
    }

    /// `syslog(type, buf, len)` (`klogctl`): the kernel log
    /// ([`crate::klog`]). Reading it, clearing it and setting the console level need
    /// `CAP_SYSLOG` (or `CAP_SYS_ADMIN`); the sizes need nothing.
    pub(crate) fn sys_syslog(&mut self, ty: u64, buf: u64, len: u64) -> i64 {
        let len = len as i32;
        let privileged =
            self.creds.has(crate::caps::CAP_SYSLOG) || self.creds.has(crate::caps::CAP_SYS_ADMIN);
        let needs = !matches!(ty, SYSLOG_ACTION_SIZE_BUFFER | SYSLOG_ACTION_SIZE_UNREAD);
        match ty {
            SYSLOG_ACTION_CLOSE..=SYSLOG_ACTION_SIZE_BUFFER => {}
            _ => return err(errno::EINVAL),
        }
        if needs && !privileged {
            return err(errno::EPERM);
        }
        match ty {
            SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => 0,
            SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
                if buf == 0 || len < 0 {
                    return err(errno::EINVAL);
                }
                if len == 0 {
                    return 0;
                }
                if !uaccess::valid(buf, len as u64, true) {
                    return err(errno::EFAULT);
                }
                // A destructive read takes what is unread, at once (with
                // nothing unread, nothing: it does not wait for more).
                let text = match ty {
                    SYSLOG_ACTION_READ => crate::klog::read_unread(len as usize),
                    _ => crate::klog::read_all(len as usize, ty == SYSLOG_ACTION_READ_CLEAR),
                };
                guest!(uaccess::write_from(buf, &text));
                text.len() as i64
            }
            SYSLOG_ACTION_CLEAR => {
                crate::klog::clear();
                0
            }
            // The console's level (`kernel.printk`'s first): off is the
            // least it may be, the level before kept for on.
            SYSLOG_ACTION_CONSOLE_OFF => {
                let mut p = printk();
                if SAVED_LEVEL.load(SeqCst) < 0 {
                    SAVED_LEVEL.store(p[0], SeqCst);
                }
                p[0] = p[2];
                set_printk(p)
            }
            SYSLOG_ACTION_CONSOLE_ON => {
                let saved = SAVED_LEVEL.swap(-1, SeqCst);
                if saved < 0 {
                    return 0;
                }
                let mut p = printk();
                p[0] = saved;
                set_printk(p)
            }
            SYSLOG_ACTION_CONSOLE_LEVEL => {
                if !(1..=8).contains(&len) {
                    return err(errno::EINVAL);
                }
                let mut p = printk();
                p[0] = i64::from(len).max(p[2]);
                SAVED_LEVEL.store(-1, SeqCst);
                set_printk(p)
            }
            SYSLOG_ACTION_SIZE_UNREAD => crate::klog::unread() as i64,
            _ => crate::klog::LOG_BUF_LEN as i64,
        }
    }

    /// `membarrier(cmd, flags, cpu_id)`: a barrier across the process's
    /// threads (or every process: no other runs code of this process's,
    /// so the same), the private ones only once registered for.
    /// `lsm_list_modules(ids, size, flags)`: the security modules' ids.
    pub(crate) fn sys_lsm_list_modules(&mut self, ids: u64, size: u64, flags: u64) -> i64 {
        if flags != 0 {
            return err(errno::EINVAL);
        }
        let given: u32 = guest!(uaccess::read(size));
        let total = (LSM_IDS.len() * 8) as u32;
        guest!(uaccess::write(size, total));
        if given < total {
            return err(errno::E2BIG);
        }
        for (i, id) in LSM_IDS.iter().enumerate() {
            guest!(uaccess::write(ids + 8 * i as u64, *id));
        }
        LSM_IDS.len() as i64
    }

    /// `lsm_get_self_attr(attr, ctx, size, flags)`: no module keeps
    /// attributes of a process (`EOPNOTSUPP`).
    pub(crate) fn sys_lsm_get_self_attr(&mut self, attr: u64, size: u64, flags: u64) -> i64 {
        const LSM_FLAG_SINGLE: u64 = 1;
        if attr == 0 || flags & !LSM_FLAG_SINGLE != 0 {
            return err(errno::EINVAL);
        }
        let _: u32 = guest!(uaccess::read(size));
        err(errno::EOPNOTSUPP)
    }

    /// `lsm_set_self_attr(attr, ctx, size, flags)`: the context checked
    /// as Linux checks it, then `EOPNOTSUPP`, as no module takes one.
    pub(crate) fn sys_lsm_set_self_attr(&mut self, ctx: u64, size: u64, flags: u64) -> i64 {
        if flags != 0 || size < LSM_CTX_HEADER {
            return err(errno::EINVAL);
        }
        if size > 4096 {
            return err(errno::E2BIG);
        }
        let b = guest!(uaccess::read_bytes(ctx, size as usize));
        let word = |at: usize| u64::from_ne_bytes(b[at..at + 8].try_into().unwrap());
        let (len, ctx_len) = (word(16), word(24));
        if size < len || size < ctx_len + LSM_CTX_HEADER || len < ctx_len + LSM_CTX_HEADER {
            return err(errno::EINVAL);
        }
        err(errno::EOPNOTSUPP)
    }

    /// The process `ioprio_get`/`ioprio_set` name: this one (`Ok(true)`),
    /// another (`Ok(false)`), or none (`ESRCH`), and `EINVAL` for an
    /// unknown `which`.
    fn ioprio_target(&self, which: u64, who: u64) -> Result<bool, i32> {
        const IOPRIO_WHO_PROCESS: u64 = 1;
        const IOPRIO_WHO_PGRP: u64 = 2;
        const IOPRIO_WHO_USER: u64 = 3;
        let who = who as i32;
        match which {
            IOPRIO_WHO_PROCESS => {
                if who == 0 || who == thread::tgid() || thread::host_thread(who).is_some() {
                    return Ok(true);
                }
                match crate::pidns::to_host(who) {
                    Some(h) if crate::host::process_exists(h) => Ok(false),
                    _ => Err(errno::ESRCH),
                }
            }
            IOPRIO_WHO_PGRP | IOPRIO_WHO_USER => Ok(who == 0),
            _ => Err(errno::EINVAL),
        }
    }

    /// `ioprio_get(which, who)`: the I/O priority this process set, (none,
    /// 0) for another, which fwe keeps none of.
    pub(crate) fn sys_ioprio_get(&mut self, which: u64, who: u64) -> i64 {
        match self.ioprio_target(which, who) {
            Ok(true) => IOPRIO.load(SeqCst),
            Ok(false) => 0,
            Err(e) => err(e),
        }
    }

    /// `ioprio_set(which, who, ioprio)`: checked as Linux checks it; the
    /// host has no I/O priorities to apply it to.
    pub(crate) fn sys_ioprio_set(&mut self, which: u64, who: u64, prio: u64) -> i64 {
        const CLASS_NONE: u64 = 0;
        const CLASS_RT: u64 = 1;
        const CLASS_BE: u64 = 2;
        const CLASS_IDLE: u64 = 3;
        let prio = prio as u16 as u64;
        let (class, level) = (prio >> 13, prio & 7);
        let high = prio & 0x1ff8;
        match class {
            CLASS_RT
                if !self.creds.has(crate::caps::CAP_SYS_NICE)
                    && !self.creds.has(crate::caps::CAP_SYS_ADMIN) =>
            {
                return err(errno::EPERM);
            }
            CLASS_RT | CLASS_BE if high != 0 => return err(errno::EINVAL),
            CLASS_NONE if prio != 0 => return err(errno::EINVAL),
            CLASS_RT | CLASS_BE | CLASS_IDLE | CLASS_NONE => {}
            _ => return err(errno::EINVAL),
        }
        let _ = level;
        match self.ioprio_target(which, who) {
            Ok(true) => {
                IOPRIO.store(prio as i64, SeqCst);
                0
            }
            Ok(false) => 0,
            Err(e) => err(e),
        }
    }

    /// `cachestat(fd, range, cstat, flags)`: how many of a file's pages in
    /// `range` the host has in memory (`mincore` of a mapping of them);
    /// none for any other kind of file.
    pub(crate) fn sys_cachestat(&mut self, fd: u64, range: u64, out: u64, flags: u64) -> i64 {
        let fd = fd as i32;
        if !crate::fdtable::guest_visible(fd)
            || crate::fdmarks::marked(fd) == Some(crate::fdmarks::Mark::Path)
            // SAFETY: plain host call.
            || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
        {
            return err(errno::EBADF);
        }
        let r: [u64; 2] = guest!(uaccess::read(range));
        if flags != 0 {
            return err(errno::EINVAL);
        }
        let page = self.page_size;
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe { libc::fstat(fd, &mut st) };
        let mut cached = 0u64;
        // fwe's `/proc` and `/sys` files are its own, of no page cache.
        let own = crate::fdmarks::origin(fd).is_some_and(|o| {
            matches!(o.fstype, crate::mounts::FsType::Proc | crate::mounts::FsType::Sysfs)
        });
        if !own && st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_size > 0 {
            let size = st.st_size as u64;
            let first = r[0] / page * page;
            let end = if r[1] == 0 { size } else { r[0].saturating_add(r[1]).min(size) };
            if end > first {
                let len = (end - first) as usize;
                // SAFETY: a fresh read-only shared mapping of the file,
                // unmapped below; `mincore` fills one byte a page.
                unsafe {
                    let m = libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ,
                        libc::MAP_SHARED,
                        fd,
                        first as libc::off_t,
                    );
                    if m != libc::MAP_FAILED {
                        let mut vec = vec![0u8; len.div_ceil(page as usize)];
                        if libc::mincore(m, len, vec.as_mut_ptr().cast()) == 0 {
                            cached = vec.iter().filter(|&&b| b & 1 != 0).count() as u64;
                        }
                        libc::munmap(m, len);
                    }
                }
            }
        }
        guest!(uaccess::write(out, [cached, 0u64, 0, 0, 0]));
        0
    }

    pub(crate) fn sys_membarrier(&mut self, cmd: u64, flags: u64) -> i64 {
        if flags != 0 {
            return err(errno::EINVAL);
        }
        let registered = MEMBARRIER_REGISTERED.load(SeqCst);
        match cmd {
            MEMBARRIER_CMD_QUERY => MEMBARRIER_SUPPORTED as i64,
            MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
                process_barrier();
                0
            }
            MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
                // Issued only once registered for (the command's register
                // bit is twice its own).
                if registered & (cmd << 1) == 0 {
                    return err(errno::EPERM);
                }
                process_barrier();
                0
            }
            MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
                MEMBARRIER_REGISTERED.fetch_or(cmd, SeqCst);
                0
            }
            MEMBARRIER_CMD_GET_REGISTRATIONS => registered as i64,
            _ => err(errno::EINVAL),
        }
    }

    /// `rt_sigqueueinfo(tgid, sig, info)`: signal `sig` with the siginfo
    /// the caller made. To another process it may not claim to be from the
    /// kernel or `tkill` (`EPERM`).
    pub(crate) fn sys_rt_sigqueueinfo(&mut self, tgid: u64, s: u64, info: u64) -> i64 {
        self.queue_info(tgid as i32, None, s, info)
    }

    /// `rt_tgsigqueueinfo(tgid, tid, sig, info)`: likewise, to thread `tid`
    /// of `tgid`.
    pub(crate) fn sys_rt_tgsigqueueinfo(&mut self, tgid: u64, tid: u64, s: u64, info: u64) -> i64 {
        if (tgid as i32) <= 0 || (tid as i32) <= 0 {
            return err(errno::EINVAL);
        }
        self.queue_info(tgid as i32, Some(tid as i32), s, info)
    }

    pub(crate) fn queue_info(&mut self, tgid: i32, tid: Option<i32>, s: u64, info: u64) -> i64 {
        let raw: [u8; 128] = guest!(uaccess::read(info));
        let word = |at: usize| i32::from_ne_bytes(raw[at..at + 4].try_into().unwrap());
        let code = word(8);
        let value = u64::from_ne_bytes(raw[24..32].try_into().unwrap());
        let me = thread::tgid();
        // A code only the kernel or `tkill` gives only to the calling thread
        // itself, by its own id, as Linux compares it.
        if (code >= 0 || code == sig::SI_TKILL) && tid.unwrap_or(tgid) != thread::tid() {
            return err(errno::EPERM);
        }
        // Only a process: Linux finds none for 0 or a negative number.
        if tgid <= 0 {
            return err(errno::ESRCH);
        }
        if s > sig::NSIG {
            return err(errno::EINVAL);
        }
        // Another thread's id names its process, as on Linux.
        let tgid = if tid.is_none() && thread::host_thread(tgid).is_some() { me } else { tgid };
        // Another process's thread, named alone, names its process too.
        let owner = (tid.is_none() && tgid != me && !crate::pidns::nested())
            .then(|| thread::owner_of_tid(tgid))
            .flatten();
        let Some(host) = owner.or_else(|| crate::pidns::to_host(tgid)) else {
            return err(errno::ESRCH);
        };
        // As `kill` is: only a process the caller may signal.
        if tgid != me && !self.may_signal(host, s) {
            return err(errno::EPERM);
        }
        if s == 0 {
            return 0;
        }
        // The caller's own `si_pid` and `si_uid`, as Linux delivers them:
        // the pid as the process it names in the caller's namespace (0 for
        // none), the user as the caller's user namespace has it.
        let pid = crate::pidns::to_host(word(16)).unwrap_or(0);
        let uid = crate::userns::from_ns(word(20) as u32, false).unwrap_or(crate::userns::OVERFLOW);
        let info = thread::SigInfo { code, pid, uid, value, ..Default::default() };
        if tgid == me {
            if !thread::may_queue(s, code) {
                return err(errno::EAGAIN);
            }
            match tid {
                Some(t) if t != me => {
                    if thread::post_thread(t, s, info).is_none() {
                        return err(errno::ESRCH);
                    }
                }
                _ => thread::post_process(s, info),
            }
            thread::wake_others(crate::host::WAKE_SIGNAL);
            return 0;
        }
        if let Some(t) = tid.filter(|&t| t != tgid) {
            // Another process's other thread: queued for it in the
            // process's mailbox, the process woken to give it to the
            // thread (SIGKILL ends the process).
            if thread::owner_of_tid(t) != Some(host) || !crate::host::is_fwe(host) {
                return err(errno::ESRCH);
            }
            if s == fwe_abi::signal::SIGKILL {
                crate::signote::note(host, libc::SIGKILL);
                return crate::host::kill_process(host, libc::SIGKILL);
            }
            if let Err(e) = crate::signote::queue_thread_from(host, t, s, code, value, (pid, uid)) {
                return err(e);
            }
            return crate::host::kill_process(host, crate::host::WAKE_SIGNAL);
        }
        // One the host lacks, or SIGTRAP (which the host would merge with
        // the target's next system-call trap): through the mailbox.
        let h = crate::host::signal_to_host(s).filter(|_| s != fwe_abi::signal::SIGTRAP);
        let Some(h) = h else {
            return crate::signal::send_unhosted_from(host, s, code, value, (pid, uid));
        };
        // A host signal names its sender's pid itself.
        crate::signote::note_with(host, h, code, value, uid);
        let r = crate::host::kill_process(host, h);
        if r != 0 {
            crate::signote::unnote(host, h);
        }
        r
    }
}

/// A memory barrier on every thread of the process: a change of a page's
/// protection makes the host interrupt every CPU running one, as Linux's
/// expedited barriers do.
fn process_barrier() {
    use std::sync::OnceLock;
    static PAGE: OnceLock<usize> = OnceLock::new();
    let page = *PAGE.get_or_init(|| {
        // SAFETY: a fresh anonymous page of fwe's own.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED { 0 } else { p as usize }
    });
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    if page != 0 {
        // SAFETY: fwe's own page; touched so it is mapped, then its
        // protection changed and restored.
        unsafe {
            (page as *mut u8).write_volatile(0);
            libc::mprotect(page as *mut libc::c_void, 16384, libc::PROT_READ);
            libc::mprotect(page as *mut libc::c_void, 16384, libc::PROT_READ | libc::PROT_WRITE);
        }
    }
}

/// The console's level before `syslog` turned it off (-1: not off).
static SAVED_LEVEL: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(-1);

/// `kernel.printk`: the console's level, the default message level, the
/// least console level and the default console level.
fn printk() -> [i64; 4] {
    let text = crate::sysctl::text(b"kernel/printk").unwrap_or_default();
    let mut v = [4, 4, 1, 7];
    for (slot, w) in v.iter_mut().zip(text.split_whitespace()) {
        *slot = w.parse().unwrap_or(*slot);
    }
    v
}

fn set_printk(v: [i64; 4]) -> i64 {
    let text = v.iter().map(i64::to_string).collect::<Vec<_>>().join("\t");
    match crate::sysctl::set_global(b"kernel/printk", text) {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}
