//! Small system calls with little state of their own: `getcpu`,
//! `vhangup`, `readahead`, `sync_file_range`, `delete_module`, `syslog`,
//! `membarrier`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo`, and the LSM
//! calls (`lsm_list_modules`, `lsm_get_self_attr`, `lsm_set_self_attr`),
//! each checked as Linux checks its arguments.

use crate::{Kernel, Platform, guest, thread, uaccess};
use fwe_abi::{err, errno, signal as sig};
use std::sync::atomic::Ordering::SeqCst;

/// `sync_file_range`'s flags.
const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
const SYNC_FILE_RANGE_WRITE: u64 = 2;
const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;

/// The security modules fwe has: Linux's capabilities and Landlock
/// (`LSM_ID_CAPABILITY`, `LSM_ID_LANDLOCK`), which keep no attributes of a
/// process.
const LSM_IDS: [u64; 2] = [100, 110];

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
/// The kernel log's size Linux reports (`CONFIG_LOG_BUF_SHIFT` of 17).
const LOG_BUF_LEN: i64 = 1 << 17;

/// The longest module name (`MODULE_NAME_LEN`).
const MODULE_NAME_LEN: usize = 56;

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

    /// `delete_module(name, flags)`: no module is loaded, so any name is
    /// not found (`ENOENT`), once `CAP_SYS_MODULE` is had and the name
    /// read.
    pub(crate) fn sys_delete_module(&mut self, name: u64) -> i64 {
        if !self.creds.has(crate::caps::CAP_SYS_MODULE) {
            return err(errno::EPERM);
        }
        let n = guest!(uaccess::read_cstr(name, MODULE_NAME_LEN + 1));
        if n.len() >= MODULE_NAME_LEN {
            return err(errno::ENOENT);
        }
        err(errno::ENOENT)
    }

    /// `syslog(type, buf, len)` (`klogctl`): the kernel log, which is
    /// empty. Reading it, clearing it and setting the console level need
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
                // An empty log: a read of it waits for none, nothing to
                // copy.
                0
            }
            SYSLOG_ACTION_CLEAR => 0,
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
            SYSLOG_ACTION_SIZE_UNREAD => 0,
            _ => LOG_BUF_LEN,
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
            CLASS_RT if !self.creds.has(crate::caps::CAP_SYS_NICE) && !self.creds.has_admin() => {
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
        // Only a process: Linux finds none for 0 or a negative number.
        if tgid <= 0 {
            return err(errno::ESRCH);
        }
        // Another thread's id names its process, as on Linux.
        let tgid = if tid.is_none() && thread::host_thread(tgid).is_some() { me } else { tgid };
        if (code >= 0 || code == sig::SI_TKILL) && tgid != me {
            return err(errno::EPERM);
        }
        if s > sig::NSIG {
            return err(errno::EINVAL);
        }
        let Some(host) = crate::pidns::to_host(tgid) else { return err(errno::ESRCH) };
        // As `kill` is: only a process the caller may signal.
        if tgid != me && !self.may_signal(host, s) {
            return err(errno::EPERM);
        }
        if s == 0 {
            return 0;
        }
        // SAFETY: getpid and getuid cannot fail.
        let (pid, uid) = unsafe { (libc::getpid(), libc::getuid()) };
        let info = thread::SigInfo { code, pid, uid, value, ..Default::default() };
        if tgid == me {
            if !thread::may_queue(s) {
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
        if tid.is_some_and(|t| t != tgid) {
            // Another process's other thread: the host signals processes.
            return err(errno::ESRCH);
        }
        // One the host lacks, or SIGTRAP (which the host would merge with
        // the target's next system-call trap): through the mailbox.
        let h = crate::host::signal_to_host(s).filter(|_| s != fwe_abi::signal::SIGTRAP);
        let Some(h) = h else {
            return crate::signal::send_unhosted(host, s, code, value);
        };
        crate::signote::note_with(host, h, code, value);
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
