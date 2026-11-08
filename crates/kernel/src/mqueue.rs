//! POSIX message queues: `mq_open`, `mq_unlink`, `mq_timedsend`,
//! `mq_timedreceive`, `mq_notify` and `mq_getsetattr`, one set of queues
//! per IPC namespace, shared by every process in it.
//!
//! A queue is a record of its own ([`crate::shared::Record`]) in a
//! directory inside its namespace's ([`crate::sysvipc::Ipc`]), which
//! names it and counts it against `fs.mqueue.queues_max` and the
//! creator's `RLIMIT_MSGQUEUE`. The record holds the queue's owner,
//! permissions, attributes, messages (by priority, oldest first within
//! one), the receivers waiting and the notification registered. Every
//! send or receive is one change of it, under its lock; one that must wait
//! (a full or empty queue) waits for the record to change and tries again.
//!
//! The guest's descriptor is a host descriptor of a file in the queue's
//! directory, opened with the guest's access mode, which holds a shared
//! `flock` on it: the lock lasts as long as any descriptor of that open
//! (through `dup`, `fork` and an `exec` that keeps it), so a queue that is
//! unlinked is freed once nothing holds its file, as Linux frees one with
//! its last descriptor. A descriptor is close-on-exec, as Linux makes it.
//! Reading one gives the queue's status line; writing one is refused. The
//! mqueue filesystem (`/dev/mqueue`) lists the namespace's queues, each
//! file reading as its status line.
//!
//! A notification goes to the process that registered it, whoever sends
//! the message that makes the queue non-empty: a signal (`SI_MESGQ`, with
//! the sender and the registered value), which reaches another process as
//! a host signal with a note of what it carries ([`crate::signote`]); or,
//! for `SIGEV_THREAD` (which the C library turns into a netlink socket and
//! a cookie), the cookie, sent to the socket at the host address fwe gave
//! it ([`crate::netlink::bind_for_notify`]).
//!
//! Not kept: `poll`, `select` and `epoll` see a queue's descriptor as
//! always ready (its readiness is the queue's, not the host file's), a
//! queue's file in the mqueue filesystem is read, not opened as the queue
//! or removed, and a real-time signal is not sent to another process (see
//! `docs/architecture.md`).

use crate::creds::Creds;
use crate::fdmarks::{self, Mark};
use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use crate::sysvipc::{self as ipc, Ipc, Proc};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::mqueue::*;
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The longest name: `NAME_MAX`.
const NAME_MAX: usize = 255;
/// What Linux charges a queue for each message's header and each
/// priority's tree node (`struct msg_msg`, `struct posix_msg_tree_node`).
const MSG_OVERHEAD: u64 = 48;
const NODE_OVERHEAD: u64 = 48;

/// A registered notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notify {
    /// The process that registered it.
    pub owner: Proc,
    /// `SIGEV_NONE`, `SIGEV_SIGNAL` or `SIGEV_THREAD`.
    pub how: i32,
    /// `SIGEV_SIGNAL`'s signal (0: none) and value.
    pub signo: u32,
    pub value: u64,
    /// `SIGEV_THREAD`'s socket's host address and cookie.
    pub path: Vec<u8>,
    pub cookie: Vec<u8>,
}

/// A queue.
#[derive(Clone, Debug, Default)]
pub struct Queue {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub maxmsg: i64,
    pub msgsize: i64,
    /// The messages, highest priority first, oldest first within one.
    pub msgs: Vec<(u32, Vec<u8>)>,
    /// Threads waiting to receive (a message sent then goes to one of
    /// them, and no notification is sent).
    pub receivers: Vec<(Proc, i32)>,
    pub notify: Option<Notify>,
}

impl Queue {
    fn bytes(&self) -> u64 {
        self.msgs.iter().map(|(_, m)| m.len() as u64).sum()
    }

    /// Put a message where its priority goes: after every one of the
    /// same or higher.
    fn insert(&mut self, prio: u32, msg: Vec<u8>) {
        let at = self.msgs.iter().position(|&(p, _)| p < prio).unwrap_or(self.msgs.len());
        self.msgs.insert(at, (prio, msg));
    }

    /// Drop what processes that are gone left: a registration and waiting
    /// receivers. Whether anything was.
    fn reap(&mut self) -> bool {
        let before = self.receivers.len();
        self.receivers.retain(|&(p, _)| alive(p));
        let gone = self.notify.as_ref().is_some_and(|n| !alive(n.owner));
        if gone {
            self.notify = None;
        }
        gone || self.receivers.len() != before
    }
}

fn alive(p: Proc) -> bool {
    p == ipc::me() || crate::procreg::alive(p)
}

impl Data for Queue {
    fn encode(&self, e: &mut Enc) {
        for v in [self.uid, self.gid, self.mode] {
            e.u32(v);
        }
        e.u64(self.maxmsg as u64);
        e.u64(self.msgsize as u64);
        e.u64(self.msgs.len() as u64);
        for (p, m) in &self.msgs {
            e.u32(*p);
            e.bytes(m);
        }
        e.u64(self.receivers.len() as u64);
        for &((pid, start), tid) in &self.receivers {
            e.i32(pid);
            e.u64(start);
            e.i32(tid);
        }
        e.bool(self.notify.is_some());
        if let Some(n) = &self.notify {
            e.i32(n.owner.0);
            e.u64(n.owner.1);
            e.i32(n.how);
            e.u32(n.signo);
            e.u64(n.value);
            e.bytes(&n.path);
            e.bytes(&n.cookie);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let (uid, gid, mode) = (d.u32(), d.u32(), d.u32());
        let (maxmsg, msgsize) = (d.u64() as i64, d.u64() as i64);
        let n = d.count(12);
        let msgs = (0..n).map(|_| (d.u32(), d.bytes())).collect();
        let n = d.count(16);
        let receivers = (0..n).map(|_| ((d.i32(), d.u64()), d.i32())).collect();
        let notify = d.bool().then(|| Notify {
            owner: (d.i32(), d.u64()),
            how: d.i32(),
            signo: d.u32(),
            value: d.u64(),
            path: d.bytes(),
            cookie: d.bytes(),
        });
        Queue { uid, gid, mode, maxmsg, msgsize, msgs, receivers, notify }
    }

    fn valid(&self) -> bool {
        self.maxmsg > 0
    }
}

/// Records of a kind, by directory.
type Cache<T> = Mutex<Option<HashMap<Vec<u8>, Arc<Record<T>>>>>;

/// The records this process has used, by directory: each is opened once
/// (a record maps its generation for good).
fn cached<T: Data>(
    cache: &'static Cache<T>,
    dir: &[u8],
    open: impl FnOnce() -> Result<Record<T>, i32>,
) -> Result<Arc<Record<T>>, i32> {
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if let Some(r) = m.get(dir) {
        return Ok(r.clone());
    }
    let r = Arc::new(open()?);
    m.insert(dir.to_vec(), r.clone());
    Ok(r)
}

static QUEUES: Cache<Queue> = Mutex::new(None);
static NAMESPACES: Cache<Ipc> = Mutex::new(None);

fn queue_at(dir: &[u8]) -> Result<Arc<Record<Queue>>, i32> {
    cached(&QUEUES, dir, || Record::join(dir, 0))
}

/// The directory of the queue `fd` is a descriptor of (`EBADF` for one of
/// anything else).
fn dir_of(fd: i32) -> Result<Vec<u8>, i32> {
    if fd < 0 || !fdmarks::any_marks() || fdmarks::marked(fd) != Some(Mark::Mq) {
        return Err(errno::EBADF);
    }
    let file = host_path(fd).ok_or(errno::EBADF)?;
    let slash = file.iter().rposition(|&b| b == b'/').ok_or(errno::EBADF)?;
    Ok(file[..slash].to_vec())
}

/// The host path of the file `fd` is open on.
fn host_path(fd: i32) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        // SAFETY: a buffer of `PATH_MAX` bytes, as `F_GETPATH` needs.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } != 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0)?;
        Some(buf[..end].to_vec())
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
        Some(p.as_os_str().as_bytes().to_vec())
    }
}

/// Directory `dir` as the host names it (its links resolved), as a
/// descriptor's path reads: the one key for a queue's records.
fn canonical(dir: &[u8]) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    std::fs::canonicalize(std::ffi::OsStr::from_bytes(dir))
        .map_or_else(|_| dir.to_vec(), |p| p.as_os_str().as_bytes().to_vec())
}

/// The queue's file in its directory, which each descriptor is open on.
fn file_of(dir: &[u8]) -> Vec<u8> {
    [dir, b"/q"].concat()
}

/// The namespace record a queue directory is in.
fn namespace_of(dir: &[u8]) -> Result<Arc<Record<Ipc>>, i32> {
    let slash = dir.iter().rposition(|&b| b == b'/').ok_or(errno::EBADF)?;
    let ns = &dir[..slash];
    cached(&NAMESPACES, ns, || Record::join(ns, 0))
}

fn cstr(p: &[u8]) -> Result<std::ffi::CString, i32> {
    std::ffi::CString::new(p).map_err(|_| errno::EINVAL)
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// Whether nothing holds queue `dir`'s file open.
fn unheld(dir: &[u8]) -> bool {
    let Ok(c) = cstr(&file_of(dir)) else { return false };
    // SAFETY: a NUL-terminated path in fwe's private directory; the
    // descriptor is closed again.
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return true;
        }
        let free = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0;
        libc::close(fd);
        free
    }
}

/// Free the queues of namespace `t` (at `ns_dir`) that are unlinked and
/// that nothing holds open. Whether any was.
fn free_unheld(t: &mut Ipc, ns_dir: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let named: std::collections::HashSet<&Vec<u8>> = t.mq_names.values().collect();
    let gone: Vec<Vec<u8>> = t
        .mq_live
        .keys()
        .filter(|d| !named.contains(d))
        .filter(|d| unheld(&[ns_dir, b"/", d].concat()))
        .cloned()
        .collect();
    for d in &gone {
        t.mq_live.remove(d);
        let full = [ns_dir, b"/", d].concat();
        let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes(&full));
        QUEUES.lock().unwrap_or_else(|e| e.into_inner()).as_mut().map(|m| m.remove(&full));
    }
    !gone.is_empty()
}

/// A queue name as `mq_open` and `mq_unlink` look it up (the C library
/// takes off the leading `/`): `ENOENT` for none, `EACCES` for one that
/// is not a single name, `ENAMETOOLONG` past `NAME_MAX`.
fn read_name(addr: u64) -> Result<Vec<u8>, i32> {
    let name = uaccess::read_cstr(addr, libc::PATH_MAX as usize - 1)?;
    if name.is_empty() {
        return Err(errno::ENOENT);
    }
    if name.contains(&b'/') || name == b"." || name == b".." {
        return Err(errno::EACCES);
    }
    if name.len() > NAME_MAX {
        return Err(errno::ENAMETOOLONG);
    }
    Ok(name)
}

/// Whether `creds` may access queue `q` as `want` (`rwx` bits), as a
/// file's permission is checked.
fn may(creds: &Creds, q: &Queue, want: u32) -> bool {
    let shift = if creds.fsuid == q.uid {
        6
    } else if creds.fsgid == q.gid || creds.groups.contains(&q.gid) {
        3
    } else {
        0
    };
    (q.mode >> shift) & want == want
        || creds.has(crate::caps::CAP_DAC_OVERRIDE)
        || (want == 4 && creds.has(crate::caps::CAP_DAC_READ_SEARCH))
}

/// The guest's access mode of queue descriptor `fd`: (readable,
/// writable, non-blocking).
fn access(fd: i32) -> Result<(bool, bool, bool), i32> {
    // SAFETY: plain host call.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(errno::EBADF);
    }
    let acc = fl & libc::O_ACCMODE;
    Ok((acc != libc::O_WRONLY, acc != libc::O_RDONLY, fl & libc::O_NONBLOCK != 0))
}

/// A deadline from the absolute `CLOCK_REALTIME` time at guest `ts` (none
/// for 0): `EFAULT` or `EINVAL` for a bad one, as Linux checks it first.
fn deadline(ts: u64) -> Result<Option<Instant>, i32> {
    if ts == 0 {
        return Ok(None);
    }
    let t: fwe_abi::Timespec = uaccess::read(ts)?;
    if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
        return Err(errno::EINVAL);
    }
    let at = Duration::new(t.tv_sec as u64, t.tv_nsec as u32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Ok(Some(Instant::now() + at.saturating_sub(now)))
}

/// The outcome of one try of a send or receive.
enum Try<T> {
    Done(T),
    Wait,
}

/// Run `step` (one try, under the queue record's lock) until it is done,
/// waiting for the record to change between tries: up to `until`
/// (`ETIMEDOUT`), and no longer than a signal for the guest (`EINTR`).
/// `cancel` undoes what a try that waited left in the record.
fn wait_for<T>(
    r: &Record<Queue>,
    until: Option<Instant>,
    mut step: impl FnMut(&mut Queue) -> Result<(Try<T>, bool), i32>,
    cancel: impl Fn(&mut Queue) -> bool,
) -> Result<T, i32> {
    loop {
        let seen = r.generation();
        match r.update_maybe(|q| {
            let reaped = q.reap();
            let (out, changed) = step(q)?;
            Ok((out, changed || reaped))
        }) {
            Ok(Try::Done(v)) => return Ok(v),
            Ok(Try::Wait) => {}
            // The queue's record gone: it was freed under this descriptor.
            Err(errno::ENOENT) => return Err(errno::EBADF),
            Err(e) => return Err(e),
        }
        if let Err(e) = r.wait_change(seen, until) {
            let _ = r.update_maybe(|q| Ok(((), cancel(q))));
            return Err(if e == errno::EAGAIN { errno::ETIMEDOUT } else { e });
        }
    }
}

/// Who sends a notification: this process, with the real user `uid` (in
/// the initial namespace's terms).
#[derive(Clone, Copy)]
struct Sender {
    pid: i32,
    uid: u32,
}

/// Send notification `n`, as the kernel does when a message comes to an
/// empty queue (`why` `NOTIFY_WOKENUP`), or when its registration is
/// removed (`NOTIFY_REMOVED`, which only a `SIGEV_THREAD` one hears of).
fn send_notification(n: &Notify, why: u8, by: Sender) {
    match n.how {
        SIGEV_THREAD => {
            let mut cookie = n.cookie.clone();
            cookie.resize(NOTIFY_COOKIE_LEN, 0);
            cookie[NOTIFY_COOKIE_LEN - 1] = why;
            crate::netlink::notify(&n.path, &cookie);
        }
        SIGEV_SIGNAL if why == NOTIFY_WOKENUP && n.signo != 0 => {
            let sig = n.signo as u64;
            let info = crate::thread::SigInfo {
                code: fwe_abi::signal::SI_MESGQ,
                pid: by.pid,
                uid: by.uid,
                status: 0,
                value: n.value,
                poll: None,
            };
            if n.owner == ipc::me() {
                crate::thread::post_process(sig, info);
                crate::thread::wake_others(crate::host::WAKE_SIGNAL);
            } else if let Some(h) = crate::host::signal_to_host(sig) {
                // Another process: a host signal, with a note of what it
                // carries. A real-time signal, which the host lacks, cannot
                // reach it.
                crate::signote::note_with(n.owner.0, h, info.code, info.value);
                if crate::host::kill(n.owner.0, h) != 0 {
                    crate::signote::unnote(n.owner.0, h);
                }
            }
        }
        _ => {}
    }
}

/// What a send or receive needs of the caller, taken under the kernel
/// lock: who it is.
fn sender(creds: &Creds) -> Sender {
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let uid = crate::userns::from_ns(creds.uid, false).unwrap_or(crate::userns::OVERFLOW);
    Sender { pid, uid }
}

/// `mq_timedsend(fd, msg, len, prio, abs_timeout)`.
pub fn timedsend(creds: &Creds, fd: u64, msg: u64, len: u64, prio: u64, ts: u64) -> i64 {
    let until = guest!(deadline(ts));
    // An `unsigned int`.
    let prio = prio as u32 as u64;
    if prio >= MQ_PRIO_MAX {
        return err(errno::EINVAL);
    }
    let fd = fd as i32;
    let dir = guest!(dir_of(fd));
    let (_, writable, nonblock) = guest!(access(fd));
    if !writable {
        return err(errno::EBADF);
    }
    let r = guest!(queue_at(&dir));
    if len > r.get().msgsize as u64 {
        return err(errno::EMSGSIZE);
    }
    let text = guest!(uaccess::read_bytes(msg, len as usize));
    let notify = wait_for(
        &r,
        until,
        |q| {
            if q.msgs.len() as i64 >= q.maxmsg {
                if nonblock {
                    return Err(errno::EAGAIN);
                }
                return Ok((Try::Wait, false));
            }
            q.insert(prio as u32, text.clone());
            // A message to an empty queue that no receiver waits for:
            // the registration is spent on it.
            let notify =
                if q.msgs.len() == 1 && q.receivers.is_empty() { q.notify.take() } else { None };
            Ok((Try::Done(notify), true))
        },
        |_| false,
    );
    match notify {
        Ok(n) => {
            if let Some(n) = n {
                send_notification(&n, NOTIFY_WOKENUP, sender(creds));
            }
            0
        }
        Err(e) => err(e),
    }
}

/// `mq_timedreceive(fd, buf, len, prio, abs_timeout)`: the oldest of the
/// messages of the highest priority, its length.
pub fn timedreceive(fd: u64, buf: u64, len: u64, prio: u64, ts: u64) -> i64 {
    let until = guest!(deadline(ts));
    let fd = fd as i32;
    let dir = guest!(dir_of(fd));
    let (readable, _, nonblock) = guest!(access(fd));
    if !readable {
        return err(errno::EBADF);
    }
    let r = guest!(queue_at(&dir));
    if len < r.get().msgsize as u64 {
        return err(errno::EMSGSIZE);
    }
    let me = (ipc::me(), crate::thread::tid());
    let got = wait_for(
        &r,
        until,
        |q| {
            if q.msgs.is_empty() {
                if nonblock {
                    return Err(errno::EAGAIN);
                }
                let waiting = q.receivers.contains(&me);
                if !waiting {
                    q.receivers.push(me);
                }
                return Ok((Try::Wait, !waiting));
            }
            q.receivers.retain(|w| *w != me);
            Ok((Try::Done(q.msgs.remove(0)), true))
        },
        |q| {
            let before = q.receivers.len();
            q.receivers.retain(|w| *w != me);
            q.receivers.len() != before
        },
    );
    let (p, text) = guest!(got);
    // The message is taken even if it cannot be stored, as on Linux.
    if prio != 0 {
        guest!(uaccess::write(prio, p));
    }
    guest!(uaccess::write_from(buf, &text));
    text.len() as i64
}

/// The status line reading a queue's descriptor gives.
fn status(q: &Queue) -> Vec<u8> {
    let (how, signo, pid) = match &q.notify {
        Some(n) => {
            let pid =
                if crate::pidns::nested() { crate::pidns::to_guest(n.owner.0) } else { n.owner.0 };
            let signo = if n.how == SIGEV_SIGNAL { n.signo } else { 0 };
            (n.how, signo, pid)
        }
        None => (0, 0, 0),
    };
    format!("QSIZE:{:<10} NOTIFY:{how:<5} SIGNO:{signo:<5} NOTIFY_PID:{pid:<6}\n", q.bytes())
        .into_bytes()
}

/// If `fd` is a queue's descriptor, the queue's mode and owner (user and
/// group): what `fstat` of it reports.
pub fn owner_of(fd: i32) -> Option<(u32, u32, u32)> {
    let dir = dir_of(fd).ok()?;
    let q = queue_at(&dir).ok()?.get();
    Some((q.mode, q.uid, q.gid))
}

/// The names of the process's IPC namespace's queues: what its mqueue
/// filesystem lists.
pub fn names() -> Vec<Vec<u8>> {
    ipc::current().map_or_else(Vec::new, |r| r.get().mq_names.keys().cloned().collect())
}

/// The status line of the process's IPC namespace's queue `name`, if it
/// has one: what the queue's file in its mqueue filesystem reads as.
pub fn status_of(name: &[u8]) -> Option<Vec<u8>> {
    let ns = ipc::current()?;
    let dir = ns.get().mq_names.get(name)?.clone();
    let q = queue_at(&[&canonical(ns.dir())[..], b"/", &dir].concat()).ok()?;
    Some(status(&q.get()))
}

/// A read or write of a queue's descriptor (`read`, `pread64`, `readv`
/// and the like): reading gives its status line from the descriptor's
/// position, as Linux reads one; writing is refused (`EINVAL`), as Linux
/// has no write for it. `None` for another descriptor.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    let read = matches!(nr, n::READ | n::PREAD64 | n::READV | n::PREADV | n::PREADV2);
    let write = matches!(nr, n::WRITE | n::PWRITE64 | n::WRITEV | n::PWRITEV | n::PWRITEV2);
    if !(read || write) || !fdmarks::any_marks() {
        return None;
    }
    let fd = a[0] as i32;
    if fdmarks::marked(fd) != Some(Mark::Mq) {
        return None;
    }
    let dir = match dir_of(fd) {
        Ok(d) => d,
        Err(e) => return Some(err(e)),
    };
    let (readable, writable, _) = match access(fd) {
        Ok(a) => a,
        Err(e) => return Some(err(e)),
    };
    if write {
        return Some(err(if writable { errno::EINVAL } else { errno::EBADF }));
    }
    if !readable {
        return Some(err(errno::EBADF));
    }
    let text = match queue_at(&dir) {
        Ok(r) => status(&r.get()),
        Err(e) => return Some(err(e)),
    };
    let at = match nr {
        n::PREAD64 | n::PREADV => Some(a[3]),
        n::PREADV2 if a[3] as i64 != -1 => Some(a[3]),
        _ => None,
    };
    if at.is_some_and(|p| (p as i64) < 0) {
        return Some(err(errno::EINVAL));
    }
    // SAFETY: plain host call on the queue's file.
    let pos = at.unwrap_or_else(|| unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }.max(0) as u64);
    let mut rest = text.get(pos as usize..).unwrap_or_default();
    let iov = if matches!(nr, n::READ | n::PREAD64) {
        uaccess::host_buffer(a[1], a[2], true).map(|v| vec![v])
    } else {
        uaccess::host_iovecs(a[1], a[2], true)
    };
    let iov = match iov {
        Ok(v) => v,
        Err(e) => return Some(err(e)),
    };
    let mut done = 0u64;
    for v in iov {
        let n = rest.len().min(v.iov_len);
        // SAFETY: `host_buffer` checked the buffer is writable guest
        // memory of `iov_len` bytes.
        unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), v.iov_base.cast::<u8>(), n) };
        rest = &rest[n..];
        done += n as u64;
    }
    if at.is_none() {
        // SAFETY: as above.
        unsafe { libc::lseek(fd, (pos + done) as libc::off_t, libc::SEEK_SET) };
    }
    Some(done as i64)
}

/// Descriptor `fd` is about to be closed: if it is a queue's, what Linux
/// does as one is (its registration, if this process made it, is
/// removed), then, once it is closed, the queue freed if it is unlinked
/// and nothing holds it. Returns what to do after the close.
pub fn closing(fd: i32, creds: &Creds) -> Option<impl FnOnce()> {
    if !fdmarks::any_marks() || fdmarks::marked(fd) != Some(Mark::Mq) {
        return None;
    }
    let dir = dir_of(fd).ok()?;
    if let Ok(r) = queue_at(&dir) {
        let me = ipc::me();
        let removed = r.update_maybe(|q| {
            let mine = q.notify.as_ref().is_some_and(|n| n.owner == me);
            Ok((if mine { q.notify.take() } else { None }, mine))
        });
        if let Ok(Some(n)) = removed {
            send_notification(&n, NOTIFY_REMOVED, sender(creds));
        }
    }
    Some(move || {
        if let Ok(ns) = namespace_of(&dir) {
            let ns_dir = ns.dir().to_vec();
            let _ = ns.update_maybe(|t| Ok(((), free_unheld(t, &ns_dir))));
        }
    })
}

/// The process is about to replace its program by a host `execve`, which
/// closes its close-on-exec descriptors: what closing each queue's among
/// them does (its registration removed), as Linux does as it closes them.
pub fn exec_closing(creds: &Creds) {
    if !fdmarks::any_marks() {
        return;
    }
    for fd in crate::fdtable::open_fds() {
        // SAFETY: plain host call on an open descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
            // The queue's freeing is left to the next look, once it is closed.
            let _ = closing(fd, creds);
        }
    }
}

impl<P: Platform> Kernel<P> {
    /// The process's IPC namespace, for its queues, and its directory.
    fn mq_namespace(&self) -> Result<(Arc<Record<Ipc>>, Vec<u8>), i32> {
        let r = self.fs().ns.ipc.clone().or_else(ipc::initial).ok_or(errno::ENOMEM)?;
        ipc::set_current(&r);
        let dir = canonical(r.dir());
        Ok((r, dir))
    }

    /// `mq_open(name, oflag, mode, attr)`.
    pub(crate) fn sys_mq_open(&mut self, name: u64, oflag: u64, mode: u64, attr: u64) -> i64 {
        use fwe_abi::fcntl::{O_CREAT, O_EXCL, O_NONBLOCK};
        let asked: Option<[i64; 8]> =
            if attr != 0 { Some(guest!(uaccess::read(attr))) } else { None };
        let name = guest!(read_name(name));
        // The descriptor's number, taken first (`EMFILE`), as Linux takes it.
        // SAFETY: a NUL-terminated path; the descriptor is the call's.
        let slot = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if slot < 0 {
            return err(last());
        }
        if crate::fdtable::over_limit(&[slot]) {
            // SAFETY: the descriptor taken above.
            unsafe { libc::close(slot) };
            return err(errno::EMFILE);
        }
        let (ns, ns_dir) = match self.mq_namespace() {
            Ok(n) => n,
            Err(e) => {
                // SAFETY: the descriptor taken above.
                unsafe { libc::close(slot) };
                return err(e);
            }
        };
        let creds = self.creds.clone();
        let umask = self.fs().umask();
        let host_mode = match oflag as i32 & 3 {
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => libc::O_RDONLY,
        };
        let host_flags = host_mode
            | libc::O_CLOEXEC
            | if oflag & O_NONBLOCK != 0 { libc::O_NONBLOCK } else { 0 };
        let opened = ns.update_maybe(|t| {
            let freed = free_unheld(t, &ns_dir);
            sweep_addresses(&ns_dir);
            let (dir, made) = match t.mq_names.get(&name) {
                Some(d) => {
                    if oflag & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                        return Err(errno::EEXIST);
                    }
                    if oflag & 3 == 3 {
                        return Err(errno::EINVAL);
                    }
                    let want = [4, 2, 6][(oflag & 3) as usize];
                    let full = [&ns_dir[..], b"/", d].concat();
                    let q = queue_at(&full)?.get();
                    if !may(&creds, &q, want) {
                        return Err(errno::EACCES);
                    }
                    (full, false)
                }
                None => {
                    if oflag & O_CREAT == 0 {
                        return Err(errno::ENOENT);
                    }
                    let privileged = creds.has(crate::caps::CAP_SYS_RESOURCE);
                    if t.mq_live.len() as i64 >= t.mq_tunable("queues_max") && !privileged {
                        return Err(errno::ENOSPC);
                    }
                    let (maxmsg, msgsize) = match asked {
                        Some(a) => (a[1], a[2]),
                        None => (t.mq_tunable("msg_default"), t.mq_tunable("msgsize_default")),
                    };
                    if maxmsg <= 0 || msgsize <= 0 {
                        return Err(errno::EINVAL);
                    }
                    let (most, largest) = if privileged {
                        (HARD_MSGMAX, HARD_MSGSIZEMAX)
                    } else {
                        (t.mq_tunable("msg_max"), t.mq_tunable("msgsize_max"))
                    };
                    if asked.is_some() && (maxmsg > most || msgsize > largest) {
                        return Err(errno::EINVAL);
                    }
                    let (n, size) = (maxmsg as u64, msgsize as u64);
                    let bytes = n * (MSG_OVERHEAD + size) + n.min(MQ_PRIO_MAX) * NODE_OVERHEAD;
                    let charged: u64 = t
                        .mq_live
                        .values()
                        .filter(|&&(uid, _)| uid == creds.uid)
                        .map(|&(_, b)| b)
                        .sum();
                    let (limit, _) = crate::rlimits::get(fwe_abi::resource::RLIMIT_MSGQUEUE);
                    if charged.saturating_add(bytes) > limit {
                        return Err(errno::EMFILE);
                    }
                    let rel = format!("mq-{}", t.mq_seq).into_bytes();
                    let full = [&ns_dir[..], b"/", &rel].concat();
                    let q = Queue {
                        uid: creds.fsuid,
                        gid: creds.fsgid,
                        mode: mode as u32 & 0o777 & !umask,
                        maxmsg,
                        msgsize,
                        ..Queue::default()
                    };
                    let r = Arc::new(Record::at(full.clone(), || q)?);
                    let c = cstr(&file_of(&full))?;
                    // SAFETY: a NUL-terminated path in the record's
                    // directory; the descriptor is closed again.
                    let fd = unsafe {
                        libc::open(
                            c.as_ptr(),
                            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                            0o600,
                        )
                    };
                    if fd < 0 {
                        return Err(last());
                    }
                    // SAFETY: the descriptor just opened.
                    unsafe { libc::close(fd) };
                    QUEUES
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_or_insert_with(HashMap::new)
                        .insert(full.clone(), r);
                    t.mq_seq += 1;
                    t.mq_names.insert(name.clone(), rel.clone());
                    t.mq_live.insert(rel, (creds.uid, bytes));
                    (full, true)
                }
            };
            let c = cstr(&file_of(&dir))?;
            // SAFETY: a NUL-terminated path in fwe's private directory.
            let fd = unsafe { libc::open(c.as_ptr(), host_flags) };
            if fd < 0 {
                return Err(last());
            }
            // SAFETY: the descriptor just opened: its shared lock says the
            // queue is held.
            unsafe { libc::flock(fd, libc::LOCK_SH) };
            Ok((fd, made || freed))
        });
        let fd = match opened {
            Ok(fd) => fd,
            Err(e) => {
                // SAFETY: the descriptor taken above.
                unsafe { libc::close(slot) };
                return err(e);
            }
        };
        // SAFETY: both descriptors are this call's; the queue's takes the
        // number taken first.
        unsafe {
            libc::dup2(fd, slot);
            libc::close(fd);
            // `dup2` clears the flag: a queue's descriptor is close-on-exec.
            libc::fcntl(slot, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        fdmarks::mark(slot, Mark::Mq);
        slot as i64
    }

    /// `mq_unlink(name)`: the name goes; the queue lives while it is open.
    pub(crate) fn sys_mq_unlink(&mut self, name: u64) -> i64 {
        let name = guest!(read_name(name));
        let (ns, ns_dir) = guest!(self.mq_namespace());
        let creds = self.creds.clone();
        let r = ns.update_maybe(|t| {
            let dir = t.mq_names.get(&name).ok_or(errno::ENOENT)?;
            let q = queue_at(&[&ns_dir[..], b"/", dir].concat())?.get();
            // The queues' directory is root's and sticky: only the queue's
            // owner removes it, or one with `CAP_FOWNER`.
            if creds.fsuid != q.uid && creds.fsuid != 0 && !creds.has(crate::caps::CAP_FOWNER) {
                return Err(errno::EPERM);
            }
            t.mq_names.remove(&name);
            free_unheld(t, &ns_dir);
            Ok(((), true))
        });
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `mq_notify(fd, sevp)`: register (or with none, remove) the
    /// process's notification of a message coming to the empty queue.
    pub(crate) fn sys_mq_notify(&mut self, fd: u64, sevp: u64) -> i64 {
        let sev = if sevp != 0 {
            let b = guest!(uaccess::read_bytes(sevp, SIGEVENT_SIZE));
            let word = |at: usize| i32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
            Some((u64::from_ne_bytes(b[0..8].try_into().unwrap()), word(8), word(12)))
        } else {
            None
        };
        // What the request asks, checked first.
        let mut cookie = Vec::new();
        if let Some((value, signo, how)) = sev {
            if !matches!(how, SIGEV_NONE | SIGEV_SIGNAL | SIGEV_THREAD) {
                return err(errno::EINVAL);
            }
            if how == SIGEV_SIGNAL && !(0..=fwe_abi::signal::NSIG as i32).contains(&signo) {
                return err(errno::EINVAL);
            }
            if how == SIGEV_THREAD {
                cookie = guest!(uaccess::read_bytes(value, NOTIFY_COOKIE_LEN));
                guest!(notify_socket(signo));
            }
        }
        let fd = fd as i32;
        let dir = guest!(dir_of(fd));
        let r = guest!(queue_at(&dir));
        let me = ipc::me();
        let by = sender(&self.creds);
        let result = r.update_maybe(|q| {
            let reaped = q.reap();
            let Some((value, signo, how)) = sev else {
                let mine = q.notify.as_ref().is_some_and(|n| n.owner == me);
                return Ok((if mine { q.notify.take() } else { None }, mine || reaped));
            };
            if q.notify.is_some() {
                return Err(errno::EBUSY);
            }
            let path = if how == SIGEV_THREAD {
                let ns_dir = &dir[..dir.iter().rposition(|&b| b == b'/').unwrap_or(0)];
                let path = notify_path(ns_dir);
                crate::netlink::bind_for_notify(signo, &path)?
            } else {
                Vec::new()
            };
            q.notify = Some(Notify {
                owner: me,
                how,
                signo: signo as u32,
                value,
                path,
                cookie: cookie.clone(),
            });
            Ok((None, true))
        });
        match result {
            Ok(removed) => {
                if let Some(n) = removed {
                    send_notification(&n, NOTIFY_REMOVED, by);
                }
                0
            }
            Err(e) => err(e),
        }
    }

    /// `mq_getsetattr(fd, new, old)`: the queue's attributes, with the
    /// descriptor's `O_NONBLOCK`, which `new` may change.
    pub(crate) fn sys_mq_getsetattr(&mut self, fd: u64, new: u64, old: u64) -> i64 {
        use fwe_abi::fcntl::O_NONBLOCK;
        let set: Option<[i64; 8]> = if new != 0 { Some(guest!(uaccess::read(new))) } else { None };
        if set.is_some_and(|a| a[0] as u64 & !O_NONBLOCK != 0) {
            return err(errno::EINVAL);
        }
        let fd = fd as i32;
        let dir = guest!(dir_of(fd));
        let q = guest!(queue_at(&dir)).get();
        let (_, _, nonblock) = guest!(access(fd));
        let attr: [i64; 8] = [
            if nonblock { O_NONBLOCK as i64 } else { 0 },
            q.maxmsg,
            q.msgsize,
            q.msgs.len() as i64,
            0,
            0,
            0,
            0,
        ];
        if let Some(a) = set {
            // SAFETY: plain host calls on the queue's descriptor.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                let fl = if a[0] as u64 & O_NONBLOCK != 0 {
                    fl | libc::O_NONBLOCK
                } else {
                    fl & !libc::O_NONBLOCK
                };
                libc::fcntl(fd, libc::F_SETFL, fl);
            }
        }
        if old != 0 {
            guest!(uaccess::write(old, attr));
        }
        0
    }
}

/// A host address, in queue `dir`, no other socket is given: where a
/// `SIGEV_THREAD` registration's socket is bound.
fn notify_path(ns_dir: &[u8]) -> Vec<u8> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    [ns_dir, format!("/{NOTIFY_PREFIX}{pid}-{n}").as_bytes()].concat()
}

/// What the name of a `SIGEV_THREAD` socket's address starts with, then
/// the binding process's pid.
const NOTIFY_PREFIX: &str = "nl-";

/// Remove the socket addresses in namespace directory `ns_dir` of
/// processes that have gone (the binder removes its own as it closes the
/// socket, which one killed outright does not).
fn sweep_addresses(ns_dir: &[u8]) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(ns_dir)) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(rest) = name.as_bytes().strip_prefix(NOTIFY_PREFIX.as_bytes()) else { continue };
        let pid = std::str::from_utf8(rest.split(|&b| b == b'-').next().unwrap_or_default())
            .ok()
            .and_then(|p| p.parse::<i32>().ok());
        if pid.is_some_and(|p| crate::procreg::start_time(p).is_none()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Check `fd` is a netlink socket, as `SIGEV_THREAD`'s `sigev_signo` must
/// name: `EBADF` for no descriptor, `ENOTSOCK` for one that is not a
/// socket, `ECONNREFUSED` for another socket.
fn notify_socket(fd: i32) -> Result<(), i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(errno::EBADF);
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(errno::ENOTSOCK);
    }
    if !crate::netlink::is(fd) {
        return Err(errno::ECONNREFUSED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_go_by_priority_then_age() {
        let mut q = Queue { maxmsg: 10, msgsize: 8, ..Queue::default() };
        q.insert(1, b"a".to_vec());
        q.insert(5, b"b".to_vec());
        q.insert(1, b"c".to_vec());
        q.insert(5, b"d".to_vec());
        let order: Vec<&[u8]> = q.msgs.iter().map(|(_, m)| &m[..]).collect();
        assert_eq!(order, [b"b", b"d", b"a", b"c"]);
        assert_eq!(q.bytes(), 4);
    }

    #[test]
    fn a_queue_round_trips() {
        let q = Queue {
            uid: 1,
            gid: 2,
            mode: 0o640,
            maxmsg: 3,
            msgsize: 16,
            msgs: vec![(7, b"hi".to_vec())],
            receivers: vec![((10, 20), 11)],
            notify: Some(Notify {
                owner: (10, 20),
                how: SIGEV_THREAD,
                signo: 4,
                value: 0xdead,
                path: b"/x/n".to_vec(),
                cookie: vec![1; NOTIFY_COOKIE_LEN],
            }),
        };
        let mut e = Enc::new();
        q.encode(&mut e);
        let bytes = e.into_bytes();
        let mut d = Dec::new(&bytes);
        let back = Queue::decode(&mut d);
        assert!(d.finish().is_ok());
        assert_eq!(
            (back.uid, back.gid, back.mode, back.maxmsg, back.msgsize),
            (1, 2, 0o640, 3, 16)
        );
        assert_eq!(back.msgs, q.msgs);
        assert_eq!(back.receivers, q.receivers);
        assert_eq!(back.notify, q.notify);
    }

    #[test]
    fn the_status_line_is_linuxs() {
        let q = Queue { maxmsg: 1, msgs: vec![(0, vec![0; 12])], ..Queue::default() };
        assert_eq!(
            status(&q),
            b"QSIZE:12         NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n".to_vec()
        );
    }
}
