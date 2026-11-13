//! What fwe knows about an open descriptor beyond the host's own view of
//! it: where a file was opened ([`Origin`]), and whether a socket stands
//! in for a kind the host lacks ([`Mark`]).
//!
//! On Linux an open file keeps the mount it was reached by: `fstatfs`
//! reports that mount's flags and `/proc/self/fd` its path, even once the
//! mount is detached. A host descriptor knows nothing of fwe's mounts.
//! macOS has no `SOCK_SEQPACKET` Unix sockets either, and fwe makes one of
//! a stream socket ([`crate::seqpacket`]). So fwe records both against the
//! descriptor, follows it through `dup` and
//! `close`, `fork` and `exec`, and drops a record whose descriptor no
//! longer names the same file.

use crate::mounts::FsType;
use crate::snapshot::{Dec, Enc};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Where an open file was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The mount (its id in the namespace's table), its flags and its
    /// filesystem's type.
    pub mount: u32,
    pub flags: u64,
    pub fstype: FsType,
    /// The file's path in the mount namespace's view, as it was opened
    /// (empty when fwe could not place it).
    pub ns_path: Vec<u8>,
    /// The layers of the overlay it was opened in, if it was: the
    /// overlay's file it is wherever the mount has gone since.
    pub ovl: Option<std::sync::Arc<crate::overlay::Layers>>,
    /// For an `O_PATH` descriptor fwe could not open the file for (a FIFO,
    /// which any open of would count as a reader; a device or a socket):
    /// the host path of the file the stand-in descriptor names.
    pub stand_in: Option<Vec<u8>>,
}

/// A socket standing in for another kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// A `SOCK_SEQPACKET` Unix socket, made of a stream socket whose
    /// messages are framed ([`crate::seqpacket`]).
    SeqPacket,
    /// A sysctl of the network namespace opened for writing (its index in
    /// [`crate::sysctl`]'s table).
    Sysctl(u8),
    /// `/dev/full`, whose writes fail with `ENOSPC`.
    DevFull,
    /// A socket bound in a network namespace of fwe's, to its port `port`
    /// (of the wildcard address if `any`), or to a low loopback port of the
    /// host's namespace that fwe mapped; `key` is the protocol its table
    /// keeps the port under. See [`crate::netns`].
    NetBound { port: u16, any: bool, key: u8 },
    /// `/proc/<pid>/uid_map` (`which` 0), `gid_map` (1) or `setgroups` (2)
    /// of host process `host`, opened for writing by a process that was
    /// `privileged` there, and whose own id in the map's parent namespace
    /// is `own` (Linux checks the opener's credentials).
    ProcMap { host: i32, which: u8, privileged: bool, own: u32 },
    /// `/proc/<pid>/oom_score_adj` (or the older `oom_adj`, `legacy`) of
    /// host process `host`, opened for writing by a process that may lower
    /// it (`privileged`: `CAP_SYS_RESOURCE`).
    OomScore { host: i32, legacy: bool, privileged: bool },
    /// `/proc/<pid>/timerslack_ns` of host process `host`, opened for
    /// writing.
    TimerSlack { host: i32 },
    /// An `AF_NETLINK` socket ([`crate::netlink`]).
    Netlink,
    /// Loop device `N`'s node, open as the device ([`crate::loopdev`]).
    Loop(u32),
    /// `/dev/loop-control`'s node, open as the device.
    LoopControl,
    /// An `O_PATH` descriptor: it names a file, which is not open to
    /// read, write or act on ([`refuses_path`]).
    Path,
    /// A POSIX message queue's descriptor ([`crate::mqueue`]).
    Mq,
    /// A filesystem context of the new mount API (`fsopen`, `fspick`),
    /// by its number ([`crate::mountapi`]).
    FsContext(u32),
    /// A detached mount tree (`fsmount`, `open_tree`), by its number: an
    /// `O_PATH` descriptor ([`crate::mountapi`]).
    Detached(u32),
    /// A namespace (`/proc/<pid>/ns/<kind>` opened), by its number
    /// ([`crate::nsfd`]).
    Ns(u32),
    /// An inotify instance, by its number ([`crate::inotify`]).
    Inotify(u32),
    /// An `O_PATH | O_NOFOLLOW` descriptor of a link of fwe's `/proc` (a
    /// stand-in, its origin's path the link's), which names the link.
    ProcLink,
    /// A process descriptor of host process `host` (for one of its threads,
    /// thread `tid`; 0 for the process), `PIDFD_NONBLOCK` if `nonblock`
    /// ([`crate::pidfd`]).
    Pid { host: i32, tid: i32, nonblock: bool },
    /// `/proc/self/mem`: the process's memory, by address
    /// ([`crate::procmem`]).
    Mem,
    /// `/proc/<pid>/mem` of another process: tracee `id`'s memory (a
    /// thread's tid, or a process's host pid, as ptrace names tracees).
    RemoteMem { id: i32 },
    /// `/proc/self/pagemap`: an entry per page of the process's memory
    /// ([`crate::procmem`]).
    Pagemap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// The file, to tell a record from a reused descriptor number.
    dev: u64,
    ino: u64,
    origin: Option<Origin>,
    mark: Option<Mark>,
}

pub(crate) static RECORDS: Mutex<BTreeMap<i32, Record>> = Mutex::new(BTreeMap::new());

/// How many records are of files in a cgroup filesystem, so that a write
/// checks for one only while there are any ([`cgroup_file`]).
static CGROUP_FILES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many records are of files of a mount whose access times fwe keeps
/// itself (`noatime`, `nodiratime` or `strictatime`), so that a read looks
/// for one only while there are any ([`atime_files`]).
static ATIME_FILES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many records are of files in a tmpfs, so that `fstat` looks for
/// one only while there are any ([`tmpfs_mount`]).
static TMPFS_FILES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn count(rec: Option<&Record>, up: bool) {
    use crate::mounts::ms;
    use std::sync::atomic::Ordering::SeqCst;
    let Some(o) = rec.and_then(|r| r.origin.as_ref()) else { return };
    let bump = |c: &std::sync::atomic::AtomicUsize| {
        if up {
            c.fetch_add(1, SeqCst);
        } else {
            c.fetch_sub(1, SeqCst);
        }
    };
    if o.fstype == FsType::Cgroup2 {
        bump(&CGROUP_FILES);
    }
    if o.fstype == FsType::Tmpfs {
        bump(&TMPFS_FILES);
    }
    if o.flags & (ms::NOATIME | ms::NODIRATIME | ms::STRICTATIME) != 0 {
        bump(&ATIME_FILES);
    }
}

/// Whether a file opened through mount `id` is open here.
pub fn open_in(id: u32) -> bool {
    records().values().any(|r| r.origin.as_ref().is_some_and(|o| o.mount == id))
}

/// Whether any recorded file is of a mount whose access times fwe keeps
/// ([`crate::atime`]).
pub fn atime_files() -> bool {
    ATIME_FILES.load(std::sync::atomic::Ordering::SeqCst) > 0
}

fn insert(r: &mut BTreeMap<i32, Record>, fd: i32, rec: Record) {
    // A mark however it came: made here, duplicated, or inherited through
    // a VM fork or a re-execution ([`load`]).
    if rec.mark.is_some() {
        MARKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    count(Some(&rec), true);
    count(r.insert(fd, rec).as_ref(), false);
}

fn take(r: &mut BTreeMap<i32, Record>, fd: i32) {
    count(r.remove(&fd).as_ref(), false);
}

/// The tmpfs mount `fd` was opened in, if it is the file of host identity
/// `dev`, `ino` opened in one.
pub fn tmpfs_mount(fd: i32, dev: u64, ino: u64) -> Option<u32> {
    if TMPFS_FILES.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        return None;
    }
    let r = records();
    let rec = r.get(&fd).filter(|rec| (rec.dev, rec.ino) == (dev, ino))?;
    rec.origin.as_ref().filter(|o| o.fstype == FsType::Tmpfs).map(|o| o.mount)
}

/// Whether `fd` is a file in a cgroup filesystem (which a write acts on,
/// see [`crate::cgroupfs`]): its host path, if so.
pub fn cgroup_file(fd: i32) -> Option<Vec<u8>> {
    if CGROUP_FILES.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        return None;
    }
    let o = origin(fd)?;
    if o.fstype != FsType::Cgroup2 {
        return None;
    }
    crate::fs::host_path_of(fd)
}

fn records() -> std::sync::MutexGuard<'static, BTreeMap<i32, Record>> {
    RECORDS.lock().unwrap_or_else(|e| e.into_inner())
}

fn identity(fd: i32) -> Option<(u64, u64)> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino as u64))
}

/// The record of `fd`, if fwe made one and `fd` still names that file.
fn record(fd: i32) -> Option<Record> {
    let r = records().get(&fd).cloned()?;
    if identity(fd) == Some((r.dev, r.ino)) { Some(r) } else { None }
}

/// Record that `fd` was opened at `ns_path` in a mount with `flags` and
/// `fstype`.
pub fn opened(
    fd: i32,
    ns_path: Vec<u8>,
    mount: u32,
    flags: u64,
    fstype: FsType,
    ovl: Option<std::sync::Arc<crate::overlay::Layers>>,
) {
    let Some(id) = identity(fd) else { return };
    opened_as(fd, id, ns_path, mount, flags, fstype, ovl);
}

/// [`opened`], for a descriptor whose file (`dev`, `ino`) the caller has
/// looked at already.
pub fn opened_as(
    fd: i32,
    (dev, ino): (u64, u64),
    ns_path: Vec<u8>,
    mount: u32,
    flags: u64,
    fstype: FsType,
    ovl: Option<std::sync::Arc<crate::overlay::Layers>>,
) {
    let origin = Some(Origin { mount, flags, fstype, ns_path, ovl, stand_in: None });
    let mut r = records();
    let mark = kept(&r, fd, dev, ino).and_then(|rec| rec.mark);
    insert(&mut r, fd, Record { dev, ino, origin, mark });
}

/// The record of `fd` that is of the file `dev`, `ino`, which a new
/// origin or mark of the same descriptor adds to (a device's node is
/// marked as the device and records where it was opened).
fn kept(r: &BTreeMap<i32, Record>, fd: i32, dev: u64, ino: u64) -> Option<Record> {
    r.get(&fd).filter(|rec| (rec.dev, rec.ino) == (dev, ino)).cloned()
}

/// How many stand-in descriptors were made ([`set_stand_in`]), so that a
/// path lookup looks for one only once there are any.
static STAND_INS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `fd` is a stand-in for the file at host path `host` (see
/// [`Origin::stand_in`]), its origin recorded already.
pub fn set_stand_in(fd: i32, host: Vec<u8>) {
    let mut r = records();
    if let Some(o) = r.get_mut(&fd).and_then(|rec| rec.origin.as_mut()) {
        STAND_INS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        o.stand_in = Some(host);
    }
}

/// The host path of the file stand-in descriptor `fd` names, if it is one.
pub fn stand_in(fd: i32) -> Option<Vec<u8>> {
    if STAND_INS.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        return None;
    }
    origin(fd)?.stand_in
}

/// How many marks were ever recorded, so that a call looks for one only
/// once there have been any.
static MARKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether any descriptor was ever marked (so a write need not look).
pub fn any_marks() -> bool {
    MARKS.load(std::sync::atomic::Ordering::SeqCst) > 0
}

/// Whether system call `nr` (arguments `a`) names an `O_PATH` descriptor
/// where Linux needs one open for I/O (it then fails with `EBADF`): reads
/// and writes, requests, mappings, changes through the descriptor, syncs,
/// locks, seeks, listings, extended attributes, socket calls, and every `fcntl` but
/// those that duplicate it or read or set its descriptor flags.
pub fn refuses_path(nr: u64, a: &[u64; 6]) -> bool {
    use fwe_abi::{fcntl, mman, nr as n};
    if !any_marks() {
        return false;
    }
    let path = |fd: u64| is_path(fd as i32);
    match nr {
        n::READ
        | n::READV
        | n::PREAD64
        | n::PREADV
        | n::PREADV2
        | n::WRITE
        | n::WRITEV
        | n::PWRITE64
        | n::PWRITEV
        | n::PWRITEV2
        | n::IOCTL
        | n::FCHMOD
        | n::FCHOWN
        | n::FSYNC
        | n::FDATASYNC
        | n::FTRUNCATE
        | n::FALLOCATE
        | n::FLOCK
        | n::LSEEK
        | n::GETDENTS64
        | n::FADVISE64
        | n::FSETXATTR
        | n::FGETXATTR
        | n::FLISTXATTR
        | n::FREMOVEXATTR
        | n::SYNC_FILE_RANGE
        | n::SYNCFS
        | n::READAHEAD
        | n::VMSPLICE
        | n::ACCEPT
        | n::ACCEPT4
        | n::BIND
        | n::CONNECT
        | n::LISTEN
        | n::GETSOCKNAME
        | n::GETPEERNAME
        | n::SETSOCKOPT
        | n::GETSOCKOPT
        | n::SHUTDOWN
        | n::SENDTO
        | n::RECVFROM
        | n::SENDMSG
        | n::RECVMSG
        | n::SENDMMSG
        | n::RECVMMSG => path(a[0]),
        n::SPLICE | n::COPY_FILE_RANGE => path(a[0]) || path(a[2]),
        n::EPOLL_CTL => path(a[0]) || path(a[2]),
        n::TEE | n::SENDFILE => path(a[0]) || path(a[1]),
        n::MMAP => a[3] & mman::MAP_ANONYMOUS == 0 && path(a[4]),
        n::FCNTL => {
            !matches!(
                a[1],
                fcntl::F_DUPFD
                    | fcntl::F_DUPFD_CLOEXEC
                    | fcntl::F_GETFD
                    | fcntl::F_SETFD
                    | fcntl::F_GETFL
            ) && path(a[0])
        }
        _ => false,
    }
}

/// Record `fd` as a file opened in mount `mount` of a detached tree, with
/// `flags` and `fstype` (a file reopened through the tree's descriptor, as
/// `/proc/self/exe` of a program run through one): an ordinary open file
/// there, not the tree's own descriptor.
pub fn opened_in_tree(fd: i32, mount: u32, flags: u64, fstype: FsType) {
    let Some((dev, ino)) = identity(fd) else { return };
    let origin =
        Some(Origin { mount, flags, fstype, ns_path: Vec::new(), ovl: None, stand_in: None });
    insert(&mut records(), fd, Record { dev, ino, origin, mark: None });
}

/// The namespace paths descriptors were opened at, each made `moved(path)`
/// (the namespace's mounts moved by `pivot_root`).
pub fn rebase(moved: impl Fn(&[u8]) -> Vec<u8>) {
    for rec in records().values_mut() {
        if let Some(o) = rec.origin.as_mut()
            && !o.ns_path.is_empty()
        {
            o.ns_path = moved(&o.ns_path);
        }
    }
}

/// Mark `fd` as standing in for another kind of file.
pub fn mark(fd: i32, mark: Mark) {
    let Some((dev, ino)) = identity(fd) else { return };
    let mut r = records();
    let origin = kept(&r, fd, dev, ino).and_then(|rec| rec.origin);
    insert(&mut r, fd, Record { dev, ino, origin, mark: Some(mark) });
}

/// Where `fd` was opened, if fwe recorded it.
pub fn origin(fd: i32) -> Option<Origin> {
    record(fd)?.origin
}

/// Whether `fd` is an `O_PATH` descriptor (a detached mount's is one).
pub fn is_path(fd: i32) -> bool {
    any_marks() && matches!(marked(fd), Some(Mark::Path | Mark::Detached(_) | Mark::ProcLink))
}

/// The namespace path of the `/proc` link `fd` names, if it is an
/// `O_PATH | O_NOFOLLOW` descriptor of one ([`Mark::ProcLink`]).
pub fn proc_link(fd: i32) -> Option<Vec<u8>> {
    if !any_marks() || marked(fd) != Some(Mark::ProcLink) {
        return None;
    }
    origin(fd).map(|o| o.ns_path)
}

/// What `fd` stands in for, if anything.
pub fn marked(fd: i32) -> Option<Mark> {
    if !any_marks() {
        return None;
    }
    // The mark first: most records have none, and the check that `fd`
    // still names the file asks the host.
    let (mark, dev, ino) = {
        let r = records();
        let rec = r.get(&fd)?;
        (rec.mark?, rec.dev, rec.ino)
    };
    (identity(fd) == Some((dev, ino))).then_some(mark)
}

/// Every marked descriptor, with its mark (whether or not it is still
/// open).
pub fn marks() -> Vec<(i32, Mark)> {
    if !any_marks() {
        return Vec::new();
    }
    records().iter().filter_map(|(&fd, r)| Some((fd, r.mark?))).collect()
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    take(&mut records(), fd);
    crate::overlay::closed(fd);
    crate::fdstate::closed(fd);
}

/// Whether a descriptor of this process other than `fd` is open on the
/// file `fd` is (as a `dup` of it would be).
pub fn shared_elsewhere(fd: i32) -> bool {
    // An inet socket has no identity the host reports (every one is 0:0):
    // a bound one's duplicates carry its mark.
    if let Some(m @ Mark::NetBound { .. }) = marked(fd) {
        let others: Vec<i32> = records()
            .iter()
            .filter(|(o, r)| **o != fd && r.mark == Some(m))
            .map(|(o, _)| *o)
            .collect();
        // SAFETY: F_GETFD only queries the descriptor.
        return others.into_iter().any(|o| unsafe { libc::fcntl(o, libc::F_GETFD) } >= 0);
    }
    let Some(id) = identity(fd) else { return false };
    crate::fdtable::open_fds().into_iter().any(|o| o != fd && identity(o) == Some(id))
}

/// Forget the records of descriptors that are not open, in a new process
/// that took over another's (those closed on exec), so that one never
/// lends its record to a later descriptor at its number.
pub fn forget_closed() {
    let mut r = records();
    // SAFETY: F_GETFD only queries the descriptor.
    let gone: Vec<i32> =
        r.keys().copied().filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0).collect();
    for fd in gone {
        take(&mut r, fd);
    }
}

/// `new` is a duplicate of `old`.
pub fn duplicated(old: i32, new: i32) {
    crate::fdstate::duplicated(old, new);
    let mut r = records();
    match r.get(&old).cloned() {
        Some(rec) => insert(&mut r, new, rec),
        None => take(&mut r, new),
    }
}

/// Every record, for a process fwe re-executes or a VM fork child (one
/// whose descriptor does not survive is never trusted there).
pub fn save(e: &mut Enc) {
    let r = records();
    e.u64(r.len() as u64);
    for (fd, rec) in r.iter() {
        e.i32(*fd);
        e.u64(rec.dev);
        e.u64(rec.ino);
        match &rec.origin {
            Some(o) => {
                e.bool(true);
                e.u32(o.mount);
                e.u64(o.flags);
                e.u32(o.fstype as u32);
                e.bytes(&o.ns_path);
                e.bool(o.ovl.is_some());
                if let Some(l) = &o.ovl {
                    l.encode(e);
                }
                e.bool(o.stand_in.is_some());
                e.bytes(o.stand_in.as_deref().unwrap_or_default());
            }
            None => e.bool(false),
        }
        e.u8(match rec.mark {
            None => 0,
            Some(Mark::SeqPacket) => 1,
            Some(Mark::DevFull) => 2,
            Some(Mark::NetBound { .. }) => 3,
            Some(Mark::ProcMap { .. }) => 4,
            Some(Mark::OomScore { .. }) => 7,
            Some(Mark::Netlink) => 8,
            Some(Mark::Sysctl(_)) => 6,
            Some(Mark::Loop(_)) => 9,
            Some(Mark::LoopControl) => 10,
            Some(Mark::Path) => 11,
            Some(Mark::Mq) => 12,
            Some(Mark::FsContext(_)) => 13,
            Some(Mark::Detached(_)) => 14,
            Some(Mark::Ns(_)) => 15,
            Some(Mark::Inotify(_)) => 16,
            Some(Mark::ProcLink) => 17,
            Some(Mark::TimerSlack { .. }) => 18,
            Some(Mark::Pid { .. }) => 19,
            Some(Mark::Mem) => 20,
            Some(Mark::Pagemap) => 21,
            Some(Mark::RemoteMem { .. }) => 22,
        });
        if let Some(Mark::Pid { host, tid, nonblock }) = rec.mark {
            e.i32(host);
            e.i32(tid);
            e.bool(nonblock);
        }
        if let Some(Mark::TimerSlack { host } | Mark::RemoteMem { id: host }) = rec.mark {
            e.i32(host);
        }
        if let Some(Mark::FsContext(n) | Mark::Detached(n) | Mark::Ns(n) | Mark::Inotify(n)) =
            rec.mark
        {
            e.u32(n);
        }
        if let Some(Mark::Loop(n)) = rec.mark {
            e.u32(n);
        }
        if let Some(Mark::Sysctl(i)) = rec.mark {
            e.u8(i);
        }
        if let Some(Mark::OomScore { host, legacy, privileged }) = rec.mark {
            e.i32(host);
            e.bool(legacy);
            e.bool(privileged);
        }
        if let Some(Mark::ProcMap { host, which, privileged, own }) = rec.mark {
            e.i32(host);
            e.u8(which);
            e.bool(privileged);
            e.u32(own);
        }
        if let Some(Mark::NetBound { port, any, key }) = rec.mark {
            e.u32(u32::from(port));
            e.bool(any);
            e.u8(key);
        }
    }
}

/// What [`save`] wrote, in the new process.
pub fn load(d: &mut Dec) {
    let n = d.count(22);
    let mut r = records();
    for _ in 0..n {
        let fd = d.i32();
        let (dev, ino) = (d.u64(), d.u64());
        let origin = if d.bool() {
            let mount = d.u32();
            let (flags, fstype, ns_path) = (d.u64(), FsType::from_code(d.u32()), d.bytes());
            let ovl = d.bool().then(|| std::sync::Arc::new(crate::overlay::Layers::decode(d)));
            let (some, path) = (d.bool(), d.bytes());
            let stand_in = some.then_some(path);
            if stand_in.is_some() {
                STAND_INS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Some(Origin { mount, flags, fstype, ns_path, ovl, stand_in })
        } else {
            None
        };
        let mark = match d.u8() {
            1 => Some(Mark::SeqPacket),
            2 => Some(Mark::DevFull),
            3 => Some(Mark::NetBound { port: d.u32() as u16, any: d.bool(), key: d.u8() }),
            4 => Some(Mark::ProcMap {
                host: d.i32(),
                which: d.u8(),
                privileged: d.bool(),
                own: d.u32(),
            }),
            6 => Some(Mark::Sysctl(d.u8())),
            7 => Some(Mark::OomScore { host: d.i32(), legacy: d.bool(), privileged: d.bool() }),
            8 => Some(Mark::Netlink),
            9 => Some(Mark::Loop(d.u32())),
            10 => Some(Mark::LoopControl),
            11 => Some(Mark::Path),
            12 => Some(Mark::Mq),
            13 => Some(Mark::FsContext(d.u32())),
            14 => Some(Mark::Detached(d.u32())),
            15 => Some(Mark::Ns(d.u32())),
            16 => Some(Mark::Inotify(d.u32())),
            17 => Some(Mark::ProcLink),
            18 => Some(Mark::TimerSlack { host: d.i32() }),
            19 => Some(Mark::Pid { host: d.i32(), tid: d.i32(), nonblock: d.bool() }),
            20 => Some(Mark::Mem),
            21 => Some(Mark::Pagemap),
            22 => Some(Mark::RemoteMem { id: d.i32() }),
            _ => None,
        };
        insert(&mut r, fd, Record { dev, ino, origin, mark });
    }
}

/// The result of system call `nr` on descriptor `a[0]`, with what the
/// host reports differently for a file that stands in for another kind
/// made as Linux reports it: a write to `/dev/full` fails with `ENOSPC`.
pub fn linux_result(nr: u64, a: &[u64; 6], r: i64) -> i64 {
    use fwe_abi::{err, errno, nr as n};
    let writes = matches!(nr, n::WRITE | n::WRITEV | n::PWRITE64 | n::PWRITEV | n::PWRITEV2);
    if r >= 0
        && writes
        && MARKS.load(std::sync::atomic::Ordering::SeqCst) > 0
        && marked(a[0] as i32) == Some(Mark::DevFull)
    {
        return err(errno::ENOSPC);
    }
    r
}
