//! What fwe knows about an open descriptor beyond the host's own view of
//! it: where a file was opened ([`Origin`]), and whether a socket stands
//! in for a kind the host lacks ([`Mark`]).
//!
//! On Linux an open file keeps the mount it was reached by: `fstatfs`
//! reports that mount's flags and `/proc/self/fd` its path, even once the
//! mount is detached. A host descriptor knows nothing of fwe's mounts.
//! macOS has no `SOCK_SEQPACKET` Unix sockets either, and fwe makes a pair
//! of them from a datagram pair, which keeps message boundaries. So fwe
//! records both against the descriptor, follows it through `dup` and
//! `close`, `fork` and `exec`, and drops a record whose descriptor no
//! longer names the same file.

use crate::mounts::FsType;
use crate::snapshot::{Dec, Enc};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Where an open file was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The mount's flags and filesystem type.
    pub flags: u64,
    pub fstype: FsType,
    /// The file's path in the mount namespace's view, as it was opened.
    pub ns_path: Vec<u8>,
}

/// A socket standing in for another kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// One end of a `SOCK_SEQPACKET` socketpair, made of a datagram pair.
    SeqPacket,
    /// `/dev/full`, whose writes fail with `ENOSPC`.
    DevFull,
    /// A socket bound in a network namespace of fwe's, to its port `port`
    /// (of the wildcard address if `any`), see [`crate::netns`].
    NetBound { port: u16, any: bool },
    /// `/proc/<pid>/uid_map` (`which` 0), `gid_map` (1) or `setgroups` (2)
    /// of host process `host`, opened for writing by a process that was
    /// `privileged` there, and whose own id in the map's parent namespace
    /// is `own` (Linux checks the opener's credentials).
    ProcMap { host: i32, which: u8, privileged: bool, own: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    /// The file, to tell a record from a reused descriptor number.
    dev: u64,
    ino: u64,
    origin: Option<Origin>,
    mark: Option<Mark>,
}

static RECORDS: Mutex<BTreeMap<i32, Record>> = Mutex::new(BTreeMap::new());

/// How many records are of files in a cgroup filesystem, so that a write
/// checks for one only while there are any ([`cgroup_file`]).
static CGROUP_FILES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn count(rec: Option<&Record>, up: bool) {
    use std::sync::atomic::Ordering::SeqCst;
    if rec.and_then(|r| r.origin.as_ref()).is_some_and(|o| o.fstype == FsType::Cgroup2) {
        if up {
            CGROUP_FILES.fetch_add(1, SeqCst);
        } else {
            CGROUP_FILES.fetch_sub(1, SeqCst);
        }
    }
}

fn insert(r: &mut BTreeMap<i32, Record>, fd: i32, rec: Record) {
    count(Some(&rec), true);
    count(r.insert(fd, rec).as_ref(), false);
}

fn take(r: &mut BTreeMap<i32, Record>, fd: i32) {
    count(r.remove(&fd).as_ref(), false);
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
pub fn opened(fd: i32, ns_path: Vec<u8>, flags: u64, fstype: FsType) {
    let Some((dev, ino)) = identity(fd) else { return };
    let origin = Some(Origin { flags, fstype, ns_path });
    insert(&mut records(), fd, Record { dev, ino, origin, mark: None });
}

/// How many marks there are, so that a write looks for one only while
/// there are any.
static MARKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether any descriptor was ever marked (so a write need not look).
pub fn any_marks() -> bool {
    MARKS.load(std::sync::atomic::Ordering::SeqCst) > 0
}

/// Mark `fd` as standing in for another kind of file.
pub fn mark(fd: i32, mark: Mark) {
    MARKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some((dev, ino)) = identity(fd) else { return };
    insert(&mut records(), fd, Record { dev, ino, origin: None, mark: Some(mark) });
}

/// Where `fd` was opened, if fwe recorded it.
pub fn origin(fd: i32) -> Option<Origin> {
    record(fd)?.origin
}

/// What `fd` stands in for, if anything.
pub fn marked(fd: i32) -> Option<Mark> {
    record(fd)?.mark
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    take(&mut records(), fd);
}

/// Whether a descriptor of this process other than `fd` is open on the
/// file `fd` is (as a `dup` of it would be).
pub fn shared_elsewhere(fd: i32) -> bool {
    let Some(id) = identity(fd) else { return false };
    crate::fdtable::open_fds().into_iter().any(|o| o != fd && identity(o) == Some(id))
}

/// `new` is a duplicate of `old`.
pub fn duplicated(old: i32, new: i32) {
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
                e.u64(o.flags);
                e.u32(o.fstype as u32);
                e.bytes(&o.ns_path);
            }
            None => e.bool(false),
        }
        e.u8(match rec.mark {
            None => 0,
            Some(Mark::SeqPacket) => 1,
            Some(Mark::DevFull) => 2,
            Some(Mark::NetBound { .. }) => 3,
            Some(Mark::ProcMap { .. }) => 4,
        });
        if let Some(Mark::ProcMap { host, which, privileged, own }) = rec.mark {
            e.i32(host);
            e.u8(which);
            e.bool(privileged);
            e.u32(own);
        }
        if let Some(Mark::NetBound { port, any }) = rec.mark {
            e.u32(u32::from(port));
            e.bool(any);
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
            Some(Origin { flags: d.u64(), fstype: FsType::from_code(d.u32()), ns_path: d.bytes() })
        } else {
            None
        };
        let mark = match d.u8() {
            1 => Some(Mark::SeqPacket),
            2 => Some(Mark::DevFull),
            3 => Some(Mark::NetBound { port: d.u32() as u16, any: d.bool() }),
            4 => Some(Mark::ProcMap {
                host: d.i32(),
                which: d.u8(),
                privileged: d.bool(),
                own: d.u32(),
            }),
            _ => None,
        };
        insert(&mut r, fd, Record { dev, ino, origin, mark });
    }
}

/// The result of system call `nr` on descriptor `a[0]`, with what the
/// host reports differently for a socket that stands in for another kind
/// made as Linux reports it: a `SOCK_SEQPACKET` socket whose peer has gone
/// reads end-of-file (`ECONNRESET` on the datagram socket behind it), and
/// a send to it fails with `EPIPE`.
pub fn linux_result(nr: u64, a: &[u64; 6], r: i64) -> i64 {
    use fwe_abi::{err, errno, nr as n};
    if r >= 0 {
        // A write to /dev/full is refused.
        let writes = matches!(nr, n::WRITE | n::WRITEV | n::PWRITE64);
        if writes
            && MARKS.load(std::sync::atomic::Ordering::SeqCst) > 0
            && marked(a[0] as i32) == Some(Mark::DevFull)
        {
            return err(errno::ENOSPC);
        }
        return r;
    }
    let reset = r == err(errno::ECONNRESET);
    let gone = r == err(errno::EDESTADDRREQ) || r == err(errno::ENOTCONN) || reset;
    if !gone {
        return r;
    }
    let receives = matches!(nr, n::READ | n::READV | n::RECVFROM | n::RECVMSG | n::PREAD64);
    let sends = matches!(nr, n::WRITE | n::WRITEV | n::SENDTO | n::SENDMSG | n::PWRITE64);
    if !(receives && reset || sends) || marked(a[0] as i32) != Some(Mark::SeqPacket) {
        return r;
    }
    if receives { 0 } else { err(errno::EPIPE) }
}
