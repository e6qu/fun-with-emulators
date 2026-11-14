//! fwe's record of each process, which other fwe processes read: its cgroup
//! (what `cgroup.procs` lists and writing to it changes), the shared
//! records of its namespaces (which keep them from being collected, see
//! [`crate::shared::collect`]), and its line of ancestors and whether it
//! is a child subreaper (who takes its children if it ends, see
//! [`crate::reaper`]). A file per host pid in fwe's private directory, with
//! the process's start time, so the record of a process that has gone is
//! never taken for a new one with its pid.
//!
//! A process that ends where a reaper might adopt it leaves an [`Ended`]
//! record of how it ended, which its parent's `wait` removes, or else the
//! reaper that adopts it once its parent is gone.

use crate::snapshot::{Dec, Enc};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

/// What fwe records of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcRecord {
    /// When the host process started, in microseconds since the epoch.
    pub start: u64,
    /// Its cgroup, a path from the hierarchy's root.
    pub cgroup: Vec<u8>,
    /// The directories of the shared records of its namespaces.
    pub ns: Vec<Vec<u8>>,
    /// Its name (`comm`), command line (NUL-separated) and program's path,
    /// for `/proc/<pid>`.
    pub comm: Vec<u8>,
    pub cmdline: Vec<u8>,
    pub exe: Vec<u8>,
    /// Its parent, the parent's parent and so on, as (host pid, start
    /// time), up to the first process fwe did not start.
    pub lineage: Vec<Proc>,
    /// The init of its parent's pid namespace, which its adoption stops at
    /// (`None` in the initial namespace).
    pub bound: Option<Proc>,
    /// Whether it is a child subreaper (`PR_SET_CHILD_SUBREAPER`).
    pub subreaper: bool,
    /// The orphans below it that already had their adopter when it became
    /// a subreaper, which it does not take from that adopter.
    pub declined: Vec<Proc>,
    /// The orphans it adopted as a subreaper, which stay its own once it
    /// no longer is one.
    pub kept: Vec<Proc>,
    /// Its process group, as it last set it (what a `wait` for a group
    /// matches it by once it is gone).
    pub pgid: i32,
    /// Whether the host reaps its children as they end (it ignores
    /// `SIGCHLD`, or set `SA_NOCLDWAIT`): no reaper is to take them.
    pub autoreap: bool,
    /// Its `oom_score_adj` (-1000 to 1000), which its children inherit.
    pub oom_score_adj: i32,
    /// The least `oom_score_adj` it may set without `CAP_SYS_RESOURCE`: the
    /// last one a privileged process set it to (inherited too).
    pub oom_score_adj_min: i32,
    /// Its user and group ids, as the kernel holds them (real, effective,
    /// saved and filesystem user ids, then the same of groups): what its
    /// files in `/proc` are owned by.
    pub ids: [u32; 8],
    /// Resource limits another process set for it with `prlimit`
    /// (resource, soft, hard), which it takes up at its next limit call,
    /// `fork` or `execve`.
    pub limits: Vec<(u32, u64, u64)>,
    /// Its nice value (-20 to 19, `setpriority`), which its children
    /// inherit.
    pub nice: i32,
    /// Its scheduling policy and attributes ([`crate::sched`]), which its
    /// children inherit.
    pub sched: Sched,
    /// Its mappings as they were when it was forked, until it publishes
    /// its own (see [`crate::maps::publish`]): what a fork child inherits,
    /// recorded with the record it writes anyway.
    pub maps: Vec<u8>,
    /// Its main thread's timer slack and the default a slack of 0 restores
    /// (`PR_SET_TIMERSLACK`, `/proc/<pid>/timerslack_ns`), in nanoseconds.
    pub slack: (u64, u64),
    /// Whether it has run a program of its own since its fork (Linux's
    /// `PF_FORKNOEXEC` cleared): a parent may no longer move it to another
    /// process group.
    pub execed: bool,
    /// The auxiliary vector its program started with (`/proc/<pid>/auxv`,
    /// where a debugger finds where the program was loaded).
    pub auxv: Vec<u8>,
    /// The namespaces its threads are in apart from its own (records'
    /// directories), which they hold as the process does its own.
    pub held: Vec<Vec<u8>>,
    /// Its parent (the head of its line) is not its parent on the host:
    /// it was made with `CLONE_PARENT`, so its parent waits for it as a
    /// reaper waits for one it adopted ([`crate::reaper`]).
    pub foster: bool,
}

/// A host process, as its pid and its start time.
pub type Proc = (i32, u64);

/// A process's scheduling policy and attributes, as `sched_setattr` sets
/// them (the nice value is the record's own).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sched {
    pub policy: u32,
    /// The real-time priority (1 to 99, for `SCHED_FIFO` and `SCHED_RR`).
    pub priority: u32,
    /// `SCHED_RESET_ON_FORK`.
    pub reset_on_fork: bool,
    /// `SCHED_DEADLINE`'s runtime, deadline and period, in nanoseconds.
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    /// The utilisation clamps (0 to 1024), and whether each was set.
    pub util_min: Option<u32>,
    pub util_max: Option<u32>,
}

impl Sched {
    fn encode(&self, e: &mut Enc) {
        e.u32(self.policy);
        e.u32(self.priority);
        e.bool(self.reset_on_fork);
        e.u64(self.runtime);
        e.u64(self.deadline);
        e.u64(self.period);
        for v in [self.util_min, self.util_max] {
            e.bool(v.is_some());
            e.u32(v.unwrap_or(0));
        }
    }

    fn decode(d: &mut Dec) -> Sched {
        let (policy, priority, reset_on_fork) = (d.u32(), d.u32(), d.bool());
        let (runtime, deadline, period) = (d.u64(), d.u64(), d.u64());
        let mut clamp = || {
            let (set, v) = (d.bool(), d.u32());
            set.then_some(v)
        };
        let (util_min, util_max) = (clamp(), clamp());
        Sched { policy, priority, reset_on_fork, runtime, deadline, period, util_min, util_max }
    }
}

fn put_procs(e: &mut Enc, ps: &[Proc]) {
    e.u64(ps.len() as u64);
    for (p, s) in ps {
        e.i32(*p);
        e.u64(*s);
    }
}

fn get_procs(d: &mut Dec) -> Vec<Proc> {
    let n = d.count(12);
    (0..n).map(|_| (d.i32(), d.u64())).collect()
}

fn put_opt(e: &mut Enc, p: Option<Proc>) {
    put_procs(e, p.as_slice());
}

fn get_opt(d: &mut Dec) -> Option<Proc> {
    get_procs(d).first().copied()
}

/// The directory `name` in fwe's private directory, made the first time
/// this process asks for it.
fn made_dir(cell: &'static std::sync::OnceLock<Vec<u8>>, name: &str) -> Option<Vec<u8>> {
    if let Some(d) = cell.get() {
        return Some(d.clone());
    }
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-{name}", crate::shared::FORMAT).as_bytes());
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(std::ffi::CString::new(d.clone()).ok()?.as_ptr(), 0o700) };
    Some(cell.get_or_init(|| d).clone())
}

fn dir() -> Option<Vec<u8>> {
    static DIR: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    made_dir(&DIR, "procs")
}

/// The directory the process records are kept in.
pub fn records_dir() -> Option<Vec<u8>> {
    dir()
}

fn path(pid: i32) -> Option<Vec<u8>> {
    Some([dir()?, format!("/{pid}").into_bytes()].concat())
}

/// The file host process `pid` publishes its mappings in (see
/// [`crate::maps::publish`]).
pub fn maps_path(pid: i32) -> Option<Vec<u8>> {
    Some([path(pid)?, b".maps".to_vec()].concat())
}

/// Host process `pid`'s parent as the host has it, if it exists.
pub fn host_parent(pid: i32) -> Option<i32> {
    host_info(pid).map(|(_, ppid, _)| ppid)
}

/// When host process `pid` started, if it exists.
pub fn start_time(pid: i32) -> Option<u64> {
    host_info(pid).map(|(start, _, _)| start)
}

fn encode(r: &ProcRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u64(r.start);
    e.bytes(&r.cgroup);
    e.u64(r.ns.len() as u64);
    for d in &r.ns {
        e.bytes(d);
    }
    e.bytes(&r.comm);
    e.bytes(&r.cmdline);
    e.bytes(&r.exe);
    put_procs(&mut e, &r.lineage);
    put_opt(&mut e, r.bound);
    e.bool(r.subreaper);
    put_procs(&mut e, &r.declined);
    put_procs(&mut e, &r.kept);
    e.i32(r.pgid);
    e.bool(r.autoreap);
    e.i32(r.oom_score_adj);
    e.i32(r.oom_score_adj_min);
    for id in r.ids {
        e.u32(id);
    }
    e.u64(r.limits.len() as u64);
    for &(res, soft, hard) in &r.limits {
        e.u32(res);
        e.u64(soft);
        e.u64(hard);
    }
    e.i32(r.nice);
    r.sched.encode(&mut e);
    e.bytes(&r.maps);
    e.u64(r.slack.0);
    e.u64(r.slack.1);
    e.bool(r.execed);
    e.bytes(&r.auxv);
    e.u64(r.held.len() as u64);
    for d in &r.held {
        e.bytes(d);
    }
    e.bool(r.foster);
    e.into_bytes()
}

/// The record of live host process `pid`.
pub fn read(pid: i32) -> Option<ProcRecord> {
    if pid == crate::host::pid() {
        return with_held(pid, read_own(pid));
    }
    with_held(pid, read_any(pid).filter(|r| start_time(pid) == Some(r.start)))
}

/// What a record's file looks like on the host: its identity, when it was
/// last written, and its size.
type FileKey = (u64, u64, i64, i64, i64);

fn file_key(path: &[u8]) -> Option<FileKey> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a valid out-parameter.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)] // field types differ by host
    Some((
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_mtime as i64,
        st.st_mtime_nsec as i64,
        st.st_size as i64,
    ))
}

/// This process's record as last read, by what its file looked like then.
static OWN: std::sync::Mutex<Option<(i32, FileKey, ProcRecord)>> = std::sync::Mutex::new(None);

/// This process's start time, by pid.
static OWN_START: std::sync::Mutex<(i32, u64)> = std::sync::Mutex::new((0, 0));

/// [`read`] of this process's own record (host pid `me`): read again only
/// once its file changed, which a look at the file tells (a thread
/// started reads it, for its creator's timer slack).
fn read_own(me: i32) -> Option<ProcRecord> {
    let p = path(me)?;
    let key = file_key(&p)?;
    {
        let own = OWN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((pid, k, r)) = own.as_ref()
            && (*pid, *k) == (me, key)
        {
            return Some(r.clone());
        }
    }
    let start = {
        let mut s = OWN_START.lock().unwrap_or_else(|e| e.into_inner());
        if s.0 != me {
            *s = (me, start_time(me)?);
        }
        s.1
    };
    let r = read_any(me).filter(|r| r.start == start)?;
    // Kept only if the file did not change while it was read.
    if file_key(&p) == Some(key) {
        *OWN.lock().unwrap_or_else(|e| e.into_inner()) = Some((me, key, r.clone()));
    }
    Some(r)
}

/// The record kept for host pid `pid`, whether or not its process lives.
fn read_any(pid: i32) -> Option<ProcRecord> {
    let p = path(pid)?;
    // A record is rewritten in place ([`write`]): one read while it is
    // being written fails its check, and is made again. An empty file is
    // one not yet written (or whose writer died first): no record.
    for _ in 0..100 {
        let bytes = std::fs::read(OsStr::from_bytes(&p)).ok()?;
        if bytes.is_empty() {
            return None;
        }
        if let Some(body) = unframe(&bytes) {
            return decode(body);
        }
        std::thread::yield_now();
    }
    None
}

/// A record's bytes as written: its length and checksum, then itself.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&checksum(body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The record in `bytes` ([`frame`]), if it is whole.
fn unframe(bytes: &[u8]) -> Option<&[u8]> {
    let len = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?) as usize;
    let sum = u64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?);
    let body = bytes.get(16..16usize.checked_add(len)?)?;
    (checksum(body) == sum).then_some(body)
}

/// A record's checksum over its little-endian words, the last one padded
/// with zeros. Records carry a process's mappings, thousands of them for
/// some, and are read at every reap: a word at a time, and straight from
/// the buffer when it is aligned.
fn checksum(bytes: &[u8]) -> u64 {
    let mix = |h: u64, w: u64| (h ^ w).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    // SAFETY: every bit pattern is a valid u64.
    let (head, words, _) = unsafe { bytes.align_to::<u64>() };
    let rest = if head.is_empty() && cfg!(target_endian = "little") {
        let mut i = 0;
        while i < words.len() {
            h = mix(h, words[i]);
            i += 1;
        }
        &bytes[words.len() * 8..]
    } else {
        bytes
    };
    let mut chunks = rest.chunks(8);
    for c in &mut chunks {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        h = mix(h, u64::from_le_bytes(w));
    }
    h
}

fn decode(bytes: &[u8]) -> Option<ProcRecord> {
    let mut d = Dec::new(bytes);
    let (start, cgroup) = (d.u64(), d.bytes());
    let n = d.count(8);
    let ns = (0..n).map(|_| d.bytes()).collect();
    let (comm, cmdline, exe) = (d.bytes(), d.bytes(), d.bytes());
    let (lineage, bound, subreaper) = (get_procs(&mut d), get_opt(&mut d), d.bool());
    let (declined, kept) = (get_procs(&mut d), get_procs(&mut d));
    let (pgid, autoreap, oom_score_adj, oom_score_adj_min) = (d.i32(), d.bool(), d.i32(), d.i32());
    let mut ids = [0u32; 8];
    for id in &mut ids {
        *id = d.u32();
    }
    let n = d.count(20);
    let limits = (0..n).map(|_| (d.u32(), d.u64(), d.u64())).collect();
    let nice = d.i32();
    let sched = Sched::decode(&mut d);
    let maps = d.bytes();
    let slack = (d.u64(), d.u64());
    let execed = d.bool();
    let auxv = d.bytes();
    let n = d.count(8);
    let held = (0..n).map(|_| d.bytes()).collect();
    let foster = d.bool();
    d.finish().ok()?;
    Some(ProcRecord {
        start,
        cgroup,
        ns,
        comm,
        cmdline,
        exe,
        lineage,
        bound,
        subreaper,
        declined,
        kept,
        pgid,
        autoreap,
        oom_score_adj,
        oom_score_adj_min,
        ids,
        limits,
        nice,
        sched,
        maps,
        slack,
        execed,
        auxv,
        held,
        foster,
    })
}

/// Write the record of host process `pid`, under its lock ([`change`]): in
/// place (a new file costs the host far more than rewriting one), framed
/// with its length and checksum, for readers (who take no lock) to tell a
/// whole record from one being written, and from an older one's longer
/// tail.
/// What this process kept of its own record ([`read_own`]) is read again
/// after a write of host process `pid`'s.
fn forget_own(pid: i32) {
    if let Some(own) = OWN.lock().unwrap_or_else(|e| e.into_inner()).as_mut()
        && own.0 == pid
    {
        own.0 = 0;
    }
}

fn write(pid: i32, r: &ProcRecord) {
    forget_own(pid);
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let Some(p) = path(pid) else { return };
    let bytes = frame(&encode(r));
    let Ok(f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(OsStr::from_bytes(&p))
    else {
        return;
    };
    // An older record's longer tail stays, past the frame.
    let _ = f.write_all_at(&bytes, 0);
}

/// Hold host process `pid`'s record's lock while the result lives: a lock
/// on the record's own file (made, empty, if there is none: an empty file
/// is no record), which the holder reads and writes through
/// ([`read_locked`], [`write_locked`]).
fn lock(pid: i32) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let p = path(pid)?;
    // A file removed while this waited for its lock is no longer the
    // record's: the lock is taken again on the one there now.
    for _ in 0..100 {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(OsStr::from_bytes(&p))
            .ok()?;
        // SAFETY: plain host call on the file just opened; the lock goes with it.
        crate::shared::lock_exclusive(f.as_raw_fd());
        let held = f.metadata().ok().map(|m| (m.dev(), m.ino()));
        let there = std::fs::metadata(OsStr::from_bytes(&p)).ok().map(|m| (m.dev(), m.ino()));
        if held.is_some() && held == there {
            return Some(f);
        }
    }
    None
}

/// The record in `f`, the locked file of host process `pid`'s record (see
/// [`lock`]), if it is of the process that started at `start`.
fn read_locked(f: &std::fs::File, pid: i32, start: u64) -> Option<ProcRecord> {
    use std::io::{Read, Seek};
    let mut bytes = Vec::new();
    let mut f = f;
    f.seek(std::io::SeekFrom::Start(0)).ok()?;
    f.read_to_end(&mut bytes).ok()?;
    let r = (!bytes.is_empty()).then(|| unframe(&bytes).and_then(decode)).flatten();
    with_held(pid, r.filter(|r| r.start == start))
}

/// Write record `r` of host process `pid` into `f`, its locked file.
fn write_locked(f: &std::fs::File, pid: i32, r: &ProcRecord) {
    use std::os::unix::fs::FileExt;
    forget_own(pid);
    // An older record's longer tail stays, past the frame.
    let _ = f.write_all_at(&frame(&encode(r)), 0);
}

fn end_path(pid: i32) -> Option<Vec<u8>> {
    Some([dir()?, format!("/{pid}.end").into_bytes()].concat())
}

/// This process ends of a Linux signal, with Linux wait status `status`
/// (the signal, and `0x80` if it dumped core): what its parent's `wait` is
/// to report, which the host cannot say when the host has no such signal,
/// ignores it by default (`SIGIO`), or wrote no core.
pub fn ending(status: i32) {
    let Some(p) = end_path(crate::host::pid()) else { return };
    let _ = std::fs::write(OsStr::from_bytes(&p), status.to_ne_bytes());
}

/// The Linux wait status host process `pid` left as it ended of a signal.
/// Async-signal-safe (a `SIGCHLD` handler asks): it allocates nothing.
pub fn end_status(pid: i32) -> Option<i32> {
    let mut buf = [0u8; 512];
    let path = crate::signote::record_file(pid, b".end", &mut buf)?;
    let mut b = [0u8; 4];
    let saved = crate::host::last_errno();
    // SAFETY: a NUL-terminated path; a buffer of its length; the
    // descriptor is closed here.
    let n = unsafe {
        let fd = libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC);
        let n = if fd < 0 { -1 } else { libc::read(fd, b.as_mut_ptr().cast(), b.len()) };
        if fd >= 0 {
            libc::close(fd);
        }
        n
    };
    crate::host::set_errno(saved);
    (n == 4).then(|| i32::from_ne_bytes(b))
}

/// Host process `pid` was reaped, or this one starts with that number:
/// its end status goes.
pub fn forget_end(pid: i32) {
    if let Some(p) = end_path(pid) {
        let _ = std::fs::remove_file(OsStr::from_bytes(&p));
    }
}

/// Forget host process `pid` (it ended). Where a new process has the pid
/// already, only the old one's record goes: the files beside it (its
/// mailbox and mappings) are the new one's now, which may have
/// opened them before it wrote its own record.
pub fn remove(pid: i32) {
    let Some(p) = path(pid) else { return };
    let _ = std::fs::remove_file(OsStr::from_bytes(&p));
    if start_time(pid).is_some() {
        return;
    }
    let _ = std::fs::remove_file(OsStr::from_bytes(&[&p[..], b".maps"].concat()));
    crate::signote::remove(pid);
}

/// Remove the files kept beside the records for processes that are gone
/// (their mailbox, lock, mappings, thread ids and how they ended), older
/// than `young`: a process whose record was taken away ([`remove`])
/// without them, as when its pid had been given to another process by
/// then, or whose parent was not fwe's to reap it.
pub fn collect_leftovers(young: std::time::Duration) {
    let Some(d) = dir() else { return };
    let Ok(entries) = std::fs::read_dir(OsStr::from_bytes(&d)) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let pid = match name.split_once('.') {
            Some((p, "sig" | "lock" | "maps" | "end")) => p,
            _ => match name.strip_prefix("tids-").or_else(|| name.strip_prefix("threads-")) {
                Some(p) => p.strip_suffix(".new").unwrap_or(p),
                None => continue,
            },
        };
        let Ok(pid) = pid.parse::<i32>() else { continue };
        if pid <= 0 || start_time(pid).is_some() || read(pid).is_some() {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= young);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Every live process fwe has a record of, forgetting those that ended
/// (zombies too).
pub fn all() -> Vec<(i32, ProcRecord)> {
    let Some(d) = dir() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(OsStr::from_bytes(&d)) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            // A lock or a write in progress; a leftover of a writer that died
            // goes with its process's record.
            continue;
        };
        // A zombie has ended (Linux lists it in no cgroup either): its
        // record goes, and how it ended is kept for whoever reaps it.
        // Read again once before it is taken for gone: another process may
        // have been replacing the record, or the host not yet answered.
        let live = || read(pid).filter(|r| alive((pid, r.start)));
        match live().or_else(live) {
            Some(r) => out.push((pid, r)),
            None => gone(pid),
        }
    }
    out
}

/// The first fwe process of the run that host process `pid` (with record
/// `r`) belongs to: the last of its line of ancestors, or itself if it has
/// none.
fn run_root(pid: i32, r: &ProcRecord) -> Proc {
    r.lineage.last().copied().unwrap_or((pid, r.start))
}

/// The live processes of this process's run of fwe: those started, one
/// from another, from the same first fwe process (which a program run
/// under fwe sees as its whole system, where `kill(-1)` reaches).
pub fn run() -> Vec<i32> {
    let me = me();
    let Some(mine) = read(me) else { return vec![me] };
    let root = run_root(me, &mine);
    all().into_iter().filter(|(pid, r)| run_root(*pid, r) == root).map(|(pid, _)| pid).collect()
}

/// Host process `pid`, which has a record, has gone: forget its record. It
/// ended without leaving one of how it ended (it was killed by `SIGKILL`,
/// which it cannot see coming), so leave that for it if a reaper might
/// take it. A zombie has ended too, but its record stays until it is
/// reaped: `/proc/<pid>` shows it, as Linux shows a zombie.
pub fn gone(pid: i32) {
    let _lock = lock(pid);
    if let Some(r) = read_any(pid)
        && !alive((pid, r.start))
    {
        // A namespace's init takes its namespace with it.
        crate::pidns::init_gone(&r.ns, pid);
        // An account the process left itself stands.
        let told = ended_path(pid, r.start)
            .is_some_and(|p| std::path::Path::new(OsStr::from_bytes(&p)).exists());
        if !told
            && crate::reaper::takes_end((pid, r.start), &r.lineage, r.bound, r.foster)
            && !parent_autoreaps(&r.lineage)
        {
            write_ended(&Ended {
                pid,
                start: r.start,
                status: fwe_abi::signal::SIGKILL as i32,
                pgid: r.pgid,
                numbers: numbers_in(&r.ns, pid),
                lineage: r.lineage,
                bound: r.bound,
                foster: r.foster,
            });
        }
        let zombie = host_info(pid).is_some_and(|(start, _, z)| z && start == r.start);
        if !zombie {
            remove(pid);
        }
    }
}

/// Whether the parent at the head of `lineage` lives and has the host reap
/// its children as they end: then no reaper is to take one of them.
fn parent_autoreaps(lineage: &[Proc]) -> bool {
    lineage.first().is_some_and(|&p| alive(p) && read(p.0).is_some_and(|r| r.autoreap))
}

/// Host process `pid` (this one or a child) has changed process group.
pub fn record_pgid(pid: i32) {
    // SAFETY: plain host call.
    let pgid = unsafe { libc::getpgid(pid) };
    if read(pid).is_some_and(|r| r.pgid != pgid) {
        let _ = change(pid, |r| r.pgid = pgid);
    }
}

/// The host reaps this process's children as they end, or not.
pub fn own_autoreap(on: bool) {
    // Written only when it changes.
    if read(me()).is_some_and(|r| r.autoreap != on) {
        let _ = change(me(), |r| r.autoreap = on);
    }
}

/// Host process `host`'s numbers in the pid namespaces that `dirs` (a
/// process's namespaces' records) name, and those above them.
pub(crate) fn numbers_in(dirs: &[Vec<u8>], host: i32) -> Vec<(Vec<u8>, i32)> {
    let prefix = format!("v{}-pid-", crate::shared::FORMAT);
    let mut out: Vec<(Vec<u8>, i32)> = Vec::new();
    for d in dirs {
        if !d.rsplit(|&b| b == b'/').next().is_some_and(|n| n.starts_with(prefix.as_bytes())) {
            continue;
        }
        let Ok(r) = crate::shared::Record::<crate::pidns::PidNs>::join(d, 0) else { continue };
        for ns in crate::pidns::chain_from(Some(std::sync::Arc::new(r))) {
            if let Some(n) = ns.get().number_of(host)
                && !out.iter().any(|(d, _)| d == ns.dir())
            {
                out.push((ns.dir().to_vec(), n));
            }
        }
    }
    out
}

/// The host pid of this process.
fn me() -> i32 {
    crate::host::pid()
}

/// This process's cgroup: its record's, made in the root if it has none.
pub fn own_cgroup() -> Vec<u8> {
    cgroup_of(me())
}

/// Host process `pid`'s cgroup (the root's for one fwe has no record of).
pub fn cgroup_of(pid: i32) -> Vec<u8> {
    read(pid).map_or_else(|| b"/".to_vec(), |r| r.cgroup)
}

/// The record of a process fwe has none of yet.
fn fresh(pid: i32, start: u64) -> ProcRecord {
    ProcRecord {
        start,
        cgroup: b"/".to_vec(),
        ns: Vec::new(),
        comm: Vec::new(),
        cmdline: Vec::new(),
        exe: Vec::new(),
        lineage: Vec::new(),
        bound: None,
        subreaper: false,
        declined: Vec::new(),
        kept: Vec::new(),
        // SAFETY: plain host call.
        pgid: unsafe { libc::getpgid(pid) },
        autoreap: false,
        oom_score_adj: 0,
        oom_score_adj_min: 0,
        ids: [0; 8],
        limits: Vec::new(),
        nice: 0,
        sched: Sched::default(),
        maps: Vec::new(),
        slack: (crate::thread::DEFAULT_SLACK, crate::thread::DEFAULT_SLACK),
        execed: false,
        auxv: Vec::new(),
        held: Vec::new(),
        foster: false,
    }
}

/// Change the record of host process `pid` with `f` (making one if it has
/// none).
fn change(pid: i32, f: impl FnOnce(&mut ProcRecord)) -> Result<(), i32> {
    let start = start_time(pid).ok_or(fwe_abi::errno::ESRCH)?;
    // Under the record's lock: a parent and its child may change one.
    let Some(file) = lock(pid) else {
        let mut r = read(pid).unwrap_or_else(|| fresh(pid, start));
        f(&mut r);
        write(pid, &r);
        return Ok(());
    };
    let mut r = read_locked(&file, pid, start).unwrap_or_else(|| fresh(pid, start));
    f(&mut r);
    write_locked(&file, pid, &r);
    Ok(())
}

/// Put host process `pid` in `cgroup`.
pub fn set_cgroup(pid: i32, cgroup: &[u8]) -> Result<(), i32> {
    change(pid, |r| r.cgroup = cgroup.to_vec())
}

/// Record that host process `pid` is in the namespaces whose shared
/// records are `ns`.
pub fn set_namespaces(pid: i32, ns: Vec<Vec<u8>>) {
    let _ = change(pid, |r| r.ns = ns);
}

/// A change to this process's record held back by [`batch`].
type Pending = Box<dyn Fn(&mut ProcRecord) + Send>;

/// The changes [`batch`] holds back, with the process they are for.
static BATCH: std::sync::Mutex<Option<(i32, Vec<Pending>)>> = std::sync::Mutex::new(None);

/// Whether a [`batch`] runs: only then is [`BATCH`] looked at, so a
/// process forked while another thread reads a record never inherits it
/// locked.
static BATCHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Run `f`, making the changes it makes to this process's own record
/// ([`own_program`], [`own_auxv`], [`own_namespaces`]) in one write at its
/// end: a program's start makes several. Only while the process has one
/// thread (its start, an `execve`).
pub fn batch<R>(f: impl FnOnce() -> R) -> R {
    use std::sync::atomic::Ordering::SeqCst;
    *BATCH.lock().unwrap_or_else(|e| e.into_inner()) = Some((me(), Vec::new()));
    BATCHING.store(true, SeqCst);
    let out = f();
    BATCHING.store(false, SeqCst);
    let held = BATCH.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some((pid, changes)) = held.filter(|(_, c)| !c.is_empty()) {
        let _ = change(pid, |r| changes.iter().for_each(|c| c(r)));
    }
    out
}

/// Change this process's own record with `f`, or hold the change back
/// for [`batch`].
fn change_own(f: impl Fn(&mut ProcRecord) + Send + 'static) {
    let me = me();
    if BATCHING.load(std::sync::atomic::Ordering::SeqCst) {
        let mut b = BATCH.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((pid, changes)) = b.as_mut()
            && *pid == me
        {
            changes.push(Box::new(f));
            return;
        }
    }
    let _ = change(me, f);
}

/// This process's record with the changes [`batch`] holds back.
fn with_held(pid: i32, r: Option<ProcRecord>) -> Option<ProcRecord> {
    if !BATCHING.load(std::sync::atomic::Ordering::SeqCst) {
        return r;
    }
    let b = BATCH.lock().unwrap_or_else(|e| e.into_inner());
    match b.as_ref() {
        Some((p, changes)) if *p == pid && !changes.is_empty() => {
            let mut r = r.or_else(|| start_time(pid).map(|start| fresh(pid, start)))?;
            changes.iter().for_each(|c| c(&mut r));
            Some(r)
        }
        _ => r,
    }
}

/// This process runs program `exe` with command line `cmdline`.
pub fn own_program(exe: &[u8], cmdline: &[u8]) {
    let base = exe.rsplit(|&b| b == b'/').next().unwrap_or(exe);
    let comm = base[..base.len().min(15)].to_vec();
    let (exe, cmdline) = (exe.to_vec(), cmdline.to_vec());
    change_own(move |r| {
        r.exe = exe.clone();
        r.cmdline = cmdline.clone();
        r.comm = comm.clone();
        r.execed = true;
    });
}

/// This process's program started with auxiliary vector `auxv`.
pub fn own_auxv(auxv: &[u8]) {
    let auxv = auxv.to_vec();
    change_own(move |r| r.auxv = auxv.clone());
}

/// This process's threads are in the namespaces whose records are `held`
/// besides its own.
pub fn own_held(held: Vec<Vec<u8>>) {
    let _ = change(me(), |r| r.held = held);
}

/// This process's main thread is named `comm`.
pub fn own_comm(comm: &[u8]) {
    let _ = change(me(), |r| r.comm = comm.to_vec());
}

/// This process is in the namespaces `ns`.
pub fn own_namespaces(ns: Vec<Vec<u8>>) {
    change_own(move |r| r.ns = ns.clone());
}

/// What a fork child takes of this process's record, as it is when it
/// forks: its ids, OOM adjustments, nice value and scheduling.
#[derive(Clone, Debug, Default)]
pub struct Inherit {
    ids: [u32; 8],
    oom: (i32, i32),
    nice: i32,
    sched: Sched,
    /// The forking thread's timer slack: the child's, and its default.
    slack: u64,
    /// The child is made with `CLONE_PARENT` ([`ProcRecord::foster`]).
    pub foster: bool,
}

/// What a child forked now inherits ([`Inherit`]): a child of a process
/// that asked to reset on fork starts as an ordinary one, its nice value no
/// less than 0, as on Linux.
pub fn inherit() -> Inherit {
    let Some(r) = read(me()) else { return Inherit::default() };
    let (sched, nice) = match r.sched {
        s if s.reset_on_fork => {
            use fwe_abi::sched::*;
            let realtime = matches!(s.policy, SCHED_FIFO | SCHED_RR | SCHED_DEADLINE);
            let sched = if realtime {
                Sched::default()
            } else {
                Sched { reset_on_fork: false, util_min: None, util_max: None, ..s }
            };
            (sched, if realtime { 0 } else { r.nice.max(0) })
        }
        s => (s, r.nice),
    };
    let slack = crate::thread::slack();
    Inherit {
        ids: r.ids,
        oom: (r.oom_score_adj, r.oom_score_adj_min),
        nice,
        sched,
        slack,
        foster: false,
    }
}

/// Write `i` for a child that starts on state handed to it.
pub fn save_inherit(e: &mut Enc, i: &Inherit) {
    for id in i.ids {
        e.u32(id);
    }
    e.i32(i.oom.0);
    e.i32(i.oom.1);
    e.i32(i.nice);
    i.sched.encode(e);
    e.u64(i.slack);
    e.bool(i.foster);
}

/// What [`save_inherit`] wrote.
pub fn load_inherit(d: &mut Dec) -> Inherit {
    let mut ids = [0u32; 8];
    for id in &mut ids {
        *id = d.u32();
    }
    let oom = (d.i32(), d.i32());
    let nice = d.i32();
    let sched = Sched::decode(d);
    let slack = d.u64();
    let foster = d.bool();
    Inherit { ids, oom, nice, sched, slack, foster }
}

/// Set `r`'s inherited part.
fn apply(r: &mut ProcRecord, i: &Inherit) {
    r.ids = i.ids;
    (r.oom_score_adj, r.oom_score_adj_min) = i.oom;
    r.nice = i.nice;
    r.sched = i.sched;
    // `SCHED_RESET_ON_FORK`: the child starts as an ordinary process (a
    // real-time or deadline policy, and a raised priority, not passed on).
    if r.sched.reset_on_fork {
        r.sched = Sched::default();
        r.nice = r.nice.max(0);
    }
    if i.slack != 0 {
        r.slack = (i.slack, i.slack);
    }
    r.foster = i.foster;
}

/// A child `child` of this process starts in this process's cgroup (or in
/// `cgroup`, from `CLONE_INTO_CGROUP`), in the
/// namespaces `ns`, with the line of ancestors and bound of `line`
/// ([`child_line`]), what it inherits (`inherit`, unless the child has
/// written it already, see [`own_line`]) and this process's mappings `maps`
/// (see [`crate::maps::forked`]).
pub fn forked(
    child: i32,
    ns: Vec<Vec<u8>>,
    line: &(Vec<Proc>, Option<Proc>),
    inherit: &Inherit,
    maps: Vec<u8>,
    cgroup: Option<&[u8]>,
) {
    let mine = read(me());
    let (comm, cmdline, exe) = mine.map(|r| (r.comm, r.cmdline, r.exe)).unwrap_or_default();
    let cgroup = cgroup.map_or_else(own_cgroup, <[u8]>::to_vec);
    // Kept what the child has already written of itself (its program,
    // and its namespaces and cgroup, which it may have changed since).
    let _ = change(child, |r| {
        let child_wrote = !r.lineage.is_empty();
        if !child_wrote || r.cgroup.is_empty() {
            r.cgroup = cgroup;
        }
        if !child_wrote {
            r.ns = ns;
        }
        if r.exe.is_empty() {
            (r.comm, r.cmdline, r.exe) = (comm, cmdline, exe);
        }
        // What the child wrote of itself already stands: it may have
        // changed it since.
        if r.lineage.is_empty() {
            apply(r, inherit);
        }
        (r.lineage, r.bound) = line.clone();
        // An ignored SIGCHLD is inherited, and so is the host's reaping.
        r.autoreap = crate::host::children_reaped_by_host();
        // Whichever of the two writes first, the child's mappings are there
        // from the start; the child's own stand.
        if r.maps.is_empty() {
            r.maps = maps;
        }
    });
}

/// Host process `pid`'s nice value: as `setpriority` set it, or for a
/// process fwe has no record of, the host's.
pub fn nice(pid: i32) -> i32 {
    read(pid).map_or_else(
        || {
            // SAFETY: plain host call; -1 is a valid value, so errno is
            // not consulted (an absent process reads as 0).
            let v = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
            v.clamp(-20, 19)
        },
        |r| r.nice,
    )
}

/// Host process `pid`'s scheduling attributes, if fwe has its record.
pub fn sched(pid: i32) -> Option<Sched> {
    read(pid).map(|r| r.sched)
}

/// Change host process `pid`'s scheduling attributes and nice value with
/// `f`, under its record's lock (`f`'s error is the result, the record
/// unchanged).
pub fn change_sched(
    pid: i32,
    f: impl FnOnce(&Sched, i32) -> Result<(Sched, i32), i32>,
) -> Result<(), i32> {
    let mut out = Ok(());
    change(pid, |r| match f(&r.sched, r.nice) {
        Ok((s, nice)) => (r.sched, r.nice) = (s, nice),
        Err(e) => out = Err(e),
    })?;
    out
}

/// Host process `pid`'s nice value is now `nice`.
pub fn set_nice(pid: i32, nice: i32) -> Result<(), i32> {
    change(pid, |r| r.nice = nice)
}

/// Host process `pid`'s `oom_score_adj` (0 for one fwe has no record of).
pub fn oom_score_adj(pid: i32) -> i32 {
    read(pid).map_or(0, |r| r.oom_score_adj)
}

/// Leave resource limit `res` (soft, hard) for host process `pid` to take
/// up ([`take_limits`]).
pub fn push_limit(pid: i32, res: u32, soft: u64, hard: u64) -> Result<(), i32> {
    change(pid, |r| {
        r.limits.retain(|l| l.0 != res);
        r.limits.push((res, soft, hard));
    })
}

/// The limits another process left for this one, taken.
pub fn take_limits() -> Vec<(u32, u64, u64)> {
    let me = me();
    if read(me).is_none_or(|r| r.limits.is_empty()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let _ = change(me, |r| out = std::mem::take(&mut r.limits));
    out
}

/// The limit `res` left for host process `pid`, if any.
pub fn pending_limit(pid: i32, res: u32) -> Option<(u64, u64)> {
    read(pid)?.limits.iter().find(|l| l.0 == res).map(|l| (l.1, l.2))
}

/// Host process `pid`'s ids ([`ProcRecord::ids`]; root's for one fwe has
/// no record of).
pub fn ids(pid: i32) -> [u32; 8] {
    read(pid).map_or([0; 8], |r| r.ids)
}

/// This process's ids are now `ids` ([`ProcRecord::ids`]).
pub fn set_own_ids(ids: [u32; 8]) {
    let _ = change(me(), |r| r.ids = ids);
}

/// Host process `pid`'s main thread's timer slack and its default.
pub fn slack(pid: i32) -> (u64, u64) {
    read(pid).map_or((crate::thread::DEFAULT_SLACK, crate::thread::DEFAULT_SLACK), |r| r.slack)
}

/// Set host process `pid`'s main thread's timer slack to `value` (0: its
/// default).
pub fn set_slack(pid: i32, value: u64) -> Result<(), i32> {
    change(pid, |r| r.slack.0 = if value == 0 { r.slack.1 } else { value })
}

/// Host process `pid`'s `oom_score_adj` and the least it may set without
/// `CAP_SYS_RESOURCE`.
pub fn oom_score_adj_range(pid: i32) -> (i32, i32) {
    read(pid).map_or((0, 0), |r| (r.oom_score_adj, r.oom_score_adj_min))
}

/// Set host process `pid`'s `oom_score_adj`, and, set by a privileged
/// process (`floor`), the least it may set without privilege.
pub fn set_oom_score_adj(pid: i32, value: i32, floor: bool) -> Result<(), i32> {
    change(pid, |r| {
        r.oom_score_adj = value;
        if floor {
            r.oom_score_adj_min = value;
        }
    })
}

/// The line of ancestors a child of this process has (this process, then
/// its own), and the init of this process's pid namespace (the bound of
/// the child's adoption), which `fork` hands the child.
pub fn child_line() -> (Vec<Proc>, Option<Proc>) {
    let me = me();
    let mut line = Vec::new();
    if let Some(start) = start_time(me) {
        line.push((me, start));
    }
    line.extend(read(me).map(|r| r.lineage).unwrap_or_default());
    let bound = crate::pidns::current()
        .first()
        .and_then(|r| r.get().host_of(1))
        .and_then(|h| Some((h, start_time(h)?)));
    (line, bound)
}

/// A line of ancestors and bound, in a fork's snapshot.
pub fn save_line(e: &mut Enc, line: &(Vec<Proc>, Option<Proc>)) {
    put_procs(e, &line.0);
    put_opt(e, line.1);
}

/// What [`save_line`] saved.
pub fn load_line(d: &mut Dec) -> (Vec<Proc>, Option<Proc>) {
    (get_procs(d), get_opt(d))
}

/// This process (just forked) has the line of ancestors and bound `line`,
/// what it inherited of its parent's record (`inherit`), the namespaces
/// `ns` it starts in, the auxiliary vector `auxv` of the program it runs,
/// and the mappings `maps` it inherited (see
/// [`crate::maps::forked`]): written by the child first, so it reads its
/// own from the start, and the parent's later write ([`forked`]) keeps
/// what it changed since (a namespace it unshared, say).
pub fn own_line(
    line: &(Vec<Proc>, Option<Proc>),
    inherit: &Inherit,
    ns: Vec<Vec<u8>>,
    maps: Vec<u8>,
    auxv: &[u8],
) {
    let _ = change(me(), |r| {
        if r.lineage.is_empty() {
            apply(r, inherit);
            r.ns = ns;
        }
        (r.lineage, r.bound) = line.clone();
        r.maps = maps;
        // The program its parent runs, which it runs too until it execs.
        r.auxv = auxv.to_vec();
    });
}

/// Make this process a child subreaper, or not, with the orphans below it
/// it is not to adopt (`declined`) and those it keeps (`kept`), see
/// [`crate::reaper::set_subreaper`].
pub fn set_own_subreaper(on: bool, declined: Vec<Proc>, kept: Vec<Proc>) {
    let _ = change(me(), |r| (r.subreaper, r.declined, r.kept) = (on, declined, kept));
}

/// Whether this process is a child subreaper.
pub fn own_subreaper() -> bool {
    read(me()).is_some_and(|r| r.subreaper)
}

/// Whether host process `pid` is stopped, and by which signal (the
/// host's): `None` if it runs or is gone.
pub fn stopped_by(pid: i32) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are a valid `proc_bsdinfo`, which the call fills.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: a valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if n != size || info.pbi_status != libc::SSTOP {
            return None;
        }
        // The signal is `p_xstat` of the process's `kinfo_proc`, which the
        // libc crate does not describe: a `u16` 280 bytes into its 648.
        const SIZE: usize = 648;
        const XSTAT: usize = 280;
        let mut buf = [0u8; SIZE];
        let mut len = SIZE;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        // SAFETY: a valid name and out-buffer of `len` bytes.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 || len != SIZE {
            return Some(libc::SIGSTOP);
        }
        Some(i32::from(u16::from_ne_bytes([buf[XSTAT], buf[XSTAT + 1]])))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// What the host keeps of any process in its `kinfo_proc`, which it
/// gives for a zombie, and for another user's process, where
/// `proc_pidinfo` answers nothing.
pub struct Kinfo {
    /// Its start, in microseconds since the epoch.
    pub start: u64,
    pub ppid: i32,
    pub pgid: i32,
    /// The host's state (`SIDL` 1, `SRUN` 2, `SSLEEP` 3, `SSTOP` 4,
    /// `SZOMB` 5).
    pub state: u8,
    pub comm: Vec<u8>,
}

/// Host process `pid`'s `kinfo_proc`, which the libc crate does not
/// describe (648 bytes: the start time at 0, the state at 36, the command
/// name at 243, the parent and process group at 560 and 564).
#[cfg(target_os = "macos")]
pub fn kinfo(pid: i32) -> Option<Kinfo> {
    const SIZE: usize = 648;
    let mut buf = [0u8; SIZE];
    let mut len = SIZE;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // SAFETY: a valid name and out-buffer of `len` bytes.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    // A pid with no process gives an empty answer.
    if r != 0 || len != SIZE {
        return None;
    }
    let i64_at = |at: usize| i64::from_ne_bytes(buf[at..at + 8].try_into().unwrap());
    let i32_at = |at: usize| i32::from_ne_bytes(buf[at..at + 4].try_into().unwrap());
    let comm = &buf[243..243 + 17];
    Some(Kinfo {
        start: (i64_at(0).max(0) as u64) * 1_000_000 + i32_at(8).max(0) as u64,
        ppid: i32_at(560),
        pgid: i32_at(564),
        state: buf[36],
        comm: comm[..comm.iter().position(|&b| b == 0).unwrap_or(comm.len())].to_vec(),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn kinfo(_: i32) -> Option<Kinfo> {
    None
}

/// Host process `pid`'s `kinfo_proc`, if it is a zombie.
pub fn zombie_info(pid: i32) -> Option<Kinfo> {
    kinfo(pid).filter(|k| k.state == 5)
}

/// Whether host process `p` is alive (not ended, nor a zombie) and the one
/// that started then.
pub fn alive(p: Proc) -> bool {
    host_info(p.0).is_some_and(|(start, _, zombie)| start == p.1 && !zombie)
}

/// Host process `pid`'s start time, parent and whether it is a zombie.
pub fn host_info(pid: i32) -> Option<(u64, i32, bool)> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are a valid `proc_bsdinfo`, which the call fills.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: a valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        // SZOMB is 5.
        if n == size {
            return Some((
                info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
                info.pbi_ppid as i32,
                info.pbi_status == 5,
            ));
        }
        // The host tells nothing that way of a zombie, nor of a process
        // still ending (its descriptors not yet closed, so not gone): its
        // `kinfo_proc`.
        kinfo(pid).map(|k| (k.start, k.ppid, k.state == 5))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rsplit_once(')')?.1;
        let f: Vec<&str> = after.split_whitespace().collect();
        Some((f.get(19)?.parse().ok()?, f.get(1)?.parse().ok()?, f.first() == Some(&"Z")))
    }
}

/// How a process ended, kept until whoever reaps it takes it: its parent
/// or, once that has gone too, the reaper that adopts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    pub pid: i32,
    pub start: u64,
    /// Its wait status, in Linux's layout.
    pub status: i32,
    /// Its process group then.
    pub pgid: i32,
    pub lineage: Vec<Proc>,
    pub bound: Option<Proc>,
    /// Its pid namespaces' records, and its number in each.
    pub numbers: Vec<(Vec<u8>, i32)>,
    /// It was a foster child ([`ProcRecord::foster`]).
    pub foster: bool,
}

impl Ended {
    fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.i32(self.pid);
        e.u64(self.start);
        e.i32(self.status);
        e.i32(self.pgid);
        put_procs(&mut e, &self.lineage);
        put_opt(&mut e, self.bound);
        e.u64(self.numbers.len() as u64);
        for (d, n) in &self.numbers {
            e.bytes(d);
            e.i32(*n);
        }
        e.bool(self.foster);
        e.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Option<Ended> {
        let mut d = Dec::new(bytes);
        let (pid, start, status, pgid) = (d.i32(), d.u64(), d.i32(), d.i32());
        let (lineage, bound) = (get_procs(&mut d), get_opt(&mut d));
        let n = d.count(12);
        let numbers = (0..n).map(|_| (d.bytes(), d.i32())).collect();
        let foster = d.bool();
        d.finish().ok()?;
        Some(Ended { pid, start, status, pgid, lineage, bound, numbers, foster })
    }

    /// Its number in the pid namespace whose record is `dir`.
    pub fn number_in(&self, dir: &[u8]) -> Option<i32> {
        self.numbers.iter().find(|(d, _)| d == dir).map(|(_, n)| *n)
    }
}

fn ended_dir() -> Option<Vec<u8>> {
    static DIR: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    made_dir(&DIR, "ended")
}

fn ended_path(pid: i32, start: u64) -> Option<Vec<u8>> {
    Some([ended_dir()?, format!("/{pid}.{start}").into_bytes()].concat())
}

/// Record how a process ended.
pub fn write_ended(e: &Ended) {
    let Some(p) = ended_path(e.pid, e.start) else { return };
    let tmp = [&p[..], format!(".{}.tmp", me()).as_bytes()].concat();
    if std::fs::write(OsStr::from_bytes(&tmp), e.encode()).is_ok() {
        let _ = std::fs::rename(OsStr::from_bytes(&tmp), OsStr::from_bytes(&p));
    }
}

/// Every record of a process that ended and is not yet reaped.
pub fn all_ended() -> Vec<Ended> {
    let Some(d) = ended_dir() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(OsStr::from_bytes(&d)) else { return Vec::new() };
    entries
        .flatten()
        .filter(|e| !e.file_name().as_bytes().ends_with(b".tmp"))
        .filter_map(|e| Ended::decode(&std::fs::read(e.path()).ok()?))
        .collect()
}

/// Take the record of how `e` ended: whoever removes it reaps the process.
pub fn take_ended(e: &Ended) -> bool {
    ended_path(e.pid, e.start).is_some_and(|p| std::fs::remove_file(OsStr::from_bytes(&p)).is_ok())
}

/// Reap ended process `e`, adopted: take the account of how it ended, and
/// its record with it, under the record's lock, so that no one finding it
/// gone ([`gone`]) takes it for one killed outright and records a second
/// end. Whoever takes the account reaps the process.
pub fn take_adopted_end(e: &Ended) -> bool {
    let _lock = lock(e.pid);
    if !take_ended(e) {
        return false;
    }
    if read_any(e.pid).is_some_and(|r| r.start == e.start) && !alive((e.pid, e.start)) {
        remove(e.pid);
    }
    true
}

/// Child `pid` was reaped by its parent: forget it, and how it ended.
pub fn reaped(pid: i32) {
    forget_end(pid);
    crate::reaper::forget_exit_signal(pid);
    if read(pid).is_none() {
        let _lock = lock(pid);
        if let Some(r) = read_any(pid)
            && r.lineage.first().is_some_and(|&(p, _)| p == me())
        {
            // An init killed outright: its namespace goes with it.
            crate::pidns::init_gone(&r.ns, pid);
            remove(pid);
        }
    }
    for e in all_ended().into_iter().filter(|e| e.pid == pid) {
        // Only the one the parent reaped: an older process with its pid
        // had another parent, now gone.
        if e.lineage.first().is_some_and(|&(p, _)| p == me()) {
            take_ended(&e);
        }
    }
}

/// This process is ending with Linux wait status `status`: leave a record
/// of how it ended if a reaper might take it.
pub fn exiting(status: i32) {
    // The robust futexes its threads hold.
    crate::release_robust_lists();
    // Its files closed, as it ends (inotify's close events), and its
    // instances gone.
    crate::inotify::exiting();
    // The program it runs no longer; no tracer waits on it.
    crate::textbusy::exiting();
    crate::ptrace::exiting(status);
    crate::thread::process_ending();
    // Its System V IPC attachments and undo adjustments, as it ends.
    crate::sysvipc::process_leaving(false);
    // The files it keeps open and writes, closed before it ends.
    crate::maps::close_for_exit();
    crate::thread::close_tids_for_exit();
    let me = me();
    // Ending of a Linux signal: its status as recorded ([`ending`]).
    let status = end_status(me).unwrap_or(status);
    // Its accounting record, if accounting is on.
    crate::acct::process_ending(status);
    crate::pidns::exiting();
    if crate::host::children_reaped_by_host() {
        forget_children(me);
    }
    // Under the record's lock: whoever finds the process gone (`gone`)
    // checks its record and records how it ended under the same lock, so
    // it sees the record with this account written, or no record at all.
    let _lock = lock(me);
    if let Some(r) = read(me) {
        let ended = Ended {
            pid: me,
            start: r.start,
            status,
            // SAFETY: plain host call.
            pgid: unsafe { libc::getpgrp() },
            numbers: crate::pidns::current()
                .iter()
                .filter_map(|ns| Some((ns.dir().to_vec(), ns.get().number_of(me)?)))
                .collect(),
            lineage: r.lineage,
            bound: r.bound,
            foster: r.foster,
        };
        if crate::reaper::takes_end(
            (ended.pid, ended.start),
            &ended.lineage,
            ended.bound,
            ended.foster,
        ) && !parent_autoreaps(&ended.lineage)
        {
            write_ended(&ended);
        }
    }
    // The record stays while the process is a zombie, for `/proc/<pid>`:
    // whoever reaps it, or finds it gone from the host, removes it
    // ([`reaped`], [`gone`]).
}

/// The host reaped the children of `parent` as they ended (it ignores
/// `SIGCHLD`, or set `SA_NOCLDWAIT`): forget those that ended, which no
/// reaper is to take.
fn forget_children(parent: i32) {
    for e in all_ended().into_iter().filter(|e| e.lineage.first().is_some_and(|p| p.0 == parent)) {
        take_ended(&e);
    }
    let Some(d) = dir() else { return };
    let Ok(entries) = std::fs::read_dir(OsStr::from_bytes(&d)) else { return };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        let _lock = lock(pid);
        if let Some(r) = read_any(pid)
            && r.lineage.first().is_some_and(|p| p.0 == parent)
            && start_time(pid) != Some(r.start)
        {
            remove(pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_caught_mid_write_is_not_taken_for_whole() {
        let r = fresh(me(), 1);
        let body = encode(&r);
        let whole = frame(&body);
        assert_eq!(decode(unframe(&whole).unwrap()), Some(r));
        // The longer tail of the record written before, not yet cut off.
        let mut longer = whole.clone();
        longer.extend_from_slice(&[7; 40]);
        assert_eq!(unframe(&longer), Some(&body[..]));
        // Cut short, empty, or a byte of another write.
        assert_eq!(unframe(&whole[..whole.len() - 1]), None);
        assert_eq!(unframe(&[]), None);
        let mut mixed = whole.clone();
        let last = mixed.len() - 1;
        mixed[last] ^= 1;
        assert_eq!(unframe(&mixed), None);
    }

    #[test]
    fn a_checksum_is_the_same_wherever_the_bytes_lie() {
        let bytes: Vec<u8> = (0..100u8).collect();
        let mut buf = [0u8; 120];
        for at in 0..8 {
            for len in [0, 1, 7, 8, 9, 64, 99] {
                buf[at..at + len].copy_from_slice(&bytes[..len]);
                assert_eq!(
                    checksum(&buf[at..at + len]),
                    checksum(&bytes[..len]),
                    "at {at}, {len} bytes"
                );
            }
        }
        // Any one byte changed changes it.
        for i in 0..bytes.len() {
            let mut other = bytes.clone();
            other[i] ^= 0x40;
            assert_ne!(checksum(&other), checksum(&bytes), "byte {i}");
        }
    }

    #[test]
    fn a_batch_writes_once_and_its_changes_are_read_meanwhile() {
        let exe = format!("/batch-test-{}", std::process::id()).into_bytes();
        batch(|| {
            own_program(&exe, b"batch\0");
            own_auxv(&[1, 2, 3]);
            // Held back, but this process reads them.
            let held = read(me()).unwrap();
            assert_eq!((held.exe.as_slice(), held.auxv.as_slice()), (&exe[..], &[1, 2, 3][..]));
            assert!(read_any(me()).is_none_or(|r| r.exe != exe), "written before the batch ends");
        });
        let r = read_any(me()).unwrap();
        // Its name is the program's, cut to 15 bytes as Linux's is.
        assert_eq!((r.exe, r.auxv, r.comm), (exe.clone(), vec![1, 2, 3], exe[1..16].to_vec()));
        remove(me());
    }
}
