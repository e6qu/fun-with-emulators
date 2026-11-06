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
    /// Its process group, as it last set it (what a `wait` for a group
    /// matches it by once it is gone).
    pub pgid: i32,
    /// Whether the host reaps its children as they end (it ignores
    /// `SIGCHLD`, or set `SA_NOCLDWAIT`): no reaper is to take them.
    pub autoreap: bool,
}

/// A host process, as its pid and its start time.
pub type Proc = (i32, u64);

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

fn dir() -> Option<Vec<u8>> {
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-procs", crate::shared::FORMAT).as_bytes());
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(std::ffi::CString::new(d.clone()).ok()?.as_ptr(), 0o700) };
    Some(d)
}

fn path(pid: i32) -> Option<Vec<u8>> {
    Some([dir()?, format!("/{pid}").into_bytes()].concat())
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
    e.i32(r.pgid);
    e.bool(r.autoreap);
    e.into_bytes()
}

/// The record of live host process `pid`.
pub fn read(pid: i32) -> Option<ProcRecord> {
    read_any(pid).filter(|r| start_time(pid) == Some(r.start))
}

/// The record kept for host pid `pid`, whether or not its process lives.
fn read_any(pid: i32) -> Option<ProcRecord> {
    let bytes = std::fs::read(OsStr::from_bytes(&path(pid)?)).ok()?;
    let mut d = Dec::new(&bytes);
    let (start, cgroup) = (d.u64(), d.bytes());
    let n = d.count(8);
    let ns = (0..n).map(|_| d.bytes()).collect();
    let (comm, cmdline, exe) = (d.bytes(), d.bytes(), d.bytes());
    let (lineage, bound, subreaper) = (get_procs(&mut d), get_opt(&mut d), d.bool());
    let (pgid, autoreap) = (d.i32(), d.bool());
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
        pgid,
        autoreap,
    })
}

/// Write the record of host process `pid`.
pub fn write(pid: i32, r: &ProcRecord) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let Some(p) = path(pid) else { return };
    // A name of this writer's own: two processes may write one record.
    let tmp = [&p[..], format!(".{}.{}.tmp", me(), N.fetch_add(1, Ordering::Relaxed)).as_bytes()]
        .concat();
    if std::fs::write(OsStr::from_bytes(&tmp), encode(r)).is_ok() {
        let _ = std::fs::rename(OsStr::from_bytes(&tmp), OsStr::from_bytes(&p));
    }
}

/// Hold host process `pid`'s record's lock while the result lives.
fn lock(pid: i32) -> Option<std::fs::File> {
    let p = [path(pid)?, b".lock".to_vec()].concat();
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(OsStr::from_bytes(&p))
        .ok()?;
    use std::os::fd::AsRawFd;
    // SAFETY: plain host call on the file just opened; the lock goes with it.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    Some(f)
}

/// Forget host process `pid` (it ended).
pub fn remove(pid: i32) {
    if let Some(p) = path(pid) {
        let _ = std::fs::remove_file(OsStr::from_bytes(&p));
        let _ = std::fs::remove_file(OsStr::from_bytes(&[&p[..], b".lock"].concat()));
    }
}

/// Every live process fwe has a record of, forgetting those that ended.
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
        match read(pid) {
            Some(r) => out.push((pid, r)),
            None => gone(pid),
        }
    }
    out
}

/// Host process `pid`, which has a record, has gone: forget its record. It
/// ended without leaving one of how it ended (it was killed by `SIGKILL`,
/// which it cannot see coming), so leave that for it if a reaper might
/// take it.
pub fn gone(pid: i32) {
    let _lock = lock(pid);
    // A zombie has ended: its record goes now, not once it is reaped.
    if let Some(r) = read_any(pid)
        && !alive((pid, r.start))
    {
        // A namespace's init takes its namespace with it.
        crate::pidns::init_gone(&r.ns, pid);
        if crate::reaper::might_adopt(&r.lineage, r.bound) && !parent_autoreaps(&r.lineage) {
            write_ended(&Ended {
                pid,
                start: r.start,
                status: fwe_abi::signal::SIGKILL as i32,
                pgid: r.pgid,
                numbers: numbers_in(&r.ns, pid),
                lineage: r.lineage,
                bound: r.bound,
            });
        }
        remove(pid);
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
fn numbers_in(dirs: &[Vec<u8>], host: i32) -> Vec<(Vec<u8>, i32)> {
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
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() }
}

/// This process's cgroup: its record's, made in the root if it has none.
pub fn own_cgroup() -> Vec<u8> {
    cgroup_of(me())
}

/// Host process `pid`'s cgroup (the root's for one fwe has no record of).
pub fn cgroup_of(pid: i32) -> Vec<u8> {
    read(pid).map_or_else(|| b"/".to_vec(), |r| r.cgroup)
}

/// Change the record of host process `pid` with `f` (making one if it has
/// none).
fn change(pid: i32, f: impl FnOnce(&mut ProcRecord)) -> Result<(), i32> {
    let start = start_time(pid).ok_or(fwe_abi::errno::ESRCH)?;
    // Under the record's lock: a parent and its child may change one.
    let _lock = lock(pid);
    let mut r = read(pid).unwrap_or(ProcRecord {
        start,
        cgroup: b"/".to_vec(),
        ns: Vec::new(),
        comm: Vec::new(),
        cmdline: Vec::new(),
        exe: Vec::new(),
        lineage: Vec::new(),
        bound: None,
        subreaper: false,
        // SAFETY: plain host call.
        pgid: unsafe { libc::getpgid(pid) },
        autoreap: false,
    });
    f(&mut r);
    write(pid, &r);
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

/// This process runs program `exe` with command line `cmdline`.
pub fn own_program(exe: &[u8], cmdline: &[u8]) {
    let base = exe.rsplit(|&b| b == b'/').next().unwrap_or(exe);
    let comm = base[..base.len().min(15)].to_vec();
    let _ = change(me(), |r| {
        r.exe = exe.to_vec();
        r.cmdline = cmdline.to_vec();
        r.comm = comm;
    });
}

/// This process's main thread is named `comm`.
pub fn own_comm(comm: &[u8]) {
    let _ = change(me(), |r| r.comm = comm.to_vec());
}

/// This process is in the namespaces `ns`.
pub fn own_namespaces(ns: Vec<Vec<u8>>) {
    set_namespaces(me(), ns);
}

/// A child `child` of this process starts in this process's cgroup, in the
/// namespaces `ns`, with the line of ancestors and bound of `line`
/// ([`child_line`]).
pub fn forked(child: i32, ns: Vec<Vec<u8>>, line: &(Vec<Proc>, Option<Proc>)) {
    let mine = read(me());
    let (comm, cmdline, exe) = mine.map(|r| (r.comm, r.cmdline, r.exe)).unwrap_or_default();
    let cgroup = own_cgroup();
    // Kept what the child has already written of itself (its program).
    let _ = change(child, |r| {
        r.cgroup = cgroup;
        r.ns = ns;
        if r.exe.is_empty() {
            (r.comm, r.cmdline, r.exe) = (comm, cmdline, exe);
        }
        (r.lineage, r.bound) = line.clone();
        // An ignored SIGCHLD is inherited, and so is the host's reaping.
        r.autoreap = crate::host::children_reaped_by_host();
    });
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

/// This process (just forked) has the line of ancestors and bound `line`.
pub fn own_line(line: &(Vec<Proc>, Option<Proc>)) {
    let _ = change(me(), |r| (r.lineage, r.bound) = line.clone());
}

/// Make this process a child subreaper, or not.
pub fn set_own_subreaper(on: bool) {
    let _ = change(me(), |r| r.subreaper = on);
}

/// Whether this process is a child subreaper.
pub fn own_subreaper() -> bool {
    read(me()).is_some_and(|r| r.subreaper)
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
        (n == size).then(|| {
            (
                info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
                info.pbi_ppid as i32,
                info.pbi_status == 5,
            )
        })
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
        e.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Option<Ended> {
        let mut d = Dec::new(bytes);
        let (pid, start, status, pgid) = (d.i32(), d.u64(), d.i32(), d.i32());
        let (lineage, bound) = (get_procs(&mut d), get_opt(&mut d));
        let n = d.count(12);
        let numbers = (0..n).map(|_| (d.bytes(), d.i32())).collect();
        d.finish().ok()?;
        Some(Ended { pid, start, status, pgid, lineage, bound, numbers })
    }

    /// Its number in the pid namespace whose record is `dir`.
    pub fn number_in(&self, dir: &[u8]) -> Option<i32> {
        self.numbers.iter().find(|(d, _)| d == dir).map(|(_, n)| *n)
    }
}

fn ended_dir() -> Option<Vec<u8>> {
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-ended", crate::shared::FORMAT).as_bytes());
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(std::ffi::CString::new(d.clone()).ok()?.as_ptr(), 0o700) };
    Some(d)
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

/// Child `pid` was reaped by its parent: forget it, and how it ended.
pub fn reaped(pid: i32) {
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

/// This process is ending with Linux wait status `status`: forget its
/// record, and leave one of how it ended if a reaper might take it.
pub fn exiting(status: i32) {
    let me = me();
    crate::pidns::exiting();
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
        };
        if crate::reaper::might_adopt(&ended.lineage, ended.bound)
            && !parent_autoreaps(&ended.lineage)
        {
            write_ended(&ended);
        }
    }
    if crate::host::children_reaped_by_host() {
        forget_children(me);
    }
    remove(me);
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
