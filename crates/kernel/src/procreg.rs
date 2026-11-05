//! fwe's record of each process, which other fwe processes read: its cgroup
//! (what `cgroup.procs` lists and writing to it changes) and the shared
//! records of its namespaces (which keep them from being collected, see
//! [`crate::shared::collect`]). A file per host pid in fwe's private
//! directory, with the process's start time, so the record of a process
//! that has gone is never taken for a new one with its pid.

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
        (n == size).then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rsplit_once(')')?.1;
        after.split_whitespace().nth(19)?.parse().ok()
    }
}

fn encode(r: &ProcRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u64(r.start);
    e.bytes(&r.cgroup);
    e.u64(r.ns.len() as u64);
    for d in &r.ns {
        e.bytes(d);
    }
    e.into_bytes()
}

/// The record of live host process `pid`.
pub fn read(pid: i32) -> Option<ProcRecord> {
    let bytes = std::fs::read(OsStr::from_bytes(&path(pid)?)).ok()?;
    let mut d = Dec::new(&bytes);
    let (start, cgroup) = (d.u64(), d.bytes());
    let n = d.count(8);
    let ns = (0..n).map(|_| d.bytes()).collect();
    let r = ProcRecord { start, cgroup, ns };
    d.finish().ok()?;
    (start_time(pid) == Some(r.start)).then_some(r)
}

/// Write the record of host process `pid`.
pub fn write(pid: i32, r: &ProcRecord) {
    let Some(p) = path(pid) else { return };
    let tmp = [&p[..], b".tmp"].concat();
    if std::fs::write(OsStr::from_bytes(&tmp), encode(r)).is_ok() {
        let _ = std::fs::rename(OsStr::from_bytes(&tmp), OsStr::from_bytes(&p));
    }
}

/// Forget host process `pid` (it ended).
pub fn remove(pid: i32) {
    if let Some(p) = path(pid) {
        let _ = std::fs::remove_file(OsStr::from_bytes(&p));
    }
}

/// Every live process fwe has a record of, forgetting those that ended.
pub fn all() -> Vec<(i32, ProcRecord)> {
    let Some(d) = dir() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(OsStr::from_bytes(&d)) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        match read(pid) {
            Some(r) => out.push((pid, r)),
            None => remove(pid),
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

/// Put host process `pid` in `cgroup`.
pub fn set_cgroup(pid: i32, cgroup: &[u8]) -> Result<(), i32> {
    let start = start_time(pid).ok_or(fwe_abi::errno::ESRCH)?;
    let ns = read(pid).map(|r| r.ns).unwrap_or_default();
    write(pid, &ProcRecord { start, cgroup: cgroup.to_vec(), ns });
    Ok(())
}

/// Record that host process `pid` is in the namespaces whose shared
/// records are `ns`.
pub fn set_namespaces(pid: i32, ns: Vec<Vec<u8>>) {
    let Some(start) = start_time(pid) else { return };
    let cgroup = read(pid).map_or_else(|| b"/".to_vec(), |r| r.cgroup);
    write(pid, &ProcRecord { start, cgroup, ns });
}

/// This process is in the namespaces `ns`.
pub fn own_namespaces(ns: Vec<Vec<u8>>) {
    set_namespaces(me(), ns);
}

/// A child `child` of this process starts in this process's cgroup, in the
/// namespaces `ns`.
pub fn forked(child: i32, ns: Vec<Vec<u8>>) {
    let Some(start) = start_time(child) else { return };
    write(child, &ProcRecord { start, cgroup: own_cgroup(), ns });
}

/// This process is ending.
pub fn exiting() {
    remove(me());
}
