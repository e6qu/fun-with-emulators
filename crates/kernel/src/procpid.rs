//! `/proc/<pid>`: what a process can see of the processes of its pid
//! namespace, from fwe's record of each ([`crate::procreg`]) and what the
//! host reports of its process (state, parent, times, memory).

use crate::procfs::{DT_DIR, DT_LNK, DT_REG, Entry};

/// What the host reports of a process.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostInfo {
    pub state: u8,
    pub ppid: i32,
    pub pgid: i32,
    pub sid: i32,
    pub nice: i32,
    pub threads: u64,
    pub rss_bytes: u64,
    pub vsize: u64,
    /// In clock ticks (100 a second, Linux's `USER_HZ`).
    pub utime: u64,
    pub stime: u64,
    pub start: u64,
}

#[cfg(target_os = "macos")]
const HZ: u64 = 100;

/// What the host reports of host process `pid`.
pub fn host_info(pid: i32) -> Option<HostInfo> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are valid for both structures, which the
        // calls fill.
        let mut b: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let bsize = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: a valid out-buffer of `bsize` bytes.
        if unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut b as *mut libc::proc_bsdinfo).cast(),
                bsize,
            )
        } != bsize
        {
            return None;
        }
        // SAFETY: as above.
        let mut t: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let tsize = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        // SAFETY: a valid out-buffer of `tsize` bytes.
        let have_task = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                (&mut t as *mut libc::proc_taskinfo).cast(),
                tsize,
            )
        } == tsize;
        let state = match b.pbi_status {
            2 => b'R', // SRUN
            4 => b'T', // SSTOP
            5 => b'Z', // SZOMB
            _ => b'S', // SIDL, SSLEEP
        };
        let ns_to_ticks = |ns: u64| ns * HZ / 1_000_000_000;
        let boot = crate::host::uptime();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let started = b.pbi_start_tvsec as f64 + b.pbi_start_tvusec as f64 / 1e6;
        let since_boot = (started - (now - boot)).max(0.0);
        // SAFETY: plain host call.
        let sid = unsafe { libc::getsid(pid) };
        Some(HostInfo {
            state,
            // The guest's parent: an orphan's is the reaper that adopted it.
            ppid: crate::reaper::parent_of(pid, b.pbi_ppid as i32),
            pgid: b.pbi_pgid as i32,
            sid,
            nice: b.pbi_nice,
            threads: if have_task { t.pti_threadnum as u64 } else { 1 },
            rss_bytes: if have_task { t.pti_resident_size } else { 0 },
            vsize: if have_task { t.pti_virtual_size } else { 0 },
            utime: if have_task { ns_to_ticks(mach_to_ns(t.pti_total_user)) } else { 0 },
            stime: if have_task { ns_to_ticks(mach_to_ns(t.pti_total_system)) } else { 0 },
            start: (since_boot * HZ as f64) as u64,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Mach absolute time units (what the host reports CPU times in) in
/// nanoseconds.
#[cfg(target_os = "macos")]
pub fn mach_to_ns(t: u64) -> u64 {
    use std::sync::OnceLock;
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    static BASE: OnceLock<(u32, u32)> = OnceLock::new();
    let (numer, denom) = *BASE.get_or_init(|| {
        let mut info = Timebase { numer: 1, denom: 1 };
        // SAFETY: a valid out-parameter.
        unsafe { mach_timebase_info(&mut info) };
        (info.numer, info.denom.max(1))
    });
    (t as u128 * numer as u128 / denom as u128) as u64
}

/// The files of a `/proc/<pid>` directory.
pub const FILES: &[(&[u8], u8)] = &[
    (b"stat", DT_REG),
    (b"status", DT_REG),
    (b"cmdline", DT_REG),
    (b"comm", DT_REG),
    (b"exe", DT_LNK),
    (b"cgroup", DT_REG),
    (b"ns", DT_DIR),
    (b"task", DT_DIR),
];

/// `/proc/<pid>/stat` of process `pid` (as the reader sees it) named
/// `comm`.
pub fn stat_line(pid: i32, comm: &[u8], h: &HostInfo) -> Vec<u8> {
    let g = crate::pidns::to_guest;
    let page = 16384;
    format!(
        "{pid} ({}) {} {} {} {} 0 -1 4194560 0 0 0 0 {} {} 0 0 20 {} {} 0 {} {} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        String::from_utf8_lossy(comm),
        h.state as char,
        g(h.ppid),
        g(h.pgid),
        g(h.sid),
        h.utime,
        h.stime,
        h.nice,
        h.threads,
        h.start,
        h.vsize,
        h.rss_bytes / page,
    )
    .into_bytes()
}

/// The credentials and limits `/proc/<pid>/status` shows, where fwe knows
/// them (for the reader itself).
#[derive(Clone, Debug, Default)]
pub struct Creds {
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub groups: Vec<u32>,
    pub caps: Option<crate::caps::Caps>,
    pub no_new_privs: bool,
    pub seccomp: u8,
    pub umask: u32,
}

/// `/proc/<pid>/status`.
pub fn status(pid: i32, comm: &[u8], h: &HostInfo, c: &Creds) -> Vec<u8> {
    let g = crate::pidns::to_guest;
    let state = match h.state {
        b'R' => "R (running)",
        b'T' => "T (stopped)",
        b'Z' => "Z (zombie)",
        _ => "S (sleeping)",
    };
    let ids = |v: &[u32; 4]| v.iter().map(u32::to_string).collect::<Vec<_>>().join("\t");
    let groups = c.groups.iter().map(u32::to_string).collect::<Vec<_>>().join(" ");
    let caps = c.caps.map_or_else(
        || "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n".to_string(),
        |k| k.status(),
    );
    format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{state}\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{}\nTracerPid:\t0\n\
         Uid:\t{}\nGid:\t{}\nFDSize:\t64\nGroups:\t{groups}\nNStgid:\t{pid}\nNSpid:\t{pid}\nNSpgid:\t{}\nNSsid:\t{}\n\
         VmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{}\nSigQ:\t0/63448\n{caps}NoNewPrivs:\t{}\nSeccomp:\t{}\n\
         Seccomp_filters:\t{}\nCpus_allowed_list:\t0-{}\nvoluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        String::from_utf8_lossy(comm),
        c.umask,
        g(h.ppid),
        ids(&c.uids),
        ids(&c.gids),
        g(h.pgid),
        g(h.sid),
        h.vsize / 1024,
        h.rss_bytes / 1024,
        h.threads,
        u8::from(c.no_new_privs),
        c.seccomp,
        u8::from(c.seccomp == 2),
        crate::procfs::ncpu_hint().saturating_sub(1),
    )
    .into_bytes()
}

/// A namespace's link (`/proc/<pid>/ns/<kind>`) for a process in the
/// namespaces whose records are `dirs`: the identity the record has
/// ([`crate::shared::Record`]), or `init`'s when it is in the initial one.
fn ns_link(kind: &[u8], dirs: &[Vec<u8>], init: u64) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let k: &[u8] = if kind == b"pid_for_children" { b"pid" } else { kind };
    let prefix = [format!("v{}-", crate::shared::FORMAT).as_bytes(), k, b"-"].concat();
    let init_mnt = [format!("v{}-mnt-init-", crate::shared::FORMAT).as_bytes()].concat();
    let id = dirs
        .iter()
        .filter_map(|d| Some((d, d.rsplit(|&b| b == b'/').next()?)))
        .find(|(_, name)| name.starts_with(&prefix))
        .and_then(|(d, name)| {
            if name.starts_with(&init_mnt) {
                return Some(crate::mounts::store::INIT_ID);
            }
            let generation = [&d[..], b"/generation"].concat();
            let m = std::fs::metadata(std::ffi::OsStr::from_bytes(&generation)).ok()?;
            Some(4026532000 + (m.ino() & 0xffff_ffff))
        })
        .unwrap_or(init);
    [k, format!(":[{id}]").as_bytes()].concat()
}

/// The user namespace record among a process's namespace records, if it
/// is in one of fwe's.
pub fn user_record(dirs: &[Vec<u8>]) -> Option<crate::shared::Record<crate::userns::UserNs>> {
    let prefix = format!("v{}-user-", crate::shared::FORMAT);
    let d = dirs.iter().find(|d| {
        d.rsplit(|&b| b == b'/').next().is_some_and(|n| n.starts_with(prefix.as_bytes()))
    })?;
    crate::shared::Record::join(d, 0).ok()
}

/// The entry `sub` (empty for the directory itself) of `/proc/<pid>`, for
/// process `pid` of the reader's pid namespace behind host pid `host`.
pub fn entry(host: i32, pid: i32, sub: &[u8]) -> Entry {
    let Some(rec) = crate::procreg::read(host) else {
        // A process fwe has no record of: only what the host says.
        return match (crate::procreg::start_time(host), sub) {
            (None, _) => Entry::Missing,
            (Some(_), b"") => Entry::Dir,
            (Some(_), _) => Entry::Missing,
        };
    };
    let Some(h) = host_info(host) else { return Entry::Missing };
    use crate::ns::*;
    match sub {
        b"" | b"/ns" | b"/task" => Entry::Dir,
        b"/stat" => Entry::File(stat_line(pid, &rec.comm, &h)),
        b"/status" => Entry::File(status(
            pid,
            &rec.comm,
            &h,
            &Creds { uids: [0; 4], gids: [0; 4], groups: vec![0], ..Creds::default() },
        )),
        b"/cmdline" => Entry::File(rec.cmdline.clone()),
        b"/comm" => Entry::File([&rec.comm[..], b"\n"].concat()),
        b"/exe" => Entry::Symlink(rec.exe.clone()),
        b"/cgroup" => Entry::File([b"0::", &rec.cgroup[..], b"\n"].concat()),
        b"/uid_map" | b"/gid_map" | b"/setgroups" => match user_record(&rec.ns) {
            Some(u) => {
                let n = u.get();
                Entry::File(match sub {
                    b"/uid_map" => crate::userns::show_map(&n.uid_map),
                    b"/gid_map" => crate::userns::show_map(&n.gid_map),
                    _ => {
                        if n.setgroups_deny {
                            b"deny\n".to_vec()
                        } else {
                            b"allow\n".to_vec()
                        }
                    }
                })
            }
            None if sub == b"/setgroups" => Entry::File(b"allow\n".to_vec()),
            None => Entry::File(b"         0          0 4294967295\n".to_vec()),
        },
        _ => {
            if let Some(kind) = sub.strip_prefix(b"/ns/") {
                let init = match kind {
                    b"uts" => INIT_UTS,
                    b"ipc" => INIT_IPC,
                    b"net" => INIT_NET,
                    b"pid" | b"pid_for_children" => INIT_PID,
                    b"user" => INIT_USER,
                    b"cgroup" => INIT_CGROUP,
                    b"mnt" => crate::mounts::store::INIT_ID,
                    _ => return Entry::Missing,
                };
                return Entry::Symlink(ns_link(kind, &rec.ns, init));
            }
            if let Some(t) = sub.strip_prefix(b"/task/") {
                // The main thread only: fwe knows another's threads by count.
                return if t == pid.to_string().as_bytes() { Entry::Dir } else { Entry::Missing };
            }
            Entry::Missing
        }
    }
}

/// The entries of `/proc/<pid>` or one of its directories.
pub fn children(pid: i32, sub: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    let mut out = vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)];
    match sub {
        b"" => out.extend(FILES.iter().map(|(n, t)| (n.to_vec(), *t))),
        b"/ns" => out.extend(
            [&b"cgroup"[..], b"ipc", b"mnt", b"net", b"pid", b"pid_for_children", b"user", b"uts"]
                .iter()
                .map(|n| (n.to_vec(), DT_LNK)),
        ),
        b"/task" => out.push((pid.to_string().into_bytes(), DT_DIR)),
        _ => return None,
    }
    Some(out)
}

/// The pids `/proc` lists: the processes of the reader's pid namespace.
pub fn listed() -> Vec<i32> {
    let chain = crate::pidns::current();
    let mut pids: Vec<i32> = match chain.first() {
        Some(r) => {
            r.get().pids.iter().filter(|(_, e)| !e.thread && e.host != 0).map(|(n, _)| *n).collect()
        }
        None => crate::procreg::all().into_iter().map(|(p, _)| p).collect(),
    };
    pids.push(crate::thread::tgid());
    pids.sort_unstable();
    pids.dedup();
    pids
}
