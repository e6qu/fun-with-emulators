//! `/proc/<pid>`: what a process can see of the processes of its pid
//! namespace, from fwe's record of each ([`crate::procreg`]) and what the
//! host reports of its process (state, parent, times, memory).

use crate::ids::HostPid;
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
pub fn host_info(pid: HostPid) -> Option<HostInfo> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are valid for both structures, which the
        // calls fill.
        let mut b: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let bsize = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: a valid out-buffer of `bsize` bytes.
        if unsafe {
            libc::proc_pidinfo(
                pid.get(),
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut b as *mut libc::proc_bsdinfo).cast(),
                bsize,
            )
        } != bsize
        {
            // A zombie, or another user's process, which the host answers
            // for only in its `kinfo_proc`: what it keeps, no usage.
            let z = crate::procreg::kinfo(pid)?;
            return Some(HostInfo {
                state: match z.state {
                    2 => b'R',
                    4 => b'T',
                    5 => b'Z',
                    _ => b'S',
                },
                ppid: crate::reaper::parent_of(pid, z.ppid),
                pgid: z.pgid,
                // SAFETY: plain host call.
                sid: unsafe { libc::getsid(pid.get()) },
                nice: 0,
                threads: 1,
                rss_bytes: 0,
                vsize: 0,
                utime: 0,
                stime: 0,
                start: ticks_since_boot(z.start as f64 / 1e6),
            });
        }
        // SAFETY: as above.
        let mut t: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let tsize = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        // SAFETY: a valid out-buffer of `tsize` bytes.
        let have_task = unsafe {
            libc::proc_pidinfo(
                pid.get(),
                libc::PROC_PIDTASKINFO,
                0,
                (&mut t as *mut libc::proc_taskinfo).cast(),
                tsize,
            )
        } == tsize;
        let start = b.pbi_start_tvsec * 1_000_000 + b.pbi_start_tvusec;
        let state = match b.pbi_status {
            4 => b'T', // SSTOP
            // In a stop of fwe's.
            2 | 3 if crate::signote::job_stop_of(pid).is_some() => b'T',
            5 => b'Z', // SZOMB
            // Not yet in the program: whatever waits the host shows it in
            // are its making's ([`crate::procstore::entered`]).
            _ if crate::procstore::not_yet_entered(pid, start) => b'R',
            // SRUN: running or runnable, as the host sees a process that
            // is neither stopped nor ended; Linux tells from its threads.
            2 => threads_state(pid),
            _ => b'S', // SIDL, SSLEEP
        };
        let ns_to_ticks = |ns: u64| ns * HZ / 1_000_000_000;
        let started = b.pbi_start_tvsec as f64 + b.pbi_start_tvusec as f64 / 1e6;
        // SAFETY: plain host call.
        let sid = unsafe { libc::getsid(pid.get()) };
        Some(HostInfo {
            state,
            // The guest's parent: an orphan's is the reaper that adopted it.
            ppid: crate::reaper::parent_of(pid, b.pbi_ppid as i32),
            pgid: b.pbi_pgid as i32,
            sid,
            nice: crate::procreg::nice(pid),
            threads: if have_task { t.pti_threadnum as u64 } else { 1 },
            rss_bytes: if have_task { t.pti_resident_size } else { 0 },
            // A process of fwe's maps what its guest mapped, as Linux
            // counts it; the host's count holds fwe's reservations too.
            vsize: crate::maps::mapped_bytes(pid).unwrap_or(if have_task {
                t.pti_virtual_size
            } else {
                0
            }),
            utime: if have_task { ns_to_ticks(mach_to_ns(t.pti_total_user)) } else { 0 },
            stime: if have_task { ns_to_ticks(mach_to_ns(t.pti_total_system)) } else { 0 },
            start: ticks_since_boot(started),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// When a process that started at `started` (seconds since the epoch)
/// did, in clock ticks since the host booted.
#[cfg(target_os = "macos")]
fn ticks_since_boot(started: f64) -> u64 {
    let boot = crate::host::uptime();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    ((started - (now - boot)).max(0.0) * HZ as f64) as u64
}

/// Linux's state of host process `pid`, which the host has running: its
/// main thread's, as Linux shows a process (`R` if it runs or waits only
/// for a processor, `S` if it sleeps, as a thread in a system call that
/// waits does, which programs wait to see). This process's main thread is
/// fwe's record of it; another's is the first the host lists, the one
/// created first. One in fwe's own work, waiting for the host or not, is
/// running ([`crate::procstore::Busy`]), as a Linux thread doing its
/// kernel's work is: the mark is read before and after the host's state,
/// and a wait the host showed is the guest's only if fwe's work neither
/// went on at either look nor began or ended between them (a wait for
/// fwe's lock, over just before the second look, is fwe's).
#[cfg(target_os = "macos")]
fn threads_state(pid: HostPid) -> u8 {
    let before = crate::procstore::busy_mark(pid);
    let host = host_thread_state(pid);
    if host != b'R' && crate::procstore::busy_between(before, crate::procstore::busy_mark(pid)) {
        return b'R';
    }
    host
}

/// What the host shows of process `pid`'s main thread, as Linux's state
/// letter ([`threads_state`]).
#[cfg(target_os = "macos")]
fn host_thread_state(pid: HostPid) -> u8 {
    /// `PROC_PIDLISTTHREADS`: the process's thread handles.
    const PROC_PIDLISTTHREADS: i32 = 6;
    if pid == crate::host::pid() {
        return match crate::thread::host_state(crate::thread::tgid()) {
            Some((_, _, true)) | None => b'R',
            Some((_, _, false)) => b'S',
        };
    }
    let mut handles = [0u64; 256];
    let size = std::mem::size_of_val(&handles) as i32;
    // SAFETY: a valid out-buffer of `size` bytes.
    let got = unsafe {
        libc::proc_pidinfo(pid.get(), PROC_PIDLISTTHREADS, 0, handles.as_mut_ptr().cast(), size)
    };
    if got < 8 {
        return b'R';
    }
    // SAFETY: zeroed bytes are a valid `proc_threadinfo`, which the call
    // fills.
    let mut t: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
    let tsize = std::mem::size_of::<libc::proc_threadinfo>() as i32;
    // SAFETY: a valid out-buffer of `tsize` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDTHREADINFO,
            handles[0],
            (&mut t as *mut libc::proc_threadinfo).cast(),
            tsize,
        )
    };
    if n != tsize {
        return b'R';
    }
    match t.pth_run_state {
        libc::TH_STATE_RUNNING => b'R',
        // A wait it cannot be woken from by a signal (a page brought in):
        // Linux's disk sleep.
        libc::TH_STATE_UNINTERRUPTIBLE => b'D',
        _ => b'S',
    }
}

/// The CPU time host process `pid` has used, user and system, in
/// nanoseconds.
pub fn cpu_ns(pid: HostPid) -> Option<(u64, u64)> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are a valid `proc_taskinfo`, which the call
        // fills.
        let mut t: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        // SAFETY: a valid out-buffer of `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                pid.get(),
                libc::PROC_PIDTASKINFO,
                0,
                (&mut t as *mut libc::proc_taskinfo).cast(),
                size,
            )
        };
        (got == size).then(|| (mach_to_ns(t.pti_total_user), mach_to_ns(t.pti_total_system)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Nanoseconds as the clock ticks (`USER_HZ`) `/proc` counts CPU time in.
pub fn ns_to_ticks(ns: u64) -> u64 {
    ns / (1_000_000_000 / 100)
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
    (b"maps", DT_REG),
    (b"smaps", DT_REG),
    (b"comm", DT_REG),
    (b"exe", DT_LNK),
    (b"cgroup", DT_REG),
    (b"oom_score_adj", DT_REG),
    (b"oom_adj", DT_REG),
    (b"oom_score", DT_REG),
    (b"coredump_filter", DT_REG),
    (b"timerslack_ns", DT_REG),
    (b"mem", DT_REG),
    (b"auxv", DT_REG),
    (b"environ", DT_REG),
    (b"limits", DT_REG),
    (b"statm", DT_REG),
    (b"io", DT_REG),
    (b"cwd", DT_LNK),
    (b"root", DT_LNK),
    (b"mountinfo", DT_REG),
    (b"mounts", DT_REG),
    (b"uid_map", DT_REG),
    (b"gid_map", DT_REG),
    (b"setgroups", DT_REG),
    (b"ns", DT_DIR),
    (b"net", DT_DIR),
    (b"fd", DT_DIR),
    (b"task", DT_DIR),
];

/// The files another process's `/proc/<pid>` shows only to a reader that
/// can read it as a tracer would (`PTRACE_MODE_READ_FSCREDS`), as Linux
/// has it: `EACCES` for anyone else.
pub const TRACER_ONLY: &[&[u8]] = &[b"/maps", b"/smaps", b"/environ", b"/io", b"/cwd", b"/root"];

/// `/proc/<pid>/environ` of a process whose program started with
/// auxiliary vector `auxv` and command line `cmdline`, its memory read
/// with `read`: the environment strings, which the initial stack holds
/// after the arguments (from the platform's name on, `AT_PLATFORM`) and
/// before the program's path (`AT_EXECFN`), as the program left them.
pub fn environ(auxv: &[u8], cmdline: &[u8], read: impl Fn(u64, &mut [u8]) -> bool) -> Vec<u8> {
    const MAX: u64 = 4 << 20;
    let at = |k| crate::procfs::auxv_value(auxv, k);
    let (Some(platform), Some(execfn)) =
        (at(fwe_abi::auxv::AT_PLATFORM), at(fwe_abi::auxv::AT_EXECFN))
    else {
        return Vec::new();
    };
    // Past "aarch64" and its NUL.
    let start = platform + 8;
    if execfn <= start || execfn - start > MAX {
        return Vec::new();
    }
    let mut b = vec![0u8; (execfn - start) as usize];
    if !read(start, &mut b) {
        return Vec::new();
    }
    // Past the arguments, as many strings as the command line has.
    let argc = cmdline.iter().filter(|&&c| c == 0).count();
    let mut skip = 0;
    for _ in 0..argc {
        match b[skip..].iter().position(|&c| c == 0) {
            Some(i) => skip += i + 1,
            None => return Vec::new(),
        }
    }
    b.split_off(skip)
}

/// `/proc/<pid>/limits` of a process with resource limits `limits`
/// (soft, hard), as Linux writes it.
pub fn limits(limits: &[(u64, u64)]) -> Vec<u8> {
    const NAMES: [(&str, &str); 16] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let shown = |v: u64| {
        if v == fwe_abi::resource::RLIM_INFINITY { "unlimited".to_string() } else { v.to_string() }
    };
    let mut out =
        format!("{:<25} {:<20} {:<20} {:<10}\n", "Limit", "Soft Limit", "Hard Limit", "Units");
    for ((name, unit), (soft, hard)) in NAMES.iter().zip(limits) {
        out.push_str(&format!("{name:<25} {:<20} {:<20} ", shown(*soft), shown(*hard)));
        if !unit.is_empty() {
            out.push_str(&format!("{unit:<10}"));
        }
        out.push('\n');
    }
    out.into_bytes()
}

/// `/proc/<pid>/statm` of host process `host`, in pages: its size (what
/// its guest mapped) and resident set (the host's count)
/// (`/proc/<pid>/status` reports the same); the shared, text and data
/// counts are not kept (0).
pub fn statm(host: HostPid) -> Vec<u8> {
    let h = host_info(host).unwrap_or_default();
    let page = crate::maps::page_size().max(1);
    format!("{} {} 0 0 0 0 0\n", h.vsize / page, h.rss_bytes / page).into_bytes()
}

/// `/proc/<pid>/io` of host process `host`: the bytes it had the host read
/// from and write to storage; the counts of `read` and `write` calls and
/// the bytes they moved are not kept (0).
pub fn io(host: HostPid) -> Vec<u8> {
    let (read, written) = crate::host::disk_io(host.get());
    format!(
        "rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: {read}\nwrite_bytes: {written}\n\
         cancelled_write_bytes: 0\n"
    )
    .into_bytes()
}

/// `/proc/<pid>/stat` of process `pid` (as the reader sees it) named
/// `comm`.
pub fn stat_line(pid: i32, comm: &[u8], h: &HostInfo) -> Vec<u8> {
    let g = crate::pidns::to_guest;
    let page = 16384;
    format!(
        "{pid} ({}) {} {} {} {} 0 -1 4194560 0 0 0 0 {} {} 0 0 {} {} {} 0 {} {} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        String::from_utf8_lossy(comm),
        h.state as char,
        g(h.ppid),
        g(h.pgid),
        g(h.sid),
        h.utime,
        h.stime,
        20 + h.nice,
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
    /// How many seccomp filters it has.
    pub filters: u32,
    pub umask: u32,
    /// Bytes of memory locked (`mlock`).
    pub locked: u64,
    /// Its tracer's pid in the reader's pid namespace (0: none).
    pub tracer: i32,
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
    // Each group then a space, and a space with none, as Linux writes the
    // line (crash reporters parse it so).
    let groups = c.groups.iter().map(|g| format!("{g} ")).collect::<String>();
    let groups = if groups.is_empty() { " ".to_string() } else { groups };
    let caps = c.caps.map_or_else(
        || {
            format!(
                "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
                 CapBnd:\t{:016x}\nCapAmb:\t0000000000000000\n",
                crate::caps::INITIAL
            )
        },
        |k| k.status(),
    );
    format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{state}\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{}\nTracerPid:\t{}\n\
         Uid:\t{}\nGid:\t{}\nFDSize:\t64\nGroups:\t{groups}\nNStgid:\t{pid}\nNSpid:\t{pid}\nNSpgid:\t{}\nNSsid:\t{}\n\
         VmSize:\t{} kB\nVmLck:\t{} kB\nVmRSS:\t{} kB\nVmSwap:\t0 kB\nThreads:\t{}\nSigQ:\t0/63448\n{caps}NoNewPrivs:\t{}\nSeccomp:\t{}\n\
         Seccomp_filters:\t{}\nCpus_allowed_list:\t0-{}\nvoluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        String::from_utf8_lossy(comm),
        c.umask,
        g(h.ppid),
        c.tracer,
        ids(&c.uids),
        ids(&c.gids),
        g(h.pgid),
        g(h.sid),
        h.vsize / 1024,
        c.locked / 1024,
        h.rss_bytes / 1024,
        h.threads,
        u8::from(c.no_new_privs),
        c.seccomp,
        c.filters,
        crate::procfs::ncpu_hint().saturating_sub(1),
    )
    .into_bytes()
}

/// The identity of the initial namespace of `kind` (a `/proc/<pid>/ns`
/// name), if it is one.
fn init_ns(kind: &[u8]) -> Option<u64> {
    use crate::ns::*;
    Some(match kind {
        b"uts" => INIT_UTS,
        b"ipc" => INIT_IPC,
        b"net" => INIT_NET,
        b"pid" | b"pid_for_children" => INIT_PID,
        b"user" => INIT_USER,
        b"cgroup" => INIT_CGROUP,
        b"mnt" => crate::mounts::store::INIT_ID,
        _ => return None,
    })
}

/// The link `/proc/<pid>/ns/<kind>` reads for a process in the namespaces
/// whose records are `dirs` (empty for a kind there is none of).
pub(crate) fn ns_link_of(kind: &[u8], dirs: &[Vec<u8>]) -> Vec<u8> {
    init_ns(kind).map_or_else(Vec::new, |init| ns_link(kind, dirs, init))
}

/// A namespace's link (`/proc/<pid>/ns/<kind>`) for a process in the
/// namespaces whose records are `dirs`: the identity the record has
/// ([`crate::shared::Record`]), or `init`'s when it is in the initial one.
fn ns_link(kind: &[u8], dirs: &[Vec<u8>], init: u64) -> Vec<u8> {
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
            crate::shared::id_of(d)
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
pub fn entry(host: HostPid, pid: i32, sub: &[u8]) -> Entry {
    let Some(rec) = crate::procreg::read(host) else {
        // A process fwe has no record of (one of another user's, such as
        // the host's process 1, too): that it exists, and what the host
        // tells of it.
        return match sub {
            b"" if crate::host::probe(host).exists() => Entry::Dir,
            b"/stat" => match host_info(host) {
                Some(h) => {
                    let comm = crate::procreg::kinfo(host).map(|k| k.comm).unwrap_or_default();
                    Entry::File(stat_line(pid, &comm, &h))
                }
                None => Entry::Missing(fwe_abi::errno::ENOENT),
            },
            _ => Entry::Missing(fwe_abi::errno::ENOENT),
        };
    };
    let Some(h) = host_info(host) else { return Entry::Missing(fwe_abi::errno::ENOENT) };
    // Its credentials, as its `status` shows them.
    let creds = || {
        let u = |id| crate::userns::to_ns(id, false);
        let g = |id| crate::userns::to_ns(id, true);
        let i = rec.ids;
        let s = rec.sec;
        let [effective, permitted, inheritable, bounding, ambient] = s.caps;
        let tracer = crate::ptrace::tracer_of(host.get());
        Creds {
            uids: [u(i[0]), u(i[1]), u(i[2]), u(i[3])],
            gids: [g(i[4]), g(i[5]), g(i[6]), g(i[7])],
            groups: rec.groups.iter().map(|&id| g(id)).collect(),
            caps: Some(crate::caps::Caps {
                effective,
                permitted,
                inheritable,
                bounding,
                ambient,
                securebits: 0,
            }),
            no_new_privs: s.no_new_privs,
            seccomp: s.seccomp,
            filters: s.filters,
            tracer: if tracer == 0 { 0 } else { crate::pidns::to_guest(tracer) },
            ..Creds::default()
        }
    };
    match sub {
        b"" | b"/ns" | b"/task" => Entry::Dir,
        b"/stat" => Entry::File(stat_line(pid, &rec.comm, &h)),
        b"/status" => Entry::File(status(pid, &rec.comm, &h, &creds())),
        b"/maps" | b"/smaps" => match crate::mm::MapsView::of(host) {
            Some(v) => Entry::File(v.render(sub == b"/smaps")),
            None => Entry::Missing(fwe_abi::errno::ENOENT),
        },
        b"/cmdline" => Entry::File(rec.cmdline.clone()),
        b"/environ" => Entry::File(environ(&rec.auxv, &rec.cmdline, |addr, buf| {
            crate::procvm::remote(host, addr, buf, false).is_ok_and(|n| n == buf.len())
        })),
        b"/limits" => match crate::fs::OtherView::of(host) {
            Some(v) => Entry::File(limits(&v.limits)),
            None => Entry::Missing(fwe_abi::errno::ENOENT),
        },
        b"/statm" => Entry::File(statm(host)),
        b"/io" => Entry::File(io(host)),
        b"/comm" => Entry::File([&rec.comm[..], b"\n"].concat()),
        b"/exe" => Entry::Symlink(rec.exe.clone()),
        // Relative to the reader's cgroup namespace (`Fs::synthetic_entry`).
        b"/cgroup" => Entry::Missing(fwe_abi::errno::ENOENT),
        b"/oom_score_adj" | b"/oom_adj" | b"/oom_score" => {
            Entry::File(oom_file(sub, rec.oom_score_adj))
        }
        b"/coredump_filter" => Entry::File(crate::coredump::FILTER.to_vec()),
        b"/timerslack_ns" => Entry::File(format!("{}\n", rec.slack.0).into_bytes()),
        // Read and written by address (`crate::procmem`).
        b"/mem" => Entry::File(Vec::new()),
        b"/auxv" => Entry::File(rec.auxv.clone()),
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
                return match init_ns(kind) {
                    Some(init) => Entry::Symlink(ns_link(kind, &rec.ns, init)),
                    None => Entry::Missing(fwe_abi::errno::ENOENT),
                };
            }
            if let Some(t) = sub.strip_prefix(b"/task/") {
                // A thread's memory is its process's.
                if let Some(t) = t.strip_suffix(b"/mem") {
                    return match entry(host, pid, &[b"/task/", t].concat()) {
                        Entry::Dir => Entry::File(Vec::new()),
                        other => other,
                    };
                }
                // Its threads, as it published them (the main thread always),
                // each with its own name.
                let (num, file) = match t.iter().position(|&b| b == b'/') {
                    Some(i) => (&t[..i], &t[i..]),
                    None => (t, &b""[..]),
                };
                let Some(n) = std::str::from_utf8(num).ok().and_then(|n| n.parse::<i32>().ok())
                else {
                    return Entry::Missing(fwe_abi::errno::ENOENT);
                };
                let thread = if n == pid {
                    Some(crate::ids::Tid::main_of(host))
                } else {
                    let tids = crate::thread::published_tids(host);
                    tids.into_iter().find(|&id| crate::pidns::thread_number(id) == n)
                };
                let Some(thread) = thread else { return Entry::Missing(fwe_abi::errno::ENOENT) };
                let comm = match crate::thread::published_name(host, thread) {
                    Some(name) => name.iter().take_while(|&&b| b != 0).copied().collect(),
                    None => rec.comm.clone(),
                };
                return match file {
                    b"" => Entry::Dir,
                    b"/comm" => Entry::File([&comm[..], b"\n"].concat()),
                    b"/stat" => Entry::File(stat_line(n, &comm, &h)),
                    b"/status" => Entry::File(status(n, &comm, &h, &creds())),
                    _ => Entry::Missing(fwe_abi::errno::ENOENT),
                };
            }
            Entry::Missing(fwe_abi::errno::ENOENT)
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
        b"/net" => out.extend(crate::procnet::FILES.iter().map(|n| (n.to_vec(), DT_REG))),
        // A thread's directory: the files of it fwe has.
        _ if sub.strip_prefix(b"/task/").is_some_and(|t| !t.contains(&b'/')) => {
            out.extend([&b"comm"[..], b"stat", b"status"].iter().map(|n| (n.to_vec(), DT_REG)))
        }
        b"/task" => {
            out.push((pid.to_string().into_bytes(), DT_DIR));
            let me = pid.to_string().into_bytes();
            let tids = crate::pidns::to_host(pid).map(crate::thread::published_tids);
            for t in tids.unwrap_or_default().into_iter().map(crate::pidns::thread_number) {
                if t == 0 {
                    continue;
                }
                let name = t.to_string().into_bytes();
                if name != me {
                    out.push((name, DT_DIR));
                }
            }
        }
        _ => return None,
    }
    Some(out)
}

/// The pids `/proc` lists: the processes of the reader's pid namespace.
pub fn listed() -> Vec<i32> {
    let chain = crate::pidns::current();
    let mut pids: Vec<i32> = match chain.first() {
        Some(r) => r
            .get()
            .pids
            .iter()
            .filter(|(_, e)| e.thread.is_none() && e.host != 0)
            .map(|(n, _)| *n)
            .collect(),
        None => crate::procreg::all().into_iter().map(|(p, _)| p.get()).collect(),
    };
    pids.push(crate::thread::tgid());
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// `/proc/<pid>/oom_score_adj`, `oom_adj` or `oom_score` (`sub`) of a
/// process whose `oom_score_adj` is `adj`. fwe has no OOM killer to rank
/// processes for, so the score is the adjustment's share of its range.
pub fn oom_file(sub: &[u8], adj: i32) -> Vec<u8> {
    let v = match sub {
        b"/oom_adj" => legacy_adj(adj),
        b"/oom_score" => adj.clamp(0, 1000),
        _ => adj,
    };
    format!("{v}\n").into_bytes()
}

/// `oom_adj` (-17 to 15) for `oom_score_adj` `adj`, as Linux scales it
/// (by 17/1000, the top of the range kept the top).
fn legacy_adj(adj: i32) -> i32 {
    if adj == 1000 { 15 } else { adj * 17 / 1000 }
}

/// What a write of `data` to `/proc/<pid>/oom_score_adj` (or `oom_adj`)
/// opened as `mark` does.
/// `data` up to its first NUL, if it has one.
fn c_text(data: &[u8]) -> &[u8] {
    data.split(|&b| b == 0).next().unwrap_or_default()
}

pub fn oom_write(mark: crate::fdmarks::Mark, data: &[u8], len: u64) -> i64 {
    use fwe_abi::{err, errno};
    let crate::fdmarks::Mark::OomScore { host, legacy, privileged } = mark else {
        return err(errno::EINVAL);
    };
    let Ok(v) = String::from_utf8_lossy(data).trim().parse::<i32>() else {
        return err(errno::EINVAL);
    };
    let adj = if legacy {
        if !(-17..=15).contains(&v) {
            return err(errno::EINVAL);
        }
        if v == 15 { 1000 } else { v * 1000 / 17 }
    } else {
        if !(-1000..=1000).contains(&v) {
            return err(errno::EINVAL);
        }
        v
    };
    // Going below the floor a privileged process set (or, by the older
    // file, lowering it at all) takes CAP_SYS_RESOURCE, as on Linux.
    let (now, floor) = crate::procreg::oom_score_adj_range(host);
    if adj < if legacy { now } else { floor } && !privileged {
        return err(errno::EACCES);
    }
    match crate::procreg::set_oom_score_adj(host, adj, privileged && !legacy) {
        Ok(()) => len as i64,
        Err(_) => err(errno::ESRCH),
    }
}

/// A write of `len` bytes, `data` the first of them, to `fd`: for an
/// `oom_score_adj` file opened for writing, what the write does (see
/// [`crate::specialwrite`]).
pub fn try_write(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    // The text ends at a NUL, as Linux reads it: runc writes its value with
    // the NUL that ends it.
    let data = c_text(data);
    match crate::fdmarks::marked(fd)? {
        mark @ crate::fdmarks::Mark::OomScore { .. } => {
            Some(oom_write(mark, &data[..data.len().min(64)], len))
        }
        crate::fdmarks::Mark::Comm { tid } => Some(comm_write(tid, data, len)),
        crate::fdmarks::Mark::UtsName { domain } => {
            use fwe_abi::err;
            // The first line, as much of it as the name holds.
            let line = data.split(|&b| b == b'\n').next().unwrap_or_default();
            let name = &line[..line.len().min(crate::ns::HOST_NAME_MAX)];
            Some(match crate::ns::set_current_name(!domain, name) {
                Ok(()) => len as i64,
                Err(e) => err(e),
            })
        }
        crate::fdmarks::Mark::TimerSlack { host } => {
            use fwe_abi::{err, errno};
            let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
            let Ok(v) = text.trim().parse::<u64>() else { return Some(err(errno::EINVAL)) };
            Some(match crate::procreg::set_slack(host, v) {
                Ok(()) => len as i64,
                Err(_) => err(errno::ESRCH),
            })
        }
        _ => None,
    }
}

/// A write of `data` (`len` bytes in all) to the `comm` of thread `tid`
/// of this process (0: the main thread; -1: another process's, `EINVAL`
/// as Linux has it): its first 15 bytes are the thread's name, as
/// `PR_SET_NAME` sets it.
fn comm_write(tid: i32, data: &[u8], len: u64) -> i64 {
    use fwe_abi::prctl::TASK_COMM_LEN;
    use fwe_abi::{err, errno};
    let n = data.len().min(TASK_COMM_LEN - 1);
    let mut name = [0u8; TASK_COMM_LEN];
    name[..n].copy_from_slice(&data[..n]);
    // Any thread of the process's, as Linux allows; the main one's is the
    // process's too.
    let tid = if tid == 0 { crate::thread::tgid() } else { tid };
    let main = tid == crate::thread::tgid();
    if main {
        crate::procreg::own_comm(&name[..n]);
    }
    if !crate::thread::set_name_of(tid, Some(name)) && !main {
        return err(errno::EINVAL);
    }
    len as i64
}

/// What one of another process's descriptors is open on, as the host
/// reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdTarget {
    /// A file, at this host path.
    Path(Vec<u8>),
    /// A pipe, of this identity (its `fstat` inode).
    Pipe(u64),
    /// A socket, of this identity (see [`socket_id`]).
    Socket(u64),
    /// Something with neither: Linux's name for its kind.
    Anon(&'static str),
}

/// The guest's descriptors of host process `host`, with what each is open
/// on (fwe's own, in the reserved range, left out: every fwe process
/// reserves the same range).
pub fn fds(host: HostPid) -> Vec<(i32, FdTarget)> {
    #[cfg(target_os = "macos")]
    {
        let size = std::mem::size_of::<libc::proc_fdinfo>();
        let mut buf: Vec<libc::proc_fdinfo> = Vec::new();
        let mut n = 64usize;
        loop {
            // SAFETY: zeroed bytes are valid `proc_fdinfo`s.
            buf.resize(n, unsafe { std::mem::zeroed() });
            // SAFETY: a valid out-buffer of `n` entries.
            let got = unsafe {
                libc::proc_pidinfo(
                    host.get(),
                    libc::PROC_PIDLISTFDS,
                    0,
                    buf.as_mut_ptr().cast(),
                    (n * size) as i32,
                )
            };
            if got <= 0 {
                return Vec::new();
            }
            let count = got as usize / size;
            if count < n {
                buf.truncate(count);
                break;
            }
            n *= 2;
        }
        buf.iter()
            .filter(|f| crate::fdtable::guest_visible(f.proc_fd))
            .filter_map(|f| Some((f.proc_fd, target_of(host, f.proc_fd, f.proc_fdtype as i32)?)))
            .collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = host;
        Vec::new()
    }
}

/// What descriptor `fd` of host process `host`, of host kind `kind`, is
/// open on.
#[cfg(target_os = "macos")]
fn target_of(host: HostPid, fd: i32, kind: i32) -> Option<FdTarget> {
    /// The `proc_pidfdinfo` flavours, and where in their results the path
    /// and the pipe's identity are (measured against the SDK's headers).
    const VNODE_PATH: i32 = 2;
    const PIPE: i32 = 6;
    const VNODE_PATH_SIZE: usize = 1200;
    const PATH_AT: usize = 176;
    const PIPE_SIZE: usize = 184;
    const PIPE_HANDLE_AT: usize = 160;
    let info = |flavor: i32, size: usize| -> Option<Vec<u8>> {
        let mut b = vec![0u8; size];
        // SAFETY: a valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidfdinfo(host.get(), fd, flavor, b.as_mut_ptr().cast(), size as i32)
        };
        (n as usize == size).then_some(b)
    };
    Some(match kind {
        libc::PROX_FDTYPE_VNODE => {
            let b = info(VNODE_PATH, VNODE_PATH_SIZE)?;
            let path = &b[PATH_AT..];
            let end = path.iter().position(|&c| c == 0)?;
            FdTarget::Path(path[..end].to_vec())
        }
        libc::PROX_FDTYPE_PIPE => {
            let b = info(PIPE, PIPE_SIZE)?;
            let h = u64::from_ne_bytes(b[PIPE_HANDLE_AT..PIPE_HANDLE_AT + 8].try_into().ok()?);
            FdTarget::Pipe(h)
        }
        libc::PROX_FDTYPE_SOCKET => FdTarget::Socket(socket_id(host, fd)?),
        libc::PROX_FDTYPE_KQUEUE => FdTarget::Anon("anon_inode:[eventpoll]"),
        _ => FdTarget::Anon("anon_inode:[unknown]"),
    })
}

/// The handle of the socket a connected Unix socket, descriptor `fd` of
/// host process `host`, is connected to: what [`socket_id`] gives for
/// the other end.
pub fn socket_peer(host: HostPid, fd: i32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let at = peer_offset()?;
        let b = socket_info(host, fd)?;
        let v = u64::from_ne_bytes(b[at..at + 8].try_into().ok()?);
        (v != 0).then_some(v)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (host, fd);
        None
    }
}

/// `PROC_PIDFDSOCKETINFO` of descriptor `fd` of host process `host`.
#[cfg(target_os = "macos")]
pub(crate) fn socket_info_of(host: HostPid, fd: i32) -> Option<Vec<u8>> {
    socket_info(host, fd)
}

#[cfg(target_os = "macos")]
fn socket_info(host: HostPid, fd: i32) -> Option<Vec<u8>> {
    const SOCKET: i32 = 3;
    const SOCKET_SIZE: usize = 792;
    let mut b = vec![0u8; SOCKET_SIZE];
    // SAFETY: a valid out-buffer of its size.
    let n = unsafe {
        libc::proc_pidfdinfo(host.get(), fd, SOCKET, b.as_mut_ptr().cast(), SOCKET_SIZE as i32)
    };
    (n as usize == SOCKET_SIZE).then_some(b)
}

/// Where in a Unix socket's [`socket_info`] its peer's handle is
/// (`unsi_conn_so`): found once, on a pair of fwe's own, as the place in
/// one end's that holds the other's handle.
#[cfg(target_os = "macos")]
fn peer_offset() -> Option<usize> {
    static AT: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *AT.get_or_init(|| {
        let mut sv = [-1i32; 2];
        // SAFETY: a valid out-array.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) } != 0 {
            return None;
        }
        let me = crate::host::pid();
        let found = (|| {
            let a = socket_info(me, sv[0])?;
            let other = socket_id(me, sv[1])?;
            // Past the socket's own handle (at 160).
            (168..a.len() - 8)
                .step_by(8)
                .find(|&i| u64::from_ne_bytes(a[i..i + 8].try_into().unwrap()) == other)
        })();
        // SAFETY: closing the pair just made.
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
        found
    })
}

/// A socket's identity as every process names it: the host's kernel handle
/// of descriptor `fd` of host process `host` (its `fstat` inode is a
/// number only that process can read).
pub fn socket_id(host: HostPid, fd: i32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        const SOCKET: i32 = 3;
        const SOCKET_SIZE: usize = 792;
        /// `psi.soi_so`, measured against the SDK's headers.
        const SO_AT: usize = 160;
        let mut b = vec![0u8; SOCKET_SIZE];
        // SAFETY: a valid out-buffer of its size.
        let n = unsafe {
            libc::proc_pidfdinfo(host.get(), fd, SOCKET, b.as_mut_ptr().cast(), SOCKET_SIZE as i32)
        };
        if n as usize != SOCKET_SIZE {
            return None;
        }
        Some(u64::from_ne_bytes(b[SO_AT..SO_AT + 8].try_into().ok()?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (host, fd);
        None
    }
}
