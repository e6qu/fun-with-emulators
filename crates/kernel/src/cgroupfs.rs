//! The cgroup v2 hierarchy (`/sys/fs/cgroup`).
//!
//! Every fwe process of the user is somewhere in one tree, as a machine's
//! processes are, so the tree is shared: its cgroups are real directories in
//! fwe's private directory ([`tree_dir`]), which a `cgroup2` mount shows,
//! and a cgroup's interface files are files there. What a process's cgroup
//! is lives in fwe's record of the process ([`crate::procreg`]).
//!
//! fwe does what the files say where it can:
//!
//! - `mkdir` makes a cgroup with the files of the controllers its parent
//!   enables, within `cgroup.max.depth` and `cgroup.max.descendants` up
//!   the tree; `rmdir` removes an empty one (`EBUSY` while it has
//!   processes or children).
//! - Writing a pid to `cgroup.procs` moves the process, by Linux's
//!   delegation rules (write access to the common ancestor's
//!   `cgroup.procs`, within the writer's cgroup namespace); the file lists
//!   the members when opened, as `cgroup.threads` their threads, and
//!   `cgroup.events`, `pids.current`, `memory.current` and `cpu.stat`
//!   what they report. Only domain cgroups are made: `cgroup.type` refuses
//!   `threaded`.
//! - `cgroup.subtree_control` enables controllers for the children, with
//!   Linux's rule that a cgroup with processes has none enabled for
//!   children (the root aside).
//! - `cgroup.freeze` stops and continues the members of the cgroup and
//!   those below it, and whoever joins or is forked into a frozen one;
//!   `cgroup.kill` kills them; `pids.max` limits `fork` and new threads
//!   (counted in `pids.events`); and device programs attached to a cgroup
//!   ([`crate::bpf`]) decide every device access of its members.
//! - The other limits are kept and read back but not enforced: the host has
//!   no way to hold a process to a memory or CPU budget.

use crate::procreg;
use fwe_abi::{err, errno};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

/// The controllers fwe's hierarchy offers.
pub const CONTROLLERS: &[&str] =
    &["cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"];

/// Where fwe keeps what is attached to a cgroup (device programs); hidden
/// from the guest.
pub const PRIVATE: &[u8] = b".fwe-bpf";

/// The files every non-root cgroup has, with what they start with.
const CORE_FILES: &[(&str, &str, bool)] = &[
    ("cgroup.controllers", "", false),
    ("cgroup.subtree_control", "", true),
    ("cgroup.procs", "", true),
    ("cgroup.threads", "", true),
    ("cgroup.type", "domain\n", true),
    ("cgroup.max.depth", "max\n", true),
    ("cgroup.max.descendants", "max\n", true),
    ("cgroup.stat", "nr_descendants 0\nnr_dying_descendants 0\n", false),
    ("cgroup.events", "populated 0\nfrozen 0\n", false),
    ("cgroup.freeze", "0\n", true),
    ("cgroup.kill", "", true),
];

/// The root's.
const ROOT_FILES: &[&str] = &[
    "cgroup.controllers",
    "cgroup.subtree_control",
    "cgroup.procs",
    "cgroup.threads",
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "cgroup.stat",
    "cpuset.cpus.effective",
    "cpuset.mems.effective",
];

/// The host's CPUs, as a cpuset lists them (`0-7`).
fn all_cpus() -> String {
    match crate::procfs::ncpu_hint() {
        1 => "0\n".to_string(),
        n => format!("0-{}\n", n - 1),
    }
}

/// Each controller's files in a cgroup whose parent enables it: name,
/// initial content, writable.
const CONTROLLER_FILES: &[(&str, &str, &str, bool)] = &[
    ("memory", "memory.max", "max\n", true),
    ("memory", "memory.high", "max\n", true),
    ("memory", "memory.low", "0\n", true),
    ("memory", "memory.min", "0\n", true),
    ("memory", "memory.swap.max", "max\n", true),
    ("memory", "memory.current", "0\n", false),
    ("memory", "memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", false),
    ("memory", "memory.stat", "anon 0\nfile 0\n", false),
    ("memory", "memory.oom.group", "0\n", true),
    ("pids", "pids.max", "max\n", true),
    ("pids", "pids.current", "0\n", false),
    ("pids", "pids.events", "max 0\n", false),
    ("cpu", "cpu.max", "max 100000\n", true),
    ("cpu", "cpu.weight", "100\n", true),
    ("cpu", "cpu.weight.nice", "0\n", true),
    ("cpu", "cpu.stat", "usage_usec 0\nuser_usec 0\nsystem_usec 0\n", false),
    ("cpuset", "cpuset.cpus", "\n", true),
    ("cpuset", "cpuset.mems", "\n", true),
    ("cpuset", "cpuset.cpus.effective", "", false),
    ("cpuset", "cpuset.mems.effective", "0\n", false),
    ("io", "io.max", "", true),
    ("io", "io.weight", "default 100\n", true),
    ("io", "io.stat", "", false),
    ("hugetlb", "hugetlb.2MB.max", "max\n", true),
    ("hugetlb", "hugetlb.2MB.current", "0\n", false),
    ("rdma", "rdma.max", "", true),
    ("rdma", "rdma.current", "", false),
    ("misc", "misc.max", "", true),
    ("misc", "misc.current", "", false),
];

fn os(p: &[u8]) -> &OsStr {
    OsStr::from_bytes(p)
}

fn put(dir: &[u8], name: &str, content: &str, writable: bool) {
    let p = [dir, b"/", name.as_bytes()].concat();
    if std::fs::symlink_metadata(os(&p)).is_err() {
        let _ = std::fs::write(os(&p), content);
    }
    let mode = if writable { 0o644 } else { 0o444 };
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(os(&p), std::fs::Permissions::from_mode(mode));
}

/// The hierarchy's root, on the host, made on first use.
pub fn tree_dir() -> Result<Vec<u8>, i32> {
    let mut dir = crate::fs::shm::user_dir()?;
    dir.extend_from_slice(format!("/v{}-cgroup", crate::shared::FORMAT).as_bytes());
    if std::fs::create_dir(os(&dir)).is_ok()
        || !std::path::Path::new(os(&dir)).join("cgroup.procs").exists()
    {
        let all = CONTROLLERS.join(" ") + "\n";
        let cpus = all_cpus();
        for name in ROOT_FILES {
            // Written as they are made: the read-only ones cannot be after.
            let content = match *name {
                "cgroup.controllers" => all.as_str(),
                "cpuset.cpus.effective" => cpus.as_str(),
                "cpuset.mems.effective" => "0\n",
                _ => "",
            };
            let writable = !matches!(
                *name,
                "cgroup.controllers"
                    | "cgroup.stat"
                    | "cpuset.cpus.effective"
                    | "cpuset.mems.effective"
            );
            put(&dir, name, content, writable);
        }
    }
    Ok(dir)
}

/// The host directory of cgroup `cg` (a path from the root).
pub fn host_dir(cg: &[u8]) -> Result<Vec<u8>, i32> {
    Ok(crate::mounts::join(&tree_dir()?, cg))
}

/// The cgroup a host path in the tree is (or is in), and the file it names
/// there, if any.
pub fn locate(host: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let top = tree_dir().ok()?;
    let rest = crate::mounts::under(host, &top)?;
    let p = if rest.is_empty() { b"/".to_vec() } else { rest.to_vec() };
    if std::path::Path::new(os(host)).is_dir() {
        return Some((p, None));
    }
    let (dir, name) = match p.iter().rposition(|&b| b == b'/') {
        Some(0) => (b"/".to_vec(), p[1..].to_vec()),
        Some(i) => (p[..i].to_vec(), p[i + 1..].to_vec()),
        None => return None,
    };
    Some((dir, Some(name)))
}

fn read_words(path: &[u8]) -> Vec<String> {
    std::fs::read_to_string(os(path))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The controllers cgroup `cg` may use: all at the root, else those its
/// parent enables.
pub fn controllers(cg: &[u8]) -> Vec<String> {
    if cg == b"/" {
        return CONTROLLERS.iter().map(|c| c.to_string()).collect();
    }
    let parent = crate::fs::normalize(cg, b"..");
    match host_dir(&parent) {
        Ok(d) => read_words(&[&d[..], b"/cgroup.subtree_control"].concat()),
        Err(_) => Vec::new(),
    }
}

/// A new cgroup's files, after the `mkdir` that made it at host path `dir`.
pub fn made(dir: &[u8]) {
    let Some((cg, None)) = locate(dir) else { return };
    for (name, content, writable) in CORE_FILES {
        put(dir, name, content, *writable);
    }
    let enabled = controllers(&cg);
    let _ = std::fs::write(os(&[dir, b"/cgroup.controllers"].concat()), enabled.join(" ") + "\n");
    let cpus = all_cpus();
    for (ctl, name, content, writable) in CONTROLLER_FILES {
        if enabled.iter().any(|e| e == ctl) {
            // Every CPU is the cgroup's: none is held back.
            let content = if *name == "cpuset.cpus.effective" { cpus.as_str() } else { content };
            put(dir, name, content, *writable);
        }
    }
}

/// The processes in cgroup `cg` (host pids), or in it and every cgroup
/// below it with `subtree`.
pub fn members(cg: &[u8], subtree: bool) -> Vec<i32> {
    procreg::all()
        .into_iter()
        .filter(|(_, r)| r.cgroup == cg || subtree && crate::mounts::under(&r.cgroup, cg).is_some())
        .map(|(pid, _)| pid)
        .collect()
}

fn children(dir: &[u8]) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(os(dir)) else { return Vec::new() };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()) && e.file_name().as_bytes() != PRIVATE)
        .map(|e| e.file_name().as_bytes().to_vec())
        .collect()
}

/// `rmdir` of the cgroup at host path `dir`: `EBUSY` while it has processes
/// or children, else it and its files go.
pub fn remove(dir: &[u8]) -> Result<(), i32> {
    let Some((cg, None)) = locate(dir) else { return Err(errno::ENOTDIR) };
    if cg == b"/" {
        return Err(errno::EBUSY);
    }
    if !children(dir).is_empty() || !members(&cg, false).is_empty() {
        return Err(errno::EBUSY);
    }
    std::fs::remove_dir_all(os(dir))
        .map_err(|e| e.raw_os_error().map_or(errno::EIO, crate::host::errno_to_linux))
}

/// The task count, resident memory and CPU time (in microseconds) of host
/// process `pid`.
fn usage(pid: i32) -> (u64, u64, u64, u64) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zeroed bytes are a valid `proc_taskinfo`, which the call fills.
        let mut t: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        // SAFETY: a valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                (&mut t as *mut libc::proc_taskinfo).cast(),
                size,
            )
        };
        if n == size {
            return (
                t.pti_threadnum as u64,
                t.pti_resident_size,
                // In Mach time units: microseconds here.
                crate::procpid::mach_to_ns(t.pti_total_user) / 1000,
                crate::procpid::mach_to_ns(t.pti_total_system) / 1000,
            );
        }
        (1, 0, 0, 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        (1, 0, 0, 0)
    }
}

/// Bring the file `name` of cgroup `cg` (host directory `dir`) up to date
/// before it is opened, for the files whose content is what is so now.
pub fn refresh(dir: &[u8], cg: &[u8], name: &[u8]) {
    let write = |content: String| replace(&[dir, b"/", name].concat(), content);
    let lines = |pids: Vec<i32>| {
        let mut v: Vec<i32> =
            pids.into_iter().map(crate::pidns::to_guest).filter(|&p| p != 0).collect();
        v.sort_unstable();
        v.iter().map(|p| format!("{p}\n")).collect::<String>()
    };
    match name {
        b"cgroup.procs" => write(lines(members(cg, false))),
        // Every thread of each member, its main thread by its pid.
        b"cgroup.threads" => {
            let mut v: Vec<i32> = Vec::new();
            for p in members(cg, false) {
                let pid = crate::pidns::to_guest(p);
                if pid == 0 {
                    continue;
                }
                v.push(pid);
                let tids = if p == crate::host::pid() {
                    crate::thread::tids()
                } else {
                    crate::thread::published_tids(p)
                };
                v.extend(tids.into_iter().filter(|&t| t != pid && t > 0));
            }
            v.sort_unstable();
            v.dedup();
            write(v.iter().map(|t| format!("{t}\n")).collect());
        }
        b"cgroup.events" => {
            let populated = !members(cg, true).is_empty();
            let f = frozen(cg);
            write(format!("populated {}\nfrozen {}\n", u8::from(populated), u8::from(f)));
        }
        b"cgroup.stat" => {
            let n = count_descendants(dir);
            write(format!("nr_descendants {n}\nnr_dying_descendants 0\n"));
        }
        b"pids.current" => {
            let n: u64 = members(cg, true).into_iter().map(|p| usage(p).0).sum();
            write(format!("{n}\n"));
        }
        b"memory.current" => {
            let n: u64 = members(cg, true).into_iter().map(|p| usage(p).1).sum();
            write(format!("{n}\n"));
        }
        b"cpu.stat" => {
            let (u, s) = members(cg, true)
                .into_iter()
                .map(usage)
                .fold((0, 0), |(u, s), x| (u + x.2, s + x.3));
            write(format!("usage_usec {}\nuser_usec {u}\nsystem_usec {s}\n", u + s));
        }
        _ => {}
    }
}

/// Make `content` what the interface file at host path `p` holds,
/// through a fresh file: the guest's descriptor of the old one, if it
/// holds one, keeps what it read. The file keeps the owner and mode the
/// guest gave it (a runtime delegates a cgroup by giving its files away).
fn replace(p: &[u8], content: String) {
    let tmp = [p, b".fwe-new"].concat();
    let old = guest_stat(p);
    if std::fs::write(os(&tmp), content).is_err() {
        return;
    }
    if let Ok(f) = std::fs::File::open(os(&tmp)) {
        use std::os::fd::AsRawFd;
        let (owner, perm) =
            old.map_or(((0, 0), 0o444), |st| ((st.st_uid, st.st_gid), crate::modes::perm_of(&st)));
        let _ = crate::owners::keep_fd(f.as_raw_fd(), owner);
        let _ = crate::modes::keep_fd(f.as_raw_fd(), perm);
    }
    let _ = std::fs::rename(os(&tmp), os(p));
}

fn count_descendants(dir: &[u8]) -> usize {
    children(dir).iter().map(|c| 1 + count_descendants(&[dir, b"/", c].concat())).sum()
}

/// A write of `data` to file `name` of cgroup `cg` (host directory `dir`):
/// what the write does, as Linux does it.
pub fn write(dir: &[u8], cg: &[u8], name: &[u8], data: &[u8]) -> Result<(), i32> {
    let text = std::str::from_utf8(data).map_err(|_| errno::EINVAL)?;
    let store = |content: String| -> Result<(), i32> {
        std::fs::write(os(&[dir, b"/", name].concat()), content)
            .map_err(|e| e.raw_os_error().map_or(errno::EIO, crate::host::errno_to_linux))
    };
    match name {
        b"cgroup.procs" | b"cgroup.threads" => {
            let threads = name == b"cgroup.threads";
            for word in text.split_whitespace() {
                let id: i32 = word.parse().map_err(|_| errno::EINVAL)?;
                let host = if threads { thread_process(id)? } else { process(id)? };
                let from = procreg::cgroup_of(host);
                may_move(&from, cg)?;
                if threads {
                    // One thread apart from its process takes a threaded
                    // cgroup, which fwe does not make: only where it is.
                    if from != cg {
                        return Err(errno::EOPNOTSUPP);
                    }
                    continue;
                }
                may_join(cg)?;
                procreg::set_cgroup(host, cg)?;
                changed();
                // A process moved into a frozen cgroup is frozen, out of
                // one thawed.
                let (was, is) = (frozen(&from), frozen(cg));
                if was != is {
                    crate::host::kill_process(host, if is { libc::SIGSTOP } else { libc::SIGCONT });
                }
            }
            Ok(())
        }
        // Only a domain: a threaded cgroup fwe does not make.
        b"cgroup.type" => match text.trim() {
            "threaded" => Err(errno::EOPNOTSUPP),
            _ => Err(errno::EINVAL),
        },
        b"cgroup.max.depth" | b"cgroup.max.descendants" => {
            let v = text.trim();
            if v != "max" && v.parse::<u32>().is_err() {
                return Err(errno::EINVAL);
            }
            store(format!("{v}\n"))
        }
        b"cgroup.subtree_control" => {
            let mut enabled = read_words(&[dir, b"/cgroup.subtree_control"].concat());
            let available = controllers(cg);
            for word in text.split_whitespace() {
                let (on, ctl) = match word.as_bytes().first() {
                    Some(b'+') => (true, &word[1..]),
                    Some(b'-') => (false, &word[1..]),
                    _ => return Err(errno::EINVAL),
                };
                if !available.iter().any(|c| c == ctl) {
                    return Err(errno::ENOENT);
                }
                if on && cg != b"/" && !members(cg, false).is_empty() {
                    return Err(errno::EBUSY);
                }
                let kids = children(dir);
                if !on
                    && kids.iter().any(|k| {
                        read_words(&[dir, b"/", k, b"/cgroup.subtree_control"].concat())
                            .iter()
                            .any(|c| c == ctl)
                    })
                {
                    return Err(errno::EBUSY);
                }
                if on && !enabled.iter().any(|c| c == ctl) {
                    enabled.push(ctl.to_string());
                }
                if !on {
                    enabled.retain(|c| c != ctl);
                }
                // The children's files for it come and go.
                for k in kids {
                    let child = [dir, b"/", &k].concat();
                    for (c, file, content, writable) in CONTROLLER_FILES {
                        if *c != ctl {
                            continue;
                        }
                        if on {
                            let cpus = all_cpus();
                            let content = if *file == "cpuset.cpus.effective" {
                                cpus.as_str()
                            } else {
                                content
                            };
                            put(&child, file, content, *writable);
                        } else {
                            let _ = std::fs::remove_file(os(
                                &[&child[..], b"/", file.as_bytes()].concat()
                            ));
                        }
                    }
                }
            }
            enabled.sort_by_key(|c| CONTROLLERS.iter().position(|k| k == c));
            store(enabled.join(" ") + "\n")?;
            for k in children(dir) {
                let child = [dir, b"/", &k].concat();
                let _ = std::fs::write(
                    os(&[&child[..], b"/cgroup.controllers"].concat()),
                    enabled.join(" ") + "\n",
                );
            }
            Ok(())
        }
        b"cgroup.freeze" => {
            let on = match text.trim() {
                "1" => true,
                "0" => false,
                _ => return Err(errno::EINVAL),
            };
            store(format!("{}\n", u8::from(on)))?;
            // Each process below takes the state its cgroup now has: one
            // in a cgroup a cgroup above it freezes stays frozen.
            let mut known: std::collections::HashMap<Vec<u8>, bool> = Default::default();
            for (pid, r) in procreg::all() {
                if r.cgroup != cg && crate::mounts::under(&r.cgroup, cg).is_none() {
                    continue;
                }
                let f = *known.entry(r.cgroup.clone()).or_insert_with(|| frozen(&r.cgroup));
                crate::host::kill_process(pid, if f { libc::SIGSTOP } else { libc::SIGCONT });
            }
            Ok(())
        }
        b"cgroup.kill" => {
            if text.trim() != "1" {
                return Err(errno::EINVAL);
            }
            for pid in members(cg, true).into_iter().filter(|&p| p > 0) {
                // Relayed, so a VM process takes its VM down first.
                crate::host::kill_process(pid, libc::SIGKILL);
            }
            Ok(())
        }
        b"pids.max" | b"memory.max" | b"memory.high" | b"memory.low" | b"memory.min"
        | b"memory.swap.max" => {
            let v = text.trim();
            let parsed =
                if v == "max" { Some(v.to_string()) } else { parse_size(v).map(|n| n.to_string()) };
            store(parsed.ok_or(errno::EINVAL)? + "\n")?;
            if name == b"pids.max" {
                changed();
            }
            Ok(())
        }
        b"cpu.max" => {
            let mut w = text.split_whitespace();
            let quota = w.next().ok_or(errno::EINVAL)?;
            let period = w.next().unwrap_or("100000");
            if quota != "max" && quota.parse::<u64>().is_err() || period.parse::<u64>().is_err() {
                return Err(errno::EINVAL);
            }
            store(format!("{quota} {period}\n"))
        }
        b"cpu.weight" => {
            let n: u64 = text.trim().parse().map_err(|_| errno::EINVAL)?;
            if !(1..=10000).contains(&n) {
                return Err(errno::ERANGE);
            }
            store(format!("{n}\n"))
        }
        _ => store(text.trim_end().to_string() + "\n"),
    }
}

/// A size with an optional `K`, `M`, `G` or `T` suffix.
fn parse_size(v: &str) -> Option<u64> {
    let (num, mul) = match v.as_bytes().last()? {
        b'K' | b'k' => (&v[..v.len() - 1], 1u64 << 10),
        b'M' | b'm' => (&v[..v.len() - 1], 1 << 20),
        b'G' | b'g' => (&v[..v.len() - 1], 1 << 30),
        b'T' | b't' => (&v[..v.len() - 1], 1 << 40),
        _ => (v, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mul)
}

/// Whether a process may join cgroup `cg`: not one that enables
/// controllers for its children, but at the root (`EBUSY`).
pub fn may_join(cg: &[u8]) -> Result<(), i32> {
    let dir = host_dir(cg)?;
    if cg != b"/" && !read_words(&[&dir[..], b"/cgroup.subtree_control"].concat()).is_empty() {
        return Err(errno::EBUSY);
    }
    Ok(())
}

/// Cgroup `cg` and each cgroup above it, up to the root.
fn ancestors(cg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![cg.to_vec()];
    while out.last().is_some_and(|c| c != b"/") {
        let up = crate::fs::normalize(out.last().unwrap_or(&b"/".to_vec()), b"..");
        out.push(up);
    }
    out
}

/// Whether cgroup `cg` is frozen: its own `cgroup.freeze`, or one above
/// it, says so.
pub fn frozen(cg: &[u8]) -> bool {
    ancestors(cg).iter().any(|c| {
        host_dir(c).is_ok_and(|d| {
            read_words(&[&d[..], b"/cgroup.freeze"].concat()).first().is_some_and(|w| w == "1")
        })
    })
}

/// Whether one more task in cgroup `cg` stays within the `pids.max` of
/// it and every cgroup above it (`EAGAIN` otherwise, counted in the
/// `pids.events` of the cgroup whose limit it is).
pub fn fork_allowed(cg: &[u8]) -> Result<(), i32> {
    for at in ancestors(cg) {
        let Ok(dir) = host_dir(&at) else { continue };
        if let Some(max) = read_words(&[&dir[..], b"/pids.max"].concat()).first()
            && let Ok(max) = max.parse::<u64>()
        {
            let n: u64 = members(&at, true).into_iter().map(|p| usage(p).0).sum();
            if n >= max {
                count_max_event(&dir);
                return Err(errno::EAGAIN);
            }
        }
    }
    Ok(())
}

/// One more task refused for the `pids.max` of the cgroup at `dir`.
fn count_max_event(dir: &[u8]) {
    let p = [dir, b"/pids.events"].concat();
    let words = read_words(&p);
    let n: u64 = words.get(1).and_then(|w| w.parse().ok()).unwrap_or(0);
    replace(&p, format!("max {}\n", n + 1));
}

/// A record whose generation moves whenever a process changes cgroup or
/// a `pids.max` changes: what [`thread_allowed`] knows of the process's
/// cgroups is good until it moves.
fn moves() -> Option<&'static crate::shared::Record<crate::sysctl::Globals>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<crate::sysctl::Globals>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| {
        crate::shared::Record::named("cgroupmoves", 0, crate::sysctl::Globals::default).ok()
    })
    .as_ref()
}

/// A process changed cgroup, or a `pids.max` changed.
fn changed() {
    if let Some(r) = moves() {
        let _ = r.update(|_| Ok(()));
    }
}

/// [`moves`]'s generation when this process last looked at its cgroups
/// (`u64::MAX`: never), and whether a `pids.max` was set in one of them.
static SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static LIMITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// This process was just forked: it may be in another cgroup than its
/// parent (`CLONE_INTO_CGROUP`), so it looks again.
pub fn forked() {
    SEEN.store(u64::MAX, std::sync::atomic::Ordering::Release);
}

/// Whether a new thread of this process stays within the `pids.max` of
/// its cgroups (`EAGAIN` otherwise). Most cgroups set none: whether one
/// does is looked at again only after a process moved or a limit changed.
pub fn thread_allowed() -> Result<(), i32> {
    use std::sync::atomic::Ordering;
    let Some(r) = moves() else { return Ok(()) };
    let now = r.generation();
    if SEEN.load(Ordering::Acquire) != now {
        let limited = ancestors(&current()).iter().any(|c| {
            host_dir(c).is_ok_and(|d| {
                read_words(&[&d[..], b"/pids.max"].concat())
                    .first()
                    .is_some_and(|w| w.parse::<u64>().is_ok())
            })
        });
        LIMITED.store(limited, Ordering::Release);
        SEEN.store(now, Ordering::Release);
    }
    if LIMITED.load(Ordering::Acquire) { fork_allowed(&current()) } else { Ok(()) }
}

/// Whether this process may have one more thread: within `RLIMIT_NPROC`
/// (the tasks of its real user, unless it is exempt) and the `pids.max`
/// of its cgroups ([`thread_allowed`]); `EAGAIN` otherwise.
pub fn task_allowed() -> Result<(), i32> {
    use fwe_abi::resource::{RLIM_INFINITY, RLIMIT_NPROC};
    let (nproc, _) = crate::rlimits::get(RLIMIT_NPROC);
    if nproc != RLIM_INFINITY
        && let Some(uid) = crate::creds::nproc_user()
    {
        let tasks: u64 = procreg::all()
            .into_iter()
            .filter(|(_, r)| r.ids[0] == uid)
            .map(|(p, _)| usage(p).0)
            .sum();
        if tasks >= nproc {
            return Err(errno::EAGAIN);
        }
    }
    thread_allowed()
}

/// The host process of pid `pid` (0: this one) of the caller's pid
/// namespace.
fn process(pid: i32) -> Result<i32, i32> {
    if pid < 0 {
        return Err(errno::EINVAL);
    }
    if pid == 0 { Ok(crate::host::pid()) } else { crate::pidns::host_arg(pid) }
}

/// The host process thread `tid` (0: the caller) is in.
fn thread_process(tid: i32) -> Result<i32, i32> {
    if tid == 0 || crate::thread::tids().contains(&tid) {
        return Ok(crate::host::pid());
    }
    match crate::thread::owner_of_tid(tid) {
        Some(p) => Ok(p),
        None => process(tid),
    }
}

/// The root of the cgroup namespace of the process (or of the thread
/// that runs a call), which a move must stay inside (`nsdelegate`).
static NS_ROOT: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// The process's cgroup namespace's root is cgroup `root`.
pub fn set_ns_root(root: &[u8]) {
    *NS_ROOT.lock().unwrap_or_else(|e| e.into_inner()) = root.to_vec();
}

fn ns_root() -> Vec<u8> {
    let r = NS_ROOT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if r.is_empty() { b"/".to_vec() } else { r }
}

/// Whether the caller may move a process from cgroup `from` to `to`, as
/// Linux's delegation has it: both inside its cgroup namespace (the
/// hierarchy is mounted `nsdelegate`; `ENOENT` otherwise), and write
/// access to `cgroup.procs` of the cgroup both are in (`EACCES`).
pub fn may_move(from: &[u8], to: &[u8]) -> Result<(), i32> {
    let root = ns_root();
    let inside = |c: &[u8]| c == root.as_slice() || crate::mounts::under(c, &root).is_some();
    if !inside(from) || !inside(to) {
        return Err(errno::ENOENT);
    }
    let a = ancestors(from);
    let common = ancestors(to).into_iter().find(|c| a.contains(c)).unwrap_or(b"/".to_vec());
    let file = [&host_dir(&common)?[..], b"/cgroup.procs"].concat();
    match guest_stat(&file) {
        Some(st) if crate::creds::access().permits(&st, 2) => Ok(()),
        _ => Err(errno::EACCES),
    }
}

/// The metadata the guest sees of the host file at `path`: its owner and
/// mode as fwe keeps them.
fn guest_stat(path: &[u8]) -> Option<libc::stat> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: a NUL-terminated path; the descriptor is closed below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: zeroed bytes are a valid `stat`, which the call fills.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter for the descriptor just opened.
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    if ok {
        let owner = crate::owners::of_fd(fd, &st);
        let perm = crate::modes::guest_perm_fd(fd, &st);
        crate::owners::apply(&mut st, owner);
        crate::modes::apply(&mut st, perm);
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(fd) };
    ok.then_some(st)
}

/// Whether a cgroup may be made in the cgroup at host directory `parent`:
/// within the `cgroup.max.descendants` and `cgroup.max.depth` of it and
/// every cgroup above it (`EAGAIN` otherwise).
pub fn may_make(parent: &[u8]) -> Result<(), i32> {
    let Some((cg, None)) = locate(parent) else { return Ok(()) };
    for (level, at) in ancestors(&cg).iter().enumerate() {
        let dir = host_dir(at)?;
        let limit = |name: &[u8]| {
            read_words(&[&dir[..], b"/", name].concat())
                .first()
                .and_then(|w| w.parse::<usize>().ok())
                .unwrap_or(usize::MAX)
        };
        if count_descendants(&dir) >= limit(b"cgroup.max.descendants")
            || level + 1 > limit(b"cgroup.max.depth")
        {
            return Err(errno::EAGAIN);
        }
    }
    Ok(())
}

/// This process's cgroup, a path from the hierarchy's root.
pub fn current() -> Vec<u8> {
    procreg::own_cgroup()
}

/// `/proc/<pid>/cgroup` of a process in cgroup `cg`, for a reader whose
/// cgroup namespace's root is `ns_root`: the cgroup's path from that
/// root, through `..` for one outside it, as Linux shows it.
pub fn proc_cgroup(cg: &[u8], ns_root: &[u8]) -> Vec<u8> {
    [b"0::", &relative(cg, ns_root)[..], b"\n"].concat()
}

/// Cgroup `cg` as a path from cgroup `root`.
fn relative(cg: &[u8], root: &[u8]) -> Vec<u8> {
    let parts = |p: &[u8]| -> Vec<Vec<u8>> {
        p.split(|&b| b == b'/').filter(|s| !s.is_empty()).map(<[u8]>::to_vec).collect()
    };
    let (cg, root) = (parts(cg), parts(root));
    let common = cg.iter().zip(&root).take_while(|(a, b)| a == b).count();
    let mut out = Vec::new();
    for _ in common..root.len() {
        out.extend_from_slice(b"/..");
    }
    for p in &cg[common..] {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

// --- device programs ---------------------------------------------------------

/// Attach device program `prog` (its instructions), with identity `id`, to
/// the cgroup at host directory `dir`.
pub fn attach(dir: &[u8], id: u32, prog: &[u8]) -> Result<(), i32> {
    let d = [dir, b"/", PRIVATE].concat();
    let _ = std::fs::create_dir(os(&d));
    std::fs::write(os(&[&d[..], format!("/{id}").as_bytes()].concat()), prog)
        .map_err(|e| e.raw_os_error().map_or(errno::EIO, crate::host::errno_to_linux))
}

/// Detach the device program `id` from the cgroup at `dir`.
pub fn detach(dir: &[u8], id: u32) -> Result<(), i32> {
    let p = [dir, b"/", PRIVATE, format!("/{id}").as_bytes()].concat();
    std::fs::remove_file(os(&p)).map_err(|_| errno::ENOENT)
}

/// The device programs attached to the cgroup at `dir`: their identities.
pub fn attached(dir: &[u8]) -> Vec<u32> {
    let d = [dir, b"/", PRIVATE].concat();
    let Ok(entries) = std::fs::read_dir(os(&d)) else { return Vec::new() };
    let mut ids: Vec<u32> =
        entries.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
    ids.sort_unstable();
    ids
}

/// The program with identity `id`, wherever in the tree it is attached.
pub fn find(id: u32) -> Option<Vec<u8>> {
    fn walk(dir: &[u8], id: u32) -> Option<Vec<u8>> {
        let p = [dir, b"/", PRIVATE, format!("/{id}").as_bytes()].concat();
        if let Ok(b) = std::fs::read(os(&p)) {
            return Some(b);
        }
        children(dir).iter().find_map(|c| walk(&[dir, b"/", c].concat(), id))
    }
    walk(&tree_dir().ok()?, id)
}

/// Whether this process may make the device access `access`
/// (`BPF_DEVCG_ACC_*`) to device `major:minor` of type `dev_type`: every
/// device program attached to its cgroup or one above it must allow it.
pub fn device_allowed(access: u32, dev_type: u32, major: u32, minor: u32) -> bool {
    let mut at = current();
    loop {
        if let Ok(dir) = host_dir(&at) {
            for id in attached(&dir) {
                let p = [&dir[..], b"/", PRIVATE, format!("/{id}").as_bytes()].concat();
                let Ok(bytes) = std::fs::read(os(&p)) else { continue };
                let allowed = crate::bpf::load(&bytes)
                    .ok()
                    .and_then(|prog| crate::bpf::run(&prog, access, dev_type, major, minor))
                    .is_some_and(|v| v != 0);
                if !allowed {
                    return false;
                }
            }
        }
        if at == b"/" {
            return true;
        }
        at = crate::fs::normalize(&at, b"..");
    }
}

/// `EPERM` unless [`device_allowed`].
pub fn check_device(access: u32, dev_type: u32, major: u32, minor: u32) -> Result<(), i32> {
    if device_allowed(access, dev_type, major, minor) { Ok(()) } else { Err(errno::EPERM) }
}

/// A write of `len` bytes, `data` the first of them, to `fd`: for a
/// cgroup's interface file, what the write does (`Some` result); `None`
/// for any other descriptor ([`crate::specialwrite`]).
pub fn try_write(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    let host = crate::fdmarks::cgroup_file(fd)?;
    let (cg, Some(name)) = locate(&host)? else { return None };
    // Writable only if opened so.
    // SAFETY: plain host call.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl & libc::O_ACCMODE == libc::O_RDONLY {
        return Some(err(errno::EBADF));
    }
    let dir = host_dir(&cg).ok()?;
    Some(match write(&dir, &cg, &name, data) {
        Ok(()) => len as i64,
        Err(e) => err(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cgroup is shown from the reader's namespace root, through `..`
    /// for one outside it.
    #[test]
    fn cgroups_relative_to_the_namespace_root() {
        assert_eq!(proc_cgroup(b"/a/b", b"/"), b"0::/a/b\n");
        assert_eq!(proc_cgroup(b"/a/b", b"/a"), b"0::/b\n");
        assert_eq!(proc_cgroup(b"/a", b"/a"), b"0::/\n");
        assert_eq!(proc_cgroup(b"/a/c", b"/a/b"), b"0::/../c\n");
        assert_eq!(proc_cgroup(b"/", b"/a/b"), b"0::/../..\n");
    }

    /// A cgroup of the test's own, with `children` below it: its path and
    /// host directory, and theirs.
    fn made_tree(tag: &str, children: &[&str]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cg = format!("/fwe-unit-{tag}-{}", std::process::id()).into_bytes();
        let mut out = vec![cg.clone()];
        out.extend(children.iter().map(|c| [&cg[..], b"/", c.as_bytes()].concat()));
        out.into_iter()
            .map(|c| {
                let dir = host_dir(&c).unwrap();
                std::fs::create_dir(os(&dir)).unwrap();
                made(&dir);
                (c, dir)
            })
            .collect()
    }

    /// `cgroup.max.depth` and `cgroup.max.descendants` hold a new cgroup
    /// (`EAGAIN`), and take only `max` or a count; `cgroup.type` takes no
    /// threaded cgroup.
    #[test]
    fn hierarchy_limits_and_type() {
        let t = made_tree("limits", &["a"]);
        let ((cg, dir), (_, a)) = (&t[0], &t[1]);
        assert_eq!(write(dir, cg, b"cgroup.type", b"threaded"), Err(errno::EOPNOTSUPP));
        assert_eq!(write(dir, cg, b"cgroup.type", b"domain"), Err(errno::EINVAL));
        assert_eq!(write(dir, cg, b"cgroup.max.depth", b"-1"), Err(errno::EINVAL));
        assert_eq!(may_make(a), Ok(()));
        write(dir, cg, b"cgroup.max.depth", b"1").unwrap();
        assert_eq!(may_make(dir), Ok(()));
        assert_eq!(may_make(a), Err(errno::EAGAIN));
        write(dir, cg, b"cgroup.max.depth", b"max").unwrap();
        write(dir, cg, b"cgroup.max.descendants", b"1").unwrap();
        assert_eq!(may_make(dir), Err(errno::EAGAIN));
        let _ = std::fs::remove_dir_all(os(dir));
    }

    /// A cgroup is frozen while it or one above it freezes it, which its
    /// `cgroup.events` shows.
    #[test]
    fn freezing_is_hierarchical() {
        let t = made_tree("freeze", &["k"]);
        let ((cg, dir), (k, kdir)) = (&t[0], &t[1]);
        write(dir, cg, b"cgroup.freeze", b"1").unwrap();
        assert!(frozen(k));
        write(kdir, k, b"cgroup.freeze", b"0").unwrap();
        assert!(frozen(k));
        refresh(kdir, k, b"cgroup.events");
        let events = std::fs::read(os(&[&kdir[..], b"/cgroup.events"].concat())).unwrap();
        assert_eq!(events, b"populated 0\nfrozen 1\n");
        write(dir, cg, b"cgroup.freeze", b"0").unwrap();
        assert!(!frozen(k));
        let _ = std::fs::remove_dir_all(os(dir));
    }
}
