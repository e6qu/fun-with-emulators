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
//!   enables; `rmdir` removes an empty one (`EBUSY` while it has processes
//!   or children).
//! - Writing a pid to `cgroup.procs` moves the process; the file lists the
//!   members when opened, as do `cgroup.events`, `pids.current`,
//!   `memory.current` and `cpu.stat` what they report.
//! - `cgroup.subtree_control` enables controllers for the children, with
//!   Linux's rule that a cgroup with processes has none enabled for
//!   children (the root aside).
//! - `cgroup.freeze` stops and continues the members, `cgroup.kill` kills
//!   them, `pids.max` limits `fork`, and device programs attached to a
//!   cgroup ([`crate::bpf`]) decide every device access of its members.
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
    let write = |content: String| {
        let p = [dir, b"/", name].concat();
        // Through a fresh file: the guest's descriptor of the old one, if
        // it holds one, keeps what it read.
        let tmp = [&p[..], b".fwe-new"].concat();
        if std::fs::write(os(&tmp), content).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(os(&p)).map(|m| m.permissions().mode()).unwrap_or(0o444);
            let _ = std::fs::set_permissions(os(&tmp), std::fs::Permissions::from_mode(mode));
            let _ = std::fs::rename(os(&tmp), os(&p));
        }
    };
    let lines = |pids: Vec<i32>| {
        let mut v: Vec<i32> =
            pids.into_iter().map(crate::pidns::to_guest).filter(|&p| p != 0).collect();
        v.sort_unstable();
        v.iter().map(|p| format!("{p}\n")).collect::<String>()
    };
    match name {
        b"cgroup.procs" | b"cgroup.threads" => write(lines(members(cg, false))),
        b"cgroup.events" => {
            let populated = !members(cg, true).is_empty();
            let frozen =
                read_words(&[dir, b"/cgroup.freeze"].concat()).first().is_some_and(|w| w == "1");
            write(format!("populated {}\nfrozen {}\n", u8::from(populated), u8::from(frozen)));
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
        b"cgroup.procs" => {
            for word in text.split_whitespace() {
                let pid: i32 = word.parse().map_err(|_| errno::EINVAL)?;
                let host = if pid == 0 {
                    // SAFETY: getpid cannot fail.
                    unsafe { libc::getpid() }
                } else {
                    crate::pidns::host_arg(pid)?
                };
                // No processes in a cgroup that enables controllers for its
                // children, but at the root.
                if cg != b"/" && !read_words(&[dir, b"/cgroup.subtree_control"].concat()).is_empty()
                {
                    return Err(errno::EBUSY);
                }
                procreg::set_cgroup(host, cg)?;
            }
            Ok(())
        }
        // Moving single threads needs a threaded cgroup, which fwe does not
        // make.
        b"cgroup.threads" => Err(errno::EOPNOTSUPP),
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
            for pid in members(cg, true) {
                // SAFETY: plain host call.
                unsafe { libc::kill(pid, if on { libc::SIGSTOP } else { libc::SIGCONT }) };
            }
            store(format!("{}\n", u8::from(on)))
        }
        b"cgroup.kill" => {
            if text.trim() != "1" {
                return Err(errno::EINVAL);
            }
            for pid in members(cg, true) {
                // SAFETY: plain host call.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            Ok(())
        }
        b"pids.max" | b"memory.max" | b"memory.high" | b"memory.low" | b"memory.min"
        | b"memory.swap.max" => {
            let v = text.trim();
            let parsed =
                if v == "max" { Some(v.to_string()) } else { parse_size(v).map(|n| n.to_string()) };
            store(parsed.ok_or(errno::EINVAL)? + "\n")
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

/// Whether a `fork` in cgroup `cg` stays within the `pids.max` of it and
/// every cgroup above it (`EAGAIN` otherwise).
pub fn fork_allowed(cg: &[u8]) -> Result<(), i32> {
    let mut at = cg.to_vec();
    loop {
        if let Ok(dir) = host_dir(&at)
            && let Some(max) = read_words(&[&dir[..], b"/pids.max"].concat()).first()
            && let Ok(max) = max.parse::<u64>()
        {
            let n: u64 = members(&at, true).into_iter().map(|p| usage(p).0).sum();
            if n >= max {
                return Err(errno::EAGAIN);
            }
        }
        if at == b"/" {
            return Ok(());
        }
        at = crate::fs::normalize(&at, b"..");
    }
}

/// This process's cgroup, a path from the hierarchy's root.
pub fn current() -> Vec<u8> {
    procreg::own_cgroup()
}

/// `/proc/self/cgroup`: the cgroup from the cgroup namespace's root.
pub fn proc_self_cgroup(ns_root: &[u8]) -> Vec<u8> {
    let cg = current();
    let shown = match crate::mounts::under(&cg, ns_root) {
        Some(b"") => b"/".to_vec(),
        Some(r) => r.to_vec(),
        None => cg,
    };
    [b"0::", &shown[..], b"\n"].concat()
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
