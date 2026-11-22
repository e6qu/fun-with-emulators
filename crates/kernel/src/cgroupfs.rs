//! The cgroup v2 hierarchy (`/sys/fs/cgroup`).
//!
//! Every fwe process of the user is somewhere in one tree, as a machine's
//! processes are, so the tree is shared: a filesystem of fwe's store
//! ([`tree`]), in memory every fwe process of the user maps, which a
//! `cgroup2` mount shows. Its cgroups are directories there, a cgroup's
//! interface files are files in them, and the device programs attached to
//! a cgroup are attributes of its directory that no listing shows. What a
//! process's cgroup is lives in fwe's record of the process
//! ([`crate::procreg`]).
//!
//! fwe does what the files say where it can:
//!
//! - `mkdir` makes a cgroup with the files of the controllers its parent
//!   enables, within `cgroup.max.depth` and `cgroup.max.descendants` up
//!   the tree, its files its creator's (a controller's files are whoever
//!   enables the controller); `rmdir` removes an empty one (`EBUSY`
//!   while it has processes or children). Making, removing and moving into
//!   one take the hierarchy's lock ([`TreeLock`]), so they happen one at a
//!   time across processes, as under Linux's `cgroup_mutex`.
//! - Writing a pid to `cgroup.procs` moves the process, by Linux's
//!   delegation rules (write access to the common ancestor's
//!   `cgroup.procs`, within the writer's cgroup namespace); the file lists
//!   the members when opened, as `cgroup.threads` their threads, and
//!   `cgroup.events`, `pids.current`, `memory.current` and `cpu.stat`
//!   what they report. Only domain cgroups are made: `cgroup.type` refuses
//!   `threaded`.
//! - `cgroup.subtree_control` enables controllers for the children, with
//!   Linux's rule that a cgroup with processes has none enabled for
//!   children (the root aside), and its parsing: a controller Linux lacks
//!   is `EINVAL`, one the cgroup may not use `ENOENT`.
//! - `cgroup.freeze` stops and continues the members of the cgroup and
//!   those below it, and whoever joins or is forked into a frozen one;
//!   `cgroup.kill` kills them; `pids.max` limits `fork` and new threads
//!   (counted in `pids.events`); and device programs attached to a cgroup
//!   ([`crate::bpf`]) decide every device access of its members.
//! - The other limits are kept and read back but not enforced: the host has
//!   no way to hold a process to a memory or CPU budget. Each is parsed as
//!   Linux parses it (`pids.max` a whole number, a memory limit a size
//!   kept in whole pages).

use crate::filestore::data;
use crate::filestore::fs::Fs;
use crate::filestore::tree::{Gone, Ino, New, S_IFDIR, S_IFMT, S_IFREG, Tx};
use crate::procreg;
use fwe_abi::{err, errno};
use std::sync::Arc;

/// The controllers fwe's hierarchy offers.
pub const CONTROLLERS: &[&str] =
    &["cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"];

/// The attributes of a cgroup's directory holding the device programs
/// attached to it, `<this><id>`: a name no guest can give an attribute.
const PROGRAM: &[u8] = b"\0bpf.";

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

/// The hierarchy's filesystem of fwe's store: the user's, of this layout.
pub fn tree_id() -> u64 {
    0x6367_0000_0000_0000 | crate::shared::FORMAT as u64
}

/// The hierarchy, its root's files made on first use: a root directory
/// root's that only it may change, as Linux makes a hierarchy's root.
pub fn tree() -> Result<Arc<Fs>, i32> {
    static READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let f = crate::filestore::fs::lasting(tree_id(), 0o555)?;
    if !READY.load(std::sync::atomic::Ordering::Acquire) {
        let mut t = f.lock()?;
        let root = t.root();
        if t.lookup(root, b"cgroup.procs").is_err() {
            let all = CONTROLLERS.join(" ") + "\n";
            let cpus = all_cpus();
            for name in ROOT_FILES {
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
                put_new(&mut t, root, name, content, writable, (0, 0))?;
            }
        }
        drop(t);
        READY.store(true, std::sync::atomic::Ordering::Release);
    }
    Ok(f)
}

/// The hierarchy's lock, held while a cgroup is made or removed or a
/// process moved, as Linux's `cgroup_mutex` holds them apart: a removal's
/// look for children and members stands until it is done, so no `mkdir`
/// below it or move into it comes between. Every fwe process of the user
/// takes it: a lock in the process store
/// ([`crate::procstore::Area::CgroupTree`]), taken over from a holder that
/// ended.
pub struct TreeLock {
    _held: crate::procstore::Held,
}

/// Take the hierarchy's lock ([`TreeLock`]).
pub fn lock_tree() -> Result<TreeLock, i32> {
    Ok(TreeLock { _held: crate::procstore::lock_area(crate::procstore::Area::CgroupTree) })
}

/// `f` with the hierarchy held.
fn in_tree<R>(f: impl FnOnce(&mut Tx) -> Result<R, i32>) -> Result<R, i32> {
    let fs = tree()?;
    let mut t = fs.lock()?;
    f(&mut t)
}

/// The directory of cgroup `cg` (a path from the root).
fn dir_in(t: &Tx, cg: &[u8]) -> Result<Ino, i32> {
    let mut at = t.root();
    for c in cg.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
        at = t.lookup(at, c)?;
        if t.stat(at)?.mode & S_IFMT != S_IFDIR {
            return Err(errno::ENOTDIR);
        }
    }
    Ok(at)
}

/// Its data object goes with an inode that went.
fn drop_gone(g: Gone) {
    if let Some(o) = g.data.filter(|&o| o != 0) {
        data::remove(o);
    }
}

/// What regular file `ino` holds.
fn content(t: &mut Tx, ino: Ino) -> Result<Vec<u8>, i32> {
    let size = t.stat(ino)?.size;
    let (object, n) = t.readable(ino, 0, size)?;
    let mut buf = vec![0u8; n as usize];
    if n > 0 {
        data::read(object, 0, &mut buf)?;
    }
    Ok(buf)
}

/// Make `content` what file `name` of directory `dir` holds: a new file in
/// its place (a descriptor of the one there keeps what it read, as a
/// reader of a cgroup's file on Linux keeps what it was shown), with
/// permission bits `perm` and `owner`.
fn put(
    t: &mut Tx,
    dir: Ino,
    name: &[u8],
    content: &[u8],
    perm: u32,
    owner: (u32, u32),
) -> Result<(), i32> {
    // Made under a name no one sees: the filesystem is held throughout
    // (one a process that ended while holding it left goes first).
    const NEW: &[u8] = b".fwe-new";
    if t.lookup(dir, NEW).is_ok() {
        drop_gone(t.unlink(dir, NEW, false)?);
    }
    let ino =
        t.create(dir, NEW, &New { mode: S_IFREG | perm, uid: owner.0, gid: owner.1, rdev: 0 })?;
    if !content.is_empty() {
        let w = t.writable(ino, 0, content.len() as u64, false)?;
        data::write(w.object, 0, &content[..w.fits as usize])?;
        t.wrote(ino, w.fits)?;
    }
    if let Some(g) = t.rename(dir, NEW, dir, name, 0)? {
        drop_gone(g);
    }
    Ok(())
}

/// Make interface file `name` of directory `dir`, if it is not there, with
/// `content`, owned by `owner`, as Linux's `cgroup_kn_set_ugid` gives a
/// cgroup's files to whoever makes them: the cgroup's creator, or for a
/// controller's files whoever enables the controller.
fn put_new(
    t: &mut Tx,
    dir: Ino,
    name: &str,
    content: &str,
    writable: bool,
    owner: (u32, u32),
) -> Result<(), i32> {
    if t.lookup(dir, name.as_bytes()).is_ok() {
        return Ok(());
    }
    put(t, dir, name.as_bytes(), content.as_bytes(), if writable { 0o644 } else { 0o444 }, owner)
}

/// The caller's file-system user and group: who owns what it makes.
fn maker() -> (u32, u32) {
    let a = crate::creds::access();
    (a.fsuid, a.fsgid)
}

/// What file `name` of cgroup `cg` holds (nothing where it has none).
fn read_file(cg: &[u8], name: &[u8]) -> String {
    let bytes = in_tree(|t| {
        let ino = t.lookup(dir_in(t, cg)?, name)?;
        content(t, ino)
    });
    String::from_utf8(bytes.unwrap_or_default()).unwrap_or_default()
}

fn read_words(cg: &[u8], name: &[u8]) -> Vec<String> {
    read_file(cg, name).split_whitespace().map(str::to_owned).collect()
}

/// Make `content` what the existing file `name` of cgroup `cg` holds, its
/// owner and mode kept (a runtime delegates a cgroup by giving its files
/// away).
fn set(cg: &[u8], name: &[u8], content: &[u8]) -> Result<(), i32> {
    in_tree(|t| {
        let dir = dir_in(t, cg).map_err(|_| errno::ENODEV)?;
        let st = t.stat(t.lookup(dir, name)?)?;
        put(t, dir, name, content, st.mode & 0o7777, (st.uid, st.gid))
    })
}

/// The cgroup directory `ino` of store filesystem `fs` is, if it is one: its
/// path from the root.
pub fn cgroup_at(fs: u64, ino: Ino) -> Option<Vec<u8>> {
    if fs != tree_id() {
        return None;
    }
    tree().ok()?.lock().ok()?.path(ino)
}

/// The cgroup whose directory `fd` is open on: `EBADF` for no descriptor,
/// `EINVAL` for one of another file.
pub fn of_fd(fd: i32) -> Result<Vec<u8>, i32> {
    // SAFETY: plain host call.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(errno::EBADF);
    }
    let file = crate::filestore::desc::of(fd).ok_or(errno::EINVAL)?;
    cgroup_at(file.fs, file.ino).ok_or(errno::EINVAL)
}

/// The cgroup and the name of the interface file `fd` is open on, if it is
/// one.
pub fn file_of(fd: i32) -> Option<(Vec<u8>, Vec<u8>)> {
    let file = crate::filestore::desc::of(fd)?;
    if file.fs != tree_id() {
        return None;
    }
    let (dir, name) = crate::filestore::desc::place(fd)?;
    Some((cgroup_at(file.fs, dir)?, name))
}

/// The controllers cgroup `cg` may use: all at the root, else those its
/// parent enables.
pub fn controllers(cg: &[u8]) -> Vec<String> {
    if cg == b"/" {
        return CONTROLLERS.iter().map(|c| c.to_string()).collect();
    }
    read_words(&crate::fs::normalize(cg, b".."), b"cgroup.subtree_control")
}

/// A new cgroup `cg`'s files, made by the caller after the `mkdir` that
/// made its directory.
pub fn made(cg: &[u8]) -> Result<(), i32> {
    let enabled = controllers(cg);
    let owner = maker();
    in_tree(|t| {
        let dir = dir_in(t, cg)?;
        for (name, content, writable) in CORE_FILES {
            let content = if *name == "cgroup.controllers" {
                enabled.join(" ") + "\n"
            } else {
                content.to_string()
            };
            put_new(t, dir, name, &content, *writable, owner)?;
        }
        let cpus = all_cpus();
        for (ctl, name, content, writable) in CONTROLLER_FILES {
            if enabled.iter().any(|e| e == ctl) {
                // Every CPU is the cgroup's: none is held back.
                let content =
                    if *name == "cpuset.cpus.effective" { cpus.as_str() } else { content };
                put_new(t, dir, name, content, *writable, owner)?;
            }
        }
        Ok(())
    })
}

/// The processes in cgroup `cg` (host pids), or in it and every cgroup
/// below it with `subtree`.
pub fn members(cg: &[u8], subtree: bool) -> Vec<i32> {
    procreg::all()
        .into_iter()
        .filter(|(_, r)| {
            r.cgroup() == cg || subtree && crate::mounts::under(r.cgroup(), cg).is_some()
        })
        .map(|(pid, _)| pid)
        .collect()
}

/// The names of the cgroups directly below directory `dir`.
fn children(t: &Tx, dir: Ino) -> Vec<Vec<u8>> {
    t.list(dir, 0, usize::MAX, 0)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.kind == S_IFDIR && e.name != b"." && e.name != b"..")
        .map(|e| e.name)
        .collect()
}

/// `rmdir` of cgroup `cg`: `EBUSY` while it has processes or children
/// (the root always), else it and its files go.
pub fn remove(cg: &[u8]) -> Result<(), i32> {
    if cg == b"/" {
        return Err(errno::EBUSY);
    }
    let _held = lock_tree()?;
    let members = members(cg, false);
    in_tree(|t| {
        let dir = dir_in(t, cg)?;
        if !children(t, dir).is_empty() || !members.is_empty() {
            return Err(errno::EBUSY);
        }
        for e in t.list(dir, 0, usize::MAX, 0)? {
            if e.kind != S_IFDIR {
                drop_gone(t.unlink(dir, &e.name, false)?);
            }
        }
        let parent = dir_in(t, &crate::fs::normalize(cg, b".."))?;
        let name = cg.rsplit(|&b| b == b'/').next().unwrap_or_default();
        drop_gone(t.unlink(parent, name, true)?);
        Ok(())
    })
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

/// Bring the file `name` of cgroup `cg` up to date before it is opened,
/// for the files whose content is what is so now: a new file where what
/// it holds changed.
pub fn refresh(cg: &[u8], name: &[u8]) {
    let write = |now: String| {
        let _ = in_tree(|t| {
            let dir = dir_in(t, cg)?;
            let ino = t.lookup(dir, name)?;
            if content(t, ino)? == now.as_bytes() {
                return Ok(());
            }
            let st = t.stat(ino)?;
            put(t, dir, name, now.as_bytes(), st.mode & 0o7777, (st.uid, st.gid))
        });
    };
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
            let n = in_tree(|t| Ok(count_descendants(t, dir_in(t, cg)?))).unwrap_or(0);
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

fn count_descendants(t: &Tx, dir: Ino) -> usize {
    children(t, dir)
        .iter()
        .map(|c| 1 + t.lookup(dir, c).map_or(0, |d| count_descendants(t, d)))
        .sum()
}

/// A write of `data` to file `name` of cgroup `cg`: what the write does,
/// as Linux does it.
pub fn write(cg: &[u8], name: &[u8], data: &[u8]) -> Result<(), i32> {
    let text = std::str::from_utf8(data).map_err(|_| errno::EINVAL)?;
    let store = |content: String| set(cg, name, content.as_bytes());
    match name {
        b"cgroup.procs" | b"cgroup.threads" => {
            let threads = name == b"cgroup.threads";
            // (Not into a cgroup being removed.)
            let _held = lock_tree()?;
            in_tree(|t| dir_in(t, cg)).map_err(|_| errno::ENODEV)?;
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
            let mut enabled = read_words(cg, b"cgroup.subtree_control");
            let changes = subtree_changes(text, &enabled, &controllers(cg))?;
            let members = members(cg, false);
            let owner = maker();
            in_tree(|t| {
                let dir = dir_in(t, cg).map_err(|_| errno::ENODEV)?;
                let kids: Vec<Ino> =
                    children(t, dir).iter().filter_map(|k| t.lookup(dir, k).ok()).collect();
                for &(on, ctl) in &changes {
                    if !on
                        && kids.iter().any(|&k| {
                            t.lookup(k, b"cgroup.subtree_control")
                                .and_then(|f| content(t, f))
                                .is_ok_and(|c| {
                                    String::from_utf8_lossy(&c).split_whitespace().any(|c| c == ctl)
                                })
                        })
                    {
                        return Err(errno::EBUSY);
                    }
                }
                if changes.iter().any(|&(on, _)| on) && cg != b"/" && !members.is_empty() {
                    return Err(errno::EBUSY);
                }
                let cpus = all_cpus();
                for (on, ctl) in changes {
                    if on {
                        enabled.push(ctl.to_string());
                    } else {
                        enabled.retain(|c| c != ctl);
                    }
                    // The children's files for it come and go.
                    for &k in &kids {
                        for (c, file, content, writable) in CONTROLLER_FILES {
                            if *c != ctl {
                                continue;
                            }
                            if on {
                                let content = if *file == "cpuset.cpus.effective" {
                                    cpus.as_str()
                                } else {
                                    content
                                };
                                put_new(t, k, file, content, *writable, owner)?;
                            } else if t.lookup(k, file.as_bytes()).is_ok() {
                                drop_gone(t.unlink(k, file.as_bytes(), false)?);
                            }
                        }
                    }
                }
                enabled.sort_by_key(|c| CONTROLLERS.iter().position(|k| k == c));
                let line = enabled.join(" ") + "\n";
                let st = t.stat(t.lookup(dir, b"cgroup.subtree_control")?)?;
                put(
                    t,
                    dir,
                    b"cgroup.subtree_control",
                    line.as_bytes(),
                    st.mode & 0o7777,
                    (st.uid, st.gid),
                )?;
                for &k in &kids {
                    let st = t.stat(t.lookup(k, b"cgroup.controllers")?)?;
                    put(
                        t,
                        k,
                        b"cgroup.controllers",
                        line.as_bytes(),
                        st.mode & 0o7777,
                        (st.uid, st.gid),
                    )?;
                }
                Ok(())
            })
        }
        b"cgroup.freeze" => {
            let on = match text.trim() {
                "1" => true,
                "0" => false,
                _ => return Err(errno::EINVAL),
            };
            store(format!("{}\n", u8::from(on)))?;
            changed();
            // Each process below takes the state its cgroup now has: one
            // in a cgroup a cgroup above it freezes stays frozen.
            let mut known: std::collections::HashMap<Vec<u8>, bool> = Default::default();
            for (pid, r) in procreg::all() {
                if r.cgroup() != cg && crate::mounts::under(r.cgroup(), cg).is_none() {
                    continue;
                }
                let f = *known.entry(r.cgroup().to_vec()).or_insert_with(|| frozen(r.cgroup()));
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
        b"pids.max" => {
            store(pids_max(text.trim())? + "\n")?;
            changed();
            Ok(())
        }
        b"memory.max" | b"memory.high" | b"memory.low" | b"memory.min" | b"memory.swap.max" => {
            store(memory_limit(text.trim())? + "\n")
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

/// The changes a write of `text` to `cgroup.subtree_control` asks, as
/// Linux's `cgroup_subtree_control_write` reads them: every word `+name`
/// or `-name` of a controller Linux has (`EINVAL` otherwise, before
/// anything changes), the last word for a controller winning; enabling
/// one the cgroup may not use (not in `available`) is `ENOENT`; enabling
/// what is `enabled` already, or disabling what is not, is nothing.
fn subtree_changes<'a>(
    text: &'a str,
    enabled: &[String],
    available: &[String],
) -> Result<Vec<(bool, &'a str)>, i32> {
    let mut asked: Vec<(bool, &str)> = Vec::new();
    for word in text.split_whitespace() {
        let (on, ctl) = match word.as_bytes().first() {
            Some(b'+') => (true, &word[1..]),
            Some(b'-') => (false, &word[1..]),
            _ => return Err(errno::EINVAL),
        };
        if !CONTROLLERS.contains(&ctl) {
            return Err(errno::EINVAL);
        }
        asked.retain(|&(_, c)| c != ctl);
        asked.push((on, ctl));
    }
    let mut changes = Vec::new();
    for c in CONTROLLERS {
        let Some(&(on, ctl)) = asked.iter().find(|(_, a)| a == c) else { continue };
        let is_on = enabled.iter().any(|e| e == ctl);
        if on == is_on {
            continue;
        }
        if on && !available.iter().any(|a| a == ctl) {
            return Err(errno::ENOENT);
        }
        changes.push((on, ctl));
    }
    Ok(changes)
}

/// A number as the kernel's `simple_strtoull` and `kstrtoull` read one in
/// base 0: hexadecimal after `0x`, octal after `0`, else decimal; the
/// number (`None` past 64 bits) and what follows it.
fn parse_number(v: &str) -> Option<(Option<u64>, &str)> {
    let (digits, radix) = if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        (h, 16)
    } else if v.len() > 1 && v.starts_with('0') {
        (&v[1..], 8)
    } else {
        (v, 10)
    };
    let end = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    Some((u64::from_str_radix(&digits[..end], radix).ok(), &digits[end..]))
}

/// The most `pids.max` may be: Linux's `PIDS_MAX` (`PID_MAX_LIMIT` + 1)
/// less one.
const PIDS_MAX: u64 = 4 * 1024 * 1024;

/// A value written to `pids.max`, as Linux's `pids_max_write` takes it:
/// `max`, or a whole number (an optional sign, then base 0, nothing
/// after) from 0 to `PIDS_MAX`; `EINVAL` otherwise (`ERANGE` past 64
/// bits). The value as the file keeps it.
fn pids_max(v: &str) -> Result<String, i32> {
    if v == "max" {
        return Ok(v.to_string());
    }
    let (neg, digits) = match v.as_bytes().first() {
        Some(b'-') => (true, &v[1..]),
        Some(b'+') => (false, &v[1..]),
        _ => (false, v),
    };
    let (n, rest) = parse_number(digits).ok_or(errno::EINVAL)?;
    if !rest.is_empty() {
        return Err(errno::EINVAL);
    }
    let n = n.ok_or(errno::ERANGE)?;
    if neg && n != 0 || n > PIDS_MAX {
        return Err(errno::EINVAL);
    }
    Ok(n.to_string())
}

/// A value written to a memory limit (`memory.max` and the like), as
/// Linux's `page_counter_memparse` takes it: `max`, or a size (base 0,
/// then an optional `K`, `M`, `G`, `T`, `P` or `E`, in either case, and
/// nothing after; `EINVAL` otherwise), kept in whole pages, so the file
/// reads it rounded down to a page.
fn memory_limit(v: &str) -> Result<String, i32> {
    if v == "max" {
        return Ok(v.to_string());
    }
    let (n, rest) = parse_number(v).ok_or(errno::EINVAL)?;
    // Too large for 64 bits: no limit.
    let n = n.unwrap_or(u64::MAX);
    let shift = match rest {
        "" => 0,
        "K" | "k" => 10,
        "M" | "m" => 20,
        "G" | "g" => 30,
        "T" | "t" => 40,
        "P" | "p" => 50,
        "E" | "e" => 60,
        _ => return Err(errno::EINVAL),
    };
    // Bits shifted out are lost, as `memparse` loses them.
    let bytes = n.wrapping_shl(shift);
    // `PAGE_COUNTER_MAX`: anything larger reads as `max`.
    let pages = bytes / 4096;
    if pages >= i64::MAX as u64 / 4096 {
        return Ok("max".to_string());
    }
    Ok((pages * 4096).to_string())
}

/// Whether a process may join cgroup `cg`: not one that enables
/// controllers for its children, but at the root (`EBUSY`).
pub fn may_join(cg: &[u8]) -> Result<(), i32> {
    if cg != b"/" && !read_words(cg, b"cgroup.subtree_control").is_empty() {
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

/// Cgroup `cg` and each cgroup above it but the root, which has no
/// `pids.max` or `cgroup.freeze` to read (a task of the root's has none
/// of them).
fn below_root(cg: &[u8]) -> impl Iterator<Item = Vec<u8>> {
    ancestors(cg).into_iter().filter(|c| c != b"/")
}

/// Whether cgroup `cg` is frozen: its own `cgroup.freeze`, or one above
/// it, says so.
pub fn frozen(cg: &[u8]) -> bool {
    below_root(cg).any(|c| read_words(&c, b"cgroup.freeze").first().is_some_and(|w| w == "1"))
}

/// Whether one more task in cgroup `cg` stays within the `pids.max` of
/// it and every cgroup above it (`EAGAIN` otherwise, counted in the
/// `pids.events` of the cgroup whose limit it is).
pub fn fork_allowed(cg: &[u8]) -> Result<(), i32> {
    for at in below_root(cg) {
        if let Some(max) = read_words(&at, b"pids.max").first()
            && let Ok(max) = max.parse::<u64>()
        {
            let n: u64 = members(&at, true).into_iter().map(|p| usage(p).0).sum();
            if n >= max {
                count_max_event(&at);
                return Err(errno::EAGAIN);
            }
        }
    }
    Ok(())
}

/// One more task refused for the `pids.max` of cgroup `cg`.
fn count_max_event(cg: &[u8]) {
    let words = read_words(cg, b"pids.events");
    let n: u64 = words.get(1).and_then(|w| w.parse().ok()).unwrap_or(0);
    let _ = set(cg, b"pids.events", format!("max {}\n", n + 1).as_bytes());
}

/// A record whose generation moves whenever a process changes cgroup, or
/// a `pids.max` or `cgroup.freeze` changes: what [`looked`] knows of the
/// process's cgroups is good until it moves.
fn moves() -> Option<&'static crate::shared::Record<crate::sysctl::Globals>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<crate::sysctl::Globals>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| {
        crate::shared::Record::named("cgroupmoves", 0, crate::sysctl::Globals::default).ok()
    })
    .as_ref()
}

/// A process changed cgroup, or a `pids.max` or `cgroup.freeze` changed.
fn changed() {
    if let Some(r) = moves() {
        let _ = r.update(|_| Ok(()));
    }
}

/// [`moves`]'s generation when this process last looked at its cgroups
/// (`u64::MAX`: never), whether a `pids.max` was set in one of them, and
/// whether one of them was frozen.
static SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static LIMITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a `pids.max` is set in this process's cgroup or one above it,
/// and whether one of them is frozen: looked at again only after a process
/// moved or a limit or freeze changed ([`moves`]), every time without the
/// record that tells.
fn looked() -> (bool, bool) {
    use std::sync::atomic::Ordering;
    let look = || {
        let cg = current();
        let limited = below_root(&cg)
            .any(|c| read_words(&c, b"pids.max").first().is_some_and(|w| w.parse::<u64>().is_ok()));
        (limited, frozen(&cg))
    };
    let Some(r) = moves() else { return look() };
    let now = r.generation();
    if SEEN.load(Ordering::Acquire) != now {
        let (limited, frozen) = look();
        LIMITED.store(limited, Ordering::Release);
        FROZEN.store(frozen, Ordering::Release);
        SEEN.store(now, Ordering::Release);
    }
    (LIMITED.load(Ordering::Acquire), FROZEN.load(Ordering::Acquire))
}

/// Whether a child may start in cgroup `cg` (this process's own if
/// `None`): within the `pids.max` of it and those above it (`EAGAIN`
/// otherwise); and whether it starts frozen.
pub fn fork_checks(cg: Option<&[u8]>) -> Result<bool, i32> {
    match cg {
        Some(cg) => {
            fork_allowed(cg)?;
            Ok(frozen(cg))
        }
        None => {
            let (limited, frozen) = looked();
            if limited {
                fork_allowed(&current())?;
            }
            Ok(frozen)
        }
    }
}

/// This process was just forked: it may be in another cgroup than its
/// parent (`CLONE_INTO_CGROUP`), so it looks again.
pub fn forked() {
    SEEN.store(u64::MAX, std::sync::atomic::Ordering::Release);
}

/// Whether a new thread of this process stays within the `pids.max` of
/// its cgroups (`EAGAIN` otherwise). Most cgroups set none: whether one
/// does is looked at again only after a process moved or a limit changed.
pub fn thread_allowed() -> Result<(), i32> {
    if looked().0 { fork_allowed(&current()) } else { Ok(()) }
}

/// Whether this process may have one more thread: within `RLIMIT_NPROC`
/// (the tasks of its real user, unless it is exempt) and the `pids.max`
/// of its cgroups ([`thread_allowed`]); `EAGAIN` otherwise.
pub fn task_allowed() -> Result<(), i32> {
    use fwe_abi::resource::{RLIM_INFINITY, RLIMIT_NPROC};
    let (nproc, _) = crate::rlimits::get(RLIMIT_NPROC);
    if nproc != RLIM_INFINITY
        && let Some(uid) = crate::creds::nproc_user()
        && user_tasks(uid) >= nproc
    {
        return Err(errno::EAGAIN);
    }
    thread_allowed()
}

/// How many tasks (threads, in every process) of fwe's processes have
/// real user `uid`: what `RLIMIT_NPROC` counts, as Linux counts a user's
/// tasks.
pub fn user_tasks(uid: u32) -> u64 {
    // Every pid with a record first, without reading one: a process gone
    // without its record removed (killed, its parent not fwe) counts there
    // until a listing finds it gone, so only the processes alive count
    // where the user is at a limit.
    let all = crate::procstore::user_tasks(uid, crate::procstore::pids());
    let nproc = crate::rlimits::get(fwe_abi::resource::RLIMIT_NPROC).0;
    if all < nproc {
        return all;
    }
    crate::procstore::user_tasks(uid, procreg::all().into_iter().map(|(p, _)| p))
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
    let st = in_tree(|t| {
        let ino = t.lookup(dir_in(t, &common)?, b"cgroup.procs")?;
        Ok(crate::filestore::io::host_stat(t.dev(), &t.stat(ino)?))
    });
    match st {
        Ok(st) if crate::creds::access().permits(&st, 2) => Ok(()),
        _ => Err(errno::EACCES),
    }
}

/// Whether a cgroup may be made in cgroup `parent`: within the
/// `cgroup.max.descendants` and `cgroup.max.depth` of it and every cgroup
/// above it (`EAGAIN` otherwise).
pub fn may_make(parent: &[u8]) -> Result<(), i32> {
    for (level, at) in ancestors(parent).iter().enumerate() {
        let limit = |name: &[u8]| {
            read_words(at, name).first().and_then(|w| w.parse::<usize>().ok()).unwrap_or(usize::MAX)
        };
        let descendants = in_tree(|t| Ok(count_descendants(t, dir_in(t, at)?)))?;
        if descendants >= limit(b"cgroup.max.descendants") || level + 1 > limit(b"cgroup.max.depth")
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

/// The attribute holding device program `id`.
fn program(id: u32) -> Vec<u8> {
    [PROGRAM, id.to_string().as_bytes()].concat()
}

/// Attach device program `prog` (its instructions), with identity `id`, to
/// cgroup `cg`.
pub fn attach(cg: &[u8], id: u32, prog: &[u8]) -> Result<(), i32> {
    in_tree(|t| {
        let dir = dir_in(t, cg)?;
        t.set_xattr(dir, &program(id), Some(prog))
    })
}

/// Detach the device program `id` from cgroup `cg`.
pub fn detach(cg: &[u8], id: u32) -> Result<(), i32> {
    in_tree(|t| {
        let dir = dir_in(t, cg)?;
        t.xattr(dir, &program(id)).map_err(|_| errno::ENOENT)?;
        t.set_xattr(dir, &program(id), None)
    })
}

/// The device programs attached to directory `dir`: their identities and
/// instructions, by identity.
fn programs(t: &Tx, dir: Ino) -> Vec<(u32, Vec<u8>)> {
    let mut out: Vec<(u32, Vec<u8>)> = t
        .xattrs(dir)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, prog)| {
            let id = std::str::from_utf8(name.strip_prefix(PROGRAM)?).ok()?.parse().ok()?;
            Some((id, prog))
        })
        .collect();
    out.sort_unstable_by_key(|&(id, _)| id);
    out
}

/// The device programs attached to cgroup `cg`: their identities.
pub fn attached(cg: &[u8]) -> Vec<u32> {
    in_tree(|t| Ok(programs(t, dir_in(t, cg)?).into_iter().map(|(id, _)| id).collect()))
        .unwrap_or_default()
}

/// The program with identity `id`, wherever in the tree it is attached.
pub fn find(id: u32) -> Option<Vec<u8>> {
    in_tree(|t| Ok(t.inodes().into_iter().find_map(|ino| t.xattr(ino, &program(id)).ok())))
        .ok()
        .flatten()
}

/// Whether this process may make the device access `access`
/// (`BPF_DEVCG_ACC_*`) to device `major:minor` of type `dev_type`: every
/// device program attached to its cgroup or one above it must allow it.
pub fn device_allowed(access: u32, dev_type: u32, major: u32, minor: u32) -> bool {
    let progs: Vec<Vec<u8>> = in_tree(|t| {
        let mut out = Vec::new();
        for at in ancestors(&current()) {
            if let Ok(dir) = dir_in(t, &at) {
                out.extend(programs(t, dir).into_iter().map(|(_, p)| p));
            }
        }
        Ok(out)
    })
    .unwrap_or_default();
    progs.iter().all(|bytes| {
        crate::bpf::load(bytes)
            .ok()
            .and_then(|prog| crate::bpf::run(&prog, access, dev_type, major, minor))
            .is_some_and(|v| v != 0)
    })
}

/// `EPERM` unless [`device_allowed`].
pub fn check_device(access: u32, dev_type: u32, major: u32, minor: u32) -> Result<(), i32> {
    if device_allowed(access, dev_type, major, minor) { Ok(()) } else { Err(errno::EPERM) }
}

/// A write of `len` bytes, `data` the first of them, to `fd`: for a
/// cgroup's interface file, what the write does (`Some` result); `None`
/// for any other descriptor ([`crate::specialwrite`]).
pub fn try_write(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    let (cg, name) = crate::fdmarks::cgroup_file(fd)?;
    // Writable only if opened so.
    // SAFETY: plain host call.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl & libc::O_ACCMODE == libc::O_RDONLY {
        return Some(err(errno::EBADF));
    }
    Some(match write(&cg, &name, data) {
        Ok(()) => len as i64,
        Err(e) => err(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pids.max` takes `max` or a whole number up to `PIDS_MAX`, with no
    /// suffix; memory limits take a size with one, in whole pages.
    #[test]
    fn limits_parse_as_linux_parses_them() {
        assert_eq!(pids_max("max"), Ok("max".to_string()));
        assert_eq!(pids_max("10"), Ok("10".to_string()));
        assert_eq!(pids_max("0x10"), Ok("16".to_string()));
        assert_eq!(pids_max("+5"), Ok("5".to_string()));
        assert_eq!(pids_max("4194304"), Ok("4194304".to_string()));
        assert_eq!(pids_max("4194305"), Err(errno::EINVAL));
        assert_eq!(pids_max("1K"), Err(errno::EINVAL));
        assert_eq!(pids_max("-1"), Err(errno::EINVAL));
        assert_eq!(pids_max(""), Err(errno::EINVAL));
        assert_eq!(pids_max("99999999999999999999"), Err(errno::ERANGE));
        assert_eq!(memory_limit("max"), Ok("max".to_string()));
        assert_eq!(memory_limit("1K"), Ok("0".to_string()));
        assert_eq!(memory_limit("8k"), Ok("8192".to_string()));
        assert_eq!(memory_limit("1M"), Ok("1048576".to_string()));
        assert_eq!(memory_limit("5000"), Ok("4096".to_string()));
        assert_eq!(memory_limit("1Q"), Err(errno::EINVAL));
        assert_eq!(memory_limit("1KB"), Err(errno::EINVAL));
        assert_eq!(memory_limit("8E"), Ok("max".to_string()));
    }

    /// A cgroup of the test's own, below the root: made with its files.
    fn make(cg: &[u8]) {
        in_tree(|t| {
            let parent = dir_in(t, &crate::fs::normalize(cg, b".."))?;
            let name = cg.rsplit(|&b| b == b'/').next().unwrap();
            t.create(parent, name, &New { mode: S_IFDIR | 0o755, uid: 0, gid: 0, rdev: 0 })
        })
        .unwrap();
        made(cg).unwrap();
    }

    /// Cgroup `cg` and those below it go.
    fn unmake(cg: &[u8]) {
        let kids = in_tree(|t| Ok(children(t, dir_in(t, cg)?))).unwrap_or_default();
        for k in kids {
            unmake(&[cg, b"/", &k].concat());
        }
        remove(cg).unwrap();
    }

    /// The owner of file `name` of cgroup `cg`.
    fn owner(cg: &[u8], name: &[u8]) -> (u32, u32) {
        in_tree(|t| {
            let st = t.stat(t.lookup(dir_in(t, cg)?, name)?)?;
            Ok((st.uid, st.gid))
        })
        .unwrap()
    }

    /// A new cgroup's interface files are its creator's; a removed cgroup
    /// takes its files and device programs with it.
    #[test]
    fn a_new_cgroups_files_are_its_creators() {
        let cg = format!("/fwe-unit-owner-{}", std::process::id()).into_bytes();
        let creator = crate::creds::Access {
            fsuid: 1000,
            fsgid: 1001,
            groups: Vec::new(),
            dac_override: false,
            dac_read_search: false,
            scoped: false,
        };
        crate::creds::walking_as(creator, || make(&cg));
        for name in ["cgroup.procs", "cgroup.controllers", "cgroup.stat"] {
            assert_eq!(owner(&cg, name.as_bytes()), (1000, 1001), "{name}");
        }
        attach(&cg, 0xfeed_0001, b"prog").unwrap();
        assert_eq!(attached(&cg), vec![0xfeed_0001]);
        assert_eq!(find(0xfeed_0001).as_deref(), Some(&b"prog"[..]));
        let procs = in_tree(|t| t.lookup(dir_in(t, &cg)?, b"cgroup.procs")).unwrap();
        unmake(&cg);
        assert_eq!(find(0xfeed_0001), None);
        assert_eq!(in_tree(|t| t.stat(procs).map(|_| ())), Err(errno::ENOENT));
        assert_eq!(in_tree(|t| dir_in(t, &cg)), Err(errno::ENOENT));
    }

    /// A file's content is replaced by a new file: a descriptor of the old
    /// one keeps what it read, and a refresh that changes nothing makes
    /// none.
    #[test]
    fn a_refresh_makes_a_new_file_only_for_new_content() {
        let cg = format!("/fwe-unit-refresh-{}", std::process::id()).into_bytes();
        make(&cg);
        let ino = |name: &[u8]| in_tree(|t| t.lookup(dir_in(t, &cg)?, name)).unwrap();
        let first = ino(b"cgroup.events");
        refresh(&cg, b"cgroup.events");
        assert_eq!(ino(b"cgroup.events"), first);
        write(&cg, b"cgroup.freeze", b"1").unwrap();
        refresh(&cg, b"cgroup.events");
        assert_ne!(ino(b"cgroup.events"), first);
        assert_eq!(read_file(&cg, b"cgroup.events"), "populated 0\nfrozen 1\n");
        assert_eq!(read_file(&cg, b"cgroup.freeze"), "1\n");
        unmake(&cg);
    }

    /// `cgroup.subtree_control` refuses an unknown controller (`EINVAL`)
    /// and enabling one the cgroup may not use (`ENOENT`) before changing
    /// anything; disabling what is not enabled is nothing.
    #[test]
    fn subtree_control_words() {
        let all: Vec<String> = CONTROLLERS.iter().map(|c| c.to_string()).collect();
        let some = vec!["pids".to_string()];
        assert_eq!(subtree_changes("+pids +bogus", &[], &all), Err(errno::EINVAL));
        assert_eq!(subtree_changes("pids", &[], &all), Err(errno::EINVAL));
        assert_eq!(subtree_changes("+memory", &[], &some), Err(errno::ENOENT));
        assert_eq!(subtree_changes("-memory", &[], &some), Ok(vec![]));
        assert_eq!(subtree_changes("+pids", &some, &some), Ok(vec![]));
        assert_eq!(subtree_changes("+pids -pids", &[], &some), Ok(vec![]));
        assert_eq!(
            subtree_changes("+pids +memory", &[], &all),
            Ok(vec![(true, "memory"), (true, "pids")])
        );
    }

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
    /// theirs.
    fn made_tree(tag: &str, children: &[&str]) -> Vec<Vec<u8>> {
        let cg = format!("/fwe-unit-{tag}-{}", std::process::id()).into_bytes();
        let mut out = vec![cg.clone()];
        out.extend(children.iter().map(|c| [&cg[..], b"/", c.as_bytes()].concat()));
        for c in &out {
            make(c);
        }
        out
    }

    /// `cgroup.max.depth` and `cgroup.max.descendants` hold a new cgroup
    /// (`EAGAIN`), and take only `max` or a count; `cgroup.type` takes no
    /// threaded cgroup.
    #[test]
    fn hierarchy_limits_and_type() {
        let t = made_tree("limits", &["a"]);
        let (cg, a) = (&t[0], &t[1]);
        assert_eq!(write(cg, b"cgroup.type", b"threaded"), Err(errno::EOPNOTSUPP));
        assert_eq!(write(cg, b"cgroup.type", b"domain"), Err(errno::EINVAL));
        assert_eq!(write(cg, b"cgroup.max.depth", b"-1"), Err(errno::EINVAL));
        assert_eq!(may_make(a), Ok(()));
        write(cg, b"cgroup.max.depth", b"1").unwrap();
        assert_eq!(may_make(cg), Ok(()));
        assert_eq!(may_make(a), Err(errno::EAGAIN));
        write(cg, b"cgroup.max.depth", b"max").unwrap();
        write(cg, b"cgroup.max.descendants", b"1").unwrap();
        assert_eq!(may_make(cg), Err(errno::EAGAIN));
        unmake(cg);
    }

    /// A cgroup is frozen while it or one above it freezes it, which its
    /// `cgroup.events` shows.
    #[test]
    fn freezing_is_hierarchical() {
        let t = made_tree("freeze", &["k"]);
        let (cg, k) = (&t[0], &t[1]);
        write(cg, b"cgroup.freeze", b"1").unwrap();
        assert!(frozen(k));
        write(k, b"cgroup.freeze", b"0").unwrap();
        assert!(frozen(k));
        refresh(k, b"cgroup.events");
        assert_eq!(read_file(k, b"cgroup.events"), "populated 0\nfrozen 1\n");
        write(cg, b"cgroup.freeze", b"0").unwrap();
        assert!(!frozen(k));
        unmake(cg);
    }
}
