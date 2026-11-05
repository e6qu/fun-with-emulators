//! The cgroup v2 hierarchy (`/sys/fs/cgroup`).
//!
//! Every fwe process of the user is somewhere in one tree, as a machine's
//! processes are, so the tree is shared: its cgroups are real directories
//! in fwe's private directory ([`tree_dir`]), which the `cgroup2` mount
//! shows, and a cgroup's interface files are files there, made when the
//! cgroup is.
//!
//! What a process's cgroup is lives with fwe's record of the process.

use fwe_abi::errno;

/// The controllers fwe's hierarchy offers.
pub const CONTROLLERS: &[u8] = b"cpuset cpu io memory hugetlb pids rdma misc";

/// The files every cgroup has, with what they start with; the root has
/// only the first few.
const CORE_FILES: &[(&[u8], &[u8])] = &[
    (b"cgroup.controllers", b""),
    (b"cgroup.subtree_control", b"\n"),
    (b"cgroup.procs", b""),
    (b"cgroup.threads", b""),
    (b"cgroup.type", b"domain\n"),
    (b"cgroup.max.depth", b"max\n"),
    (b"cgroup.max.descendants", b"max\n"),
    (b"cgroup.stat", b"nr_descendants 0\nnr_dying_descendants 0\n"),
    (b"cgroup.events", b"populated 0\nfrozen 0\n"),
    (b"cgroup.freeze", b"0\n"),
];

/// A non-root cgroup's files for its parent's enabled controllers.
const CONTROLLER_FILES: &[(&[u8], &[u8], &[u8])] = &[
    (b"memory", b"memory.max", b"max\n"),
    (b"memory", b"memory.high", b"max\n"),
    (b"memory", b"memory.low", b"0\n"),
    (b"memory", b"memory.min", b"0\n"),
    (b"memory", b"memory.swap.max", b"max\n"),
    (b"memory", b"memory.current", b"0\n"),
    (b"memory", b"memory.events", b"low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),
    (b"memory", b"memory.stat", b"anon 0\nfile 0\n"),
    (b"memory", b"memory.oom.group", b"0\n"),
    (b"pids", b"pids.max", b"max\n"),
    (b"pids", b"pids.current", b"0\n"),
    (b"pids", b"pids.events", b"max 0\n"),
    (b"cpu", b"cpu.max", b"max 100000\n"),
    (b"cpu", b"cpu.weight", b"100\n"),
    (b"cpu", b"cpu.weight.nice", b"0\n"),
    (b"cpu", b"cpu.stat", b"usage_usec 0\nuser_usec 0\nsystem_usec 0\n"),
    (b"cpuset", b"cpuset.cpus", b"\n"),
    (b"cpuset", b"cpuset.mems", b"\n"),
    (b"cpuset", b"cpuset.cpus.effective", b"\n"),
    (b"cpuset", b"cpuset.mems.effective", b"0\n"),
    (b"io", b"io.max", b""),
    (b"io", b"io.weight", b"default 100\n"),
    (b"io", b"io.stat", b""),
];

fn write_new(path: &[u8], content: &[u8]) {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::OsStr::from_bytes(path);
    if std::fs::symlink_metadata(p).is_err() {
        let _ = std::fs::write(p, content);
    }
}

/// Make the interface files of the cgroup at host path `dir`; `root` for
/// the hierarchy's root, which has no controller files of its own.
pub fn populate(dir: &[u8], root: bool) {
    for (name, content) in CORE_FILES {
        if root
            && !matches!(
                *name,
                b"cgroup.controllers"
                    | b"cgroup.subtree_control"
                    | b"cgroup.procs"
                    | b"cgroup.threads"
                    | b"cgroup.max.depth"
                    | b"cgroup.max.descendants"
                    | b"cgroup.stat"
            )
        {
            continue;
        }
        let content: &[u8] =
            if *name == b"cgroup.controllers" { &[CONTROLLERS, b"\n"].concat() } else { content };
        write_new(&[dir, b"/", name].concat(), content);
    }
    if root {
        return;
    }
    for (_, name, content) in CONTROLLER_FILES {
        write_new(&[dir, b"/", name].concat(), content);
    }
}

/// The host directory of the hierarchy's root, made on first use.
pub fn tree_dir() -> Result<Vec<u8>, i32> {
    let mut dir = crate::fs::shm::user_dir()?;
    dir.extend_from_slice(b"/cgroup");
    let c = std::ffi::CString::new(dir.clone()).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(c.as_ptr(), 0o755) };
    populate(&dir, true);
    Ok(dir)
}

/// This process's cgroup, a path from the hierarchy's root.
pub fn current() -> Vec<u8> {
    b"/".to_vec()
}
