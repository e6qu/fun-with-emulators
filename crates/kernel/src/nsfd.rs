//! Namespace descriptors: `/proc/<pid>/ns/<kind>` opened, what `setns`
//! joins and the `NS_GET_*` requests ask about.
//!
//! A descriptor names a namespace by kind, identity and the directory of
//! its shared record ([`crate::shared::Record`]; none for an initial
//! namespace other than the mount namespace, whose initial table is a
//! record too). The process keeps that against a descriptor of an
//! anonymous file ([`Mark::Ns`]), which `fstat` shows as nsfs shows a
//! namespace: its identity is the inode. `setns` joins the namespace the
//! descriptor names, as `unshare` moves to a new one.

use crate::fdmarks::{self, Mark};
use crate::{Kernel, Platform, uaccess};
use fwe_abi::clone::*;
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// A namespace a descriptor names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NsRef {
    /// Its `CLONE_NEW*` type.
    pub kind: u64,
    /// Its identity (the number `/proc/<pid>/ns/<kind>` shows).
    pub id: u64,
    /// Its record's directory (none: the initial namespace of its kind).
    pub dir: Option<Vec<u8>>,
}

/// The `ioctl` requests on a namespace descriptor (`linux/nsfs.h`).
const NS_GET_USERNS: u64 = 0xb701;
const NS_GET_PARENT: u64 = 0xb702;
const NS_GET_NSTYPE: u64 = 0xb703;
const NS_GET_OWNER_UID: u64 = 0xb704;
const NS_GET_MNTNS_ID: u64 = 0x8008_b705;

/// The device nsfs's files are on.
pub const NSFS_DEV: (u32, u32) = (0, 4);

static FDS: Mutex<Option<HashMap<u32, NsRef>>> = Mutex::new(None);
static NEXT: AtomicU32 = AtomicU32::new(1);

fn with<R>(f: impl FnOnce(&mut HashMap<u32, NsRef>) -> R) -> R {
    let mut g = FDS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// The `CLONE_NEW*` type of `/proc/<pid>/ns` entry `name`.
pub fn kind_of(name: &[u8]) -> Option<u64> {
    Some(match name {
        b"uts" => CLONE_NEWUTS,
        b"ipc" => CLONE_NEWIPC,
        b"net" => CLONE_NEWNET,
        b"pid" | b"pid_for_children" => CLONE_NEWPID,
        b"user" => CLONE_NEWUSER,
        b"cgroup" => CLONE_NEWCGROUP,
        b"mnt" => CLONE_NEWNS,
        _ => return None,
    })
}

/// The name a namespace of `CLONE_NEW*` type `kind` goes by.
fn name_of(kind: u64) -> &'static str {
    match kind {
        CLONE_NEWUTS => "uts",
        CLONE_NEWIPC => "ipc",
        CLONE_NEWNET => "net",
        CLONE_NEWPID => "pid",
        CLONE_NEWUSER => "user",
        CLONE_NEWCGROUP => "cgroup",
        _ => "mnt",
    }
}

/// The record directory, among a process's namespace records `dirs`, of
/// its namespace named `name` (`pid` for `pid_for_children`).
pub fn dir_among(name: &[u8], dirs: &[Vec<u8>]) -> Option<Vec<u8>> {
    let k: &[u8] = if name == b"pid_for_children" { b"pid" } else { name };
    let prefix = [format!("v{}-", crate::shared::FORMAT).as_bytes(), k, b"-"].concat();
    dirs.iter()
        .find(|d| d.rsplit(|&b| b == b'/').next().is_some_and(|n| n.starts_with(&prefix)))
        .cloned()
}

/// The namespace descriptor `fd` is, if it is one.
pub fn of(fd: i32) -> Option<NsRef> {
    match fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() {
        Some(Mark::Ns(k)) => with(|m| m.get(&k).cloned()),
        _ => None,
    }
}

/// A read, write or copy of a namespace descriptor: refused (`EINVAL`),
/// as nsfs has neither. `None` for another descriptor.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    let rw = matches!(
        nr,
        n::READ
            | n::PREAD64
            | n::READV
            | n::PREADV
            | n::PREADV2
            | n::WRITE
            | n::PWRITE64
            | n::WRITEV
            | n::PWRITEV
            | n::PWRITEV2
    );
    // Copied from or to one, by `sendfile` (in, out), `splice` and
    // `copy_file_range` (in, out at 0 and 2).
    let copy = match nr {
        n::SENDFILE => of(a[0] as i32).is_some() || of(a[1] as i32).is_some(),
        n::SPLICE | n::COPY_FILE_RANGE => of(a[0] as i32).is_some() || of(a[2] as i32).is_some(),
        _ => false,
    };
    ((rw && of(a[0] as i32).is_some()) || copy).then(|| err(errno::EINVAL))
}

/// What `/proc/self/fd/<fd>` links to for a namespace descriptor.
pub fn target(fd: i32) -> Option<Vec<u8>> {
    of(fd).map(|n| format!("{}:[{}]", name_of(n.kind), n.id).into_bytes())
}

/// `fd` is closed: what it named goes with its last descriptor.
pub fn closed(fd: i32) {
    if fdmarks::shared_elsewhere(fd) {
        return;
    }
    if let Some(Mark::Ns(k)) = fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() {
        with(|m| m.remove(&k));
    }
}

/// A new descriptor of namespace `n`, close-on-exec if `cloexec`.
pub fn open(n: NsRef, cloexec: bool) -> i64 {
    let mut path = match crate::fs::shm::user_dir() {
        Ok(d) => d,
        Err(e) => return err(e),
    };
    path.extend_from_slice(b"/nsfd-XXXXXX\0");
    // SAFETY: a NUL-terminated template in fwe's private directory; the
    // file is unlinked at once, its descriptor kept.
    let fd = unsafe {
        let fd = libc::mkstemp(path.as_mut_ptr().cast());
        if fd >= 0 {
            libc::unlink(path.as_ptr().cast());
            libc::fcntl(fd, libc::F_SETFD, if cloexec { libc::FD_CLOEXEC } else { 0 });
        }
        fd
    };
    if fd < 0 {
        return crate::host::last_error();
    }
    let k = NEXT.fetch_add(1, Ordering::Relaxed);
    with(|m| m.insert(k, n));
    fdmarks::mark(fd, Mark::Ns(k));
    fd as i64
}

/// Write the process's namespace descriptors into a fork snapshot or exec
/// state (the descriptors go with it: [`crate::fdmarks`]).
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    e.u32(NEXT.load(Ordering::Relaxed));
    with(|m| {
        e.u64(m.len() as u64);
        for (&k, n) in m.iter() {
            e.u32(k);
            e.u64(n.kind);
            e.u64(n.id);
            e.bool(n.dir.is_some());
            e.bytes(n.dir.as_deref().unwrap_or_default());
        }
    });
}

/// What [`save`] wrote, in the new process.
pub(crate) fn load(d: &mut crate::snapshot::Dec) {
    NEXT.store(d.u32(), Ordering::Relaxed);
    let count = d.count(29);
    for _ in 0..count {
        let (k, kind, id, some, dir) = (d.u32(), d.u64(), d.u64(), d.bool(), d.bytes());
        with(|m| m.insert(k, NsRef { kind, id, dir: some.then_some(dir) }));
    }
}

/// The namespace the record at `dir` (with identity `id`) is inside, for
/// a user or pid namespace: its parent's directory and identity (none for
/// one inside the initial namespace).
fn parent_of(kind: u64, dir: &[u8], id: u64) -> Option<Option<(Vec<u8>, u64)>> {
    match kind {
        CLONE_NEWUSER => crate::shared::Record::<crate::userns::UserNs>::join(dir, id)
            .ok()
            .map(|r| r.get().parent.clone()),
        CLONE_NEWPID => crate::shared::Record::<crate::pidns::PidNs>::join(dir, id)
            .ok()
            .map(|r| r.get().parent.clone()),
        _ => None,
    }
}

impl<P: Platform> Kernel<P> {
    /// Open the namespace `/proc/<pid>/ns/<name>` names, for a process in
    /// the namespaces whose record directories are `dirs` (the caller's,
    /// for `self`); `link` is its link's text, `kind:[id]`.
    pub(crate) fn open_ns(&self, name: &[u8], dirs: &[Vec<u8>], link: &[u8], flags: u64) -> i64 {
        let Some(kind) = kind_of(name) else { return err(errno::ENOENT) };
        let id = link.iter().position(|&b| b == b'[').and_then(|o| {
            std::str::from_utf8(link[o + 1..].strip_suffix(b"]")?).ok()?.parse().ok()
        });
        let Some(id) = id else { return err(errno::ENOENT) };
        let dir = dir_among(name, dirs).or_else(|| {
            // The initial mount namespace's table is a record too.
            (kind == CLONE_NEWNS).then(|| self.fs().mount_ns().dir().to_vec())
        });
        open(NsRef { kind, id, dir }, flags & fwe_abi::fcntl::O_CLOEXEC != 0)
    }

    /// An `ioctl` on namespace descriptor `fd`: `None` for another one.
    pub(crate) fn ns_ioctl(&mut self, fd: i32, req: u64, arg: u64) -> Option<i64> {
        let n = of(fd)?;
        let fresh = |n: NsRef| open(n, true);
        Some(match req {
            NS_GET_NSTYPE => n.kind as i64,
            NS_GET_OWNER_UID => {
                if n.kind != CLONE_NEWUSER {
                    return Some(err(errno::EINVAL));
                }
                let owner = n
                    .dir
                    .as_ref()
                    .and_then(|d| {
                        crate::shared::Record::<crate::userns::UserNs>::join(d, n.id).ok()
                    })
                    .map_or(0, |r| r.get().owner);
                let uid = crate::userns::to_ns(owner, false);
                match uaccess::write(arg, uid) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            NS_GET_MNTNS_ID => {
                if n.kind != CLONE_NEWNS {
                    return Some(err(errno::EINVAL));
                }
                match uaccess::write(arg, n.id) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            NS_GET_PARENT | NS_GET_USERNS => {
                if req == NS_GET_PARENT && !matches!(n.kind, CLONE_NEWPID | CLONE_NEWUSER) {
                    return Some(err(errno::EINVAL));
                }
                let kind = if req == NS_GET_PARENT { n.kind } else { CLONE_NEWUSER };
                // What is asked for: the parent (a user namespace's owner
                // is its parent); for another kind's owner, the user
                // namespace it was made in, which fwe takes as the
                // caller's. `None`: there is none (an initial namespace's
                // parent); `Some(None)`: the initial namespace.
                let wanted: Option<Option<(Vec<u8>, u64)>> =
                    if req == NS_GET_USERNS && n.kind != CLONE_NEWUSER {
                        Some(self.fs().ns.user.as_ref().map(|u| (u.dir().to_vec(), u.id())))
                    } else {
                        match &n.dir {
                            None => None,
                            Some(d) => match parent_of(kind, d, n.id) {
                                Some(p) => Some(p),
                                None => return Some(err(errno::EINVAL)),
                            },
                        }
                    };
                // Only one the caller can see, as Linux has it: its own, or
                // one its own is inside.
                let Some(wanted) = wanted else { return Some(err(errno::EPERM)) };
                if !self.reaches(kind, &wanted) {
                    return Some(err(errno::EPERM));
                }
                let init =
                    if kind == CLONE_NEWPID { crate::ns::INIT_PID } else { crate::ns::INIT_USER };
                match wanted {
                    Some((d, id)) => fresh(NsRef { kind, id, dir: Some(d) }),
                    None => fresh(NsRef { kind, id: init, dir: None }),
                }
            }
            _ => err(errno::ENOTTY),
        })
    }

    /// Whether, from namespace `start` of `kind` (`None`: the initial one)
    /// and up through its parents, the caller's own is reached.
    fn reaches(&self, kind: u64, start: &Option<(Vec<u8>, u64)>) -> bool {
        let ns = &self.fs().ns;
        let own: Option<Vec<u8>> = if kind == CLONE_NEWPID {
            ns.pid.as_ref().map(|r| r.dir().to_vec())
        } else {
            ns.user.as_ref().map(|r| r.dir().to_vec())
        };
        let Some(own) = own else { return true };
        let mut at = start.clone();
        for _ in 0..64 {
            let Some((d, id)) = at else { return false };
            if d == own {
                return true;
            }
            at = parent_of(kind, &d, id).flatten();
        }
        false
    }

    /// `setns(fd, nstype)`: join the namespace `fd` names.
    pub(crate) fn sys_setns(&mut self, fd: u64, nstype: u64) -> i64 {
        let fd = fd as i32;
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
            return err(errno::EBADF);
        }
        let Some(n) = of(fd) else { return err(errno::EINVAL) };
        let nstype = nstype as u32 as u64;
        if nstype != 0 && nstype != n.kind {
            return err(errno::EINVAL);
        }
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if n.kind == CLONE_NEWUSER && crate::thread::live_threads() > 1 {
            return err(errno::EINVAL);
        }
        let r = self.join_ns(&n);
        if let Err(e) = r {
            return err(e);
        }
        let fs = self.fs.as_mut().expect("filesystem configured");
        crate::procreg::own_namespaces(fs.ns_dirs());
        fs.ns.activate();
        0
    }

    /// Make namespace `n` the process's (for a pid namespace, its
    /// children's).
    fn join_ns(&mut self, n: &NsRef) -> Result<(), i32> {
        use crate::shared::Record;
        use std::sync::Arc;
        fn join<T: crate::shared::Data>(n: &NsRef) -> Result<Option<Arc<Record<T>>>, i32> {
            n.dir.as_ref().map(|d| Record::join(d, n.id).map(Arc::new)).transpose()
        }
        let fs = self.fs.as_mut().expect("filesystem configured");
        match n.kind {
            CLONE_NEWUTS => fs.ns.uts = join(n)?,
            CLONE_NEWIPC => fs.ns.ipc = join(n)?,
            CLONE_NEWNET => fs.ns.net = join(n)?,
            CLONE_NEWCGROUP => fs.ns.cgroup = join(n)?,
            CLONE_NEWPID => fs.ns.pid_children = join(n)?,
            CLONE_NEWUSER => {
                fs.ns.user = join(n)?;
                // In the namespace it joins, the caller has every
                // capability, as Linux gives it.
                self.creds.caps = crate::caps::Caps {
                    effective: crate::caps::ALL,
                    permitted: crate::caps::ALL,
                    inheritable: 0,
                    bounding: crate::caps::ALL,
                    ambient: 0,
                    securebits: 0,
                };
            }
            _ => {
                let dir = n.dir.as_ref().ok_or(errno::EINVAL)?;
                let ns = crate::mounts::store::Ns::join(dir, n.id)?;
                fs.set_mount_ns(Arc::new(ns));
                // At the namespace's root, as Linux leaves the caller.
                fs.set_root(b"/".to_vec(), b"/".to_vec());
                fs.set_mounts(0, 0);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_records_are_named_as_proc_names_them() {
        assert_eq!(kind_of(b"pid_for_children"), Some(CLONE_NEWPID));
        assert_eq!(kind_of(b"time"), None);
        assert_eq!(name_of(CLONE_NEWNS), "mnt");
        let f = crate::shared::FORMAT;
        let dirs =
            vec![format!("/x/v{f}-uts-1-2-3").into_bytes(), format!("/x/v{f}-pid-4").into_bytes()];
        assert_eq!(dir_among(b"pid_for_children", &dirs), Some(dirs[1].clone()));
        assert_eq!(dir_among(b"net", &dirs), None);
    }
}
