//! The path calls on files of fwe's file store ([`crate::filestore`]): a
//! tmpfs's, `/dev/shm`'s. What the resolver found in a directory of the
//! store ([`crate::fs::Resolved::store`]) is opened, made, removed,
//! renamed, linked and changed here, in the filesystem's shared record,
//! with Linux's checks in Linux's order: the mount's (`EROFS`), the
//! file's flags (`EPERM`), then permission (`EACCES`).

use crate::filestore::desc::{self, File};
use crate::filestore::tree::{self, Ino, New, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Stat};
use crate::fs::{Resolved, StoreDir};
use crate::{Kernel, Platform};
use fwe_abi::{err, errno, fcntl};

/// Linux's inode flags a tmpfs keeps: immutable, append-only.
const FS_IMMUTABLE_FL: u32 = 0x10;
const FS_APPEND_FL: u32 = 0x20;

/// The seals a file of a tmpfs starts with: none may be added
/// (`F_SEAL_SEAL`), as Linux's tmpfs makes its files.
const TMPFS_SEALS: u32 = fcntl::F_SEAL_SEAL;

/// Whether directory `d` is a cgroup's ([`crate::cgroupfs`]): its names
/// are the kernel's to make, but for the cgroups `mkdir` makes.
fn in_cgroups(d: &StoreDir) -> bool {
    d.fs.id == crate::cgroupfs::tree_id()
}

/// The cgroup named `name` in cgroup directory `d`.
fn cgroup_named(d: &StoreDir, name: &[u8]) -> Result<Vec<u8>, i32> {
    let parent = crate::cgroupfs::cgroup_at(d.fs.id, d.ino).ok_or(errno::ENOENT)?;
    Ok(crate::mounts::join(&parent, name))
}

/// What an open's flags ask of the file: `R_OK`, `W_OK` bits.
fn wants(flags: u64) -> u32 {
    let mut want = match flags & fcntl::O_ACCMODE {
        fcntl::O_RDONLY => 4,
        fcntl::O_WRONLY => 2,
        _ => 6,
    };
    if flags & fcntl::O_TRUNC != 0 {
        want |= 2;
    }
    want
}

impl<P: Platform> Kernel<P> {
    /// The guest's status of `ino` of `d`'s filesystem, as the host lays
    /// it out (what permission checks read).
    fn store_stat(d: &StoreDir, ino: Ino) -> Result<libc::stat, i32> {
        d.host_stat(ino)
    }

    /// The owner, group and permission bits of a file made with bits
    /// `perm` (the umask applied; `asked` before it) in directory `dir`, a
    /// directory if `is_dir`: the caller's file-system user, its group or,
    /// in a set-group-ID directory, the directory's (whose bit a directory
    /// made there inherits); a file made set-group-ID for a group the
    /// caller is not in loses the bit without `CAP_FSETID`.
    fn store_owner(&self, dir: &Stat, perm: u32, asked: u32, is_dir: bool) -> (u32, u32, u32) {
        let c = &self.creds;
        let setgid_dir = dir.mode & 0o2000 != 0;
        let gid = if setgid_dir { dir.gid } else { c.fsgid };
        let mut kept = perm & 0o7777;
        if setgid_dir && is_dir {
            kept |= 0o2000;
        } else if !is_dir
            && kept & 0o2000 != 0
            && asked & 0o010 != 0
            && gid != c.fsgid
            && !c.groups().contains(&gid)
            && !c.has_over(crate::caps::CAP_FSETID, c.fsuid, gid)
        {
            kept &= !0o2000;
        }
        (c.fsuid, gid, kept)
    }

    /// Whether the caller may make or remove a name in directory `dir` of
    /// fwe's store: the mount is writable (`EROFS`), the directory is there
    /// still (`ENOENT`) and the caller may write and search it (`EACCES`).
    fn store_may_change(&self, r: &Resolved, d: &StoreDir) -> Result<Stat, i32> {
        r.writable()?;
        let st = d.fs.lock()?.stat(d.ino)?;
        if st.nlink == 0 {
            return Err(errno::ENOENT);
        }
        if !self.permits(&Self::store_stat(d, d.ino)?, 2 | 1) {
            return Err(errno::EACCES);
        }
        Ok(st)
    }

    /// Whether the caller may remove (or rename away, or replace) `ino`
    /// from directory `d`: in a sticky directory, only its owner, the
    /// directory's, or a caller with `CAP_FOWNER` over it (`EPERM`); an
    /// immutable or append-only file or directory, not at all (`EPERM`).
    fn store_may_remove(&self, d: &StoreDir, ino: Ino) -> Result<(), i32> {
        let t = d.fs.lock()?;
        let (dir, f) = (t.stat(d.ino)?, t.stat(ino)?);
        drop(t);
        if (f.flags | dir.flags) & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
            return Err(errno::EPERM);
        }
        if dir.mode & 0o1000 == 0 {
            return Ok(());
        }
        let c = &self.creds;
        if f.uid == c.fsuid
            || dir.uid == c.fsuid
            || c.has_over(crate::caps::CAP_FOWNER, f.uid, f.gid)
        {
            return Ok(());
        }
        Err(errno::EPERM)
    }

    /// A descriptor of `file` for the open of `r` with Linux's `flags`,
    /// placed where it was opened.
    fn store_descriptor(&self, r: &Resolved, file: File, flags: u64, created: bool) -> i64 {
        let fd = match desc::open(file, flags, desc::new_id(flags)) {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        if let Some(ns) = &r.ns_path {
            crate::fdmarks::opened(fd, ns.clone(), r.mount_id, r.mount_flags, r.fstype, None);
        }
        if let Some(d) = &r.store
            && r.name != b"."
        {
            desc::set_place(fd, d.ino, &r.name);
        }
        crate::fdstate::update(fd, |s| s.created = created);
        fd as i64
    }

    /// `openat` of what was resolved in directory `d` of fwe's store, with
    /// Linux's `flags` (`O_PATH` already narrowed) and `mode`; `slash` if
    /// the path ended in `/`.
    pub(crate) fn store_open(
        &mut self,
        r: &Resolved,
        d: &StoreDir,
        flags: u64,
        mode: u64,
        slash: bool,
    ) -> i64 {
        // What a cgroup's file reports is what is so as it is opened.
        if in_cgroups(d)
            && let Some(cg) = crate::cgroupfs::cgroup_at(d.fs.id, d.ino)
        {
            crate::cgroupfs::refresh(&cg, &r.name);
        }
        let found = match d.find(&r.name) {
            Ok(f) => Some(f),
            Err(errno::ENOENT) => None,
            Err(e) => return err(e),
        };
        let Some((ino, st)) = found else {
            return self.store_create(r, d, flags, mode, slash);
        };
        if flags & (fcntl::O_CREAT | fcntl::O_EXCL) == fcntl::O_CREAT | fcntl::O_EXCL {
            return err(errno::EEXIST);
        }
        let kind = st.mode & S_IFMT;
        let file = File { fs: d.fs.id, ino };
        if kind == S_IFLNK {
            // Not followed (`O_NOFOLLOW`): named by `O_PATH`, else a loop.
            if flags & fcntl::O_PATH != 0 && flags & fcntl::O_NOFOLLOW != 0 {
                return self.store_descriptor(r, file, flags, false);
            }
            return err(errno::ELOOP);
        }
        if flags & fcntl::O_DIRECTORY != 0 && kind != S_IFDIR {
            return err(errno::ENOTDIR);
        }
        if flags & fcntl::O_CREAT != 0 && kind == S_IFDIR {
            return err(errno::EISDIR);
        }
        if flags & fcntl::O_PATH != 0 {
            return self.store_descriptor(r, file, flags, false);
        }
        let write = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY;
        if kind == S_IFDIR && (write || flags & fcntl::O_TRUNC != 0) {
            return err(errno::EISDIR);
        }
        // A device's node, a FIFO and a socket are what is behind them.
        if !matches!(kind, S_IFREG | S_IFDIR) {
            return self.store_open_special(r, d, ino, &st, flags);
        }
        let changes = write || flags & fcntl::O_TRUNC != 0;
        if changes && let Err(e) = r.writable() {
            return err(e);
        }
        if changes && st.flags & FS_IMMUTABLE_FL != 0 {
            return err(errno::EPERM);
        }
        let hst = match Self::store_stat(d, ino) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        if !self.permits(&hst, wants(flags)) {
            return err(errno::EACCES);
        }
        // An append-only file is written at its end, never cut.
        if st.flags & FS_APPEND_FL != 0
            && ((write && flags & fcntl::O_APPEND == 0) || flags & fcntl::O_TRUNC != 0)
        {
            return err(errno::EPERM);
        }
        // `O_NOATIME` is the file's owner's to ask for.
        if flags & fcntl::O_NOATIME != 0
            && st.uid != self.creds.fsuid
            && !self.creds.has_over(crate::caps::CAP_FOWNER, st.uid, st.gid)
        {
            return err(errno::EPERM);
        }
        if kind == S_IFREG {
            // A running program's file is not to be written; a lease the
            // open conflicts with is broken first.
            let dev = hst.st_dev as u64;
            if changes && crate::textbusy::is_running(dev, ino) {
                return err(errno::ETXTBSY);
            }
            if let Err(e) =
                crate::leases::break_for(dev, ino, changes, flags & fcntl::O_NONBLOCK != 0)
            {
                return err(e);
            }
        }
        let fd = self.store_descriptor(r, file, flags, false);
        // A cgroup's interface file is not cut (Linux's kernfs takes the
        // size and changes nothing).
        if fd >= 0
            && kind == S_IFREG
            && flags & fcntl::O_TRUNC != 0
            && !in_cgroups(d)
            && let Some(e) = crate::filestore::io::ftruncate(fd as i32, 0).filter(|&e| e < 0)
        {
            let _ = self.syscall(fwe_abi::nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            return e;
        }
        fd
    }

    /// The open of `ino` of `d`'s filesystem, of status `st`, that is not a
    /// regular file or a directory: a FIFO opens its host node (opened
    /// already, if the open waits for the other end: [`crate::fs::take_fifo`]);
    /// a device's node opens the device its numbers name; a socket's node
    /// is no file to open (`ENXIO`).
    fn store_open_special(
        &mut self,
        r: &Resolved,
        d: &StoreDir,
        ino: Ino,
        st: &Stat,
        flags: u64,
    ) -> i64 {
        let kind = st.mode & S_IFMT;
        let device = matches!(kind, tree::S_IFCHR | tree::S_IFBLK);
        if device && r.mount_flags & crate::mounts::ms::NODEV != 0 {
            return err(errno::EACCES);
        }
        let hst = match Self::store_stat(d, ino) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        // Neither is cut by `O_TRUNC`.
        if !self.permits(&hst, wants(flags & !fcntl::O_TRUNC)) {
            return err(errno::EACCES);
        }
        let fd = match kind {
            tree::S_IFIFO => {
                let node = match crate::storenodes::path(d.fs.id, ino)
                    .and_then(|p| std::ffi::CString::new(p).map_err(|_| errno::EINVAL))
                {
                    Ok(c) => c,
                    Err(e) => return err(e),
                };
                let mut host: libc::stat = crate::fsops::zeroed_stat();
                // SAFETY: a NUL-terminated path; a valid out-parameter.
                if unsafe { libc::lstat(node.as_ptr(), &mut host) } != 0 {
                    return err(crate::host::errno_to_linux(crate::host::last_errno()));
                }
                match crate::fs::take_fifo(flags, &host) {
                    Some(fd) => crate::fsops::fifo_flags(fd, flags),
                    None => {
                        let h = crate::host::open_flags_to_host(
                            flags & !(fcntl::O_CREAT | fcntl::O_EXCL | fcntl::O_TRUNC),
                        );
                        // SAFETY: a NUL-terminated host path.
                        let fd = unsafe { libc::open(node.as_ptr(), h | libc::O_NOFOLLOW) };
                        if fd < 0 {
                            return err(crate::host::errno_to_linux(crate::host::last_errno()));
                        }
                        fd
                    }
                }
            }
            tree::S_IFCHR | tree::S_IFBLK => {
                let n = crate::devnodes::Node {
                    kind,
                    major: crate::fsops::major(st.rdev),
                    minor: crate::fsops::minor(st.rdev),
                };
                // A loop device is a descriptor of its node, marked so.
                if crate::loopdev::is_loop_node(n) {
                    if let Err(e) = crate::loopdev::check_open(n) {
                        return err(e);
                    }
                    let h = crate::host::open_flags_to_host(flags & fcntl::O_CLOEXEC);
                    // SAFETY: a constant NUL-terminated path.
                    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), h) };
                    if fd < 0 {
                        return err(crate::host::errno_to_linux(crate::host::last_errno()));
                    }
                    crate::loopdev::opened(fd, n);
                    fd
                } else {
                    let fd = crate::fsops::open_device(-1, n, flags, true);
                    if fd < 0 {
                        return fd;
                    }
                    fd as i32
                }
            }
            _ => return err(errno::ENXIO),
        };
        if let Some(ns) = &r.ns_path {
            crate::fdmarks::opened(fd, ns.clone(), r.mount_id, r.mount_flags, r.fstype, None);
        }
        crate::fdstate::update(fd, |s| s.created = false);
        fd as i64
    }

    /// The open with `O_CREAT` of a name missing in directory `d`.
    fn store_create(
        &mut self,
        r: &Resolved,
        d: &StoreDir,
        flags: u64,
        mode: u64,
        slash: bool,
    ) -> i64 {
        if flags & fcntl::O_CREAT == 0 {
            return err(errno::ENOENT);
        }
        // A name ending in `/` is a directory's, which `open` makes not.
        if slash {
            return err(errno::EISDIR);
        }
        // A cgroup has only the files the kernel makes.
        if in_cgroups(d) {
            return err(errno::EACCES);
        }
        let dir = match self.store_may_change(r, d) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        let asked = mode as u32;
        let perm = self.fs().apply_umask(asked);
        let (uid, gid, perm) = self.store_owner(&dir, perm, asked, false);
        let made = d.fs.lock().and_then(|mut t| {
            let ino = t.create(d.ino, &r.name, &New { mode: S_IFREG | perm, uid, gid, rdev: 0 })?;
            t.set_seals(ino, TMPFS_SEALS)?;
            Ok(ino)
        });
        let ino = match made {
            Ok(ino) => ino,
            // Made meanwhile, by another: opened as it is.
            Err(errno::EEXIST) if flags & fcntl::O_EXCL == 0 => {
                return self.store_open(r, d, flags & !fcntl::O_CREAT, mode, slash);
            }
            Err(e) => return err(e),
        };
        self.store_descriptor(r, File { fs: d.fs.id, ino }, flags, true)
    }

    /// `O_TMPFILE` in directory `d` of fwe's store (what was resolved, `.`
    /// of the directory itself): a regular file with no name, which
    /// `linkat` may name unless `O_EXCL`.
    pub(crate) fn store_tmpfile(
        &mut self,
        r: &Resolved,
        d: &StoreDir,
        flags: u64,
        mode: u64,
    ) -> i64 {
        if in_cgroups(d) {
            return err(errno::EOPNOTSUPP);
        }
        let dir = match self.store_may_change(r, d) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        let asked = mode as u32;
        let perm = self.fs().apply_umask(asked);
        let (uid, gid, perm) = self.store_owner(&dir, perm, asked, false);
        let id = desc::new_id(flags);
        let made = d.fs.lock().and_then(|mut t| {
            let ino = t.create_unnamed(&New { mode: S_IFREG | perm, uid, gid, rdev: 0 })?;
            // Held from the start, so no sweep takes it before its
            // descriptor counts; linkable unless asked not to be.
            let held = t
                .hold(ino, crate::sysvipc::me(), &[(id, 1)])
                .and_then(|_| t.set_seals(ino, TMPFS_SEALS))
                .and_then(|()| t.set_linkable(ino, flags & fcntl::O_EXCL == 0));
            if let Err(e) = held {
                let _ = t.hold(ino, crate::sysvipc::me(), &[]);
                return Err(e);
            }
            Ok(ino)
        });
        let ino = match made {
            Ok(ino) => ino,
            Err(e) => return err(e),
        };
        let file = File { fs: d.fs.id, ino };
        let open = flags & !(fcntl::O_TMPFILE & !fcntl::O_DIRECTORY) & !fcntl::O_DIRECTORY;
        let fd = match desc::open(file, open, id) {
            Ok(fd) => fd,
            Err(e) => {
                if let Ok(mut t) = d.fs.lock()
                    && let Ok(gone) = t.hold(ino, crate::sysvipc::me(), &[])
                    && let Some(o) = gone.data
                {
                    crate::filestore::data::remove(o);
                }
                return err(e);
            }
        };
        if let Some(ns) = &r.ns_path {
            crate::fdmarks::opened(fd, ns.clone(), r.mount_id, r.mount_flags, r.fstype, None);
        }
        crate::fdstate::update(fd, |s| s.created = true);
        fd as i64
    }

    /// `mkdirat` of what was resolved in directory `d` of fwe's store.
    pub(crate) fn store_mkdir(&self, r: &Resolved, d: &StoreDir, mode: u32) -> i64 {
        if d.find(&r.name).is_ok() {
            return err(errno::EEXIST);
        }
        let dir = match self.store_may_change(r, d) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        // A new cgroup, within the limits of those above it, made whole
        // under the hierarchy's lock (no removal of its parent between),
        // its name one Linux's `cgroup_mkdir` takes.
        let cgroup = if in_cgroups(d) {
            if r.name.contains(&b'\n') {
                return err(errno::EINVAL);
            }
            let held = match crate::cgroupfs::lock_tree() {
                Ok(l) => l,
                Err(e) => return err(e),
            };
            let made = cgroup_named(d, &r.name);
            let parent = crate::cgroupfs::cgroup_at(d.fs.id, d.ino).ok_or(errno::ENOENT);
            if let Err(e) = parent.and_then(|p| crate::cgroupfs::may_make(&p)).and(made.clone()) {
                return err(e);
            }
            made.ok().map(|cg| (cg, held))
        } else {
            None
        };
        let perm = self.fs().apply_umask(mode & 0o7777) & 0o1777;
        let (uid, gid, perm) = self.store_owner(&dir, perm, mode, true);
        let made = d.fs.lock().and_then(|mut t| {
            t.create(d.ino, &r.name, &New { mode: S_IFDIR | perm, uid, gid, rdev: 0 })
        });
        if let Err(e) = made {
            return err(e);
        }
        // Its interface files.
        if let Some((cg, _held)) = cgroup
            && let Err(e) = crate::cgroupfs::made(&cg)
        {
            return err(e);
        }
        0
    }

    /// `mknodat` of what was resolved in directory `d` of fwe's store: a
    /// regular file, a FIFO, a socket's node or a device's (`kind` the
    /// type bits, `perm` before the umask, `rdev` Linux's numbers).
    pub(crate) fn store_mknod(
        &self,
        r: &Resolved,
        d: &StoreDir,
        kind: u32,
        perm: u32,
        rdev: u64,
    ) -> i64 {
        if d.find(&r.name).is_ok() {
            return err(errno::EEXIST);
        }
        let dir = match self.store_may_change(r, d) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        // A cgroup's directory takes no other file (no `mknod` of kernfs's).
        if in_cgroups(d) {
            return err(errno::EPERM);
        }
        if matches!(kind, tree::S_IFCHR | tree::S_IFBLK) {
            let node = crate::devnodes::Node {
                kind,
                major: crate::devnodes::major(rdev),
                minor: crate::devnodes::minor(rdev),
            };
            // A whiteout (a 0:0 character device) needs no `CAP_MKNOD`.
            let whiteout = kind == tree::S_IFCHR && node.major == 0 && node.minor == 0;
            if !whiteout && !self.creds.has(crate::caps::CAP_MKNOD) {
                return err(errno::EPERM);
            }
            if let Err(e) = crate::cgroupfs::check_device(
                crate::bpf::BPF_DEVCG_ACC_MKNOD,
                node.bpf_type(),
                node.major,
                node.minor,
            ) {
                return err(e);
            }
        }
        let applied = self.fs().apply_umask(perm);
        let (uid, gid, applied) = self.store_owner(&dir, applied, perm, false);
        let rdev = if matches!(kind, tree::S_IFCHR | tree::S_IFBLK) { rdev } else { 0 };
        let made = d.fs.lock().and_then(|mut t| {
            let ino = t.create(d.ino, &r.name, &New { mode: kind | applied, uid, gid, rdev })?;
            if kind == S_IFREG {
                t.set_seals(ino, TMPFS_SEALS)?;
            }
            Ok(ino)
        });
        let ino = match made {
            Ok(ino) => ino,
            Err(e) => return err(e),
        };
        // A FIFO's or a socket's node has the host's behind it.
        if matches!(kind, tree::S_IFIFO | tree::S_IFSOCK)
            && let Err(e) = crate::storenodes::make(d, ino, kind)
        {
            if let Ok(mut t) = d.fs.lock() {
                let _ = t.unlink(d.ino, &r.name, false);
            }
            return err(e);
        }
        0
    }

    /// `symlinkat` of `target` at what was resolved in directory `d` of
    /// fwe's store.
    pub(crate) fn store_symlink(&self, r: &Resolved, d: &StoreDir, target: &[u8]) -> i64 {
        if d.find(&r.name).is_ok() {
            return err(errno::EEXIST);
        }
        if let Err(e) = self.store_may_change(r, d) {
            return err(e);
        }
        if in_cgroups(d) {
            return err(errno::EPERM);
        }
        let (uid, gid) = (self.creds.fsuid, {
            let dir = d.fs.lock().and_then(|t| t.stat(d.ino));
            match dir {
                Ok(st) if st.mode & 0o2000 != 0 => st.gid,
                _ => self.creds.fsgid,
            }
        });
        match d.fs.lock().and_then(|mut t| t.symlink(d.ino, &r.name, target, uid, gid)) {
            Ok(_) => 0,
            Err(e) => err(e),
        }
    }

    /// `readlinkat` of what was resolved in directory `d` of fwe's store:
    /// the link's target.
    pub(crate) fn store_readlink(r: &Resolved, d: &StoreDir) -> Result<Vec<u8>, i32> {
        let (ino, _) = d.find(&r.name)?;
        d.fs.lock()?.readlink(ino)
    }

    /// `unlinkat` (`rmdir` with `AT_REMOVEDIR`) of what was resolved in
    /// directory `d` of fwe's store.
    pub(crate) fn store_unlink(&self, r: &Resolved, d: &StoreDir, rmdir: bool) -> i64 {
        if r.mount_root || (rmdir && r.name == b".") {
            return err(if r.mount_root { errno::EBUSY } else { errno::EINVAL });
        }
        let (ino, st) = match d.find(&r.name) {
            Ok(f) => f,
            Err(e) => return err(e),
        };
        if let Err(e) = self.store_may_change(r, d) {
            return err(e);
        }
        if let Err(e) = self.store_may_remove(d, ino) {
            return err(e);
        }
        // A mount point is busy.
        if st.mode & S_IFMT == S_IFDIR
            && let Some(ns) = &r.ns_path
            && self.fs().mount_ns().table().mounts.iter().any(|m| m.point == *ns)
        {
            return err(errno::EBUSY);
        }
        // A cgroup goes with its files when empty; its files stay (no
        // `unlink` of kernfs's).
        if in_cgroups(d) {
            if !rmdir {
                return err(errno::EPERM);
            }
            if st.mode & S_IFMT != S_IFDIR {
                return err(errno::ENOTDIR);
            }
            return match cgroup_named(d, &r.name).and_then(|cg| crate::cgroupfs::remove(&cg)) {
                Ok(()) => 0,
                Err(e) => err(e),
            };
        }
        let gone = d.fs.lock().and_then(|mut t| t.unlink(d.ino, &r.name, rmdir));
        match gone {
            Ok(gone) => {
                if let Some(o) = gone.data {
                    crate::filestore::data::remove(o);
                }
                if gone.node {
                    crate::storenodes::gone(d.fs.id, ino);
                }
                0
            }
            Err(e) => err(e),
        }
    }

    /// `linkat` of file `ino` of filesystem `fs` (found by `old`'s
    /// resolution, or a descriptor's) to what was resolved as `new`.
    pub(crate) fn store_link(
        &self,
        fs: u64,
        ino: Ino,
        new: &Resolved,
        nd: &StoreDir,
        from_fd: bool,
    ) -> i64 {
        if nd.fs.id != fs {
            return err(errno::EXDEV);
        }
        if nd.find(&new.name).is_ok() {
            return err(errno::EEXIST);
        }
        if let Err(e) = self.store_may_change(new, nd) {
            return err(e);
        }
        if in_cgroups(nd) {
            return err(errno::EPERM);
        }
        let st = match nd.fs.lock().and_then(|t| t.stat(ino)) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        if st.mode & S_IFMT == S_IFDIR {
            return err(errno::EPERM);
        }
        if st.flags & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
            return err(errno::EPERM);
        }
        // A file with no names is named again only from its descriptor,
        // and only an `O_TMPFILE` made linkable.
        if st.nlink == 0 {
            let linkable = nd.fs.lock().and_then(|t| t.linkable(ino)).unwrap_or(false);
            if !from_fd || !linkable {
                return err(errno::ENOENT);
            }
        }
        // `fs.protected_hardlinks`: another's file only if the caller
        // could read and write it, or owns it.
        let hst = match nd.host_stat(ino) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        if crate::sysctl::protected_links().1
            && st.uid != self.creds.fsuid
            && !self.creds.has_over(crate::caps::CAP_FOWNER, st.uid, st.gid)
            && (st.mode & S_IFMT != S_IFREG
                || st.mode & 0o6010 == 0o6010
                || st.mode & 0o4000 != 0
                || !self.permits(&hst, 6))
        {
            return err(errno::EPERM);
        }
        let linked = nd.fs.lock().and_then(|mut t| {
            t.link(ino, nd.ino, &new.name)?;
            // Named, it is no longer one to name again from its descriptor.
            t.set_linkable(ino, false)
        });
        match linked {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `renameat2` of `old` (in directory `od` of fwe's store) to `new`
    /// (in `nd`), with Linux's `flags` (`RENAME_NOREPLACE`,
    /// `RENAME_EXCHANGE`; `RENAME_WHITEOUT` makes a whiteout where `old`
    /// was).
    pub(crate) fn store_rename(
        &self,
        old: &Resolved,
        od: &StoreDir,
        new: &Resolved,
        nd: &StoreDir,
        flags: u64,
    ) -> i64 {
        const NOREPLACE: u64 = 1;
        const EXCHANGE: u64 = 2;
        const WHITEOUT: u64 = 4;
        if flags & !(NOREPLACE | EXCHANGE | WHITEOUT) != 0
            || flags & EXCHANGE != 0 && flags & (NOREPLACE | WHITEOUT) != 0
        {
            return err(errno::EINVAL);
        }
        if od.fs.id != nd.fs.id {
            return err(errno::EXDEV);
        }
        // A cgroup is not renamed on the unified hierarchy (Linux's has no
        // `rename` for kernfs to call).
        if in_cgroups(od) {
            return err(errno::EPERM);
        }
        if old.mount_root || new.mount_root {
            return err(errno::EBUSY);
        }
        let (oino, ost) = match od.find(&old.name) {
            Ok(f) => f,
            Err(e) => return err(e),
        };
        let target = nd.find(&new.name).ok();
        if flags & NOREPLACE != 0 && target.is_some() {
            return err(errno::EEXIST);
        }
        if flags & EXCHANGE != 0 && target.is_none() {
            return err(errno::ENOENT);
        }
        // `RENAME_WHITEOUT` is for those who may make device nodes.
        if flags & WHITEOUT != 0 && !self.creds.has(crate::caps::CAP_MKNOD) {
            return err(errno::EPERM);
        }
        for (r, d) in [(old, od), (new, nd)] {
            if let Err(e) = self.store_may_change(r, d) {
                return err(e);
            }
        }
        if let Err(e) = self.store_may_remove(od, oino) {
            return err(e);
        }
        if let Some((tino, _)) = target
            && let Err(e) = self.store_may_remove(nd, tino)
        {
            return err(e);
        }
        // A directory moved to another holds its `..`, which it writes.
        let moves_dir = |ino: Ino, st: &Stat| -> Result<(), i32> {
            if st.mode & S_IFMT == S_IFDIR && od.ino != nd.ino {
                let hst = od.host_stat(ino)?;
                if !self.permits(&hst, 2) {
                    return Err(errno::EACCES);
                }
            }
            Ok(())
        };
        if let Err(e) = moves_dir(oino, &ost) {
            return err(e);
        }
        if flags & EXCHANGE != 0
            && let Some((tino, tst)) = &target
            && let Err(e) = moves_dir(*tino, tst)
        {
            return err(e);
        }
        // Mount points are not moved or replaced.
        let table = self.fs().mount_ns().table();
        let mounted = |r: &Resolved| {
            r.ns_path.as_ref().is_some_and(|ns| table.mounts.iter().any(|m| m.point == *ns))
        };
        if mounted(old) || (target.is_some() && mounted(new)) {
            return err(errno::EBUSY);
        }
        let tree_flags = (flags & (NOREPLACE | EXCHANGE)) as u32;
        let renamed = od.fs.lock().and_then(|mut t| {
            let gone = t.rename(od.ino, &old.name, nd.ino, &new.name, tree_flags)?;
            if flags & WHITEOUT != 0 {
                let w = New {
                    mode: tree::S_IFCHR,
                    uid: self.creds.fsuid,
                    gid: self.creds.fsgid,
                    rdev: 0,
                };
                t.create(od.ino, &old.name, &w)?;
            }
            Ok(gone)
        });
        match renamed {
            Ok(gone) => {
                if let Some(g) = gone {
                    if let Some(o) = g.data {
                        crate::filestore::data::remove(o);
                    }
                    if g.node {
                        crate::storenodes::gone(od.fs.id, g.ino);
                    }
                }
                0
            }
            Err(e) => err(e),
        }
    }
}
