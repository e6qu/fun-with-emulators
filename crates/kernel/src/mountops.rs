//! `mount`, `umount2`, `pivot_root` and `chroot`, on the mount namespace's
//! table ([`crate::mounts`]).
//!
//! A tmpfs is a fresh directory of fwe's ([`tmpfs_dir`]), the synthetic
//! filesystems (`proc`, `sysfs`, `cgroup2`, `devpts`, `mqueue`) are fwe's
//! own, an overlay stacks directories the guest names
//! ([`crate::overlay`]), and a bind mount shows a directory or file the
//! guest names. A mount made under a shared mount propagates to its peers
//! and slaves, in this namespace and others ([`crate::mounts`]).

use crate::mounts::{FsType, Source, ms};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{err, errno};

/// `umount2` flags.
const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

/// The access-time flag a new mount (or a remount) with `flags` gets if
/// it names none: `relatime`, Linux's default.
pub(crate) fn default_atime(flags: u64) -> u64 {
    if flags & (ms::NOATIME | ms::STRICTATIME) == 0 { ms::RELATIME } else { 0 }
}

/// The initial namespace's id for id `v` (text) of the caller's user
/// namespace, as a mount option names it (`EINVAL` for one it does not
/// map), Linux's `make_kuid` and `make_kgid`.
fn kernel_id(v: &[u8], gid: bool) -> Result<u32, i32> {
    let n = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok()).ok_or(errno::EINVAL)?;
    crate::userns::from_ns(n, gid).ok_or(errno::EINVAL)
}

impl<P: Platform> Kernel<P> {
    /// Filesystem options `data` of a new `kind` filesystem (or a remount),
    /// checked as Linux checks them (`EINVAL`), and as the mount keeps
    /// them: a user or group id as the initial namespace has it, as
    /// `mountinfo` shows it. A tmpfs's ([`crate::tmpfs::parse`]); a
    /// `proc`'s `hidepid=` (`0` to `2`, `4`, or their names), `gid=` and
    /// `subset=` (`pid`, or nothing).
    pub(crate) fn fs_data(kind: FsType, data: &[u8]) -> Result<Vec<u8>, i32> {
        if kind == FsType::Tmpfs {
            crate::tmpfs::parse(data)?;
        }
        if !matches!(kind, FsType::Tmpfs | FsType::Proc) {
            return Ok(data.to_vec());
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        for o in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
            let (key, value) = match o.iter().position(|&b| b == b'=') {
                Some(i) => (&o[..i], &o[i + 1..]),
                None => (o, &b""[..]),
            };
            out.push(match (kind, key) {
                (_, b"uid") if kind == FsType::Tmpfs => {
                    format!("uid={}", kernel_id(value, false)?).into_bytes()
                }
                (_, b"gid") => format!("gid={}", kernel_id(value, true)?).into_bytes(),
                (FsType::Proc, b"hidepid") => {
                    crate::procfs::hidepid(value).ok_or(errno::EINVAL)?;
                    o.to_vec()
                }
                (FsType::Proc, b"subset") if !matches!(value, b"pid" | b"") => {
                    return Err(errno::EINVAL);
                }
                _ => o.to_vec(),
            });
        }
        Ok(out.join(&b","[..]))
    }

    /// Whether the caller may change its mount namespace's mounts:
    /// `CAP_SYS_ADMIN` in the user namespace that owns the namespace
    /// (Linux's `may_mount`).
    pub(crate) fn may_mount(&self) -> bool {
        let owner = self.fs().mount_ns().table().owner.clone();
        self.creds.has_in(&owner, crate::caps::CAP_SYS_ADMIN)
    }

    /// Whether the caller may make a new filesystem of `kind`: every kind
    /// fwe has is one a user namespace may mount (`FS_USERNS_MOUNT`), with
    /// `CAP_SYS_ADMIN` in the user namespace the filesystem belongs to:
    /// the one owning the pid namespace for `proc`, the network namespace
    /// for `sysfs`, the IPC namespace for `mqueue`, the cgroup namespace
    /// for `cgroup2`, else the caller's own (Linux's `mount_capable`).
    pub(crate) fn may_make_filesystem(&self, kind: FsType) -> bool {
        use fwe_abi::clone::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWPID};
        let ns = &self.fs().ns;
        let owner = match kind {
            FsType::Proc => ns.owner(CLONE_NEWPID),
            FsType::Sysfs => ns.owner(CLONE_NEWNET),
            FsType::Mqueue => ns.owner(CLONE_NEWIPC),
            FsType::Cgroup2 => ns.owner(CLONE_NEWCGROUP),
            _ => return self.creds.has_own(crate::caps::CAP_SYS_ADMIN),
        };
        self.creds.has_in(&owner, crate::caps::CAP_SYS_ADMIN)
    }

    /// The namespace path of `path`, which must exist; `follow` as for
    /// resolution, a link in `/proc` included (`/proc/self/exe` names the
    /// program's file, `/proc/self/fd/N` the open file's). Fails with
    /// `EINVAL` for one fwe cannot place.
    fn mount_path(&self, path: &[u8], follow: bool) -> Result<(Vec<u8>, bool), i32> {
        self.mount_path_at(fwe_abi::fcntl::AT_FDCWD as i32, path, follow)
    }

    /// [`mount_path`](Self::mount_path) of `path` from directory `dirfd`.
    pub(crate) fn mount_path_at(
        &self,
        dirfd: i32,
        path: &[u8],
        follow: bool,
    ) -> Result<(Vec<u8>, bool), i32> {
        if let Some(entry) = self.fs().synthetic(dirfd, path) {
            use crate::procfs::Entry;
            return match entry {
                Entry::Missing => Err(errno::ENOENT),
                Entry::Symlink(target) if follow && target.starts_with(b"/") => {
                    self.mount_path(&target, true)
                }
                // A descriptor of a link (not mounted on: Linux follows no
                // magic link to a link).
                Entry::Fd { fd, .. } if follow && crate::fdmarks::proc_link(fd).is_some() => {
                    Err(errno::ENOENT)
                }
                Entry::Fd { fd, .. } if follow => {
                    // The file itself, where it was opened.
                    let ns = self.fs().fd_ns_path(fd).ok_or(errno::EINVAL)?;
                    if crate::synthdir::path_of(fd).is_some() {
                        return Ok((ns, true));
                    }
                    if let Some(st) = crate::filestore::io::stat(fd) {
                        return Ok((ns, st?.st_mode & libc::S_IFMT == libc::S_IFDIR));
                    }
                    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: a valid out-parameter.
                    unsafe { libc::fstat(fd, &mut st) };
                    Ok((ns, st.st_mode & libc::S_IFMT == libc::S_IFDIR))
                }
                Entry::Dir => {
                    let absolute = self.fs().absolute_path(dirfd, path).ok_or(errno::EBADF)?;
                    Ok((self.fs().to_ns(&absolute), true))
                }
                _ => {
                    let absolute = self.fs().absolute_path(dirfd, path).ok_or(errno::EBADF)?;
                    Ok((self.fs().to_ns(&absolute), false))
                }
            };
        }
        let r = self.fs().resolve(dirfd, path, follow)?;
        // It must exist.
        let st = r.lstat().ok_or(errno::ENOENT)?;
        let ns = r.ns_path.ok_or(errno::EINVAL)?;
        Ok((ns, st.st_mode & libc::S_IFMT == libc::S_IFDIR))
    }

    /// A new filesystem of `kind` with options `data`: where it is, the
    /// path inside it a mount shows, and the mount flags it imposes (an
    /// overlay with nothing to write to is read-only, as on Linux).
    pub(crate) fn new_filesystem(
        &self,
        kind: FsType,
        data: &[u8],
    ) -> Result<(Source, Vec<u8>, u64), i32> {
        let mut root = b"/".to_vec();
        let mut flags = 0;
        let src = match kind {
            FsType::Tmpfs => {
                // Options as [`Self::fs_data`] keeps them: ids the initial
                // namespace's.
                let o = crate::tmpfs::parse(data)?;
                // A filesystem of fwe's store, in memory: its root is its
                // mounter's, or the owner asked for, and it holds what its
                // size and inodes allow.
                let id = crate::filestore::fs::make(
                    o.mode.unwrap_or(0o1777),
                    o.uid.unwrap_or(self.creds.fsuid),
                    o.gid.unwrap_or(self.creds.fsgid),
                    o.size.unwrap_or_else(crate::tmpfs::default_size),
                    o.inodes.unwrap_or_else(crate::tmpfs::default_inodes),
                )?;
                Source::Store(id)
            }
            FsType::Cgroup2 => {
                // The hierarchy from the cgroup namespace's root.
                let id = crate::cgroupfs::tree()?.id;
                root = self.fs().ns.cgroup.as_ref().map_or(b"/".to_vec(), |c| c.get().root.clone());
                Source::Store(id)
            }
            FsType::Overlay => {
                let layers = self.overlay_layers(data)?;
                if layers.upper.is_none() {
                    flags |= ms::RDONLY;
                }
                Source::Overlay(std::sync::Arc::new(layers))
            }
            _ => Source::Synthetic,
        };
        Ok((src, root, flags))
    }

    /// The host file `path` resolves to when it is one fwe serves from the
    /// host outside any mount.
    fn host_source(&self, path: &[u8]) -> Option<Vec<u8>> {
        let r = self.fs().resolve(fwe_abi::fcntl::AT_FDCWD as i32, path, true).ok()?;
        if r.ns_path.is_some() {
            return None;
        }
        let dir = crate::fs::host_path_of(std::os::fd::AsRawFd::as_raw_fd(&r.dir))?;
        Some(crate::mounts::join(&dir, &r.name))
    }

    /// Where the guest directory `path`, an overlay's layer, is: a host
    /// directory of a mount of host directories, or a directory of a
    /// filesystem of fwe's store (`EINVAL` for one in an overlay or in a
    /// filesystem fwe makes up); `EROFS` for one to be written to (`write`)
    /// in a read-only mount.
    fn layer_place(&self, path: &[u8], write: bool) -> Result<crate::overlay::Place, i32> {
        let (ns, is_dir) = self.mount_path(path, true)?;
        if !is_dir {
            return Err(errno::ENOTDIR);
        }
        let table = self.fs().mounts();
        let (m, rest) = table.locate(&ns);
        if write && m.read_only() {
            return Err(errno::EROFS);
        }
        if let crate::mounts::Source::Store(id) = m.source {
            return Ok(crate::overlay::Place::Store { fs: id, path: m.fs_path(&rest) });
        }
        m.host_path(&rest).map(crate::overlay::Place::Host).ok_or(errno::EINVAL)
    }

    /// The layers an overlay's mount options (`data`) name, checked as
    /// Linux checks them, with the work directory made ready.
    fn overlay_layers(&self, data: &[u8]) -> Result<crate::overlay::Layers, i32> {
        let o = crate::overlay::parse(data)?;
        let lowers =
            o.lowers.iter().map(|p| self.layer_place(p, false)).collect::<Result<Vec<_>, _>>()?;
        let upper = o.upper.as_deref().map(|p| self.layer_place(p, true)).transpose()?;
        let work = o.work.as_deref().map(|p| self.layer_place(p, true)).transpose()?;
        if let (Some(u), Some(w)) = (&upper, &work) {
            // Separate directories of one filesystem.
            let dev = |p: &[u8]| -> Result<u64, i32> {
                let c = std::ffi::CString::new(p).map_err(|_| errno::EINVAL)?;
                // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: a NUL-terminated path; a valid out-parameter.
                if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
                    return Err(crate::host::errno_to_linux(crate::host::last_errno()));
                }
                Ok(crate::host::dev_of(&st))
            };
            if !u.same_fs(w, dev)? || u.nested(w) {
                return Err(errno::EINVAL);
            }
            crate::overlay::prepare_work(w)?;
        }
        Ok(crate::overlay::Layers { upper, work, lowers, userxattr: o.userxattr })
    }

    /// The namespace `source` names, if it is a namespace's file: a
    /// `/proc/<pid>/ns/<kind>` link, a descriptor of a namespace through
    /// `/proc/self/fd`, or a path a namespace is bound to.
    fn bound_namespace(&self, source: &[u8]) -> Option<Result<crate::nsfd::NsRef, i32>> {
        use crate::procfs::Entry;
        let cwd = fwe_abi::fcntl::AT_FDCWD as i32;
        match self.fs().synthetic(cwd, source)? {
            Entry::Ns(n) => Some(Ok(n)),
            Entry::Fd { fd, .. } => crate::nsfd::of(fd).map(Ok),
            Entry::Symlink(link) if link.contains(&b'[') && link.ends_with(b"]") => {
                Some(self.ns_at(cwd, source, &link))
            }
            _ => None,
        }
    }

    /// `mount(source, target, fstype, flags, data)`.
    pub(crate) fn sys_mount(
        &mut self,
        source: u64,
        target: u64,
        fstype: u64,
        mut flags: u64,
        data: u64,
    ) -> i64 {
        if !self.may_mount() {
            return err(errno::EPERM);
        }
        let target = guest!(uaccess::read_cstr(target, uaccess::PATH_MAX));
        let read_opt = |p: u64| -> Result<Vec<u8>, i32> {
            if p == 0 { Ok(Vec::new()) } else { uaccess::read_cstr(p, uaccess::PATH_MAX) }
        };
        let source = guest!(read_opt(source));
        let fstype_ptr = fstype;
        let fstype = guest!(read_opt(fstype));
        // `data` is a page of options, a string for the filesystems fwe has.
        let data = guest!(read_opt(data));
        let (point, is_dir) = match self.mount_path(&target, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let ns = self.fs().mount_ns().clone();
        let r = if flags & ms::REMOUNT != 0 {
            let opts = (!data.is_empty() && flags & ms::BIND == 0).then(|| data.clone());
            // With no access-time mode named the mount keeps its own.
            let named = flags & (ms::NOATIME | ms::NODIRATIME | ms::RELATIME | ms::STRICTATIME);
            let flags = if named == 0 { flags } else { flags | default_atime(flags) };
            // The options checked as a new filesystem's, of its type.
            let kind = ns.table().locate(&point).0.fstype;
            let opts = match opts.map(|d| Self::fs_data(kind, &d)).transpose() {
                Ok(o) => o,
                Err(e) => return err(e),
            };
            // A tmpfs given a new size or number of inodes holds to it from
            // now on.
            if flags & ms::BIND == 0
                && let Ok(o) = crate::tmpfs::parse(&data)
                && let (m, _) = ns.table().locate(&point)
                && let Source::Store(id) = m.source
                && let Err(e) = crate::filestore::fs::get(id, false)
                    .and_then(|f| f.lock()?.limit(o.size, o.inodes))
            {
                return err(e);
            }
            ns.update(|t| t.remount(&point, flags, opts))
        } else if flags & ms::BIND != 0
            && let Some(found) = self.bound_namespace(&source)
        {
            // A namespace's file (`/proc/<pid>/ns/<kind>`, a descriptor of
            // one, or a path one is bound to) bound to a file: opening it
            // gives the namespace, which lives as long as the mount.
            let n = match found {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            if is_dir {
                return err(errno::ENOTDIR);
            }
            let name = crate::nsfd::name_of(n.kind);
            let root = [name.as_bytes(), format!(":[{}]", n.id).as_bytes()].concat();
            ns.update(|t| {
                t.mount(
                    &point,
                    FsType::Nsfs,
                    Source::Ns(n),
                    root,
                    flags & ms::PER_MOUNT,
                    b"nsfs".to_vec(),
                    b"rw".to_vec(),
                );
                Ok(())
            })
        } else if flags & ms::BIND != 0 {
            // A file fwe serves from the host outside any mount (the
            // standard device nodes): that host file.
            let device = self.fs().device_host(&source);
            let from = match device {
                Some(_) => Err(errno::EINVAL),
                None => self.mount_path(&source, true),
            };
            match from {
                Ok((from, _)) => {
                    ns.update(|t| t.bind(&from, &point, flags & ms::REC != 0).map(|_| ()))
                }
                Err(errno::EINVAL) => match device.or_else(|| self.host_source(&source)) {
                    Some(host) => ns.update(|t| {
                        t.mount(
                            &point,
                            FsType::Tmpfs,
                            Source::Host(host),
                            b"/".to_vec(),
                            0,
                            b"devtmpfs".to_vec(),
                            Vec::new(),
                        );
                        Ok(())
                    }),
                    None => return err(errno::EINVAL),
                },
                Err(e) => return err(e),
            }
        } else if flags & ms::MOVE != 0 {
            let (from, _) = match self.mount_path(&source, true) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            ns.update(|t| t.move_mount(&from, &point))
        } else if flags & ms::PROPAGATION != 0 {
            let how = flags & ms::PROPAGATION;
            if how.count_ones() != 1 {
                return err(errno::EINVAL);
            }
            ns.update(|t| t.set_propagation(&point, how, flags & ms::REC != 0))
        } else {
            if !is_dir {
                return err(errno::ENOTDIR);
            }
            // A new mount names its filesystem's type.
            if fstype_ptr == 0 {
                return err(errno::EINVAL);
            }
            // Only the v2 hierarchy: `cgroup` (v1) is no type fwe knows, as
            // on a kernel built without it.
            let Some(kind) = FsType::from_name(&fstype) else { return err(errno::ENODEV) };
            if !self.may_make_filesystem(kind) {
                return err(errno::EPERM);
            }
            let data = match Self::fs_data(kind, &data) {
                Ok(d) => d,
                Err(e) => return err(e),
            };
            let (src, root, more) = match self.new_filesystem(kind, &data) {
                Ok(v) => v,
                Err(e) => return err(e),
            };

            flags |= more | default_atime(flags);
            let device = if source.is_empty() { kind.name().as_bytes().to_vec() } else { source };
            ns.update(|t| {
                t.mount(&point, kind, src, root, flags, device, data);
                Ok(())
            })
        };
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `umount2(target, flags)`: a mount in use is refused (`EBUSY`, see
    /// [`Self::mount_busy`]) unless detached (`MNT_DETACH`), forced
    /// (`MNT_FORCE`) or not, as Linux's own file systems refuse it; with
    /// `MNT_EXPIRE` an unused one is first marked (`EAGAIN`), and unmounted
    /// by the next such call if nothing used it in between.
    pub(crate) fn sys_umount2(&mut self, target: u64, flags: u64) -> i64 {
        if !self.may_mount() {
            return err(errno::EPERM);
        }
        if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0
            || flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0
        {
            return err(errno::EINVAL);
        }
        let target = guest!(uaccess::read_cstr(target, uaccess::PATH_MAX));
        crate::fs::UNMOUNTING.with(|u| u.set(true));
        let found = self.mount_path(&target, flags & UMOUNT_NOFOLLOW == 0);
        crate::fs::UNMOUNTING.with(|u| u.set(false));
        let (point, _) = match found {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let ns = self.fs().mount_ns().clone();
        let table = ns.table();
        let (m, rest) = table.locate(&point);
        if !rest.is_empty() || m.parent == m.id {
            return err(errno::EINVAL);
        }
        let id = m.id;
        if flags & MNT_EXPIRE != 0 {
            // Not the caller's root; not in use; marked by a first call,
            // unmounted by a second if nothing used it in between.
            if point == self.fs().proc_root() {
                return err(errno::EINVAL);
            }
            if self.mount_busy(&table, id) {
                return err(errno::EBUSY);
            }
            if !table.expiring.contains(&id) {
                let _ = ns.update(|t| {
                    t.expiring.push(id);
                    Ok(())
                });
                return err(errno::EAGAIN);
            }
        } else if flags & MNT_DETACH == 0 && self.mount_busy(&table, id) {
            return err(errno::EBUSY);
        }
        match ns.update(|t| {
            t.expiring.retain(|i| *i != id);
            t.umount(&point)
        }) {
            Ok(()) => {
                crate::inotify::unmounted(ns.dir(), &point);
                0
            }
            Err(e) => err(e),
        }
    }

    /// Whether mount `id` is in use, as Linux refuses to unmount one that
    /// is (`EBUSY`): something is mounted under it, the caller's working
    /// directory or root is in it, or a file opened through it is open in
    /// this process or, as far as the host can tell, another fwe process
    /// of the namespace.
    fn mount_busy(&self, table: &crate::mounts::Table, id: u32) -> bool {
        use crate::mounts::under;
        let Some(m) = table.get(id) else { return false };
        if table.mounts.iter().any(|c| c.parent == id && c.id != id) {
            return true;
        }
        let fs = self.fs();
        let cwd_in = match fs.cwd_mount().filter(|c| table.get(*c).is_some()) {
            Some(c) => c == id,
            None => under(&fs.to_ns(fs.cwd()), &m.point).is_some(),
        };
        let root_in = match fs.root_mount().filter(|r| table.get(*r).is_some()) {
            Some(r) => r == id,
            None => fs.proc_root() != b"/" && under(fs.proc_root(), &m.point).is_some(),
        };
        if cwd_in || root_in {
            return true;
        }
        // A file opened through it here.
        if crate::fdmarks::open_in(id) {
            return true;
        }
        // One open in another fwe process of the namespace, by where it is
        // on the host: in this mount's files and in no other mount's as
        // deeply (a path two mounts share, as a bind of one directory or a
        // lower layer two overlays have, could be either's).
        let canonical = |r: &[u8]| -> Vec<u8> {
            use std::os::unix::ffi::{OsStrExt, OsStringExt};
            std::fs::canonicalize(std::ffi::OsStr::from_bytes(r))
                .map_or_else(|_| r.to_vec(), |p| p.into_os_string().into_vec())
        };
        let roots_of = |m: &crate::mounts::Mount| -> Vec<Vec<u8>> {
            let roots: Vec<Vec<u8>> = match &m.source {
                Source::Host(_) => m.host_path(b"").into_iter().collect(),
                Source::Overlay(l) => {
                    l.places().filter_map(crate::overlay::Place::host).map(<[u8]>::to_vec).collect()
                }
                Source::Synthetic | Source::Ns(_) | Source::Store(_) => Vec::new(),
            };
            roots.iter().map(|r| canonical(r)).collect()
        };
        let roots = roots_of(m);
        if roots.is_empty() {
            return false;
        }
        let others: Vec<Vec<u8>> =
            table.mounts.iter().filter(|o| o.id != id).flat_map(roots_of).collect();
        let deepest = |path: &[u8], roots: &[Vec<u8>]| {
            roots.iter().filter(|r| under(path, r).is_some()).map(Vec::len).max()
        };
        let ours = |path: &[u8]| match deepest(path, &roots) {
            Some(d) => deepest(path, &others).is_none_or(|o| o < d),
            None => false,
        };
        let me = crate::host::pid();
        let ns = fs.mount_ns().dir().to_vec();
        crate::procreg::all()
            .into_iter()
            .filter(|(p, r)| *p != me && r.ns.first().is_none_or(|d| *d == ns))
            .any(|(p, _)| {
                crate::procpid::fds(p).into_iter().any(|(_, t)| match t {
                    crate::procpid::FdTarget::Path(path) => ours(&path),
                    _ => false,
                })
            })
    }

    /// `pivot_root(new_root, put_old)`: the mount at `new_root` becomes the
    /// namespace's root, the old root moves to `put_old`, and a process
    /// whose root was the old one now has the new one; its working
    /// directory, if in the old tree, follows it there.
    pub(crate) fn sys_pivot_root(&mut self, new_root: u64, put_old: u64) -> i64 {
        if !self.may_mount() {
            return err(errno::EPERM);
        }
        let new_root = guest!(uaccess::read_cstr(new_root, uaccess::PATH_MAX));
        let put_old = guest!(uaccess::read_cstr(put_old, uaccess::PATH_MAX));
        let (new_ns, new_dir) = match self.mount_path(&new_root, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let (old_ns, old_dir) = match self.mount_path(&put_old, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if !new_dir || !old_dir {
            return err(errno::ENOTDIR);
        }
        // The mount at the caller's root (which must be one's root) is the
        // one replaced: the namespace's, or a chroot's.
        let root = self.fs().proc_root().to_vec();
        let cwd_ns = self.fs().to_ns(self.fs().cwd());
        let ns = self.fs().mount_ns().clone();
        let new_put = match ns.update(|t| t.pivot_root(&root, &new_ns, &old_ns)) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        // A working directory at the root stays there (the new root now);
        // one in the new root's tree, or in the old one's, moves with it,
        // as Linux has it.
        use crate::mounts::{join, under};
        let moved = |p: &[u8]| -> Vec<u8> {
            if p == root {
                p.to_vec()
            } else if let Some(rest) = under(p, &new_ns) {
                join(&root, rest)
            } else if let Some(rest) = under(p, &root) {
                join(&new_put, rest)
            } else {
                p.to_vec()
            }
        };
        let cwd_ns = moved(&cwd_ns);
        // What open descriptors were opened at moves the same way: a mount
        // attached through a descriptor is still that descriptor's after
        // the pivot (crun sets its container's `/sys` flags so).
        crate::fdmarks::rebase(moved);
        let fs = self.fs_mut();
        let cwd = fs.from_ns(&cwd_ns).unwrap_or_else(|| b"/".to_vec());
        let root_mount = fs.mounts().locate(&root).0.id;
        fs.set_root(root, cwd);
        fs.set_mounts(root_mount, 0);
        0
    }

    /// `chroot(path)`.
    pub(crate) fn sys_chroot(&mut self, path: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if !self.creds.has_own(crate::caps::CAP_SYS_CHROOT) {
            // Linux looks the directory up, and checks it may be entered,
            // before the privilege.
            const X_OK: u64 = 1;
            let r = self.access_path(fwe_abi::fcntl::AT_FDCWD as i32, &path, X_OK, true, true);
            return if r < 0 { r } else { err(errno::EPERM) };
        }
        let (ns, is_dir) = match self.mount_path(&path, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if !is_dir {
            return err(errno::ENOTDIR);
        }
        // The working directory stays where it is; from the new root it
        // has a path only if it is inside.
        let fs = self.fs_mut();
        let cwd_ns = fs.to_ns(fs.cwd());
        let inside = crate::mounts::under(&cwd_ns, &ns).map(|r| crate::mounts::join(b"/", r));
        let outside = inside.is_none().then(|| cwd_ns.clone());
        let cwd = inside.unwrap_or_else(|| b"/".to_vec());
        let root_mount = fs.mounts().locate(&ns).0.id;
        let cwd_mount = fs.cwd_mount().unwrap_or(0);
        fs.set_root(ns, cwd);
        fs.set_cwd_outside(outside);
        fs.set_mounts(root_mount, cwd_mount);
        0
    }
}
