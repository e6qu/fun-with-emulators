//! `mount`, `umount2`, `pivot_root` and `chroot`, on the mount namespace's
//! table ([`crate::mounts`]).
//!
//! A tmpfs is a fresh directory of fwe's ([`tmpfs_dir`]), the synthetic
//! filesystems (`proc`, `sysfs`, `cgroup2`, `devpts`, `mqueue`) are fwe's
//! own, an overlay stacks directories the guest names
//! ([`crate::overlay`]), and a bind mount shows a directory or file the
//! guest names. Mounts
//! do not propagate between namespaces: each is private, whatever its
//! propagation type says.

use crate::mounts::{FsType, Source, ms};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{err, errno};

/// `umount2` flags.
const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

/// A new directory of fwe's to back a tmpfs: in its private directory, so
/// only the user reaches it from the host.
fn tmpfs_dir(mode: u32) -> Result<Vec<u8>, i32> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut dir = crate::fs::shm::user_dir()?;
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    dir.extend_from_slice(
        format!("/tmpfs-{pid}-{now}-{}", N.fetch_add(1, Ordering::Relaxed)).as_bytes(),
    );
    let c = std::ffi::CString::new(dir.clone()).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    if unsafe { libc::mkdir(c.as_ptr(), 0o700) } != 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    // The mode asked for, whatever the umask.
    // SAFETY: as above.
    unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
    Ok(dir)
}

/// The `mode=` a filesystem's options give (octal), if any.
fn mode_option(data: &[u8]) -> Option<u32> {
    data.split(|&b| b == b',')
        .find_map(|o| o.strip_prefix(b"mode="))
        .and_then(|m| u32::from_str_radix(std::str::from_utf8(m).ok()?, 8).ok())
}

impl<P: Platform> Kernel<P> {
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
                Entry::Fd { fd, .. } if follow => {
                    // The file itself, where it was opened.
                    let ns = self.fs().fd_ns_path(fd).ok_or(errno::EINVAL)?;
                    if crate::synthdir::path_of(fd).is_some() {
                        return Ok((ns, true));
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
        let name = r.name_c()?;
        // It must exist.
        // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a live directory descriptor and NUL-terminated name.
        if unsafe {
            libc::fstatat(
                std::os::fd::AsRawFd::as_raw_fd(&r.dir),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
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
            FsType::Tmpfs => Source::Host(tmpfs_dir(mode_option(data).unwrap_or(0o1777))?),
            FsType::Cgroup2 => {
                // The hierarchy from the cgroup namespace's root.
                let dir = crate::cgroupfs::tree_dir()?;
                root = self.fs().ns.cgroup.as_ref().map_or(b"/".to_vec(), |c| c.get().root.clone());
                Source::Host(dir)
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

    /// The host directory of the guest directory `path`, which must be in
    /// a mount of host directories (`EINVAL` for one in an overlay or in
    /// a filesystem of fwe's).
    fn host_dir(&self, path: &[u8]) -> Result<Vec<u8>, i32> {
        self.host_dir_rw(path, false)
    }

    /// [`host_dir`](Self::host_dir) of a directory to be written to:
    /// `EROFS` in a read-only mount.
    fn host_dir_rw(&self, path: &[u8], write: bool) -> Result<Vec<u8>, i32> {
        let (ns, is_dir) = self.mount_path(path, true)?;
        if !is_dir {
            return Err(errno::ENOTDIR);
        }
        let table = self.fs().mounts();
        let (m, rest) = table.locate(&ns);
        if write && m.read_only() {
            return Err(errno::EROFS);
        }
        m.host_path(&rest).ok_or(errno::EINVAL)
    }

    /// The layers an overlay's mount options (`data`) name, checked as
    /// Linux checks them, with the work directory made ready.
    fn overlay_layers(&self, data: &[u8]) -> Result<crate::overlay::Layers, i32> {
        let o = crate::overlay::parse(data)?;
        let lowers = o.lowers.iter().map(|p| self.host_dir(p)).collect::<Result<Vec<_>, _>>()?;
        let upper = o.upper.as_deref().map(|p| self.host_dir_rw(p, true)).transpose()?;
        let work = o.work.as_deref().map(|p| self.host_dir_rw(p, true)).transpose()?;
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
                Ok(st.st_dev as u64)
            };
            if dev(u)? != dev(w)?
                || crate::mounts::under(u, w).is_some()
                || crate::mounts::under(w, u).is_some()
            {
                return Err(errno::EINVAL);
            }
            crate::overlay::prepare_work(w)?;
        }
        Ok(crate::overlay::Layers { upper, work, lowers, userxattr: o.userxattr })
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
        if !self.creds.has_admin() {
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
            ns.update(|t| t.remount(&point, flags, opts))
        } else if flags & ms::BIND != 0 {
            match self.mount_path(&source, true) {
                Ok((from, _)) => {
                    ns.update(|t| t.bind(&from, &point, flags & ms::REC != 0, 0).map(|_| ()))
                }
                // A file fwe serves from the host outside any mount (the
                // standard device nodes): that host file.
                Err(errno::EINVAL) => match self.host_source(&source) {
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
            // `cgroup` names the v2 hierarchy when that is the one there is.
            let name: &[u8] = if fstype == b"cgroup" { b"cgroup2" } else { &fstype };
            let Some(kind) = FsType::from_name(name) else { return err(errno::ENODEV) };
            let (src, root, more) = match self.new_filesystem(kind, &data) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            flags |= more;
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

    /// `umount2(target, flags)`. A mount is always detached at once
    /// (`MNT_DETACH`): fwe does not track what keeps it busy.
    pub(crate) fn sys_umount2(&mut self, target: u64, flags: u64) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0
            || flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0
        {
            return err(errno::EINVAL);
        }
        let target = guest!(uaccess::read_cstr(target, uaccess::PATH_MAX));
        let (point, _) = match self.mount_path(&target, flags & UMOUNT_NOFOLLOW == 0) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match self.fs().mount_ns().clone().update(|t| t.umount(&point)) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `pivot_root(new_root, put_old)`: the mount at `new_root` becomes the
    /// namespace's root, the old root moves to `put_old`, and a process
    /// whose root was the old one now has the new one; its working
    /// directory, if in the old tree, follows it there.
    pub(crate) fn sys_pivot_root(&mut self, new_root: u64, put_old: u64) -> i64 {
        if !self.creds.has_admin() {
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
        // Only a process whose root is the namespace's can pivot it.
        if self.fs().proc_root() != b"/" {
            return err(errno::EINVAL);
        }
        let cwd_ns = self.fs().to_ns(self.fs().cwd());
        let ns = self.fs().mount_ns().clone();
        let old_point = match ns.update(|t| t.pivot_root(&new_ns, &old_ns)) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        // A working directory at the old root moves to the new one, as
        // Linux moves it.
        let cwd = match crate::mounts::under(&cwd_ns, &new_ns) {
            Some(rest) => crate::mounts::join(b"/", rest),
            None if cwd_ns == b"/" => b"/".to_vec(),
            None => crate::mounts::join(&old_point, &cwd_ns),
        };
        let fs = self.fs.as_mut().expect("filesystem configured");
        fs.set_root(b"/".to_vec(), cwd);
        0
    }

    /// `chroot(path)`.
    pub(crate) fn sys_chroot(&mut self, path: u64) -> i64 {
        if !self.creds.has_chroot() {
            return err(errno::EPERM);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let (ns, is_dir) = match self.mount_path(&path, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if !is_dir {
            return err(errno::ENOTDIR);
        }
        // The working directory stays where it is; from the new root it
        // has a path only if it is inside.
        let fs = self.fs.as_mut().expect("filesystem configured");
        let cwd_ns = fs.to_ns(fs.cwd());
        let cwd = crate::mounts::under(&cwd_ns, &ns)
            .map(|r| crate::mounts::join(b"/", r))
            .unwrap_or_else(|| b"/".to_vec());
        fs.set_root(ns, cwd);
        0
    }
}
