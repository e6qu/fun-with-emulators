//! `mount`, `umount2`, `pivot_root` and `chroot`, on the mount namespace's
//! table ([`crate::mounts`]).
//!
//! A tmpfs is a fresh directory of fwe's ([`tmpfs_dir`]), the synthetic
//! filesystems (`proc`, `sysfs`, `cgroup2`, `devpts`, `mqueue`) are fwe's
//! own, and a bind mount shows a directory or file the guest names. Mounts
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
    /// resolution. Fails with `EINVAL` for one fwe cannot place.
    fn mount_path(&self, path: &[u8], follow: bool) -> Result<(Vec<u8>, bool), i32> {
        if let Some(entry) = self.fs().synthetic(fwe_abi::fcntl::AT_FDCWD as i32, path) {
            if matches!(entry, crate::procfs::Entry::Missing) {
                return Err(errno::ENOENT);
            }
            let absolute = crate::fs::normalize(self.fs().cwd(), path);
            return Ok((self.fs().to_ns(&absolute), false));
        }
        let r = self.fs().resolve(fwe_abi::fcntl::AT_FDCWD as i32, path, follow)?;
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

    /// `mount(source, target, fstype, flags, data)`.
    pub(crate) fn sys_mount(
        &mut self,
        source: u64,
        target: u64,
        fstype: u64,
        flags: u64,
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
            ns.update(|t| {
                // A remount keeps what it does not set of the atime flags.
                t.remount(&point, flags, opts)
            })
        } else if flags & ms::BIND != 0 {
            let (from, _) = match self.mount_path(&source, true) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            ns.update(|t| t.bind(&from, &point, flags & ms::REC != 0, 0).map(|_| ()))
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
            // `cgroup` names the v2 hierarchy when that is the one there is.
            let name: &[u8] = if fstype == b"cgroup" { b"cgroup2" } else { &fstype };
            let Some(kind) = FsType::from_name(name) else { return err(errno::ENODEV) };
            let src = match kind {
                FsType::Tmpfs => match tmpfs_dir(mode_option(&data).unwrap_or(0o1777)) {
                    Ok(dir) => Source::Host(dir),
                    Err(e) => return err(e),
                },
                _ => Source::Synthetic,
            };
            let device = if source.is_empty() { kind.name().as_bytes().to_vec() } else { source };
            ns.update(|t| {
                t.mount(&point, kind, src, b"/".to_vec(), flags, device, data);
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
        let cwd = match crate::mounts::under(&cwd_ns, &new_ns) {
            Some(rest) => crate::mounts::join(b"/", rest),
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

    /// `unshare(flags)`. Of the namespaces, only the mount namespace yet.
    pub(crate) fn sys_unshare(&mut self, flags: u64) -> i64 {
        use fwe_abi::clone::*;
        // What is shared already in a single-threaded process, or not at all.
        let unshared = CLONE_FILES | CLONE_FS | CLONE_SYSVSEM;
        if flags & !(unshared | CLONE_NEWNS) != 0 {
            return err(errno::EINVAL);
        }
        if flags & CLONE_NEWNS != 0 {
            if !self.creds.has_admin() {
                return err(errno::EPERM);
            }
            if let Err(e) = self.new_mount_ns() {
                return err(e);
            }
        }
        0
    }

    /// `unshare(CLONE_NEWNS)` and a `clone` with it: a copy of the mount
    /// namespace of the process's own.
    pub(crate) fn new_mount_ns(&mut self) -> Result<(), i32> {
        let fs = self.fs.as_mut().expect("filesystem configured");
        let copy = fs.mount_ns().copy()?;
        fs.set_mount_ns(std::sync::Arc::new(copy));
        Ok(())
    }
}
