//! File and directory system calls, built on the [`crate::fs`] resolver.

use crate::fs::Fs;
use crate::host::{self, last_error, ret};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{Stat, Statx, err, errno, fcntl, statx_mask};
use std::ffi::CString;
use std::os::fd::AsRawFd;

#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn stat_to_linux(s: &libc::stat) -> Stat {
    // A host device has the numbers Linux gives it.
    let rdev = crate::devnodes::linux_numbers_of_host(s)
        .map_or(s.st_rdev as u64, |n| crate::devnodes::makedev(n.major, n.minor));
    Stat {
        st_dev: s.st_dev as u64,
        st_ino: s.st_ino as u64,
        st_mode: s.st_mode as u32,
        st_nlink: s.st_nlink as u32,
        st_uid: host::uid_to_linux(s.st_uid),
        st_gid: host::gid_to_linux(s.st_gid),
        st_rdev: rdev,
        __pad1: 0,
        st_size: s.st_size as i64,
        st_blksize: s.st_blksize as i32,
        __pad2: 0,
        st_blocks: s.st_blocks as i64,
        st_atime: s.st_atime as i64,
        st_atime_nsec: s.st_atime_nsec as u64,
        st_mtime: s.st_mtime as i64,
        st_mtime_nsec: s.st_mtime_nsec as u64,
        st_ctime: s.st_ctime as i64,
        st_ctime_nsec: s.st_ctime_nsec as u64,
        __unused4: 0,
        __unused5: 0,
    }
}

#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn statx_from(s: &libc::stat) -> Statx {
    let rdev = crate::devnodes::linux_numbers_of_host(s)
        .map_or(s.st_rdev as u64, |n| crate::devnodes::makedev(n.major, n.minor));
    let ts = |sec: i64, nsec: i64| fwe_abi::StatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    };
    Statx {
        stx_mask: statx_mask::STATX_BASIC_STATS,
        stx_blksize: s.st_blksize as u32,
        stx_attributes: 0,
        stx_nlink: s.st_nlink as u32,
        stx_uid: host::uid_to_linux(s.st_uid),
        stx_gid: host::gid_to_linux(s.st_gid),
        stx_mode: s.st_mode as u16,
        __spare0: 0,
        stx_ino: s.st_ino as u64,
        stx_size: s.st_size as u64,
        stx_blocks: s.st_blocks as u64,
        stx_attributes_mask: 0,
        stx_atime: ts(s.st_atime as i64, s.st_atime_nsec as i64),
        stx_btime: fwe_abi::StatxTimestamp::default(),
        stx_ctime: ts(s.st_ctime as i64, s.st_ctime_nsec as i64),
        stx_mtime: ts(s.st_mtime as i64, s.st_mtime_nsec as i64),
        stx_rdev_major: crate::devnodes::major(rdev),
        stx_rdev_minor: crate::devnodes::minor(rdev),
        stx_dev_major: major(s.st_dev as u64),
        stx_dev_minor: minor(s.st_dev as u64),
        stx_mnt_id: 0,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        __spare3: [0; 12],
    }
}

/// If `path` is `/dev/pts/<n>` with a decimal `<n>`, return `n`.
fn pts_number(path: &[u8]) -> Option<u32> {
    let rest = path.strip_prefix(b"/dev/pts/")?;
    if rest.is_empty() || !rest.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(rest).ok()?.parse().ok()
}

fn major(dev: u64) -> u32 {
    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff)) as u32
}

fn minor(dev: u64) -> u32 {
    (((dev >> 12) & 0xffff_ff00) | (dev & 0xff)) as u32
}

/// Fetch host metadata for the resolved path (symlink already resolved).
fn stat_at(dir: i32, name: &CString) -> Result<libc::stat, i32> {
    // SAFETY: `out` is a valid out-parameter; `name` is NUL-terminated.
    let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd; `out` valid.
    let r = unsafe { libc::fstatat(dir, name.as_ptr(), &mut out, libc::AT_SYMLINK_NOFOLLOW) };
    if r < 0 { Err(host::errno_to_linux(host::last_errno())) } else { Ok(out) }
}

impl<P: Platform> Kernel<P> {
    pub(crate) fn fs(&self) -> &Fs {
        self.fs.as_ref().expect("filesystem configured")
    }

    pub(crate) fn sys_openat(&mut self, dirfd: u64, path: u64, flags: u64, mode: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        self.open_path(dirfd, path, flags, mode)
    }

    /// `openat` of `path`, read from the guest.
    fn open_path(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        // Pseudo-terminal devices are synthesized, not served from the rootfs.
        if path == b"/dev/ptmx" {
            return crate::pty::open_master(flags);
        }
        if let Some(n) = pts_number(&path) {
            return crate::pty::open_slave(n, host::open_flags_to_host(flags));
        }
        // Synthetic /proc and /sys files take priority over the host rootfs.
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            return match entry {
                crate::procfs::Entry::File(_)
                    if self.fs().proc_path(dirfd as i32, &path).as_deref()
                        == Some(b"/proc/self/status") =>
                {
                    anon_fd(&self.self_status())
                }
                crate::procfs::Entry::File(content)
                    if flags & fcntl::O_ACCMODE != fcntl::O_RDONLY =>
                {
                    // The map files take a write; the rest are read-only.
                    match self.map_file(dirfd as i32, &path) {
                        Some(mark) => {
                            let fd = anon_fd(&content);
                            if fd >= 0 {
                                crate::fdmarks::mark(fd as i32, mark);
                            }
                            fd
                        }
                        None => err(errno::EACCES),
                    }
                }
                crate::procfs::Entry::File(content) => anon_fd(&content),
                crate::procfs::Entry::Symlink(target) => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return err(errno::ELOOP);
                    }
                    // Follow the link, from the directory it is in.
                    let target = self.fs().link_target(dirfd as i32, &path, &target);
                    self.open_path(fcntl::AT_FDCWD as u64, target, flags, mode)
                }
                crate::procfs::Entry::Fd { fd, target } => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return err(errno::ELOOP);
                    }
                    if crate::fs::has_path(fd, &target) {
                        // Reopen the file, as Linux does: the same one, in
                        // the mount it was opened through, whatever has
                        // become of its path.
                        return reopen(fd, flags);
                    }
                    // A pipe, socket, memfd or the like: a new descriptor
                    // for it.
                    let cmd = if flags & fcntl::O_CLOEXEC != 0 {
                        libc::F_DUPFD_CLOEXEC
                    } else {
                        libc::F_DUPFD
                    };
                    // SAFETY: plain host call on an open guest descriptor.
                    ret(unsafe { libc::fcntl(fd, cmd, 0) })
                }
                crate::procfs::Entry::Dir => match self.fs().synth_children(dirfd as i32, &path) {
                    Some(entries) => {
                        let at = self.fs().absolute_path(dirfd as i32, &path).unwrap_or_default();
                        let fd = crate::synthdir::open(at, entries);
                        if fd >= 0 && self.fs().lists_fds(dirfd as i32, &path) {
                            // Linux lists the listing's own descriptor too.
                            let name = fd.to_string().into_bytes();
                            crate::synthdir::add(fd as i32, name, crate::procfs::DT_LNK);
                        }
                        fd
                    }
                    None => err(errno::ENOENT),
                },
                crate::procfs::Entry::Missing => err(errno::ENOENT),
            };
        }
        self.sys_openat_bytes(dirfd, &path, flags, mode)
    }

    fn sys_openat_bytes(&mut self, dirfd: u64, path: &[u8], flags: u64, mode: u64) -> i64 {
        let follow_final = flags & fcntl::O_NOFOLLOW == 0
            && flags & (fcntl::O_CREAT | fcntl::O_EXCL) != fcntl::O_CREAT | fcntl::O_EXCL;
        let resolved = match self.fs().resolve(dirfd as i32, path, follow_final) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // O_TMPFILE includes O_DIRECTORY's bit: all of it, or not at all.
        let writes = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY
            || flags & fcntl::O_TRUNC != 0
            || flags & fcntl::O_TMPFILE == fcntl::O_TMPFILE;
        if writes || flags & fcntl::O_CREAT != 0 {
            // A file that exists on a read-only mount may still be opened
            // to read with O_CREAT.
            let exists =
                resolved.name_c().is_ok_and(|n| stat_at(resolved.dir.as_raw_fd(), &n).is_ok());
            if (writes || !exists)
                && let Err(e) = resolved.writable()
            {
                return err(e);
            }
        }
        let name = match resolved.name_c() {
            Ok(n) => n,
            Err(e) => return err(e),
        };
        let mut host_flags = host::open_flags_to_host(flags);
        if flags & fcntl::O_DIRECTORY == 0 && resolved.name == b"." {
            // Opening the directory itself.
            host_flags |= libc::O_DIRECTORY;
        }
        let mode = if flags & fcntl::O_CREAT != 0 { self.fs().apply_umask(mode as u32) } else { 0 };
        if resolved.fstype == crate::mounts::FsType::Cgroup2
            && let Some(host) = crate::fs::host_path_in(resolved.dir.as_raw_fd(), &resolved.name)
            && let Some((cg, Some(file))) = crate::cgroupfs::locate(&host)
        {
            // What the file reports is what is so as it is opened.
            let dir = crate::cgroupfs::host_dir(&cg).unwrap_or_default();
            crate::cgroupfs::refresh(&dir, &cg, &file);
            use std::os::unix::ffi::OsStrExt;
            if flags & fcntl::O_CREAT != 0
                && !std::path::Path::new(std::ffi::OsStr::from_bytes(&host)).exists()
            {
                // A cgroup has only the files the kernel makes.
                return err(errno::EACCES);
            }
        }
        // SAFETY: `dir` is a live directory fd.
        let mut fd = unsafe {
            host::openat(resolved.dir.as_raw_fd(), &name, host_flags, mode as libc::c_uint)
        };
        if fd < 0
            && flags & fcntl::O_PATH != 0
            && matches!(host::last_errno(), libc::ENXIO | libc::ENODEV | libc::EBUSY)
        {
            // O_PATH names a device without opening it; the host has no such
            // open, so a stand-in holds the node's place (where it was
            // opened, which is what an O_PATH descriptor is used for).
            // SAFETY: a constant NUL-terminated path.
            fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        }
        if fd < 0 {
            return last_error();
        }
        // A device: allowed by the cgroup's device programs, and the host's
        // own device behind one of fwe's nodes.
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // An O_PATH descriptor is of the node itself, the device untouched.
        // SAFETY: a valid out-parameter.
        if flags & fcntl::O_PATH == 0 && unsafe { libc::fstat(fd, &mut st) } == 0 {
            let node = if crate::devnodes::marked(&st) {
                crate::devnodes::node_of(fd)
            } else {
                crate::devnodes::linux_numbers_of_host(&st)
            };
            if let Some(n) = node {
                let device = open_device(fd, n, flags, crate::devnodes::marked(&st));
                if device < 0 || crate::devnodes::marked(&st) {
                    // SAFETY: closing the node's own descriptor.
                    unsafe { libc::close(fd) };
                }
                if device < 0 {
                    return device;
                }
                if crate::devnodes::marked(&st) {
                    // Linked to the node, where it was opened.
                    if let Some(ns) = resolved.ns_path {
                        crate::fdmarks::opened(
                            device as i32,
                            ns,
                            resolved.mount_flags,
                            resolved.fstype,
                        );
                    }
                    return device;
                }
            }
        }
        if let Some(ns) = resolved.ns_path {
            crate::fdmarks::opened(fd, ns, resolved.mount_flags, resolved.fstype);
        }
        fd as i64
    }

    pub(crate) fn sys_faccessat(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        let r = match self.fs().resolve(dirfd as i32, &path, follow) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        const W_OK: u64 = 2;
        if mode & W_OK != 0 && r.writable().is_err() {
            return err(errno::EROFS);
        }
        let (dir, name) = match r.name_c() {
            Ok(n) => (r.dir, n),
            Err(e) => return err(e),
        };
        // With CAP_DAC_OVERRIDE (root's) the permission bits are bypassed, as
        // on Linux: any existing file is accessible, and X_OK needs only one
        // execute bit set.
        const X_OK: u64 = 1;
        if self.creds.has(crate::caps::CAP_DAC_OVERRIDE) {
            // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: valid dirfd, path and stat out-parameter.
            if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, 0) } < 0 {
                return last_error();
            }
            if mode & X_OK != 0 && (st.st_mode & 0o111) == 0 {
                return err(errno::EACCES);
            }
            return 0;
        }
        // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd.
        ret(unsafe { libc::faccessat(dir.as_raw_fd(), name.as_ptr(), mode as i32, 0) })
    }

    /// `statfs(path, buf)`: the filesystem of the directory holding `path`
    /// (a rootfs has no mount points within it, so it is the same one).
    pub(crate) fn sys_statfs(&mut self, path: u64, buf: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Some(entry) = self.fs().synthetic(fcntl::AT_FDCWD as i32, &path) {
            if matches!(entry, crate::procfs::Entry::Missing) {
                return err(errno::ENOENT);
            }
            // A filesystem of fwe's: its mount says what it is.
            let absolute = crate::fs::normalize(self.fs().cwd(), &path);
            let (m, _) = self.fs().mount_of(&absolute);
            let root = self.fs().resolve(fcntl::AT_FDCWD as i32, b"/", true);
            return match root {
                Ok(r) => statfs_fd(r.dir.as_raw_fd(), buf, Some((m.fstype, m.flags))),
                Err(e) => err(e),
            };
        }
        let r = match self.fs().resolve(fcntl::AT_FDCWD as i32, &path, true) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let mount = r.ns_path.is_some().then_some((r.fstype, r.mount_flags));
        statfs_fd(r.dir.as_raw_fd(), buf, mount)
    }

    /// `fstatfs(fd, buf)`.
    pub(crate) fn sys_fstatfs(&mut self, fd: u64, buf: u64) -> i64 {
        let fd = fd as i32;
        if let Some(o) = crate::fdmarks::origin(fd) {
            return statfs_fd(fd, buf, Some((o.fstype, o.flags)));
        }
        let mount = self.fs.as_ref().and_then(|fs| fs.ns_path_of_fd(fd)).map(|ns| {
            let table = self.fs().mounts();
            let (m, _) = table.locate(&ns);
            (m.fstype, m.flags)
        });
        statfs_fd(fd, buf, mount)
    }

    pub(crate) fn sys_newfstatat(&mut self, dirfd: u64, path: u64, buf: u64, flags: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            return self.sys_fstat(dirfd, buf);
        }
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            use fwe_abi::stat as st;
            let s = match entry {
                crate::procfs::Entry::File(c) => synth_stat(st::S_IFREG | 0o444, c.len() as u64),
                crate::procfs::Entry::Symlink(_) if follow => {
                    // /proc/self/exe and the like follow to the real target.
                    let target = match self.fs().synthetic(dirfd as i32, &path) {
                        Some(crate::procfs::Entry::Symlink(t)) => t,
                        _ => return err(errno::ENOENT),
                    };
                    let target = self.fs().link_target(dirfd as i32, &path, &target);
                    return self.stat_path(fcntl::AT_FDCWD as u64, &target, buf, flags);
                }
                crate::procfs::Entry::Symlink(t) => synth_stat(st::S_IFLNK | 0o777, t.len() as u64),
                crate::procfs::Entry::Fd { fd, .. } if follow => {
                    return self.sys_fstat(fd as u64, buf);
                }
                crate::procfs::Entry::Fd { target, .. } => {
                    synth_stat(st::S_IFLNK | 0o700, target.len() as u64)
                }
                crate::procfs::Entry::Dir => synth_stat(st::S_IFDIR | 0o555, 0),
                crate::procfs::Entry::Missing => return err(errno::ENOENT),
            };
            guest!(uaccess::write(buf, s));
            return 0;
        }
        let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match stat_at(dir.as_raw_fd(), &name) {
            Ok(s) => {
                let node = crate::devnodes::marked(&s)
                    .then(|| crate::devnodes::node_at(dir.as_raw_fd(), &name))
                    .flatten();
                guest!(uaccess::write(buf, as_node(stat_to_linux(&s), node)));
                0
            }
            Err(e) => err(e),
        }
    }

    /// `stat` a path given as bytes, following a final symlink per `flags`.
    fn stat_path(&mut self, dirfd: u64, path: &[u8], buf: u64, flags: u64) -> i64 {
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        let (dir, name) = match self.resolve_c(dirfd, path, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match stat_at(dir.as_raw_fd(), &name) {
            Ok(s) => {
                guest!(uaccess::write(buf, stat_to_linux(&s)));
                0
            }
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_fstat(&mut self, fd: u64, buf: u64) -> i64 {
        if crate::synthdir::fstat_is_dir(fd as i32) {
            use fwe_abi::stat as st;
            guest!(uaccess::write(buf, synth_stat(st::S_IFDIR | 0o555, 0)));
            return 0;
        }
        // SAFETY: `out` is a valid out-parameter.
        let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: plain host call on a guest fd.
        if unsafe { libc::fstat(fd as i32, &mut out) } < 0 {
            return last_error();
        }
        let node =
            crate::devnodes::marked(&out).then(|| crate::devnodes::node_of(fd as i32)).flatten();
        guest!(uaccess::write(buf, as_node(stat_to_linux(&out), node)));
        0
    }

    pub(crate) fn sys_statx(
        &mut self,
        dirfd: u64,
        path: u64,
        flags: u64,
        _mask: u64,
        buf: u64,
    ) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let (host, node) = if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            // SAFETY: `out` is a valid out-parameter.
            let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: plain host call on a guest fd with a valid out-parameter.
            if unsafe { libc::fstat(dirfd as i32, &mut out) } < 0 {
                return last_error();
            }
            let node = crate::devnodes::marked(&out)
                .then(|| crate::devnodes::node_of(dirfd as i32))
                .flatten();
            (out, node)
        } else {
            let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
            let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            match stat_at(dir.as_raw_fd(), &name) {
                Ok(s) => {
                    let node = crate::devnodes::marked(&s)
                        .then(|| crate::devnodes::node_at(dir.as_raw_fd(), &name))
                        .flatten();
                    (s, node)
                }
                Err(e) => return err(e),
            }
        };
        let mut x = statx_from(&host);
        if let Some(n) = node {
            x.stx_mode = (n.kind | (x.stx_mode as u32 & 0o7777)) as u16;
            x.stx_rdev_major = n.major;
            x.stx_rdev_minor = n.minor;
            x.stx_size = 0;
        }
        guest!(uaccess::write(buf, x));
        0
    }

    pub(crate) fn sys_readlinkat(&mut self, dirfd: u64, path: u64, buf: u64, size: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            return match entry {
                crate::procfs::Entry::Symlink(target) | crate::procfs::Entry::Fd { target, .. } => {
                    let n = target.len().min(size as usize);
                    guest!(uaccess::write_from(buf, &target[..n]));
                    n as i64
                }
                crate::procfs::Entry::File(_) | crate::procfs::Entry::Dir => err(errno::EINVAL),
                crate::procfs::Entry::Missing => err(errno::ENOENT),
            };
        }
        let (dir, name) = match self.resolve_c(dirfd, &path, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        // SAFETY: the guest passed a buffer of `size` bytes; `name` NUL-terminated.
        ret(unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                name.as_ptr(),
                buf as *mut libc::c_char,
                size as usize,
            )
        } as i64)
    }

    pub(crate) fn sys_getcwd(&mut self, buf: u64, size: u64) -> i64 {
        let cwd = self.fs().cwd();
        let need = cwd.len() + 1;
        if (size as usize) < need {
            return err(errno::ERANGE);
        }
        let mut out = cwd.to_vec();
        out.push(0);
        guest!(uaccess::write_from(buf, &out));
        need as i64
    }

    pub(crate) fn sys_chdir(&mut self, path: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let fs = self.fs.as_mut().expect("filesystem configured");
        match fs.chdir(fcntl::AT_FDCWD as i32, &path) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_fchdir(&mut self, fd: u64) -> i64 {
        let fs = self.fs.as_mut().expect("filesystem configured");
        match fs.fchdir(fd as i32) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_mkdirat(&mut self, dirfd: u64, path: u64, mode: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            // Nothing is made in fwe's own filesystems: what is there exists,
            // and proc has no room for more (sysfs refuses outright).
            let sysfs = self
                .fs()
                .absolute_path(dirfd as i32, &path)
                .is_some_and(|a| self.fs().mount_of(&a).0.fstype == crate::mounts::FsType::Sysfs);
            return err(match entry {
                crate::procfs::Entry::Missing if sysfs => errno::EPERM,
                crate::procfs::Entry::Missing => errno::ENOENT,
                _ => errno::EEXIST,
            });
        }
        let r = match self.fs().resolve(dirfd as i32, &path, false) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        if let Err(e) = r.writable() {
            return err(e);
        }
        if r.mount_root {
            return err(errno::EEXIST);
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let mode = self.fs().apply_umask(mode as u32);
        // SAFETY: `name` NUL-terminated; `dir` live.
        let made =
            ret(unsafe { libc::mkdirat(r.dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) });
        if made == 0 && r.fstype == crate::mounts::FsType::Cgroup2 {
            // A new cgroup, with its interface files.
            if let Some(host) = crate::fs::host_path_in(r.dir.as_raw_fd(), &r.name) {
                crate::cgroupfs::made(&host);
            }
        }
        made
    }

    /// `mknodat(dirfd, path, mode, dev)`: a regular file, a FIFO, or a
    /// device node of fwe's ([`crate::devnodes`]).
    pub(crate) fn sys_mknodat(&mut self, dirfd: u64, path: u64, mode: u64, dev: u64) -> i64 {
        use crate::devnodes::{Node, S_IFBLK, S_IFCHR};
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let kind = mode as u32 & 0o170000;
        let perm = self.fs().apply_umask(mode as u32 & 0o7777);
        let (dir, name) = match self.resolve_w(dirfd, &path, false, false) {
            Ok((d, n, _)) => (d, n),
            Err(errno::EBUSY) => return err(errno::EEXIST),
            Err(e) => return err(e),
        };
        match kind {
            0 | 0o100000 => {
                // SAFETY: a NUL-terminated name; `dir` live.
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                        perm as libc::c_uint,
                    )
                };
                if fd < 0 {
                    return last_error();
                }
                // SAFETY: closing the descriptor just made.
                unsafe { libc::close(fd) };
                0
            }
            0o010000 => {
                // SAFETY: a NUL-terminated name; `dir` live.
                ret(unsafe { libc::mkfifoat(dir.as_raw_fd(), name.as_ptr(), perm as libc::mode_t) })
            }
            S_IFCHR | S_IFBLK => {
                if !self.creds.has(crate::caps::CAP_MKNOD) {
                    return err(errno::EPERM);
                }
                let node = Node {
                    kind,
                    major: crate::devnodes::major(dev),
                    minor: crate::devnodes::minor(dev),
                };
                if let Err(e) = crate::cgroupfs::check_device(
                    crate::bpf::BPF_DEVCG_ACC_MKNOD,
                    node.bpf_type(),
                    node.major,
                    node.minor,
                ) {
                    return err(e);
                }
                match crate::devnodes::make(dir.as_raw_fd(), &name, node, perm) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            // A socket node is made by binding a socket there.
            0o140000 => err(errno::EPERM),
            _ => err(errno::EINVAL),
        }
    }

    pub(crate) fn sys_unlinkat(&mut self, dirfd: u64, path: u64, flags: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Ok(r) = self.fs().resolve(dirfd as i32, &path, false)
            && r.fstype == crate::mounts::FsType::Cgroup2
        {
            // A cgroup goes with its files when empty; its files stay.
            let Some(host) = crate::fs::host_path_in(r.dir.as_raw_fd(), &r.name) else {
                return err(errno::ENOENT);
            };
            if flags & fcntl::AT_REMOVEDIR == 0 {
                return err(errno::EPERM);
            }
            return match crate::cgroupfs::remove(&host) {
                Ok(()) => 0,
                Err(e) => err(e),
            };
        }
        let (dir, name) = match self.resolve_w(dirfd, &path, false, false) {
            Ok((d, n, _)) => (d, n),
            Err(e) => return err(e),
        };
        let host_flags = if flags & fcntl::AT_REMOVEDIR != 0 { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: `name` NUL-terminated; `dir` live.
        ret(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), host_flags) })
    }

    pub(crate) fn sys_symlinkat(&mut self, target: u64, dirfd: u64, path: u64) -> i64 {
        let target = guest!(uaccess::read_cstr(target, uaccess::PATH_MAX));
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let target = match CString::new(target) {
            Ok(t) => t,
            Err(_) => return err(errno::EINVAL),
        };
        let (dir, name) = match self.resolve_w(dirfd, &path, false, false) {
            Ok((d, n, _)) => (d, n),
            Err(errno::EBUSY) => return err(errno::EEXIST),
            Err(e) => return err(e),
        };
        // SAFETY: both strings NUL-terminated; `dir` live.
        ret(unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) })
    }

    pub(crate) fn sys_linkat(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
    ) -> i64 {
        let oldpath = guest!(uaccess::read_cstr(oldpath, uaccess::PATH_MAX));
        let newpath = guest!(uaccess::read_cstr(newpath, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_FOLLOW != 0;
        let (od, on, om) = match self.resolve_w(olddirfd, &oldpath, follow, true) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let (nd, nn, nm) = match self.resolve_w(newdirfd, &newpath, false, false) {
            Ok(v) => v,
            Err(errno::EBUSY) => return err(errno::EEXIST),
            Err(e) => return err(e),
        };
        if om != nm && om != 0 && nm != 0 {
            // Across mounts, even of one filesystem.
            return err(errno::EXDEV);
        }
        // SAFETY: names NUL-terminated; dirs live. We resolved symlinks, so 0.
        ret(unsafe { libc::linkat(od.as_raw_fd(), on.as_ptr(), nd.as_raw_fd(), nn.as_ptr(), 0) })
    }

    pub(crate) fn sys_renameat2(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
    ) -> i64 {
        let oldpath = guest!(uaccess::read_cstr(oldpath, uaccess::PATH_MAX));
        let newpath = guest!(uaccess::read_cstr(newpath, uaccess::PATH_MAX));
        let (od, on, om) = match self.resolve_w(olddirfd, &oldpath, false, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let (nd, nn, nm) = match self.resolve_w(newdirfd, &newpath, false, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if om != nm && om != 0 && nm != 0 {
            // Across mounts, even of one filesystem.
            return err(errno::EXDEV);
        }
        rename(od.as_raw_fd(), &on, nd.as_raw_fd(), &nn, flags)
    }

    pub(crate) fn sys_fchmodat(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            if let Err(e) = Self::fd_writable(fd) {
                return err(e);
            }
            // SAFETY: plain host call on an open descriptor.
            return ret(unsafe { libc::fchmod(fd, mode as libc::mode_t) });
        }
        let (dir, name) = match self.resolve_w(dirfd, &path, follow, true) {
            Ok((d, n, _)) => (d, n),
            Err(e) => return err(e),
        };
        // SAFETY: `name` NUL-terminated; `dir` live.
        ret(unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t, 0) })
    }

    pub(crate) fn sys_fchownat(
        &mut self,
        dirfd: u64,
        path: u64,
        uid: u64,
        gid: u64,
        flags: u64,
    ) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            if let Err(e) = Self::fd_writable(fd) {
                return err(e);
            }
            return self.chown_check(uid as u32, gid as u32);
        }
        // Resolve for existence/permission errors, then apply the virtual
        // ownership policy (ownership is not reflected to the host file).
        match self.resolve_w(dirfd, &path, follow, true) {
            Ok(_) => self.chown_check(uid as u32, gid as u32),
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_truncate(&mut self, path: u64, len: u64) -> i64 {
        let fd = self.sys_openat(fcntl::AT_FDCWD as u64, path, fcntl::O_WRONLY, 0);
        if fd < 0 {
            return fd;
        }
        let r = self.sys_ftruncate(fd as u64, len);
        // SAFETY: closing the fd we just opened.
        unsafe { libc::close(fd as i32) };
        r
    }

    pub(crate) fn sys_ftruncate(&mut self, fd: u64, len: u64) -> i64 {
        if let Err(e) = crate::memfd::check_resize(fd as i32, len as i64) {
            return err(e);
        }
        // SAFETY: plain host call on a guest fd.
        ret(unsafe { libc::ftruncate(fd as i32, len as libc::off_t) })
    }

    pub(crate) fn sys_fallocate(&mut self, fd: u64, mode: u64, offset: u64, len: u64) -> i64 {
        if mode & fwe_abi::falloc::FALLOC_FL_KEEP_SIZE == 0 {
            let end = (offset as i64).saturating_add(len as i64);
            // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `st` is a valid out-parameter.
            let size = if unsafe { libc::fstat(fd as i32, &mut st) } == 0 { st.st_size } else { 0 };
            if end > size {
                if let Err(e) = crate::memfd::check_resize(fd as i32, end) {
                    return err(e);
                }
            }
        }
        if mode & fwe_abi::falloc::FALLOC_FL_PUNCH_HOLE != 0
            && crate::memfd::write_refused(fd as i32)
        {
            return err(errno::EPERM);
        }
        match crate::host::fallocate(fd as i32, mode, offset as i64, len as i64) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_umask(&mut self, mask: u64) -> i64 {
        let fs = self.fs.as_mut().expect("filesystem configured");
        fs.set_umask(mask as u32) as i64
    }

    pub(crate) fn sys_pipe2(&mut self, buf: u64, flags: u64) -> i64 {
        let mut fds = [0i32; 2];
        if let Err(e) = make_pipe(&mut fds, flags) {
            return err(e);
        }
        if uaccess::write(buf, fds).is_err() {
            // SAFETY: closing the pipe just made.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return err(errno::EFAULT);
        }
        0
    }

    pub(crate) fn sys_getdents64(&mut self, fd: u64, buf: u64, count: u64) -> i64 {
        // SAFETY: the guest passed a buffer of `count` bytes.
        if let Some(r) = unsafe { crate::synthdir::getdents64(fd as i32, buf, count) } {
            return r;
        }
        // What fwe keeps in a cgroup's directory is its own.
        let cgroup = crate::fdmarks::origin(fd as i32)
            .is_some_and(|o| o.fstype == crate::mounts::FsType::Cgroup2);
        let hide = |name: &[u8]| {
            cgroup && (name == crate::cgroupfs::PRIVATE || name.ends_with(b".fwe-new"))
        };
        getdents64(fd as i32, buf, count as usize, &hide)
    }

    pub(crate) fn sys_utimensat(&mut self, dirfd: u64, path: u64, times: u64, flags: u64) -> i64 {
        let times_ptr = if times == 0 { std::ptr::null() } else { times as *const libc::timespec };
        if path == 0 {
            // futimens-style: operate on the fd in dirfd.
            // SAFETY: valid timespec array pointer or null.
            return ret(unsafe { libc::futimens(dirfd as i32, times_ptr) });
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            if let Err(e) = Self::fd_writable(fd) {
                return err(e);
            }
            // SAFETY: valid timespec array pointer or null.
            return ret(unsafe { libc::futimens(fd, times_ptr) });
        }
        let (dir, name) = match self.resolve_w(dirfd, &path, follow, true) {
            Ok((d, n, _)) => (d, n),
            Err(e) => return err(e),
        };
        // SAFETY: `name` NUL-terminated; `dir` live; times valid or null.
        ret(unsafe { libc::utimensat(dir.as_raw_fd(), name.as_ptr(), times_ptr, 0) })
    }

    /// The open file a `/proc/self/fd/N` link (or `/proc/self/exe`) at
    /// `path` leads to, when the call follows it: Linux acts on that file
    /// itself, whatever has become of its path.
    fn fd_link(&self, dirfd: u64, path: &[u8], follow: bool) -> Option<i32> {
        if !follow {
            return None;
        }
        match self.fs().synthetic(dirfd as i32, path)? {
            crate::procfs::Entry::Fd { fd, .. } => Some(fd),
            _ => None,
        }
    }

    /// For `/proc/<pid>/uid_map`, `gid_map` or `setgroups` at `path`, what
    /// a write to it acts on, with the opener's standing (see `userns`).
    fn map_file(&self, dirfd: i32, path: &[u8]) -> Option<crate::fdmarks::Mark> {
        let p = self.fs().proc_path(dirfd, path).or_else(|| {
            // Another process's: /proc/<pid>/...
            let a = self.fs().absolute_path(dirfd, path)?;
            let (m, fs_path) = self.fs().mount_of(&a);
            (m.fstype == crate::mounts::FsType::Proc)
                .then(|| crate::mounts::join(b"/proc", &fs_path))
        })?;
        let rest = p.strip_prefix(b"/proc/")?;
        let (who, file) = rest.split_at(rest.iter().position(|&b| b == b'/')?);
        let which = match file {
            b"/uid_map" => 0,
            b"/gid_map" => 1,
            b"/setgroups" => 2,
            _ => return None,
        };
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let host = if who == b"self" {
            me
        } else {
            crate::pidns::to_host(std::str::from_utf8(who).ok()?.parse().ok()?)?
        };
        let target = crate::procreg::read(host).and_then(|r| crate::procpid::user_record(&r.ns));
        let (privileged, own) = match &target {
            Some(t) => {
                let gid = which == 1;
                let cap = if gid { crate::caps::CAP_SETGID } else { crate::caps::CAP_SETUID };
                let kid = if gid { self.creds.egid } else { self.creds.euid };
                crate::userns::standing(t, kid, gid, self.creds.has(cap))
            }
            None => (false, 0),
        };
        Some(crate::fdmarks::Mark::ProcMap { host, which, privileged, own })
    }

    /// `EROFS` for a file opened through a read-only mount.
    fn fd_writable(fd: i32) -> Result<(), i32> {
        match crate::fdmarks::origin(fd) {
            Some(o) if o.flags & crate::mounts::ms::RDONLY != 0 => Err(errno::EROFS),
            _ => Ok(()),
        }
    }

    /// [`resolve_c`](Self::resolve_c) for a call that changes what it
    /// names: `EROFS` on a read-only mount, and, unless `mount_root_ok`,
    /// `EBUSY` for a mount's root.
    fn resolve_w(
        &self,
        dirfd: u64,
        path: &[u8],
        follow: bool,
        mount_root_ok: bool,
    ) -> Result<(std::os::fd::OwnedFd, CString, u32), i32> {
        let r = self.fs().resolve(dirfd as i32, path, follow)?;
        r.writable()?;
        if r.mount_root && !mount_root_ok {
            return Err(errno::EBUSY);
        }
        let name = r.name_c()?;
        Ok((r.dir, name, r.mount_id))
    }

    /// Resolve and return the parent dir fd plus a C name.
    fn resolve_c(
        &self,
        dirfd: u64,
        path: &[u8],
        follow: bool,
    ) -> Result<(std::os::fd::OwnedFd, CString), i32> {
        let r = self.fs().resolve(dirfd as i32, path, follow)?;
        let name = r.name_c()?;
        Ok((r.dir, name))
    }
}

/// A stat as a device node shows it.
fn as_node(mut s: Stat, node: Option<crate::devnodes::Node>) -> Stat {
    if let Some(n) = node {
        s.st_mode = n.kind | (s.st_mode & 0o7777);
        s.st_rdev = crate::devnodes::makedev(n.major, n.minor);
        s.st_size = 0;
    }
    s
}

/// An `open` with Linux `flags` of a device: checked against the cgroup's
/// device programs, then, for one of fwe's nodes (`node_file`, open on
/// `fd`), the host device its numbers name.
fn open_device(fd: i32, node: crate::devnodes::Node, flags: u64, node_file: bool) -> i64 {
    use crate::bpf::{BPF_DEVCG_ACC_READ, BPF_DEVCG_ACC_WRITE};
    let access = match flags & fcntl::O_ACCMODE {
        fcntl::O_RDONLY => BPF_DEVCG_ACC_READ,
        fcntl::O_WRONLY => BPF_DEVCG_ACC_WRITE,
        _ => BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE,
    };
    if let Err(e) = crate::cgroupfs::check_device(access, node.bpf_type(), node.major, node.minor) {
        return err(e);
    }
    if !node_file {
        return fd as i64;
    }
    let Some(host) = crate::devnodes::host_device(node) else {
        return err(crate::devnodes::NO_DEVICE);
    };
    let host_flags = host::open_flags_to_host(
        flags & !(fcntl::O_CREAT | fcntl::O_EXCL | fcntl::O_TRUNC | fcntl::O_DIRECTORY),
    );
    // SAFETY: a NUL-terminated host path.
    let dev = unsafe { libc::open(host.as_ptr(), host_flags, 0) };
    if dev < 0 {
        return last_error();
    }
    if crate::devnodes::full(node) {
        crate::fdmarks::mark(dev, crate::fdmarks::Mark::DevFull);
    }
    dev as i64
}

/// Open the file `fd` is open on afresh, with Linux open `flags`: a new
/// open file description of it, as opening `/proc/self/fd/N` makes.
fn reopen(fd: i32, flags: u64) -> i64 {
    let origin = crate::fdmarks::origin(fd);
    let writes = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY || flags & fcntl::O_TRUNC != 0;
    if writes && origin.as_ref().is_some_and(|o| o.flags & crate::mounts::ms::RDONLY != 0) {
        return err(errno::EROFS);
    }
    let Some(host) = crate::fs::host_path_of(fd) else { return err(errno::ENOENT) };
    let Ok(p) = CString::new(host) else { return err(errno::EINVAL) };
    // The host flags, without those that would make a new file.
    let host_flags = host::open_flags_to_host(flags & !(fcntl::O_CREAT | fcntl::O_EXCL));
    // SAFETY: a NUL-terminated host path.
    let new = unsafe { libc::open(p.as_ptr(), host_flags, 0) };
    if new < 0 {
        return last_error();
    }
    crate::fdmarks::duplicated(fd, new);
    new as i64
}

/// The filesystem holding host descriptor `fd`, written to `buf` in Linux
/// layout, as the mount it is in shows it: its type and its flags.
fn statfs_fd(fd: i32, buf: u64, mount: Option<(crate::mounts::FsType, u64)>) -> i64 {
    // SAFETY: zeroed bytes are a valid `statfs`; `fstatfs` fills it.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out parameter.
    if unsafe { libc::fstatfs(fd, &mut s) } < 0 {
        return last_error();
    }
    let mut out = host::statfs_to_linux(&s);
    if let Some((fstype, flags)) = mount {
        use crate::mounts::ms;
        use fwe_abi::statfs::*;
        out.f_type = fstype.magic();
        let mut f = 0;
        for (m, st) in [
            (ms::RDONLY, ST_RDONLY),
            (ms::NOSUID, ST_NOSUID),
            (ms::NODEV, ST_NODEV),
            (ms::NOEXEC, ST_NOEXEC),
            (ms::NOATIME, ST_NOATIME),
            (ms::NODIRATIME, ST_NODIRATIME),
            (ms::RELATIME, ST_RELATIME),
        ] {
            if flags & m != 0 {
                f |= st;
            }
        }
        out.f_flags = f;
    }
    guest!(uaccess::write(buf, out));
    0
}

/// `RENAME_NOREPLACE`.
#[cfg(target_os = "macos")]
const RENAME_NOREPLACE: u64 = 1;
/// `RENAME_EXCHANGE`.
#[cfg(target_os = "macos")]
const RENAME_EXCHANGE: u64 = 2;

fn rename(od: i32, on: &CString, nd: i32, nn: &CString, flags: u64) -> i64 {
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: names NUL-terminated; dirs live.
        ret(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                od,
                on.as_ptr(),
                nd,
                nn.as_ptr(),
                flags as libc::c_uint,
            )
        })
    }
    #[cfg(target_os = "macos")]
    {
        if flags & RENAME_EXCHANGE != 0 {
            // RENAME_SWAP; emulated best-effort is unsafe, so report unsupported.
            return err(errno::ENOSYS);
        }
        if flags & RENAME_NOREPLACE != 0 {
            // Not atomic, but adequate until renameatx_np is wired up.
            // SAFETY: `nn` NUL-terminated; `nd` live.
            let exists = unsafe { libc::faccessat(nd, nn.as_ptr(), libc::F_OK, 0) } == 0;
            if exists {
                return err(errno::EEXIST);
            }
        }
        // SAFETY: names NUL-terminated; dirs live.
        ret(unsafe { libc::renameat(od, on.as_ptr(), nd, nn.as_ptr()) })
    }
}

fn make_pipe(fds: &mut [i32; 2], flags: u64) -> Result<(), i32> {
    #[cfg(not(target_os = "macos"))]
    {
        let mut host = 0;
        if flags & fcntl::O_NONBLOCK != 0 {
            host |= libc::O_NONBLOCK;
        }
        if flags & fcntl::O_CLOEXEC != 0 {
            host |= libc::O_CLOEXEC;
        }
        // SAFETY: `fds` is a valid array of two ints.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), host) } < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `fds` is a valid array of two ints.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        for &fd in fds.iter() {
            if flags & fcntl::O_CLOEXEC != 0 {
                // SAFETY: plain host call on a fresh fd.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            if flags & fcntl::O_NONBLOCK != 0 {
                // SAFETY: plain host call on a fresh fd.
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn getdents64(fd: i32, buf: u64, count: usize, _hide: &dyn Fn(&[u8]) -> bool) -> i64 {
    // On a Linux host the kernel produces the exact arm64 layout.
    // SAFETY: the guest passed a buffer of `count` bytes.
    ret(unsafe { libc::syscall(libc::SYS_getdents64, fd, buf as *mut libc::c_void, count) })
}

#[cfg(target_os = "macos")]
fn getdents64(fd: i32, buf: u64, count: usize, hide: &dyn Fn(&[u8]) -> bool) -> i64 {
    use fwe_abi::DIRENT64_HEADER;

    // The `__getdirentries64` syscall produces the 64-bit-inode layout (the
    // plain `getdirentries` C symbol is the legacy 32-bit variant). Entries:
    // struct dirent { u64 d_ino; u64 d_seekoff; u16 d_reclen; u16 d_namlen;
    // u8 d_type; char d_name[]; }.
    const SYS___GETDIRENTRIES64: libc::c_int = 344;
    const BSD_HEADER: usize = 21;

    // Where the stream stands, so entries fetched from the host but not
    // delivered can be re-read next time. `d_seekoff` is 0 on APFS, so the
    // position has to come from the descriptor itself.
    // SAFETY: plain host call on a guest fd.
    let start = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if start < 0 {
        return last_error();
    }
    // A translated record can be up to 4 bytes longer than the host's (they
    // round to 8 and 4 bytes), so a host buffer of `count` bytes may yield a
    // little more than fits. When it does, the stream is rewound and re-read
    // with exactly the host bytes that did fit.
    let mut size = count;
    loop {
        let mut bsd = vec![0u8; size];
        let mut position: libc::off_t = 0;
        // SAFETY: `bsd` is a valid buffer; the syscall advances the fd offset
        // and writes the new position through `position`.
        let n = unsafe {
            libc::syscall(
                SYS___GETDIRENTRIES64,
                fd,
                bsd.as_mut_ptr(),
                bsd.len(),
                &mut position as *mut libc::off_t,
            )
        };
        if n < 0 {
            return last_error();
        }
        let n = n as usize;
        let mut src = 0usize;
        let mut out: Vec<u8> = Vec::with_capacity(count);
        let mut overflow = false;
        while src + BSD_HEADER <= n {
            let rec = &bsd[src..];
            let d_ino = u64::from_ne_bytes(rec[0..8].try_into().unwrap());
            let d_seekoff = u64::from_ne_bytes(rec[8..16].try_into().unwrap());
            let d_reclen = u16::from_ne_bytes(rec[16..18].try_into().unwrap()) as usize;
            let d_namlen = u16::from_ne_bytes(rec[18..20].try_into().unwrap()) as usize;
            let d_type = rec[20];
            if d_reclen == 0 || src + BSD_HEADER + d_namlen > n {
                break;
            }
            let name = &rec[BSD_HEADER..BSD_HEADER + d_namlen];
            if hide(name) {
                src += d_reclen;
                continue;
            }

            let out_len = (DIRENT64_HEADER + d_namlen + 1).div_ceil(8) * 8;
            if out.len() + out_len > count {
                overflow = true;
                break;
            }

            // The linux_dirent64 header (packed in the ABI), the name, then
            // zeros for its terminator and the padding.
            let at = out.len();
            out.resize(at + out_len, 0);
            let rec = &mut out[at..];
            rec[0..8].copy_from_slice(&d_ino.to_ne_bytes());
            rec[8..16].copy_from_slice(&(d_seekoff as i64).to_ne_bytes());
            rec[16..18].copy_from_slice(&(out_len as u16).to_ne_bytes());
            rec[18] = d_type;
            rec[DIRENT64_HEADER..DIRENT64_HEADER + d_namlen].copy_from_slice(name);
            src += d_reclen;
        }
        if !overflow {
            if crate::uaccess::write_from(buf, &out).is_err() {
                // Leave the stream where it was, as if nothing was read.
                // SAFETY: plain host call on a guest fd.
                unsafe { libc::lseek(fd, start, libc::SEEK_SET) };
                return err(errno::EFAULT);
            }
            return out.len() as i64;
        }
        if src == 0 {
            // Not even the first entry fits: the guest's buffer is too small.
            return err(errno::EINVAL);
        }
        // SAFETY: plain host call on a guest fd, back to where this call began.
        if unsafe { libc::lseek(fd, start, libc::SEEK_SET) } < 0 {
            return last_error();
        }
        size = src;
    }
}

/// Build a synthetic `struct stat` for a `/proc` or `/sys` entry.
fn synth_stat(mode: u32, size: u64) -> Stat {
    Stat {
        st_mode: mode,
        st_nlink: 1,
        st_size: size as i64,
        st_blksize: 4096,
        st_blocks: size.div_ceil(512) as i64,
        ..Stat::default()
    }
}

/// An anonymous, seekable, readable fd preloaded with `content`, used to serve
/// a synthetic `/proc` or `/sys` file. Backed by an immediately-unlinked temp
/// file so it works on both Linux and macOS.
fn anon_fd(content: &[u8]) -> i64 {
    let mut template = *b"/tmp/fwe-proc-XXXXXX\0";
    // SAFETY: `template` is a NUL-terminated mutable buffer for mkstemp.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 {
        return last_error();
    }
    // SAFETY: `template` is the NUL-terminated name just created.
    unsafe { libc::unlink(template.as_ptr().cast()) };
    let mut off = 0usize;
    while off < content.len() {
        // SAFETY: writing the remaining content to the temp fd.
        let n = unsafe { libc::write(fd, content[off..].as_ptr().cast(), content.len() - off) };
        if n <= 0 {
            // SAFETY: closing the fd we created.
            unsafe { libc::close(fd) };
            return last_error();
        }
        off += n as usize;
    }
    // SAFETY: rewinding to the start for the guest's reads.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    fd as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Kernel, Platform, Tracer};
    use fwe_abi::{Stat, nr};
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct NoPlatform;
    impl Platform for NoPlatform {
        fn prepare_exec(
            &mut self,
            _addr: u64,
            _len: u64,
            _known: Option<&[(u64, u64)]>,
        ) -> Result<(), crate::PrepareFailed> {
            Ok(())
        }
        fn exit(&mut self, code: i32) -> ! {
            panic!("exit({code})")
        }
        fn exit_thread(&mut self, code: i32) -> ! {
            panic!("exit_thread({code})")
        }
        fn kill_self(&mut self, sig: libc::c_int) -> ! {
            panic!("killed by {sig}")
        }
    }

    /// A kernel rooted at a fresh temporary directory, returned with its path.
    fn rooted() -> (Kernel<NoPlatform>, std::path::PathBuf) {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fwe-fs-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Fs::new(Some(dir.as_os_str().as_encoded_bytes())).unwrap();
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let k = Kernel::new(
            NoPlatform,
            page,
            Brk { start: 0, current: 0, limit: 0 },
            Some(root),
            Tracer::default(),
        );
        (k, dir)
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    const AT_FDCWD: u64 = -100i64 as u64;

    fn open(k: &mut Kernel<NoPlatform>, path: &CString, flags: u64, mode: u64) -> i64 {
        k.syscall(nr::OPENAT, [AT_FDCWD, path.as_ptr() as u64, flags, mode, 0, 0])
    }

    #[test]
    fn open_write_read_stat() {
        use fwe_abi::fcntl::{O_CREAT, O_RDWR};
        let (mut k, _d) = rooted();
        let p = cstr("/hello.txt");
        let fd = open(&mut k, &p, O_CREAT | O_RDWR, 0o644);
        assert!(fd >= 0, "openat: {fd}");
        let data = b"filesystem works\n";
        assert_eq!(
            k.syscall(nr::WRITE, [fd as u64, data.as_ptr() as u64, data.len() as u64, 0, 0, 0]),
            data.len() as i64
        );
        assert_eq!(k.syscall(nr::LSEEK, [fd as u64, 0, 0, 0, 0, 0]), 0);
        let mut buf = [0u8; 64];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], data);

        let mut st = Stat::default();
        assert_eq!(k.syscall(nr::FSTAT, [fd as u64, &mut st as *mut _ as u64, 0, 0, 0, 0]), 0);
        assert_eq!(st.st_size, data.len() as i64);
        assert_eq!(st.st_mode & fwe_abi::stat::S_IFMT, fwe_abi::stat::S_IFREG);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // newfstatat by path agrees.
        let mut st2 = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, p.as_ptr() as u64, &mut st2 as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(st2.st_size, data.len() as i64);
    }

    /// A buffer too small for a whole directory delivers every entry exactly
    /// once across calls: what the host returned but did not fit is re-read,
    /// not dropped and not repeated.
    #[test]
    fn getdents_small_buffer_delivers_each_entry_once() {
        use fwe_abi::fcntl::{O_DIRECTORY, O_RDONLY};
        let (mut k, _d) = rooted();
        let want: Vec<String> = (0..40).map(|i| format!("entry-number-{i:02}")).collect();
        for name in &want {
            let path = cstr(&format!("/{name}"));
            assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, path.as_ptr() as u64, 0o755, 0, 0, 0]), 0);
        }
        let root = cstr("/");
        let fd = open(&mut k, &root, O_RDONLY | O_DIRECTORY, 0);
        assert!(fd >= 0);
        let mut buf = [0u8; 100];
        let mut names = Vec::new();
        for _ in 0..1000 {
            let n = k.syscall(
                nr::GETDENTS64,
                [fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0],
            );
            assert!(n >= 0, "getdents64: {n}");
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n as usize {
                let reclen =
                    u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 19..off + reclen];
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                names.push(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
                off += reclen;
            }
        }
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        names.retain(|n| n != "." && n != "..");
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "an entry was delivered twice: {names:?}");
        assert_eq!(sorted, want);
    }

    #[test]
    fn mkdir_and_getdents() {
        use fwe_abi::fcntl::{O_DIRECTORY, O_RDONLY};
        let (mut k, _d) = rooted();
        for name in ["/a", "/b", "/c"] {
            assert_eq!(
                k.syscall(nr::MKDIRAT, [AT_FDCWD, cstr(name).as_ptr() as u64, 0o755, 0, 0, 0]),
                0
            );
        }
        let root = cstr("/");
        let fd = open(&mut k, &root, O_RDONLY | O_DIRECTORY, 0);
        assert!(fd >= 0);
        let mut buf = [0u8; 4096];
        let mut names = Vec::new();
        loop {
            let n = k.syscall(
                nr::GETDENTS64,
                [fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0],
            );
            assert!(n >= 0, "getdents64: {n}");
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n as usize {
                let reclen =
                    u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 19..off + reclen];
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                names.push(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
                off += reclen;
            }
        }
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        for want in ["a", "b", "c"] {
            assert!(names.iter().any(|n| n == want), "missing {want} in {names:?}");
        }
    }

    #[test]
    fn symlinks_are_contained() {
        use fwe_abi::fcntl::O_WRONLY;
        let (mut k, dir) = rooted();
        // A file reachable only within the root.
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/secret"), b"in-root").unwrap();
        // An absolute symlink that would escape on the host.
        assert_eq!(
            k.syscall(
                nr::SYMLINKAT,
                [cstr("/etc").as_ptr() as u64, AT_FDCWD, cstr("/esc").as_ptr() as u64, 0, 0, 0]
            ),
            0
        );
        // "/esc/passwd" resolves under the root, not the host's /etc.
        let fd = open(&mut k, &cstr("/esc/passwd"), O_WRONLY, 0);
        assert_eq!(fd, err(errno::ENOENT), "symlink escaped the root");

        // ".." cannot climb above the root.
        let fd = open(&mut k, &cstr("/../../real/secret"), 0, 0);
        assert!(fd >= 0, "dotdot clamp: {fd}");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // A relative symlink within the root resolves normally.
        assert_eq!(
            k.syscall(
                nr::SYMLINKAT,
                [
                    cstr("real/secret").as_ptr() as u64,
                    AT_FDCWD,
                    cstr("/link").as_ptr() as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        let fd = open(&mut k, &cstr("/link"), 0, 0);
        assert!(fd >= 0, "relative symlink: {fd}");
        let mut buf = [0u8; 16];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 16, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"in-root");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // readlinkat returns the stored target without following it.
        let mut link = [0u8; 64];
        let n = k.syscall(
            nr::READLINKAT,
            [AT_FDCWD, cstr("/esc").as_ptr() as u64, link.as_mut_ptr() as u64, 64, 0, 0],
        );
        assert_eq!(&link[..n as usize], b"/etc");
    }

    #[test]
    fn cwd_and_relative_paths() {
        use fwe_abi::fcntl::{O_CREAT, O_WRONLY};
        let (mut k, _d) = rooted();
        assert_eq!(
            k.syscall(nr::MKDIRAT, [AT_FDCWD, cstr("/sub").as_ptr() as u64, 0o755, 0, 0, 0]),
            0
        );
        assert_eq!(k.syscall(nr::CHDIR, [cstr("/sub").as_ptr() as u64, 0, 0, 0, 0, 0]), 0);

        let mut buf = [0u8; 64];
        let n = k.syscall(nr::GETCWD, [buf.as_mut_ptr() as u64, 64, 0, 0, 0, 0]);
        assert!(n > 0);
        assert_eq!(&buf[..n as usize], b"/sub\0");

        // A relative create lands in /sub.
        let fd = open(&mut k, &cstr("f"), O_CREAT | O_WRONLY, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let mut st = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/sub/f").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
    }

    /// An `O_CREAT` open succeeds while another process keeps unlinking and
    /// recreating the name, as on Linux (the macOS host fails such opens
    /// with `ENOENT` now and then).
    #[cfg(target_os = "macos")]
    #[test]
    fn create_survives_a_racing_unlink() {
        use fwe_abi::fcntl::{O_CLOEXEC, O_CREAT, O_RDWR};
        let (mut k, dir) = rooted();
        let host = std::ffi::CString::new(dir.join("f").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the child makes only raw system calls until it is killed.
        let child = unsafe { libc::fork() };
        if child == 0 {
            loop {
                // SAFETY: plain host calls on a NUL-terminated path.
                unsafe {
                    libc::unlink(host.as_ptr());
                    let fd = libc::open(host.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644);
                    libc::close(fd);
                }
            }
        }
        let failures = (0..20_000)
            .filter(|_| {
                let fd = open(&mut k, &cstr("/f"), O_CREAT | O_RDWR | O_CLOEXEC, 0o644);
                // SAFETY: closing a test fd (or nothing, on failure).
                unsafe { libc::close(fd as i32) };
                fd < 0
            })
            .count();
        // SAFETY: ending and reaping the child forked above.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(failures, 0);
    }

    #[test]
    fn statfs_of_a_path_in_the_root() {
        let (mut k, _d) = rooted();
        let mut st = fwe_abi::Statfs::default();
        let p = &mut st as *mut _ as u64;
        assert_eq!(k.syscall(nr::STATFS, [cstr("/").as_ptr() as u64, p, 0, 0, 0, 0]), 0);
        assert!(st.f_bsize > 0 && st.f_blocks > 0, "{st:?}");
        let missing = cstr("/no/such/dir/x");
        assert_eq!(
            k.syscall(nr::STATFS, [missing.as_ptr() as u64, p, 0, 0, 0, 0]),
            err(errno::ENOENT)
        );
    }

    #[test]
    fn unlink_and_rename() {
        use fwe_abi::fcntl::{O_CREAT, O_WRONLY};
        let (mut k, _d) = rooted();
        let fd = open(&mut k, &cstr("/x"), O_CREAT | O_WRONLY, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        assert_eq!(
            k.syscall(
                nr::RENAMEAT2,
                [AT_FDCWD, cstr("/x").as_ptr() as u64, AT_FDCWD, cstr("/y").as_ptr() as u64, 0, 0]
            ),
            0
        );
        let mut st = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/x").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            err(errno::ENOENT)
        );
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
        // The flagless renameat, which glibc's `rename` uses on arm64.
        assert_eq!(
            k.syscall(
                nr::RENAMEAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, AT_FDCWD, cstr("/z").as_ptr() as u64, 0, 0]
            ),
            0
        );
        assert_eq!(k.syscall(nr::UNLINKAT, [AT_FDCWD, cstr("/z").as_ptr() as u64, 0, 0, 0, 0]), 0);
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            err(errno::ENOENT)
        );
    }

    #[test]
    fn synthetic_proc_and_sys() {
        use fwe_abi::stat as st;
        let (mut k, _d) = rooted();
        k.fs.as_mut().unwrap().set_proc_info(
            b"/bin/prog".to_vec(),
            b"prog\0-x\0".to_vec(),
            4,
            b"host".to_vec(),
        );

        // Read a known /proc file.
        let fd = open(&mut k, &cstr("/proc/sys/kernel/ostype"), 0, 0);
        assert!(fd >= 0, "open: {fd}");
        let mut buf = [0u8; 64];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"Linux\n");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // cmdline round-trips the NUL-joined argv.
        let fd = open(&mut k, &cstr("/proc/self/cmdline"), 0, 0);
        assert!(fd >= 0);
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"prog\0-x\0");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // /proc/self/exe is a symlink to the program.
        let n = k.syscall(
            nr::READLINKAT,
            [AT_FDCWD, cstr("/proc/self/exe").as_ptr() as u64, buf.as_mut_ptr() as u64, 64, 0, 0],
        );
        assert_eq!(&buf[..n as usize], b"/bin/prog");

        // A /proc file stats as a regular file; an unknown one is ENOENT.
        let mut stbuf = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [
                    AT_FDCWD,
                    cstr("/proc/cpuinfo").as_ptr() as u64,
                    &mut stbuf as *mut _ as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(stbuf.st_mode & st::S_IFMT, st::S_IFREG);
        assert_eq!(open(&mut k, &cstr("/proc/nonexistent"), 0, 0), err(errno::ENOENT));
    }
}
