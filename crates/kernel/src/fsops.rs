//! File and directory system calls, built on the [`crate::fs`] resolver.

use crate::fs::Fs;
use crate::host::{self, last_error, ret};
use crate::{Kernel, Platform};
use fwe_abi::{Stat, Statx, err, errno, fcntl, statx_mask};
use std::ffi::CString;
use std::os::fd::AsRawFd;

/// Read a NUL-terminated path from guest memory (without the NUL).
///
/// # Safety
/// `addr` must point to a NUL-terminated byte string in guest memory.
unsafe fn read_cstr(addr: u64) -> Vec<u8> {
    const MAX: usize = 1 << 16;
    let mut out = Vec::new();
    for i in 0..MAX as u64 {
        // SAFETY: the caller guarantees a NUL-terminated string at `addr`.
        let b = unsafe { (addr as *const u8).add(i as usize).read() };
        if b == 0 {
            break;
        }
        out.push(b);
    }
    out
}

/// Write a POD value to guest memory.
///
/// # Safety
/// `addr` must point to writable guest memory with room for a `T`.
unsafe fn write<T: Copy>(addr: u64, value: T) {
    // SAFETY: guaranteed by the caller.
    unsafe { (addr as *mut T).write_unaligned(value) }
}

#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn stat_to_linux(s: &libc::stat) -> Stat {
    Stat {
        st_dev: s.st_dev as u64,
        st_ino: s.st_ino as u64,
        st_mode: s.st_mode as u32,
        st_nlink: s.st_nlink as u32,
        st_uid: s.st_uid,
        st_gid: s.st_gid,
        st_rdev: s.st_rdev as u64,
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
        stx_uid: s.st_uid,
        stx_gid: s.st_gid,
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
        stx_rdev_major: major(s.st_rdev as u64),
        stx_rdev_minor: minor(s.st_rdev as u64),
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
    fn fs(&self) -> &Fs {
        self.fs.as_ref().expect("filesystem configured")
    }

    pub(crate) fn sys_openat(&mut self, dirfd: u64, path: u64, flags: u64, mode: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
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
                crate::procfs::Entry::File(content) => anon_fd(&content),
                crate::procfs::Entry::Symlink(target) => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return err(errno::ELOOP);
                    }
                    // Follow the link through the normal path.
                    self.sys_openat_bytes(dirfd, &target, flags, mode)
                }
                crate::procfs::Entry::Dir => match self.fs().synth_children(dirfd as i32, &path) {
                    Some(entries) => crate::synthdir::open(entries),
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
        // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd.
        let fd = unsafe {
            libc::openat(resolved.dir.as_raw_fd(), name.as_ptr(), host_flags, mode as libc::c_uint)
        };
        if fd < 0 { last_error() } else { fd as i64 }
    }

    pub(crate) fn sys_faccessat(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        // A virtual root bypasses the permission bits, as Linux root does: any
        // existing file is accessible, and X_OK needs only one execute bit set.
        const X_OK: u64 = 1;
        if self.creds.euid == 0 {
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

    pub(crate) fn sys_newfstatat(&mut self, dirfd: u64, path: u64, buf: u64, flags: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
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
                    return self.stat_path(dirfd, &target, buf, flags);
                }
                crate::procfs::Entry::Symlink(t) => synth_stat(st::S_IFLNK | 0o777, t.len() as u64),
                crate::procfs::Entry::Dir => synth_stat(st::S_IFDIR | 0o555, 0),
                crate::procfs::Entry::Missing => return err(errno::ENOENT),
            };
            // SAFETY: the guest passed a buffer for a `struct stat`.
            unsafe { write(buf, s) };
            return 0;
        }
        let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match stat_at(dir.as_raw_fd(), &name) {
            Ok(s) => {
                // SAFETY: the guest passed a buffer for a `struct stat`.
                unsafe { write(buf, stat_to_linux(&s)) };
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
                // SAFETY: the guest passed a buffer for a `struct stat`.
                unsafe { write(buf, stat_to_linux(&s)) };
                0
            }
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_fstat(&mut self, fd: u64, buf: u64) -> i64 {
        if crate::synthdir::fstat_is_dir(fd as i32) {
            use fwe_abi::stat as st;
            // SAFETY: the guest passed a buffer for a `struct stat`.
            unsafe { write(buf, synth_stat(st::S_IFDIR | 0o555, 0)) };
            return 0;
        }
        // SAFETY: `out` is a valid out-parameter.
        let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: plain host call on a guest fd.
        if unsafe { libc::fstat(fd as i32, &mut out) } < 0 {
            return last_error();
        }
        // SAFETY: the guest passed a buffer for a `struct stat`.
        unsafe { write(buf, stat_to_linux(&out)) };
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
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let host = if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            // SAFETY: `out` is a valid out-parameter.
            let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: plain host call on a guest fd with a valid out-parameter.
            if unsafe { libc::fstat(dirfd as i32, &mut out) } < 0 {
                return last_error();
            }
            out
        } else {
            let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
            let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            match stat_at(dir.as_raw_fd(), &name) {
                Ok(s) => s,
                Err(e) => return err(e),
            }
        };
        // SAFETY: the guest passed a buffer for a `struct statx`.
        unsafe { write(buf, statx_from(&host)) };
        0
    }

    pub(crate) fn sys_readlinkat(&mut self, dirfd: u64, path: u64, buf: u64, size: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            return match entry {
                crate::procfs::Entry::Symlink(target) => {
                    let n = target.len().min(size as usize);
                    // SAFETY: the guest passed a buffer of `size` bytes.
                    unsafe { std::ptr::copy_nonoverlapping(target.as_ptr(), buf as *mut u8, n) };
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
        // SAFETY: the guest passed a buffer of `size >= need` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(cwd.as_ptr(), buf as *mut u8, cwd.len());
            (buf as *mut u8).add(cwd.len()).write(0);
        }
        need as i64
    }

    pub(crate) fn sys_chdir(&mut self, path: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
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
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let (dir, name) = match self.resolve_c(dirfd, &path, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let mode = self.fs().apply_umask(mode as u32);
        // SAFETY: `name` NUL-terminated; `dir` live.
        ret(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) })
    }

    pub(crate) fn sys_unlinkat(&mut self, dirfd: u64, path: u64, flags: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let (dir, name) = match self.resolve_c(dirfd, &path, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let host_flags = if flags & fcntl::AT_REMOVEDIR != 0 { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: `name` NUL-terminated; `dir` live.
        ret(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), host_flags) })
    }

    pub(crate) fn sys_symlinkat(&mut self, target: u64, dirfd: u64, path: u64) -> i64 {
        // SAFETY: the guest passed two string pointers.
        let (target, path) = unsafe { (read_cstr(target), read_cstr(path)) };
        let target = match CString::new(target) {
            Ok(t) => t,
            Err(_) => return err(errno::EINVAL),
        };
        let (dir, name) = match self.resolve_c(dirfd, &path, false) {
            Ok(v) => v,
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
        // SAFETY: the guest passed two path pointers.
        let (oldpath, newpath) = unsafe { (read_cstr(oldpath), read_cstr(newpath)) };
        let follow = flags & fcntl::AT_SYMLINK_FOLLOW != 0;
        let (od, on) = match self.resolve_c(olddirfd, &oldpath, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let (nd, nn) = match self.resolve_c(newdirfd, &newpath, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
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
        // SAFETY: the guest passed two path pointers.
        let (oldpath, newpath) = unsafe { (read_cstr(oldpath), read_cstr(newpath)) };
        let (od, on) = match self.resolve_c(olddirfd, &oldpath, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let (nd, nn) = match self.resolve_c(newdirfd, &newpath, false) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        rename(od.as_raw_fd(), &on, nd.as_raw_fd(), &nn, flags)
    }

    pub(crate) fn sys_fchmodat(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
            Ok(v) => v,
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
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        // Resolve for existence/permission errors, then apply the virtual
        // ownership policy (ownership is not reflected to the host file).
        match self.resolve_c(dirfd, &path, follow) {
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
        // SAFETY: plain host call on a guest fd.
        ret(unsafe { libc::ftruncate(fd as i32, len as libc::off_t) })
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
        // SAFETY: the guest passed a buffer for two ints.
        unsafe {
            write(buf, fds[0]);
            write(buf + 4, fds[1]);
        }
        0
    }

    pub(crate) fn sys_getdents64(&mut self, fd: u64, buf: u64, count: u64) -> i64 {
        // SAFETY: the guest passed a buffer of `count` bytes.
        if let Some(r) = unsafe { crate::synthdir::getdents64(fd as i32, buf, count) } {
            return r;
        }
        getdents64(fd as i32, buf, count as usize)
    }

    pub(crate) fn sys_utimensat(&mut self, dirfd: u64, path: u64, times: u64, flags: u64) -> i64 {
        let times_ptr = if times == 0 { std::ptr::null() } else { times as *const libc::timespec };
        if path == 0 {
            // futimens-style: operate on the fd in dirfd.
            // SAFETY: valid timespec array pointer or null.
            return ret(unsafe { libc::futimens(dirfd as i32, times_ptr) });
        }
        // SAFETY: the guest passed a path pointer.
        let path = unsafe { read_cstr(path) };
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        let (dir, name) = match self.resolve_c(dirfd, &path, follow) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        // SAFETY: `name` NUL-terminated; `dir` live; times valid or null.
        ret(unsafe { libc::utimensat(dir.as_raw_fd(), name.as_ptr(), times_ptr, 0) })
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
fn getdents64(fd: i32, buf: u64, count: usize) -> i64 {
    // On a Linux host the kernel produces the exact arm64 layout.
    // SAFETY: the guest passed a buffer of `count` bytes.
    ret(unsafe { libc::syscall(libc::SYS_getdents64, fd, buf as *mut libc::c_void, count) })
}

#[cfg(target_os = "macos")]
fn getdents64(fd: i32, buf: u64, count: usize) -> i64 {
    use fwe_abi::DIRENT64_HEADER;

    // The `__getdirentries64` syscall produces the 64-bit-inode layout (the
    // plain `getdirentries` C symbol is the legacy 32-bit variant). Entries:
    // struct dirent { u64 d_ino; u64 d_seekoff; u16 d_reclen; u16 d_namlen;
    // u8 d_type; char d_name[]; }.
    const SYS___GETDIRENTRIES64: libc::c_int = 344;
    const BSD_HEADER: usize = 21;

    let mut bsd = vec![0u8; count.max(4096)];
    let mut position: libc::off_t = 0;
    // SAFETY: `bsd` is a valid buffer; the syscall advances the fd offset and
    // writes the new position through `position`.
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
    let mut written = 0u64;
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

        let out_len = (DIRENT64_HEADER + d_namlen + 1).div_ceil(8) * 8;
        if written + out_len as u64 > count as u64 {
            // Re-read this entry next time by rewinding the fd.
            // SAFETY: plain host call on a guest fd.
            unsafe { libc::lseek(fd, d_seekoff as libc::off_t, libc::SEEK_SET) };
            break;
        }

        // Serialize the linux_dirent64 header and name directly into the
        // guest buffer, field by field (the header is packed in the ABI).
        let at = buf + written;
        // SAFETY: `[at, at + out_len)` lies within the guest buffer.
        unsafe {
            let p = at as *mut u8;
            p.copy_from(d_ino.to_ne_bytes().as_ptr(), 8);
            p.add(8).copy_from((d_seekoff as i64).to_ne_bytes().as_ptr(), 8);
            p.add(16).copy_from((out_len as u16).to_ne_bytes().as_ptr(), 2);
            p.add(18).write(d_type);
            for (i, &b) in name.iter().enumerate() {
                p.add(DIRENT64_HEADER + i).write(b);
            }
            p.add(DIRENT64_HEADER + d_namlen).write(0);
        }
        written += out_len as u64;
        src += d_reclen;
    }
    if written == 0 && n > 0 {
        return err(errno::EINVAL);
    }
    written as i64
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
        fn prepare_exec(&mut self, _addr: u64, _len: u64) -> Result<(), i32> {
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
        assert_eq!(k.syscall(nr::UNLINKAT, [AT_FDCWD, cstr("/y").as_ptr() as u64, 0, 0, 0, 0]), 0);
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
