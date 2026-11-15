//! File handles (`name_to_handle_at`, `open_by_handle_at`): a handle names
//! a file by the host file system it is on and its inode there, which the
//! host turns back into a path (`fsgetpath`), so a handle outlives renames
//! of the file, as a Linux handle does, and goes stale once the file is
//! gone. A file fwe makes up (under `/proc`) has an identifier handle
//! (`AT_HANDLE_FID`) only, which opens nothing.
//!
//! `open_by_handle_at` opens the file at a path the caller sees it at:
//! where its host path falls under the host directory of `mount_fd`'s
//! mount (or one of an overlay's layers), at that mount's place, under the
//! caller's root, and found there as that same file. Then it is opened as
//! `openat` opens it, with Linux's permission checks, read-only mounts and
//! `O_PATH`. Any other file is stale (`ESTALE`): a handle never reaches
//! past the guest's root or mounts.

use crate::{Kernel, Platform};
use fwe_abi::{err, errno};
use std::os::unix::ffi::OsStrExt;

/// Linux's `MAX_HANDLE_SZ`.
const MAX_HANDLE_SZ: u32 = 128;
/// The handle's bytes: the host file system's id (two words) and inode.
const HANDLE_BYTES: u32 = 16;
/// The handle's type (Linux's `FILEID_INO32_GEN`, a positive one).
const HANDLE_TYPE: i32 = 1;
/// The type of an identifier handle of a file fwe makes up.
const FID_TYPE: i32 = 0xfe;

const AT_HANDLE_MNT_ID_UNIQUE: u64 = 0x1;
const AT_HANDLE_CONNECTABLE: u64 = 0x2;
const AT_HANDLE_FID: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;

/// The host file system of the file open as `fd`: its id's two words.
fn fsid_of(fd: i32) -> Option<[i32; 2]> {
    // SAFETY: an all-zero `statfs` is a valid out-parameter.
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstatfs(fd, &mut sf) } != 0 {
        return None;
    }
    // SAFETY: `fsid_t` is two `i32`s, whose fields the libc crate keeps
    // private.
    Some(unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(sf.f_fsid) })
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn fsgetpath(buf: *mut libc::c_char, size: usize, fsid: *const [i32; 2], obj: u64) -> isize;
}

/// The host path of inode `ino` on host file system `fsid`, if it still
/// has one.
#[cfg(not(target_os = "macos"))]
fn path_of(_: [i32; 2], _: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn path_of(fsid: [i32; 2], ino: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: a buffer of its length, and the identity read above.
    let n = unsafe { fsgetpath(buf.as_mut_ptr().cast(), buf.len(), &fsid, ino) };
    if n <= 0 {
        return None;
    }
    buf.truncate(buf.iter().position(|&b| b == 0).unwrap_or(n as usize));
    Some(buf)
}

impl<P: Platform> Kernel<P> {
    /// `name_to_handle_at(dirfd, path, handle, mount_id, flags)`.
    pub(crate) fn sys_name_to_handle_at(
        &mut self,
        dirfd: u64,
        path: u64,
        handle: u64,
        mount_id: u64,
        flags: u64,
    ) -> i64 {
        let known = AT_SYMLINK_FOLLOW
            | AT_EMPTY_PATH
            | AT_HANDLE_FID
            | AT_HANDLE_MNT_ID_UNIQUE
            | AT_HANDLE_CONNECTABLE;
        if flags & !known != 0 || (flags & AT_HANDLE_FID != 0 && flags & AT_HANDLE_CONNECTABLE != 0)
        {
            return err(errno::EINVAL);
        }
        let path = crate::guest!(crate::uaccess::read_cstr(path, crate::uaccess::PATH_MAX));
        let follow = flags & AT_SYMLINK_FOLLOW != 0;
        // What it names: (host file system, inode, mount), or a file fwe
        // makes up, by its path.
        let target: Result<([i32; 2], u64, u64), Vec<u8>> = if path.is_empty() {
            if flags & AT_EMPTY_PATH == 0 {
                return err(errno::ENOENT);
            }
            // The working directory, or the file open as `dirfd`.
            let cwd;
            let fd = if dirfd as i32 as i64 == fwe_abi::fcntl::AT_FDCWD {
                match self.fs().resolve(fwe_abi::fcntl::AT_FDCWD as i32, b".", true) {
                    Ok(r) => {
                        cwd = r.dir;
                        std::os::fd::AsRawFd::as_raw_fd(&cwd)
                    }
                    Err(e) => return err(e),
                }
            } else {
                dirfd as i32
            };
            let mount = crate::fdmarks::origin(fd).map_or(0, |o| u64::from(o.mount));
            match crate::fdmarks::stand_in(fd) {
                // A stand-in `O_PATH` descriptor: the file it names.
                Some(host) => match identity_at(&host) {
                    Some((fsid, ino)) => Ok((fsid, ino, mount)),
                    None => return err(errno::ESTALE),
                },
                None => {
                    let Some((_, ino)) = crate::fsops::host_identity(fd) else {
                        return err(errno::EBADF);
                    };
                    let Some(fsid) = fsid_of(fd) else { return err(errno::EBADF) };
                    Ok((fsid, ino, mount))
                }
            }
        } else if self.fs().synthetic(dirfd as i32, &path).is_some() {
            Err(path.clone())
        } else {
            let r = match self.fs().resolve(dirfd as i32, &path, follow) {
                Ok(r) => r,
                Err(e) => return err(e),
            };
            let name = match r.name_c() {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            // SAFETY: an all-zero `stat` is a valid out-parameter.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let how = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
            // SAFETY: the resolved directory and a NUL-terminated name.
            if unsafe {
                libc::fstatat(std::os::fd::AsRawFd::as_raw_fd(&r.dir), name.as_ptr(), &mut st, how)
            } != 0
            {
                return crate::host::last_error();
            }
            let Some(fsid) = fsid_of(std::os::fd::AsRawFd::as_raw_fd(&r.dir)) else {
                return err(errno::ENOENT);
            };
            Ok((fsid, st.st_ino, u64::from(r.mount_id)))
        };
        let mnt = target.as_ref().map_or(0, |t| t.2);
        let (bytes, kind, data) = match target {
            Ok((fsid, ino, _)) => {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&fsid[0].to_ne_bytes());
                d[4..8].copy_from_slice(&fsid[1].to_ne_bytes());
                d[8..16].copy_from_slice(&ino.to_ne_bytes());
                (HANDLE_BYTES, HANDLE_TYPE, d)
            }
            // A file fwe makes up: an identifier only, where one is asked.
            Err(p) => {
                if flags & AT_HANDLE_FID == 0 {
                    return err(errno::EOPNOTSUPP);
                }
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&crate::shared::hash(&p).to_ne_bytes());
                (HANDLE_BYTES, FID_TYPE, d)
            }
        };
        let room: u32 = crate::guest!(crate::uaccess::read(handle));
        if room > MAX_HANDLE_SZ {
            return err(errno::EINVAL);
        }
        // The mount's id is written whatever the handle's room, as Linux
        // writes it.
        let put_mount = || -> Result<(), i32> {
            if flags & AT_HANDLE_MNT_ID_UNIQUE != 0 {
                crate::uaccess::write(mount_id, mnt)
            } else {
                crate::uaccess::write(mount_id, mnt as i32)
            }
        };
        if room < bytes {
            crate::guest!(crate::uaccess::write(handle, bytes));
            crate::guest!(put_mount());
            return err(errno::EOVERFLOW);
        }
        crate::guest!(crate::uaccess::write(handle, [bytes, kind as u32]));
        crate::guest!(crate::uaccess::write_from(handle + 8, &data));
        crate::guest!(put_mount());
        0
    }

    /// `open_by_handle_at(mount_fd, handle, flags)`: the file the handle
    /// names, opened as `openat` opens it (permission checks, read-only
    /// mounts, `O_PATH`) at a path the caller sees it at in the mount of
    /// `mount_fd` ([`Self::handle_path`]); `ESTALE` where it has none.
    pub(crate) fn sys_open_by_handle_at(&mut self, mount_fd: u64, handle: u64, flags: u64) -> i64 {
        use fwe_abi::fcntl;
        // The mount the handle is to be of: the descriptor's.
        let mfd = mount_fd as i32;
        let anchor = if i64::from(mfd) == fcntl::AT_FDCWD {
            self.fs().resolve(mfd, b".", true).ok().map(|r| {
                let fd = std::os::fd::AsRawFd::as_raw_fd(&r.dir);
                (fsid_of(fd), r.ns_path.unwrap_or_default())
            })
        } else {
            self.fs().fd_ns_path(mfd).map(|ns| (fsid_of(mfd), ns))
        };
        let Some((Some(fsid), anchor)) = anchor else { return err(errno::EBADF) };
        if !self.creds.has(crate::caps::CAP_DAC_READ_SEARCH) {
            return err(errno::EPERM);
        }
        let head: [u32; 2] = crate::guest!(crate::uaccess::read(handle));
        if head[0] > MAX_HANDLE_SZ || head[0] == 0 {
            return err(errno::EINVAL);
        }
        let data = crate::guest!(crate::uaccess::read_bytes(handle + 8, head[0] as usize));
        if head[1] as i32 != HANDLE_TYPE || data.len() != HANDLE_BYTES as usize {
            return err(errno::ESTALE);
        }
        let word = |at: usize| i32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
        let of = [word(0), word(4)];
        let ino = u64::from_ne_bytes(data[8..16].try_into().unwrap());
        if of != fsid {
            return err(errno::ESTALE);
        }
        let Some(path) = self.handle_path(&anchor, of, ino) else { return err(errno::ESTALE) };
        // The file itself: a link opens as `O_NOFOLLOW` opens one (`ELOOP`,
        // or with `O_PATH` the link); nothing is made.
        let flags =
            flags & !(fcntl::O_CREAT | fcntl::O_EXCL | fcntl::O_TMPFILE) | fcntl::O_NOFOLLOW;
        let fd = self.open_with(fcntl::AT_FDCWD as u64, path, flags, 0);
        // Replaced at the path between the look and the open: stale.
        if fd >= 0 && !same_file(fd as i32, of, ino) {
            let _ = self.syscall(fwe_abi::nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            return err(errno::ESTALE);
        }
        fd
    }

    /// The path, from the caller's root, of inode `ino` of host file system
    /// `fsid` in the mount at namespace path `anchor` (a `mount_fd`'s): the
    /// host's path of the file, under the mount's host directory (or one of
    /// an overlay's layers), at the mount's place, where the caller finds
    /// that same file (no mount over it, under its root). `None` for a file
    /// the caller cannot reach so.
    fn handle_path(&self, anchor: &[u8], fsid: [i32; 2], ino: u64) -> Option<Vec<u8>> {
        let host = std::fs::canonicalize(std::ffi::OsStr::from_bytes(&path_of(fsid, ino)?)).ok()?;
        let host = host.as_os_str().as_bytes();
        let table = self.fs().mounts();
        let (m, _) = table.locate(anchor);
        let dirs: Vec<Vec<u8>> = match &m.source {
            crate::mounts::Source::Host(_) => vec![m.host_path(b"")?],
            crate::mounts::Source::Overlay(layers) => {
                layers.paths().map(|p| crate::mounts::join(p, &m.root)).collect()
            }
            _ => return None,
        };
        let rest = dirs.iter().find_map(|d| {
            let d = std::fs::canonicalize(std::ffi::OsStr::from_bytes(d)).ok()?;
            crate::mounts::under(host, d.as_os_str().as_bytes()).map(<[u8]>::to_vec)
        })?;
        let ns = crate::mounts::join(&m.point, &rest);
        let path = self.fs().from_ns(&ns)?;
        // The same file there, not one a mount or another layer shows.
        let r = self.fs().resolve(fwe_abi::fcntl::AT_FDCWD as i32, &path, false).ok()?;
        let st = r.lstat()?;
        let dir = std::os::fd::AsRawFd::as_raw_fd(&r.dir);
        (st.st_ino == ino && fsid_of(dir) == Some(fsid)).then_some(path)
    }
}

/// Whether the file open as `fd` is inode `ino` of host file system
/// `fsid`.
fn same_file(fd: i32, fsid: [i32; 2], ino: u64) -> bool {
    match crate::fdmarks::stand_in(fd) {
        // A stand-in `O_PATH` descriptor: the file it names.
        Some(host) => identity_at(&host) == Some((fsid, ino)),
        None => {
            crate::fsops::host_identity(fd).is_some_and(|(_, i)| i == ino)
                && fsid_of(fd) == Some(fsid)
        }
    }
}

/// The host file system and inode of the file at host path `path` (a link
/// itself): the file system of the directory it is in.
fn identity_at(path: &[u8]) -> Option<([i32; 2], u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let dir = match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => &b"/"[..],
        Some(i) => &path[..i],
    };
    let dir = std::ffi::CString::new(dir).ok()?;
    // SAFETY: all-zero `stat` and `statfs` are valid out-parameters.
    let (mut st, mut sf): (libc::stat, libc::statfs) = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated paths and valid out-parameters.
    if unsafe { libc::lstat(c.as_ptr(), &mut st) != 0 || libc::statfs(dir.as_ptr(), &mut sf) != 0 }
    {
        return None;
    }
    // SAFETY: `fsid_t` is two `i32`s, whose fields the libc crate keeps
    // private.
    let fsid = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(sf.f_fsid) };
    #[allow(clippy::unnecessary_cast)] // `st_ino`'s width differs by host
    Some((fsid, st.st_ino as u64))
}
