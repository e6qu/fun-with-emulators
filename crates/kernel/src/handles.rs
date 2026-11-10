//! File handles (`name_to_handle_at`, `open_by_handle_at`): a handle names
//! a file by the host file system it is on and its inode there, which the
//! host turns back into a path (`fsgetpath`), so a handle outlives renames
//! of the file, as a Linux handle does, and goes stale once the file is
//! gone. A file fwe makes up (under `/proc`) has an identifier handle
//! (`AT_HANDLE_FID`) only, which opens nothing.

use crate::{Kernel, Platform};
use fwe_abi::{err, errno};

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
    /// The host file system of the working directory.
    fn cwd_fsid(&self) -> Option<[i32; 2]> {
        let r = self.fs().resolve(fwe_abi::fcntl::AT_FDCWD as i32, b".", true).ok()?;
        fsid_of(std::os::fd::AsRawFd::as_raw_fd(&r.dir))
    }

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
            // SAFETY: an all-zero `stat` is a valid out-parameter.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return err(errno::EBADF);
            }
            let Some(fsid) = fsid_of(fd) else { return err(errno::EBADF) };
            Ok((fsid, st.st_ino, 0))
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

    /// `open_by_handle_at(mount_fd, handle, flags)`.
    pub(crate) fn sys_open_by_handle_at(&mut self, mount_fd: u64, handle: u64, flags: u64) -> i64 {
        // The file system the handle is to be of: the descriptor's.
        let mfd = mount_fd as i32;
        let fsid =
            if i64::from(mfd) == fwe_abi::fcntl::AT_FDCWD { self.cwd_fsid() } else { fsid_of(mfd) };
        let Some(fsid) = fsid else { return err(errno::EBADF) };
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
        let Some(path) = path_of(of, ino) else { return err(errno::ESTALE) };
        let Ok(c) = std::ffi::CString::new(path) else { return err(errno::ESTALE) };
        // A handle of a symbolic link opens nothing (`ELOOP`), as Linux's.
        let host = crate::host::open_flags_to_host(flags) | libc::O_NOFOLLOW;
        // SAFETY: a NUL-terminated host path.
        let fd = unsafe { libc::open(c.as_ptr(), host, 0) };
        if fd < 0 {
            return crate::host::last_error();
        }
        fd as i64
    }
}
