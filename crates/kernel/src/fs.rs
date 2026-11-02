//! A root filesystem and path resolution.
//!
//! The guest sees a filesystem rooted at a host directory (the rootfs). Guest
//! paths are resolved under that directory, component by component, following
//! symlinks ourselves and clamping `..` so a path can never escape the root —
//! the containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done by hand so
//! it works on macOS too. With no rootfs configured the root is the host `/`,
//! which reproduces pass-through behaviour.
//!
//! Guest file descriptors are host file descriptors: an opened file's host fd
//! is handed back to the guest unchanged, so `read`, `write`, `lseek` and the
//! rest act on it directly.

use crate::host::{errno_to_linux, last_errno};
use fwe_abi::{errno, fcntl};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Maximum symlinks followed while resolving one path.
const MAX_SYMLINKS: u32 = 40;

/// The last host errno as a Linux errno.
fn e() -> i32 {
    errno_to_linux(last_errno())
}

fn cstr(bytes: &[u8]) -> Result<CString, i32> {
    CString::new(bytes).map_err(|_| errno::EINVAL)
}

/// Duplicate `fd` with close-on-exec set.
fn dup_cloexec(fd: i32) -> Result<OwnedFd, i32> {
    // SAFETY: plain host call; the result is an owned fd.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(e());
    }
    // SAFETY: `new` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Split a path into components, dropping empty ones and ".".
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty() && c != b".").map(<[u8]>::to_vec).collect()
}

/// Lexically normalize `path` against the absolute `base`, clamping `..` at
/// the root. Used for the stored working directory, not for access.
pub fn normalize(base: &[u8], path: &[u8]) -> Vec<u8> {
    let mut stack: Vec<Vec<u8>> =
        if path.first() == Some(&b'/') { Vec::new() } else { components(base) };
    for comp in components(path) {
        if comp == b".." {
            stack.pop();
        } else {
            stack.push(comp);
        }
    }
    let mut out = Vec::with_capacity(1 + stack.iter().map(|c| c.len() + 1).sum::<usize>());
    for comp in &stack {
        out.push(b'/');
        out.extend_from_slice(comp);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// A resolved path: the directory holding the final component, and its name.
pub struct Resolved {
    pub dir: OwnedFd,
    /// Final component, or "." when the path names the directory itself.
    pub name: Vec<u8>,
}

impl Resolved {
    pub fn name_c(&self) -> Result<CString, i32> {
        cstr(&self.name)
    }
}

/// The guest's view of the filesystem.
pub struct Fs {
    root: OwnedFd,
    /// Current working directory, as a normalized absolute guest path.
    cwd: Vec<u8>,
    /// Host path of the root directory, for translating fd paths back.
    root_host: Vec<u8>,
    umask: u32,
    proc: crate::procfs::ProcInfo,
}

impl Fs {
    /// Open `path` as the rootfs, or the host `/` when `path` is `None`.
    pub fn new(path: Option<&[u8]>) -> Result<Fs, i32> {
        let path = cstr(path.unwrap_or(b"/"))?;
        // SAFETY: opening a directory by path.
        let fd = unsafe {
            libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(e());
        }
        // SAFETY: `fd` is a fresh owned directory descriptor.
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        let root_host = fd_path(root.as_raw_fd()).unwrap_or_else(|| b"/".to_vec());
        Ok(Fs {
            root,
            cwd: b"/".to_vec(),
            root_host,
            umask: 0o022,
            proc: crate::procfs::ProcInfo::default(),
        })
    }

    /// Set the per-process information the synthetic `/proc` files draw on.
    pub fn set_proc_info(&mut self, exe: Vec<u8>, cmdline: Vec<u8>, ncpu: u32, hostname: Vec<u8>) {
        self.proc = crate::procfs::ProcInfo { exe, cmdline, ncpu, hostname };
    }

    /// A synthetic `/proc` or `/sys` entry for `path`, if it names one. Only
    /// absolute paths and `AT_FDCWD`-relative paths are considered.
    pub fn synthetic(&self, dirfd: i32, path: &[u8]) -> Option<crate::procfs::Entry> {
        let absolute = if path.first() == Some(&b'/') {
            normalize(b"/", path)
        } else if dirfd as i64 == fcntl::AT_FDCWD {
            normalize(&self.cwd, path)
        } else {
            return None;
        };
        crate::procfs::lookup(&absolute, &self.proc)
    }

    pub fn cwd(&self) -> &[u8] {
        &self.cwd
    }

    pub fn umask(&self) -> u32 {
        self.umask
    }

    /// Set the umask, returning the previous value.
    pub fn set_umask(&mut self, mask: u32) -> u32 {
        std::mem::replace(&mut self.umask, mask & 0o777)
    }

    /// Apply the umask to a creation mode.
    pub fn apply_umask(&self, mode: u32) -> u32 {
        mode & !self.umask & 0o7777
    }

    /// The directory to start resolving from, and the path to resolve.
    fn base(&self, dirfd: i32, path: &[u8]) -> Result<(OwnedFd, Vec<u8>), i32> {
        if path.first() == Some(&b'/') {
            Ok((dup_cloexec(self.root.as_raw_fd())?, path.to_vec()))
        } else if dirfd as i64 == fcntl::AT_FDCWD {
            Ok((dup_cloexec(self.root.as_raw_fd())?, normalize(&self.cwd, path)))
        } else {
            Ok((dup_cloexec(dirfd)?, path.to_vec()))
        }
    }

    /// Resolve `path` relative to `dirfd`. Every symlink is followed except,
    /// when `follow_final` is false, one that is the last component.
    pub fn resolve(&self, dirfd: i32, path: &[u8], follow_final: bool) -> Result<Resolved, i32> {
        let (mut dir, path) = self.base(dirfd, path)?;
        let mut ancestors: Vec<OwnedFd> = Vec::new();
        let mut pending = components(&path);
        pending.reverse();
        let mut symlinks = 0;

        while let Some(comp) = pending.pop() {
            if comp == b".." {
                if let Some(parent) = ancestors.pop() {
                    dir = parent;
                }
                continue;
            }
            let is_last = pending.is_empty();
            if is_last && !follow_final {
                return Ok(Resolved { dir, name: comp });
            }
            let comp_c = cstr(&comp)?;
            match readlink_at(dir.as_raw_fd(), &comp_c) {
                Ok(target) => {
                    symlinks += 1;
                    if symlinks > MAX_SYMLINKS {
                        return Err(errno::ELOOP);
                    }
                    if target.first() == Some(&b'/') {
                        dir = dup_cloexec(self.root.as_raw_fd())?;
                        ancestors.clear();
                    }
                    // Push the target's components so they are resolved next,
                    // ahead of the remaining path. `pending` is a stack popped
                    // from the end, so pushing them reversed yields the first
                    // target component on top.
                    let mut parts = components(&target);
                    parts.reverse();
                    pending.extend(parts);
                }
                Err(errno::EINVAL) => {
                    // Not a symlink.
                    if is_last {
                        return Ok(Resolved { dir, name: comp });
                    }
                    let child = open_dir(dir.as_raw_fd(), &comp_c)?;
                    ancestors.push(dir);
                    dir = child;
                }
                Err(errno::ENOENT) => {
                    if is_last {
                        return Ok(Resolved { dir, name: comp });
                    }
                    return Err(errno::ENOENT);
                }
                Err(other) => return Err(other),
            }
        }
        Ok(Resolved { dir, name: b".".to_vec() })
    }

    /// Resolve and read a whole file under the root (following symlinks).
    /// Used to load the dynamic linker named by a guest executable.
    pub fn read(&self, path: &[u8]) -> Result<Vec<u8>, i32> {
        let resolved = self.resolve(fcntl::AT_FDCWD as i32, path, true)?;
        let name = resolved.name_c()?;
        // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd.
        let fd = unsafe {
            libc::openat(resolved.dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(e());
        }
        // SAFETY: `fd` is a fresh owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut data = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            // SAFETY: reading into a valid local buffer.
            let n = unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if n < 0 {
                return Err(e());
            }
            if n == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..n as usize]);
        }
        Ok(data)
    }

    /// Translate a host path under the root to a guest path.
    pub fn host_to_guest(&self, host: &[u8]) -> Option<Vec<u8>> {
        if self.root_host == b"/" {
            return Some(host.to_vec());
        }
        let rest = host.strip_prefix(self.root_host.as_slice())?;
        if rest.is_empty() {
            Some(b"/".to_vec())
        } else if rest.first() == Some(&b'/') {
            Some(rest.to_vec())
        } else {
            None
        }
    }

    /// Set the working directory to the resolved `path`.
    pub fn chdir(&mut self, dirfd: i32, path: &[u8]) -> Result<(), i32> {
        let resolved = self.resolve(dirfd, path, true)?;
        // Confirm it is a directory we can enter.
        let child = match &resolved.name[..] {
            b"." => dup_cloexec(resolved.dir.as_raw_fd())?,
            name => open_dir(resolved.dir.as_raw_fd(), &cstr(name)?)?,
        };
        drop(child);
        let absolute =
            if path.first() == Some(&b'/') { path.to_vec() } else { normalize(&self.cwd, path) };
        self.cwd = normalize(&absolute, b"");
        Ok(())
    }

    /// Set the working directory to the host directory `fd` refers to.
    pub fn fchdir(&mut self, fd: i32) -> Result<(), i32> {
        let host = fd_path(fd).ok_or(errno::EBADF)?;
        match self.host_to_guest(&host) {
            Some(guest) => {
                self.cwd = guest;
                Ok(())
            }
            None => Err(errno::EACCES),
        }
    }
}

/// `readlinkat`, returning the target or a Linux errno (`EINVAL` if `name`
/// is not a symlink).
fn readlink_at(dir: i32, name: &CString) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: `buf` is a valid buffer of its length; `name` is NUL-terminated.
        let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(e());
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Open `name` in `dir` as a directory, not following a final symlink.
fn open_dir(dir: i32, name: &CString) -> Result<OwnedFd, i32> {
    // SAFETY: opening a directory relative to `dir`.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(e());
    }
    // SAFETY: `fd` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The host path a descriptor refers to.
fn fd_path(fd: i32) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; 1024]; // PATH_MAX on macOS.
        // SAFETY: F_GETPATH fills `buf` with a NUL-terminated path.
        let r = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
        if r != 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0)?;
        Some(buf[..end].to_vec())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let link = format!("/proc/self/fd/{fd}");
        std::fs::read_link(link).ok().map(|p| {
            use std::os::unix::ffi::OsStringExt;
            p.into_os_string().into_vec()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_clamps_dotdot_at_root() {
        assert_eq!(normalize(b"/", b"a/b"), b"/a/b");
        assert_eq!(normalize(b"/x", b"../../a"), b"/a");
        assert_eq!(normalize(b"/x/y", b"./z/../w"), b"/x/y/w");
        assert_eq!(normalize(b"/x", b"/abs/p"), b"/abs/p");
        assert_eq!(normalize(b"/", b".."), b"/");
    }

    #[test]
    fn components_drop_empties_and_dot() {
        assert_eq!(components(b"//a/./b//c"), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert!(components(b"///").is_empty());
    }
}
