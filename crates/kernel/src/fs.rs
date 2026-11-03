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

/// The device nodes every Linux system has in `/dev`, which the guest finds
/// there whatever the rootfs holds: they are the host's own nodes (a rootfs
/// unpacked without privileges has none, and Linux mounts `/dev` over it).
const DEVICES: &[&[u8]] = &[b"null", b"zero", b"random", b"urandom", b"tty"];

/// `/dev` entries that are links into `/proc/self/fd`, as on Linux.
fn dev_link(absolute: &[u8]) -> Option<Vec<u8>> {
    let fd = match absolute {
        b"/dev/fd" => return Some(b"/proc/self/fd".to_vec()),
        b"/dev/stdin" => 0,
        b"/dev/stdout" => 1,
        b"/dev/stderr" => 2,
        _ => return None,
    };
    Some(format!("/proc/self/fd/{fd}").into_bytes())
}

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
    /// Write the filesystem view into a fork snapshot. The root directory
    /// descriptor is inherited, so its number is enough.
    pub(crate) fn save(&self, e: &mut crate::snapshot::Enc) {
        use std::os::fd::AsRawFd;
        e.i32(self.root.as_raw_fd());
        e.bytes(&self.cwd);
        e.bytes(&self.root_host);
        e.u32(self.umask);
        e.bytes(&self.proc.exe);
        e.bytes(&self.proc.cmdline);
        e.u32(self.proc.ncpu);
        e.bytes(&self.proc.hostname);
    }

    /// The filesystem view [`Fs::save`] wrote, in a fork child.
    pub(crate) fn restore(d: &mut crate::snapshot::Dec) -> Fs {
        use std::os::fd::FromRawFd;
        let fd = d.i32();
        // SAFETY: the parent's root descriptor, inherited at the same number
        // and owned by nothing else in this process.
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        Fs {
            root,
            cwd: d.bytes(),
            root_host: d.bytes(),
            umask: d.u32(),
            proc: crate::procfs::ProcInfo {
                exe: d.bytes(),
                cmdline: d.bytes(),
                ncpu: d.u32(),
                hostname: d.bytes(),
            },
        }
    }

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
        // The root is fwe's: out of the guest's reach.
        let fd = crate::fdtable::reserve(fd);
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
    /// Record what `/proc/self` reports. A relative `exe` is taken against
    /// the guest's working directory: `/proc/self/exe` is always absolute.
    pub fn set_proc_info(&mut self, exe: Vec<u8>, cmdline: Vec<u8>, ncpu: u32, hostname: Vec<u8>) {
        let exe = if exe.starts_with(b"/") { exe } else { normalize(&self.cwd, &exe) };
        self.proc = crate::procfs::ProcInfo { exe, cmdline, ncpu, hostname };
    }

    /// The host path of the rootfs, or `None` when the root is the host `/`
    /// (pass-through). Used to root `AF_UNIX` socket paths.
    pub fn root_host_path(&self) -> Option<std::path::PathBuf> {
        if self.root_host == b"/" {
            None
        } else {
            use std::os::unix::ffi::OsStrExt;
            Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&self.root_host)))
        }
    }

    /// A synthetic `/proc` or `/sys` entry for `path`, if it names one. Only
    /// absolute paths and `AT_FDCWD`-relative paths are considered.
    pub fn synthetic(&self, dirfd: i32, path: &[u8]) -> Option<crate::procfs::Entry> {
        let mut absolute = self.absolute(dirfd, path)?;
        if let Some(target) = dev_link(&absolute) {
            return Some(crate::procfs::Entry::Symlink(target));
        }
        if let Some(n) = absolute.strip_prefix(b"/dev/fd/") {
            absolute = [b"/proc/self/fd/", n].concat();
        }
        if let Some(n) = absolute.strip_prefix(b"/proc/self/fd/") {
            let fd = std::str::from_utf8(n).ok().and_then(|n| n.parse::<i32>().ok());
            let open = fd.is_some_and(|fd| {
                // SAFETY: F_GETFD only queries the descriptor.
                fd >= 0
                    && crate::fdtable::guest_visible(fd)
                    && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0
            });
            return Some(match fd {
                Some(fd) if open => crate::procfs::Entry::Fd { fd, target: self.fd_target(fd) },
                _ => crate::procfs::Entry::Missing,
            });
        }
        crate::procfs::lookup(&absolute, &self.proc)
    }

    /// What `/proc/self/fd/<fd>` links to: the guest path of the open file,
    /// or Linux's name for an object with none.
    pub fn fd_target(&self, fd: i32) -> Vec<u8> {
        if let Some(name) = crate::specialfd::anon_name(fd) {
            return format!("anon_inode:{name}").into_bytes();
        }
        if crate::signalfd::is_signalfd(fd) {
            return b"anon_inode:[signalfd]".to_vec();
        }
        // SAFETY: an all-zero stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return b"anon_inode:[unknown]".to_vec();
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFIFO => return format!("pipe:[{}]", st.st_ino).into_bytes(),
            libc::S_IFSOCK => return format!("socket:[{}]", st.st_ino).into_bytes(),
            _ => {}
        }
        match fd_path(fd) {
            Some(host) if self.root_host == b"/" => host,
            Some(host) => match host.strip_prefix(self.root_host.as_slice()) {
                Some(b"") => b"/".to_vec(),
                Some(rest) if rest.starts_with(b"/") => rest.to_vec(),
                _ => host,
            },
            // A kqueue (an epoll descriptor) has neither path nor type.
            None => b"anon_inode:[eventpoll]".to_vec(),
        }
    }

    /// Whether `path` names `/proc/self/fd`, whose listing is the open
    /// descriptors.
    pub fn lists_fds(&self, dirfd: i32, path: &[u8]) -> bool {
        let absolute = if path.first() == Some(&b'/') {
            normalize(b"/", path)
        } else if dirfd as i64 == fcntl::AT_FDCWD {
            normalize(&self.cwd, path)
        } else {
            return false;
        };
        absolute == b"/proc/self/fd"
    }

    /// The entries of a synthetic `/proc` or `/sys` directory `path`, if it is
    /// one. Normalizes like [`synthetic`](Self::synthetic).
    pub fn synth_children(&self, dirfd: i32, path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
        let absolute = if path.first() == Some(&b'/') {
            normalize(b"/", path)
        } else if dirfd as i64 == fcntl::AT_FDCWD {
            normalize(&self.cwd, path)
        } else {
            return None;
        };
        if absolute == b"/proc/self/fd" {
            let mut out = vec![
                (b".".to_vec(), crate::procfs::DT_DIR),
                (b"..".to_vec(), crate::procfs::DT_DIR),
            ];
            out.extend(
                crate::fdtable::open_fds()
                    .into_iter()
                    .map(|fd| (fd.to_string().into_bytes(), crate::procfs::DT_LNK)),
            );
            return Some(out);
        }
        crate::procfs::children(&absolute)
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

    /// `path` as a normalized absolute guest path, if it is absolute or
    /// relative to the working directory (not to another directory fd).
    fn absolute(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        if path.first() == Some(&b'/') {
            Some(normalize(b"/", path))
        } else if dirfd as i64 == fcntl::AT_FDCWD {
            Some(normalize(&self.cwd, path))
        } else {
            None
        }
    }

    /// Resolve `path` relative to `dirfd`. Every symlink is followed except,
    /// when `follow_final` is false, one that is the last component. The
    /// standard device nodes ([`DEVICES`]) resolve to the host's.
    pub fn resolve(&self, dirfd: i32, path: &[u8], follow_final: bool) -> Result<Resolved, i32> {
        let device = self.absolute(dirfd, path).and_then(|a| {
            a.strip_prefix(b"/dev/").filter(|n| DEVICES.contains(n)).map(<[u8]>::to_vec)
        });
        if let Some(name) = device {
            // SAFETY: plain host call; the result is checked and owned.
            let dev = unsafe {
                libc::open(c"/dev".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
            };
            if dev < 0 {
                return Err(e());
            }
            // SAFETY: `dev` is a fresh owned descriptor.
            return Ok(Resolved { dir: unsafe { OwnedFd::from_raw_fd(dev) }, name });
        }
        let (mut dir, path) = self.base(dirfd, path)?;
        let mut ancestors: Vec<OwnedFd> = Vec::new();
        let mut pending = components(&path);
        pending.reverse();
        let mut symlinks = 0;

        while let Some(comp) = pending.pop() {
            if comp == b".." {
                // Back to the directory we came through; with none recorded
                // (a path relative to a directory fd), ascend on the host —
                // unless this is the root, where `..` stays put.
                if let Some(parent) = ancestors.pop() {
                    dir = parent;
                } else if !same_file(dir.as_raw_fd(), self.root.as_raw_fd()) {
                    dir = open_dir(dir.as_raw_fd(), c"..")?;
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
/// Whether two descriptors name the same file (same device and inode).
fn same_file(a: i32, b: i32) -> bool {
    let stat = |fd: i32| {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-parameter.
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    };
    match (stat(a), stat(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn open_dir(dir: i32, name: &std::ffi::CStr) -> Result<OwnedFd, i32> {
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

    /// `..` relative to a directory fd ascends to the parent on the host
    /// (gnulib's fts walks trees this way), but never past the root.
    #[test]
    fn dotdot_relative_to_dirfd_ascends_but_stays_in_root() {
        let root = std::env::temp_dir().join(format!("fwe-fs-dotdot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/marker"), b"x").unwrap();
        let fs = Fs::new(Some(root.to_str().unwrap().as_bytes())).unwrap();

        let b = fs.resolve(fcntl::AT_FDCWD as i32, b"/a/b", true).unwrap();
        let b_fd = open_dir(b.dir.as_raw_fd(), &b.name_c().unwrap()).unwrap();
        // "../marker" from /a/b names /a/marker.
        let r = fs.resolve(b_fd.as_raw_fd(), b"../marker", true).unwrap();
        assert_eq!(r.name, b"marker");
        assert!(same_file(
            r.dir.as_raw_fd(),
            open_dir(fs.root.as_raw_fd(), c"a").unwrap().as_raw_fd()
        ));
        // "../../../marker" is clamped at the root: /marker, which does not exist.
        let r = fs.resolve(b_fd.as_raw_fd(), b"../../../../marker", true).unwrap();
        assert!(same_file(r.dir.as_raw_fd(), fs.root.as_raw_fd()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A rootfs with no `/dev` still has the standard device nodes (the
    /// host's) and the links into `/proc/self/fd`; other `/dev` names are
    /// looked up in the rootfs.
    #[test]
    fn dev_has_the_standard_nodes() {
        let root = std::env::temp_dir().join(format!("fwe-fs-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fs = Fs::new(Some(root.to_str().unwrap().as_bytes())).unwrap();
        // SAFETY: opening a host directory for comparison.
        let dev = unsafe { libc::open(c"/dev".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        // SAFETY: `dev` is a fresh descriptor.
        let dev = unsafe { OwnedFd::from_raw_fd(dev) };
        for path in [&b"/dev/null"[..], b"/dev/./zero", b"/tmp/../dev/urandom"] {
            let r = fs.resolve(fcntl::AT_FDCWD as i32, path, true).unwrap();
            assert!(same_file(r.dir.as_raw_fd(), dev.as_raw_fd()));
        }
        assert!(fs.resolve(fcntl::AT_FDCWD as i32, b"/dev/disk0", true).is_err());
        let link = |p: &[u8]| match fs.synthetic(fcntl::AT_FDCWD as i32, p) {
            Some(crate::procfs::Entry::Symlink(t)) => Some(t),
            _ => None,
        };
        assert_eq!(link(b"/dev/stdout").unwrap(), b"/proc/self/fd/1");
        assert_eq!(link(b"/dev/fd").unwrap(), b"/proc/self/fd");
        assert!(matches!(
            fs.synthetic(fcntl::AT_FDCWD as i32, b"/dev/fd/1"),
            Some(crate::procfs::Entry::Fd { fd: 1, .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn components_drop_empties_and_dot() {
        assert_eq!(components(b"//a/./b//c"), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert!(components(b"///").is_empty());
    }
}
