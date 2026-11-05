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
        let fd = crate::fdtable::reserve(fd)?;
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
            Some(host) => guest_path(&self.root_host, &host).unwrap_or(host),
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

    /// The guest path of the program the process runs (`/proc/self/exe`).
    pub fn exe(&self) -> &[u8] {
        &self.proc.exe
    }

    /// Apply the umask to a creation mode.
    pub fn apply_umask(&self, mode: u32) -> u32 {
        mode & !self.umask & 0o7777
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
    /// standard device nodes ([`DEVICES`]) resolve to the host's, and
    /// `/dev/shm` to fwe's own directory for it ([`shm`]).
    pub fn resolve(&self, dirfd: i32, path: &[u8], follow_final: bool) -> Result<Resolved, i32> {
        resolve_in(self.root.as_raw_fd(), &self.root_host, &self.cwd, dirfd, path, follow_final)
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

    /// Make this the view the socket calls resolve `AF_UNIX` paths in (see
    /// [`resolve_host`]). Called once the process's filesystem is set up.
    pub fn publish(&self) {
        *published() = Some(Published {
            root: self.root.as_raw_fd(),
            root_host: self.root_host.clone(),
            cwd: self.cwd.clone(),
        });
    }

    /// Bring the published view's working directory up to date, if this is
    /// the published view.
    fn republish(&self) {
        if let Some(v) = published().as_mut().filter(|v| v.root == self.root.as_raw_fd()) {
            v.cwd = self.cwd.clone();
        }
    }

    /// Translate a host path under the root (or in `/dev/shm`) to a guest
    /// path.
    pub fn host_to_guest(&self, host: &[u8]) -> Option<Vec<u8>> {
        guest_path(&self.root_host, host)
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
        self.republish();
        Ok(())
    }

    /// Set the working directory to the host directory `fd` refers to.
    pub fn fchdir(&mut self, fd: i32) -> Result<(), i32> {
        let host = fd_path(fd).ok_or(errno::EBADF)?;
        match self.host_to_guest(&host) {
            Some(guest) => {
                self.cwd = guest;
                self.republish();
                Ok(())
            }
            None => Err(errno::EACCES),
        }
    }
}

/// Resolve `path` relative to `dirfd` under the root directory `root`
/// (host path `root_host`) with the working directory `cwd`: the work of
/// [`Fs::resolve`], also done for the socket calls that run without the
/// kernel lock ([`resolve_host`]).
fn resolve_in(
    root: i32,
    root_host: &[u8],
    cwd: &[u8],
    dirfd: i32,
    path: &[u8],
    follow_final: bool,
) -> Result<Resolved, i32> {
    let absolute = if path.first() == Some(&b'/') {
        Some(normalize(b"/", path))
    } else if dirfd as i64 == fcntl::AT_FDCWD {
        Some(normalize(cwd, path))
    } else {
        None
    };
    let device = absolute
        .as_deref()
        .and_then(|a| a.strip_prefix(b"/dev/").filter(|n| DEVICES.contains(n)).map(<[u8]>::to_vec));
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
    // Where to start, and the guest path of the directory being looked in
    // (its components; unknown when resolving from another directory fd),
    // by which `/dev/shm` is recognized.
    let (mut dir, path, mut guest) = if path.first() == Some(&b'/') {
        (dup_cloexec(root)?, path.to_vec(), Some(Vec::new()))
    } else if dirfd as i64 == fcntl::AT_FDCWD {
        (dup_cloexec(root)?, normalize(cwd, path), Some(Vec::new()))
    } else {
        (dup_cloexec(dirfd)?, path.to_vec(), None)
    };
    let mut ancestors: Vec<OwnedFd> = Vec::new();
    let mut pending = components(&path);
    pending.reverse();
    let mut symlinks = 0;

    while let Some(comp) = pending.pop() {
        if comp == b".." {
            // Back to the directory we came through; with none recorded
            // (a path relative to a directory fd), ascend on the host —
            // unless this is the root, where `..` stays put, or the top of
            // `/dev/shm`, whose parent is the root's `/dev`.
            if let Some(parent) = ancestors.pop() {
                dir = parent;
                if let Some(g) = guest.as_mut() {
                    g.pop();
                }
            } else if same_file(dir.as_raw_fd(), root) {
            } else if shm::is_top(dir.as_raw_fd()) {
                dir = dev_dir(root)?;
                guest = Some(vec![b"dev".to_vec()]);
            } else {
                dir = open_dir(dir.as_raw_fd(), c"..")?;
            }
            continue;
        }
        // `/dev/shm`, the tmpfs Linux always mounts there, is fwe's own
        // directory for this root; a rootfs need not have a `/dev` for it.
        let at = guest.as_deref().map(<[Vec<u8>]>::len);
        let into_shm = match (at, guest.as_deref().and_then(<[_]>::first)) {
            (Some(1), Some(d)) => d == b"dev" && comp == b"shm",
            (Some(0), _) => {
                comp == b"dev"
                    && pending.last().is_some_and(|n| n == b"shm")
                    && open_dir(dir.as_raw_fd(), c"dev").is_err_and(|e| e == errno::ENOENT)
            }
            _ => false,
        };
        if into_shm {
            if comp == b"dev" {
                pending.pop();
            }
            let top = shm::open(root_host)?;
            ancestors.push(dev_dir(root)?);
            dir = top;
            guest = Some(vec![b"dev".to_vec(), b"shm".to_vec()]);
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
                    dir = dup_cloexec(root)?;
                    ancestors.clear();
                    guest = Some(Vec::new());
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
                if let Some(g) = guest.as_mut() {
                    g.push(comp);
                }
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

/// The root's `/dev`, or the root itself when it has none: the parent of
/// `/dev/shm`.
fn dev_dir(root: i32) -> Result<OwnedFd, i32> {
    open_dir(root, c"dev").or_else(|_| dup_cloexec(root))
}

/// The guest path of the host path `host`, for a root at `root_host`: under
/// the root, or in `/dev/shm`.
fn guest_path(root_host: &[u8], host: &[u8]) -> Option<Vec<u8>> {
    if let Some(guest) = shm::guest_path(host) {
        return Some(guest);
    }
    if root_host == b"/" {
        return Some(host.to_vec());
    }
    match host.strip_prefix(root_host)? {
        b"" => Some(b"/".to_vec()),
        rest if rest.first() == Some(&b'/') => Some(rest.to_vec()),
        _ => None,
    }
}

/// The filesystem view the socket calls resolve `AF_UNIX` paths in: they
/// run without the kernel lock, so the [`Fs`] that [`Fs::publish`] was
/// called on keeps a copy of its root and working directory here.
struct Published {
    /// The root directory descriptor, owned by that [`Fs`] (which lives as
    /// long as the process).
    root: i32,
    root_host: Vec<u8>,
    cwd: Vec<u8>,
}

static PUBLISHED: std::sync::Mutex<Option<Published>> = std::sync::Mutex::new(None);

fn published() -> std::sync::MutexGuard<'static, Option<Published>> {
    PUBLISHED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Forget the published view (for tests whose [`Fs`] goes away).
#[cfg(test)]
pub(crate) fn unpublish() {
    *published() = None;
}

/// Run `f` holding the published view's lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = published();
    f()
}

/// The host path an `AF_UNIX` socket address's `path` names, resolved as a
/// file's path is (`follow_final` as for [`Fs::resolve`]), or `path`
/// itself when no filesystem view was published.
pub(crate) fn resolve_host(path: &[u8], follow_final: bool) -> Result<Vec<u8>, i32> {
    let view = published();
    let Some(v) = view.as_ref() else { return Ok(path.to_vec()) };
    let r = resolve_in(v.root, &v.root_host, &v.cwd, fcntl::AT_FDCWD as i32, path, follow_final)?;
    let mut host = fd_path(r.dir.as_raw_fd()).ok_or(errno::ENOENT)?;
    if r.name != b"." {
        if host.last() != Some(&b'/') {
            host.push(b'/');
        }
        host.extend_from_slice(&r.name);
    }
    Ok(host)
}

/// The guest path of the host path an `AF_UNIX` socket is bound to, if it
/// is in the published view.
pub(crate) fn guest_of_host(host: &[u8]) -> Option<Vec<u8>> {
    let view = published();
    match view.as_ref() {
        Some(v) => guest_path(&v.root_host, host),
        None => Some(host.to_vec()),
    }
}

/// `/dev/shm`: Linux mounts a tmpfs there that every process on the
/// machine shares. fwe keeps one directory for it per rootfs (the host's
/// `/` included), private to the user, shared by every fwe process that
/// runs on that root: `fwe-<uid>/shm-<hash of the root's host path>` in the
/// user's temporary directory. Unlike a tmpfs it outlives the processes,
/// until the host clears its temporary files.
mod shm {
    use super::{OwnedFd, e, fd_path};
    use fwe_abi::errno;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::OnceLock;

    struct Top {
        /// Canonical host path.
        path: Vec<u8>,
        dev: libc::dev_t,
        ino: libc::ino_t,
    }

    /// The directory, once a guest path has led to it (a process has one
    /// root).
    static TOP: OnceLock<Top> = OnceLock::new();

    /// The user's own temporary directory on the host.
    fn user_temp() -> Vec<u8> {
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; 1024];
            // SAFETY: `buf` is valid for its length; confstr NUL-terminates.
            let n = unsafe {
                libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len())
            };
            if n > 0 && n <= buf.len() {
                buf.truncate(n - 1);
                return buf;
            }
        }
        b"/tmp".to_vec()
    }

    fn c(path: &[u8]) -> Result<std::ffi::CString, i32> {
        std::ffi::CString::new(path).map_err(|_| errno::EINVAL)
    }

    /// Create the directory `path` with `mode` if it is missing, and check
    /// it is a real directory of this user's (not a link someone planted).
    fn ensure_dir(path: &[u8], mode: libc::mode_t, private: bool) -> Result<(), i32> {
        let p = c(path)?;
        // SAFETY: `p` is NUL-terminated.
        if unsafe { libc::mkdir(p.as_ptr(), mode) } == 0 {
            // The mode as given, whatever the umask.
            // SAFETY: as above.
            unsafe { libc::chmod(p.as_ptr(), mode) };
        }
        // SAFETY: zeroed bytes are a valid `stat`; `lstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `p` is NUL-terminated; `st` is a valid out-parameter.
        if unsafe { libc::lstat(p.as_ptr(), &mut st) } != 0 {
            return Err(e());
        }
        // SAFETY: getuid cannot fail.
        let mine = st.st_uid == unsafe { libc::getuid() };
        let dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if !mine || !dir || (private && st.st_mode & 0o077 != 0) {
            return Err(errno::EACCES);
        }
        Ok(())
    }

    /// Open the directory for the root at `root_host`, creating it on first
    /// use.
    pub(super) fn open(root_host: &[u8]) -> Result<OwnedFd, i32> {
        let path = match TOP.get() {
            Some(top) => top.path.clone(),
            None => {
                // SAFETY: getuid cannot fail.
                let uid = unsafe { libc::getuid() };
                let mut base = user_temp();
                if base.last() != Some(&b'/') {
                    base.push(b'/');
                }
                base.extend_from_slice(format!("fwe-{uid}").as_bytes());
                ensure_dir(&base, 0o700, true)?;
                // FNV-1a: stable across processes and fwe builds.
                let hash = root_host.iter().fold(0xcbf29ce484222325u64, |h, &b| {
                    (h ^ b as u64).wrapping_mul(0x100000001b3)
                });
                base.extend_from_slice(format!("/shm-{hash:016x}").as_bytes());
                // Linux's `/dev/shm` is world-writable and sticky; this one
                // is in a directory only the user can enter.
                ensure_dir(&base, 0o1777, false)?;
                base
            }
        };
        let p = c(&path)?;
        // SAFETY: opening a directory by path; the result is checked.
        let fd = unsafe {
            libc::open(
                p.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(e());
        }
        // SAFETY: `fd` is a fresh owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if TOP.get().is_none() {
            // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `st` is a valid out-parameter.
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
                return Err(e());
            }
            let path = fd_path(fd.as_raw_fd()).unwrap_or(path);
            let _ = TOP.set(Top { path, dev: st.st_dev, ino: st.st_ino });
        }
        Ok(fd)
    }

    /// Whether `fd` is the directory itself.
    pub(super) fn is_top(fd: i32) -> bool {
        let Some(top) = TOP.get() else { return false };
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-parameter.
        unsafe { libc::fstat(fd, &mut st) == 0 && (st.st_dev, st.st_ino) == (top.dev, top.ino) }
    }

    /// The guest path (`/dev/shm/...`) of a host path in the directory.
    pub(super) fn guest_path(host: &[u8]) -> Option<Vec<u8>> {
        let top = TOP.get()?;
        match host.strip_prefix(top.path.as_slice())? {
            b"" => Some(b"/dev/shm".to_vec()),
            rest if rest.first() == Some(&b'/') => Some([&b"/dev/shm"[..], rest].concat()),
            _ => None,
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

    /// `/dev/shm` is fwe's own directory for the root, whether or not the
    /// rootfs has a `/dev`: reached directly, through a symlink and from
    /// the working directory; its `..` is the root's `/dev`; files in it
    /// report their guest paths.
    #[test]
    fn dev_shm_is_a_directory_of_its_own() {
        let root = std::env::temp_dir().join(format!("fwe-fs-shm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::os::unix::fs::symlink("/dev/shm/f", root.join("tmp/link")).unwrap();
        let mut fs = Fs::new(Some(root.to_str().unwrap().as_bytes())).unwrap();
        let at = fcntl::AT_FDCWD as i32;
        let top = fs.resolve(at, b"/dev/shm", true).unwrap();
        assert_eq!(top.name, b".");
        assert!(shm::is_top(top.dir.as_raw_fd()));
        assert!(!root.join("dev").exists());
        // A file created there is found by each way in, and not in the rootfs.
        let f = fs.resolve(at, b"/dev/shm/f", true).unwrap();
        assert!(shm::is_top(f.dir.as_raw_fd()));
        // SAFETY: creating a file in a live directory fd.
        let fd = unsafe {
            libc::openat(f.dir.as_raw_fd(), c"f".as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600)
        };
        assert!(fd >= 0);
        // SAFETY: `fd` is a fresh descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(fs.fd_target(fd.as_raw_fd()), b"/dev/shm/f");
        for path in [&b"/tmp/link"[..], b"/dev/./shm/../shm/f", b"/../dev/shm/f"] {
            let r = fs.resolve(at, path, true).unwrap();
            assert!(shm::is_top(r.dir.as_raw_fd()), "{}", String::from_utf8_lossy(path));
            assert_eq!(r.name, b"f");
        }
        fs.chdir(at, b"/dev/shm").unwrap();
        assert!(shm::is_top(fs.resolve(at, b"f", true).unwrap().dir.as_raw_fd()));
        // `..` from it, also relative to its descriptor, is the root's /dev
        // (or the root, when it has none).
        let up = fs.resolve(top.dir.as_raw_fd(), b"../tmp", true).unwrap();
        assert!(same_file(up.dir.as_raw_fd(), fs.root.as_raw_fd()));
        std::fs::create_dir_all(root.join("dev/marker")).unwrap();
        let dev = open_dir(fs.root.as_raw_fd(), c"dev").unwrap();
        for dir in [at, top.dir.as_raw_fd()] {
            let up = fs.resolve(dir, b"../marker", true).unwrap();
            assert!(same_file(up.dir.as_raw_fd(), dev.as_raw_fd()));
        }
        assert!(shm::is_top(fs.resolve(at, b"/dev/shm/f", true).unwrap().dir.as_raw_fd()));
        // SAFETY: removing the file made above.
        unsafe { libc::unlinkat(f.dir.as_raw_fd(), c"f".as_ptr(), 0) };
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn components_drop_empties_and_dot() {
        assert_eq!(components(b"//a/./b//c"), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert!(components(b"///").is_empty());
    }
}
