//! A root filesystem and path resolution.
//!
//! The guest sees a filesystem rooted at a host directory (the rootfs), with
//! what is mounted on it ([`crate::mounts`]): `/proc`, `/sys`, `/dev/shm` and
//! whatever the guest mounts. Guest paths are resolved component by
//! component, following symlinks ourselves, crossing into a mount where one
//! is attached and clamping `..` at the process's root, so a path can never
//! escape it — the containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done
//! by hand so it works on macOS too. With no rootfs configured the root is
//! the host `/`, which reproduces pass-through behaviour.
//!
//! A process's root is a path in its mount namespace's view (`/` until it
//! calls `chroot`, or `pivot_root` moves the namespace's root), and its
//! working directory a path from that root.
//!
//! Guest file descriptors are host file descriptors: an opened file's host fd
//! is handed back to the guest unchanged, so `read`, `write`, `lseek` and the
//! rest act on it directly.

use crate::host::{errno_to_linux, last_errno};
use crate::mounts::{self, FsType, Mount, Source, Table, store::Ns};
use fwe_abi::{errno, fcntl};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

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
    /// Where it is in the mount namespace's view, when known (not for a
    /// path relative to a directory outside the process's root).
    pub ns_path: Option<Vec<u8>>,
    /// The flags of the mount it is in (`MS_RDONLY` and the like).
    pub mount_flags: u64,
    /// The type of the filesystem it is in.
    pub fstype: FsType,
    /// The mount it is in (0 when not known).
    pub mount_id: u32,
    /// It is the root of a mount (which cannot be removed or renamed).
    pub mount_root: bool,
}

impl Resolved {
    pub fn name_c(&self) -> Result<CString, i32> {
        cstr(&self.name)
    }

    /// `EROFS` when the mount is read-only.
    pub fn writable(&self) -> Result<(), i32> {
        if self.mount_flags & mounts::ms::RDONLY != 0 { Err(errno::EROFS) } else { Ok(()) }
    }

    fn plain(dir: OwnedFd, name: Vec<u8>) -> Resolved {
        Resolved {
            dir,
            name,
            ns_path: None,
            mount_flags: 0,
            fstype: FsType::Ext4,
            mount_root: false,
            mount_id: 0,
        }
    }
}

/// The guest's view of the filesystem.
pub struct Fs {
    /// The rootfs: the host directory of the initial namespace's root
    /// mount, fwe's own descriptor of it.
    root: OwnedFd,
    /// Its host path.
    root_host: Vec<u8>,
    /// The mount namespace.
    mnt: Arc<Ns>,
    /// The process's root, a path in the namespace's view.
    proc_root: Vec<u8>,
    /// Current working directory, a normalized absolute path from the
    /// process's root.
    cwd: Vec<u8>,
    umask: u32,
    proc: crate::procfs::ProcInfo,
    /// The process's other namespaces.
    pub ns: crate::ns::Namespaces,
}

impl Fs {
    /// Write the filesystem view into a fork snapshot. The root directory
    /// descriptor is inherited, so its number is enough.
    pub(crate) fn save(&self, e: &mut crate::snapshot::Enc) {
        use std::os::fd::AsRawFd;
        e.i32(self.root.as_raw_fd());
        e.bytes(&self.cwd);
        e.bytes(&self.root_host);
        e.bytes(self.mnt.dir());
        e.u64(self.mnt.id());
        e.bytes(&self.proc_root);
        e.u32(self.umask);
        e.bytes(&self.proc.exe);
        e.bytes(&self.proc.cmdline);
        e.u32(self.proc.ncpu);
        e.bytes(&self.proc.hostname);
        // Inherited like the root's.
        e.i32(self.proc.exe_fd.unwrap_or(-1));
        self.ns.save(e);
    }

    /// The filesystem view [`Fs::save`] wrote, in a fork child.
    pub(crate) fn restore(d: &mut crate::snapshot::Dec) -> Fs {
        use std::os::fd::FromRawFd;
        let fd = d.i32();
        // SAFETY: the parent's root descriptor, inherited at the same number
        // and owned by nothing else in this process.
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        let cwd = d.bytes();
        let root_host = d.bytes();
        let (dir, id) = (d.bytes(), d.u64());
        let mnt = match Ns::join(&dir, id) {
            Ok(ns) => Arc::new(ns),
            // The parent is in it, so it exists; failing that, the rootfs's.
            Err(_) => Arc::new(
                Ns::initial(&root_host, shm::dir_path(&root_host).ok().as_deref())
                    .expect("the initial mount namespace"),
            ),
        };
        Fs {
            root,
            cwd,
            root_host,
            mnt,
            proc_root: d.bytes(),
            umask: d.u32(),
            proc: crate::procfs::ProcInfo {
                exe: d.bytes(),
                cmdline: d.bytes(),
                ncpu: d.u32(),
                hostname: d.bytes(),
                exe_fd: Some(d.i32()).filter(|&fd| fd >= 0),
            },
            ns: crate::ns::Namespaces::load(d).unwrap_or_default(),
        }
    }

    /// Record the mount namespace and the process's root, for an `execve`
    /// that re-executes fwe ([`crate::Kernel::exec_state`]).
    pub(crate) fn save_view(&self, e: &mut crate::snapshot::Enc) {
        e.bytes(self.mnt.dir());
        e.u64(self.mnt.id());
        e.bytes(&self.proc_root);
        self.ns.save(e);
    }

    pub(crate) fn skip_view(d: &mut crate::snapshot::Dec) {
        let _ = (d.bytes(), d.u64(), d.bytes());
        let _ = crate::ns::Namespaces::load(d);
    }

    /// Take the mount namespace and root an exec state records, in a
    /// process fwe re-executed for a guest `execve`, before anything is
    /// looked up in them. A state with no view leaves the initial one.
    pub fn adopt_exec_view(&mut self, state: &[u8]) -> Result<(), String> {
        let mut d = crate::snapshot::Dec::new(state);
        if d.u64() != crate::EXEC_STATE_MAGIC {
            return Err("the exec state is not fwe's".into());
        }
        if !d.bool() {
            return Ok(());
        }
        let (dir, id, root) = (d.bytes(), d.u64(), d.bytes());
        if dir != self.mnt.dir() {
            let ns = Ns::join(&dir, id)
                .map_err(|e| format!("joining the mount namespace: errno {e}"))?;
            self.mnt = Arc::new(ns);
        }
        self.proc_root = root;
        self.ns = crate::ns::Namespaces::load(&mut d)
            .map_err(|e| format!("joining the namespaces: errno {e}"))?;
        self.republish();
        Ok(())
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
        let shm = shm::dir_path(&root_host).ok();
        let mnt = Arc::new(Ns::initial(&root_host, shm.as_deref())?);
        Ok(Fs {
            root,
            cwd: b"/".to_vec(),
            root_host,
            mnt,
            proc_root: b"/".to_vec(),
            umask: 0o022,
            proc: crate::procfs::ProcInfo::default(),
            ns: crate::ns::Namespaces::default(),
        })
    }

    /// Set the per-process information the synthetic `/proc` files draw on.
    /// Record what `/proc/self` reports. A relative `exe` is taken against
    /// the guest's working directory: `/proc/self/exe` is always absolute.
    pub fn set_proc_info(&mut self, exe: Vec<u8>, cmdline: Vec<u8>, ncpu: u32, hostname: Vec<u8>) {
        let exe = if exe.starts_with(b"/") { exe } else { normalize(&self.cwd, &exe) };
        let exe_fd = self.proc.exe_fd;
        self.proc = crate::procfs::ProcInfo { exe, cmdline, ncpu, hostname, exe_fd };
    }

    /// Hold `fd` (fwe's, in the reserved range) as the running program's
    /// file, for a program with no path; `None` for one that has a path.
    /// The descriptor held before is closed.
    pub fn set_exe_fd(&mut self, fd: Option<i32>) {
        if let Some(old) = self.proc.exe_fd
            && Some(old) != fd
        {
            // SAFETY: closing fwe's own descriptor of the old program.
            unsafe { libc::close(old) };
        }
        self.proc.exe_fd = fd;
    }

    /// What `/proc/self/exe` names when the program has no path (see
    /// [`set_exe_fd`](Self::set_exe_fd)).
    pub fn exe_fd_target(&self) -> Option<Vec<u8>> {
        self.proc.exe_fd.map(|fd| self.fd_target(fd))
    }

    /// The descriptor `path` reaches when it names an open file that has no
    /// path of its own (`/dev/fd/N` or `/proc/self/fd/N` of a memfd, or
    /// `/proc/self/exe` of a program run from one), which is then read and
    /// executed through the descriptor.
    pub fn pathless_fd(&self, path: &[u8]) -> Option<i32> {
        match self.synthetic(fcntl::AT_FDCWD as i32, path)? {
            crate::procfs::Entry::Fd { fd, target } if !has_path(fd, &target) => Some(fd),
            _ => None,
        }
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

    /// The mount namespace.
    pub fn mount_ns(&self) -> &Arc<Ns> {
        &self.mnt
    }

    /// The mount table as it is now.
    pub fn mounts(&self) -> Arc<Table> {
        self.mnt.table()
    }

    /// Move to the mount namespace `ns` (`unshare`, `setns`), keeping the
    /// root and working directory at the same paths.
    pub fn set_mount_ns(&mut self, ns: Arc<Ns>) {
        self.mnt = ns;
        self.republish();
    }

    /// The process's root, a path in the namespace's view.
    pub fn proc_root(&self) -> &[u8] {
        &self.proc_root
    }

    /// Make the namespace path `root` the process's root (`chroot`), or
    /// keep it while the namespace's root moved (`pivot_root`), with the
    /// working directory `cwd` from it.
    pub fn set_root(&mut self, root: Vec<u8>, cwd: Vec<u8>) {
        self.proc_root = root;
        self.cwd = cwd;
        self.republish();
    }

    /// The namespace path of `path`, an absolute guest path.
    pub fn to_ns(&self, path: &[u8]) -> Vec<u8> {
        to_ns(&self.proc_root, path)
    }

    /// The guest path of the namespace path `ns`, if it is under the
    /// process's root.
    pub fn from_ns(&self, ns: &[u8]) -> Option<Vec<u8>> {
        from_ns(&self.proc_root, ns)
    }

    /// The mount the absolute guest path `path` is in (taken lexically),
    /// and the path inside its filesystem.
    pub fn mount_of(&self, path: &[u8]) -> (Mount, Vec<u8>) {
        let table = self.mnt.table();
        let (m, rest) = table.locate(&self.to_ns(path));
        let fs_path = m.fs_path(&rest);
        (m.clone(), fs_path)
    }

    /// A synthetic `/proc` or `/sys` entry for `path`, if it names one. Only
    /// absolute paths and `AT_FDCWD`-relative paths are considered.
    pub fn synthetic(&self, dirfd: i32, path: &[u8]) -> Option<crate::procfs::Entry> {
        let absolute = self.absolute(dirfd, path)?;
        let (m, fs_path) = self.mount_of(&absolute);
        let absolute = match m.fstype {
            FsType::Proc => mounts::join(b"/proc", &fs_path),
            FsType::Sysfs => mounts::join(b"/sys", &fs_path),
            FsType::Devpts | FsType::Mqueue => {
                // Directories of their own, empty until fwe fills them.
                return Some(if fs_path == b"/" {
                    crate::procfs::Entry::Dir
                } else {
                    crate::procfs::Entry::Missing
                });
            }
            _ if is_rootfs(&m, &self.root_host) => {
                if let Some(target) = dev_link(&fs_path) {
                    return Some(crate::procfs::Entry::Symlink(target));
                }
                [b"/proc/self/fd/", fs_path.strip_prefix(b"/dev/fd/")?].concat()
            }
            _ => return None,
        };
        if let Some(kind) = absolute.strip_prefix(b"/proc/self/ns/") {
            return Some(match self.ns.link(kind, self.mnt.id()) {
                Some(link) => crate::procfs::Entry::Symlink(link),
                None => crate::procfs::Entry::Missing,
            });
        }
        match &absolute[..] {
            b"/proc/sys/kernel/hostname" => {
                return Some(crate::procfs::Entry::File([&self.ns.hostname()[..], b"\n"].concat()));
            }
            b"/proc/sys/kernel/domainname" => {
                return Some(crate::procfs::Entry::File(
                    [&self.ns.domainname()[..], b"\n"].concat(),
                ));
            }
            b"/proc/self/mountinfo" => {
                return Some(crate::procfs::Entry::File(self.mounts().mountinfo(&self.proc_root)));
            }
            b"/proc/self/mounts" => {
                return Some(crate::procfs::Entry::File(
                    self.mounts().mounts_file(&self.proc_root),
                ));
            }
            b"/proc/mounts" => return Some(crate::procfs::Entry::Symlink(b"self/mounts".to_vec())),
            _ => {}
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
        if let Some(name) = crate::memfd::name(fd) {
            return [&b"/memfd:"[..], &name, b" (deleted)"].concat();
        }
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
            Some(host) => self.host_to_guest(&host).unwrap_or(host),
            // A kqueue (an epoll descriptor) has neither path nor type.
            None => b"anon_inode:[eventpoll]".to_vec(),
        }
    }

    /// Whether `path` names `/proc/self/fd`, whose listing is the open
    /// descriptors.
    pub fn lists_fds(&self, dirfd: i32, path: &[u8]) -> bool {
        self.synthetic_path(dirfd, path).as_deref() == Some(b"/proc/self/fd")
    }

    /// The path in fwe's synthetic tree (`/proc/...`, `/sys/...`) that
    /// `path` names, if it is in a `proc` or `sysfs` mount.
    fn synthetic_path(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        let absolute = self.absolute(dirfd, path)?;
        let (m, fs_path) = self.mount_of(&absolute);
        match m.fstype {
            FsType::Proc => Some(mounts::join(b"/proc", &fs_path)),
            FsType::Sysfs => Some(mounts::join(b"/sys", &fs_path)),
            _ => None,
        }
    }

    /// The entries of a synthetic `/proc` or `/sys` directory `path`, if it is
    /// one. Normalizes like [`synthetic`](Self::synthetic).
    pub fn synth_children(&self, dirfd: i32, path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
        let Some(absolute) = self.synthetic_path(dirfd, path) else {
            // The directories of the filesystems fwe has nothing in yet.
            let absolute = self.absolute(dirfd, path)?;
            let (m, fs_path) = self.mount_of(&absolute);
            return match m.fstype {
                FsType::Devpts | FsType::Mqueue if fs_path == b"/" => Some(vec![
                    (b".".to_vec(), crate::procfs::DT_DIR),
                    (b"..".to_vec(), crate::procfs::DT_DIR),
                ]),
                _ => None,
            };
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
        resolve_in(&self.view(), dirfd, path, follow_final)
    }

    fn view(&self) -> View<'_> {
        View {
            root: self.root.as_raw_fd(),
            root_host: &self.root_host,
            ns: &self.mnt,
            proc_root: &self.proc_root,
            cwd: &self.cwd,
        }
    }

    /// Resolve and read a whole file under the root (following symlinks).
    /// Used to load the dynamic linker named by a guest executable.
    pub fn read(&self, path: &[u8]) -> Result<Vec<u8>, i32> {
        if let Some(entry) = self.synthetic(fcntl::AT_FDCWD as i32, path) {
            use crate::procfs::Entry;
            return match entry {
                Entry::File(data) => Ok(data),
                Entry::Fd { fd, target } if !has_path(fd, &target) => read_all(fd),
                Entry::Fd { target: t, .. } | Entry::Symlink(t) if t.starts_with(b"/") => {
                    self.read(&t)
                }
                Entry::Dir => Err(errno::EISDIR),
                _ => Err(errno::ENOENT),
            };
        }
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
            ns: self.mnt.clone(),
            proc_root: self.proc_root.clone(),
            cwd: self.cwd.clone(),
        });
    }

    /// Bring the published view's working directory up to date, if this is
    /// the published view.
    fn republish(&self) {
        if let Some(v) = published().as_mut().filter(|v| v.root == self.root.as_raw_fd()) {
            v.cwd = self.cwd.clone();
            v.ns = self.mnt.clone();
            v.proc_root = self.proc_root.clone();
        }
    }

    /// Translate a host path to the guest path it is reached by, through
    /// the mounts the process can see.
    pub fn host_to_guest(&self, host: &[u8]) -> Option<Vec<u8>> {
        let ns = host_to_ns(&self.mnt.table(), host)?;
        self.from_ns(&ns)
    }

    /// The namespace path of the directory `fd` is open on, if fwe can tell.
    pub fn ns_path_of_fd(&self, fd: i32) -> Option<Vec<u8>> {
        host_to_ns(&self.mnt.table(), &fd_path(fd)?)
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
        let guest = resolved.ns_path.as_deref().and_then(|ns| self.from_ns(ns));
        self.cwd = match guest {
            Some(g) => g,
            None => {
                let absolute = if path.first() == Some(&b'/') {
                    path.to_vec()
                } else {
                    normalize(&self.cwd, path)
                };
                normalize(&absolute, b"")
            }
        };
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

/// What resolution works in: the rootfs, the mount namespace, and the
/// process's root and working directory.
struct View<'a> {
    /// fwe's descriptor of the rootfs.
    root: i32,
    root_host: &'a [u8],
    ns: &'a Ns,
    proc_root: &'a [u8],
    cwd: &'a [u8],
}

/// The namespace path of the absolute guest path `path`, for a process
/// whose root is `proc_root`.
fn to_ns(proc_root: &[u8], path: &[u8]) -> Vec<u8> {
    mounts::join(proc_root, &normalize(b"/", path))
}

/// The guest path of the namespace path `ns`, if it is under `proc_root`.
fn from_ns(proc_root: &[u8], ns: &[u8]) -> Option<Vec<u8>> {
    let rest = mounts::under(ns, proc_root)?;
    Some(if rest.is_empty() { b"/".to_vec() } else { rest.to_vec() })
}

/// Whether `m` is the rootfs itself, where fwe supplies the standard
/// `/dev` entries the host's own nodes stand in for.
fn is_rootfs(m: &Mount, root_host: &[u8]) -> bool {
    m.source == Source::Host(root_host.to_vec()) && m.root == b"/"
}

/// The namespace path the host path `host` is reached by: through the
/// deepest host-backed mount showing it that resolution enters.
fn host_to_ns(table: &Table, host: &[u8]) -> Option<Vec<u8>> {
    let mut best: Option<(usize, Vec<u8>)> = None;
    for m in &table.mounts {
        let Some(top) = m.host_path(b"") else { continue };
        let Some(rest) = mounts::under(host, &top) else { continue };
        let ns = mounts::join(&m.point, rest);
        if table.locate(&ns).0.id != m.id {
            // Covered by another mount there.
            continue;
        }
        if best.as_ref().is_none_or(|(len, _)| top.len() > *len) {
            best = Some((top.len(), ns));
        }
    }
    best.map(|(_, ns)| ns)
}

/// Open the directory at `rest` (a path inside the mount, from its root)
/// of the host-backed mount `m`; the rootfs through fwe's descriptor of
/// it, one component at a time, never following a link.
fn open_in_mount(v: &View, m: &Mount, rest: &[u8]) -> Result<OwnedFd, i32> {
    let Source::Host(base) = &m.source else { return Err(errno::ENOENT) };
    let mut dir = if base == v.root_host {
        let mut d = dup_cloexec(v.root)?;
        for comp in components(&m.root) {
            d = open_dir(d.as_raw_fd(), &cstr(&comp)?)?;
        }
        d
    } else {
        let top = cstr(&mounts::join(base, &m.root))?;
        // SAFETY: opening a host directory by path.
        let fd = unsafe {
            libc::open(top.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(e());
        }
        // SAFETY: `fd` is a fresh owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    for comp in components(rest) {
        dir = open_dir(dir.as_raw_fd(), &cstr(&comp)?)?;
    }
    Ok(dir)
}

/// One step's state in [`resolve_in`].
struct Here {
    dir: OwnedFd,
    /// The mount `dir` is in, and the namespace path of `dir`, when known.
    at: Option<(u32, Vec<u8>)>,
    /// `dir` stands in for a directory that does not exist but has a mount
    /// below it (a rootfs with no `/dev` still has `/dev/shm`): the nearest
    /// directory above it that does.
    phantom: bool,
}

/// Resolve `path` relative to `dirfd` in the view `v`: the work of
/// [`Fs::resolve`], also done for the socket calls that run without the
/// kernel lock ([`resolve_host`]).
fn resolve_in(v: &View, dirfd: i32, path: &[u8], follow_final: bool) -> Result<Resolved, i32> {
    let table = v.ns.table();
    let absolute = if path.first() == Some(&b'/') {
        Some(normalize(b"/", path))
    } else if dirfd as i64 == fcntl::AT_FDCWD {
        Some(normalize(v.cwd, path))
    } else {
        None
    };
    // The standard device nodes, in the rootfs's own /dev.
    let device = absolute.as_deref().and_then(|a| {
        let name = a.strip_prefix(b"/dev/").filter(|n| DEVICES.contains(n))?;
        let (m, _) = table.locate(&to_ns(v.proc_root, a));
        is_rootfs(m, v.root_host).then(|| name.to_vec())
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
        return Ok(Resolved::plain(unsafe { OwnedFd::from_raw_fd(dev) }, name));
    }
    let root_ns = v.proc_root.to_vec();
    // The directory with namespace path `ns`, entered from the root.
    let enter = |ns: &[u8]| -> Result<Here, i32> {
        let (m, rest) = table.locate(ns);
        if m.source == Source::Synthetic {
            return Err(errno::ENOENT);
        }
        match open_in_mount(v, m, &rest) {
            Ok(dir) => Ok(Here { dir, at: Some((m.id, ns.to_vec())), phantom: false }),
            Err(errno::ENOENT)
                if table.mounts.iter().any(|o| mounts::under(&o.point, ns).is_some()) =>
            {
                // A missing directory a mount hangs below: stand in the
                // nearest one above that exists.
                let mut up = ns.to_vec();
                loop {
                    let parent = normalize(&up, b"..");
                    let (pm, prest) = table.locate(&parent);
                    if let Ok(dir) = open_in_mount(v, pm, &prest) {
                        return Ok(Here { dir, at: Some((m.id, ns.to_vec())), phantom: true });
                    }
                    if parent == up {
                        return Err(errno::ENOENT);
                    }
                    up = parent;
                }
            }
            Err(e) => Err(e),
        }
    };
    let (mut here, path) = match (path.first() == Some(&b'/'), dirfd as i64 == fcntl::AT_FDCWD) {
        (true, _) => (enter(&root_ns)?, path.to_vec()),
        (false, true) => (enter(&to_ns(v.proc_root, v.cwd))?, path.to_vec()),
        _ => {
            // From a directory descriptor: where it is, when fwe can tell
            // and it is inside the process's root.
            let ns = fd_path(dirfd)
                .and_then(|h| host_to_ns(&table, &h))
                .filter(|ns| mounts::under(ns, &root_ns).is_some());
            let dir = dup_cloexec(dirfd)?;
            let at = ns.map(|ns| (table.locate(&ns).0.id, ns));
            (Here { dir, at, phantom: false }, path.to_vec())
        }
    };
    let mut ancestors: Vec<Here> = Vec::new();
    let mut pending = components(&path);
    pending.reverse();
    let mut symlinks = 0;
    // The resolution of the name `name` in `here`.
    let done = |here: Here, name: Vec<u8>, mount_root: bool| -> Result<Resolved, i32> {
        let (ns_path, mount) = match &here.at {
            Some((id, ns)) => {
                let p = if name == b"." { ns.clone() } else { mounts::join(ns, &name) };
                let m = if mount_root {
                    table.locate(&p).0.clone()
                } else {
                    table.get(*id).cloned().unwrap_or_else(|| table.root().clone())
                };
                (Some(p), Some(m))
            }
            None => (None, None),
        };
        if here.phantom {
            // Only the mounts below a missing directory are there.
            return Err(errno::ENOENT);
        }
        Ok(Resolved {
            dir: here.dir,
            name,
            ns_path,
            mount_flags: mount.as_ref().map_or(0, |m| m.flags),
            fstype: mount.as_ref().map_or(FsType::Ext4, |m| m.fstype),
            mount_id: mount.as_ref().map_or(0, |m| m.id),
            mount_root,
        })
    };

    while let Some(comp) = pending.pop() {
        if comp == b".." {
            match &here.at {
                // At the process's root `..` stays put.
                Some((_, ns)) if *ns == root_ns => {}
                Some((_, ns)) => {
                    let parent = normalize(ns, b"..");
                    here = match ancestors.pop() {
                        Some(a) => a,
                        None => enter(&parent)?,
                    };
                }
                None => {
                    // Somewhere fwe cannot place: up on the host, but never
                    // above the rootfs.
                    if !same_file(here.dir.as_raw_fd(), v.root) {
                        here.dir = open_dir(here.dir.as_raw_fd(), c"..")?;
                    }
                }
            }
            continue;
        }
        let is_last = pending.is_empty();
        // A mount attached here comes before what the directory holds.
        if let Some((mid, ns)) = &here.at {
            let child_ns = mounts::join(ns, &comp);
            if let Some(m) = table.child_at(*mid, &child_ns).cloned() {
                if m.source == Source::Synthetic {
                    // Served by `Fs::synthetic`, which the callers ask first.
                    return Err(errno::ENOENT);
                }
                let Some(host) = m.host_path(b"") else { return Err(errno::ENOENT) };
                let is_dir = std::fs::metadata(std::ffi::OsStr::from_bytes_compat(&host))
                    .is_ok_and(|md| md.is_dir());
                if !is_dir {
                    // A file bind mount: the host file itself.
                    if !is_last {
                        return Err(errno::ENOTDIR);
                    }
                    let (parent, name) = split_host(&host);
                    let dir = open_host_dir(&parent)?;
                    let mut r = done(Here { dir, at: None, phantom: false }, name, true)?;
                    r.ns_path = Some(child_ns.clone());
                    r.mount_flags = m.flags;
                    r.fstype = m.fstype;
                    r.mount_id = m.id;
                    return Ok(r);
                }
                let dir = open_in_mount(v, &m, b"")?;
                let next = Here { dir, at: Some((m.id, child_ns)), phantom: false };
                if is_last {
                    return done(next, b".".to_vec(), true);
                }
                ancestors.push(std::mem::replace(&mut here, next));
                continue;
            }
        }
        if is_last && !follow_final {
            return done(here, comp, false);
        }
        let comp_c = cstr(&comp)?;
        let looked = if here.phantom {
            Err(errno::ENOENT)
        } else {
            readlink_at(here.dir.as_raw_fd(), &comp_c)
        };
        match looked {
            Ok(target) => {
                symlinks += 1;
                if symlinks > MAX_SYMLINKS {
                    return Err(errno::ELOOP);
                }
                if target.first() == Some(&b'/') {
                    here = enter(&root_ns)?;
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
                    return done(here, comp, false);
                }
                let child = open_dir(here.dir.as_raw_fd(), &comp_c)?;
                let at = here.at.as_ref().map(|(id, ns)| (*id, mounts::join(ns, &comp)));
                ancestors
                    .push(std::mem::replace(&mut here, Here { dir: child, at, phantom: false }));
            }
            Err(errno::ENOENT) => {
                let below = here.at.as_ref().map(|(_, ns)| mounts::join(ns, &comp)).filter(|p| {
                    table
                        .mounts
                        .iter()
                        .any(|o| mounts::under(&o.point, p).is_some_and(|r| !r.is_empty()))
                });
                if let Some(p) = below {
                    // Missing, but a mount hangs below it.
                    let at = Some((here.at.as_ref().unwrap().0, p));
                    let dir = dup_cloexec(here.dir.as_raw_fd())?;
                    ancestors.push(std::mem::replace(&mut here, Here { dir, at, phantom: true }));
                    continue;
                }
                if is_last {
                    return done(here, comp, false);
                }
                return Err(errno::ENOENT);
            }
            Err(other) => return Err(other),
        }
    }
    done(here, b".".to_vec(), false)
}

/// A host path's directory and final name.
fn split_host(host: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match host.iter().rposition(|&b| b == b'/') {
        Some(0) => (b"/".to_vec(), host[1..].to_vec()),
        Some(i) => (host[..i].to_vec(), host[i + 1..].to_vec()),
        None => (b".".to_vec(), host.to_vec()),
    }
}

fn open_host_dir(path: &[u8]) -> Result<OwnedFd, i32> {
    let p = cstr(path)?;
    // SAFETY: opening a host directory by path.
    let fd =
        unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(e());
    }
    // SAFETY: `fd` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `OsStr::from_bytes`, for the Unix hosts fwe builds on.
trait FromBytesCompat {
    fn from_bytes_compat(b: &[u8]) -> &std::ffi::OsStr;
}

impl FromBytesCompat for std::ffi::OsStr {
    fn from_bytes_compat(b: &[u8]) -> &std::ffi::OsStr {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b)
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
    ns: Arc<Ns>,
    proc_root: Vec<u8>,
    cwd: Vec<u8>,
}

impl Published {
    fn view(&self) -> View<'_> {
        View {
            root: self.root,
            root_host: &self.root_host,
            ns: &self.ns,
            proc_root: &self.proc_root,
            cwd: &self.cwd,
        }
    }
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
    let r = resolve_in(&v.view(), fcntl::AT_FDCWD as i32, path, follow_final)?;
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
        Some(v) => from_ns(&v.proc_root, &host_to_ns(&v.ns.table(), host)?),
        None => Some(host.to_vec()),
    }
}

/// `/dev/shm`: Linux mounts a tmpfs there that every process on the
/// machine shares. fwe keeps one directory for it per rootfs (the host's
/// `/` included), private to the user, shared by every fwe process that
/// runs on that root: `fwe-<uid>/shm-<hash of the root's host path>` in the
/// user's temporary directory. Unlike a tmpfs it outlives the processes,
/// until the host clears its temporary files.
/// Whether `target`, what `/proc/self/fd/<fd>` links to, is a path the
/// file can be opened by again; otherwise opening the link duplicates the
/// descriptor (a pipe, a socket, a memfd).
pub(crate) fn has_path(fd: i32, target: &[u8]) -> bool {
    target.starts_with(b"/") && crate::memfd::name(fd).is_none()
}

/// The whole contents of the file `fd` is open on, from its start whatever
/// its offset.
fn read_all(fd: i32) -> Result<Vec<u8>, i32> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        // SAFETY: reading into a valid local buffer.
        let n = unsafe {
            libc::pread(fd, chunk.as_mut_ptr().cast(), chunk.len(), data.len() as libc::off_t)
        };
        if n < 0 {
            return Err(e());
        }
        if n == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&chunk[..n as usize]);
    }
}

pub(crate) mod shm {
    use super::{OwnedFd, e, fd_path};
    use fwe_abi::errno;
    use std::os::fd::{AsRawFd, FromRawFd};

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

    /// fwe's private directory for this user (`fwe-<uid>` in the user's
    /// temporary directory), created on first use.
    pub(crate) fn user_dir() -> Result<Vec<u8>, i32> {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut base = user_temp();
        if base.last() != Some(&b'/') {
            base.push(b'/');
        }
        base.extend_from_slice(format!("fwe-{uid}").as_bytes());
        ensure_dir(&base, 0o700, true)?;
        Ok(base)
    }

    /// The host path of the directory for the root at `root_host`, created
    /// on first use: what the initial namespace mounts at `/dev/shm`.
    pub(crate) fn dir_path(root_host: &[u8]) -> Result<Vec<u8>, i32> {
        let mut base = user_dir()?;
        // FNV-1a: stable across processes and fwe builds.
        let hash = root_host
            .iter()
            .fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        base.extend_from_slice(format!("/shm-{hash:016x}").as_bytes());
        // Linux's `/dev/shm` is world-writable and sticky; this one is in a
        // directory only the user can enter.
        ensure_dir(&base, 0o1777, false)?;
        // Its canonical path, as the host reports a descriptor's.
        let p = c(&base)?;
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
        Ok(fd_path(fd.as_raw_fd()).unwrap_or(base))
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
        let shm_dir = open_host_dir(&shm::dir_path(&fs.root_host).unwrap()).unwrap();
        let is_shm = |fd: i32| same_file(fd, shm_dir.as_raw_fd());
        let at = fcntl::AT_FDCWD as i32;
        let top = fs.resolve(at, b"/dev/shm", true).unwrap();
        assert_eq!(top.name, b".");
        assert!(is_shm(top.dir.as_raw_fd()));
        assert!(!root.join("dev").exists());
        // A file created there is found by each way in, and not in the rootfs.
        let f = fs.resolve(at, b"/dev/shm/f", true).unwrap();
        assert!(is_shm(f.dir.as_raw_fd()));
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
            assert!(is_shm(r.dir.as_raw_fd()), "{}", String::from_utf8_lossy(path));
            assert_eq!(r.name, b"f");
        }
        fs.chdir(at, b"/dev/shm").unwrap();
        assert!(is_shm(fs.resolve(at, b"f", true).unwrap().dir.as_raw_fd()));
        // `..` from it, also relative to its descriptor, is the root's /dev,
        // which holds nothing else while the rootfs has none.
        assert_eq!(fs.resolve(top.dir.as_raw_fd(), b"../tmp", true).err(), Some(errno::ENOENT));
        assert_eq!(fs.resolve(at, b"/dev/tmp", true).err(), Some(errno::ENOENT));
        std::fs::create_dir_all(root.join("dev/marker")).unwrap();
        let dev = open_dir(fs.root.as_raw_fd(), c"dev").unwrap();
        for dir in [at, top.dir.as_raw_fd()] {
            let up = fs.resolve(dir, b"../marker", true).unwrap();
            assert!(same_file(up.dir.as_raw_fd(), dev.as_raw_fd()));
        }
        assert!(is_shm(fs.resolve(at, b"/dev/shm/f", true).unwrap().dir.as_raw_fd()));
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
