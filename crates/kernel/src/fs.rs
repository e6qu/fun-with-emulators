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
use crate::overlay::{self, Layers};
use fwe_abi::{errno, fcntl};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

/// Maximum symlinks followed while resolving one path.
const MAX_SYMLINKS: u32 = 40;

/// The device nodes every Linux system has in `/dev`, which the guest finds
/// there whatever the rootfs holds: they are the host's own nodes (a rootfs
/// unpacked without privileges has none, and Linux mounts `/dev` over it).
/// The loop devices' nodes are there too ([`crate::loopdev::node_named`]).
const DEVICES: &[&[u8]] = &[b"null", b"zero", b"full", b"random", b"urandom", b"tty"];

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
    /// Where it is in an overlay, when it is in one.
    pub ovl: Option<Ovl>,
    /// What [`Resolved::prepare`] set up for a file being made in an
    /// overlay, which [`Resolved::finish`] puts in place.
    created: Option<overlay::Created>,
}

/// Where a resolved name is in an overlay mount ([`crate::overlay`]).
pub struct Ovl {
    pub layers: Arc<Layers>,
    /// The overlay path of the directory holding the name (of the
    /// directory itself, for `.`).
    pub parent: Vec<u8>,
    /// What the name is there.
    pub found: overlay::Found,
}

impl Ovl {
    /// The overlay path of what was resolved.
    pub fn path(&self, name: &[u8]) -> Vec<u8> {
        if name == b"." { self.parent.clone() } else { mounts::join(&self.parent, name) }
    }
}

/// How a call is about to change what it resolved ([`Resolved::prepare`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Make it (it is missing).
    Create,
    /// Change the file that is there: its data or its metadata.
    Modify,
    /// Remove or rename it, which an overlay does its own way
    /// ([`crate::overlay::remove`], [`crate::overlay::rename`]): nothing
    /// to prepare but the check of the mount.
    Remove,
}

impl Resolved {
    pub fn name_c(&self) -> Result<CString, i32> {
        cstr(&self.name)
    }

    /// `EROFS` when the mount is read-only.
    pub fn writable(&self) -> Result<(), i32> {
        if self.mount_flags & mounts::ms::RDONLY != 0 { Err(errno::EROFS) } else { Ok(()) }
    }

    /// Get ready for a call that is about to change what was resolved, as
    /// `how` says: `EROFS` on a read-only mount; in an overlay, the copy-up
    /// that puts it (or, to make it, its directory) in the upper layer,
    /// after which [`dir`](Self::dir) and [`name`](Self::name) are where the
    /// call acts. A call that makes a file calls [`finish`](Self::finish)
    /// once it has.
    pub fn prepare(&mut self, how: Change) -> Result<(), i32> {
        self.writable()?;
        let Some(o) = &self.ovl else { return Ok(()) };
        let upper = o.layers.upper.is_some();
        let dir = match (&o.found, how) {
            (_, Change::Modify) if self.name == b"." => overlay::upper_dir(&o.layers, &o.parent)?,
            // Nothing there to change, or already in the upper layer.
            (overlay::Found::Missing, Change::Modify) => return Ok(()),
            (overlay::Found::Other { layer: 0, .. }, _) if upper => return Ok(()),
            (overlay::Found::Dir(d), _) if upper && d.fds[0].is_some() => return Ok(()),
            (overlay::Found::Missing, Change::Create) => {
                let made = overlay::create(&o.layers, &o.parent, &self.name)?;
                let (dir, name) = made.target();
                self.dir = dup_cloexec(dir)?;
                self.name = name.to_bytes().to_vec();
                self.created = Some(made);
                return Ok(());
            }
            // Made already: the call fails as it would anywhere.
            (_, Change::Create) | (_, Change::Remove) => return Ok(()),
            (_, Change::Modify) => overlay::copy_up(&o.layers, &o.path(&self.name))?,
        };
        self.dir = dup_cloexec(dir.as_raw_fd())?;
        Ok(())
    }

    /// Get ready for a `bind` to make a socket's node at what was
    /// resolved: in an overlay, the directory copied up, and a whiteout in
    /// the way removed (the host makes the node where `bind` says, so it
    /// cannot be made aside and moved over the whiteout).
    pub fn prepare_bind(&mut self) -> Result<(), i32> {
        let Some(o) = &self.ovl else { return Ok(()) };
        if !matches!(o.found, overlay::Found::Missing) {
            return Ok(());
        }
        self.writable()?;
        let made = overlay::create(&o.layers, &o.parent, &self.name)?;
        if let Some((_, _)) = &made.temp {
            // SAFETY: a NUL-terminated name in a live directory.
            if unsafe { libc::unlinkat(made.dir.as_raw_fd(), made.name.as_ptr(), 0) } != 0 {
                return Err(e());
            }
        }
        self.dir = dup_cloexec(made.dir.as_raw_fd())?;
        Ok(())
    }

    /// Put a file made after [`prepare`](Self::prepare) with
    /// [`Change::Create`] in place (`made`), or clear up after a call that
    /// failed to make it.
    pub fn finish(&mut self, made: bool) -> Result<(), i32> {
        match self.created.take() {
            Some(c) => {
                let r = c.finish(made);
                self.dir = dup_cloexec(c.dir.as_raw_fd())?;
                self.name = c.name.to_bytes().to_vec();
                r
            }
            None => Ok(()),
        }
    }

    fn plain(dir: OwnedFd, name: Vec<u8>) -> Resolved {
        Resolved {
            dir: out_of_reach(dir),
            name,
            ns_path: None,
            mount_flags: 0,
            fstype: FsType::Ext4,
            mount_root: false,
            mount_id: 0,
            ovl: None,
            created: None,
        }
    }
}

thread_local! {
    /// This thread is looking up an unmount's target, which is no use of
    /// the mount ([`Fs::resolve`], `MNT_EXPIRE`).
    pub static UNMOUNTING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
    /// The mount it was entered through (0 when not known), which it stays
    /// in when another is mounted over it, as on Linux.
    cwd_mount: u32,
    /// Where the working directory is when a `chroot` left it outside the
    /// root (a path in the namespace's view): `getcwd` reports it
    /// unreachable, as Linux does, until the next `chdir`.
    cwd_outside: Option<Vec<u8>>,
    /// The mount the root was set in (0 when not known), which it stays in
    /// when another is mounted over it.
    root_mount: u32,
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
        e.u32(self.cwd_mount);
        e.u32(self.root_mount);
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
        e.bytes(&self.proc.auxv);
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
        let cwd_mount = d.u32();
        let root_mount = d.u32();
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
            cwd_mount,
            cwd_outside: None,
            root_mount,
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
                auxv: d.bytes(),
            },
            ns: {
                let ns = crate::ns::Namespaces::load(d).unwrap_or_default();
                ns.activate();
                ns
            },
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
        self.ns.activate();
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
            cwd_mount: 0,
            cwd_outside: None,
            root_mount: 0,
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
        // The program's own path, not the links it was run through (such as
        // `/proc/self/exe`).
        let exe = if self.proc.exe_fd.is_some() { exe } else { self.program_path(&exe) };
        let exe_fd = self.proc.exe_fd;
        let auxv = std::mem::take(&mut self.proc.auxv);
        crate::procreg::own_program(&exe, &cmdline);
        // The program's file, for `/proc/self/maps`: through the descriptor
        // it was run by, if it has no path.
        let id = match exe_fd {
            Some(fd) => crate::fsops::linux_fstat(fd).ok().map(|st| (st.st_dev, st.st_ino)),
            None => self.file_id(&exe),
        };
        crate::maps::record().set_exe(exe.clone(), id.unwrap_or((0, 0)));
        // The program's file is busy while it runs (`ETXTBSY`).
        let host_id = match exe_fd {
            Some(fd) => crate::fsops::host_identity(fd),
            None => self.file_id(&exe),
        };
        if let Some((dev, ino)) = host_id {
            crate::textbusy::running(dev, ino);
        }
        crate::maps::publish();
        self.proc = crate::procfs::ProcInfo { exe, cmdline, ncpu, hostname, exe_fd, auxv };
    }

    /// The running program started with the auxiliary vector `auxv` (its
    /// words, `AT_NULL` included), which `/proc/self/auxv` shows.
    pub fn set_auxv(&mut self, auxv: Vec<u8>) {
        self.proc.auxv = auxv;
    }

    /// The guest path of the file `path` names, its links followed (`path`
    /// itself if that cannot be found).
    pub fn program_path(&self, path: &[u8]) -> Vec<u8> {
        let mut p = path.to_vec();
        for _ in 0..40 {
            use crate::procfs::Entry;
            match self.synthetic(fcntl::AT_FDCWD as i32, &p) {
                Some(Entry::Symlink(t)) if t.starts_with(b"/") => p = t,
                Some(Entry::Fd { fd, .. }) => return self.fd_target(fd),
                Some(_) => return p,
                None => break,
            }
        }
        let Ok(r) = self.resolve(fcntl::AT_FDCWD as i32, &p, true) else { return p };
        let Ok(name) = r.name_c() else { return p };
        // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd.
        let fd = unsafe {
            libc::openat(r.dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return p;
        }
        // SAFETY: `fd` is a fresh owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        self.fd_target(fd.as_raw_fd())
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

    /// The descriptor `path` reaches when it names an open file through
    /// one (`/dev/fd/N` or `/proc/self/fd/N`, or `/proc/self/exe` of a
    /// program run that way), which is then read and executed through the
    /// descriptor, as Linux runs the open file whatever has become of its
    /// path.
    pub fn exec_fd(&self, path: &[u8]) -> Option<i32> {
        match self.synthetic(fcntl::AT_FDCWD as i32, path)? {
            crate::procfs::Entry::Fd { fd, .. } => Some(fd),
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

    /// The directories of the shared records of the process's namespaces,
    /// for its record ([`crate::procreg`]).
    pub fn ns_dirs(&self) -> Vec<Vec<u8>> {
        let mut d = vec![self.mnt.dir().to_vec()];
        d.extend(self.ns.dirs());
        d
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

    /// The mounts the root and the working directory are in now (0: not
    /// known), as `chroot`, `pivot_root` and `setns` leave them.
    pub fn set_mounts(&mut self, root: u32, cwd: u32) {
        self.root_mount = root;
        self.cwd_mount = cwd;
    }

    /// The mount the working directory is in, if fwe knows it.
    pub fn cwd_mount(&self) -> Option<u32> {
        (self.cwd_mount != 0).then_some(self.cwd_mount)
    }

    /// The mount the root is in, if fwe knows it.
    pub fn root_mount(&self) -> Option<u32> {
        (self.root_mount != 0).then_some(self.root_mount)
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

    /// Where the synthetic link `path` (relative to `dirfd`) to `target`
    /// leads: `target` itself if absolute, else from the link's directory.
    pub fn link_target(&self, dirfd: i32, path: &[u8], target: &[u8]) -> Vec<u8> {
        if target.first() == Some(&b'/') {
            return target.to_vec();
        }
        let link = self.absolute(dirfd, path).unwrap_or_else(|| path.to_vec());
        normalize(&normalize(&link, b".."), target)
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
    /// As [`synthetic`](Self::synthetic), following a symbolic link of the
    /// host's that `path` ends in (`/etc/mtab` to `/proc/self/mounts`, say):
    /// what the link leads to, if that is fwe's.
    pub fn synthetic_followed(&self, dirfd: i32, path: &[u8]) -> Option<crate::procfs::Entry> {
        if let Some(e) = self.synthetic(dirfd, path) {
            return Some(e);
        }
        self.synthetic(fcntl::AT_FDCWD as i32, &self.synthetic_target(dirfd, path)?)
    }

    /// The path in fwe's `/proc` or `/sys` that the host's symbolic link
    /// `path` ends in leads to (through further links of the host's), if
    /// it leads there.
    pub fn synthetic_target(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        let mut at = self.absolute(dirfd, path)?;
        for _ in 0..40 {
            let r = self.resolve(fcntl::AT_FDCWD as i32, &at, false).ok()?;
            let name = std::ffi::CString::new(r.name.clone()).ok()?;
            let mut target = vec![0u8; crate::uaccess::PATH_MAX];
            // SAFETY: a NUL-terminated name in an open directory, and a
            // buffer of its length; not a link, it fails (EINVAL).
            let n = unsafe {
                libc::readlinkat(
                    r.dir.as_raw_fd(),
                    name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if n <= 0 {
                return None;
            }
            target.truncate(n as usize);
            at = if target.starts_with(b"/") {
                target
            } else {
                mounts::join(&normalize(&at, b".."), &target)
            };
            if self.synthetic(fcntl::AT_FDCWD as i32, &at).is_some() {
                return Some(at);
            }
        }
        None
    }

    pub fn synthetic(&self, dirfd: i32, path: &[u8]) -> Option<crate::procfs::Entry> {
        if path.is_empty() {
            // Names nothing (`AT_EMPTY_PATH` is the callers' to handle).
            return None;
        }
        let absolute = self.absolute(dirfd, path)?;
        let (m, fs_path) = self.mount_of(&absolute);
        let absolute = match m.fstype {
            FsType::Proc => mounts::join(b"/proc", &fs_path),
            FsType::Sysfs => mounts::join(b"/sys", &fs_path),
            FsType::Devpts | FsType::Mqueue => {
                // Directories of their own: the message queues' holds a file
                // of each queue's, which reads as its status line.
                let queue = fs_path.strip_prefix(b"/").filter(|_| m.fstype == FsType::Mqueue);
                return Some(if fs_path == b"/" {
                    crate::procfs::Entry::Dir
                } else if let Some(status) = queue.and_then(crate::mqueue::status_of) {
                    crate::procfs::Entry::File(status)
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
        // /proc/<pid>: the reader's own is /proc/self; another, what fwe
        // knows of it.
        let absolute = match own_or_other(&absolute) {
            Ok(a) => a,
            Err((host, pid, sub)) => {
                return Some(match host {
                    Some(h) if sub == b"/fd" => match crate::procreg::read(h) {
                        Some(_) => crate::procfs::Entry::Dir,
                        None => crate::procfs::Entry::Missing,
                    },
                    Some(h) if sub.starts_with(b"/fd/") => self.other_fd(h, &sub[4..]),
                    Some(h) => crate::procpid::entry(h, pid, &sub),
                    None => crate::procfs::Entry::Missing,
                });
            }
        };
        // A path through one of the process's magic links is the
        // resolver's to follow, out of `/proc`.
        if let Some(rel) = absolute.strip_prefix(b"/proc/")
            && let Some((link, rest)) = through_magic_link(rel)
        {
            // What the link leads to, if fwe knows its path, is asked
            // again; else the resolver follows the descriptor itself.
            let base = match link {
                MagicLink::Cwd => self.cwd.clone(),
                MagicLink::Root => b"/".to_vec(),
                MagicLink::Fd(fd) => self.fd_target(fd),
            };
            if !base.starts_with(b"/") {
                return None;
            }
            return self.synthetic(fcntl::AT_FDCWD as i32, &mounts::join(&base, &rest));
        }
        match &absolute[..] {
            b"/proc/self/cwd" => return Some(crate::procfs::Entry::Symlink(self.cwd.clone())),
            b"/proc/self/root" => return Some(crate::procfs::Entry::Symlink(b"/".to_vec())),
            _ => {}
        }
        if let Some(kind) = absolute.strip_prefix(b"/proc/self/ns/") {
            return Some(match self.ns.link(kind, self.mnt.id()) {
                Some(link) => crate::procfs::Entry::Symlink(link),
                None => crate::procfs::Entry::Missing,
            });
        }
        if absolute == b"/proc/self/task" {
            return Some(crate::procfs::Entry::Dir);
        }
        if absolute == b"/proc/self/maps" || absolute == b"/proc/self/smaps" {
            return Some(crate::procfs::Entry::File(self.maps(absolute.ends_with(b"/smaps"))));
        }
        // The calling process's IPC namespace's objects.
        if let Some(kind) = absolute.strip_prefix(b"/proc/sysvipc/") {
            use crate::sysvipc::Kind;
            let kind = match kind {
                b"shm" => Kind::Shm,
                b"sem" => Kind::Sem,
                b"msg" => Kind::Msg,
                _ => return Some(crate::procfs::Entry::Missing),
            };
            let r = self.ns.ipc.clone().or_else(crate::sysvipc::initial);
            return Some(crate::procfs::Entry::File(
                r.map_or_else(Vec::new, |r| crate::sysvipc::proc_listing(&r, kind)),
            ));
        }
        if let Some(rest) = absolute.strip_prefix(b"/proc/self/task/") {
            return Some(task_entry(rest));
        }
        match &absolute[..] {
            b"/proc/self/stat" => {
                let me = crate::thread::tgid();
                // SAFETY: getpid cannot fail.
                let host = unsafe { libc::getpid() };
                let comm = crate::procreg::read(host).map(|r| r.comm).unwrap_or_default();
                let h = crate::procpid::host_info(host).unwrap_or_default();
                return Some(crate::procfs::Entry::File(crate::procpid::stat_line(me, &comm, &h)));
            }
            // The kernel's view of the process fills it in (see
            // `Kernel::self_status`); its place is held here.
            b"/proc/self/status" => return Some(crate::procfs::Entry::File(Vec::new())),
            // Read and written by address (`crate::procmem`).
            b"/proc/self/mem" | b"/proc/self/pagemap" => {
                return Some(crate::procfs::Entry::File(Vec::new()));
            }
            b"/proc/self/coredump_filter" => {
                return Some(crate::procfs::Entry::File(crate::coredump::FILTER.to_vec()));
            }
            b"/proc/self/timerslack_ns" => {
                // SAFETY: getpid cannot fail.
                let (slack, _) = crate::procreg::slack(unsafe { libc::getpid() });
                return Some(crate::procfs::Entry::File(format!("{slack}\n").into_bytes()));
            }
            // The main thread's name, as the process's.
            b"/proc/self/comm" => {
                // SAFETY: getpid cannot fail.
                let host = unsafe { libc::getpid() };
                let comm = crate::procreg::read(host).map(|r| r.comm).unwrap_or_default();
                return Some(crate::procfs::Entry::File([&comm[..], b"\n"].concat()));
            }
            b"/proc/self/uid_map" | b"/proc/self/gid_map" | b"/proc/self/setgroups" => {
                if let Some(u) = &self.ns.user {
                    let n = u.get();
                    return Some(crate::procfs::Entry::File(match &absolute[..] {
                        b"/proc/self/uid_map" => crate::userns::show_map(&n.uid_map),
                        b"/proc/self/gid_map" => crate::userns::show_map(&n.gid_map),
                        _ => {
                            if n.setgroups_deny {
                                b"deny\n".to_vec()
                            } else {
                                b"allow\n".to_vec()
                            }
                        }
                    }));
                }
            }
            b"/proc/self/oom_score_adj" | b"/proc/self/oom_adj" | b"/proc/self/oom_score" => {
                let sub = &absolute[b"/proc/self".len()..];
                // SAFETY: getpid cannot fail.
                let adj = crate::procreg::oom_score_adj(unsafe { libc::getpid() });
                return Some(crate::procfs::Entry::File(crate::procpid::oom_file(sub, adj)));
            }
            b"/proc/self/cgroup" => {
                let root = self.ns.cgroup.as_ref().map_or(b"/".to_vec(), |c| c.get().root.clone());
                return Some(crate::procfs::Entry::File(crate::cgroupfs::proc_self_cgroup(&root)));
            }
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
        if absolute == b"/proc/self/fdinfo" {
            return Some(crate::procfs::Entry::Dir);
        }
        if let Some(n) = absolute.strip_prefix(b"/proc/self/fdinfo/") {
            let fd = std::str::from_utf8(n).ok().and_then(|n| n.parse::<i32>().ok());
            return Some(match fd.filter(|&fd| self.guest_fd_open(fd)) {
                Some(fd) => crate::procfs::Entry::File(self.fdinfo(fd)),
                None => crate::procfs::Entry::Missing,
            });
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
        if crate::bpf::prog_info(fd).is_some() {
            return b"anon_inode:bpf-prog".to_vec();
        }
        if crate::bpfmap::of(fd).is_some() {
            return b"anon_inode:bpf-map".to_vec();
        }
        if let Some(p) = crate::synthdir::path_of(fd) {
            return p;
        }
        if let Some(name) = crate::specialfd::anon_name(fd) {
            return format!("anon_inode:{name}").into_bytes();
        }
        if crate::signalfd::is_signalfd(fd) {
            return b"anon_inode:[signalfd]".to_vec();
        }
        if let Some(t) = crate::nsfd::target(fd) {
            return t;
        }
        if crate::pidfd::of(fd).is_some() {
            return b"anon_inode:[pidfd]".to_vec();
        }
        // A descriptor of a `/proc` link: the link's path.
        if let Some(link) = crate::fdmarks::proc_link(fd).and_then(|ns| self.from_ns(&ns)) {
            return link;
        }
        if crate::inotify::instance_of(fd).is_some() {
            return b"anon_inode:inotify".to_vec();
        }
        if crate::mountapi::is_context(fd) {
            return b"anon_inode:[fscontext]".to_vec();
        }
        // SAFETY: an all-zero stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return b"anon_inode:[unknown]".to_vec();
        }
        match st.st_mode & libc::S_IFMT {
            // A pipe; a named FIFO has its path.
            libc::S_IFIFO if fd_path(fd).is_none() => {
                return format!("pipe:[{}]", st.st_ino).into_bytes();
            }
            libc::S_IFSOCK => {
                // Named as other processes see it ([`crate::procpid::socket_id`]).
                // SAFETY: getpid cannot fail.
                let id = crate::procpid::socket_id(unsafe { libc::getpid() }, fd);
                return format!("socket:[{}]", id.unwrap_or(st.st_ino as u64)).into_bytes();
            }
            _ => {}
        }
        if let Some(guest) = crate::fdmarks::origin(fd).and_then(|o| self.from_ns(&o.ns_path)) {
            return guest;
        }
        match fd_path(fd) {
            Some(host) => self.host_to_guest(&host).unwrap_or(host),
            // A kqueue (an epoll descriptor) has neither path nor type.
            None => b"anon_inode:[eventpoll]".to_vec(),
        }
    }

    /// `/proc/<pid>/fd/<n>` of another process, host process `host`: a
    /// link to what its descriptor `n` is open on, a path as this process
    /// sees it.
    fn other_fd(&self, host: i32, n: &[u8]) -> crate::procfs::Entry {
        use crate::procpid::FdTarget;
        let Some(fd) = std::str::from_utf8(n).ok().and_then(|n| n.parse::<i32>().ok()) else {
            return crate::procfs::Entry::Missing;
        };
        let Some((_, target)) = crate::procpid::fds(host).into_iter().find(|(f, _)| *f == fd)
        else {
            return crate::procfs::Entry::Missing;
        };
        crate::procfs::Entry::Symlink(match target {
            FdTarget::Path(p) => self.host_to_guest(&p).unwrap_or(p),
            FdTarget::Pipe(id) => format!("pipe:[{id}]").into_bytes(),
            FdTarget::Socket(id) => format!("socket:[{id}]").into_bytes(),
            FdTarget::Anon(name) => name.as_bytes().to_vec(),
        })
    }

    /// Whether guest descriptor `fd` is open.
    fn guest_fd_open(&self, fd: i32) -> bool {
        // SAFETY: F_GETFD only queries the descriptor.
        fd >= 0
            && crate::fdtable::guest_visible(fd)
            && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0
    }

    /// `/proc/self/fdinfo/<fd>`: the descriptor's offset, flags (Linux's),
    /// mount and inode, and for a BPF program its type, tag and identity.
    #[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
    fn fdinfo(&self, fd: i32) -> Vec<u8> {
        // SAFETY: plain host calls on an open descriptor.
        let (pos, status, fd_flags) = unsafe {
            (
                libc::lseek(fd, 0, libc::SEEK_CUR).max(0),
                libc::fcntl(fd, libc::F_GETFL),
                libc::fcntl(fd, libc::F_GETFD),
            )
        };
        let mut flags = crate::host::status_flags_to_linux(status);
        if fd_flags & libc::FD_CLOEXEC != 0 {
            flags |= fcntl::O_CLOEXEC;
        }
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        match crate::fdmarks::stand_in(fd).and_then(|h| std::ffi::CString::new(h).ok()) {
            // An O_PATH stand-in: the file it names.
            Some(host) => {
                flags = flags & fcntl::O_CLOEXEC | fcntl::O_PATH;
                // SAFETY: a NUL-terminated path and a valid out-parameter.
                unsafe { libc::lstat(host.as_ptr(), &mut st) };
            }
            // SAFETY: a valid out-parameter.
            None => unsafe {
                libc::fstat(fd, &mut st);
            },
        }
        let mnt = crate::fdmarks::origin(fd)
            .filter(|o| !o.ns_path.is_empty())
            .map_or(self.mnt.table().root().id, |o| self.mnt.table().locate(&o.ns_path).0.id);
        let mut out = format!(
            "pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t{mnt}\nino:\t{}\n",
            st.st_ino as u64
        );
        if let Some((id, ty, insns)) = crate::bpf::prog_info(fd) {
            out.push_str(&format!(
                "prog_type:\t{ty}\nprog_jited:\t0\nprog_tag:\t{}\nmemlock:\t4096\n\
                 prog_id:\t{id}\nrun_time_ns:\t0\nrun_cnt:\t0\nrecursion_misses:\t0\n\
                 verified_insns:\t{}\n",
                crate::bpf::tag_hex(&insns),
                insns.len() / 8
            ));
        }
        if let Some(lines) = crate::inotify::fdinfo(fd) {
            out.push_str(&lines);
        }
        if let Some(lines) = crate::pidfd::fdinfo(fd) {
            out.push_str(&lines);
        }
        out.into_bytes()
    }

    /// Whether `path` names `/proc/self/fd`, whose listing is the open
    /// descriptors.
    pub fn lists_fds(&self, dirfd: i32, path: &[u8]) -> bool {
        self.synthetic_path(dirfd, path).as_deref() == Some(b"/proc/self/fd")
    }

    /// The `/proc` path `path` names, the reader's own process as
    /// `/proc/self`, if it is in a `proc` mount.
    pub fn proc_path(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        let p = self.synthetic_path(dirfd, path)?;
        own_or_other(&p).ok()
    }

    /// The process a `/proc/<pid>/...` path (from `dirfd`) is about and the
    /// rest of the path: `None` for the caller (`self` or its own pid),
    /// else its host pid (`None` inside when it has none), with the rest.
    pub fn proc_target(&self, dirfd: i32, path: &[u8]) -> Option<(Option<Option<i32>>, Vec<u8>)> {
        let p = self.synthetic_path(dirfd, path)?;
        match own_or_other(&p) {
            Ok(own) => Some((None, own.strip_prefix(b"/proc/self")?.to_vec())),
            Err((host, _, sub)) => Some((Some(host), sub)),
        }
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
                FsType::Devpts | FsType::Mqueue if fs_path == b"/" => {
                    let mut out = vec![
                        (b".".to_vec(), crate::procfs::DT_DIR),
                        (b"..".to_vec(), crate::procfs::DT_DIR),
                    ];
                    if m.fstype == FsType::Mqueue {
                        let names = crate::mqueue::names();
                        out.extend(names.into_iter().map(|n| (n, crate::procfs::DT_REG)));
                    }
                    Some(out)
                }
                _ => None,
            };
        };
        let absolute = match own_or_other(&absolute) {
            Ok(a) => a,
            Err((Some(h), _, sub)) if sub == b"/fd" => {
                let mut out = vec![
                    (b".".to_vec(), crate::procfs::DT_DIR),
                    (b"..".to_vec(), crate::procfs::DT_DIR),
                ];
                out.extend(
                    crate::procpid::fds(h)
                        .into_iter()
                        .map(|(fd, _)| (fd.to_string().into_bytes(), crate::procfs::DT_LNK)),
                );
                return Some(out);
            }
            Err((Some(_), pid, sub)) => return crate::procpid::children(pid, &sub),
            Err((None, _, _)) => return None,
        };
        if absolute == b"/proc" {
            let mut out = crate::procfs::children(b"/proc")?;
            out.extend(
                crate::procpid::listed()
                    .into_iter()
                    .map(|p| (p.to_string().into_bytes(), crate::procfs::DT_DIR)),
            );
            return Some(out);
        }
        if absolute == b"/proc/self/fdinfo" {
            let mut out = vec![
                (b".".to_vec(), crate::procfs::DT_DIR),
                (b"..".to_vec(), crate::procfs::DT_DIR),
            ];
            out.extend(
                crate::fdtable::open_fds()
                    .into_iter()
                    .map(|fd| (fd.to_string().into_bytes(), crate::procfs::DT_REG)),
            );
            return Some(out);
        }
        if absolute == b"/proc/self/task" {
            let mut out = vec![
                (b".".to_vec(), crate::procfs::DT_DIR),
                (b"..".to_vec(), crate::procfs::DT_DIR),
            ];
            out.extend(
                crate::thread::tids()
                    .into_iter()
                    .map(|t| (t.to_string().into_bytes(), crate::procfs::DT_DIR)),
            );
            return Some(out);
        }
        if let Some(t) = absolute.strip_prefix(b"/proc/self/task/")
            && matches!(task_entry(t), crate::procfs::Entry::Dir)
        {
            let mut out = vec![
                (b".".to_vec(), crate::procfs::DT_DIR),
                (b"..".to_vec(), crate::procfs::DT_DIR),
            ];
            out.extend(TASK_FILES.iter().map(|n| (n.to_vec(), crate::procfs::DT_REG)));
            return Some(out);
        }
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

    /// The working directory's path in the namespace's view, when a
    /// `chroot` left it outside the root.
    pub fn cwd_outside(&self) -> Option<&[u8]> {
        self.cwd_outside.as_deref()
    }

    /// A `chroot` left the working directory outside the root, at `path`
    /// (or inside it, `None`).
    pub fn set_cwd_outside(&mut self, path: Option<Vec<u8>>) {
        self.cwd_outside = path;
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

    /// `path` as a normalized absolute guest path (taken lexically), if fwe
    /// can place it: absolute, relative to the working directory, or to a
    /// directory descriptor whose place it knows (a synthetic directory, or
    /// one opened through a mount of the process's).
    fn absolute(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        if path.first() == Some(&b'/') {
            return Some(normalize(b"/", path));
        }
        if dirfd as i64 == fcntl::AT_FDCWD {
            return Some(normalize(&self.cwd, path));
        }
        let dir = self.fd_ns_path(dirfd).and_then(|ns| self.from_ns(&ns))?;
        Some(normalize(&dir, path))
    }

    /// Where the file `fd` is open on is in the namespace's view, if fwe
    /// can tell: a synthetic directory's path, where the file was opened,
    /// or else the mount showing its host path.
    pub fn fd_ns_path(&self, fd: i32) -> Option<Vec<u8>> {
        if let Some(p) = crate::synthdir::path_of(fd) {
            return Some(self.to_ns(&p));
        }
        crate::fdmarks::origin(fd).map(|o| o.ns_path).or_else(|| self.ns_path_of_fd(fd))
    }

    /// [`absolute`](Self::absolute), for the callers outside.
    pub fn absolute_path(&self, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
        self.absolute(dirfd, path)
    }

    /// Resolve `path` relative to `dirfd`. Every symlink is followed except,
    /// when `follow_final` is false, one that is the last component. The
    /// standard device nodes ([`DEVICES`]) resolve to the host's, and
    /// `/dev/shm` to fwe's own directory for it ([`shm`]).
    pub fn resolve(&self, dirfd: i32, path: &[u8], follow_final: bool) -> Result<Resolved, i32> {
        if path.is_empty() {
            // An empty path names nothing, as on Linux; a call that takes
            // `AT_EMPTY_PATH` acts on its descriptor before resolving.
            return Err(errno::ENOENT);
        }
        let r = resolve_in(&self.view(), dirfd, path, follow_final)?;
        // A mount marked to expire (`MNT_EXPIRE`) is in use again (but by
        // the lookup of an unmount's own target).
        let t = self.mnt.table();
        if !t.expiring.is_empty()
            && !UNMOUNTING.with(std::cell::Cell::get)
            && let Some(ns) = &r.ns_path
        {
            let used: Vec<u32> = t
                .expiring
                .iter()
                .copied()
                .filter(|id| t.get(*id).is_some_and(|m| mounts::under(ns, &m.point).is_some()))
                .collect();
            if !used.is_empty() {
                let _ = self.mnt.update(|t| {
                    t.expiring.retain(|i| !used.contains(i));
                    Ok(())
                });
            }
        }
        Ok(r)
    }

    /// Whether the guest's root is the host's own (no root filesystem).
    pub fn root_is_host(&self) -> bool {
        self.root_host == b"/"
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

    /// Resolve and read a whole file under the root (following symlinks),
    /// to run it: a program, or the dynamic linker it names (`EACCES` from
    /// a `noexec` mount).
    pub fn read(&self, path: &[u8]) -> Result<Vec<u8>, i32> {
        if let Some(entry) = self.synthetic(fcntl::AT_FDCWD as i32, path) {
            use crate::procfs::Entry;
            return match entry {
                Entry::File(data) => Ok(data),
                Entry::Fd { fd, .. } => {
                    // Through the descriptor: only a regular file is run.
                    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: a valid out-parameter.
                    if unsafe { libc::fstat(fd, &mut st) } != 0
                        || st.st_mode & libc::S_IFMT != libc::S_IFREG
                    {
                        return Err(errno::EACCES);
                    }
                    read_all(fd)
                }
                Entry::Symlink(t) if t.starts_with(b"/") => self.read(&t),
                Entry::Dir => Err(errno::EISDIR),
                _ => Err(errno::ENOENT),
            };
        }
        let resolved = self.resolve(fcntl::AT_FDCWD as i32, path, true)?;
        // Nothing is run from a mount that runs nothing.
        if resolved.mount_flags & mounts::ms::NOEXEC != 0 {
            return Err(errno::EACCES);
        }
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

    /// `/proc/self/maps`, or with `smaps` `/proc/self/smaps`: the guest's
    /// mappings (see [`crate::maps`]).
    fn maps(&self, smaps: bool) -> Vec<u8> {
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        crate::mm::MapsView::of(me).map_or_else(Vec::new, |v| v.render(smaps))
    }

    /// The first `len` bytes (or fewer, at its end) of the regular file
    /// `path` names.
    pub fn read_head(&self, path: &[u8], len: usize) -> Result<Vec<u8>, i32> {
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
        let mut out = vec![0u8; len];
        let mut at = 0;
        while at < len {
            // SAFETY: reading into the rest of `out`.
            let n = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    out[at..].as_mut_ptr().cast(),
                    len - at,
                    at as libc::off_t,
                )
            };
            if n < 0 {
                return Err(e());
            }
            if n == 0 {
                break;
            }
            at += n as usize;
        }
        out.truncate(at);
        Ok(out)
    }

    /// The device and inode numbers of the file `path` names, following
    /// symbolic links, as `stat` gives them.
    pub fn file_id(&self, path: &[u8]) -> Option<(u64, u64)> {
        let resolved = self.resolve(fcntl::AT_FDCWD as i32, path, true).ok()?;
        let name = resolved.name_c().ok()?;
        // SAFETY: zeroed bytes are a valid `stat`.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated name, a live directory fd and a valid
        // out-parameter.
        let ok = unsafe { libc::fstatat(resolved.dir.as_raw_fd(), name.as_ptr(), &mut st, 0) } == 0;
        #[allow(clippy::unnecessary_cast)] // the field types differ by host
        ok.then_some((st.st_dev as u64, st.st_ino as u64))
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

    /// The host file `path` stands for, if it names one of the standard
    /// device nodes fwe serves in the rootfs's own `/dev` (see
    /// [`resolve_in`]): what a bind mount of it shows.
    pub fn device_host(&self, path: &[u8]) -> Option<Vec<u8>> {
        let absolute = self.absolute_path(fcntl::AT_FDCWD as i32, path)?;
        let name = absolute.strip_prefix(b"/dev/")?;
        if !DEVICES.contains(&name) && crate::loopdev::node_named(name).is_none() {
            return None;
        }
        if !is_rootfs(&self.mount_of(&absolute).0, &self.root_host) {
            return None;
        }
        let r = self.resolve(fcntl::AT_FDCWD as i32, path, true).ok()?;
        let dir = fd_path(r.dir.as_raw_fd())?;
        Some(mounts::join(&dir, &r.name))
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
        self.cwd_mount = resolved.mount_id;
        self.cwd_outside = None;
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
        // A directory opened through an overlay is that overlay's: its host
        // path is in one of the layers, which says nothing of where.
        let table = self.mnt.table();
        let opened = overlay_here(&table, &self.proc_root, fd)
            .ok()
            .flatten()
            .and_then(|h| h.at)
            .and_then(|(_, ns)| self.from_ns(&ns));
        let overlaid = crate::fdmarks::origin(fd).is_some_and(|o| o.ovl.is_some());
        let fallback = if overlaid { None } else { self.host_to_guest(&host) };
        match opened.or(fallback) {
            Some(guest) => {
                self.cwd = guest;
                self.cwd_outside = None;
                self.cwd_mount = crate::fdmarks::origin(fd).map_or(0, |o| o.mount);
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
    // Not through an overlay's layers: a layer's directory is the
    // overlay's only when it was opened through the overlay, which its
    // descriptor's record says ([`overlay_here`]).
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

/// Where descriptor `fd` is, if it was opened through an overlay: that
/// overlay's directory at the path the descriptor is at in its layer, in
/// the mount of that overlay that shows it inside the process's root (if
/// one still does).
fn overlay_here(table: &Table, root_ns: &[u8], fd: i32) -> Result<Option<Here>, i32> {
    let Some(l) = crate::fdmarks::origin(fd).and_then(|o| o.ovl) else { return Ok(None) };
    let path = overlay::path_of(&l, fd).ok_or(errno::ENOENT)?;
    let at = table.mounts.iter().find_map(|m| {
        let Source::Overlay(ml) = &m.source else { return None };
        if **ml != *l {
            return None;
        }
        let rest = mounts::under(&path, &m.root)?;
        let ns = mounts::join(&m.point, rest);
        (table.locate(&ns).0.id == m.id && mounts::under(&ns, root_ns).is_some())
            .then_some((m.id, ns))
    });
    Here::overlay(&l, path, at).map(Some)
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

/// A directory of an overlay mount resolution is in.
#[derive(Clone)]
struct OvlHere {
    layers: Arc<Layers>,
    /// Its path in the overlay, from the overlay's root.
    path: Vec<u8>,
    dir: overlay::Dir,
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
    /// In an overlay mount: the directory in each of its layers (`dir` is
    /// the topmost of them).
    ovl: Option<OvlHere>,
}

impl Here {
    /// The directory at overlay path `path` of the overlay `layers`.
    fn overlay(
        layers: &Arc<Layers>,
        path: Vec<u8>,
        at: Option<(u32, Vec<u8>)>,
    ) -> Result<Here, i32> {
        let dir = overlay::open(layers, &path)?;
        Here::of_overlay(layers, path, dir, at)
    }

    fn of_overlay(
        layers: &Arc<Layers>,
        path: Vec<u8>,
        dir: overlay::Dir,
        at: Option<(u32, Vec<u8>)>,
    ) -> Result<Here, i32> {
        let top = dup_cloexec(dir.top().1.as_raw_fd())?;
        Ok(Here {
            dir: top,
            at,
            phantom: false,
            ovl: Some(OvlHere { layers: layers.clone(), path, dir }),
        })
    }
}

/// The directory at `rest` (a path inside the mount, from its root) of
/// the mount `m`, which is at namespace path `ns`.
fn open_here(v: &View, m: &Mount, rest: &[u8], ns: &[u8]) -> Result<Here, i32> {
    let at = Some((m.id, ns.to_vec()));
    match &m.source {
        Source::Overlay(l) => Here::overlay(l, m.fs_path(rest), at),
        _ => Ok(Here { dir: open_in_mount(v, m, rest)?, at, phantom: false, ovl: None }),
    }
}

/// What a name in a directory resolution walks through is.
enum Step {
    /// A symbolic link, to this.
    Link(Vec<u8>),
    /// Something else that is there.
    Other,
    /// A directory of an overlay.
    OvlDir(overlay::Dir),
    Missing,
}

/// An empty directory nothing can be made in: what a name an overlay
/// does not show is resolved in, so that it is found nowhere, and a call
/// that would make it there without [`Resolved::prepare`] fails.
fn empty_dir() -> Result<OwnedFd, i32> {
    static PATH: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let path = match PATH.get() {
        Some(p) => p.clone(),
        None => {
            let p = mounts::join(&shm::user_dir()?, b"empty");
            let c = cstr(&p)?;
            // SAFETY: a NUL-terminated path in fwe's private directory.
            unsafe {
                libc::mkdir(c.as_ptr(), 0o500);
                libc::chmod(c.as_ptr(), 0o500);
            }
            PATH.get_or_init(|| p).clone()
        }
    };
    open_host_dir(&path)
}

/// Whether host metadata `st` is of [`empty_dir`], which nothing may
/// be made in.
pub(crate) fn is_empty_dir(st: &libc::stat) -> bool {
    empty_dir().is_ok_and(|d| {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut e: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        let ok = unsafe { libc::fstat(d.as_raw_fd(), &mut e) } == 0;
        ok && e.st_dev == st.st_dev && e.st_ino == st.st_ino
    })
}

/// Whether a caller of file-system user `fsuid` may follow the symbolic
/// link `name` in directory `dir`, with `fs.protected_symlinks` on: one in
/// a sticky directory anyone may write to only if it is the caller's, or
/// the directory's owner's (`EACCES`).
fn may_follow(dir: i32, name: &std::ffi::CStr, fsuid: u32) -> Result<(), i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live directory, a NUL-terminated name, a valid out-parameter.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Ok(());
    }
    let owner = crate::owners::of_at(dir, name, &st).0;
    if owner == fsuid {
        return Ok(());
    }
    let Some(parent) = guest_stat(dir) else { return Ok(()) };
    let open = (libc::S_ISVTX | libc::S_IWOTH) as libc::mode_t;
    if parent.st_mode & open != open || parent.st_uid == owner {
        return Ok(());
    }
    Err(errno::EACCES)
}

/// The guest's metadata of the file open as `fd`: its kept mode and
/// owner ([`crate::modes`], [`crate::owners`]).
fn guest_stat(fd: i32) -> Option<libc::stat> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let perm = crate::modes::guest_perm_fd(fd, &st);
    let owner = crate::owners::of_fd(fd, &st);
    crate::modes::apply(&mut st, perm);
    crate::owners::apply(&mut st, owner);
    Some(st)
}

/// [`guest_stat`] of `name` in directory `dir`, followed if it is a link.
pub(crate) fn guest_stat_at(dir: i32, name: &std::ffi::CStr) -> Option<libc::stat> {
    // SAFETY: a NUL-terminated name in a live directory; the descriptor is
    // closed below.
    let fd = unsafe {
        libc::openat(dir, name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)
    };
    if fd < 0 {
        return None;
    }
    let st = guest_stat(fd);
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd) };
    st
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
        let name = a.strip_prefix(b"/dev/")?;
        let own = crate::loopdev::node_named(name);
        if !DEVICES.contains(&name) && own.is_none() {
            return None;
        }
        let ns = to_ns(v.proc_root, a);
        let (m, _) = table.locate(&ns);
        is_rootfs(m, v.root_host).then(|| (name.to_vec(), own, ns, m.flags, m.fstype, m.id))
    });
    if let Some((name, own, ns, mount_flags, fstype, mount_id)) = device {
        // The host has no /dev/full and no loop devices: fwe's own nodes
        // stand in for them.
        let own = match (&name[..], own) {
            (b"full", _) => Some(full_node()),
            (_, own) => own,
        };
        let dir = match own {
            Some(node) => fwe_device(&name, node)?,
            None => b"/dev".to_vec(),
        };
        let dir = cstr(&dir)?;
        // SAFETY: plain host call; the result is checked and owned.
        let dev = unsafe {
            libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if dev < 0 {
            return Err(e());
        }
        // SAFETY: `dev` is a fresh owned descriptor.
        let mut r = Resolved::plain(unsafe { OwnedFd::from_raw_fd(dev) }, name);
        // Where it is in the namespace, which an open of it records.
        (r.ns_path, r.mount_flags, r.fstype, r.mount_id) =
            (Some(ns), mount_flags, fstype, mount_id);
        return Ok(r);
    }
    let root_ns = v.proc_root.to_vec();
    // The directory with namespace path `ns`, entered from the root.
    let enter = |ns: &[u8]| -> Result<Here, i32> {
        let (m, rest) = table.locate(ns);
        if m.source == Source::Synthetic {
            return Err(errno::ENOENT);
        }
        match open_here(v, m, &rest, ns) {
            Ok(here) => Ok(here),
            Err(errno::ENOENT)
                if table.mounts.iter().any(|o| mounts::under(&o.point, ns).is_some()) =>
            {
                // A missing directory a mount hangs below: stand in the
                // nearest one above that exists.
                let mut up = ns.to_vec();
                loop {
                    let parent = normalize(&up, b"..");
                    let (pm, prest) = table.locate(&parent);
                    if let Ok(found) = open_here(v, pm, &prest, &parent) {
                        let at = Some((m.id, ns.to_vec()));
                        return Ok(Here { dir: found.dir, at, phantom: true, ovl: None });
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
            // and it is inside the process's root; a directory of an
            // overlay is the overlay's, wherever the mount has gone.
            let here = match overlay_here(&table, &root_ns, dirfd)? {
                Some(here) => here,
                None => {
                    // A path relative to something that is not a directory
                    // names nothing (`ENOTDIR`).
                    // SAFETY: an all-zero `stat` is a valid out-parameter.
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: plain host call with a valid out-parameter.
                    if unsafe { libc::fstat(dirfd, &mut st) } != 0 {
                        return Err(errno::EBADF);
                    }
                    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(errno::ENOTDIR);
                    }
                    let ns = fd_path(dirfd)
                        .and_then(|h| host_to_ns(&table, &h))
                        .filter(|ns| mounts::under(ns, &root_ns).is_some());
                    let dir = dup_cloexec(dirfd)?;
                    let at = ns.map(|ns| (table.locate(&ns).0.id, ns));
                    Here { dir, at, phantom: false, ovl: None }
                }
            };
            (here, path.to_vec())
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
        let (dir, ovl) = match here.ovl {
            None => (here.dir, None),
            Some(o) if name == b"." => {
                let found = overlay::Found::Dir(o.dir.clone());
                (here.dir, Some(Ovl { layers: o.layers, parent: o.path, found }))
            }
            Some(o) => {
                let found = overlay::lookup(&o.layers, &o.dir, &cstr(&name)?)?;
                let dir = match &found {
                    overlay::Found::Missing => empty_dir()?,
                    overlay::Found::Other { layer, .. } => {
                        dup_cloexec(o.dir.fds[*layer].as_ref().expect("its layer").as_raw_fd())?
                    }
                    overlay::Found::Dir(d) => {
                        dup_cloexec(o.dir.fds[d.top().0].as_ref().expect("its layer").as_raw_fd())?
                    }
                };
                (dir, Some(Ovl { layers: o.layers, parent: o.path, found }))
            }
        };
        Ok(Resolved {
            dir: out_of_reach(dir),
            name,
            ns_path,
            mount_flags: mount.as_ref().map_or(0, |m| m.flags),
            fstype: mount.as_ref().map_or(FsType::Ext4, |m| m.fstype),
            mount_id: mount.as_ref().map_or(0, |m| m.id),
            mount_root,
            ovl,
            created: None,
        })
    };

    // Each step needs search permission on the directory it looks in, for
    // a caller that does not pass permission bits, in a root filesystem
    // (the host's own directories, without one, are searched as the host
    // user searches them: they are all its own).
    let access = crate::creds::access();
    let check_search = !access.searches_any() && v.root_host != b"/";
    while let Some(comp) = pending.pop() {
        if check_search
            && !here.phantom
            && let Some(st) = guest_stat(here.dir.as_raw_fd())
            && st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && !access.permits(&st, 1)
        {
            return Err(errno::EACCES);
        }
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
                None if here.ovl.is_some() => {
                    // An overlay directory fwe cannot place: up in the
                    // overlay, no further than its root.
                    let o = here.ovl.as_ref().expect("in an overlay");
                    if let Some(a) = ancestors.pop() {
                        here = a;
                    } else if o.path != b"/" {
                        let parent = normalize(&o.path, b"..");
                        here = Here::overlay(&o.layers.clone(), parent, None)?;
                    }
                }
                None => {
                    // Somewhere fwe cannot place: up on the host, but never
                    // above the rootfs or the top of a mount's directory,
                    // and never from outside them.
                    let host = fd_path(here.dir.as_raw_fd()).ok_or(errno::ENOENT)?;
                    let tops: Vec<Vec<u8>> = std::iter::once(v.root_host.to_vec())
                        .chain(table.mounts.iter().flat_map(mount_tops))
                        .collect();
                    if tops.contains(&host) {
                        continue;
                    }
                    if !tops.iter().any(|t| mounts::under(&host, t).is_some()) {
                        return Err(errno::EACCES);
                    }
                    here.dir = open_dir(here.dir.as_raw_fd(), c"..")?;
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
                    // Served by `Fs::synthetic`, which the callers ask
                    // first; only a mount below it is reached through it.
                    if is_last {
                        return Err(errno::ENOENT);
                    }
                    let dir = dup_cloexec(here.dir.as_raw_fd())?;
                    let next = Here { dir, at: Some((m.id, child_ns)), phantom: true, ovl: None };
                    ancestors.push(std::mem::replace(&mut here, next));
                    continue;
                }
                if let Source::Overlay(l) = &m.source {
                    let at = Some((m.id, child_ns.clone()));
                    let next = match overlay::open(l, &m.root) {
                        Ok(dir) => Here::of_overlay(l, m.root.clone(), dir, at)?,
                        Err(errno::ENOTDIR) => {
                            // A file bind mount of an overlay's file.
                            if !is_last {
                                return Err(errno::ENOTDIR);
                            }
                            let (parent, name) = split_host(&m.root);
                            let parent = Here::overlay(l, parent, None)?;
                            let mut r = done(parent, name, true)?;
                            r.ns_path = Some(child_ns.clone());
                            r.mount_flags = m.flags;
                            r.fstype = m.fstype;
                            r.mount_id = m.id;
                            return Ok(r);
                        }
                        Err(e) => return Err(e),
                    };
                    if is_last {
                        return done(next, b".".to_vec(), true);
                    }
                    ancestors.push(std::mem::replace(&mut here, next));
                    continue;
                }
                // What the mount shows, found without following a link the
                // guest could have put in its source's place.
                let (parent, name) = mount_parent(v, &m)?;
                let c_name = cstr(&name)?;
                // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: a live directory descriptor and NUL-terminated name.
                if unsafe {
                    libc::fstatat(
                        parent.as_raw_fd(),
                        c_name.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(e());
                }
                let kind = st.st_mode & libc::S_IFMT;
                if kind == libc::S_IFLNK {
                    return Err(errno::ELOOP);
                }
                if kind != libc::S_IFDIR {
                    // A file bind mount: the host file itself.
                    if !is_last {
                        return Err(errno::ENOTDIR);
                    }
                    let dir = parent;
                    let mut r =
                        done(Here { dir, at: None, phantom: false, ovl: None }, name, true)?;
                    r.ns_path = Some(child_ns.clone());
                    r.mount_flags = m.flags;
                    r.fstype = m.fstype;
                    r.mount_id = m.id;
                    return Ok(r);
                }
                let dir = open_in_mount(v, &m, b"")?;
                let next = Here { dir, at: Some((m.id, child_ns)), phantom: false, ovl: None };
                if is_last {
                    return done(next, b".".to_vec(), true);
                }
                ancestors.push(std::mem::replace(&mut here, next));
                continue;
            }
        }
        // Inside fwe's own `/proc`: names it serves itself (`Fs::synthetic`
        // answers for the last), and the magic links that lead out of it
        // to a descriptor's file, the working directory or the root.
        if here.phantom
            && let Some((id, ns)) = &here.at
            && let Some(m) = table.get(*id).filter(|m| m.source == Source::Synthetic)
        {
            let (id, child_ns) = (*id, mounts::join(ns, &comp));
            if is_last {
                // A descriptor's link, followed: the file it was opened at.
                let link = match m.fstype {
                    FsType::Proc => mounts::under(&child_ns, &m.point).and_then(proc_magic_link),
                    _ => None,
                };
                if follow_final
                    && let Some(MagicLink::Fd(fd)) = link
                    && let Some(guest) =
                        crate::fdmarks::origin(fd).and_then(|o| from_ns(v.proc_root, &o.ns_path))
                {
                    symlinks += 1;
                    if symlinks > MAX_SYMLINKS {
                        return Err(errno::ELOOP);
                    }
                    return resolve_in(v, fcntl::AT_FDCWD as i32, &guest, true);
                }
                return done(here, comp, false);
            }
            let link = match m.fstype {
                FsType::Proc => mounts::under(&child_ns, &m.point).and_then(proc_magic_link),
                _ => None,
            };
            let next = match link {
                Some(MagicLink::Fd(fd)) => match overlay_here(&table, &root_ns, fd)? {
                    Some(here) => here,
                    None => {
                        let ns = fd_path(fd)
                            .and_then(|h| host_to_ns(&table, &h))
                            .filter(|ns| mounts::under(ns, &root_ns).is_some());
                        let at = ns.map(|ns| (table.locate(&ns).0.id, ns));
                        Here { dir: dup_cloexec(fd)?, at, phantom: false, ovl: None }
                    }
                },
                Some(MagicLink::Cwd) => enter(&to_ns(v.proc_root, v.cwd))?,
                Some(MagicLink::Root) => enter(&root_ns)?,
                None => {
                    let dir = dup_cloexec(here.dir.as_raw_fd())?;
                    Here { dir, at: Some((id, child_ns)), phantom: true, ovl: None }
                }
            };
            if link.is_some() {
                // `..` from there is the file's own parent.
                ancestors.clear();
                here = next;
            } else {
                ancestors.push(std::mem::replace(&mut here, next));
            }
            continue;
        }
        if is_last && !follow_final {
            return done(here, comp, false);
        }
        let comp_c = cstr(&comp)?;
        let step = if here.phantom {
            Step::Missing
        } else if let Some(o) = &here.ovl {
            match overlay::lookup(&o.layers, &o.dir, &comp_c)? {
                overlay::Found::Missing => Step::Missing,
                overlay::Found::Dir(d) => Step::OvlDir(d),
                overlay::Found::Other { layer, link: true } => {
                    let in_layer = o.dir.fds[layer].as_ref().expect("its layer");
                    Step::Link(readlink_at(in_layer.as_raw_fd(), &comp_c)?)
                }
                overlay::Found::Other { .. } => Step::Other,
            }
        } else {
            match readlink_at(here.dir.as_raw_fd(), &comp_c) {
                Ok(target) => Step::Link(target),
                // Not a symlink.
                Err(errno::EINVAL) => Step::Other,
                Err(errno::ENOENT) => Step::Missing,
                Err(other) => return Err(other),
            }
        };
        match step {
            Step::Link(target) => {
                symlinks += 1;
                if symlinks > MAX_SYMLINKS {
                    return Err(errno::ELOOP);
                }
                if here.ovl.is_none() && crate::sysctl::protected_links().0 {
                    may_follow(here.dir.as_raw_fd(), &comp_c, access.fsuid)?;
                }
                // A mount whose links are not followed.
                let nofollow = here
                    .at
                    .as_ref()
                    .and_then(|(id, _)| table.get(*id))
                    .is_some_and(|m| m.flags & mounts::ms::NOSYMFOLLOW != 0);
                if nofollow {
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
            Step::Other | Step::OvlDir(_) if is_last => return done(here, comp, false),
            Step::Other => {
                let child = open_dir(here.dir.as_raw_fd(), &comp_c)?;
                let at = here.at.as_ref().map(|(id, ns)| (*id, mounts::join(ns, &comp)));
                let next = Here { dir: child, at, phantom: false, ovl: None };
                ancestors.push(std::mem::replace(&mut here, next));
            }
            Step::OvlDir(d) => {
                let o = here.ovl.as_ref().expect("in an overlay");
                let at = here.at.as_ref().map(|(id, ns)| (*id, mounts::join(ns, &comp)));
                let next = Here::of_overlay(&o.layers, mounts::join(&o.path, &comp), d, at)?;
                ancestors.push(std::mem::replace(&mut here, next));
            }
            Step::Missing => {
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
                    let next = Here { dir, at, phantom: true, ovl: None };
                    ancestors.push(std::mem::replace(&mut here, next));
                    continue;
                }
                if is_last {
                    return done(here, comp, false);
                }
                return Err(errno::ENOENT);
            }
        }
    }
    done(here, b".".to_vec(), false)
}

/// The host directories at the top of what mount `m` shows: its source's
/// directory, or each of an overlay's layers'.
fn mount_tops(m: &Mount) -> Vec<Vec<u8>> {
    match &m.source {
        Source::Host(_) => m.host_path(b"").into_iter().collect(),
        Source::Overlay(l) => l.paths().map(|p| mounts::join(p, &m.root)).collect(),
        Source::Synthetic => Vec::new(),
    }
}

/// Where a magic link of `/proc` leads.
#[derive(Clone, Copy)]
enum MagicLink {
    /// The file open as this process's descriptor.
    Fd(i32),
    Cwd,
    Root,
}

/// The magic link at `rel` in a `proc` mount (`self/fd/3`, `self/cwd`,
/// and the like, `self` also as this process's pid or `thread-self`), if it
/// is one of this process's.
fn proc_magic_link(rel: &[u8]) -> Option<MagicLink> {
    let parts: Vec<&[u8]> = rel.split(|&b| b == b'/').filter(|p| !p.is_empty()).collect();
    let own = |p: &[u8]| {
        p == b"self"
            || p == b"thread-self"
            || std::str::from_utf8(p).ok().and_then(|n| n.parse::<i32>().ok())
                // SAFETY: getpid cannot fail.
                == Some(crate::pidns::to_guest(unsafe { libc::getpid() }))
    };
    match parts[..] {
        [who, b"fd", n] if own(who) => {
            let fd = std::str::from_utf8(n).ok()?.parse::<i32>().ok()?;
            crate::fdtable::guest_visible(fd).then_some(MagicLink::Fd(fd))
        }
        [who, b"cwd"] if own(who) => Some(MagicLink::Cwd),
        [who, b"root"] if own(who) => Some(MagicLink::Root),
        _ => None,
    }
}

/// The magic link of the process's that `rel` (a path in a `proc` mount)
/// goes through to something below what it leads to, and the rest of it.
fn through_magic_link(rel: &[u8]) -> Option<(MagicLink, Vec<u8>)> {
    let parts: Vec<&[u8]> = rel.split(|&b| b == b'/').filter(|p| !p.is_empty()).collect();
    (2..=3).filter(|&k| parts.len() > k).find_map(|k| {
        let link = proc_magic_link(&parts[..k].join(&b'/'))?;
        Some((link, parts[k..].join(&b'/')))
    })
}

/// fwe's directory of the device nodes Linux has and the host does not
/// (`full`, the loop devices), with node `name` (of `node`) made in it on
/// first use.
fn fwe_device(name: &[u8], node: crate::devnodes::Node) -> Result<Vec<u8>, i32> {
    let dir = mounts::join(&shm::user_dir()?, format!("v{}-dev", crate::shared::FORMAT).as_bytes());
    let d = cstr(&dir)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(d.as_ptr(), 0o755) };
    let fd = open_host_dir(&dir)?;
    // Linux's modes: anyone may use /dev/full, only root and the disk
    // group a disk.
    let perm = if node.kind == crate::devnodes::S_IFCHR && node.major == 1 { 0o666 } else { 0o660 };
    match crate::devnodes::make_exact(fd.as_raw_fd(), &cstr(name)?, node, perm) {
        Ok(()) | Err(errno::EEXIST) => Ok(dir),
        Err(e) => Err(e),
    }
}

/// `/dev/full`'s numbers.
fn full_node() -> crate::devnodes::Node {
    crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: 1, minor: 7 }
}

/// The directory holding what mount `m` shows, open, and that entry's name:
/// within the rootfs, reached a component at a time without following a
/// link; elsewhere (fwe's own directories, a host device), by its path.
fn mount_parent(v: &View, m: &Mount) -> Result<(OwnedFd, Vec<u8>), i32> {
    let Source::Host(base) = &m.source else { return Err(errno::ENOENT) };
    if base == v.root_host {
        let mut comps = components(&m.root);
        let Some(name) = comps.pop() else {
            // The rootfs itself: its parent is out of reach; its own top.
            return Ok((dup_cloexec(v.root)?, b".".to_vec()));
        };
        let mut d = dup_cloexec(v.root)?;
        for c in comps {
            d = open_dir(d.as_raw_fd(), &cstr(&c)?)?;
        }
        return Ok((d, name));
    }
    let host = mounts::join(base, &m.root);
    let (parent, name) = split_host(&host);
    Ok((open_host_dir(&parent)?, name))
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
    let mut r = resolve_in(&v.view(), fcntl::AT_FDCWD as i32, path, follow_final)?;
    if !follow_final {
        // A bind, which makes the socket's node there.
        r.prepare_bind()?;
    }
    let mut host = fd_path(r.dir.as_raw_fd()).ok_or(errno::ENOENT)?;
    if r.name != b"." {
        if host.last() != Some(&b'/') {
            host.push(b'/');
        }
        host.extend_from_slice(&r.name);
    }
    Ok(host)
}

thread_local! {
    /// A FIFO [`open_fifo_unlocked`] opened for this thread's `openat`: its
    /// descriptor, and the Linux flags it was opened with.
    static FIFO: std::cell::Cell<Option<(i32, u64)>> = const { std::cell::Cell::new(None) };
}

/// FIFOs [`open_fifo_unlocked`] holds open for a thread's `openat`, by
/// fwe's descriptor: a fork child closes them, as no `openat` of its takes
/// them.
static PREOPENED: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// In a fork child: close the FIFOs other threads of the parent opened
/// ahead of their `openat` ([`open_fifo_unlocked`]).
pub(crate) fn forked_child_fifos() {
    let fds = std::mem::take(&mut *PREOPENED.lock().unwrap_or_else(|e| e.into_inner()));
    for fd in fds {
        // SAFETY: fwe's own descriptors, inherited.
        unsafe { libc::close(fd) };
    }
    FIFO.with(|f| f.set(None));
}

/// Before an `openat(dirfd, path, flags)` that runs under the kernel lock:
/// if `path` names a FIFO and the open is one that waits for the other end
/// (to read or to write, without `O_NONBLOCK`), open it here, where the
/// wait holds no lock and a signal interrupts it (`EINTR`). The locked
/// open takes the descriptor ([`take_fifo`]). Only paths from the working
/// directory or absolute are looked at (the view that runs without the
/// lock has no descriptors to start from), and only opens that the locked
/// open would not refuse first: not one that must make the file
/// (`O_CREAT|O_EXCL`), of a directory, of a link not to be followed, on a
/// read-only mount to write, of an overlay's file, or of one whose mode fwe
/// keeps aside (whose checks are the locked open's).
pub(crate) fn open_fifo_unlocked(dirfd: i32, path: u64, flags: u64) -> Result<(), i32> {
    use fwe_abi::fcntl as f;
    if flags & (f::O_NONBLOCK | f::O_PATH | f::O_DIRECTORY) != 0
        || flags & f::O_ACCMODE == f::O_RDWR
        || flags & (f::O_CREAT | f::O_EXCL) == f::O_CREAT | f::O_EXCL
    {
        return Ok(());
    }
    let Ok(path) = crate::uaccess::read_cstr(path, crate::uaccess::PATH_MAX) else { return Ok(()) };
    if path.is_empty() || path.first() != Some(&b'/') && dirfd as i64 != fcntl::AT_FDCWD {
        return Ok(());
    }
    let resolved = {
        let view = published();
        let Some(v) = view.as_ref() else { return Ok(()) };
        resolve_in(&v.view(), fcntl::AT_FDCWD as i32, &path, flags & f::O_NOFOLLOW == 0)
    };
    let Ok(r) = resolved else { return Ok(()) };
    let writes = flags & f::O_ACCMODE == f::O_WRONLY;
    if r.ovl.is_some() || writes && r.writable().is_err() || r.name == b"." {
        return Ok(());
    }
    let Ok(name) = r.name_c() else { return Ok(()) };
    // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live directory, a NUL-terminated name, a valid out-parameter.
    let found = unsafe {
        libc::fstatat(r.dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
    } == 0;
    if !found || st.st_mode & libc::S_IFMT != libc::S_IFIFO || crate::modes::marked(&st) {
        return Ok(());
    }
    let access = if writes { libc::O_WRONLY } else { libc::O_RDONLY };
    // SAFETY: as above; waits for the other end.
    let fd = unsafe {
        libc::openat(r.dir.as_raw_fd(), name.as_ptr(), access | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(e());
    }
    // Out of the guest's range while it waits to be taken.
    let fd = crate::fdtable::reserve(fd)?;
    PREOPENED.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
    if let Some((old, _)) = FIFO.with(|f| f.replace(Some((fd, flags)))) {
        forget_preopened(old);
        // SAFETY: one this thread opened and never handed on.
        unsafe { libc::close(old) };
    }
    Ok(())
}

fn forget_preopened(fd: i32) {
    PREOPENED.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
}

/// Close a FIFO [`open_fifo_unlocked`] opened that this thread's `openat`
/// did not take (it failed first), so it holds no end of the FIFO open.
pub(crate) fn drop_fifo() {
    if let Some((fd, _)) = FIFO.with(|f| f.take()) {
        forget_preopened(fd);
        // SAFETY: this thread's own, never handed on.
        unsafe { libc::close(fd) };
    }
}

/// The FIFO [`open_fifo_unlocked`] opened for this thread's `openat` with
/// `flags`, if it is the file `st` describes: the locked open uses it
/// instead of waiting under the lock. Any other is closed.
pub(crate) fn take_fifo(flags: u64, st: &libc::stat) -> Option<i32> {
    let (fd, with) = FIFO.with(|f| f.take())?;
    forget_preopened(fd);
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut own: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    let same = unsafe { libc::fstat(fd, &mut own) } == 0
        && (own.st_dev, own.st_ino) == (st.st_dev, st.st_ino)
        && with & fwe_abi::fcntl::O_ACCMODE == flags & fwe_abi::fcntl::O_ACCMODE;
    // Into the guest's range, at the lowest free number as an open's.
    // SAFETY: plain host calls on fwe's own descriptor.
    let guest = if same { unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) } } else { -1 };
    // SAFETY: this thread's own, never handed on.
    unsafe { libc::close(fd) };
    (guest >= 0).then_some(guest)
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

/// The files of `/proc/self/task/<tid>`.
const TASK_FILES: &[&[u8]] = &[b"stat", b"status", b"comm"];

/// `/proc/self/task/<rest>`: a thread of this process's directory, and in
/// it the thread's `stat` (its own state and CPU time), `comm` and
/// `status` (filled in on open, see `Kernel::task_status`).
fn task_entry(rest: &[u8]) -> crate::procfs::Entry {
    use crate::procfs::Entry;
    let (num, sub) = match rest.iter().position(|&b| b == b'/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, &b""[..]),
    };
    let Some(tid) = std::str::from_utf8(num).ok().and_then(|n| n.parse::<i32>().ok()) else {
        return Entry::Missing;
    };
    if !crate::thread::tids().contains(&tid) {
        return Entry::Missing;
    }
    // SAFETY: getpid cannot fail.
    let host = unsafe { libc::getpid() };
    let comm = || {
        if tid == crate::thread::tid()
            && let Some(name) = crate::thread::name()
        {
            return name.iter().take_while(|&&b| b != 0).copied().collect();
        }
        crate::procreg::read(host).map(|r| r.comm).unwrap_or_default()
    };
    match sub {
        b"" => Entry::Dir,
        b"/stat" => {
            let mut h = crate::procpid::host_info(host).unwrap_or_default();
            if let Some((user, system, running)) = crate::thread::host_state(tid) {
                h.state = if running { b'R' } else { b'S' };
                (h.utime, h.stime) =
                    (crate::procpid::ns_to_ticks(user), crate::procpid::ns_to_ticks(system));
            }
            Entry::File(crate::procpid::stat_line(tid, &comm(), &h))
        }
        b"/comm" => Entry::File([&comm()[..], b"\n"].concat()),
        b"/status" => Entry::File(Vec::new()),
        _ => Entry::Missing,
    }
}

/// A `/proc` path naming a process by pid: `Ok` with the reader's own as
/// `/proc/self/...` (any other path unchanged), or `Err` with another's
/// host pid (if it is in the reader's pid namespace), pid and the rest of
/// the path.
#[allow(clippy::type_complexity)]
fn own_or_other(absolute: &[u8]) -> Result<Vec<u8>, (Option<i32>, i32, Vec<u8>)> {
    let Some(rest) = absolute.strip_prefix(b"/proc/") else { return Ok(absolute.to_vec()) };
    let (num, sub) = match rest.iter().position(|&b| b == b'/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, &b""[..]),
    };
    if num.is_empty() || !num.iter().all(u8::is_ascii_digit) {
        return Ok(absolute.to_vec());
    }
    let Some(pid) = std::str::from_utf8(num).ok().and_then(|n| n.parse::<i32>().ok()) else {
        return Err((None, 0, sub.to_vec()));
    };
    if pid == crate::thread::tgid() {
        return Ok([&b"/proc/self"[..], sub].concat());
    }
    Err((crate::pidns::to_host(pid), pid, sub.to_vec()))
}

/// The host path of the file `fd` is open on.
pub(crate) fn host_path_of(fd: i32) -> Option<Vec<u8>> {
    fd_path(fd)
}

/// The host path of `name` in the directory `dir` is open on (`.` for the
/// directory itself).
pub(crate) fn host_path_in(dir: i32, name: &[u8]) -> Option<Vec<u8>> {
    let d = fd_path(dir)?;
    Some(if name == b"." { d } else { mounts::join(&d, name) })
}

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

/// `/dev/shm`: Linux mounts a tmpfs there that every process on the
/// machine shares. fwe keeps one directory for it per rootfs (the host's
/// `/` included), private to the user, shared by every fwe process that
/// runs on that root: `fwe-<uid>/shm-<hash of the root's host path>` in the
/// user's temporary directory. Unlike a tmpfs it outlives the processes,
/// until the host clears its temporary files.
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
        static DIR: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        if let Some(d) = DIR.get() {
            return Ok(d.clone());
        }
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut base = user_temp();
        if base.last() != Some(&b'/') {
            base.push(b'/');
        }
        base.extend_from_slice(format!("fwe-{uid}").as_bytes());
        ensure_dir(&base, 0o700, true)?;
        // Its canonical path, as the host reports a descriptor's (the user's
        // temporary directory is reached through the `/var` link).
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let canonical = std::fs::canonicalize(std::ffi::OsStr::from_bytes(&base))
            .map(|p| p.into_os_string().into_vec())
            .unwrap_or(base);
        Ok(DIR.get_or_init(|| canonical).clone())
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
#[cfg(test)]
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

/// `dir`, a directory a path was resolved to, moved into fwe's reserved
/// range: held while the call that resolved it runs, it must not take a
/// number the guest's next descriptor would (a file that call opens, or
/// creates, gets the lowest free one, as on Linux). Left where it is if
/// the range is full.
fn out_of_reach(dir: OwnedFd) -> OwnedFd {
    let fd = dir.as_raw_fd();
    if !crate::fdtable::guest_visible(fd) {
        return dir;
    }
    match crate::fdtable::dup_transient(fd) {
        // SAFETY: a fresh descriptor this takes ownership of; `dir` closes
        // the old one.
        Ok(high) => unsafe { OwnedFd::from_raw_fd(high) },
        Err(_) => dir,
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

/// The host path a descriptor refers to (for a stand-in `O_PATH`
/// descriptor, the file it names).
pub(crate) fn fd_path(fd: i32) -> Option<Vec<u8>> {
    if let Some(p) = crate::fdmarks::stand_in(fd) {
        return Some(p);
    }
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
