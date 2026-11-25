//! Overlay mounts: the `overlay` filesystem, which shows a stack of
//! directories (layers) as one.
//!
//! A layer is a host directory or a directory of a filesystem of fwe's
//! store (a tmpfs's, [`crate::filestore`]): [`LDir`] is either, and every
//! step below is taken in either, a copy-up from one to the other too.
//!
//! As on Linux, a name is looked up in the upper layer, then in each lower
//! one in turn: the first file found that is not a directory is the one
//! shown; directories of one name merge, their entries the union of the
//! layers'. A whiteout (a character device numbered 0:0, which fwe keeps
//! as one of its device nodes in a host layer, [`crate::devnodes`], and
//! as itself in the store) hides the name in the layers below it, and an opaque directory (attribute
//! `trusted.overlay.opaque`, or `user.overlay.opaque` with the `userxattr`
//! option, set to `y`) hides what the layers below hold of it. The lower
//! layers are never changed: what is changed is first copied up into the
//! upper layer, its parent directories with it, and what is removed is
//! covered by a whiteout where a lower layer still has it. A directory a
//! lower layer has cannot be renamed (`EXDEV`, as with `redirect_dir=off`):
//! programs copy it instead.
//!
//! Each change is built in the work directory and moved into place with an
//! atomic rename, so another process sees a copy-up whole or not at all,
//! and two that copy one file up at once keep one copy. A file made where
//! a whiteout is takes its place at once: in a host layer it is made under
//! a hidden name in the same directory (so the guest's checks and the new
//! file's group are that directory's) and renamed over the whiteout; in
//! the store, the store's call replaces the whiteout as it makes the file.
//! fwe has no `RENAME_WHITEOUT`: a rename that leaves a whiteout behind is
//! a rename and then the whiteout put in place, so another process can see
//! the lower layer's file at the old name in between.
//!
//! Resolution ([`crate::fs`]) walks an overlay mount with [`lookup`]; the
//! file calls that change one ask [`crate::fs::Resolved::prepare`] for its
//! copy-up first. A directory's entries come from [`list`], served to
//! `getdents64` by [`getdents64`].

use crate::filestore::tree::{self, New};
use crate::fs::StoreDir;
use crate::host::Rename;
use fwe_abi::errno;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

/// `f_type` in `statfs`.
pub const MAGIC: i64 = 0x794c_7630;

/// The most lower layers a mount takes, as on Linux.
const MAX_LOWERS: usize = 500;

/// Where a layer is: a host directory, or a directory of a filesystem of
/// fwe's store (a tmpfs's), by its path from that filesystem's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    Host(Vec<u8>),
    Store { fs: u64, path: Vec<u8> },
}

impl Place {
    /// Its host path, for a host directory.
    pub fn host(&self) -> Option<&[u8]> {
        match self {
            Place::Host(p) => Some(p),
            Place::Store { .. } => None,
        }
    }

    /// The directory, open.
    fn open(&self) -> Result<LDir, i32> {
        match self {
            Place::Host(p) => Ok(LDir::Host(Arc::new(open_host_dir(p)?))),
            Place::Store { fs, path } => Ok(LDir::Store(StoreDir::at(*fs, path)?)),
        }
    }

    /// Whether it is `other` or a directory below it, or above it.
    pub fn nested(&self, other: &Place) -> bool {
        let (a, b) = match (self, other) {
            (Place::Host(a), Place::Host(b)) => (a, b),
            (Place::Store { fs: x, path: a }, Place::Store { fs: y, path: b }) if x == y => (a, b),
            _ => return false,
        };
        crate::mounts::under(a, b).is_some() || crate::mounts::under(b, a).is_some()
    }

    /// Whether it is on the same filesystem as `other` (`dev`: a host
    /// path's device).
    pub fn same_fs(
        &self,
        other: &Place,
        dev: impl Fn(&[u8]) -> Result<u64, i32>,
    ) -> Result<bool, i32> {
        Ok(match (self, other) {
            (Place::Host(a), Place::Host(b)) => dev(a)? == dev(b)?,
            (Place::Store { fs: x, .. }, Place::Store { fs: y, .. }) => x == y,
            _ => false,
        })
    }

    fn encode(&self, e: &mut crate::snapshot::Enc) {
        match self {
            Place::Host(p) => {
                e.bool(false);
                e.bytes(p);
            }
            Place::Store { fs, path } => {
                e.bool(true);
                e.u64(*fs);
                e.bytes(path);
            }
        }
    }

    fn decode(d: &mut crate::snapshot::Dec) -> Place {
        if d.bool() {
            let fs = d.u64();
            Place::Store { fs, path: d.bytes() }
        } else {
            Place::Host(d.bytes())
        }
    }
}

/// An overlay's layers, the upper first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layers {
    /// Where changes go; none for a read-only overlay.
    pub upper: Option<Place>,
    /// The work directory beside it; fwe builds changes in its `work`
    /// subdirectory.
    pub work: Option<Place>,
    /// The lower layers, topmost first.
    pub lowers: Vec<Place>,
    /// The overlay's own attributes are in `user.` (`userxattr`), not
    /// `trusted.`.
    pub userxattr: bool,
}

impl Layers {
    /// Every layer, the upper first.
    pub fn places(&self) -> impl Iterator<Item = &Place> {
        self.upper.iter().chain(self.lowers.iter())
    }

    fn count(&self) -> usize {
        self.lowers.len() + usize::from(self.upper.is_some())
    }

    /// The index of the first lower layer.
    fn first_lower(&self) -> usize {
        usize::from(self.upper.is_some())
    }

    /// The attribute that makes a directory opaque.
    fn opaque_attr(&self) -> &'static [u8] {
        if self.userxattr { b"user.overlay.opaque" } else { b"trusted.overlay.opaque" }
    }

    /// The prefix of the attributes the overlay keeps for itself, which
    /// its files do not show.
    pub fn private_prefix(&self) -> &'static [u8] {
        if self.userxattr { b"user.overlay." } else { b"trusted.overlay." }
    }

    /// A name for the overlay, the same in every process: its upper (or
    /// topmost) layer's.
    pub fn key(&self) -> Vec<u8> {
        let mut e = crate::snapshot::Enc::new();
        self.places().next().expect("a layer").encode(&mut e);
        e.into_bytes()
    }

    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        let opt = |e: &mut crate::snapshot::Enc, v: &Option<Place>| {
            e.bool(v.is_some());
            if let Some(p) = v {
                p.encode(e);
            }
        };
        opt(e, &self.upper);
        opt(e, &self.work);
        e.u64(self.lowers.len() as u64);
        for l in &self.lowers {
            l.encode(e);
        }
        e.bool(self.userxattr);
    }

    pub fn decode(d: &mut crate::snapshot::Dec) -> Layers {
        let opt = |d: &mut crate::snapshot::Dec| d.bool().then(|| Place::decode(d));
        let upper = opt(d);
        let work = opt(d);
        let n = d.count(8);
        let lowers = (0..n).map(|_| Place::decode(d)).collect();
        Layers { upper, work, lowers, userxattr: d.bool() }
    }
}

/// The options an overlay `mount` is given, its directories as the guest
/// named them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub lowers: Vec<Vec<u8>>,
    pub upper: Option<Vec<u8>>,
    pub work: Option<Vec<u8>>,
    pub userxattr: bool,
}

/// Parse an overlay's mount options: `lowerdir=` (layers separated by `:`),
/// `upperdir=`, `workdir=` and `userxattr`, with `\` escaping a `,` or `:`
/// in a path. The options that ask for nothing fwe does differently are
/// accepted; one asking for a feature fwe lacks (`metacopy=on`,
/// `redirect_dir=on`, `index=on`) is `EINVAL`, as on a kernel without it,
/// so a program that probes for it goes on without.
pub fn parse(data: &[u8]) -> Result<Options, i32> {
    let mut o = Options::default();
    for opt in split_escaped(data, b',') {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (&opt[..], None),
        };
        match (key, value) {
            (b"lowerdir", Some(v)) => {
                o.lowers = split_escaped(v, b':').into_iter().map(|p| unescape(&p)).collect();
                if o.lowers.iter().any(Vec::is_empty) {
                    // `::` names data-only layers, which fwe does not have.
                    return Err(errno::EINVAL);
                }
            }
            (b"upperdir", Some(v)) => o.upper = Some(unescape(v)),
            (b"workdir", Some(v)) => o.work = Some(unescape(v)),
            (b"userxattr", None) => o.userxattr = true,
            // Nothing to sync (`volatile`), nothing kept that these turn
            // off, and inode numbers are the layers' own.
            (b"volatile", None)
            | (b"index", Some(b"off"))
            | (b"metacopy", Some(b"off"))
            | (b"redirect_dir", Some(b"off" | b"nofollow"))
            | (b"nfs_export", Some(b"off"))
            | (b"xino", Some(b"off" | b"auto"))
            | (b"uuid", Some(b"on" | b"off" | b"null" | b"auto"))
            | (b"rw" | b"ro", None) => {}
            _ => return Err(errno::EINVAL),
        }
    }
    if o.lowers.is_empty() || o.lowers.len() > MAX_LOWERS {
        return Err(errno::EINVAL);
    }
    if o.upper.is_some() != o.work.is_some() {
        return Err(errno::EINVAL);
    }
    Ok(o)
}

/// `s` split at each `sep` not escaped by a `\` (the escapes kept).
fn split_escaped(s: &[u8], sep: u8) -> Vec<Vec<u8>> {
    let mut out = vec![Vec::new()];
    let mut escaped = false;
    for &b in s {
        if !escaped && b == sep {
            out.push(Vec::new());
            continue;
        }
        escaped = !escaped && b == b'\\';
        out.last_mut().expect("one part").push(b);
    }
    out.retain(|p| !p.is_empty() || sep == b':');
    out
}

/// `s` with its `\` escapes removed.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut escaped = false;
    for &b in s {
        if !escaped && b == b'\\' {
            escaped = true;
            continue;
        }
        escaped = false;
        out.push(b);
    }
    out
}

fn e() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

fn cstr(b: &[u8]) -> Result<CString, i32> {
    CString::new(b).map_err(|_| errno::EINVAL)
}

fn stat_at(dir: i32, name: &CStr) -> Result<libc::stat, i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated name and a valid out-parameter.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(e());
    }
    Ok(st)
}

fn stat_fd(fd: i32) -> Result<libc::stat, i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(e());
    }
    Ok(st)
}

fn open_at(dir: i32, name: &CStr, flags: i32) -> Result<OwnedFd, i32> {
    // SAFETY: a NUL-terminated name relative to a live directory.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(e());
    }
    // SAFETY: a fresh descriptor, ours.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir(dir: i32, name: &CStr) -> Result<OwnedFd, i32> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
}

fn open_host_dir(path: &[u8]) -> Result<OwnedFd, i32> {
    open_at(libc::AT_FDCWD, &cstr(path)?, libc::O_RDONLY | libc::O_DIRECTORY)
}

/// A guest's file of a host layer, opened for fwe to read: given back to
/// the host with [`done_with`], which keeps it open while the process
/// holds record locks (closing any descriptor of a file drops them:
/// [`crate::reclocks`]).
fn open_to_read(dir: i32, name: &CStr) -> Result<OwnedFd, i32> {
    open_at(dir, name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
}

/// The end of [`open_to_read`]'s descriptor `fd`.
fn done_with(fd: OwnedFd) {
    if crate::reclocks::held() {
        // Kept, never closed: the guest's locks on the file stay.
        static KEPT: std::sync::Mutex<Vec<OwnedFd>> = std::sync::Mutex::new(Vec::new());
        KEPT.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
    }
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Whether `name` in host directory `dir`, whose metadata is `st`, is a
/// whiteout.
fn host_whiteout(dir: i32, name: &CStr, st: &libc::stat) -> bool {
    if crate::devnodes::marked(st) {
        let node = crate::devnodes::node_at(dir, name);
        return node
            .is_some_and(|n| n.kind == crate::devnodes::S_IFCHR && n.major == 0 && n.minor == 0);
    }
    // A host whose own character devices the layers hold.
    st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == 0
}

/// The attribute of a copied-up file naming the lower file it was copied
/// from (its device and inode): fwe's own, which no guest call sees (on
/// the host, a name outside Linux's namespaces; in the store, one
/// starting with a NUL).
const ORIGIN: &[u8] = b"org.fwe.overlay.origin";
const STORE_ORIGIN: &[u8] = b"\0overlay.origin";

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn id_bytes(st: &libc::stat) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&crate::host::dev_of(st).to_le_bytes());
    b[8..].copy_from_slice(&(st.st_ino as u64).to_le_bytes());
    b
}

fn origin_from(v: &[u8]) -> Option<(u64, u64)> {
    (v.len() == 16).then(|| {
        (
            u64::from_le_bytes(v[..8].try_into().unwrap()),
            u64::from_le_bytes(v[8..].try_into().unwrap()),
        )
    })
}

/// The lower file a copy-up made `fd`'s file of (its device and inode),
/// if it is such a copy.
pub fn origin_of(fd: i32) -> Option<(u64, u64)> {
    if let Some(file) = crate::filestore::desc::of(fd) {
        return origin_in_store(file);
    }
    origin_from(&crate::xattr::get_host(fd, ORIGIN).ok()?)
}

/// [`origin_of`] the file at host path `path` (not followed).
pub fn origin_at(path: &CStr) -> Option<(u64, u64)> {
    origin_from(&crate::xattr::get(&crate::xattr::Target::Path(path), ORIGIN).ok()?)
}

/// [`origin_of`] file `file` of fwe's store.
pub fn origin_in_store(file: crate::filestore::desc::File) -> Option<(u64, u64)> {
    let fs = file.fs().ok()?;
    let v = fs.lock().ok()?.xattr(file.ino, STORE_ORIGIN).ok()?;
    origin_from(&v)
}

/// What is removed from a filesystem of fwe's store goes: its data, and
/// a FIFO's or socket's host node.
fn dispose(fs: u64, g: tree::Gone) {
    if let Some(o) = g.data.filter(|&o| o != 0) {
        crate::filestore::data::remove(o);
    }
    if g.node {
        crate::storenodes::gone(fs, g.ino);
    }
}

/// One directory of a layer: the host's, open, or one of fwe's store.
#[derive(Clone)]
pub enum LDir {
    Host(Arc<OwnedFd>),
    Store(StoreDir),
}

impl std::fmt::Debug for LDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LDir::Host(fd) => write!(f, "Host({})", fd.as_raw_fd()),
            LDir::Store(d) => write!(f, "Store({}:{})", d.fs.id, d.ino),
        }
    }
}

impl LDir {
    /// What `name` in it is (not followed): the host's `stat` of a host
    /// file, the guest's (as the store keeps it) of a file of the store.
    fn stat(&self, name: &[u8]) -> Result<libc::stat, i32> {
        match self {
            LDir::Host(fd) => stat_at(fd.as_raw_fd(), &cstr(name)?),
            LDir::Store(d) => {
                let (ino, _) = d.find(name)?;
                d.host_stat(ino)
            }
        }
    }

    /// What `name` in it (`.` for itself) is as the guest sees it: its
    /// kept mode and owner.
    pub fn guest_stat(&self, name: &[u8]) -> Result<libc::stat, i32> {
        match self {
            LDir::Host(fd) if name == b"." => crate::fs::guest_stat(fd.as_raw_fd()).ok_or_else(e),
            LDir::Host(fd) => crate::fs::guest_stat_at(fd.as_raw_fd(), &cstr(name)?).ok_or_else(e),
            LDir::Store(d) => {
                let (ino, _) = d.find(name)?;
                d.host_stat(ino)
            }
        }
    }

    /// Whether `name` in it, whose status is `st`, is a whiteout.
    fn is_whiteout(&self, name: &[u8], st: &libc::stat) -> bool {
        match self {
            LDir::Host(fd) => cstr(name).is_ok_and(|n| host_whiteout(fd.as_raw_fd(), &n, st)),
            LDir::Store(_) => st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == 0,
        }
    }

    /// Directory `name` in it.
    fn child(&self, name: &[u8]) -> Result<LDir, i32> {
        match self {
            LDir::Host(fd) => Ok(LDir::Host(Arc::new(open_dir(fd.as_raw_fd(), &cstr(name)?)?))),
            LDir::Store(d) => {
                let (ino, st) = d.find(name)?;
                if st.mode & tree::S_IFMT != tree::S_IFDIR {
                    return Err(errno::ENOTDIR);
                }
                Ok(LDir::Store(StoreDir { fs: d.fs.clone(), ino }))
            }
        }
    }

    /// The attribute calls' target of the directory itself.
    fn target(&self) -> crate::xattr::Target<'_> {
        match self {
            LDir::Host(fd) => crate::xattr::Target::Fd(fd.as_raw_fd()),
            LDir::Store(d) => crate::xattr::Target::Store(crate::filestore::desc::File {
                fs: d.fs.id,
                ino: d.ino,
            }),
        }
    }

    /// Whether the directory is opaque.
    fn opaque(&self, l: &Layers) -> bool {
        crate::xattr::get(&self.target(), l.opaque_attr()).is_ok_and(|v| v == b"y")
    }

    /// Make the directory opaque.
    fn set_opaque(&self, l: &Layers) -> Result<(), i32> {
        crate::xattr::set(&self.target(), l.opaque_attr(), b"y", 0)
    }

    /// Its entries (not `.` or `..`, nor fwe's hidden names), with their
    /// Linux types and inode numbers.
    fn entries(&self) -> Result<Vec<(Vec<u8>, u8, u64)>, i32> {
        match self {
            LDir::Host(fd) => Ok(host_entries_ino(fd.as_raw_fd())?
                .into_iter()
                .filter(|(n, _, _)| !crate::tmpfile::hidden_name(n))
                .collect()),
            LDir::Store(d) => {
                let t = d.fs.lock()?;
                Ok(t.list(d.ino, 0, usize::MAX, 0)?
                    .into_iter()
                    .filter(|e| e.name != b"." && e.name != b"..")
                    .map(|e| (e.name, (e.kind >> 12) as u8, e.ino))
                    .collect())
            }
        }
    }

    /// The target of symbolic link `name` in it.
    pub fn readlink(&self, name: &[u8]) -> Result<Vec<u8>, i32> {
        match self {
            LDir::Host(fd) => readlink_at(fd.as_raw_fd(), &cstr(name)?),
            LDir::Store(d) => {
                let (ino, _) = d.find(name)?;
                d.fs.lock()?.readlink(ino)
            }
        }
    }

    /// Make a whiteout at `name` in it.
    fn make_whiteout(&self, name: &[u8]) -> Result<(), i32> {
        match self {
            LDir::Host(fd) => {
                let node =
                    crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: 0, minor: 0 };
                crate::devnodes::make(fd.as_raw_fd(), &cstr(name)?, node, 0o600)
            }
            LDir::Store(d) => {
                let n = New { mode: tree::S_IFCHR, uid: 0, gid: 0, rdev: 0 };
                d.fs.lock()?.create(d.ino, name, &n).map(drop)
            }
        }
    }

    /// Make directory `name` in it, for the overlay's own work (its owner
    /// alone can use it).
    fn mkdir(&self, name: &[u8]) -> Result<(), i32> {
        match self {
            LDir::Host(fd) => {
                let n = cstr(name)?;
                // SAFETY: a NUL-terminated name in a live directory.
                if unsafe { libc::mkdirat(fd.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
                    return Err(e());
                }
                Ok(())
            }
            LDir::Store(d) => {
                let n = New { mode: tree::S_IFDIR | 0o700, uid: 0, gid: 0, rdev: 0 };
                d.fs.lock()?.create(d.ino, name, &n).map(drop)
            }
        }
    }

    /// Rename `from` in it to `to_name` in `to` (of the same layer), as
    /// `how` says.
    fn rename(&self, from: &[u8], to: &LDir, to_name: &[u8], how: Rename) -> Result<(), i32> {
        match (self, to) {
            (LDir::Host(a), LDir::Host(b)) => crate::host::rename_at(
                a.as_raw_fd(),
                &cstr(from)?,
                b.as_raw_fd(),
                &cstr(to_name)?,
                how,
            ),
            (LDir::Store(a), LDir::Store(b)) if a.fs.id == b.fs.id => {
                let flags = match how {
                    Rename::Replace => 0,
                    Rename::NoReplace => 1,
                    Rename::Exchange => 2,
                };
                let gone = a.fs.lock()?.rename(a.ino, from, b.ino, to_name, flags)?;
                if let Some(g) = gone {
                    dispose(a.fs.id, g);
                }
                Ok(())
            }
            _ => Err(errno::EXDEV),
        }
    }

    /// Remove `name` from it: a directory (empty) or another file.
    fn unlink(&self, name: &[u8], dir: bool) -> Result<(), i32> {
        match self {
            LDir::Host(fd) => {
                let n = cstr(name)?;
                let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
                // SAFETY: a NUL-terminated name in a live directory.
                if unsafe { libc::unlinkat(fd.as_raw_fd(), n.as_ptr(), flags) } != 0 {
                    return Err(e());
                }
                Ok(())
            }
            LDir::Store(d) => {
                let gone = d.fs.lock()?.unlink(d.ino, name, dir)?;
                dispose(d.fs.id, gone);
                Ok(())
            }
        }
    }

    /// Remove `name` from it, everything in it first for a directory.
    fn remove_tree(&self, name: &[u8], is_dir: bool) {
        if let LDir::Host(fd) = self {
            if let Ok(n) = cstr(name) {
                remove_host_tree(fd.as_raw_fd(), &n, is_dir);
            }
            return;
        }
        if is_dir && let Ok(d) = self.child(name) {
            for (child, t, _) in d.entries().unwrap_or_default() {
                d.remove_tree(&child, t == libc::DT_DIR);
            }
        }
        let _ = self.unlink(name, is_dir);
    }

    /// Set attribute `attr` of `name` in it (not followed) to `value`.
    fn set_attr_of(&self, name: &[u8], attr: &[u8], value: &[u8]) -> Result<(), i32> {
        match self {
            LDir::Host(fd) => crate::host::at_path(fd.as_raw_fd(), &cstr(name)?, |p| {
                crate::xattr::set(&crate::xattr::Target::Path(p), attr, value, 0)
            })?,
            LDir::Store(d) => {
                let (ino, _) = d.find(name)?;
                d.fs.lock()?.set_xattr(ino, attr, Some(value))
            }
        }
    }
}

/// The entries of the host directory open as `dir` (not `.` or `..`),
/// with their host types and inode numbers.
fn host_entries_ino(dir: i32) -> Result<Vec<(Vec<u8>, u8, u64)>, i32> {
    // A descriptor of its own, which `closedir` closes.
    let own = open_at(dir, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    // SAFETY: a live descriptor whose ownership passes to the stream.
    let stream = unsafe { libc::fdopendir(own.as_raw_fd()) };
    if stream.is_null() {
        return Err(e());
    }
    std::mem::forget(own);
    let mut out = Vec::new();
    loop {
        // SAFETY: a live stream.
        let ent = unsafe { libc::readdir(stream) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `readdir` returned a valid entry, live until the next call.
        let ent = unsafe { &*ent };
        // SAFETY: `d_name` is NUL-terminated.
        let name = unsafe { CStr::from_ptr(ent.d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        out.push((name.to_vec(), ent.d_type, ent.d_ino as u64));
    }
    // SAFETY: the stream is ours.
    unsafe { libc::closedir(stream) };
    Ok(out)
}

fn readlink_at(dir: i32, name: &CStr) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: a valid buffer of its length; a NUL-terminated name.
        let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(e());
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            return Ok(buf);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// The path in the overlay `l` of what descriptor `fd` (open on a file of
/// one of its layers) is: where it is now in its layer, which a rename
/// moves it with.
pub fn path_of(l: &Layers, fd: i32) -> Option<Vec<u8>> {
    let (fs, inner) = match crate::filestore::desc::of(fd) {
        Some(file) => (Some(file.fs), store_path_of(fd, file)?),
        None => (None, crate::fs::host_path_of(fd)?),
    };
    l.places().find_map(|p| {
        let rest = match (p, fs) {
            (Place::Host(p), None) => crate::mounts::under(&inner, p)?,
            (Place::Store { fs: id, path }, Some(fs)) if *id == fs => {
                crate::mounts::under(&inner, path)?
            }
            _ => return None,
        };
        Some(if rest.is_empty() { b"/".to_vec() } else { rest.to_vec() })
    })
}

/// Where descriptor `fd` of `file` of fwe's store is in its filesystem: a
/// directory's path, or the name it was opened at while that is still
/// the file's, else one of its names.
fn store_path_of(fd: i32, file: crate::filestore::desc::File) -> Option<Vec<u8>> {
    let fs = file.fs().ok()?;
    let t = fs.lock().ok()?;
    if t.stat(file.ino).ok()?.mode & tree::S_IFMT == tree::S_IFDIR {
        return t.path(file.ino);
    }
    if let Some((dir, name)) = crate::filestore::desc::place(fd)
        && t.lookup(dir, &name).ok() == Some(file.ino)
        && let Some(p) = t.path(dir)
    {
        return Some(crate::mounts::join(&p, &name));
    }
    t.any_path(file.ino)
}

/// The identity (device, inode) of what `fd` is open on, as copy-ups
/// record it ([`id_bytes`]).
fn fd_id(fd: i32) -> Result<[u8; 16], i32> {
    if let Some(file) = crate::filestore::desc::of(fd) {
        let fs = file.fs()?;
        let t = fs.lock()?;
        let st = crate::filestore::io::host_stat(t.dev(), &t.stat(file.ino)?);
        return Ok(id_bytes(&st));
    }
    Ok(id_bytes(&stat_fd(fd)?))
}

/// The file descriptor `fd` (of one of `l`'s layers) is open on, copied up
/// if it is a lower one: the upper layer's directory holding the copy and
/// its name, or `None` if `fd` is of the upper layer already. `ESTALE` if
/// the file is not where the overlay shows it any more (renamed over).
pub fn copy_up_open(l: &Layers, fd: i32) -> Result<Option<(LDir, Vec<u8>)>, i32> {
    let upper = l.upper.as_ref().ok_or(errno::EROFS)?;
    let path = path_of(l, fd).ok_or(errno::ESTALE)?;
    let in_upper = match (crate::filestore::desc::of(fd), upper) {
        (Some(file), Place::Store { fs, path: up }) => {
            file.fs == *fs
                && store_path_of(fd, file).is_some_and(|p| crate::mounts::under(&p, up).is_some())
        }
        (None, Place::Host(up)) => {
            crate::fs::host_path_of(fd).is_some_and(|h| crate::mounts::under(&h, up).is_some())
        }
        _ => false,
    };
    if in_upper {
        return Ok(None);
    }
    let (parent, name) = split(&path);
    let own = fd_id(fd)?;
    let d = open(l, &parent).map_err(|_| errno::ESTALE)?;
    // Copied up already: the copy is the one that says it is of `fd`'s.
    let shown = match lookup(l, &d, &name)? {
        Found::Other { layer, .. } => d.dirs[layer].clone(),
        Found::Dir(child) => d.dirs[child.top().0].clone(),
        Found::Missing => None,
    };
    let Some(shown) = shown else { return Err(errno::ESTALE) };
    let of = match &shown {
        LDir::Host(dir) => {
            cstr(&name).ok().and_then(|n| open_to_read(dir.as_raw_fd(), &n).ok()).is_some_and(|f| {
                let same = stat_fd(f.as_raw_fd()).is_ok_and(|st| id_bytes(&st) == own)
                    || crate::xattr::get_host(f.as_raw_fd(), ORIGIN).is_ok_and(|v| v == own);
                done_with(f);
                same
            })
        }
        LDir::Store(sd) => sd.find(&name).is_ok_and(|(ino, _)| {
            let file = crate::filestore::desc::File { fs: sd.fs.id, ino };
            sd.host_stat(ino).is_ok_and(|st| id_bytes(&st) == own)
                || origin_in_store(file).is_some_and(|o| {
                    let mut b = [0u8; 16];
                    b[..8].copy_from_slice(&o.0.to_le_bytes());
                    b[8..].copy_from_slice(&o.1.to_le_bytes());
                    b == own
                })
        }),
    };
    if !of {
        return Err(errno::ESTALE);
    }
    let up = copy_up(l, &path)?;
    Ok(Some((up, name)))
}

/// One directory of the overlay: the directory of that path in each layer
/// that has it and shows it (`None` for one that does not, or that an
/// opaque directory or a whiteout above hides).
#[derive(Clone, Debug)]
pub struct Dir {
    pub dirs: Vec<Option<LDir>>,
}

impl Dir {
    /// The topmost layer showing the directory, and its directory there.
    pub fn top(&self) -> (usize, &LDir) {
        self.dirs
            .iter()
            .enumerate()
            .find_map(|(i, f)| f.as_ref().map(|f| (i, f)))
            .expect("a directory is in some layer")
    }

    /// Its directory in the upper layer, if it is there.
    fn upper(&self, l: &Layers) -> Option<&LDir> {
        if l.upper.is_some() { self.dirs[0].as_ref() } else { None }
    }

    /// Whether a lower layer has it.
    pub fn in_lower(&self, l: &Layers) -> bool {
        self.dirs[l.first_lower()..].iter().any(Option::is_some)
    }
}

/// What a name in an overlay directory is.
#[derive(Clone, Debug)]
pub enum Found {
    Missing,
    /// A file that is not a directory, from layer `layer`; `link` if it
    /// is a symbolic link.
    Other {
        layer: usize,
        link: bool,
    },
    Dir(Dir),
}

/// The overlay's root directory: each layer's top directory.
pub fn root(l: &Layers) -> Result<Dir, i32> {
    let mut dirs = Vec::with_capacity(l.count());
    for p in l.places() {
        dirs.push(Some(p.open()?));
    }
    Ok(Dir { dirs })
}

/// Look `name` up in the overlay directory `d`.
pub fn lookup(l: &Layers, d: &Dir, name: &[u8]) -> Result<Found, i32> {
    let mut dirs: Vec<Option<LDir>> = vec![None; d.dirs.len()];
    let mut any_dir = false;
    for (i, ld) in d.dirs.iter().enumerate() {
        let Some(ld) = ld else { continue };
        let st = match ld.stat(name) {
            Ok(st) => st,
            Err(errno::ENOENT) => continue,
            Err(e) => return Err(e),
        };
        if ld.is_whiteout(name, &st) {
            break;
        }
        if !is_dir(&st) {
            if any_dir {
                // A directory above hides it.
                break;
            }
            let link = st.st_mode & libc::S_IFMT == libc::S_IFLNK;
            return Ok(Found::Other { layer: i, link });
        }
        let child = ld.child(name)?;
        let opaque = child.opaque(l);
        dirs[i] = Some(child);
        any_dir = true;
        if opaque {
            break;
        }
    }
    Ok(if any_dir { Found::Dir(Dir { dirs }) } else { Found::Missing })
}

/// The overlay directory at `path` (a path in the overlay, from its root),
/// following no link: `ENOENT` if it is missing, `ENOTDIR` if it is not a
/// directory.
pub fn open(l: &Layers, path: &[u8]) -> Result<Dir, i32> {
    let mut d = root(l)?;
    for c in components(path) {
        d = match lookup(l, &d, &c)? {
            Found::Dir(next) => next,
            Found::Missing => return Err(errno::ENOENT),
            Found::Other { .. } => return Err(errno::ENOTDIR),
        };
    }
    Ok(d)
}

fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty() && c != b".").map(<[u8]>::to_vec).collect()
}

/// `path` split into its parent and final name (`/` and empty for the
/// root).
fn split(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut comps = components(path);
    let name = comps.pop().unwrap_or_default();
    let mut parent = Vec::new();
    for c in comps {
        parent.push(b'/');
        parent.extend_from_slice(&c);
    }
    if parent.is_empty() {
        parent.push(b'/');
    }
    (parent, name)
}

/// A fresh name for a change being built in the work directory.
fn temp_name() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let pid = crate::host::pid();
    format!("#fwe.{pid}.{}", N.fetch_add(1, Ordering::Relaxed)).into_bytes()
}

/// The directory changes are built in: `work` in the work directory.
fn work(l: &Layers) -> Result<LDir, i32> {
    l.work.as_ref().ok_or(errno::EROFS)?.open()?.child(b"work")
}

/// Prepare the work directory of a new mount: its `work` subdirectory,
/// made if missing.
pub fn prepare_work(work_dir: &Place) -> Result<(), i32> {
    match work_dir.open()?.mkdir(b"work") {
        Ok(()) | Err(errno::EEXIST) => Ok(()),
        Err(err) => Err(err),
    }
}

/// What a copy-up keeps of a file, as the guest sees it.
struct Meta {
    /// Its type and permission bits.
    mode: u32,
    owner: (u32, u32),
    /// Access and modification times, in nanoseconds.
    times: (i64, i64),
    /// Its Linux inode flags (`FS_*_FL`).
    flags: u32,
    /// Its attributes in Linux's namespaces, but the overlay's own.
    attrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// `FS_IMMUTABLE_FL`, `FS_APPEND_FL`, `FS_NODUMP_FL`, `FS_NOATIME_FL`.
#[cfg(target_os = "macos")]
const FL_IMMUTABLE: u32 = 0x10;
#[cfg(target_os = "macos")]
const FL_APPEND: u32 = 0x20;
const FL_NODUMP: u32 = 0x40;
const FL_NOATIME: u32 = 0x80;

/// Whether attribute `name` is one a copy-up takes: in one of Linux's
/// namespaces, and not the overlay's own.
fn copied_attr(l: &Layers, name: &[u8]) -> bool {
    [&b"user."[..], b"trusted.", b"security."].iter().any(|p| name.starts_with(p))
        && !name.starts_with(l.private_prefix())
}

/// What a copy-up keeps of `name` in layer directory `d`.
#[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
fn meta_of(l: &Layers, d: &LDir, name: &[u8]) -> Result<Meta, i32> {
    let ns = |t: i64, n: i64| t * 1_000_000_000 + n;
    match d {
        LDir::Host(fd) => {
            let n = cstr(name)?;
            let dir = fd.as_raw_fd();
            let st = crate::fs::guest_stat_at(dir, &n).ok_or_else(e)?;
            let raw = stat_at(dir, &n)?;
            let mut flags = 0;
            #[cfg(target_os = "macos")]
            {
                if raw.st_flags & libc::UF_IMMUTABLE != 0 {
                    flags |= FL_IMMUTABLE;
                }
                if raw.st_flags & libc::UF_APPEND != 0 {
                    flags |= FL_APPEND;
                }
            }
            if crate::modes::nodump_at(dir, &n, &raw) {
                flags |= FL_NODUMP;
            }
            if crate::modes::noatime_at(dir, &n, &raw) {
                flags |= FL_NOATIME;
            }
            let attrs = crate::host::at_path(dir, &n, |p| {
                let t = crate::xattr::Target::Path(p);
                let mut out = Vec::new();
                for a in crate::xattr::names(&t)?.into_iter().filter(|a| copied_attr(l, a)) {
                    out.push((a.clone(), crate::xattr::get(&t, &a)?));
                }
                Ok::<_, i32>(out)
            })??;
            Ok(Meta {
                mode: st.st_mode as u32,
                owner: (st.st_uid, st.st_gid),
                times: (ns(st.st_atime, st.st_atime_nsec), ns(st.st_mtime, st.st_mtime_nsec)),
                flags,
                attrs,
            })
        }
        LDir::Store(sd) => {
            let t = sd.fs.lock()?;
            let ino = t.lookup(sd.ino, name)?;
            let st = t.stat(ino)?;
            let attrs = t.xattrs(ino)?.into_iter().filter(|(a, _)| copied_attr(l, a)).collect();
            Ok(Meta {
                mode: st.mode,
                owner: (st.uid, st.gid),
                times: (st.atime, st.mtime),
                flags: st.flags,
                attrs,
            })
        }
    }
}

/// Make the copy of `name` in `src` (described by `m`) at `tmp` in the
/// work directory `w`, one of the store's or the host's other than
/// `src`'s filesystem.
fn copy_across(src: &LDir, name: &[u8], m: &Meta, w: &LDir, tmp: &[u8]) -> Result<(), i32> {
    let kind = m.mode & tree::S_IFMT;
    let perm = m.mode & 0o7777;
    match w {
        LDir::Store(wd) => {
            let made = {
                let mut t = wd.fs.lock()?;
                let ino = match kind {
                    tree::S_IFLNK => {
                        let target = src.readlink(name)?;
                        t.symlink(wd.ino, tmp, &target, m.owner.0, m.owner.1)?
                    }
                    tree::S_IFDIR | tree::S_IFREG | tree::S_IFIFO => t.create(
                        wd.ino,
                        tmp,
                        &New { mode: kind | perm, uid: m.owner.0, gid: m.owner.1, rdev: 0 },
                    )?,
                    // A socket's node is made only by binding one there, and
                    // a device's by `mknod`.
                    _ => return Err(errno::EOPNOTSUPP),
                };
                for (a, v) in &m.attrs {
                    t.set_xattr(ino, a, Some(v))?;
                }
                ino
            };
            let file = crate::filestore::desc::File { fs: wd.fs.id, ino: made };
            let filled = match kind {
                tree::S_IFREG => copy_data(src, name, &Sink::Store(file)),
                tree::S_IFIFO => crate::storenodes::make(wd, made, kind),
                _ => Ok(()),
            };
            let finished = filled.and_then(|()| {
                let mut t = wd.fs.lock()?;
                t.set_times(made, Some(m.times.0), Some(m.times.1))?;
                t.set_flags(made, m.flags)
            });
            if let Err(err) = finished {
                w.remove_tree(tmp, kind == tree::S_IFDIR);
                return Err(err);
            }
            Ok(())
        }
        LDir::Host(wfd) => {
            let wdir = wfd.as_raw_fd();
            let t = cstr(tmp)?;
            let host = crate::modes::host_perm(perm, kind == tree::S_IFDIR) as libc::mode_t;
            // SAFETY: NUL-terminated names in a live directory.
            let r = unsafe {
                match kind {
                    tree::S_IFDIR => libc::mkdirat(wdir, t.as_ptr(), host),
                    tree::S_IFIFO => libc::mkfifoat(wdir, t.as_ptr(), host),
                    tree::S_IFLNK => {
                        let target = cstr(&src.readlink(name)?)?;
                        libc::symlinkat(target.as_ptr(), wdir, t.as_ptr())
                    }
                    tree::S_IFREG => {
                        let flags =
                            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
                        let fd = libc::openat(
                            wdir,
                            t.as_ptr(),
                            flags | libc::O_CLOEXEC,
                            host as libc::c_uint,
                        );
                        if fd >= 0 {
                            libc::close(fd);
                        }
                        fd.min(0)
                    }
                    _ => return Err(errno::EOPNOTSUPP),
                }
            };
            if r != 0 {
                return Err(e());
            }
            let finished = (|| {
                if kind == tree::S_IFREG {
                    let out = open_at(wdir, &t, libc::O_WRONLY | libc::O_NOFOLLOW)?;
                    copy_data(src, name, &Sink::Host(out.as_raw_fd()))?;
                }
                if kind != tree::S_IFLNK && host as u32 != perm {
                    crate::modes::keep_at(wdir, &t, perm)?;
                }
                crate::owners::keep_at(wdir, &t, m.owner)?;
                crate::host::at_path(wdir, &t, |p| {
                    let target = crate::xattr::Target::Path(p);
                    for (a, v) in &m.attrs {
                        crate::xattr::set(&target, a, v, 0)?;
                    }
                    Ok::<_, i32>(())
                })??;
                let split = |ns: i64| libc::timespec {
                    tv_sec: ns.div_euclid(1_000_000_000) as libc::time_t,
                    tv_nsec: ns.rem_euclid(1_000_000_000) as libc::c_long,
                };
                let times = [split(m.times.0), split(m.times.1)];
                // SAFETY: a NUL-terminated name; a valid times array.
                unsafe {
                    libc::utimensat(wdir, t.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW)
                };
                // The inode flags, last: an immutable copy takes no more.
                #[cfg(target_os = "macos")]
                if kind != tree::S_IFLNK {
                    let at = |flag, on| {
                        crate::host::at_path(wdir, &t, |p| crate::modes::set_flag_path(p, flag, on))
                    };
                    if m.flags & FL_NODUMP != 0 {
                        at(crate::modes::Flag::NoDump, true)??;
                    }
                    if m.flags & FL_NOATIME != 0 {
                        at(crate::modes::Flag::NoAtime, true)??;
                    }
                    {
                        let mut f = 0;
                        if m.flags & FL_IMMUTABLE != 0 {
                            f |= libc::UF_IMMUTABLE;
                        }
                        if m.flags & FL_APPEND != 0 {
                            f |= libc::UF_APPEND;
                        }
                        if f != 0 {
                            crate::host::at_path(wdir, &t, |p| {
                                // SAFETY: a NUL-terminated path, not followed.
                                if unsafe { libc::lchflags(p.as_ptr(), f) } != 0 {
                                    Err(e())
                                } else {
                                    Ok(())
                                }
                            })??;
                        }
                    }
                }
                Ok(())
            })();
            if let Err(err) = finished {
                w.remove_tree(tmp, kind == tree::S_IFDIR);
                return Err(err);
            }
            Ok(())
        }
    }
}

/// Where a copy-up's bytes go.
enum Sink {
    Host(i32),
    Store(crate::filestore::desc::File),
}

/// Copy the bytes of regular file `name` in `src` to `sink`.
fn copy_data(src: &LDir, name: &[u8], sink: &Sink) -> Result<(), i32> {
    let put = |off: u64, bytes: &[u8]| -> Result<(), i32> {
        match sink {
            Sink::Host(fd) => {
                let mut done = 0;
                while done < bytes.len() {
                    // SAFETY: the bytes given, within their length.
                    let w = unsafe {
                        libc::pwrite(
                            *fd,
                            bytes[done..].as_ptr().cast(),
                            bytes.len() - done,
                            (off + done as u64) as libc::off_t,
                        )
                    };
                    if w < 0 {
                        return Err(e());
                    }
                    done += w as usize;
                }
                Ok(())
            }
            Sink::Store(file) => crate::filestore::io::write_for_fwe(*file, off, bytes),
        }
    };
    match src {
        LDir::Host(dir) => {
            let f = open_to_read(dir.as_raw_fd(), &cstr(name)?)?;
            let mut buf = vec![0u8; 1 << 16];
            let mut off = 0u64;
            let r = loop {
                // SAFETY: a valid buffer of its length.
                let n = unsafe {
                    libc::pread(
                        f.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        off as libc::off_t,
                    )
                };
                if n < 0 {
                    break Err(e());
                }
                if n == 0 {
                    break Ok(());
                }
                if let Err(err) = put(off, &buf[..n as usize]) {
                    break Err(err);
                }
                off += n as u64;
            };
            done_with(f);
            r
        }
        LDir::Store(sd) => {
            let (ino, st) = sd.find(name)?;
            let file = crate::filestore::desc::File { fs: sd.fs.id, ino };
            let mut off = 0u64;
            while off < st.size {
                let len = (st.size - off).min(1 << 16);
                let bytes = crate::filestore::io::read_for_fwe(file, off, len)?;
                if bytes.is_empty() {
                    break;
                }
                put(off, &bytes)?;
                off += bytes.len() as u64;
            }
            Ok(())
        }
    }
}

/// Copy the lower layer's `name` in `src` up to `name` in the upper
/// layer's `dst`, built in the work directory and moved into place, as
/// another process's copy of it might be already.
fn copy_one(l: &Layers, src: &LDir, name: &[u8], dst: &LDir) -> Result<(), i32> {
    let w = work(l)?;
    let tmp = temp_name();
    let st = src.stat(name)?;
    let kind = st.st_mode & libc::S_IFMT;
    match (src, &w) {
        (LDir::Host(s), LDir::Host(wfd)) => {
            copy_host(l, s.as_raw_fd(), &cstr(name)?, &st, wfd.as_raw_fd(), &cstr(&tmp)?)?
        }
        _ => copy_across(src, name, &meta_of(l, src, name)?, &w, &tmp)?,
    }
    if kind != libc::S_IFLNK {
        // Which lower file it is a copy of, for a descriptor of that file
        // to find its copy ([`copy_up_open`]).
        let _ = match &w {
            LDir::Host(_) => w.set_attr_of(&tmp, ORIGIN, &id_bytes(&st)),
            LDir::Store(_) => w.set_attr_of(&tmp, STORE_ORIGIN, &id_bytes(&st)),
        };
    }
    place(&w, &tmp, dst, name, kind == libc::S_IFDIR)
}

/// [`copy_one`] from a host layer into a host work directory: the file
/// cloned where the host can, with every attribute (fwe's own records of
/// its owner and mode among them).
fn copy_host(
    l: &Layers,
    src_dir: i32,
    name: &CStr,
    st: &libc::stat,
    w: i32,
    tmp: &CStr,
) -> Result<(), i32> {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {
            // SAFETY: a NUL-terminated name in a live directory.
            if unsafe { libc::mkdirat(w, tmp.as_ptr(), 0o700) } != 0 {
                return Err(e());
            }
            let made = open_dir(w, tmp)?;
            let src = open_dir(src_dir, name)?;
            if let Err(err) = copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st) {
                remove_host_tree(w, tmp, true);
                return Err(err);
            }
        }
        libc::S_IFREG => {
            // By name: a descriptor of the lower file, closed, would drop
            // the record locks the caller holds on it ([`crate::reclocks`]).
            match crate::host::clone_name_at(src_dir, name, w, tmp) {
                Ok(()) => {
                    // The clone has the attributes; the times are set again
                    // in case the host gave it its own.
                    let made = open_at(w, tmp, libc::O_RDONLY | libc::O_NOFOLLOW)?;
                    let times = [
                        libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
                        libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
                    ];
                    // SAFETY: a valid times array; an open descriptor.
                    unsafe { libc::futimens(made.as_raw_fd(), times.as_ptr()) };
                }
                // Layers on two file systems: the bytes copied.
                Err(errno::EOPNOTSUPP) => {
                    let src = open_to_read(src_dir, name)?;
                    let made = open_at(
                        w,
                        tmp,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    )?;
                    let copied = copy_host_data(src.as_raw_fd(), made.as_raw_fd())
                        .and_then(|()| copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st));
                    done_with(src);
                    if let Err(err) = copied {
                        remove_host_tree(w, tmp, false);
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        libc::S_IFLNK => {
            let target = readlink_at(src_dir, name)?;
            let t = cstr(&target)?;
            // SAFETY: NUL-terminated strings; a live directory.
            if unsafe { libc::symlinkat(t.as_ptr(), w, tmp.as_ptr()) } != 0 {
                return Err(e());
            }
            let times = [
                libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
                libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
            ];
            // SAFETY: as above, with a valid times array.
            unsafe { libc::utimensat(w, tmp.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        }
        libc::S_IFIFO => {
            // SAFETY: a NUL-terminated name in a live directory.
            if unsafe { libc::mkfifoat(w, tmp.as_ptr(), 0o600) } != 0 {
                return Err(e());
            }
            let made = open_at(w, tmp, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW)?;
            let src = open_to_read(src_dir, name)?;
            let copied = copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st);
            done_with(src);
            if let Err(err) = copied {
                remove_host_tree(w, tmp, false);
                return Err(err);
            }
        }
        // A socket's node is made only by binding one there.
        _ => return Err(errno::EOPNOTSUPP),
    }
    Ok(())
}

/// Remove `name` in host directory `dir`, everything in it first for a
/// directory.
fn remove_host_tree(dir: i32, name: &CStr, is_dir: bool) {
    if is_dir && let Ok(d) = open_dir(dir, name) {
        for (child, t, _) in host_entries_ino(d.as_raw_fd()).unwrap_or_default() {
            if let Ok(c) = cstr(&child) {
                remove_host_tree(d.as_raw_fd(), &c, t == libc::DT_DIR);
            }
        }
    }
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: a NUL-terminated name in a live directory.
    unsafe { libc::unlinkat(dir, name.as_ptr(), flags) };
}

/// Copy the metadata a copy-up keeps (owner's view of the mode, flags,
/// times, attributes other than the overlay's own) from `src` to `dst`,
/// both open host files.
fn copy_meta(l: &Layers, src: i32, dst: i32, st: &libc::stat) -> Result<(), i32> {
    copy_xattrs(l, src, dst)?;
    // SAFETY: plain host calls on open descriptors.
    unsafe {
        if libc::fchmod(dst, st.st_mode & 0o7777) != 0 {
            return Err(e());
        }
        let times = [
            libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
            libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
        ];
        libc::futimens(dst, times.as_ptr());
        #[cfg(target_os = "macos")]
        libc::fchflags(dst, st.st_flags);
    }
    Ok(())
}

/// Copy every extended attribute of host file `src` but the overlay's own
/// to `dst`.
fn copy_xattrs(l: &Layers, src: i32, dst: i32) -> Result<(), i32> {
    for name in crate::xattr::names(&crate::xattr::Target::Fd(src))? {
        // The overlay's own, and the host's (which a clone copies).
        if name.starts_with(l.private_prefix()) || name.starts_with(b"com.apple.") {
            continue;
        }
        let value = crate::xattr::get_host(src, &name)?;
        crate::xattr::set_host(dst, &name, &value)?;
    }
    Ok(())
}

fn copy_host_data(src: i32, dst: i32) -> Result<(), i32> {
    let mut buf = vec![0u8; 1 << 16];
    let mut off: libc::off_t = 0;
    loop {
        // SAFETY: a valid buffer of its length.
        let n = unsafe { libc::pread(src, buf.as_mut_ptr().cast(), buf.len(), off) };
        if n < 0 {
            return Err(e());
        }
        if n == 0 {
            return Ok(());
        }
        let mut done = 0;
        while done < n as usize {
            // SAFETY: the bytes just read.
            let w = unsafe {
                libc::pwrite(
                    dst,
                    buf[done..].as_ptr().cast(),
                    n as usize - done,
                    off + done as libc::off_t,
                )
            };
            if w < 0 {
                return Err(e());
            }
            done += w as usize;
        }
        off += n as libc::off_t;
    }
}

/// Move the change built at `tmp` in the work directory `w` to `name` in
/// `dir`, unless another process put one there first (then `tmp` goes).
fn place(w: &LDir, tmp: &[u8], dir: &LDir, name: &[u8], is_dir: bool) -> Result<(), i32> {
    match w.rename(tmp, dir, name, Rename::NoReplace) {
        Ok(()) => Ok(()),
        Err(errno::EEXIST) => {
            w.remove_tree(tmp, is_dir);
            Ok(())
        }
        Err(err) => {
            w.remove_tree(tmp, is_dir);
            Err(err)
        }
    }
}

/// Copy the overlay directory at `path` up, its parents first: its
/// directory in the upper layer.
pub fn upper_dir(l: &Layers, path: &[u8]) -> Result<LDir, i32> {
    if l.upper.is_none() {
        return Err(errno::EROFS);
    }
    let mut d = root(l)?;
    for c in components(path) {
        let up = d.upper(l).expect("copied up").clone();
        d = match lookup(l, &d, &c)? {
            Found::Missing => return Err(errno::ENOENT),
            Found::Other { .. } => return Err(errno::ENOTDIR),
            Found::Dir(mut next) => {
                if next.upper(l).is_none() {
                    let (layer, _) = next.top();
                    // The lower layer's directory holding it.
                    let parent = d.dirs[layer].as_ref().expect("its parent").clone();
                    copy_one(l, &parent, &c, &up)?;
                    next.dirs[0] = Some(up.child(&c)?);
                }
                next
            }
        };
    }
    Ok(d.upper(l).expect("copied up").clone())
}

/// Copy the file at `path` up (a directory, a regular file, a link or a
/// FIFO), its parent directories first: the upper layer's directory
/// holding it. `ENOENT` if it is missing.
pub fn copy_up(l: &Layers, path: &[u8]) -> Result<LDir, i32> {
    let (parent, name) = split(path);
    let up = upper_dir(l, &parent)?;
    if name.is_empty() {
        return Ok(up);
    }
    let d = open(l, &parent)?;
    match lookup(l, &d, &name)? {
        Found::Missing => Err(errno::ENOENT),
        Found::Other { layer, .. } if l.upper.is_some() && layer == 0 => Ok(up),
        Found::Other { layer, .. } => {
            let src = d.dirs[layer].as_ref().expect("its layer").clone();
            copy_one(l, &src, &name, &up)?;
            Ok(up)
        }
        Found::Dir(_) => {
            upper_dir(l, path)?;
            Ok(up)
        }
    }
}

/// Whether a lower layer shows `name` in the overlay directory `d` (so
/// removing it from the upper layer needs a whiteout).
fn lower_has(l: &Layers, d: &Dir, name: &[u8]) -> Result<bool, i32> {
    if l.upper.is_none() {
        return Ok(true);
    }
    // The directory as the lower layers show it: below an opaque upper
    // directory, nothing.
    if d.dirs[0].as_ref().is_some_and(|up| up.opaque(l)) {
        return Ok(false);
    }
    let lower = Dir { dirs: std::iter::once(None).chain(d.dirs[1..].iter().cloned()).collect() };
    if !lower.dirs.iter().any(Option::is_some) {
        return Ok(false);
    }
    Ok(!matches!(lookup(l, &lower, name)?, Found::Missing))
}

/// Where a creation in an overlay goes: `name` in the upper layer's
/// directory. A whiteout there is replaced: in a host layer the file is
/// made under a hidden name beside it ([`Created::target`]), which
/// [`Created::finish`] moves over it; in a layer of fwe's store, the
/// store's own call replaces it as it makes the file
/// ([`Created::over_whiteout`]).
pub struct Created {
    /// The upper layer's directory, and the name.
    pub dir: LDir,
    pub name: Vec<u8>,
    /// The hidden name the file is made at, in a host layer.
    temp: Option<Vec<u8>>,
    /// A whiteout is at the name.
    whiteout: bool,
    /// What makes a directory hide the lower layers' (one that replaces a
    /// whiteout does).
    opaque_attr: &'static [u8],
}

impl Created {
    /// The name to make the file at, in [`Created::dir`].
    pub fn target(&self) -> &[u8] {
        self.temp.as_deref().unwrap_or(&self.name)
    }

    /// In a layer of fwe's store, with a whiteout at the name: the
    /// attribute (set to `y`) a directory made in its place takes, so it
    /// hides the lower layers' ([`crate::storeops`] makes the file in the
    /// whiteout's place, in one change of the filesystem).
    pub fn over_whiteout(&self) -> Option<&'static [u8]> {
        (self.whiteout && matches!(self.dir, LDir::Store(_))).then_some(self.opaque_attr)
    }

    /// Put what was made (`made`) in place, or clear up after a failure.
    pub fn finish(&self, made: bool) -> Result<(), i32> {
        let Some(tmp) = &self.temp else { return Ok(()) };
        let Ok(st) = self.dir.stat(tmp) else { return Ok(()) };
        let dir = is_dir(&st);
        if !made {
            self.dir.remove_tree(tmp, dir);
            return Ok(());
        }
        if !dir {
            // Over the whiteout, atomically.
            return self.dir.rename(tmp, &self.dir, &self.name, Rename::Replace);
        }
        // A directory replacing a whiteout hides what the lower layers
        // have of that name; it takes the whiteout's place in one swap.
        self.dir.set_attr_of(tmp, self.opaque_attr, b"y")?;
        self.dir.rename(tmp, &self.dir, &self.name, Rename::Exchange)?;
        self.dir.remove_tree(tmp, false);
        Ok(())
    }
}

/// Prepare to make `name` in the overlay directory at `parent`: copy the
/// directory up, and see whether a whiteout is in the way.
pub fn create(l: &Layers, parent: &[u8], name: &[u8]) -> Result<Created, i32> {
    let up = upper_dir(l, parent)?;
    let whiteout = up.stat(name).is_ok_and(|st| up.is_whiteout(name, &st));
    let temp = (whiteout && matches!(up, LDir::Host(_))).then(crate::tmpfile::making_name);
    Ok(Created { dir: up, name: name.to_vec(), temp, whiteout, opaque_attr: l.opaque_attr() })
}

/// Remove `name` from the overlay directory at `parent`: a directory
/// (`rmdir`, which needs it to show no entries) or another file (`unlink`).
pub fn remove(l: &Layers, parent: &[u8], name: &[u8], rmdir: bool) -> Result<(), i32> {
    let d = open(l, parent)?;
    let found = lookup(l, &d, name)?;
    let in_upper = match &found {
        Found::Missing => return Err(errno::ENOENT),
        Found::Other { .. } if rmdir => return Err(errno::ENOTDIR),
        Found::Dir(_) if !rmdir => return Err(errno::EISDIR),
        Found::Other { layer, .. } => l.upper.is_some() && *layer == 0,
        Found::Dir(child) => {
            if !list(child)?.is_empty() {
                return Err(errno::ENOTEMPTY);
            }
            child.upper(l).is_some()
        }
    };
    let up = upper_dir(l, parent)?;
    if lower_has(l, &d, name)? {
        // A whiteout takes its place.
        let w = work(l)?;
        let tmp = temp_name();
        w.make_whiteout(&tmp)?;
        let r = match (in_upper, rmdir) {
            (false, _) => w.rename(&tmp, &up, name, Rename::NoReplace),
            (true, false) => w.rename(&tmp, &up, name, Rename::Replace),
            (true, true) => w.rename(&tmp, &up, name, Rename::Exchange),
        };
        // What was swapped out (an upper directory of whiteouts), or the
        // whiteout itself if it could not be placed.
        let swapped = r.is_ok() && in_upper && rmdir;
        if r.is_err() || swapped {
            w.remove_tree(&tmp, swapped);
        }
        return r;
    }
    if rmdir {
        // Only whiteouts are left in it.
        if let Ok(child) = up.child(name) {
            for (entry, t, _) in child.entries()? {
                child.remove_tree(&entry, t == libc::DT_DIR);
            }
        }
    }
    up.unlink(name, rmdir)
}

/// `renameat2` within one overlay: `from` (`(parent, name)`) to `to`, with
/// [`crate::host::Rename`]'s modes.
pub fn rename(
    l: &Layers,
    from: (&[u8], &[u8]),
    to: (&[u8], &[u8]),
    how: Rename,
) -> Result<(), i32> {
    let (fname, tname) = (from.1, to.1);
    let fd = open(l, from.0)?;
    let td = open(l, to.0)?;
    let src = lookup(l, &fd, fname)?;
    let dst = lookup(l, &td, tname)?;
    if matches!(src, Found::Missing) {
        return Err(errno::ENOENT);
    }
    let dst_exists = !matches!(dst, Found::Missing);
    match how {
        Rename::NoReplace if dst_exists => return Err(errno::EEXIST),
        Rename::Exchange if !dst_exists => return Err(errno::ENOENT),
        _ => {}
    }
    if from == to {
        return Ok(());
    }
    // A directory a lower layer has cannot move: fwe keeps no redirects.
    let lower_dir = |f: &Found| matches!(f, Found::Dir(d) if d.in_lower(l));
    if lower_dir(&src) || how == Rename::Exchange && lower_dir(&dst) {
        return Err(errno::EXDEV);
    }
    if how != Rename::Exchange {
        match (&src, &dst) {
            (Found::Dir(_), Found::Other { .. }) => return Err(errno::ENOTDIR),
            (Found::Other { .. }, Found::Dir(_)) => return Err(errno::EISDIR),
            (Found::Dir(_), Found::Dir(d)) if !list(d)?.is_empty() => {
                return Err(errno::ENOTEMPTY);
            }
            _ => {}
        }
    }
    let from_path = crate::mounts::join(from.0, from.1);
    let to_path = crate::mounts::join(to.0, to.1);
    let uf = copy_up(l, &from_path)?;
    let ut = if how == Rename::Exchange { copy_up(l, &to_path)? } else { upper_dir(l, to.0)? };
    if how == Rename::Exchange {
        // Both names stay. A directory moved to a name the lower layers
        // have hides theirs.
        for (found, dir, name, lower) in [
            (&src, &uf, fname, lower_has(l, &td, tname)?),
            (&dst, &ut, tname, lower_has(l, &fd, fname)?),
        ] {
            if lower && matches!(found, Found::Dir(_)) {
                dir.set_attr_of(name, l.opaque_attr(), b"y")?;
            }
        }
        return uf.rename(fname, &ut, tname, Rename::Exchange);
    }
    let src_lower = lower_has(l, &fd, fname)?;
    let dst_lower = lower_has(l, &td, tname)?;
    if let Found::Dir(_) = src
        && dst_lower
    {
        // Moved over a name the lower layers have: it hides theirs.
        uf.set_attr_of(fname, l.opaque_attr(), b"y")?;
        if let Ok(old) = ut.child(tname) {
            // The upper directory it replaces holds only whiteouts, which
            // need to go for the rename to take its place.
            old.set_opaque(l)?;
            for (entry, t, _) in old.entries()? {
                old.remove_tree(&entry, t == libc::DT_DIR);
            }
        }
    }
    let over_whiteout =
        matches!(dst, Found::Missing) && ut.stat(tname).is_ok_and(|st| ut.is_whiteout(tname, &st));
    if over_whiteout && matches!(src, Found::Dir(_)) {
        // A directory cannot replace the whiteout file: they swap, and the
        // whiteout is left at the old name, where it is wanted if a lower
        // layer has that name.
        uf.rename(fname, &ut, tname, Rename::Exchange)?;
        if !src_lower {
            uf.remove_tree(fname, false);
        }
        return Ok(());
    }
    uf.rename(fname, &ut, tname, Rename::Replace)?;
    if src_lower {
        let w = work(l)?;
        let tmp = temp_name();
        w.make_whiteout(&tmp)?;
        if let Err(err) = w.rename(&tmp, &uf, fname, Rename::NoReplace) {
            w.remove_tree(&tmp, false);
            return Err(err);
        }
    }
    Ok(())
}

/// One entry of an overlay directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    /// Linux's `d_type`.
    pub kind: u8,
    pub ino: u64,
}

/// The entries the overlay directory `d` shows (not `.` and `..`): the
/// union of its layers', without whiteouts and what they hide.
pub fn list(d: &Dir) -> Result<Vec<Entry>, i32> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for ld in d.dirs.iter().flatten() {
        for (name, t, ino) in ld.entries()? {
            if !seen.insert(name.clone()) {
                continue;
            }
            let mut kind = t;
            if matches!(t, libc::DT_REG | libc::DT_CHR | libc::DT_UNKNOWN) {
                let Ok(st) = ld.stat(&name) else { continue };
                if ld.is_whiteout(&name, &st) {
                    continue;
                }
                let LDir::Host(fd) = ld else {
                    out.push(Entry { name, kind, ino });
                    continue;
                };
                let (fd, n) = (fd.as_raw_fd(), cstr(&name)?);
                if let Some(node) =
                    crate::devnodes::marked(&st).then(|| crate::devnodes::node_at(fd, &n)).flatten()
                {
                    // One of fwe's device nodes lists as the device.
                    kind = if node.kind == crate::devnodes::S_IFBLK {
                        libc::DT_BLK
                    } else {
                        libc::DT_CHR
                    };
                }
            }
            out.push(Entry { name, kind, ino });
        }
    }
    Ok(out)
}

/// The listing an open overlay directory reads, and how far it has read.
struct Cursor {
    /// The directory, to tell a listing from a reused descriptor number's.
    id: (u64, u64),
    /// Read when first needed, and again after a seek to the start.
    entries: Option<Vec<Entry>>,
    offset: usize,
}

/// The device and inode of what `fd` is open on (a file of fwe's store's
/// its filesystem and inode).
#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(fd: i32) -> Option<(u64, u64)> {
    if let Some(file) = crate::filestore::desc::of(fd) {
        return Some((file.fs, file.ino));
    }
    stat_fd(fd).ok().map(|st| (crate::host::dev_of(&st), st.st_ino as u64))
}

static CURSORS: crate::kept::Kept<Option<std::collections::HashMap<i32, Cursor>>> =
    crate::kept::Kept::new(None);

fn cursors<R>(f: impl FnOnce(&mut std::collections::HashMap<i32, Cursor>) -> R) -> R {
    let mut g = CURSORS.lock();
    f(g.get_or_insert_with(Default::default))
}

/// Run `f` holding the cursors' lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = CURSORS.lock();
    f()
}

/// `getdents64` on overlay directory `fd`, whose entries [`list`] gives
/// (`entries`, asked for when its listing is first read or read again
/// from the start): `.` and `..`, then the overlay's, each entry's offset
/// its index.
pub fn getdents64(
    fd: i32,
    buf: u64,
    count: u64,
    entries: impl FnOnce() -> Result<Vec<Entry>, i32>,
) -> i64 {
    const HEADER: usize = fwe_abi::DIRENT64_HEADER;
    let Some(id) = identity(fd) else { return fwe_abi::err(errno::EBADF) };
    let unread = cursors(|m| {
        let c = m.entry(fd).or_insert(Cursor { id, entries: None, offset: 0 });
        if c.id != id {
            *c = Cursor { id, entries: None, offset: 0 };
        }
        c.entries.is_none()
    });
    if unread {
        let mut all = vec![
            Entry { name: b".".to_vec(), kind: libc::DT_DIR, ino: id.1 },
            Entry { name: b"..".to_vec(), kind: libc::DT_DIR, ino: 1 },
        ];
        match entries() {
            Ok(e) => all.extend(e),
            Err(err) => return fwe_abi::err(err),
        }
        cursors(|m| {
            if let Some(c) = m.get_mut(&fd) {
                c.entries = Some(all);
            }
        });
    }
    cursors(|m| {
        let Some(c) = m.get_mut(&fd) else { return fwe_abi::err(errno::EBADF) };
        let Some(entries) = &c.entries else { return fwe_abi::err(errno::EBADF) };
        let mut out = Vec::new();
        let mut i = c.offset;
        while let Some(ent) = entries.get(i) {
            let reclen = (HEADER + ent.name.len() + 1 + 7) & !7;
            if out.len() + reclen > count as usize {
                break;
            }
            let start = out.len();
            out.resize(start + reclen, 0);
            let rec = &mut out[start..];
            rec[0..8].copy_from_slice(&ent.ino.to_ne_bytes());
            rec[8..16].copy_from_slice(&((i + 1) as i64).to_ne_bytes());
            rec[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
            rec[18] = ent.kind;
            rec[HEADER..HEADER + ent.name.len()].copy_from_slice(&ent.name);
            i += 1;
        }
        if out.is_empty() && i < entries.len() {
            return fwe_abi::err(errno::EINVAL);
        }
        if let Err(err) = crate::uaccess::write_from(buf, &out) {
            return fwe_abi::err(err);
        }
        c.offset = i;
        out.len() as i64
    })
}

/// `lseek` on overlay directory `fd`: an offset is an index into its
/// listing, and seeking to 0 reads the directory again.
pub fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let Some(id) = identity(fd) else { return fwe_abi::err(errno::EBADF) };
    cursors(|m| {
        let c = m.entry(fd).or_insert(Cursor { id, entries: None, offset: 0 });
        if c.id != id {
            *c = Cursor { id, entries: None, offset: 0 };
        }
        let to = match whence {
            libc::SEEK_SET => offset,
            libc::SEEK_CUR => c.offset as i64 + offset,
            _ => return fwe_abi::err(errno::EINVAL),
        };
        if to < 0 {
            return fwe_abi::err(errno::EINVAL);
        }
        if to == 0 {
            c.entries = None;
        }
        c.offset = to as usize;
        to
    })
}

/// Directory `fd` was moved onto its copy-up: its listing is the same
/// directory's, read on from where it was.
pub fn moved(fd: i32) {
    let Some(id) = identity(fd) else { return };
    cursors(|m| {
        if let Some(c) = m.get_mut(&fd) {
            c.id = id;
        }
    });
}

/// `fd` was closed (or replaced): its listing goes.
pub fn closed(fd: i32) {
    if let Some(mut g) = CURSORS.if_used()
        && let Some(m) = g.as_mut()
    {
        m.remove(&fd);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    struct Tree(std::path::PathBuf);

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tree() -> (Tree, Layers) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "fwe-ovl-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["lower1", "lower2", "upper", "work"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let p = |d: &str| Place::Host(base.join(d).into_os_string().into_encoded_bytes());
        prepare_work(&p("work")).unwrap();
        let l = Layers {
            upper: Some(p("upper")),
            work: Some(p("work")),
            lowers: vec![p("lower1"), p("lower2")],
            userxattr: false,
        };
        (Tree(base), l)
    }

    fn names(l: &Layers, path: &[u8]) -> Vec<String> {
        let mut v: Vec<String> = list(&open(l, path).unwrap())
            .unwrap()
            .into_iter()
            .map(|e| String::from_utf8(e.name).unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn parses_options() {
        let o = parse(b"lowerdir=/a\\:b:/c,upperdir=/u,workdir=/w,index=off,volatile").unwrap();
        assert_eq!(o.lowers, vec![b"/a:b".to_vec(), b"/c".to_vec()]);
        assert_eq!(o.upper.as_deref(), Some(&b"/u"[..]));
        assert_eq!(parse(b"lowerdir=/a,metacopy=on"), Err(errno::EINVAL));
        assert_eq!(parse(b"upperdir=/u,workdir=/w"), Err(errno::EINVAL));
        assert_eq!(parse(b"lowerdir=/a,upperdir=/u"), Err(errno::EINVAL));
        assert_eq!(parse(b"lowerdir=/a::/b"), Err(errno::EINVAL));
    }

    /// Lookups and listings merge the layers; whiteouts and opaque
    /// directories hide what is below them.
    #[test]
    fn merges_layers() {
        let (t, l) = tree();
        let b = &t.0;
        std::fs::create_dir_all(b.join("lower2/d/old")).unwrap();
        std::fs::write(b.join("lower2/d/gone"), "x").unwrap();
        std::fs::write(b.join("lower2/d/f"), "2").unwrap();
        std::fs::create_dir_all(b.join("lower1/d")).unwrap();
        std::fs::write(b.join("lower1/d/f"), "1").unwrap();
        std::fs::create_dir_all(b.join("lower1/o")).unwrap();
        std::fs::create_dir_all(b.join("lower2/o")).unwrap();
        std::fs::write(b.join("lower2/o/hidden"), "").unwrap();
        std::fs::write(b.join("lower1/o/shown"), "").unwrap();
        let o = open_host_dir(b.join("lower1/o").as_os_str().as_encoded_bytes()).unwrap();
        crate::xattr::set_host(o.as_raw_fd(), b"trusted.overlay.opaque", b"y").unwrap();
        std::fs::create_dir_all(b.join("upper/d")).unwrap();
        let up = open_host_dir(b.join("upper/d").as_os_str().as_encoded_bytes()).unwrap();
        LDir::Host(Arc::new(up)).make_whiteout(b"gone").unwrap();
        assert_eq!(names(&l, b"/d"), ["f", "old"]);
        assert_eq!(names(&l, b"/o"), ["shown"]);
        let d = open(&l, b"/d").unwrap();
        assert!(matches!(lookup(&l, &d, b"gone").unwrap(), Found::Missing));
        assert!(matches!(lookup(&l, &d, b"f").unwrap(), Found::Other { layer: 1, .. }));
    }

    /// A change copies up, a removal leaves a whiteout, and a lower
    /// directory cannot be renamed.
    #[test]
    fn copies_up_and_removes() {
        let (t, l) = tree();
        let b = &t.0;
        std::fs::create_dir_all(b.join("lower1/a/b")).unwrap();
        std::fs::write(b.join("lower1/a/b/f"), "data").unwrap();
        std::fs::write(b.join("lower1/a/g"), "g").unwrap();
        copy_up(&l, b"/a/b/f").unwrap();
        assert_eq!(std::fs::read(b.join("upper/a/b/f")).unwrap(), b"data");
        // The lower layer is untouched, and the work directory clean.
        assert_eq!(std::fs::read(b.join("lower1/a/b/f")).unwrap(), b"data");
        assert_eq!(std::fs::read_dir(b.join("work/work")).unwrap().count(), 0);
        remove(&l, b"/a", b"g", false).unwrap();
        assert_eq!(names(&l, b"/a"), ["b"]);
        assert!(b.join("lower1/a/g").exists());
        assert_eq!(remove(&l, b"/a", b"b", true), Err(errno::ENOTEMPTY));
        remove(&l, b"/a/b", b"f", false).unwrap();
        remove(&l, b"/a", b"b", true).unwrap();
        assert!(names(&l, b"/a").is_empty());
        use crate::host::Rename;
        std::fs::create_dir_all(b.join("lower1/m")).unwrap();
        assert_eq!(rename(&l, (b"/", b"m"), (b"/", b"n"), Rename::Replace), Err(errno::EXDEV));
        // A new directory where a whiteout is hides the lower one's entries.
        std::fs::write(b.join("lower1/m/x"), "").unwrap();
        remove(&l, b"/m", b"x", false).unwrap();
        remove(&l, b"/", b"m", true).unwrap();
        let c = create(&l, b"/", b"m").unwrap();
        let LDir::Host(dir) = &c.dir else { panic!("a host layer") };
        // Made under a hidden name beside the whiteout, not in it.
        assert_ne!(c.target(), b"m");
        let name = cstr(c.target()).unwrap();
        // SAFETY: a NUL-terminated name in a live directory.
        assert_eq!(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) }, 0);
        c.finish(true).unwrap();
        assert!(names(&l, b"/m").is_empty());
        std::fs::write(b.join("lower1/y"), "y").unwrap();
        rename(&l, (b"/", b"y"), (b"/m", b"z"), Rename::Replace).unwrap();
        assert_eq!(names(&l, b"/m"), ["z"]);
        assert!(!names(&l, b"/").contains(&"y".to_string()));
    }
}
