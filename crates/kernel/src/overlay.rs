//! Overlay mounts: the `overlay` filesystem, which shows a stack of
//! directories (layers) as one.
//!
//! As on Linux, a name is looked up in the upper layer, then in each lower
//! one in turn: the first file found that is not a directory is the one
//! shown; directories of one name merge, their entries the union of the
//! layers'. A whiteout (a character device numbered 0:0, which fwe keeps
//! as one of its device nodes, [`crate::devnodes`]) hides the name in the
//! layers below it, and an opaque directory (attribute
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
//! and two that copy one file up at once keep one copy. fwe has no
//! `RENAME_WHITEOUT`: a rename that leaves a whiteout behind is a rename
//! and then the whiteout put in place, so another process can see the
//! lower layer's file at the old name in between.
//!
//! Resolution ([`crate::fs`]) walks an overlay mount with [`lookup`]; the
//! file calls that change one ask [`crate::fs::Resolved::prepare`] for its
//! copy-up first. A directory's entries come from [`list`], served to
//! `getdents64` by [`getdents64`].

use fwe_abi::errno;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

/// `f_type` in `statfs`.
pub const MAGIC: i64 = 0x794c_7630;

/// The most lower layers a mount takes, as on Linux.
const MAX_LOWERS: usize = 500;

/// An overlay's layers: host directories, the upper first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layers {
    /// Where changes go; none for a read-only overlay.
    pub upper: Option<Vec<u8>>,
    /// The work directory beside it; fwe builds changes in its `work`
    /// subdirectory.
    pub work: Option<Vec<u8>>,
    /// The lower layers, topmost first.
    pub lowers: Vec<Vec<u8>>,
    /// The overlay's own attributes are in `user.` (`userxattr`), not
    /// `trusted.`.
    pub userxattr: bool,
}

impl Layers {
    /// Every layer's host directory, the upper first.
    pub fn paths(&self) -> impl Iterator<Item = &[u8]> {
        self.upper.iter().chain(self.lowers.iter()).map(Vec::as_slice)
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

    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        let opt = |e: &mut crate::snapshot::Enc, v: &Option<Vec<u8>>| {
            e.bool(v.is_some());
            e.bytes(v.as_deref().unwrap_or_default());
        };
        opt(e, &self.upper);
        opt(e, &self.work);
        e.u64(self.lowers.len() as u64);
        for l in &self.lowers {
            e.bytes(l);
        }
        e.bool(self.userxattr);
    }

    pub fn decode(d: &mut crate::snapshot::Dec) -> Layers {
        let opt = |d: &mut crate::snapshot::Dec| {
            let some = d.bool();
            let v = d.bytes();
            some.then_some(v)
        };
        let upper = opt(d);
        let work = opt(d);
        let n = d.count(8);
        let lowers = (0..n).map(|_| d.bytes()).collect();
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

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Whether `name` in `dir`, whose metadata is `st`, is a whiteout.
fn whiteout(dir: i32, name: &CStr, st: &libc::stat) -> bool {
    if crate::devnodes::marked(st) {
        let node = crate::devnodes::node_at(dir, name);
        return node
            .is_some_and(|n| n.kind == crate::devnodes::S_IFCHR && n.major == 0 && n.minor == 0);
    }
    // A host whose own character devices the layers hold.
    st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == 0
}

/// Make a whiteout at `name` in `dir`.
fn make_whiteout(dir: i32, name: &CStr) -> Result<(), i32> {
    let node = crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: 0, minor: 0 };
    crate::devnodes::make(dir, name, node, 0o600)
}

/// The attribute of a copied-up file naming the lower file it was copied
/// from (its device and inode): fwe's own, which no guest call sees.
const ORIGIN: &[u8] = b"org.fwe.overlay.origin";

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn id_bytes(st: &libc::stat) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(st.st_dev as u64).to_le_bytes());
    b[8..].copy_from_slice(&(st.st_ino as u64).to_le_bytes());
    b
}

/// The lower file a copy-up made `fd`'s file of (its device and inode),
/// if it is such a copy.
pub fn origin_of(fd: i32) -> Option<(u64, u64)> {
    let v = crate::xattr::get_host(fd, ORIGIN).ok()?;
    (v.len() == 16).then(|| {
        (
            u64::from_le_bytes(v[..8].try_into().unwrap()),
            u64::from_le_bytes(v[8..].try_into().unwrap()),
        )
    })
}

/// The path in the overlay `l` of what descriptor `fd` (open on a file of
/// one of its layers) is: where it is now in its layer, which a rename
/// moves it with.
pub fn path_of(l: &Layers, fd: i32) -> Option<Vec<u8>> {
    let host = crate::fs::host_path_of(fd)?;
    l.paths().find_map(|p| {
        let rest = crate::mounts::under(&host, p)?;
        Some(if rest.is_empty() { b"/".to_vec() } else { rest.to_vec() })
    })
}

/// The file descriptor `fd` (of one of `l`'s layers) is open on, copied up
/// if it is a lower one: the upper layer's directory holding the copy and
/// its name, or `None` if `fd` is of the upper layer already. `ESTALE` if
/// the file is not where the overlay shows it any more (renamed over).
pub fn copy_up_open(l: &Layers, fd: i32) -> Result<Option<(Arc<OwnedFd>, CString)>, i32> {
    let upper = l.upper.as_deref().ok_or(errno::EROFS)?;
    let host = crate::fs::host_path_of(fd).ok_or(errno::EBADF)?;
    if crate::mounts::under(&host, upper).is_some() {
        return Ok(None);
    }
    let path = path_of(l, fd).ok_or(errno::ESTALE)?;
    let (parent, name) = split(&path);
    let own = id_bytes(&stat_fd(fd)?);
    let n = cstr(&name)?;
    let d = open(l, &parent).map_err(|_| errno::ESTALE)?;
    // Copied up already: the copy is the one that says it is of `fd`'s.
    let shown = match lookup(l, &d, &n)? {
        Found::Other { layer, .. } => d.fds[layer].clone(),
        Found::Dir(child) => d.fds[child.top().0].clone(),
        Found::Missing => None,
    };
    let Some(shown) = shown else { return Err(errno::ESTALE) };
    let of = |dir: i32| {
        open_at(dir, &n, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK).ok().is_some_and(
            |f| {
                stat_fd(f.as_raw_fd()).is_ok_and(|st| id_bytes(&st) == own)
                    || crate::xattr::get_host(f.as_raw_fd(), ORIGIN).is_ok_and(|v| v == own)
            },
        )
    };
    if !of(shown.as_raw_fd()) {
        return Err(errno::ESTALE);
    }
    let up = copy_up(l, &path)?;
    Ok(Some((up, n)))
}

/// One directory of the overlay: the directory of that path in each layer
/// that has it and shows it (`None` for one that does not, or that an
/// opaque directory or a whiteout above hides).
#[derive(Clone, Debug)]
pub struct Dir {
    pub fds: Vec<Option<Arc<OwnedFd>>>,
}

impl Dir {
    /// The topmost layer showing the directory, and its descriptor there.
    pub fn top(&self) -> (usize, &Arc<OwnedFd>) {
        self.fds
            .iter()
            .enumerate()
            .find_map(|(i, f)| f.as_ref().map(|f| (i, f)))
            .expect("a directory is in some layer")
    }

    /// Its directory in the upper layer, if it is there.
    fn upper(&self, l: &Layers) -> Option<&Arc<OwnedFd>> {
        if l.upper.is_some() { self.fds[0].as_ref() } else { None }
    }

    /// Whether a lower layer has it.
    pub fn in_lower(&self, l: &Layers) -> bool {
        self.fds[l.first_lower()..].iter().any(Option::is_some)
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
    let mut fds = Vec::with_capacity(l.count());
    for p in l.paths() {
        fds.push(Some(Arc::new(open_host_dir(p)?)));
    }
    Ok(Dir { fds })
}

/// Look `name` up in the overlay directory `d`.
pub fn lookup(l: &Layers, d: &Dir, name: &CStr) -> Result<Found, i32> {
    let mut dirs: Vec<Option<Arc<OwnedFd>>> = vec![None; d.fds.len()];
    let mut any_dir = false;
    for (i, fd) in d.fds.iter().enumerate() {
        let Some(fd) = fd else { continue };
        let st = match stat_at(fd.as_raw_fd(), name) {
            Ok(st) => st,
            Err(errno::ENOENT) => continue,
            Err(e) => return Err(e),
        };
        if whiteout(fd.as_raw_fd(), name, &st) {
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
        let child = open_dir(fd.as_raw_fd(), name)?;
        let opaque = opaque(l, child.as_raw_fd());
        dirs[i] = Some(Arc::new(child));
        any_dir = true;
        if opaque {
            break;
        }
    }
    Ok(if any_dir { Found::Dir(Dir { fds: dirs }) } else { Found::Missing })
}

/// Whether the directory open as `fd` is opaque.
fn opaque(l: &Layers, fd: i32) -> bool {
    crate::xattr::get(&crate::xattr::Target::Fd(fd), l.opaque_attr()).is_ok_and(|v| v == b"y")
}

/// The overlay directory at `path` (a path in the overlay, from its root),
/// following no link: `ENOENT` if it is missing, `ENOTDIR` if it is not a
/// directory.
pub fn open(l: &Layers, path: &[u8]) -> Result<Dir, i32> {
    let mut d = root(l)?;
    for c in components(path) {
        d = match lookup(l, &d, &cstr(&c)?)? {
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
fn temp_name() -> CString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    CString::new(format!("#fwe.{pid}.{}", N.fetch_add(1, Ordering::Relaxed))).expect("no NUL")
}

/// The directory changes are built in: `work` in the work directory.
fn work(l: &Layers) -> Result<OwnedFd, i32> {
    let dir = l.work.as_ref().ok_or(errno::EROFS)?;
    open_host_dir(&crate::mounts::join(dir, b"work"))
}

/// Prepare the work directory of a new mount: its `work` subdirectory,
/// made if missing.
pub fn prepare_work(work_dir: &[u8]) -> Result<(), i32> {
    let p = cstr(&crate::mounts::join(work_dir, b"work"))?;
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::mkdir(p.as_ptr(), 0o700) } != 0 && crate::host::last_errno() != libc::EEXIST {
        return Err(e());
    }
    Ok(())
}

/// Copy the metadata a copy-up keeps (owner's view of the mode, flags,
/// times, attributes other than the overlay's own) from `src` to `dst`,
/// both open.
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

/// Copy every extended attribute of `src` but the overlay's own to `dst`.
fn copy_xattrs(l: &Layers, src: i32, dst: i32) -> Result<(), i32> {
    for name in host_xattrs(src)? {
        // The overlay's own, and the host's (which a clone copies).
        if name.starts_with(l.private_prefix()) || name.starts_with(b"com.apple.") {
            continue;
        }
        let value = crate::xattr::get_host(src, &name)?;
        crate::xattr::set_host(dst, &name, &value)?;
    }
    Ok(())
}

/// The names of every host attribute of the file open as `fd`.
fn host_xattrs(fd: i32) -> Result<Vec<Vec<u8>>, i32> {
    let all = crate::xattr::list_host(fd)?;
    Ok(all.split(|&b| b == 0).filter(|n| !n.is_empty()).map(<[u8]>::to_vec).collect())
}

/// Move the change built at `tmp` in the work directory to `name` in
/// `dir`, unless another process put one there first (then `tmp` goes).
fn place(work: i32, tmp: &CStr, dir: i32, name: &CStr, is_dir: bool) -> Result<(), i32> {
    use crate::host::{Rename, rename_at};
    match rename_at(work, tmp, dir, name, Rename::NoReplace) {
        Ok(()) => Ok(()),
        Err(errno::EEXIST) => {
            remove_tree(work, tmp, is_dir);
            Ok(())
        }
        Err(err) => {
            remove_tree(work, tmp, is_dir);
            Err(err)
        }
    }
}

/// Remove `name` in `dir`, everything in it first for a directory.
fn remove_tree(dir: i32, name: &CStr, is_dir: bool) {
    if !is_dir {
        // SAFETY: a NUL-terminated name in a live directory.
        unsafe { libc::unlinkat(dir, name.as_ptr(), 0) };
        return;
    }
    if let Ok(d) = open_dir(dir, name) {
        for (child, t) in host_entries(d.as_raw_fd()).unwrap_or_default() {
            if let Ok(c) = cstr(&child) {
                remove_tree(d.as_raw_fd(), &c, t == libc::DT_DIR);
            }
        }
    }
    // SAFETY: as above.
    unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) };
}

/// The entries of the host directory open as `dir` (not `.` or `..`),
/// with their host types.
fn host_entries(dir: i32) -> Result<Vec<(Vec<u8>, u8)>, i32> {
    Ok(host_entries_ino(dir)?.into_iter().map(|(n, t, _)| (n, t)).collect())
}

/// [`host_entries`] with each entry's inode number.
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

/// Copy the lower layer's `name` in `src_dir` (whose metadata is `st`) up
/// to `name` in the upper layer's `dst_dir`.
fn copy_one(
    l: &Layers,
    src_dir: i32,
    name: &CStr,
    st: &libc::stat,
    dst_dir: i32,
) -> Result<(), i32> {
    let work = work(l)?;
    let w = work.as_raw_fd();
    let tmp = temp_name();
    let kind = st.st_mode & libc::S_IFMT;
    match kind {
        libc::S_IFDIR => {
            // SAFETY: a NUL-terminated name in a live directory.
            if unsafe { libc::mkdirat(w, tmp.as_ptr(), 0o700) } != 0 {
                return Err(e());
            }
            let made = open_dir(w, &tmp)?;
            let src = open_dir(src_dir, name)?;
            if let Err(err) = copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st) {
                remove_tree(w, &tmp, true);
                return Err(err);
            }
        }
        libc::S_IFREG => {
            let src = open_at(src_dir, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
            match crate::host::clone_at(src.as_raw_fd(), w, &tmp) {
                Ok(()) => {
                    // The clone has the attributes; the times are set again
                    // in case the host gave it its own.
                    let made = open_at(w, &tmp, libc::O_RDONLY | libc::O_NOFOLLOW)?;
                    let times = [
                        libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
                        libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
                    ];
                    // SAFETY: a valid times array; an open descriptor.
                    unsafe { libc::futimens(made.as_raw_fd(), times.as_ptr()) };
                }
                Err(errno::EOPNOTSUPP) => {
                    let made = open_at(
                        w,
                        &tmp,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    )?;
                    let copied = copy_data(src.as_raw_fd(), made.as_raw_fd())
                        .and_then(|()| copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st));
                    if let Err(err) = copied {
                        remove_tree(w, &tmp, false);
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
            let made = open_at(w, &tmp, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW)?;
            let src = open_at(src_dir, name, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW)?;
            if let Err(err) = copy_meta(l, src.as_raw_fd(), made.as_raw_fd(), st) {
                remove_tree(w, &tmp, false);
                return Err(err);
            }
        }
        // A socket's node is made only by binding one there.
        _ => return Err(errno::EOPNOTSUPP),
    }
    if kind != libc::S_IFLNK {
        // Which lower file it is a copy of, for a descriptor of that file
        // to find its copy ([`copy_up_open`]).
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        if let Ok(made) = open_at(w, &tmp, flags) {
            let _ = crate::xattr::set_host(made.as_raw_fd(), ORIGIN, &id_bytes(st));
        }
    }
    place(w, &tmp, dst_dir, name, kind == libc::S_IFDIR)
}

fn copy_data(src: i32, dst: i32) -> Result<(), i32> {
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

/// Copy the overlay directory at `path` up, its parents first: its
/// directory in the upper layer, open.
pub fn upper_dir(l: &Layers, path: &[u8]) -> Result<Arc<OwnedFd>, i32> {
    if l.upper.is_none() {
        return Err(errno::EROFS);
    }
    let mut d = root(l)?;
    for c in components(path) {
        let name = cstr(&c)?;
        let up = d.upper(l).expect("copied up").clone();
        d = match lookup(l, &d, &name)? {
            Found::Missing => return Err(errno::ENOENT),
            Found::Other { .. } => return Err(errno::ENOTDIR),
            Found::Dir(mut next) => {
                if next.upper(l).is_none() {
                    let (layer, fd) = next.top();
                    let st = stat_fd(fd.as_raw_fd())?;
                    // The lower layer's directory holding it.
                    let parent = d.fds[layer].as_ref().expect("its parent").clone();
                    copy_one(l, parent.as_raw_fd(), &name, &st, up.as_raw_fd())?;
                    next.fds[0] = Some(Arc::new(open_dir(up.as_raw_fd(), &name)?));
                }
                next
            }
        };
    }
    Ok(d.upper(l).expect("copied up").clone())
}

/// Copy the file at `path` up (a directory, a regular file, a link or a
/// FIFO), its parent directories first: the upper layer's directory
/// holding it, open. `ENOENT` if it is missing.
pub fn copy_up(l: &Layers, path: &[u8]) -> Result<Arc<OwnedFd>, i32> {
    let (parent, name) = split(path);
    let up = upper_dir(l, &parent)?;
    if name.is_empty() {
        return Ok(up);
    }
    let d = open(l, &parent)?;
    let n = cstr(&name)?;
    match lookup(l, &d, &n)? {
        Found::Missing => Err(errno::ENOENT),
        Found::Other { layer, .. } if l.upper.is_some() && layer == 0 => Ok(up),
        Found::Other { layer, .. } => {
            let src = d.fds[layer].as_ref().expect("its layer").clone();
            let st = stat_at(src.as_raw_fd(), &n)?;
            copy_one(l, src.as_raw_fd(), &n, &st, up.as_raw_fd())?;
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
fn lower_has(l: &Layers, d: &Dir, name: &CStr) -> Result<bool, i32> {
    if l.upper.is_none() {
        return Ok(true);
    }
    // The directory as the lower layers show it: below an opaque upper
    // directory, nothing.
    if d.fds[0].as_ref().is_some_and(|up| opaque(l, up.as_raw_fd())) {
        return Ok(false);
    }
    let lower = Dir { fds: std::iter::once(None).chain(d.fds[1..].iter().cloned()).collect() };
    if !lower.fds.iter().any(Option::is_some) {
        return Ok(false);
    }
    Ok(!matches!(lookup(l, &lower, name)?, Found::Missing))
}

/// Where a creation in an overlay goes: `name` in the upper layer's
/// directory, or, when a whiteout is there, a fresh name in the work
/// directory that [`Created::finish`] moves over it.
pub struct Created {
    /// The upper layer's directory, and the name.
    pub dir: Arc<OwnedFd>,
    pub name: CString,
    /// The work directory and the temporary name, when made there.
    pub temp: Option<(OwnedFd, CString)>,
    /// Whether a directory made there is to hide the lower layers' (it
    /// replaces a whiteout).
    opaque_attr: &'static [u8],
}

impl Created {
    /// The directory and name to make the file at.
    pub fn target(&self) -> (i32, &CStr) {
        match &self.temp {
            Some((w, t)) => (w.as_raw_fd(), t),
            None => (self.dir.as_raw_fd(), &self.name),
        }
    }

    /// Put what was made (`made`) in place, or clear up after a failure.
    pub fn finish(&self, made: bool) -> Result<(), i32> {
        let Some((w, tmp)) = &self.temp else { return Ok(()) };
        let w = w.as_raw_fd();
        let Ok(st) = stat_at(w, tmp) else { return Ok(()) };
        let dir = is_dir(&st);
        if !made {
            remove_tree(w, tmp, dir);
            return Ok(());
        }
        use crate::host::{Rename, rename_at};
        let up = self.dir.as_raw_fd();
        if !dir {
            // Over the whiteout, atomically.
            return rename_at(w, tmp, up, &self.name, Rename::Replace);
        }
        // A directory replacing a whiteout hides what the lower layers
        // have of that name; it takes the whiteout's place in one swap.
        let d = open_dir(w, tmp)?;
        crate::xattr::set_host(d.as_raw_fd(), self.opaque_attr, b"y")?;
        rename_at(w, tmp, up, &self.name, Rename::Exchange)?;
        remove_tree(w, tmp, false);
        Ok(())
    }
}

/// Prepare to make `name` in the overlay directory at `parent`: copy the
/// directory up, and see whether a whiteout is in the way.
pub fn create(l: &Layers, parent: &[u8], name: &[u8]) -> Result<Created, i32> {
    let up = upper_dir(l, parent)?;
    let n = cstr(name)?;
    let temp = match stat_at(up.as_raw_fd(), &n) {
        Ok(st) if whiteout(up.as_raw_fd(), &n, &st) => Some((work(l)?, temp_name())),
        _ => None,
    };
    Ok(Created { dir: up, name: n, temp, opaque_attr: l.opaque_attr() })
}

/// Remove `name` from the overlay directory at `parent`: a directory
/// (`rmdir`, which must show no entries) or another file (`unlink`).
pub fn remove(l: &Layers, parent: &[u8], name: &[u8], rmdir: bool) -> Result<(), i32> {
    use crate::host::{Rename, rename_at};
    let n = cstr(name)?;
    let d = open(l, parent)?;
    let found = lookup(l, &d, &n)?;
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
    let up = up.as_raw_fd();
    if lower_has(l, &d, &n)? {
        // A whiteout takes its place.
        let w = work(l)?;
        let tmp = temp_name();
        make_whiteout(w.as_raw_fd(), &tmp)?;
        let r = match (in_upper, rmdir) {
            (false, _) => rename_at(w.as_raw_fd(), &tmp, up, &n, Rename::NoReplace),
            (true, false) => rename_at(w.as_raw_fd(), &tmp, up, &n, Rename::Replace),
            (true, true) => rename_at(w.as_raw_fd(), &tmp, up, &n, Rename::Exchange),
        };
        // What was swapped out (an upper directory of whiteouts), or the
        // whiteout itself if it could not be placed.
        let swapped = r.is_ok() && in_upper && rmdir;
        if r.is_err() || swapped {
            remove_tree(w.as_raw_fd(), &tmp, swapped);
        }
        return r;
    }
    if rmdir {
        // Only whiteouts are left in it.
        if let Ok(child) = open_dir(up, &n) {
            for (entry, t) in host_entries(child.as_raw_fd())? {
                let c = cstr(&entry)?;
                remove_tree(child.as_raw_fd(), &c, t == libc::DT_DIR);
            }
        }
        // SAFETY: a NUL-terminated name in a live directory.
        if unsafe { libc::unlinkat(up, n.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(e());
        }
    } else {
        // SAFETY: as above.
        if unsafe { libc::unlinkat(up, n.as_ptr(), 0) } != 0 {
            return Err(e());
        }
    }
    Ok(())
}

/// `renameat2` within one overlay: `from` (`(parent, name)`) to `to`, with
/// [`crate::host::Rename`]'s modes.
pub fn rename(
    l: &Layers,
    from: (&[u8], &[u8]),
    to: (&[u8], &[u8]),
    how: crate::host::Rename,
) -> Result<(), i32> {
    use crate::host::{Rename, rename_at};
    let (fname, tname) = (cstr(from.1)?, cstr(to.1)?);
    let fd = open(l, from.0)?;
    let td = open(l, to.0)?;
    let src = lookup(l, &fd, &fname)?;
    let dst = lookup(l, &td, &tname)?;
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
    let up_from = copy_up(l, &from_path)?;
    let up_to = if how == Rename::Exchange { copy_up(l, &to_path)? } else { upper_dir(l, to.0)? };
    let (uf, ut) = (up_from.as_raw_fd(), up_to.as_raw_fd());
    if how == Rename::Exchange {
        // Both names stay. A directory moved to a name the lower layers
        // have hides theirs.
        for (found, dir, name, lower) in [
            (&src, uf, &fname, lower_has(l, &td, &tname)?),
            (&dst, ut, &tname, lower_has(l, &fd, &fname)?),
        ] {
            if lower && matches!(found, Found::Dir(_)) {
                let moving = open_dir(dir, name)?;
                crate::xattr::set_host(moving.as_raw_fd(), l.opaque_attr(), b"y")?;
            }
        }
        return rename_at(uf, &fname, ut, &tname, Rename::Exchange);
    }
    let src_lower = lower_has(l, &fd, &fname)?;
    let dst_lower = lower_has(l, &td, &tname)?;
    if let Found::Dir(_) = src
        && dst_lower
    {
        // Moved over a name the lower layers have: it hides theirs.
        let moved = open_dir(uf, &fname)?;
        crate::xattr::set_host(moved.as_raw_fd(), l.opaque_attr(), b"y")?;
        if let Ok(old) = open_dir(ut, &tname) {
            // The upper directory it replaces holds only whiteouts, which
            // must go for the rename to take its place.
            crate::xattr::set_host(old.as_raw_fd(), l.opaque_attr(), b"y")?;
            for (entry, t) in host_entries(old.as_raw_fd())? {
                remove_tree(old.as_raw_fd(), &cstr(&entry)?, t == libc::DT_DIR);
            }
        }
    }
    let over_whiteout = matches!(dst, Found::Missing)
        && stat_at(ut, &tname).is_ok_and(|st| whiteout(ut, &tname, &st));
    if over_whiteout && matches!(src, Found::Dir(_)) {
        // A directory cannot replace the whiteout file: they swap, and the
        // whiteout is left at the old name, where it is wanted if a lower
        // layer has that name.
        rename_at(uf, &fname, ut, &tname, Rename::Exchange)?;
        if !src_lower {
            remove_tree(uf, &fname, false);
        }
        return Ok(());
    }
    rename_at(uf, &fname, ut, &tname, Rename::Replace)?;
    if src_lower {
        let w = work(l)?;
        let tmp = temp_name();
        make_whiteout(w.as_raw_fd(), &tmp)?;
        if let Err(err) = rename_at(w.as_raw_fd(), &tmp, uf, &fname, Rename::NoReplace) {
            remove_tree(w.as_raw_fd(), &tmp, false);
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
    for fd in d.fds.iter().flatten() {
        let fd = fd.as_raw_fd();
        for (name, t, ino) in host_entries_ino(fd)? {
            if !seen.insert(name.clone()) {
                continue;
            }
            let mut kind = t;
            if matches!(t, libc::DT_REG | libc::DT_CHR | libc::DT_UNKNOWN) {
                let n = cstr(&name)?;
                let Ok(st) = stat_at(fd, &n) else { continue };
                if whiteout(fd, &n, &st) {
                    continue;
                }
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

/// The device and inode of what `fd` is open on.
#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(fd: i32) -> Option<(u64, u64)> {
    stat_fd(fd).ok().map(|st| (st.st_dev as u64, st.st_ino as u64))
}

static CURSORS: std::sync::Mutex<Option<std::collections::HashMap<i32, Cursor>>> =
    std::sync::Mutex::new(None);

fn cursors<R>(f: impl FnOnce(&mut std::collections::HashMap<i32, Cursor>) -> R) -> R {
    let mut g = CURSORS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Default::default))
}

/// Run `f` holding the cursors' lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = CURSORS.lock().unwrap_or_else(|e| e.into_inner());
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
    if CURSORS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|m| m.is_empty()) {
        return;
    }
    cursors(|m| m.remove(&fd));
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
        let p = |d: &str| base.join(d).into_os_string().into_encoded_bytes();
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
        make_whiteout(up.as_raw_fd(), c"gone").unwrap();
        assert_eq!(names(&l, b"/d"), ["f", "old"]);
        assert_eq!(names(&l, b"/o"), ["shown"]);
        let d = open(&l, b"/d").unwrap();
        assert!(matches!(lookup(&l, &d, c"gone").unwrap(), Found::Missing));
        assert!(matches!(lookup(&l, &d, c"f").unwrap(), Found::Other { layer: 1, .. }));
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
        let (dir, name) = c.target();
        // SAFETY: a NUL-terminated name in a live directory.
        assert_eq!(unsafe { libc::mkdirat(dir, name.as_ptr(), 0o755) }, 0);
        c.finish(true).unwrap();
        assert!(names(&l, b"/m").is_empty());
        std::fs::write(b.join("lower1/y"), "y").unwrap();
        rename(&l, (b"/", b"y"), (b"/m", b"z"), Rename::Replace).unwrap();
        assert_eq!(names(&l, b"/m"), ["z"]);
        assert!(!names(&l, b"/").contains(&"y".to_string()));
    }
}
