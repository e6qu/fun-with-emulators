//! Permission bits that deny a file's owner, which the host must not
//! enforce.
//!
//! Every guest file is the host user's, so the host checks the owner's
//! bits on every access; Linux's root passes them (`CAP_DAC_OVERRIDE`), and
//! container tools rely on that (a layer directory made `0555`, then
//! filled). So a mode that denies its owner something is kept apart: on
//! the host the file has the owner's read and write bits (and search, for
//! a directory), and the guest's mode is in the `org.fwe.mode` attribute,
//! the file flagged `UF_NODUMP` so that a `stat` shows at once whether to
//! look for it. `stat` reports the kept mode, and fwe itself refuses a
//! caller without the capabilities what the kept mode denies the owner.
//! The flag is also Linux's no-dump flag (`FS_NODUMP_FL`): one the guest
//! sets is recorded in `org.fwe.nodump` ([`set_nodump_fd`]), and only that
//! one (or a flag with nothing kept under it) is reported as the guest's.
//!
//! A regular file `open` makes is made with its mode itself where the host
//! enforces it on the owner as Linux does on anyone without root's
//! override ([`made_file_perm`]): most such files (a repository's objects,
//! made read-only) are never written again, and need no attribute to read
//! at every `stat`. Such a file, or one whose host mode denies its owner
//! made by something else, is converted the first time the host refuses
//! what fwe allowed ([`keep_at`], [`keep_fd`] with its own mode;
//! [`own_fd`], [`own_path`]).

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(target_os = "macos")]
const ATTR: &CStr = c"org.fwe.mode";
#[cfg(target_os = "macos")]
const MARK: u32 = libc::UF_NODUMP;
/// Present on a file the guest gave the no-dump flag, whose host flag is
/// also [`MARK`].
#[cfg(target_os = "macos")]
const NODUMP_ATTR: &CStr = c"org.fwe.nodump";

/// What the host's mode must have of guest mode `perm` (its low 12 bits)
/// for a directory (`dir`) or another file: the owner's read and write,
/// and search for a directory or execute for a file anyone may run. A
/// file's set-ID bits are never the host's (it drops them from a file of a
/// group its user is not in, and on any write): they are kept.
pub fn host_perm(perm: u32, dir: bool) -> u32 {
    // Execute for anyone is the owner's too: root may run what anyone may.
    let exec = dir || perm & 0o111 != 0;
    let setid = if dir { 0 } else { 0o6000 };
    perm & 0o7777 & !setid | 0o600 | if exec { 0o100 } else { 0 }
}

/// The host mode of a regular file `open` makes with guest mode `perm`:
/// `perm` itself, unless it has set-ID or sticky bits, or lets others run
/// the file but not its owner ([`host_perm`]'s then, the mode kept).
pub fn made_file_perm(perm: u32) -> u32 {
    let p = perm & 0o7777;
    if p & 0o7000 == 0 && (p & 0o111 == 0 || p & 0o100 != 0) { p } else { host_perm(perm, false) }
}

/// Descriptors open to write a file whose kept mode is set-ID: a write
/// through one by a caller without `CAP_FSETID` takes the bits away, as
/// Linux's does ([`wrote`]).
pub(crate) static SETID_FDS: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());
static SETID_OPEN: AtomicUsize = AtomicUsize::new(0);
/// Whether the caller has `CAP_FSETID`, as of its last system call that
/// took the kernel's lock ([`note_fsetid`]).
static FSETID: AtomicBool = AtomicBool::new(true);

fn setid_fds() -> std::sync::MutexGuard<'static, Vec<i32>> {
    SETID_FDS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether any descriptor is open to write a set-ID file.
pub fn setid_open() -> bool {
    SETID_OPEN.load(Ordering::Acquire) != 0
}

/// The caller has `CAP_FSETID` (`has`), while set-ID files are open.
pub fn note_fsetid(has: bool) {
    FSETID.store(has, Ordering::Relaxed);
}

/// `fd` was opened, or its file's kept mode set, as `perm`: it is watched
/// if it writes a set-ID file.
fn watch_setid(fd: i32, perm: u32) {
    if perm & 0o6000 == 0 {
        return;
    }
    // SAFETY: F_GETFL only queries the descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE == libc::O_RDONLY {
        return;
    }
    let mut fds = setid_fds();
    if !fds.contains(&fd) {
        fds.push(fd);
        SETID_OPEN.fetch_add(1, Ordering::AcqRel);
    }
}

/// `fd` was opened to write the file of host metadata `st`.
pub fn opened_for_writing(fd: i32, st: &libc::stat) {
    if marked(st)
        && st.st_mode & libc::S_IFMT == libc::S_IFREG
        && let Some(perm) = read_fd(fd)
    {
        watch_setid(fd, perm);
    }
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    if !setid_open() {
        return;
    }
    let mut fds = setid_fds();
    if let Some(i) = fds.iter().position(|&f| f == fd) {
        fds.swap_remove(i);
        SETID_OPEN.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `fd` was written to: a set-ID file written by a caller without
/// `CAP_FSETID` loses its set-user-ID bit, and its set-group-ID bit if
/// its group may execute it.
pub fn wrote(fd: i32) {
    if !setid_open() || FSETID.load(Ordering::Relaxed) || !setid_fds().contains(&fd) {
        return;
    }
    let Some(perm) = read_fd(fd) else { return };
    let mut kept = perm & !0o4000;
    if kept & 0o2010 == 0o2010 {
        kept &= !0o2000;
    }
    if kept != perm {
        let _ = keep_fd(fd, kept);
    }
}

/// The permission bits of host metadata `st`.
#[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
pub fn perm_of(st: &libc::stat) -> u32 {
    st.st_mode as u32 & 0o7777
}

/// Kept metadata read from a file's attributes, by its identity and its
/// host change time as a `stat` reported them: the attributes are read
/// once a process, not at every `stat` and `open` (a read is microseconds,
/// a `fstat` a fraction of one). Any change to a file's attributes or
/// flags, by any process, moves its change time, which no call sets back,
/// so a change is never served stale.
#[derive(Clone, Copy, Default)]
pub(crate) struct Read {
    mode: Option<Option<u32>>,
    owner: Option<Option<(u32, u32)>>,
    nodump: Option<Option<()>>,
}

type Key = (u64, u64, i64, i64);

pub(crate) static READ: std::sync::Mutex<std::collections::BTreeMap<Key, Read>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// How many files' reads are kept; past it they are forgotten.
const READ_KEPT: usize = 4096;

#[allow(clippy::unnecessary_cast)] // the fields' widths differ by host
fn key(st: &libc::stat) -> Key {
    (st.st_dev as u64, st.st_ino as u64, st.st_ctime as i64, st.st_ctime_nsec as i64)
}

/// `field` of the reads of the file of metadata `st`, read with `read` if
/// not kept.
fn read_once<T: Copy>(
    st: &libc::stat,
    field: impl Fn(&mut Read) -> &mut Option<Option<T>>,
    read: impl FnOnce() -> Option<T>,
) -> Option<T> {
    let k = key(st);
    let lock = || READ.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = lock().get_mut(&k).and_then(|r| *field(r)) {
        return v;
    }
    let v = read();
    let mut kept = lock();
    if kept.len() >= READ_KEPT {
        kept.clear();
    }
    *field(kept.entry(k).or_default()) = Some(v);
    v
}

/// The mode kept for the file of metadata `st`, read with `read`.
fn mode_once(st: &libc::stat, read: impl FnOnce() -> Option<u32>) -> Option<u32> {
    read_once(st, |r| &mut r.mode, read)
}

/// The owner kept for the file of metadata `st`, read with `read`.
pub(crate) fn owner_once(
    st: &libc::stat,
    read: impl FnOnce() -> Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    read_once(st, |r| &mut r.owner, read)
}

/// Whether host metadata `st` marks a kept mode.
#[cfg(target_os = "macos")]
pub fn marked(st: &libc::stat) -> bool {
    st.st_flags & MARK != 0
}

#[cfg(not(target_os = "macos"))]
pub fn marked(_st: &libc::stat) -> bool {
    false
}

/// Whether the file open as `fd`, with host metadata `st`, has the no-dump
/// flag (`FS_NODUMP_FL`) of its own: the host's flag that is not only the
/// mark of kept metadata, where a no-dump the guest set is recorded
/// ([`set_nodump_fd`]).
pub fn nodump_fd(fd: i32, st: &libc::stat) -> bool {
    marked(st)
        && (read_once(st, |r| &mut r.nodump, || nodump_attr_fd(fd)).is_some()
            || kept_mode_fd(fd, st).is_none() && crate::owners::kept_of_fd(fd, st).is_none())
}

/// [`nodump_fd`] for `name` in directory `dir`.
pub fn nodump_at(dir: i32, name: &CStr, st: &libc::stat) -> bool {
    marked(st)
        && (read_once(st, |r| &mut r.nodump, || nodump_attr_at(dir, name)).is_some()
            || mode_once(st, || read_at(dir, name)).is_none()
                && crate::owners::kept_of_at(dir, name, st).is_none())
}

/// Give the file open as `fd` the no-dump flag (`on`) or take it away:
/// recorded beside the host's flag, which stays while it marks kept
/// metadata.
#[cfg(target_os = "macos")]
pub fn set_nodump_fd(fd: i32, on: bool) -> Result<(), i32> {
    // SAFETY: plain host calls on an open descriptor with a valid buffer.
    unsafe {
        if on {
            if libc::fsetxattr(fd, NODUMP_ATTR.as_ptr(), [1u8].as_ptr().cast(), 1, 0, 0) != 0 {
                return Err(last());
            }
        } else if libc::fremovexattr(fd, NODUMP_ATTR.as_ptr(), 0) != 0
            && crate::host::last_errno() != libc::ENOATTR
        {
            return Err(last());
        }
    }
    Ok(())
}

/// [`set_nodump_fd`] for the file at host path `path` (not followed).
#[cfg(target_os = "macos")]
pub fn set_nodump_path(path: &CStr, on: bool) -> Result<(), i32> {
    let nofollow = libc::XATTR_NOFOLLOW;
    // SAFETY: plain host calls on a NUL-terminated path with a valid buffer.
    unsafe {
        if on {
            let one = [1u8].as_ptr().cast();
            if libc::setxattr(path.as_ptr(), NODUMP_ATTR.as_ptr(), one, 1, 0, nofollow) != 0 {
                return Err(last());
            }
        } else if libc::removexattr(path.as_ptr(), NODUMP_ATTR.as_ptr(), nofollow) != 0
            && crate::host::last_errno() != libc::ENOATTR
        {
            return Err(last());
        }
    }
    Ok(())
}

/// Whether the guest gave the file open as `fd` the no-dump flag, which
/// keeps the host's flag when kept metadata goes.
#[cfg(target_os = "macos")]
pub fn nodump_set_fd(fd: i32) -> bool {
    nodump_attr_fd(fd).is_some()
}

/// [`nodump_set_fd`] for the file at host path `path` (not followed).
#[cfg(target_os = "macos")]
pub fn nodump_set_path(path: &CStr) -> bool {
    nodump_attr_path(path).is_some()
}

#[cfg(target_os = "macos")]
fn nodump_attr_fd(fd: i32) -> Option<()> {
    // SAFETY: a size query of an attribute, with no buffer.
    let n = unsafe { libc::fgetxattr(fd, NODUMP_ATTR.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
    (n >= 0).then_some(())
}

#[cfg(target_os = "macos")]
fn nodump_attr_path(path: &CStr) -> Option<()> {
    // SAFETY: a size query of an attribute, with no buffer; not followed.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            NODUMP_ATTR.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    (n >= 0).then_some(())
}

#[cfg(target_os = "macos")]
fn nodump_attr_at(dir: i32, name: &CStr) -> Option<()> {
    crate::host::at_path(dir, name, nodump_attr_path).ok().flatten()
}

#[cfg(not(target_os = "macos"))]
fn nodump_attr_fd(_fd: i32) -> Option<()> {
    None
}

#[cfg(not(target_os = "macos"))]
fn nodump_attr_at(_dir: i32, _name: &CStr) -> Option<()> {
    None
}

/// The guest's permission bits of the file whose host metadata is `st`:
/// its kept mode, read through `fd` (open on it) if it has one.
pub fn guest_perm_fd(fd: i32, st: &libc::stat) -> u32 {
    let host = crate::modes::perm_of(st);
    if !marked(st) {
        return host;
    }
    kept_mode_fd(fd, st).unwrap_or(host)
}

/// The mode kept for the file open as `fd` of metadata `st`: by its path
/// where the descriptor reads no attribute (one opened only to search a
/// directory).
fn kept_mode_fd(fd: i32, st: &libc::stat) -> Option<u32> {
    mode_once(st, || {
        read_fd(fd).or_else(|| {
            let p = std::ffi::CString::new(crate::fs::fd_path(fd)?).ok()?;
            read_path(&p)
        })
    })
}

/// [`guest_perm_fd`] for `name` in directory `dir`.
pub fn guest_perm_at(dir: i32, name: &CStr, st: &libc::stat) -> u32 {
    let host = crate::modes::perm_of(st);
    if !marked(st) {
        return host;
    }
    mode_once(st, || read_at(dir, name)).unwrap_or(host)
}

/// [`guest_perm_fd`] for the file at host path `path` (not followed).
pub fn guest_perm_path(path: &CStr, st: &libc::stat) -> u32 {
    let host = crate::modes::perm_of(st);
    if !marked(st) {
        return host;
    }
    mode_once(st, || read_path(path)).unwrap_or(host)
}

/// Put the guest's permission bits in `st`.
pub fn apply(st: &mut libc::stat, perm: u32) {
    st.st_mode = (st.st_mode & !0o7777) | perm as libc::mode_t;
}

/// Give the file open as `fd` the guest mode `perm`: on the host, `perm`
/// with what the owner must have, the rest kept.
pub fn keep_fd(fd: i32, perm: u32) -> Result<(), i32> {
    let st = fstat(fd)?;
    if st.st_mode & libc::S_IFMT == libc::S_IFSOCK {
        // A socket's mode is what a node bound for it is made with.
        crate::net::set_socket_mode(fd, perm);
        return Ok(());
    }
    let dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let host = host_perm(perm, dir);
    // SAFETY: plain host call on an open descriptor.
    if unsafe { libc::fchmod(fd, host as libc::mode_t) } != 0 {
        return Err(last());
    }
    mark_fd(fd, &st, (host != perm & 0o7777).then_some(perm & 0o7777))?;
    if st.st_mode & libc::S_IFMT == libc::S_IFREG {
        watch_setid(fd, perm);
    }
    Ok(())
}

/// The host refused the file open as `fd` what fwe allowed (`EACCES`):
/// if its host mode denies its owner, keep that mode apart, so that the
/// host lets the owner through. `EACCES` where its mode does not.
pub fn own_fd(fd: i32) -> Result<(), i32> {
    let st = fstat(fd)?;
    let perm = perm_of(&st);
    if host_perm(perm, st.st_mode & libc::S_IFMT == libc::S_IFDIR) == perm {
        return Err(fwe_abi::errno::EACCES);
    }
    keep_fd(fd, perm)
}

/// [`own_fd`] for the file at host path `path` (not followed).
pub fn own_path(path: &CStr) -> Result<(), i32> {
    let st = fstatat(libc::AT_FDCWD, path)?;
    let kind = st.st_mode & libc::S_IFMT;
    let perm = perm_of(&st);
    let host = host_perm(perm, kind == libc::S_IFDIR);
    if kind == libc::S_IFLNK || host == perm {
        return Err(fwe_abi::errno::EACCES);
    }
    // SAFETY: a NUL-terminated path, not followed.
    let r = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            path.as_ptr(),
            host as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(last());
    }
    mark_path(path, &st, Some(perm))
}

/// [`keep_fd`] for `name` in directory `dir` (not a symbolic link, whose
/// mode Linux never changes).
pub fn keep_at(dir: i32, name: &CStr, perm: u32) -> Result<(), i32> {
    let st = fstatat(dir, name)?;
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        return Err(fwe_abi::errno::EOPNOTSUPP);
    }
    let host = host_perm(perm, kind == libc::S_IFDIR);
    // SAFETY: `name` NUL-terminated; `dir` live.
    let r = unsafe {
        libc::fchmodat(dir, name.as_ptr(), host as libc::mode_t, libc::AT_SYMLINK_NOFOLLOW)
    };
    if r != 0 {
        return Err(last());
    }
    let kept = (host != perm & 0o7777).then_some(perm & 0o7777);
    crate::host::at_path(dir, name, |path| mark_path(path, &st, kept))?
}

/// The kept mode of `name` in directory `dir`, by its path
/// ([`crate::host::at_path`]: never through a descriptor of it).
fn read_at(dir: i32, name: &CStr) -> Option<u32> {
    crate::host::at_path(dir, name, read_path).ok().flatten()
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

fn fstat(fd: i32) -> Result<libc::stat, i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 { Err(last()) } else { Ok(st) }
}

fn fstatat(dir: i32, name: &CStr) -> Result<libc::stat, i32> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `name` NUL-terminated; `dir` live; a valid out-parameter.
    let r = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if r != 0 { Err(last()) } else { Ok(st) }
}

#[cfg(target_os = "macos")]
fn decode(buf: &[u8], n: isize) -> Option<u32> {
    (n == 2).then(|| u32::from(u16::from_le_bytes([buf[0], buf[1]])))
}

#[cfg(target_os = "macos")]
fn read_fd(fd: i32) -> Option<u32> {
    let mut buf = [0u8; 2];
    // SAFETY: a valid buffer of 2 bytes.
    let n = unsafe { libc::fgetxattr(fd, ATTR.as_ptr(), buf.as_mut_ptr().cast(), 2, 0, 0) };
    decode(&buf, n)
}

#[cfg(target_os = "macos")]
fn read_path(path: &CStr) -> Option<u32> {
    let mut buf = [0u8; 2];
    // SAFETY: a valid buffer of 2 bytes.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            ATTR.as_ptr(),
            buf.as_mut_ptr().cast(),
            2,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    decode(&buf, n)
}

/// Keep `perm` for the file open as `fd` (or forget a kept mode, for
/// `None`), whose metadata was `st`.
#[cfg(target_os = "macos")]
fn mark_fd(fd: i32, st: &libc::stat, perm: Option<u32>) -> Result<(), i32> {
    // SAFETY: plain host calls on an open descriptor with valid buffers.
    unsafe {
        match perm {
            Some(p) => {
                let v = (p as u16).to_le_bytes();
                if libc::fsetxattr(fd, ATTR.as_ptr(), v.as_ptr().cast(), 2, 0, 0) != 0
                    || libc::fchflags(fd, st.st_flags | MARK) != 0
                {
                    return Err(last());
                }
            }
            // The flag is fwe's only where the attribute is: one a user
            // set on a file of their own stays, and so does one a kept
            // owner needs.
            None if marked(st)
                && libc::fremovexattr(fd, ATTR.as_ptr(), 0) == 0
                && !crate::owners::kept_fd(fd)
                && !nodump_set_fd(fd) =>
            {
                libc::fchflags(fd, st.st_flags & !MARK);
            }
            None => {}
        }
    }
    Ok(())
}

/// [`mark_fd`] by path.
#[cfg(target_os = "macos")]
fn mark_path(path: &CStr, st: &libc::stat, perm: Option<u32>) -> Result<(), i32> {
    // SAFETY: plain host calls on a NUL-terminated path with valid buffers.
    unsafe {
        match perm {
            Some(p) => {
                let v = (p as u16).to_le_bytes();
                let set = libc::setxattr(
                    path.as_ptr(),
                    ATTR.as_ptr(),
                    v.as_ptr().cast(),
                    2,
                    0,
                    libc::XATTR_NOFOLLOW,
                );
                if set != 0 || libc::lchflags(path.as_ptr(), st.st_flags | MARK) != 0 {
                    return Err(last());
                }
            }
            None if marked(st)
                && libc::removexattr(path.as_ptr(), ATTR.as_ptr(), libc::XATTR_NOFOLLOW) == 0
                && !crate::owners::kept_path(path)
                && !nodump_set_path(path) =>
            {
                libc::lchflags(path.as_ptr(), st.st_flags & !MARK);
            }
            None => {}
        }
    }
    Ok(())
}

/// Whether the file open as `fd` has a mode kept.
pub fn kept_fd(fd: i32) -> bool {
    read_fd(fd).is_some()
}

/// Whether the file at `path` (not followed) has a mode kept.
pub fn kept_path(path: &CStr) -> bool {
    read_path(path).is_some()
}

/// Set (`on`) or clear the flag that marks kept metadata on the file open
/// as `fd`, whose metadata was `st` (for [`crate::owners`]).
#[cfg(target_os = "macos")]
pub fn set_mark_fd(fd: i32, st: &libc::stat, on: bool) {
    let flags = if on { st.st_flags | MARK } else { st.st_flags & !MARK };
    // SAFETY: plain host call on an open descriptor.
    unsafe { libc::fchflags(fd, flags) };
}

/// [`set_mark_fd`] by path, the link itself.
#[cfg(target_os = "macos")]
pub fn set_mark_path(path: &CStr, st: &libc::stat, on: bool) {
    let flags = if on { st.st_flags | MARK } else { st.st_flags & !MARK };
    // SAFETY: a NUL-terminated path.
    unsafe { libc::lchflags(path.as_ptr(), flags) };
}

// Linux hosts run only the kernel's unit tests: the host's own mode is the
// guest's.
#[cfg(not(target_os = "macos"))]
fn read_fd(_fd: i32) -> Option<u32> {
    None
}

#[cfg(not(target_os = "macos"))]
fn read_path(_path: &CStr) -> Option<u32> {
    None
}

#[cfg(not(target_os = "macos"))]
fn mark_fd(_fd: i32, _st: &libc::stat, _perm: Option<u32>) -> Result<(), i32> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn mark_path(_path: &CStr, _st: &libc::stat, _perm: Option<u32>) -> Result<(), i32> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn set_id_bits_of_a_file_are_never_the_hosts() {
        assert_eq!(host_perm(0o7777, false), 0o1777);
        assert_eq!(host_perm(0o4755, false), 0o755);
        assert_eq!(host_perm(0o2750, false), 0o750);
        // A directory's set-group-ID is the host's (it gives new files
        // the directory's group).
        assert_eq!(host_perm(0o2775, true), 0o2775);
        assert_eq!(host_perm(0o440, false), 0o640);
    }

    #[test]
    fn a_mode_denying_the_owner_is_kept() {
        let base = std::env::temp_dir().join(format!("fwe-modes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("d")).unwrap();
        let dir = std::fs::File::open(&base).unwrap();
        let name = c"d";
        keep_at(dir.as_raw_fd(), name, 0o555).unwrap();
        let st = fstatat(dir.as_raw_fd(), name).unwrap();
        assert_eq!(st.st_mode & 0o7777, 0o755, "the owner keeps writing on the host");
        assert!(marked(&st));
        assert_eq!(guest_perm_at(dir.as_raw_fd(), name, &st), 0o555);
        // Writable on the host still.
        std::fs::write(base.join("d/f"), b"x").unwrap();
        // A mode the owner has needs no keeping.
        keep_at(dir.as_raw_fd(), name, 0o750).unwrap();
        let st = fstatat(dir.as_raw_fd(), name).unwrap();
        assert!(!marked(&st));
        assert_eq!(guest_perm_at(dir.as_raw_fd(), name, &st), 0o750);
        let _ = std::fs::remove_dir_all(&base);
    }
}
