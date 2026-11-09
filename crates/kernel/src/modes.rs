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
//!
//! A file whose host mode denies its owner, made by something else, is
//! converted the first time root is refused by it ([`keep_at`],
//! [`keep_fd`] with its own mode).

use std::ffi::CStr;

#[cfg(target_os = "macos")]
const ATTR: &CStr = c"org.fwe.mode";
#[cfg(target_os = "macos")]
const MARK: u32 = libc::UF_NODUMP;

/// What the host's mode must have of guest mode `perm` (its low 12 bits)
/// for a directory (`dir`) or another file: the owner's read and write,
/// and search for a directory or execute for a file anyone may run.
pub fn host_perm(perm: u32, dir: bool) -> u32 {
    // Execute for anyone is the owner's too: root may run what anyone may.
    let exec = dir || perm & 0o111 != 0;
    perm & 0o7777 | 0o600 | if exec { 0o100 } else { 0 }
}

/// The permission bits of host metadata `st`.
#[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
pub fn perm_of(st: &libc::stat) -> u32 {
    st.st_mode as u32 & 0o7777
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

/// The guest's permission bits of the file whose host metadata is `st`:
/// its kept mode, read through `fd` (open on it) if it has one.
pub fn guest_perm_fd(fd: i32, st: &libc::stat) -> u32 {
    let host = crate::modes::perm_of(st);
    if !marked(st) {
        return host;
    }
    // By its path where the descriptor reads no attribute (one opened only
    // to search a directory).
    read_fd(fd)
        .or_else(|| {
            let p = std::ffi::CString::new(crate::fs::fd_path(fd)?).ok()?;
            read_path(&p)
        })
        .unwrap_or(host)
}

/// [`guest_perm_fd`] for `name` in directory `dir`.
pub fn guest_perm_at(dir: i32, name: &CStr, st: &libc::stat) -> u32 {
    let host = crate::modes::perm_of(st);
    if !marked(st) {
        return host;
    }
    path_of(dir, name).and_then(|p| read_path(&p)).unwrap_or(host)
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
    mark_fd(fd, &st, (host != perm & 0o7777).then_some(perm & 0o7777))
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
    let path = path_of(dir, name).ok_or(fwe_abi::errno::ENOENT)?;
    mark_path(&path, &st, (host != perm & 0o7777).then_some(perm & 0o7777))
}

/// Whether a caller without the capabilities may do `want` (`R_OK`,
/// `W_OK`, `X_OK` bits) to a file whose guest permission bits are `perm`:
/// what its owner may do (every file is the caller's own).
pub fn owner_allows(perm: u32, want: u32) -> bool {
    (perm >> 6) & want == want
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

fn path_of(dir: i32, name: &CStr) -> Option<std::ffi::CString> {
    let mut p = crate::fs::fd_path(dir)?;
    p.push(b'/');
    p.extend_from_slice(name.to_bytes());
    std::ffi::CString::new(p).ok()
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
                && !crate::owners::kept_fd(fd) =>
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
                && !crate::owners::kept_path(path) =>
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
        assert!(owner_allows(0o555, 4 | 1) && !owner_allows(0o555, 2));
        let _ = std::fs::remove_dir_all(&base);
    }
}
