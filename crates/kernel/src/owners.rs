//! Owners of files, which the host cannot keep.
//!
//! Every guest file is the host user's, which the guest sees as root
//! ([`crate::host::uid_to_initial`]). A file another owner has — one a
//! guest that is not root made, or one given away with `chown` — keeps
//! its owner, in the initial user namespace's ids, in the `org.fwe.owner`
//! attribute: a user id and a group id, little-endian. The file is flagged
//! as [`crate::modes`] flags a kept mode (the same host flag marks either),
//! so that a `stat` shows at once whether to look. A file whose owner is
//! root again loses the attribute.

use std::ffi::CStr;

#[cfg(target_os = "macos")]
const ATTR: &CStr = c"org.fwe.owner";

/// The owner the host's own metadata `st` gives a file: root (fwe's user
/// and group), or the overflow id for any other.
pub fn host_owner(st: &libc::stat) -> (u32, u32) {
    (crate::host::uid_to_initial(st.st_uid), crate::host::gid_to_initial(st.st_gid))
}

/// The owner, as initial-namespace ids, of the file open as `fd` whose
/// host metadata is `st`.
pub fn of_fd(fd: i32, st: &libc::stat) -> (u32, u32) {
    if !crate::modes::marked(st) {
        return host_owner(st);
    }
    // By its path where the descriptor reads no attribute (one opened only
    // to search a directory).
    read_fd(fd)
        .or_else(|| {
            let p = std::ffi::CString::new(crate::fs::fd_path(fd)?).ok()?;
            read_path(&p)
        })
        .unwrap_or_else(|| host_owner(st))
}

/// [`of_fd`] for `name` in directory `dir` (not followed).
pub fn of_at(dir: i32, name: &CStr, st: &libc::stat) -> (u32, u32) {
    if !crate::modes::marked(st) {
        return host_owner(st);
    }
    match path_of(dir, name) {
        Some(p) => read_path(&p),
        // A path too long for the host: through a descriptor of the file.
        None => crate::modes::open_at(dir, name)
            .and_then(|f| read_fd(std::os::fd::AsRawFd::as_raw_fd(&f))),
    }
    .unwrap_or_else(|| host_owner(st))
}

/// [`of_fd`] for the file at host path `path` (not followed).
pub fn of_path(path: &CStr, st: &libc::stat) -> (u32, u32) {
    if !crate::modes::marked(st) {
        return host_owner(st);
    }
    read_path(path).unwrap_or_else(|| host_owner(st))
}

/// Put the owner `(uid, gid)` in `st`, in place of the host's ids.
pub fn apply(st: &mut libc::stat, owner: (u32, u32)) {
    st.st_uid = owner.0;
    st.st_gid = owner.1;
}

/// Give the file open as `fd` the owner `owner`.
pub fn keep_fd(fd: i32, owner: (u32, u32)) -> Result<(), i32> {
    let st = fstat(fd)?;
    let record = (owner != host_owner(&st)).then_some(owner);
    mark_fd(fd, &st, record)
}

/// [`keep_fd`] for `name` in directory `dir`, a symbolic link itself if it
/// is one.
pub fn keep_at(dir: i32, name: &CStr, owner: (u32, u32)) -> Result<(), i32> {
    let st = fstatat(dir, name)?;
    let record = (owner != host_owner(&st)).then_some(owner);
    match path_of(dir, name) {
        Some(path) => mark_path(&path, &st, record),
        None => {
            let fd = crate::modes::open_at(dir, name).ok_or(fwe_abi::errno::ENOENT)?;
            mark_fd(std::os::fd::AsRawFd::as_raw_fd(&fd), &st, record)
        }
    }
}

/// Whether the file open as `fd` has an owner kept.
pub fn kept_fd(fd: i32) -> bool {
    read_fd(fd).is_some()
}

/// Whether the file at `path` has an owner kept.
pub fn kept_path(path: &CStr) -> bool {
    read_path(path).is_some()
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

/// The host path of `name` in directory `dir`, if the host takes one so
/// long (a longer one is reached through a descriptor instead).
fn path_of(dir: i32, name: &CStr) -> Option<std::ffi::CString> {
    let mut p = crate::fs::fd_path(dir)?;
    p.push(b'/');
    p.extend_from_slice(name.to_bytes());
    if p.len() >= libc::PATH_MAX as usize {
        return None;
    }
    std::ffi::CString::new(p).ok()
}

#[cfg(target_os = "macos")]
fn decode(buf: &[u8; 8], n: isize) -> Option<(u32, u32)> {
    (n == 8).then(|| {
        (
            u32::from_le_bytes(buf[..4].try_into().unwrap()),
            u32::from_le_bytes(buf[4..].try_into().unwrap()),
        )
    })
}

#[cfg(target_os = "macos")]
fn encode(owner: (u32, u32)) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[..4].copy_from_slice(&owner.0.to_le_bytes());
    v[4..].copy_from_slice(&owner.1.to_le_bytes());
    v
}

#[cfg(target_os = "macos")]
fn read_fd(fd: i32) -> Option<(u32, u32)> {
    let mut buf = [0u8; 8];
    // SAFETY: a valid buffer of 8 bytes.
    let n = unsafe { libc::fgetxattr(fd, ATTR.as_ptr(), buf.as_mut_ptr().cast(), 8, 0, 0) };
    decode(&buf, n)
}

#[cfg(target_os = "macos")]
fn read_path(path: &CStr) -> Option<(u32, u32)> {
    let mut buf = [0u8; 8];
    // SAFETY: a valid buffer of 8 bytes; the link itself, not followed.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            ATTR.as_ptr(),
            buf.as_mut_ptr().cast(),
            8,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    decode(&buf, n)
}

/// Keep `owner` for the file open as `fd` (or forget a kept one, for
/// `None`), whose metadata was `st`. The mark stays while a kept mode
/// needs it.
#[cfg(target_os = "macos")]
fn mark_fd(fd: i32, st: &libc::stat, owner: Option<(u32, u32)>) -> Result<(), i32> {
    // SAFETY: plain host calls on an open descriptor with valid buffers.
    unsafe {
        match owner {
            Some(o) => {
                let v = encode(o);
                if libc::fsetxattr(fd, ATTR.as_ptr(), v.as_ptr().cast(), 8, 0, 0) != 0 {
                    return Err(last());
                }
                crate::modes::set_mark_fd(fd, st, true);
            }
            None if crate::modes::marked(st)
                && libc::fremovexattr(fd, ATTR.as_ptr(), 0) == 0
                && !crate::modes::kept_fd(fd) =>
            {
                crate::modes::set_mark_fd(fd, st, false);
            }
            None => {}
        }
    }
    Ok(())
}

/// [`mark_fd`] by path (a symbolic link itself).
#[cfg(target_os = "macos")]
fn mark_path(path: &CStr, st: &libc::stat, owner: Option<(u32, u32)>) -> Result<(), i32> {
    // SAFETY: plain host calls on a NUL-terminated path with valid buffers.
    unsafe {
        match owner {
            Some(o) => {
                let v = encode(o);
                let set = libc::setxattr(
                    path.as_ptr(),
                    ATTR.as_ptr(),
                    v.as_ptr().cast(),
                    8,
                    0,
                    libc::XATTR_NOFOLLOW,
                );
                if set != 0 {
                    return Err(last());
                }
                crate::modes::set_mark_path(path, st, true);
            }
            None if crate::modes::marked(st)
                && libc::removexattr(path.as_ptr(), ATTR.as_ptr(), libc::XATTR_NOFOLLOW) == 0
                && !crate::modes::kept_path(path) =>
            {
                crate::modes::set_mark_path(path, st, false);
            }
            None => {}
        }
    }
    Ok(())
}

// Linux hosts run only the kernel's unit tests: the host's owner is the
// guest's.
#[cfg(not(target_os = "macos"))]
fn read_fd(_fd: i32) -> Option<(u32, u32)> {
    None
}

#[cfg(not(target_os = "macos"))]
fn read_path(_path: &CStr) -> Option<(u32, u32)> {
    None
}

#[cfg(not(target_os = "macos"))]
fn mark_fd(_fd: i32, _st: &libc::stat, _owner: Option<(u32, u32)>) -> Result<(), i32> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn mark_path(_path: &CStr, _st: &libc::stat, _owner: Option<(u32, u32)>) -> Result<(), i32> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn an_owner_is_kept_beside_a_kept_mode_and_forgotten_as_root() {
        let dir = std::env::temp_dir().join(format!("fwe-owner-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let f = std::fs::File::create(&dir).unwrap();
        let fd = f.as_raw_fd();
        keep_fd(fd, (1000, 100)).unwrap();
        assert_eq!(of_fd(fd, &fstat(fd).unwrap()), (1000, 100));
        // A kept mode as well; root again, the mode's mark stays.
        crate::modes::keep_fd(fd, 0o000).unwrap();
        keep_fd(fd, (0, 0)).unwrap();
        let st = fstat(fd).unwrap();
        assert_eq!(of_fd(fd, &st), (0, 0));
        assert!(crate::modes::marked(&st));
        assert_eq!(crate::modes::guest_perm_fd(fd, &st), 0);
        drop(f);
        let _ = std::fs::remove_file(&dir);
    }
}
