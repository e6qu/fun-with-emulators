//! Extended attributes: `setxattr`, `getxattr`, `listxattr`, `removexattr`
//! and their `l` and `f` forms.
//!
//! A Linux attribute is kept as the host attribute of the same name: its
//! name always starts with one of Linux's namespaces (`user.`, `trusted.`,
//! `security.`, `system.`), so it never meets the host's own (`com.apple.`)
//! or fwe's (`org.fwe.`), and a list shows only those in Linux's
//! namespaces. Linux's rules decide who may do what:
//!
//! - `user.` attributes are for regular files and directories only;
//! - `trusted.` ones need `CAP_SYS_ADMIN`, and are hidden from others;
//! - writing a `security.` one needs `CAP_SYS_ADMIN`, or `CAP_SETFCAP` for
//!   `security.capability`;
//! - `system.` holds POSIX ACLs, which fwe does not keep (`EOPNOTSUPP`).

use fwe_abi::errno;
use std::ffi::{CStr, CString};

/// The largest value Linux keeps.
pub const SIZE_MAX: usize = 65536;
/// The longest name.
const NAME_MAX: usize = 255;

/// `XATTR_CREATE` and `XATTR_REPLACE`.
pub const CREATE: u64 = 1;
pub const REPLACE: u64 = 2;

/// Linux's attribute namespaces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    User,
    Trusted,
    Security,
    System,
}

/// The namespace of attribute `name`: `ERANGE` for an empty or too long
/// name, `EOPNOTSUPP` for one in no namespace Linux knows.
pub fn space(name: &[u8]) -> Result<Space, i32> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(errno::ERANGE);
    }
    let spaces = [
        (&b"user."[..], Space::User),
        (b"trusted.", Space::Trusted),
        (b"security.", Space::Security),
        (b"system.", Space::System),
    ];
    spaces
        .iter()
        .find(|(p, _)| name.starts_with(p) && name.len() > p.len())
        .map(|&(_, s)| s)
        .ok_or(errno::EOPNOTSUPP)
}

/// What kind of file an attribute call acts on.
#[derive(Clone, Copy, Debug)]
pub struct Kind {
    /// A regular file or a directory (a device node fwe made is neither).
    pub plain: bool,
    /// Its kept mode, if its mode denies its owner ([`crate::modes`]).
    pub kept: Option<u32>,
}

impl Kind {
    /// The kind of the file whose host metadata is `st`, with its kept mode.
    pub fn of(st: &libc::stat, kept: Option<u32>) -> Kind {
        let kind = st.st_mode & libc::S_IFMT;
        let plain =
            (kind == libc::S_IFREG && !crate::devnodes::marked(st)) || kind == libc::S_IFDIR;
        Kind { plain, kept }
    }
}

/// What a caller is and what it acts on, for the permission checks.
pub struct Who {
    /// `CAP_SYS_ADMIN`, and `CAP_SETFCAP`.
    pub admin: bool,
    pub setfcap: bool,
    /// Whether it passes permission bits to read, and to write.
    pub read_any: bool,
    pub write_any: bool,
    pub kind: Kind,
}

impl Who {
    /// Whether the file's own permission bits let it do `want` (`R_OK`,
    /// `W_OK`): as the file's owner, of a kept mode (the host checks the
    /// rest).
    fn bits_allow(&self, want: u32) -> bool {
        let passes = if want & 2 != 0 { self.write_any } else { self.read_any };
        passes || self.kind.kept.is_none_or(|k| crate::modes::owner_allows(k, want))
    }

    /// Whether `name` (in `space`) may be read: `ENODATA` where Linux hides
    /// it.
    pub fn may_read(&self, space: Space) -> Result<(), i32> {
        match space {
            Space::System => Err(errno::EOPNOTSUPP),
            Space::Trusted if !self.admin => Err(errno::ENODATA),
            Space::User if !self.kind.plain => Err(errno::ENODATA),
            Space::User if !self.bits_allow(4) => Err(errno::EACCES),
            _ => Ok(()),
        }
    }

    /// Whether `name` (in `space`) may be set or removed.
    pub fn may_write(&self, name: &[u8], space: Space) -> Result<(), i32> {
        match space {
            Space::System => Err(errno::EOPNOTSUPP),
            Space::Trusted if !self.admin => Err(errno::EPERM),
            Space::Security if name == b"security.capability" && !self.setfcap => Err(errno::EPERM),
            Space::Security if name != b"security.capability" && !self.admin => Err(errno::EPERM),
            Space::User if !self.kind.plain => Err(errno::EPERM),
            Space::User if !self.bits_allow(2) => Err(errno::EACCES),
            _ => Ok(()),
        }
    }

    /// Whether a name the host lists is shown.
    fn shows(&self, name: &[u8]) -> bool {
        match space(name) {
            Ok(Space::Trusted) => self.admin,
            Ok(Space::System) => false,
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// What an attribute call acts on on the host: a file by path (never
/// followed: the caller resolved what is to be), or an open descriptor.
pub enum Target<'a> {
    Path(&'a CStr),
    Fd(i32),
}

fn host_name(name: &[u8]) -> Result<CString, i32> {
    CString::new(name).map_err(|_| errno::EINVAL)
}

fn fail<T>() -> Result<T, i32> {
    Err(crate::host::errno_to_linux(crate::host::last_errno()))
}

/// The value of attribute `name` of `t`.
pub fn get(t: &Target, name: &[u8]) -> Result<Vec<u8>, i32> {
    let n = host_name(name)?;
    loop {
        let size = raw_get(t, &n, std::ptr::null_mut(), 0);
        if size < 0 {
            return fail();
        }
        let mut buf = vec![0u8; size as usize];
        let got = raw_get(t, &n, buf.as_mut_ptr(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(buf);
        }
        // Grown since it was measured: measure again.
        if crate::host::last_errno() != libc::ERANGE {
            return fail();
        }
    }
}

/// Set attribute `name` of `t` to `value`, with Linux `flags`.
pub fn set(t: &Target, name: &[u8], value: &[u8], flags: u64) -> Result<(), i32> {
    if flags & !(CREATE | REPLACE) != 0 {
        return Err(errno::EINVAL);
    }
    if value.len() > SIZE_MAX {
        return Err(errno::E2BIG);
    }
    let mut host_flags = 0;
    if flags & CREATE != 0 {
        host_flags |= libc::XATTR_CREATE;
    }
    if flags & REPLACE != 0 {
        host_flags |= libc::XATTR_REPLACE;
    }
    let n = host_name(name)?;
    let (v, len) = (value.as_ptr().cast(), value.len());
    // SAFETY: valid name and value buffers.
    let r = unsafe {
        match t {
            #[cfg(target_os = "macos")]
            Target::Path(p) => {
                libc::setxattr(p.as_ptr(), n.as_ptr(), v, len, 0, host_flags | libc::XATTR_NOFOLLOW)
            }
            #[cfg(target_os = "macos")]
            Target::Fd(fd) => libc::fsetxattr(*fd, n.as_ptr(), v, len, 0, host_flags),
            #[cfg(not(target_os = "macos"))]
            Target::Path(p) => libc::lsetxattr(p.as_ptr(), n.as_ptr(), v, len, host_flags),
            #[cfg(not(target_os = "macos"))]
            Target::Fd(fd) => libc::fsetxattr(*fd, n.as_ptr(), v, len, host_flags),
        }
    };
    if r != 0 { fail() } else { Ok(()) }
}

/// Remove attribute `name` of `t`.
pub fn remove(t: &Target, name: &[u8]) -> Result<(), i32> {
    let n = host_name(name)?;
    // SAFETY: a valid name.
    let r = unsafe {
        match t {
            #[cfg(target_os = "macos")]
            Target::Path(p) => libc::removexattr(p.as_ptr(), n.as_ptr(), libc::XATTR_NOFOLLOW),
            #[cfg(target_os = "macos")]
            Target::Fd(fd) => libc::fremovexattr(*fd, n.as_ptr(), 0),
            #[cfg(not(target_os = "macos"))]
            Target::Path(p) => libc::lremovexattr(p.as_ptr(), n.as_ptr()),
            #[cfg(not(target_os = "macos"))]
            Target::Fd(fd) => libc::fremovexattr(*fd, n.as_ptr()),
        }
    };
    if r != 0 { fail() } else { Ok(()) }
}

/// The names of `t`'s attributes `who` sees, each NUL-terminated, as
/// `listxattr` returns them.
pub fn list(t: &Target, who: &Who) -> Result<Vec<u8>, i32> {
    let all = loop {
        let size = raw_list(t, std::ptr::null_mut(), 0);
        if size < 0 {
            return fail();
        }
        let mut buf = vec![0u8; size as usize];
        let got = raw_list(t, buf.as_mut_ptr(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            break buf;
        }
        if crate::host::last_errno() != libc::ERANGE {
            return fail();
        }
    };
    let mut out = Vec::new();
    for name in all.split(|&b| b == 0).filter(|n| !n.is_empty() && who.shows(n)) {
        out.extend_from_slice(name);
        out.push(0);
    }
    Ok(out)
}

fn raw_get(t: &Target, n: &CStr, buf: *mut u8, len: usize) -> isize {
    // SAFETY: `buf` is null with `len` 0, or valid for `len` bytes.
    unsafe {
        match t {
            #[cfg(target_os = "macos")]
            Target::Path(p) => {
                libc::getxattr(p.as_ptr(), n.as_ptr(), buf.cast(), len, 0, libc::XATTR_NOFOLLOW)
            }
            #[cfg(target_os = "macos")]
            Target::Fd(fd) => libc::fgetxattr(*fd, n.as_ptr(), buf.cast(), len, 0, 0),
            #[cfg(not(target_os = "macos"))]
            Target::Path(p) => libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf.cast(), len),
            #[cfg(not(target_os = "macos"))]
            Target::Fd(fd) => libc::fgetxattr(*fd, n.as_ptr(), buf.cast(), len),
        }
    }
}

fn raw_list(t: &Target, buf: *mut u8, len: usize) -> isize {
    // SAFETY: `buf` is null with `len` 0, or valid for `len` bytes.
    unsafe {
        match t {
            #[cfg(target_os = "macos")]
            Target::Path(p) => libc::listxattr(p.as_ptr(), buf.cast(), len, libc::XATTR_NOFOLLOW),
            #[cfg(target_os = "macos")]
            Target::Fd(fd) => libc::flistxattr(*fd, buf.cast(), len, 0),
            #[cfg(not(target_os = "macos"))]
            Target::Path(p) => libc::llistxattr(p.as_ptr(), buf.cast(), len),
            #[cfg(not(target_os = "macos"))]
            Target::Fd(fd) => libc::flistxattr(*fd, buf.cast(), len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_have_a_linux_namespace() {
        assert_eq!(space(b"user.x"), Ok(Space::User));
        assert_eq!(space(b"trusted.overlay.opaque"), Ok(Space::Trusted));
        assert_eq!(space(b"security.capability"), Ok(Space::Security));
        assert_eq!(space(b"system.posix_acl_access"), Ok(Space::System));
        assert_eq!(space(b"user."), Err(errno::EOPNOTSUPP));
        assert_eq!(space(b"com.apple.quarantine"), Err(errno::EOPNOTSUPP));
        assert_eq!(space(b""), Err(errno::ERANGE));
        assert_eq!(space(&[b'u'; 256]), Err(errno::ERANGE));
    }

    #[test]
    fn rules_by_namespace() {
        let file = Kind { plain: true, kept: None };
        let user =
            Who { admin: false, setfcap: false, read_any: false, write_any: false, kind: file };
        assert_eq!(user.may_read(Space::Trusted), Err(errno::ENODATA));
        assert_eq!(user.may_write(b"trusted.x", Space::Trusted), Err(errno::EPERM));
        assert_eq!(user.may_write(b"user.x", Space::User), Ok(()));
        assert_eq!(user.may_write(b"security.selinux", Space::Security), Err(errno::EPERM));
        assert!(!user.shows(b"trusted.x") && user.shows(b"user.x") && !user.shows(b"org.fwe.dev"));
        let read_only = Kind { plain: true, kept: Some(0o444) };
        let user = Who { kind: read_only, ..user };
        assert_eq!(user.may_write(b"user.x", Space::User), Err(errno::EACCES));
        assert_eq!(user.may_read(Space::User), Ok(()));
        let node = Kind { plain: false, kept: None };
        let node = Who { admin: true, setfcap: true, read_any: true, write_any: true, kind: node };
        assert_eq!(node.may_write(b"user.x", Space::User), Err(errno::EPERM));
        assert_eq!(node.may_read(Space::User), Err(errno::ENODATA));
        assert_eq!(node.may_write(b"trusted.x", Space::Trusted), Ok(()));
    }

    /// On the host fwe runs on: a Linux host keeps `trusted.` attributes
    /// for its root.
    #[cfg(target_os = "macos")]
    #[test]
    fn set_get_list_remove_on_a_file() {
        let dir = std::env::temp_dir().join(format!("fwe-xattr-{}", std::process::id()));
        std::fs::write(&dir, b"").unwrap();
        let path = CString::new(dir.to_str().unwrap()).unwrap();
        let t = Target::Path(&path);
        let who = Who {
            admin: true,
            setfcap: true,
            read_any: true,
            write_any: true,
            kind: Kind { plain: true, kept: None },
        };
        set(&t, b"user.a", b"1", 0).unwrap();
        set(&t, b"trusted.b", b"22", CREATE).unwrap();
        assert_eq!(set(&t, b"trusted.b", b"3", CREATE), Err(errno::EEXIST));
        assert_eq!(set(&t, b"user.c", b"3", REPLACE), Err(errno::ENODATA));
        assert_eq!(get(&t, b"trusted.b").unwrap(), b"22");
        let mut names: Vec<&[u8]> = Vec::new();
        let l = list(&t, &who).unwrap();
        names.extend(l.split(|&b| b == 0).filter(|n| !n.is_empty()));
        names.sort();
        assert_eq!(names, [&b"trusted.b"[..], b"user.a"]);
        remove(&t, b"user.a").unwrap();
        assert_eq!(get(&t, b"user.a"), Err(errno::ENODATA));
        let _ = std::fs::remove_file(&dir);
    }
}
