//! Extended attributes: `setxattr`, `getxattr`, `listxattr`, `removexattr`
//! and their `l` and `f` forms.
//!
//! A Linux attribute is kept as the host attribute of the same name: its
//! name always starts with one of Linux's namespaces (`user.`, `trusted.`,
//! `security.`, `system.`), so it never meets the host's own (`com.apple.`)
//! or fwe's (`org.fwe.`), and a list shows only those in Linux's
//! namespaces. Linux's rules decide who may do what:
//!
//! - `user.` attributes are for regular files and directories only, and a
//!   sticky directory's are changed only by its owner (or with
//!   `CAP_FOWNER`);

//! - `trusted.` ones need `CAP_SYS_ADMIN`, and are hidden from others;
//! - writing a `security.` one needs `CAP_SYS_ADMIN`, or `CAP_SETFCAP` for
//!   `security.capability`;
//! - `system.` holds POSIX ACLs, which fwe does not keep (`EOPNOTSUPP`).
//!
//! `security.capability` (file capabilities) is checked as it is written,
//! revision 2 or 3 only, and kept as Linux keeps it: from a user namespace
//! of fwe's as revision 3, naming the root it is for as the initial
//! namespace's id; and read back as the reader's namespace sees it
//! ([`store_file_caps`], [`show_file_caps`]). A change of owner, and a
//! write, remove it ([`kill_file_caps`]).

use fwe_abi::errno;
use std::ffi::{CStr, CString};

/// File capabilities' attribute.
pub const CAPABILITY: &[u8] = b"security.capability";

/// `vfs_cap_data`'s revisions, in its first word, and their sizes.
const REVISION_MASK: u32 = 0xff00_0000;
const REVISION_2: u32 = 0x0200_0000;
const REVISION_3: u32 = 0x0300_0000;
const SIZE_2: usize = 20;
const SIZE_3: usize = 24;

fn word(v: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(v[i * 4..i * 4 + 4].try_into().unwrap())
}

/// A file-capabilities value of `magic`'s flags and `v`'s sets, as
/// revision 2, or with `rootid` revision 3.
fn caps_value(v: &[u8], rootid: Option<u32>) -> Vec<u8> {
    let rev = if rootid.is_some() { REVISION_3 } else { REVISION_2 };
    let mut out = ((word(v, 0) & !REVISION_MASK) | rev).to_le_bytes().to_vec();
    out.extend_from_slice(&v[4..SIZE_2]);
    if let Some(r) = rootid {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out
}

/// What a `security.capability` value `v` written by this process is kept
/// as (Linux's `cap_convert_nscap`): only revision 2 (20 bytes) or 3 (24),
/// else `EINVAL`. Revision 2 from the initial user namespace is kept as it
/// is; any other becomes revision 3 for its root, the writer's
/// namespace's (revision 2) or the one it names (revision 3), as the
/// initial namespace's id (`EINVAL` if it has none).
pub fn store_file_caps(v: &[u8]) -> Result<Vec<u8>, i32> {
    let rev = match v.len() {
        SIZE_2 | SIZE_3 => word(v, 0) & REVISION_MASK,
        _ => return Err(errno::EINVAL),
    };
    let ns_root = match (v.len(), rev) {
        (SIZE_2, REVISION_2) if !crate::userns::nested() => return Ok(v.to_vec()),
        (SIZE_2, REVISION_2) => 0,
        (SIZE_3, REVISION_3) => word(v, 5),
        _ => return Err(errno::EINVAL),
    };
    let kroot = crate::userns::from_ns(ns_root, false).ok_or(errno::EINVAL)?;
    Ok(caps_value(v, Some(kroot)))
}

/// A kept `security.capability` value `v` as this process reads it
/// (Linux's `cap_inode_getsecurity`): revision 3 for a root mapped in its
/// user namespace (other than its own root) with that id; revision 2 for
/// one that is root of its namespace or one above; `EOVERFLOW` for any
/// other.
pub fn show_file_caps(v: Vec<u8>) -> Result<Vec<u8>, i32> {
    if v.len() != SIZE_3 || word(&v, 0) & REVISION_MASK != REVISION_3 {
        return Ok(v);
    }
    let kroot = word(&v, 5);
    if crate::userns::mapped(kroot, false) {
        let mapped = crate::userns::to_ns(kroot, false);
        if mapped != 0 {
            return Ok(caps_value(&v, Some(mapped)));
        }
    }
    if crate::userns::roots_above().contains(&kroot) {
        Ok(caps_value(&v, None))
    } else {
        Err(errno::EOVERFLOW)
    }
}

/// Whether the file `t` names has file capabilities.
pub fn has_file_caps(t: &Target) -> bool {
    if let Some(file) = stored(t) {
        return in_store(file, |s| s.xattr(file.ino, CAPABILITY)).is_ok();
    }
    let Ok(n) = host_name(CAPABILITY) else { return false };
    raw_get(t, &n, std::ptr::null_mut(), 0) >= 0
}

/// Remove the file capabilities of the file `t` names, if it has any, as
/// Linux does on a change of owner and on a write
/// (`security_inode_killpriv`), whoever makes it.
pub fn kill_file_caps(t: &Target) {
    if has_file_caps(t) {
        let _ = remove(t, CAPABILITY);
    }
}

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
    /// Its guest mode (with its type) and owner, for the permission
    /// check ([`crate::modes`], [`crate::owners`]).
    pub meta: (u32, u32, u32),
}

impl Kind {
    /// The kind of the file whose host metadata is `st`, with its guest
    /// mode and owner.
    #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
    pub fn of(st: &libc::stat, perm: u32, owner: (u32, u32)) -> Kind {
        let kind = st.st_mode & libc::S_IFMT;
        let plain =
            (kind == libc::S_IFREG && !crate::devnodes::marked(st)) || kind == libc::S_IFDIR;
        let mode = (st.st_mode as u32 & libc::S_IFMT as u32) | perm;
        Kind { plain, meta: (mode, owner.0, owner.1) }
    }

    /// Whether it is a directory with the sticky bit.
    fn sticky_dir(&self) -> bool {
        self.meta.0 & 0o171000 == 0o41000
    }
}

/// What a caller is and what it acts on, for the permission checks.
pub struct Who {
    /// `CAP_SYS_ADMIN`, and `CAP_SETFCAP`.
    pub admin: bool,
    pub setfcap: bool,
    /// Whether it may read the file, and write it: by its permission
    /// bits, or passing them.
    pub read_any: bool,
    pub write_any: bool,
    /// Whether it owns the file, or has `CAP_FOWNER` over it.
    pub owner: bool,
    pub kind: Kind,
}

impl Who {
    /// Whether it may do `want` (`R_OK`, `W_OK`) to the file.
    fn bits_allow(&self, want: u32) -> bool {
        if want & 2 != 0 { self.write_any } else { self.read_any }
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
            // A sticky directory's are its owner's to change, as its
            // entries are.
            Space::User if self.kind.sticky_dir() && !self.owner => Err(errno::EPERM),
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
/// followed: the caller resolved what is to be), or an open descriptor (a
/// file of fwe's store's is the store's: [`stored`]).
pub enum Target<'a> {
    Path(&'a CStr),
    Fd(i32),
    /// A file of fwe's store, found by its path (a tmpfs's).
    Store(crate::filestore::desc::File),
}

/// The file of fwe's store `t` is a descriptor of, if it is one: its
/// attributes are the store's.
fn stored(t: &Target) -> Option<crate::filestore::desc::File> {
    match t {
        Target::Fd(fd) => crate::filestore::desc::of(*fd),
        Target::Store(file) => Some(*file),
        Target::Path(_) => None,
    }
}

/// `f` on the store's filesystem of `file`, held.
fn in_store<R>(
    file: crate::filestore::desc::File,
    f: impl FnOnce(&mut crate::filestore::tree::Tx) -> Result<R, i32>,
) -> Result<R, i32> {
    let fs = file.fs()?;
    let mut t = fs.lock()?;
    f(&mut t)
}

/// The Linux inode flags that leave a file's attributes unchangeable
/// (`FS_IMMUTABLE_FL`, `FS_APPEND_FL`).
#[cfg(target_os = "macos")]
const FROZEN_FLAGS: u32 = 0x10 | 0x20;

fn host_name(name: &[u8]) -> Result<CString, i32> {
    CString::new(name).map_err(|_| errno::EINVAL)
}

fn fail<T>() -> Result<T, i32> {
    Err(crate::host::errno_to_linux(crate::host::last_errno()))
}

/// The value of attribute `name` of `t`.
pub fn get(t: &Target, name: &[u8]) -> Result<Vec<u8>, i32> {
    if let Some(file) = stored(t) {
        return in_store(file, |s| s.xattr(file.ino, name));
    }
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

/// Whether the file `t` names is immutable or append-only, whose
/// attributes Linux lets no one change (the host does).
#[cfg(target_os = "macos")]
fn frozen(t: &Target) -> bool {
    if let Some(file) = stored(t) {
        return in_store(file, |s| s.stat(file.ino)).is_ok_and(|st| st.flags & FROZEN_FLAGS != 0);
    }
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid path or descriptor, and the out-parameter above.
    let r = unsafe {
        match t {
            Target::Path(p) => libc::lstat(p.as_ptr(), &mut st),
            Target::Fd(fd) => libc::fstat(*fd, &mut st),
            // (Taken above.)
            Target::Store(_) => -1,
        }
    };
    r == 0 && st.st_flags & (libc::UF_IMMUTABLE | libc::UF_APPEND) != 0
}

#[cfg(not(target_os = "macos"))]
fn frozen(_: &Target) -> bool {
    false
}

/// Set attribute `name` of `t` to `value`, with Linux `flags`.
pub fn set(t: &Target, name: &[u8], value: &[u8], flags: u64) -> Result<(), i32> {
    if flags & !(CREATE | REPLACE) != 0 {
        return Err(errno::EINVAL);
    }
    if frozen(t) {
        return Err(errno::EPERM);
    }
    if value.len() > SIZE_MAX {
        return Err(errno::E2BIG);
    }
    if let Some(file) = stored(t) {
        return in_store(file, |s| {
            let had = s.xattr(file.ino, name).is_ok();
            if flags & CREATE != 0 && had {
                return Err(errno::EEXIST);
            }
            if flags & REPLACE != 0 && !had {
                return Err(errno::ENODATA);
            }
            s.set_xattr(file.ino, name, Some(value))
        });
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
    let raw = || unsafe {
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
            // A file of fwe's store is the store's ([`stored`]).
            Target::Store(_) => -1,
        }
    };
    owned(t, raw)
}

/// Run `raw`, a host call that changes `t`'s attributes, which fwe has
/// allowed: refused by host bits that deny the owner (a file made with
/// such a mode, [`crate::modes::made_file_perm`]), the mode is kept apart
/// and `raw` run again.
fn owned(t: &Target, raw: impl Fn() -> i32) -> Result<(), i32> {
    if raw() == 0 {
        return Ok(());
    }
    let e = fail();
    if e != Err(errno::EACCES) {
        return e;
    }
    let kept = match t {
        Target::Path(p) => crate::modes::own_path(p),
        Target::Fd(fd) => crate::modes::own_fd(*fd),
        Target::Store(_) => Err(errno::EACCES),
    };
    if kept.is_err() {
        return e;
    }
    if raw() != 0 { fail() } else { Ok(()) }
}

/// Remove attribute `name` of `t`.
pub fn remove(t: &Target, name: &[u8]) -> Result<(), i32> {
    if frozen(t) {
        return Err(errno::EPERM);
    }
    if let Some(file) = stored(t) {
        return in_store(file, |s| s.set_xattr(file.ino, name, None));
    }
    let n = host_name(name)?;
    // SAFETY: a valid name.
    let raw = || unsafe {
        match t {
            #[cfg(target_os = "macos")]
            Target::Path(p) => libc::removexattr(p.as_ptr(), n.as_ptr(), libc::XATTR_NOFOLLOW),
            #[cfg(target_os = "macos")]
            Target::Fd(fd) => libc::fremovexattr(*fd, n.as_ptr(), 0),
            #[cfg(not(target_os = "macos"))]
            Target::Path(p) => libc::lremovexattr(p.as_ptr(), n.as_ptr()),
            #[cfg(not(target_os = "macos"))]
            Target::Fd(fd) => libc::fremovexattr(*fd, n.as_ptr()),
            // A file of fwe's store is the store's ([`stored`]).
            Target::Store(_) => -1,
        }
    };
    owned(t, raw)
}

/// The names of `t`'s attributes `who` sees, each NUL-terminated, as
/// `listxattr` returns them.
pub fn list(t: &Target, who: &Who) -> Result<Vec<u8>, i32> {
    let all = if let Some(file) = stored(t) {
        // (Not fwe's own, which start with a NUL no guest's name has.)
        in_store(file, |s| s.xattrs(file.ino))?
            .into_iter()
            .filter(|(n, _)| n.first() != Some(&0))
            .flat_map(|(n, _)| n.into_iter().chain([0]))
            .collect()
    } else {
        list_raw(t)?
    };
    let mut out = Vec::new();
    for name in all.split(|&b| b == 0).filter(|n| !n.is_empty() && who.shows(n)) {
        out.extend_from_slice(name);
        out.push(0);
    }
    Ok(out)
}

/// The names of every attribute of `t`: on the host, fwe's and the
/// host's own too; in the store, all but fwe's own.
pub fn names(t: &Target) -> Result<Vec<Vec<u8>>, i32> {
    if let Some(file) = stored(t) {
        return Ok(in_store(file, |s| s.xattrs(file.ino))?
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| n.first() != Some(&0))
            .collect());
    }
    Ok(list_raw(t)?.split(|&b| b == 0).filter(|n| !n.is_empty()).map(<[u8]>::to_vec).collect())
}

/// Every host attribute name of `t`, each NUL-terminated.
fn list_raw(t: &Target) -> Result<Vec<u8>, i32> {
    Ok(loop {
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
    })
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
            // A file of fwe's store is the store's ([`stored`]).
            Target::Store(_) => -1,
        }
    }
}

/// The value of host attribute `name` (any, fwe's own included) of the
/// file open as `fd`.
pub fn get_host(fd: i32, name: &[u8]) -> Result<Vec<u8>, i32> {
    get(&Target::Fd(fd), name)
}

/// Set host attribute `name` of the file open as `fd`.
pub fn set_host(fd: i32, name: &[u8], value: &[u8]) -> Result<(), i32> {
    set(&Target::Fd(fd), name, value, 0)
}

/// Every host attribute name of the file open as `fd`, each
/// NUL-terminated.
pub fn list_host(fd: i32) -> Result<Vec<u8>, i32> {
    loop {
        let size = raw_list(&Target::Fd(fd), std::ptr::null_mut(), 0);
        if size < 0 {
            return fail();
        }
        let mut buf = vec![0u8; size as usize];
        let got = raw_list(&Target::Fd(fd), buf.as_mut_ptr(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(buf);
        }
        if crate::host::last_errno() != libc::ERANGE {
            return fail();
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
            // A file of fwe's store is the store's ([`stored`]).
            Target::Store(_) => -1,
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
        let file = Kind { plain: true, meta: (0o100644, 0, 0) };
        let user = Who {
            admin: false,
            setfcap: false,
            read_any: true,
            write_any: true,
            owner: false,
            kind: file,
        };
        assert_eq!(user.may_read(Space::Trusted), Err(errno::ENODATA));
        assert_eq!(user.may_write(b"trusted.x", Space::Trusted), Err(errno::EPERM));
        assert_eq!(user.may_write(b"user.x", Space::User), Ok(()));
        assert_eq!(user.may_write(b"security.selinux", Space::Security), Err(errno::EPERM));
        assert!(!user.shows(b"trusted.x") && user.shows(b"user.x") && !user.shows(b"org.fwe.dev"));
        let read_only = Kind { plain: true, meta: (0o100444, 0, 0) };
        let user = Who { kind: read_only, write_any: false, ..user };
        assert_eq!(user.may_write(b"user.x", Space::User), Err(errno::EACCES));
        assert_eq!(user.may_read(Space::User), Ok(()));
        let node = Kind { plain: false, meta: (0o20644, 0, 0) };
        let node = Who { kind: node, admin: true, setfcap: true, owner: true, ..user };
        assert_eq!(node.may_write(b"user.x", Space::User), Err(errno::EPERM));
        assert_eq!(node.may_read(Space::User), Err(errno::ENODATA));
        assert_eq!(node.may_write(b"trusted.x", Space::Trusted), Ok(()));
    }

    /// A sticky directory's `user.` attributes are changed by its owner
    /// (or with `CAP_FOWNER`) only, whatever its bits allow; read by any
    /// who may read it (Linux's `xattr_permission`).
    #[test]
    fn sticky_directory_attributes_are_the_owners() {
        let tmp = Kind { plain: true, meta: (0o41777, 0, 0) };
        let other = Who {
            admin: false,
            setfcap: false,
            read_any: true,
            write_any: true,
            owner: false,
            kind: tmp,
        };
        assert_eq!(other.may_write(b"user.x", Space::User), Err(errno::EPERM));
        assert_eq!(other.may_read(Space::User), Ok(()));
        let owner = Who { owner: true, ..other };
        assert_eq!(owner.may_write(b"user.x", Space::User), Ok(()));
        let plain = Who { kind: Kind { plain: true, meta: (0o40777, 0, 0) }, ..other };
        assert_eq!(plain.may_write(b"user.x", Space::User), Ok(()));
        // A sticky regular file is no directory.
        let file = Who { kind: Kind { plain: true, meta: (0o101666, 0, 0) }, ..other };
        assert_eq!(file.may_write(b"user.x", Space::User), Ok(()));
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
            owner: true,
            kind: Kind { plain: true, meta: (0o100644, 0, 0) },
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
        // File capabilities go at once.
        set(&t, CAPABILITY, &[0; 20], 0).unwrap();
        assert!(has_file_caps(&t));
        kill_file_caps(&t);
        assert!(!has_file_caps(&t));
        let _ = std::fs::remove_file(&dir);
    }

    /// File capabilities are written as revision 2 or 3 only, of their
    /// sizes; revision 2 is kept as it is in the initial namespace, and
    /// revision 3 names its root as the initial namespace's id, which a
    /// reader sees as its namespace does.
    #[test]
    fn file_capabilities_are_checked_and_kept_as_linux_keeps_them() {
        let v = |magic: u32, words: &[u32]| {
            let mut out = magic.to_le_bytes().to_vec();
            for w in words {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out
        };
        let v1 = v(0x0100_0001, &[1 << 7, 0]);
        assert_eq!(store_file_caps(&v1), Err(errno::EINVAL));
        assert_eq!(store_file_caps(&[0; 7]), Err(errno::EINVAL));
        let v2 = v(0x0200_0001, &[1 << 7, 0, 0, 0]);
        assert_eq!(store_file_caps(&v2), Ok(v2.clone()));
        // A revision 3 header on a revision 2 size, and the other way.
        assert_eq!(store_file_caps(&v(0x0300_0001, &[1 << 7, 0, 0, 0])), Err(errno::EINVAL));
        assert_eq!(store_file_caps(&v(0x0200_0001, &[1 << 7, 0, 0, 0, 0])), Err(errno::EINVAL));
        let v3 = v(0x0300_0001, &[1 << 7, 0, 0, 0, 1000]);
        assert_eq!(store_file_caps(&v3), Ok(v3.clone()));
        // Read back: for another root as it is; for root, revision 2.
        assert_eq!(show_file_caps(v3.clone()), Ok(v3));
        assert_eq!(show_file_caps(v(0x0300_0001, &[1 << 7, 0, 0, 0, 0])), Ok(v2.clone()));
        assert_eq!(show_file_caps(v2.clone()), Ok(v2));
    }
}
