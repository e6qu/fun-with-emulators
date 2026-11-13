//! Landlock: a process restricting itself (`landlock_create_ruleset`,
//! `landlock_add_rule`, `landlock_restrict_self`).
//!
//! A ruleset is the process's, kept against its descriptor (a file of
//! fwe's, by its host identity). `landlock_restrict_self` adds it to the
//! process's domain as a layer; the domain goes with the process across
//! `fork` and `execve` and can only grow. Every layer is checked:
//!
//! - **Files:** an access a layer handles is allowed if a rule of the
//!   layer grants it on the file or on a directory above it, by host
//!   identity (device and inode) up the file's host path: opening to read
//!   or write a file or read a directory, executing, making and removing
//!   each kind of file in a directory, truncating (decided as a file is
//!   opened, for `ftruncate`), and moving a file between directories
//!   (`REFER` in both, or `EXDEV`). A denied access is `EACCES`.
//! - **TCP ports:** `bind` and `connect` to a port a rule names.
//! - **Scopes:** a signal, or a connection to an abstract socket, to a
//!   process outside a scoping layer's domain is `EPERM`. Each layer has
//!   an id, and a process restricted publishes its chain of ids (a file
//!   beside the process records) for others to compare with theirs.
//!
//! Nothing is looked at while the process has no domain: one flag.

use fwe_abi::errno;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The ABI fwe implements: Linux 6.12's.
pub const ABI: i64 = 6;

pub const EXECUTE: u64 = 1 << 0;
pub const WRITE_FILE: u64 = 1 << 1;
pub const READ_FILE: u64 = 1 << 2;
pub const READ_DIR: u64 = 1 << 3;
pub const REMOVE_DIR: u64 = 1 << 4;
pub const REMOVE_FILE: u64 = 1 << 5;
pub const MAKE_CHAR: u64 = 1 << 6;
pub const MAKE_DIR: u64 = 1 << 7;
pub const MAKE_REG: u64 = 1 << 8;
pub const MAKE_SOCK: u64 = 1 << 9;
pub const MAKE_FIFO: u64 = 1 << 10;
pub const MAKE_BLOCK: u64 = 1 << 11;
pub const MAKE_SYM: u64 = 1 << 12;
pub const REFER: u64 = 1 << 13;
pub const TRUNCATE: u64 = 1 << 14;
pub const IOCTL_DEV: u64 = 1 << 15;
const MASK_FS: u64 = (1 << 16) - 1;
/// The rights that apply to a file itself; the rest to a directory's
/// contents.
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

pub const BIND_TCP: u64 = 1 << 0;
pub const CONNECT_TCP: u64 = 1 << 1;
const MASK_NET: u64 = 3;

pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const SCOPE_SIGNAL: u64 = 1 << 1;
const MASK_SCOPE: u64 = 3;

const CREATE_RULESET_VERSION: u64 = 1;
const RULE_PATH_BENEATH: u64 = 1;
const RULE_NET_PORT: u64 = 2;
/// The most layers a domain may have.
const MAX_LAYERS: usize = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ruleset {
    fs: u64,
    net: u64,
    scoped: u64,
    /// Path rules: the host identity of the file or directory, its rights,
    /// and whether it is a directory.
    paths: Vec<((u64, u64), u64, bool)>,
    /// Port rules: the port and its rights.
    ports: Vec<(u64, u64)>,
}

/// The process's rulesets, by their descriptors' host identity.
pub(crate) static RULESETS: Mutex<Vec<((u64, u64), Ruleset)>> = Mutex::new(Vec::new());

/// The process's domain: each layer's id and ruleset.
pub(crate) static DOMAIN: Mutex<Vec<(u64, Ruleset)>> = Mutex::new(Vec::new());
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Descriptors opened without the right to truncate their file.
pub(crate) static NO_TRUNCATE: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Whether the process is restricted at all.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

fn fd_identity(fd: i32) -> Option<(libc::stat, (u64, u64))> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then(|| (st, identity(&st)))
}

fn ruleset_of(fd: i32) -> Result<Ruleset, i32> {
    let (_, id) = fd_identity(fd).ok_or(errno::EBADF)?;
    let r = RULESETS.lock().unwrap_or_else(|e| e.into_inner());
    r.iter().find(|(i, _)| *i == id).map(|(_, rs)| rs.clone()).ok_or(errno::EBADFD)
}

/// `landlock_create_ruleset(attr, size, flags)`.
pub fn create_ruleset(attr: u64, size: u64, flags: u64) -> Result<i64, i32> {
    if flags != 0 {
        return if flags == CREATE_RULESET_VERSION && attr == 0 && size == 0 {
            Ok(ABI)
        } else {
            Err(errno::EINVAL)
        };
    }
    if size < 8 {
        return Err(errno::EINVAL);
    }
    if size > 4096 {
        return Err(errno::E2BIG);
    }
    let b = crate::uaccess::read_bytes(attr, size as usize)?;
    if b.iter().skip(24).any(|&x| x != 0) {
        return Err(errno::E2BIG);
    }
    let word = |i: usize| b.get(i..i + 8).map_or(0, |w| u64::from_ne_bytes(w.try_into().unwrap()));
    let rs = Ruleset { fs: word(0), net: word(8), scoped: word(16), ..Ruleset::default() };
    if rs.fs & !MASK_FS != 0 || rs.net & !MASK_NET != 0 || rs.scoped & !MASK_SCOPE != 0 {
        return Err(errno::EINVAL);
    }
    if rs.fs == 0 && rs.net == 0 && rs.scoped == 0 {
        return Err(errno::ENOMSG);
    }
    let fd = anon_file()?;
    let (_, id) = fd_identity(fd).ok_or(errno::EBADF)?;
    RULESETS.lock().unwrap_or_else(|e| e.into_inner()).push((id, rs));
    Ok(i64::from(fd))
}

/// A fresh file of fwe's, unnamed, standing for a ruleset.
fn anon_file() -> Result<i32, i32> {
    static N: AtomicU64 = AtomicU64::new(0);
    let mut path = crate::procreg::records_dir().ok_or(errno::ENOMEM)?;
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    path.extend_from_slice(
        format!("/landlock-{pid}-{}", N.fetch_add(1, Ordering::Relaxed)).as_bytes(),
    );
    let p = std::ffi::CString::new(path).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory, unlinked
    // once open.
    unsafe {
        let fd = libc::open(
            p.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        );
        if fd < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        libc::unlink(p.as_ptr());
        Ok(fd)
    }
}

/// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`.
pub fn add_rule(fd: i32, ty: u64, attr: u64, flags: u64) -> Result<i64, i32> {
    if flags != 0 {
        return Err(errno::EINVAL);
    }
    let rs = ruleset_of(fd)?;
    let rule: Rule = match ty {
        RULE_PATH_BENEATH => {
            let b = crate::uaccess::read_bytes(attr, 12)?;
            let access = u64::from_ne_bytes(b[..8].try_into().unwrap());
            let parent = i32::from_ne_bytes(b[8..12].try_into().unwrap());
            if access == 0 {
                return Err(errno::ENOMSG);
            }
            if access & !rs.fs != 0 {
                return Err(errno::EINVAL);
            }
            let (st, id) = fd_identity(parent)
                .filter(|_| crate::fdtable::guest_visible(parent))
                .ok_or(errno::EBADF)?;
            let dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
            if !dir && access & !FILE_RIGHTS != 0 {
                return Err(errno::EINVAL);
            }
            Rule::Path(id, access, dir)
        }
        RULE_NET_PORT => {
            let b = crate::uaccess::read_bytes(attr, 16)?;
            let access = u64::from_ne_bytes(b[..8].try_into().unwrap());
            let port = u64::from_ne_bytes(b[8..16].try_into().unwrap());
            if access == 0 {
                return Err(errno::ENOMSG);
            }
            if access & !rs.net != 0 || port > u64::from(u16::MAX) {
                return Err(errno::EINVAL);
            }
            Rule::Port(port, access)
        }
        _ => return Err(errno::EINVAL),
    };
    let (_, id) = fd_identity(fd).ok_or(errno::EBADF)?;
    let mut r = RULESETS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, rs)) = r.iter_mut().find(|(i, _)| *i == id) {
        match rule {
            Rule::Path(obj, access, dir) => match rs.paths.iter_mut().find(|p| p.0 == obj) {
                Some(p) => p.1 |= access,
                None => rs.paths.push((obj, access, dir)),
            },
            Rule::Port(port, access) => match rs.ports.iter_mut().find(|p| p.0 == port) {
                Some(p) => p.1 |= access,
                None => rs.ports.push((port, access)),
            },
        }
    }
    Ok(0)
}

enum Rule {
    Path((u64, u64), u64, bool),
    Port(u64, u64),
}

/// `landlock_restrict_self(ruleset_fd, flags)`; `privileged` the caller
/// has `no_new_privs` set or `CAP_SYS_ADMIN`.
pub fn restrict_self(fd: i32, flags: u64, privileged: bool) -> Result<i64, i32> {
    if flags != 0 {
        return Err(errno::EINVAL);
    }
    if !privileged {
        return Err(errno::EPERM);
    }
    let rs = ruleset_of(fd)?;
    let mut d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    if d.len() >= MAX_LAYERS {
        return Err(errno::E2BIG);
    }
    let mut id = [0u8; 8];
    crate::host::fill_random(&mut id);
    d.push((u64::from_ne_bytes(id), rs));
    ACTIVE.store(true, Ordering::Relaxed);
    drop(d);
    publish();
    Ok(0)
}

/// The domain's layer ids, oldest first.
fn chain() -> Vec<u64> {
    DOMAIN.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|l| l.0).collect()
}

fn chain_file(pid: i32) -> Option<std::path::PathBuf> {
    let dir = crate::procreg::records_dir()?;
    Some(
        std::path::Path::new(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&dir))
            .join(format!("landlock-domain-{pid}")),
    )
}

/// Publish this process's chain for others ([`within`]); called as it is
/// restricted and as a restricted process starts (a fork child, a program
/// run).
pub fn publish() {
    if !active() {
        return;
    }
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    let Some(p) = chain_file(me) else { return };
    let mut b = Vec::new();
    if let Some(start) = crate::procreg::start_time(me) {
        b.extend_from_slice(&start.to_ne_bytes());
    }
    for id in chain() {
        b.extend_from_slice(&id.to_ne_bytes());
    }
    let tmp = p.with_extension("new");
    if std::fs::write(&tmp, b).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// Host process `pid`'s chain (none if it is not restricted, or the file
/// is a former process's).
fn chain_of(pid: i32) -> Vec<u64> {
    let Some(b) = chain_file(pid).and_then(|p| std::fs::read(p).ok()) else { return Vec::new() };
    let words: Vec<u64> = b.as_chunks::<8>().0.iter().map(|c| u64::from_ne_bytes(*c)).collect();
    match (words.split_first(), crate::procreg::start_time(pid)) {
        (Some((&start, rest)), Some(now)) if start == now => rest.to_vec(),
        _ => Vec::new(),
    }
}

/// Whether host process `target` is inside every layer of this process's
/// domain that scopes `scope` (it is the same domain or one nested in it).
fn within(target: i32, scope: u64) -> bool {
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    if !d.iter().any(|l| l.1.scoped & scope != 0) {
        return true;
    }
    let mine: Vec<(u64, u64)> = d.iter().map(|l| (l.0, l.1.scoped)).collect();
    drop(d);
    // SAFETY: getpid cannot fail.
    if target == unsafe { libc::getpid() } {
        return true;
    }
    let theirs = chain_of(target);
    mine.iter()
        .enumerate()
        .all(|(i, &(id, scoped))| scoped & scope == 0 || theirs.get(i) == Some(&id))
}

/// A signal to host process `target`: `EPERM` outside a scoping layer.
pub fn may_signal(target: i32) -> Result<(), i32> {
    if !active() || within(target, SCOPE_SIGNAL) { Ok(()) } else { Err(errno::EPERM) }
}

/// A connection to an abstract socket bound by host process `owner`.
pub fn may_connect_abstract(owner: i32) -> Result<(), i32> {
    if !active() || within(owner, SCOPE_ABSTRACT_UNIX_SOCKET) { Ok(()) } else { Err(errno::EPERM) }
}

/// The host identities of what is at host path `path` and of every
/// directory above it.
fn ancestry(path: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut p = path.to_vec();
    loop {
        if let Ok(c) = std::ffi::CString::new(p.clone()) {
            // SAFETY: an all-zero `stat` is a valid out-parameter; a
            // NUL-terminated path.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 {
                out.push(identity(&st));
            }
        }
        match p.iter().rposition(|&b| b == b'/') {
            Some(0) if p.len() > 1 => p.truncate(1),
            Some(0) | None => break,
            Some(i) => p.truncate(i),
        }
    }
    out
}

/// Check access `need` to what is at host path `path` (`file`: the file
/// itself, whose own rule counts as well as its directories'; else a
/// directory, for what is made or removed in it).
pub fn check_path(path: &[u8], need: u64, file: bool) -> Result<(), i32> {
    if !active() || need == 0 {
        return Ok(());
    }
    let ids = ancestry(path);
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    for (_, layer) in d.iter() {
        let want = need & layer.fs;
        if want == 0 {
            continue;
        }
        let mut granted = 0;
        for (i, id) in ids.iter().enumerate() {
            for &(obj, access, dir) in &layer.paths {
                // A file's own rule, or a directory's for what is under it.
                if obj == *id && (dir || (i == 0 && file)) {
                    granted |= access;
                }
            }
        }
        if want & !granted != 0 {
            return Err(errno::EACCES);
        }
    }
    Ok(())
}

/// The rights a layer gives what is at host path `path`, per layer: for a
/// move between directories, which needs `REFER` in both.
pub fn check_refer(from_dir: &[u8], to_dir: &[u8]) -> Result<(), i32> {
    if !active() || from_dir == to_dir {
        return Ok(());
    }
    let (a, b) = (ancestry(from_dir), ancestry(to_dir));
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    for (_, layer) in d.iter() {
        if layer.fs == 0 {
            continue;
        }
        // A layer that does not handle REFER never lets a file change
        // directory.
        if layer.fs & REFER == 0 {
            return Err(errno::EXDEV);
        }
        let grants = |ids: &[(u64, u64)]| {
            layer.paths.iter().filter(|p| p.2 && ids.contains(&p.0)).fold(0, |g, p| g | p.1)
        };
        if grants(&a) & REFER == 0 || grants(&b) & REFER == 0 {
            return Err(errno::EXDEV);
        }
    }
    Ok(())
}

/// A TCP `bind` (`connect` false) or `connect` to `port`.
pub fn check_port(port: u16, connect: bool) -> Result<(), i32> {
    if !active() {
        return Ok(());
    }
    let need = if connect { CONNECT_TCP } else { BIND_TCP };
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    for (_, layer) in d.iter() {
        if layer.net & need == 0 {
            continue;
        }
        let granted = layer.ports.iter().any(|&(p, a)| p == u64::from(port) && a & need != 0);
        if !granted {
            return Err(errno::EACCES);
        }
    }
    Ok(())
}

/// Descriptor `fd` was opened without the right to truncate its file.
pub fn opened_without_truncate(fd: i32) {
    NO_TRUNCATE.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
}

/// `ftruncate` of `fd`: `EACCES` if it was opened without the right.
pub fn may_ftruncate(fd: i32) -> Result<(), i32> {
    if active() && NO_TRUNCATE.lock().unwrap_or_else(|e| e.into_inner()).contains(&fd) {
        Err(errno::EACCES)
    } else {
        Ok(())
    }
}

/// `fd` is closed.
pub fn closed(fd: i32) {
    if active() {
        NO_TRUNCATE.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
    }
}

/// Whether some layer handles truncation without granting it to what is
/// at host path `path`.
pub fn truncate_denied(path: &[u8]) -> bool {
    check_path(path, TRUNCATE, true).is_err()
}

/// The domain, for an exec state or fork snapshot.
pub fn save(e: &mut crate::snapshot::Enc) {
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    e.u64(d.len() as u64);
    for (id, rs) in d.iter() {
        e.u64(*id);
        e.u64(rs.fs);
        e.u64(rs.net);
        e.u64(rs.scoped);
        e.u64(rs.paths.len() as u64);
        for &((dev, ino), access, dir) in &rs.paths {
            e.u64(dev);
            e.u64(ino);
            e.u64(access);
            e.bool(dir);
        }
        e.u64(rs.ports.len() as u64);
        for &(port, access) in &rs.ports {
            e.u64(port);
            e.u64(access);
        }
    }
}

/// What [`save`] wrote, as this process's domain.
pub fn load(d: &mut crate::snapshot::Dec) {
    let n = d.count(32);
    let mut layers = Vec::with_capacity(n);
    for _ in 0..n {
        let id = d.u64();
        let mut rs = Ruleset { fs: d.u64(), net: d.u64(), scoped: d.u64(), ..Ruleset::default() };
        let np = d.count(25);
        for _ in 0..np {
            rs.paths.push(((d.u64(), d.u64()), d.u64(), d.bool()));
        }
        let nn = d.count(16);
        for _ in 0..nn {
            rs.ports.push((d.u64(), d.u64()));
        }
        layers.push((id, rs));
    }
    ACTIVE.store(!layers.is_empty(), Ordering::Relaxed);
    *DOMAIN.lock().unwrap_or_else(|e| e.into_inner()) = layers;
    publish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestry_climbs_to_the_root() {
        let ids = ancestry(b"/tmp");
        assert!(!ids.is_empty());
        assert_eq!(ancestry(b"/").len(), 1);
    }
}
