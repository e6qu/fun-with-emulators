//! Landlock: a process restricting itself (`landlock_create_ruleset`,
//! `landlock_add_rule`, `landlock_restrict_self`).
//!
//! A ruleset is the process's, kept against its descriptor (one standing
//! for it, [`crate::anonfd`], marked with its number). `landlock_restrict_self` adds it to the
//! process's domain as a layer; the domain goes with the process across
//! `fork` and `execve` and can only grow. Every layer is checked:
//!
//! - **Files:** an access a layer handles is allowed if a rule of the
//!   layer grants it on the file or on a directory above it, by host
//!   identity (device and inode) up the file's host path: opening to read
//!   or write a file or read a directory, executing, making and removing
//!   each kind of file in a directory, truncating and a device's `ioctl`
//!   (decided as a file is opened, and marked on its open file
//!   description, [`opened`]), and moving a file between directories
//!   (`REFER` in both, or `EXDEV`). A denied access is `EACCES`. A domain
//!   that restricts files may not mount (`EPERM`).
//! - **TCP ports:** `bind` and `connect` to a port a rule names.
//! - **Scopes:** a signal, or a connection or datagram to an abstract
//!   socket, to a process outside a scoping layer's domain is `EPERM`, and
//!   so is tracing one ([`may_trace`]). Each layer has an id, and a
//!   process restricted publishes its chain of ids (in its entry in the
//!   process store, [`crate::procstore::Kind::Landlock`]) for others to
//!   compare with theirs.
//!
//! Nothing is looked at while the process has no domain: one flag.

use fwe_abi::errno;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

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
pub(crate) static RULESETS: Mutex<Vec<(u32, Ruleset)>> = Mutex::new(Vec::new());

/// The number the next ruleset takes ([`crate::fdmarks::Mark::Landlock`]).
static NEXT_RULESET: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// The number of the ruleset `fd` is a descriptor of, if it is one.
fn ruleset_key(fd: i32) -> Option<u32> {
    match crate::fdmarks::any_marks().then(|| crate::fdmarks::marked(fd)).flatten() {
        Some(crate::fdmarks::Mark::Landlock(k)) => Some(k),
        _ => None,
    }
}

/// Whether `fd` is a ruleset's descriptor.
pub fn is_ruleset(fd: i32) -> bool {
    ruleset_key(fd).is_some()
}

/// A read, write or copy of a ruleset's descriptor: refused (`EINVAL`),
/// as Linux's ruleset has neither. `None` for another descriptor.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    crate::anonfd::refuse_io(nr, a, is_ruleset)
}

/// The process's domain: each layer's id and ruleset.
pub(crate) static DOMAIN: Mutex<Vec<(u64, Ruleset)>> = Mutex::new(Vec::new());
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the process is restricted at all.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Whether a layer of the domain restricts file-system access.
pub fn handles_fs() -> bool {
    active() && DOMAIN.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|l| l.1.fs != 0)
}

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(st: &libc::stat) -> (u64, u64) {
    (crate::host::dev_of(st), st.st_ino as u64)
}

fn fd_identity(fd: i32) -> Option<(libc::stat, (u64, u64))> {
    // A file of fwe's store: its own device and inode.
    if let Some(st) = crate::filestore::io::stat(fd) {
        let st = st.ok()?;
        return Some((st, identity(&st)));
    }
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then(|| (st, identity(&st)))
}

fn ruleset_of(fd: i32) -> Result<Ruleset, i32> {
    // SAFETY: F_GETFD only queries the descriptor.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(errno::EBADF);
    }
    let k = ruleset_key(fd).ok_or(errno::EBADFD)?;
    let r = RULESETS.lock().unwrap_or_else(|e| e.into_inner());
    r.iter().find(|(i, _)| *i == k).map(|(_, rs)| rs.clone()).ok_or(errno::EBADFD)
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
    // (Linux makes a ruleset's descriptor close-on-exec.)
    let fd = crate::anonfd::new(true)?;
    let k = NEXT_RULESET.fetch_add(1, Ordering::Relaxed);
    RULESETS.lock().unwrap_or_else(|e| e.into_inner()).push((k, rs));
    crate::fdmarks::mark(fd, crate::fdmarks::Mark::Landlock(k));
    Ok(i64::from(fd))
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
    let k = ruleset_key(fd).ok_or(errno::EBADFD)?;
    let mut r = RULESETS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, rs)) = r.iter_mut().find(|(i, _)| *i == k) {
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

/// Publish this process's chain for others ([`within`]); called as it is
/// restricted and as a restricted process starts (a fork child, a program
/// run).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn publish() {
    if !active() {
        return;
    }
    let me = crate::host::pid();
    // After when the process started: a reader tells its chain from an
    // earlier process's of the same pid.
    let mut b = Vec::new();
    b.extend_from_slice(&crate::procreg::start_time(me).unwrap_or(0).to_ne_bytes());
    for id in chain() {
        b.extend_from_slice(&id.to_ne_bytes());
    }
    crate::procstore::put_own(crate::procstore::Kind::Landlock, Some(&b));
}

/// Host process `pid`'s chain (none if it is not restricted, or the one
/// kept is a former process's).
fn chain_of(pid: crate::ids::HostPid) -> Vec<u64> {
    let Some(b) = crate::procstore::get_of(crate::procstore::Kind::Landlock, pid) else {
        return Vec::new();
    };
    let words: Vec<u64> = b.as_chunks::<8>().0.iter().map(|c| u64::from_ne_bytes(*c)).collect();
    match (words.split_first(), crate::procreg::start_time(pid)) {
        (Some((&start, rest)), Some(now)) if start == now => rest.to_vec(),
        _ => Vec::new(),
    }
}

/// Whether host process `target` is inside every layer of this process's
/// domain that scopes `scope` (it is the same domain or one nested in it).
fn within(target: crate::ids::HostPid, scope: u64) -> bool {
    let d = DOMAIN.lock().unwrap_or_else(|e| e.into_inner());
    if !d.iter().any(|l| l.1.scoped & scope != 0) {
        return true;
    }
    let mine: Vec<(u64, u64)> = d.iter().map(|l| (l.0, l.1.scoped)).collect();
    drop(d);
    if target == crate::host::pid() {
        return true;
    }
    let theirs = chain_of(target);
    mine.iter()
        .enumerate()
        .all(|(i, &(id, scoped))| scoped & scope == 0 || theirs.get(i) == Some(&id))
}

/// A signal to host process `target`: `EPERM` outside a scoping layer.
pub fn may_signal(target: crate::ids::HostPid) -> Result<(), i32> {
    if !active() || within(target, SCOPE_SIGNAL) { Ok(()) } else { Err(errno::EPERM) }
}

/// Tracing (or reading as a tracer does) host process `target`: only one
/// in this process's domain or one nested in it (`EPERM` for a process
/// less restricted, as Linux's Landlock has it for every layer).
pub fn may_trace(target: crate::ids::HostPid) -> Result<(), i32> {
    if !active() {
        return Ok(());
    }
    if target == crate::host::pid() {
        return Ok(());
    }
    let theirs = chain_of(target);
    if chain().iter().enumerate().all(|(i, id)| theirs.get(i) == Some(id)) {
        Ok(())
    } else {
        Err(errno::EPERM)
    }
}

/// `PTRACE_TRACEME` with host process `parent` as tracer: the parent's
/// domain must be this process's or one this one's is nested in.
pub fn may_be_traced_by(parent: crate::ids::HostPid) -> Result<(), i32> {
    let theirs = chain_of(parent);
    if theirs.is_empty() {
        return Ok(());
    }
    let mine = chain();
    if theirs.iter().enumerate().all(|(i, id)| mine.get(i) == Some(id)) {
        Ok(())
    } else {
        Err(errno::EPERM)
    }
}

/// A connection to an abstract socket bound by host process `owner`.
pub fn may_connect_abstract(owner: i32) -> Result<(), i32> {
    if !active()
        || crate::ids::HostPid::new(owner).is_some_and(|o| within(o, SCOPE_ABSTRACT_UNIX_SOCKET))
    {
        Ok(())
    } else {
        Err(errno::EPERM)
    }
}

/// The identities (device, inode) of a file and of every directory above
/// it, nearest first, as a rule names them ([`check`]).
pub type Ids = Vec<(u64, u64)>;

/// The host identities of what is at host path `path` and of every
/// directory above it.
pub fn ancestry(path: &[u8]) -> Ids {
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

/// Check access `need` to what `ids` are of ([`Ids`]; `file`: the file
/// itself, whose own rule counts as well as its directories'; else a
/// directory, for what is made or removed in it).
pub fn check(ids: &[(u64, u64)], need: u64, file: bool) -> Result<(), i32> {
    if !active() || need == 0 {
        return Ok(());
    }
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

/// The rights a layer gives the directories `a` and `b` are of ([`Ids`]),
/// per layer: for a move between directories, which needs `REFER` in both.
pub fn check_refer(a: &[(u64, u64)], b: &[(u64, u64)]) -> Result<(), i32> {
    if !active() || a.first() == b.first() {
        return Ok(());
    }
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
        if grants(a) & REFER == 0 || grants(b) & REFER == 0 {
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

/// What the domain withholds from a file as it is opened: truncating it
/// (`TRUNCATE`), and for a device `ioctl` (`IOCTL_DEV`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Withheld {
    pub truncate: bool,
    pub ioctl: bool,
}

/// Descriptor `fd` was opened with `w` withheld: for a regular file the
/// right to truncate it, for a device `ioctl`. The mark goes on its open
/// file description (as Linux keeps it with the open file), so every
/// descriptor of it, `dup`'d, inherited, passed over a socket or kept
/// across `execve`, carries it ([`crate::host::mark_landlock_denied`]).
pub fn opened(fd: i32, w: Withheld) {
    let Ok(st) = crate::fsops::linux_fstat(fd) else { return };
    let denied = match st.st_mode & fwe_abi::stat::S_IFMT {
        fwe_abi::stat::S_IFREG => w.truncate,
        fwe_abi::stat::S_IFCHR | fwe_abi::stat::S_IFBLK => w.ioctl,
        _ => false,
    };
    if denied {
        crate::host::mark_landlock_denied(fd);
    }
}

/// The guest's kind of file `fd` is (`S_IFMT` bits), if it is marked
/// ([`opened`]).
fn denied_kind(fd: i32) -> Option<u32> {
    if !crate::host::landlock_denied(fd) {
        return None;
    }
    crate::fsops::linux_fstat(fd).ok().map(|st| st.st_mode & fwe_abi::stat::S_IFMT)
}

/// `ftruncate` of `fd`: `EACCES` if its file was opened without the right,
/// whichever process holds it now.
pub fn may_ftruncate(fd: i32) -> Result<(), i32> {
    match denied_kind(fd) {
        Some(fwe_abi::stat::S_IFREG) => Err(errno::EACCES),
        _ => Ok(()),
    }
}

/// `ioctl(fd, req)`: `EACCES` for a device opened without `IOCTL_DEV`,
/// but for the requests any holder may make (the descriptor's flags, the
/// file system's), as Linux's `is_masked_device_ioctl` lists them.
pub fn may_ioctl(fd: i32, req: u64) -> Result<(), i32> {
    use fwe_abi::ioctl::*;
    if matches!(
        req,
        FIOCLEX
            | FIONCLEX
            | FIONBIO
            | FIOASYNC
            | FIOQSIZE
            | FIFREEZE
            | FITHAW
            | FS_IOC_FIEMAP
            | FIGETBSZ
            | FICLONE
            | FICLONERANGE
            | FIDEDUPERANGE
            | FS_IOC_GETFSUUID
            | FS_IOC_GETFSSYSFSPATH
    ) {
        return Ok(());
    }
    match denied_kind(fd) {
        Some(fwe_abi::stat::S_IFCHR | fwe_abi::stat::S_IFBLK) => Err(errno::EACCES),
        _ => Ok(()),
    }
}

/// What some layer handles without granting it to the file at host path
/// `path`, opened for writing if `write` (truncation is a writer's).
pub fn withheld(ids: &[(u64, u64)], write: bool) -> Withheld {
    Withheld {
        truncate: write && check(ids, TRUNCATE, true).is_err(),
        ioctl: check(ids, IOCTL_DEV, true).is_err(),
    }
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

    /// A file opened without the right to truncate it keeps that on its
    /// open file description: every descriptor of it is refused, another
    /// open of the file is not, and `ioctl` is a device's to refuse.
    #[cfg(target_os = "macos")]
    #[test]
    fn withheld_rights_follow_the_open_file() {
        let path = std::env::temp_dir().join(format!("fwe-ll-trunc-{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let open = || std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let (a, b) = (open(), open());
        use std::os::fd::AsRawFd;
        opened(a.as_raw_fd(), Withheld { truncate: true, ioctl: true });
        // SAFETY: duplicating a descriptor of this test's.
        let dup = unsafe { libc::dup(a.as_raw_fd()) };
        assert_eq!(may_ftruncate(a.as_raw_fd()), Err(errno::EACCES));
        assert_eq!(may_ftruncate(dup), Err(errno::EACCES));
        assert_eq!(may_ftruncate(b.as_raw_fd()), Ok(()));
        // A regular file's mark is not a device's.
        assert_eq!(may_ioctl(a.as_raw_fd(), 0x541b), Ok(()));
        // SAFETY: closing the duplicate.
        unsafe { libc::close(dup) };
        let _ = std::fs::remove_file(&path);
    }
}
