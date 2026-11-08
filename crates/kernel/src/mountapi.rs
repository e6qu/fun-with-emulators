//! The new mount API: `fsopen`, `fsconfig`, `fsmount`, `fspick`,
//! `open_tree`, `move_mount`, `mount_setattr`,
//! `statmount` and `listmount`, on the mount namespace's table
//! ([`crate::mounts`]).
//!
//! A filesystem context (`fsopen`, or `fspick` of a mounted one) is the
//! process's, kept by number against a descriptor of an anonymous file
//! ([`Mark::FsContext`]); `fsconfig` gathers its source, flags and
//! options, and checks them as Linux does, and its `CMD_CREATE` makes the
//! filesystem as `mount(2)` does ([`Kernel::new_filesystem`]). A detached
//! mount tree (`fsmount`, `open_tree` with `OPEN_TREE_CLONE`) is the
//! process's too, kept against an `O_PATH` descriptor of its root's
//! directory ([`Mark::Detached`]); `move_mount` attaches it (or moves an
//! attached mount), beneath the mount at the target with
//! `MOVE_MOUNT_BENEATH`. Reading a context's descriptor gives its error
//! messages, as Linux logs them.
//!
//! Mount ids for `statmount` and `listmount` are the unique ones
//! ([`crate::mounts::UNIQUE_ID_BASE`]); a mount the caller cannot reach
//! from its root is refused (`EPERM`) without `CAP_SYS_ADMIN`.

use crate::fdmarks::{self, Mark};
use crate::mounts::{FsType, Mount, Source, join, ms, under};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::mount_api::*;
use fwe_abi::{err, errno, fcntl};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// Where a context is in its life, as Linux tracks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Taking parameters for a new filesystem.
    Create,
    /// Made, waiting for `fsmount`.
    AwaitingMount,
    /// Taking parameters to reconfigure a mounted one (`fspick`).
    Reconf,
    /// A create failed: nothing more can be done with it.
    Failed,
}

/// A filesystem context.
#[derive(Clone, Debug)]
struct Context {
    kind: FsType,
    phase: Phase,
    source: Option<Vec<u8>>,
    /// Superblock flags (`MS_RDONLY` and the like) the parameters set and
    /// cleared.
    set: u64,
    clear: u64,
    /// The filesystem's options, as `key` or `key=value`.
    options: Vec<Vec<u8>>,
    /// The filesystem `CMD_CREATE` made: where it is, the path a mount
    /// shows, and flags it imposes.
    made: Option<(Source, Vec<u8>, u64)>,
    /// For `fspick`: the unique id of the mount it reconfigures.
    picked: Option<u64>,
    /// Messages for the context's reader.
    log: VecDeque<Vec<u8>>,
}

static CONTEXTS: Mutex<Option<HashMap<u32, Context>>> = Mutex::new(None);
/// The detached trees, root first ([`crate::mounts::Table::copy_tree`]).
static TREES: Mutex<Option<HashMap<u32, Vec<Mount>>>> = Mutex::new(None);
static NEXT: AtomicU32 = AtomicU32::new(1);

fn with<K, R>(
    m: &'static Mutex<Option<HashMap<u32, K>>>,
    f: impl FnOnce(&mut HashMap<u32, K>) -> R,
) -> R {
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// The context `fd` is a descriptor of.
fn context_key(fd: i32) -> Option<u32> {
    match fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() {
        Some(Mark::FsContext(k)) => Some(k),
        _ => None,
    }
}

/// The detached tree `fd` is a descriptor of.
fn tree_key(fd: i32) -> Option<u32> {
    match fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() {
        Some(Mark::Detached(k)) => Some(k),
        _ => None,
    }
}

/// `fd` is closed: a context or tree it was the last descriptor of goes.
pub fn closed(fd: i32) {
    if fdmarks::shared_elsewhere(fd) {
        return;
    }
    if let Some(k) = context_key(fd) {
        with(&CONTEXTS, |m| m.remove(&k));
    }
    if let Some(k) = tree_key(fd) {
        with(&TREES, |m| m.remove(&k));
    }
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// Give descriptor `fd` (a new one of fwe's making) the guest's
/// close-on-exec flag.
fn set_cloexec(fd: i32, cloexec: bool) {
    // SAFETY: plain host call on a descriptor of this call's.
    unsafe { libc::fcntl(fd, libc::F_SETFD, if cloexec { libc::FD_CLOEXEC } else { 0 }) };
}

/// A descriptor of a new anonymous file, open to read and write: what a
/// context's descriptor is on the host.
fn anon_file() -> Result<i32, i32> {
    let mut dir = crate::fs::shm::user_dir()?;
    dir.extend_from_slice(b"/fsctx-XXXXXX\0");
    // SAFETY: a NUL-terminated template in fwe's private directory; the
    // file is unlinked at once, its descriptor kept.
    unsafe {
        let fd = libc::mkstemp(dir.as_mut_ptr().cast());
        if fd < 0 {
            return Err(last());
        }
        libc::unlink(dir.as_ptr().cast());
        Ok(fd)
    }
}

/// An `O_PATH`-like descriptor of a detached tree's root: its directory,
/// or for a filesystem with nothing on the host, an empty directory of
/// fwe's (so nothing outside the guest's files is reached through it).
fn tree_fd(root: &Mount) -> Result<i32, i32> {
    let host = match &root.source {
        Source::Host(_) => root.host_path(b""),
        Source::Overlay(l) => l.upper.clone().or_else(|| l.lowers.first().cloned()),
        Source::Synthetic => None,
    };
    let path = match host {
        Some(p) => p,
        None => {
            let mut d = crate::fs::shm::user_dir()?;
            d.extend_from_slice(b"/empty-dir");
            let c = std::ffi::CString::new(d.clone()).map_err(|_| errno::EINVAL)?;
            // SAFETY: a NUL-terminated path in fwe's private directory.
            unsafe { libc::mkdir(c.as_ptr(), 0o500) };
            d
        }
    };
    let c = std::ffi::CString::new(path).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated host path; the descriptor is the caller's.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 { Err(last()) } else { Ok(fd) }
}

/// A string argument as the kernel copies one (`strndup_user`): `EFAULT`
/// for a bad pointer, `EINVAL` for one of `max` bytes or more.
fn user_string(addr: u64, max: usize) -> Result<Vec<u8>, i32> {
    match uaccess::read_cstr(addr, max - 1) {
        Err(errno::ENAMETOOLONG) => Err(errno::EINVAL),
        r => r,
    }
}

/// The superblock flags `key` sets (or with `false`, clears), as Linux's
/// `vfs_parse_sb_flag` knows them.
fn sb_flag(key: &[u8]) -> Option<(u64, bool)> {
    Some(match key {
        b"ro" => (ms::RDONLY, true),
        b"rw" => (ms::RDONLY, false),
        b"sync" => (ms::SYNCHRONOUS, true),
        b"async" => (ms::SYNCHRONOUS, false),
        b"dirsync" => (ms::DIRSYNC, true),
        b"lazytime" => (ms::LAZYTIME, true),
        b"nolazytime" => (ms::LAZYTIME, false),
        b"mand" => (ms::MANDLOCK, true),
        b"nomand" => (ms::MANDLOCK, false),
        _ => return None,
    })
}

/// Whether filesystem `kind` takes parameter `key`.
fn known_param(kind: FsType, key: &[u8]) -> bool {
    let keys: &[&[u8]] = match kind {
        FsType::Tmpfs => &[
            b"size",
            b"nr_blocks",
            b"nr_inodes",
            b"mode",
            b"uid",
            b"gid",
            b"huge",
            b"mpol",
            b"inode32",
            b"inode64",
            b"noswap",
            b"quota",
            b"usrquota",
            b"grpquota",
        ],
        FsType::Proc => &[b"hidepid", b"gid", b"subset"],
        FsType::Cgroup2 => &[
            b"nsdelegate",
            b"favordynmods",
            b"memory_localevents",
            b"memory_recursiveprot",
            b"memory_hugetlb_accounting",
            b"pids_localevents",
        ],
        FsType::Devpts => &[b"uid", b"gid", b"mode", b"ptmxmode", b"newinstance", b"max"],
        FsType::Overlay => &[
            b"lowerdir",
            b"lowerdir+",
            b"datadir+",
            b"upperdir",
            b"workdir",
            b"default_permissions",
            b"redirect_dir",
            b"index",
            b"uuid",
            b"nfs_export",
            b"xino",
            b"metacopy",
            b"volatile",
            b"userxattr",
        ],
        _ => &[],
    };
    keys.contains(&key)
}

/// A parameter's value, as `fsconfig` gives one.
enum Value {
    Flag,
    String(Vec<u8>),
    Other,
}

/// Take parameter `key` with `value` into context `c`, as Linux's
/// `vfs_parse_fs_param` does.
fn parse_param(c: &mut Context, key: &[u8], value: Value) -> Result<(), i32> {
    let name = c.kind.name();
    let mut fail = |msg: String| {
        c.log.push_back(format!("e {msg}").into_bytes());
        Err(errno::EINVAL)
    };
    if let Some((flag, on)) = sb_flag(key) {
        if on {
            c.set |= flag;
            c.clear &= !flag;
        } else {
            c.clear |= flag;
            c.set &= !flag;
        }
        return Ok(());
    }
    if known_param(c.kind, key) {
        let opt = match value {
            Value::String(v) if !v.is_empty() => [key, b"=", &v].concat(),
            _ => key.to_vec(),
        };
        let k_eq = [key, b"="].concat();
        c.options.retain(|o| o != key && !o.starts_with(&k_eq));
        c.options.push(opt);
        return Ok(());
    }
    if key == b"source" {
        let Value::String(v) = value else { return fail("Non-string source".into()) };
        if c.source.is_some() {
            return fail("Multiple sources".into());
        }
        c.source = Some(v);
        return Ok(());
    }
    fail(format!("{name}: Unknown parameter '{}'", String::from_utf8_lossy(key)))
}

/// `MOUNT_ATTR_*` as the `MS_*` flags a mount keeps.
fn attr_to_ms(attr: u64) -> u64 {
    let mut f = 0;
    for (a, m) in [
        (MOUNT_ATTR_RDONLY, ms::RDONLY),
        (MOUNT_ATTR_NOSUID, ms::NOSUID),
        (MOUNT_ATTR_NODEV, ms::NODEV),
        (MOUNT_ATTR_NOEXEC, ms::NOEXEC),
        (MOUNT_ATTR_NODIRATIME, ms::NODIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, ms::NOSYMFOLLOW),
    ] {
        if attr & a != 0 {
            f |= m;
        }
    }
    f
}

/// A mount's `MS_*` flags as `MOUNT_ATTR_*`.
fn ms_to_attr(flags: u64) -> u64 {
    let mut a = 0;
    for (m, at) in [
        (ms::RDONLY, MOUNT_ATTR_RDONLY),
        (ms::NOSUID, MOUNT_ATTR_NOSUID),
        (ms::NODEV, MOUNT_ATTR_NODEV),
        (ms::NOEXEC, MOUNT_ATTR_NOEXEC),
        (ms::NODIRATIME, MOUNT_ATTR_NODIRATIME),
        (ms::NOSYMFOLLOW, MOUNT_ATTR_NOSYMFOLLOW),
    ] {
        if flags & m != 0 {
            a |= at;
        }
    }
    a | if flags & ms::NOATIME != 0 {
        MOUNT_ATTR_NOATIME
    } else if flags & ms::STRICTATIME != 0 {
        MOUNT_ATTR_STRICTATIME
    } else {
        MOUNT_ATTR_RELATIME
    }
}

/// The access-time `MS_*` flag of `MOUNT_ATTR__ATIME` value `atime`.
fn atime_ms(atime: u64) -> u64 {
    match atime {
        MOUNT_ATTR_NOATIME => ms::NOATIME,
        MOUNT_ATTR_STRICTATIME => ms::STRICTATIME,
        _ => ms::RELATIME,
    }
}

const ATIME_MS: u64 = ms::NOATIME | ms::STRICTATIME | ms::RELATIME;

/// What a mount's propagation reports (`MS_SHARED`, `MS_SLAVE`,
/// `MS_UNBINDABLE`, or `MS_PRIVATE` for none).
fn propagation_of(m: &Mount) -> u64 {
    let p = m.propagation & (ms::SHARED | ms::SLAVE | ms::UNBINDABLE);
    if p == 0 { ms::PRIVATE } else { p }
}

/// A `struct mnt_id_req` at `req`: (`mnt_id`, `param`, `mnt_ns_id`), as
/// Linux's `copy_mnt_id_req` takes one.
fn read_id_req(req: u64) -> Result<(u64, u64, u64), i32> {
    let size: u32 = uaccess::read(req)?;
    if size as usize > 4096 {
        return Err(errno::E2BIG);
    }
    if size < MNT_ID_REQ_SIZE_VER0 {
        return Err(errno::EINVAL);
    }
    let b = uaccess::read_bytes(req, size as usize)?;
    if b.len() > MNT_ID_REQ_SIZE_VER1 as usize
        && b[MNT_ID_REQ_SIZE_VER1 as usize..].iter().any(|&x| x != 0)
    {
        return Err(errno::E2BIG);
    }
    let word =
        |at: usize| b.get(at..at + 8).map_or(0, |w| u64::from_ne_bytes(w.try_into().unwrap()));
    let spare = u32::from_ne_bytes(b[4..8].try_into().unwrap());
    if spare != 0 {
        return Err(errno::EINVAL);
    }
    let mnt_id = word(8);
    if mnt_id <= crate::mounts::UNIQUE_ID_BASE {
        return Err(errno::EINVAL);
    }
    Ok((mnt_id, word(16), word(24)))
}

impl<P: Platform> Kernel<P> {
    /// A new descriptor of context `c`, close-on-exec as asked.
    fn context_fd(&mut self, c: Context, cloexec: bool) -> i64 {
        let fd = match anon_file() {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        set_cloexec(fd, cloexec);
        let k = NEXT.fetch_add(1, Ordering::Relaxed);
        with(&CONTEXTS, |m| m.insert(k, c));
        fdmarks::mark(fd, Mark::FsContext(k));
        fd as i64
    }

    /// A new descriptor of detached `tree`, close-on-exec as asked.
    fn tree_descriptor(&mut self, tree: Vec<Mount>, cloexec: bool) -> i64 {
        let fd = match tree_fd(&tree[0]) {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        set_cloexec(fd, cloexec);
        let k = NEXT.fetch_add(1, Ordering::Relaxed);
        with(&TREES, |m| m.insert(k, tree));
        fdmarks::mark(fd, Mark::Detached(k));
        fd as i64
    }

    /// `fsopen(fs_name, flags)`.
    pub(crate) fn sys_fsopen(&mut self, name: u64, flags: u64) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if flags & !FSOPEN_CLOEXEC != 0 {
            return err(errno::EINVAL);
        }
        let name = guest!(user_string(name, 4096));
        let name: &[u8] = if name == b"cgroup" { b"cgroup2" } else { &name };
        let Some(kind) = FsType::from_name(name) else { return err(errno::ENODEV) };
        let c = Context {
            kind,
            phase: Phase::Create,
            source: None,
            set: 0,
            clear: 0,
            options: Vec::new(),
            made: None,
            picked: None,
            log: VecDeque::new(),
        };
        self.context_fd(c, flags & FSOPEN_CLOEXEC != 0)
    }

    /// `fspick(dfd, path, flags)`: a context to reconfigure the filesystem
    /// mounted at `path`.
    pub(crate) fn sys_fspick(&mut self, dfd: u64, path: u64, flags: u64) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let all =
            FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
        if flags & !all != 0 {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let ns = guest!(self.ns_path_at(
            dfd as i32,
            &path,
            flags & FSPICK_EMPTY_PATH != 0,
            flags & FSPICK_SYMLINK_NOFOLLOW == 0
        ));
        let table = self.fs().mount_ns().table();
        let (m, rest) = table.locate(&ns);
        if !rest.is_empty() {
            return err(errno::EINVAL);
        }
        let c = Context {
            kind: m.fstype,
            phase: Phase::Reconf,
            source: None,
            set: 0,
            clear: 0,
            options: Vec::new(),
            made: None,
            picked: Some(m.unique_id()),
            log: VecDeque::new(),
        };
        self.context_fd(c, flags & FSPICK_CLOEXEC != 0)
    }

    /// The namespace path `path` from `dirfd` names, or with `empty` and
    /// an empty path, the file `dirfd` is open on.
    fn ns_path_at(
        &self,
        dirfd: i32,
        path: &[u8],
        empty: bool,
        follow: bool,
    ) -> Result<Vec<u8>, i32> {
        if path.is_empty() {
            if !empty {
                return Err(errno::ENOENT);
            }
            // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a valid out-parameter.
            if dirfd < 0 || unsafe { libc::fstat(dirfd, &mut st) } != 0 {
                return Err(errno::EBADF);
            }
            return self.fs().fd_ns_path(dirfd).ok_or(errno::EINVAL);
        }
        if !path.starts_with(b"/") && dirfd != fcntl::AT_FDCWD as i32 {
            // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a valid out-parameter.
            if dirfd < 0 || unsafe { libc::fstat(dirfd, &mut st) } != 0 {
                return Err(errno::EBADF);
            }
        }
        self.mount_path_at(dirfd, path, follow).map(|(ns, _)| ns)
    }

    /// `fsconfig(fd, cmd, key, value, aux)`.
    pub(crate) fn sys_fsconfig(
        &mut self,
        fd: u64,
        cmd: u64,
        key: u64,
        value: u64,
        aux: u64,
    ) -> i64 {
        let (fd, aux) = (fd as i32, aux as i32);
        if fd < 0 {
            return err(errno::EINVAL);
        }
        let ok = match cmd {
            FSCONFIG_SET_FLAG => key != 0 && value == 0 && aux == 0,
            FSCONFIG_SET_STRING => key != 0 && value != 0 && aux == 0,
            FSCONFIG_SET_BINARY => key != 0 && value != 0 && aux > 0 && aux <= 1024 * 1024,
            FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
                key != 0 && value != 0 && (aux == fcntl::AT_FDCWD as i32 || aux >= 0)
            }
            FSCONFIG_SET_FD => key != 0 && value == 0 && aux >= 0,
            FSCONFIG_CMD_CREATE | FSCONFIG_CMD_RECONFIGURE | FSCONFIG_CMD_CREATE_EXCL => {
                key == 0 && value == 0 && aux == 0
            }
            _ => return err(errno::EOPNOTSUPP),
        };
        if !ok {
            return err(errno::EINVAL);
        }
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return err(errno::EBADF);
        }
        let Some(k) = context_key(fd) else { return err(errno::EINVAL) };
        let key = if key != 0 { guest!(user_string(key, 256)) } else { Vec::new() };
        let value = match cmd {
            FSCONFIG_SET_STRING => Value::String(guest!(user_string(value, 256))),
            FSCONFIG_SET_BINARY => {
                guest!(uaccess::read_bytes(value, aux as usize));
                Value::Other
            }
            FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
                guest!(uaccess::read_cstr(value, uaccess::PATH_MAX));
                Value::Other
            }
            FSCONFIG_SET_FD => {
                // SAFETY: a valid out-parameter.
                if unsafe { libc::fstat(aux, &mut st) } != 0 {
                    return err(errno::EBADF);
                }
                Value::Other
            }
            _ => Value::Flag,
        };
        let Some(mut c) = with(&CONTEXTS, |m| m.get(&k).cloned()) else {
            return err(errno::EINVAL);
        };
        let r = match cmd {
            FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
                if c.phase != Phase::Create {
                    Err(errno::EBUSY)
                } else if !self.creds.has_admin() {
                    Err(errno::EPERM)
                } else {
                    let data = c.options.join(&b","[..]);
                    match self.new_filesystem(c.kind, &data) {
                        Ok(made) => {
                            c.made = Some(made);
                            c.phase = Phase::AwaitingMount;
                            Ok(())
                        }
                        Err(e) => {
                            c.phase = Phase::Failed;
                            Err(e)
                        }
                    }
                }
            }
            FSCONFIG_CMD_RECONFIGURE => {
                if c.phase != Phase::Reconf {
                    Err(errno::EBUSY)
                } else if !self.creds.has_admin() {
                    Err(errno::EPERM)
                } else {
                    self.reconfigure(&c)
                }
            }
            _ if c.phase != Phase::Create && c.phase != Phase::Reconf => Err(errno::EBUSY),
            _ => parse_param(&mut c, &key, value),
        };
        with(&CONTEXTS, |m| m.insert(k, c));
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// Apply a `fspick` context's flags and options to its mount.
    fn reconfigure(&mut self, c: &Context) -> Result<(), i32> {
        let id = c.picked.ok_or(errno::EINVAL)?;
        let (set, clear) = (c.set & ms::RDONLY, c.clear & ms::RDONLY);
        let options = c.options.clone();
        self.fs().mount_ns().clone().update(|t| {
            let m = t.mounts.iter_mut().find(|m| m.unique_id() == id).ok_or(errno::ENOENT)?;
            m.flags = (m.flags | set) & !clear;
            for o in &options {
                let key = o.split(|&b| b == b'=').next().unwrap_or_default();
                let k_eq = [key, b"="].concat();
                let mut kept: Vec<Vec<u8>> = m
                    .options
                    .split(|&b| b == b',')
                    .filter(|x| !x.is_empty() && *x != key && !x.starts_with(&k_eq))
                    .map(<[u8]>::to_vec)
                    .collect();
                kept.push(o.clone());
                m.options = kept.join(&b","[..]);
            }
            Ok(())
        })
    }

    /// `fsmount(fd, flags, attr_flags)`: a detached mount of the context's
    /// new filesystem.
    pub(crate) fn sys_fsmount(&mut self, fd: u64, flags: u64, attr: u64) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if flags & !FSMOUNT_CLOEXEC != 0 {
            return err(errno::EINVAL);
        }
        let valid = MOUNT_ATTR_RDONLY
            | MOUNT_ATTR_NOSUID
            | MOUNT_ATTR_NODEV
            | MOUNT_ATTR_NOEXEC
            | MOUNT_ATTR__ATIME
            | MOUNT_ATTR_NODIRATIME
            | MOUNT_ATTR_NOSYMFOLLOW;
        if attr & !valid != 0 {
            return err(errno::EINVAL);
        }
        if !matches!(
            attr & MOUNT_ATTR__ATIME,
            MOUNT_ATTR_RELATIME | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME
        ) {
            return err(errno::EINVAL);
        }
        let fd = fd as i32;
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
            return err(errno::EBADF);
        }
        let Some(k) = context_key(fd) else { return err(errno::EINVAL) };
        let Some(c) = with(&CONTEXTS, |m| m.get(&k).cloned()) else { return err(errno::EINVAL) };
        let Some((source, root, more)) = c.made.clone() else { return err(errno::EINVAL) };
        if c.phase != Phase::AwaitingMount {
            return err(errno::EBUSY);
        }
        let flags_ms =
            attr_to_ms(attr) | atime_ms(attr & MOUNT_ATTR__ATIME) | more | (c.set & ms::RDONLY);
        let device = c.source.clone().unwrap_or_else(|| c.kind.name().as_bytes().to_vec());
        let m = Mount {
            id: 0,
            parent: 0,
            point: Vec::new(),
            fstype: c.kind,
            source,
            root,
            flags: flags_ms & ms::PER_MOUNT,
            propagation: ms::PRIVATE,
            peer: 0,
            master: 0,
            device,
            options: c.options.join(&b","[..]),
        };
        self.tree_descriptor(vec![m], flags & FSMOUNT_CLOEXEC != 0)
    }

    /// `open_tree(dfd, path, flags)`: an `O_PATH` descriptor of `path`, or
    /// with `OPEN_TREE_CLONE`, of a detached copy of the mount there (and
    /// with `AT_RECURSIVE`, of those under it).
    pub(crate) fn sys_open_tree(&mut self, dfd: u64, path: u64, flags: u64) -> i64 {
        let all = fcntl::AT_EMPTY_PATH
            | fcntl::AT_NO_AUTOMOUNT
            | AT_RECURSIVE
            | fcntl::AT_SYMLINK_NOFOLLOW
            | OPEN_TREE_CLONE
            | OPEN_TREE_CLOEXEC;
        if flags & !all != 0 || flags & (AT_RECURSIVE | OPEN_TREE_CLONE) == AT_RECURSIVE {
            return err(errno::EINVAL);
        }
        let clone = flags & OPEN_TREE_CLONE != 0;
        if clone && !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let cloexec = flags & OPEN_TREE_CLOEXEC != 0;
        let name = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let empty = flags & fcntl::AT_EMPTY_PATH != 0;
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if !clone {
            // A plain `O_PATH` descriptor.
            if name.is_empty() && empty {
                // SAFETY: plain host call; the new descriptor is the guest's.
                let r = unsafe { libc::fcntl(dfd as i32, libc::F_DUPFD, 0) };
                if r < 0 {
                    return err(errno::EBADF);
                }
                set_cloexec(r, cloexec);
                fdmarks::duplicated(dfd as i32, r);
                fdmarks::mark(r, Mark::Path);
                return r as i64;
            }
            let oflags = fcntl::O_PATH
                | if cloexec { fcntl::O_CLOEXEC } else { 0 }
                | if follow { 0 } else { fcntl::O_NOFOLLOW };
            return self.sys_openat(dfd, path, oflags, 0);
        }
        // A detached tree of one in the caller's namespace.
        if let Some(k) = tree_key(dfd as i32).filter(|_| name.is_empty() && empty) {
            let Some(tree) = with(&TREES, |m| m.get(&k).cloned()) else {
                return err(errno::EINVAL);
            };
            return self.tree_descriptor(tree, cloexec);
        }
        let ns = guest!(self.ns_path_at(dfd as i32, &name, empty, follow));
        let tree = guest!(self.fs().mount_ns().table().copy_tree(&ns, flags & AT_RECURSIVE != 0));
        self.tree_descriptor(tree, cloexec)
    }

    /// `move_mount(from_dfd, from_path, to_dfd, to_path, flags)`: attach a
    /// detached tree, or move an attached mount, to `to`.
    pub(crate) fn sys_move_mount(
        &mut self,
        from_dfd: u64,
        from_path: u64,
        to_dfd: u64,
        to_path: u64,
        flags: u64,
    ) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if flags & !MOVE_MOUNT__MASK != 0
            || flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
                == MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP
        {
            return err(errno::EINVAL);
        }
        let from = guest!(uaccess::read_cstr(from_path, uaccess::PATH_MAX));
        let to = guest!(uaccess::read_cstr(to_path, uaccess::PATH_MAX));
        let from_empty = flags & MOVE_MOUNT_F_EMPTY_PATH != 0;
        // What is moved: a detached tree, or an attached mount's root.
        let detached = tree_key(from_dfd as i32);
        let source = match detached {
            Some(k) if from.is_empty() && from_empty => Ok(k),
            Some(_) if from.is_empty() => return err(errno::ENOENT),
            Some(_) if !from.starts_with(b"/") => {
                // A path inside the detached tree: there, but not a mount's
                // root.
                let Ok(c) = std::ffi::CString::new(from.clone()) else { return err(errno::EINVAL) };
                // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: a live descriptor and NUL-terminated name.
                if unsafe { libc::fstatat(from_dfd as i32, c.as_ptr(), &mut st, 0) } != 0 {
                    return err(last());
                }
                return err(errno::EINVAL);
            }
            _ => Err(guest!(self.ns_path_at(
                from_dfd as i32,
                &from,
                from_empty,
                flags & MOVE_MOUNT_F_SYMLINKS != 0
            ))),
        };
        let to = guest!(self.ns_path_at(
            to_dfd as i32,
            &to,
            flags & MOVE_MOUNT_T_EMPTY_PATH != 0,
            flags & MOVE_MOUNT_T_SYMLINKS != 0
        ));
        let beneath = flags & MOVE_MOUNT_BENEATH != 0;
        let ns = self.fs().mount_ns().clone();
        let r = match source {
            Ok(k) => {
                let Some(tree) = with(&TREES, |m| m.get(&k).cloned()) else {
                    return err(errno::EINVAL);
                };
                let r = ns.update(|t| t.attach_tree(&tree, &to, beneath).map(|_| ()));
                if r.is_ok() {
                    // Attached: the descriptor is an `O_PATH` one of it now.
                    with(&TREES, |m| m.remove(&k));
                    fdmarks::mark(from_dfd as i32, Mark::Path);
                }
                r
            }
            Err(from) if flags & MOVE_MOUNT_SET_GROUP != 0 => ns.update(|t| {
                let (f, rest) = t.locate(&from);
                let (to_m, to_rest) = t.locate(&to);
                if !rest.is_empty() || !to_rest.is_empty() {
                    return Err(errno::EINVAL);
                }
                let (peer, master, id) = (f.peer, f.master, to_m.id);
                let m = t.mounts.iter_mut().find(|m| m.id == id).ok_or(errno::EINVAL)?;
                m.peer = peer;
                m.master = master;
                m.propagation = match (peer != 0, master != 0) {
                    (true, true) => ms::SHARED | ms::SLAVE,
                    (true, false) => ms::SHARED,
                    (false, true) => ms::SLAVE,
                    _ => ms::PRIVATE,
                };
                Ok(())
            }),
            Err(from) => ns.update(|t| {
                if beneath {
                    // Moved as a tree, beneath the target.
                    let (m, rest) = t.locate(&from);
                    if !rest.is_empty() || m.parent == m.id {
                        return Err(errno::EINVAL);
                    }
                    let tree = t.copy_tree(&from, true)?;
                    t.umount(&from)?;
                    t.attach_tree(&tree, &to, true).map(|_| ())
                } else {
                    t.move_mount(&from, &to)
                }
            }),
        };
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `mount_setattr(dfd, path, flags, attr, size)`: change the flags and
    /// propagation of the mount at `path` (and with `AT_RECURSIVE` of
    /// those under it), attached or detached.
    pub(crate) fn sys_mount_setattr(
        &mut self,
        dfd: u64,
        path: u64,
        flags: u64,
        attr: u64,
        size: u64,
    ) -> i64 {
        let all = fcntl::AT_EMPTY_PATH
            | AT_RECURSIVE
            | fcntl::AT_SYMLINK_NOFOLLOW
            | fcntl::AT_NO_AUTOMOUNT;
        if flags & !all != 0 {
            return err(errno::EINVAL);
        }
        if size > 4096 {
            return err(errno::E2BIG);
        }
        if size < MOUNT_ATTR_SIZE_VER0 {
            return err(errno::EINVAL);
        }
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let b = guest!(uaccess::read_bytes(attr, size as usize));
        if b[32..].iter().any(|&x| x != 0) {
            return err(errno::E2BIG);
        }
        let word = |at: usize| u64::from_ne_bytes(b[at..at + 8].try_into().unwrap());
        let (set, clr, propagation) = (word(0), word(8), word(16));
        if set == 0 && clr == 0 && propagation == 0 {
            return 0;
        }
        if propagation & !ms::PROPAGATION != 0 || propagation.count_ones() > 1 {
            return err(errno::EINVAL);
        }
        let valid = MOUNT_ATTR_RDONLY
            | MOUNT_ATTR_NOSUID
            | MOUNT_ATTR_NODEV
            | MOUNT_ATTR_NOEXEC
            | MOUNT_ATTR__ATIME
            | MOUNT_ATTR_IDMAP
            | MOUNT_ATTR_NOSYMFOLLOW
            | MOUNT_ATTR_NODIRATIME;
        if (set | clr) & !valid != 0 {
            return err(errno::EINVAL);
        }
        // An id-mapped mount takes a user namespace fwe cannot map files
        // through.
        if (set | clr) & MOUNT_ATTR_IDMAP != 0 {
            return err(errno::EINVAL);
        }
        // An access-time mode is set by clearing them all first.
        if set & MOUNT_ATTR__ATIME != 0 && clr & MOUNT_ATTR__ATIME != MOUNT_ATTR__ATIME {
            return err(errno::EINVAL);
        }
        let (add, remove) = {
            let mut add = attr_to_ms(set);
            let mut remove = attr_to_ms(clr);
            if clr & MOUNT_ATTR__ATIME == MOUNT_ATTR__ATIME {
                remove |= ATIME_MS;
                add |= atime_ms(set & MOUNT_ATTR__ATIME);
            }
            (add, remove)
        };
        let recursive = flags & AT_RECURSIVE != 0;
        let apply = |m: &mut Mount| m.flags = (m.flags & !remove) | add;
        let name = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let empty = flags & fcntl::AT_EMPTY_PATH != 0;
        if let Some(k) = tree_key(dfd as i32).filter(|_| name.is_empty() && empty) {
            return with(&TREES, |m| match m.get_mut(&k) {
                Some(tree) => {
                    let n = if recursive { tree.len() } else { 1 };
                    for m in &mut tree[..n] {
                        apply(m);
                    }
                    0
                }
                None => err(errno::EINVAL),
            });
        }
        let ns_path = guest!(self.ns_path_at(
            dfd as i32,
            &name,
            empty,
            flags & fcntl::AT_SYMLINK_NOFOLLOW == 0
        ));
        let r = self.fs().mount_ns().clone().update(|t| {
            let (m, rest) = t.locate(&ns_path);
            if !rest.is_empty() {
                return Err(errno::EINVAL);
            }
            let id = m.id;
            let mut ids = vec![id];
            if recursive {
                ids.extend(t.mounts.iter().filter(|o| t.is_below(o.id, id)).map(|o| o.id));
            }
            for m in t.mounts.iter_mut().filter(|m| ids.contains(&m.id)) {
                apply(m);
            }
            if propagation != 0 {
                t.set_propagation(&ns_path, propagation, recursive)?;
            }
            Ok(())
        });
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// Whether mount `m` is where the caller can reach from its root.
    fn reachable(&self, m: &Mount) -> bool {
        under(&m.point, self.fs().proc_root()).is_some()
    }

    /// `statmount(req, buf, bufsize, flags)`.
    pub(crate) fn sys_statmount(&mut self, req: u64, buf: u64, size: u64, flags: u64) -> i64 {
        if flags != 0 {
            return err(errno::EINVAL);
        }
        let (id, mask, ns_id) = guest!(read_id_req(req));
        let ns = self.fs().mount_ns().clone();
        if ns_id != 0 && ns_id != ns.id() {
            return err(errno::ENOENT);
        }
        let strings =
            STATMOUNT_FS_TYPE | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT | STATMOUNT_MNT_OPTS;
        if mask & strings != 0 && size == STATMOUNT_SIZE as u64 {
            return err(errno::EOVERFLOW);
        }
        let table = ns.table();
        let Some(m) = table.by_unique(id).cloned() else { return err(errno::ENOENT) };
        if !self.reachable(&m) && !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let mut sm = vec![0u8; STATMOUNT_SIZE];
        let mut str_area: Vec<u8> = Vec::new();
        let put32 =
            |sm: &mut Vec<u8>, at: usize, v: u32| sm[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        let put64 =
            |sm: &mut Vec<u8>, at: usize, v: u64| sm[at..at + 8].copy_from_slice(&v.to_ne_bytes());
        let mut done = 0u64;
        if mask & STATMOUNT_SB_BASIC != 0 {
            let (major, minor) = self.mount_device(&m);
            put32(&mut sm, 16, major);
            put32(&mut sm, 20, minor);
            put64(&mut sm, 24, m.fstype.magic() as u64);
            put32(&mut sm, 32, (m.flags & ms::RDONLY) as u32);
            done |= STATMOUNT_SB_BASIC;
        }
        if mask & STATMOUNT_MNT_BASIC != 0 {
            let parent = table.get(m.parent).cloned().unwrap_or_else(|| m.clone());
            put64(&mut sm, 40, m.unique_id());
            put64(&mut sm, 48, parent.unique_id());
            put32(&mut sm, 56, m.id);
            put32(&mut sm, 60, parent.id);
            put64(&mut sm, 64, ms_to_attr(m.flags));
            put64(&mut sm, 72, propagation_of(&m));
            put64(&mut sm, 80, u64::from(m.peer));
            put64(&mut sm, 88, u64::from(m.master));
            done |= STATMOUNT_MNT_BASIC;
        }
        if mask & STATMOUNT_PROPAGATE_FROM != 0 {
            put64(&mut sm, 96, u64::from(m.master));
            done |= STATMOUNT_PROPAGATE_FROM;
        }
        let point = under(&m.point, self.fs().proc_root()).map(|r| join(b"/", r));
        let opts: Vec<u8> = m
            .options
            .split(|&b| b == b',')
            .filter(|o| !o.is_empty() && *o != b"rw" && *o != b"ro")
            .collect::<Vec<_>>()
            .join(&b","[..]);
        for (bit, at, text) in [
            (STATMOUNT_FS_TYPE, 36, Some(m.fstype.name().as_bytes().to_vec())),
            (STATMOUNT_MNT_ROOT, 104, Some(m.root.clone())),
            (STATMOUNT_MNT_POINT, 108, point),
            (STATMOUNT_MNT_OPTS, 4, Some(opts)),
        ] {
            if mask & bit == 0 {
                continue;
            }
            put32(&mut sm, at, str_area.len() as u32);
            str_area.extend_from_slice(&text.unwrap_or_default());
            if STATMOUNT_SIZE + str_area.len() >= size as usize {
                return err(errno::EOVERFLOW);
            }
            str_area.push(0);
            done |= bit;
        }
        if mask & STATMOUNT_MNT_NS_ID != 0 {
            put64(&mut sm, 112, ns.id());
            done |= STATMOUNT_MNT_NS_ID;
        }
        put64(&mut sm, 8, done);
        let head = (size as usize).min(STATMOUNT_SIZE);
        put32(&mut sm, 0, (head + str_area.len()) as u32);
        if !str_area.is_empty() {
            guest!(uaccess::write_from(buf + STATMOUNT_SIZE as u64, &str_area));
        }
        guest!(uaccess::write_from(buf, &sm[..head]));
        0
    }

    /// The device numbers of mount `m`'s filesystem, as `stat` of its root
    /// reports them.
    #[allow(clippy::unnecessary_cast)] // `dev_t` differs by host
    fn mount_device(&self, m: &Mount) -> (u32, u32) {
        let st = m.host_path(b"").and_then(|p| std::ffi::CString::new(p).ok()).and_then(|c| {
            // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a NUL-terminated path and a valid out-parameter.
            (unsafe { libc::stat(c.as_ptr(), &mut st) } == 0).then_some(st)
        });
        match st {
            Some(st) => {
                let dev = st.st_dev as u64;
                (crate::fsops::major(dev), crate::fsops::minor(dev))
            }
            None => (0, 20 + m.id),
        }
    }

    /// `listmount(req, mnt_ids, nr_mnt_ids, flags)`: the unique ids of the
    /// mounts under the one asked (`LSMT_ROOT`: the caller's root), in
    /// order, after `param`'s.
    pub(crate) fn sys_listmount(&mut self, req: u64, ids: u64, nr: u64, flags: u64) -> i64 {
        const LISTMOUNT_REVERSE: u64 = 1;
        if flags & !LISTMOUNT_REVERSE != 0 {
            return err(errno::EINVAL);
        }
        if nr > 1_000_000 {
            return err(errno::EOVERFLOW);
        }
        let (id, last, ns_id) = guest!(read_id_req(req));
        if last != 0 && last <= crate::mounts::UNIQUE_ID_BASE {
            return err(errno::EINVAL);
        }
        let ns = self.fs().mount_ns().clone();
        if ns_id != 0 && ns_id != ns.id() {
            return err(errno::ENOENT);
        }
        let table = ns.table();
        let parent = if id == LSMT_ROOT {
            table.mounts.iter().find(|m| m.parent == m.id).cloned()
        } else {
            table.by_unique(id).cloned()
        };
        let Some(parent) = parent else { return err(errno::ENOENT) };
        let from_root = id == LSMT_ROOT;
        if !from_root && !self.reachable(&parent) && !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let mut found: Vec<u64> = table
            .mounts
            .iter()
            .filter(|m| m.id != parent.id && self.reachable(m))
            .filter(|m| from_root || table.is_below(m.id, parent.id))
            .map(Mount::unique_id)
            .collect();
        found.sort_unstable();
        let reverse = flags & LISTMOUNT_REVERSE != 0;
        if reverse {
            found.reverse();
        }
        let out: Vec<u64> = found
            .into_iter()
            .filter(|&u| last == 0 || if reverse { u < last } else { u > last })
            .take(nr as usize)
            .collect();
        if out.is_empty() {
            return 0;
        }
        let bytes: Vec<u8> = out.iter().flat_map(|u| u.to_ne_bytes()).collect();
        guest!(uaccess::write_from(ids, &bytes));
        out.len() as i64
    }
}

/// A read of a context's descriptor: its next message, as Linux gives
/// them (`ENODATA` for none, `EMSGSIZE` for a buffer too small). `None`
/// for another descriptor.
pub fn read(fd: i32, buf: u64, len: u64) -> Option<i64> {
    let k = context_key(fd)?;
    let msg = with(&CONTEXTS, |m| m.get(&k).and_then(|c| c.log.front().cloned()));
    let Some(msg) = msg else { return Some(err(errno::ENODATA)) };
    if (msg.len() as u64) > len {
        return Some(err(errno::EMSGSIZE));
    }
    if let Err(e) = uaccess::write_from(buf, &msg) {
        return Some(err(e));
    }
    with(&CONTEXTS, |m| m.get_mut(&k).map(|c| c.log.pop_front()));
    Some(msg.len() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(kind: FsType) -> Context {
        Context {
            kind,
            phase: Phase::Create,
            source: None,
            set: 0,
            clear: 0,
            options: Vec::new(),
            made: None,
            picked: None,
            log: VecDeque::new(),
        }
    }

    #[test]
    fn parameters_are_taken_as_linux_parses_them() {
        let mut c = context(FsType::Tmpfs);
        assert_eq!(parse_param(&mut c, b"ro", Value::Flag), Ok(()));
        assert_eq!(parse_param(&mut c, b"sync", Value::Other), Ok(()));
        assert_eq!(parse_param(&mut c, b"size", Value::String(b"1M".to_vec())), Ok(()));
        assert_eq!(parse_param(&mut c, b"size", Value::String(b"2M".to_vec())), Ok(()));
        assert_eq!(c.options, [b"size=2M".to_vec()]);
        assert_eq!(c.set, ms::RDONLY | ms::SYNCHRONOUS);
        assert_eq!(parse_param(&mut c, b"source", Value::Flag), Err(errno::EINVAL));
        assert_eq!(parse_param(&mut c, b"source", Value::String(b"x".to_vec())), Ok(()));
        assert_eq!(
            parse_param(&mut c, b"source", Value::String(b"y".to_vec())),
            Err(errno::EINVAL)
        );
        assert_eq!(parse_param(&mut c, b"bogus", Value::Flag), Err(errno::EINVAL));
        assert_eq!(c.log.back().unwrap(), b"e tmpfs: Unknown parameter 'bogus'");
    }

    #[test]
    fn attributes_map_to_mount_flags_and_back() {
        let a = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSYMFOLLOW;
        let f = attr_to_ms(a) | atime_ms(MOUNT_ATTR_NOATIME);
        assert_eq!(f, ms::RDONLY | ms::NOEXEC | ms::NOSYMFOLLOW | ms::NOATIME);
        assert_eq!(ms_to_attr(f), a | MOUNT_ATTR_NOATIME);
        assert_eq!(ms_to_attr(ms::RELATIME), MOUNT_ATTR_RELATIME);
    }
}
