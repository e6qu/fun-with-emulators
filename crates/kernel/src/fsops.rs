//! File and directory system calls, built on the [`crate::fs`] resolver.

use crate::fs::{Change, Fs, Resolved};
use crate::host::{self, last_error, ret};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{Stat, Statx, err, errno, fcntl, statx_mask};
use std::ffi::CString;
use std::os::fd::AsRawFd;

/// A host mode as Linux reports it: a symbolic link's permissions are
/// always 0777 (the host's follow the umask it was made under).
fn linux_mode(mode: u32) -> u32 {
    // The file-type bits are the same on both.
    use fwe_abi::stat::{S_IFLNK, S_IFMT};
    if mode & S_IFMT == S_IFLNK { S_IFLNK | 0o777 } else { mode }
}

/// The link count of the file of host status `s`: an `O_TMPFILE` file's
/// hidden name is no link of Linux's ([`crate::tmpfile`]).
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn nlink(s: &libc::stat) -> u32 {
    let n = s.st_nlink as u32;
    if crate::tmpfile::hidden((s.st_dev as u64, s.st_ino as u64)) { n.saturating_sub(1) } else { n }
}

#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn stat_to_linux(s: &libc::stat) -> Stat {
    // A host device has the numbers Linux gives it.
    let rdev = crate::devnodes::linux_numbers_of_host(s)
        .map_or(s.st_rdev as u64, |n| crate::devnodes::makedev(n.major, n.minor));
    Stat {
        st_dev: s.st_dev as u64,
        st_ino: s.st_ino as u64,
        st_mode: linux_mode(s.st_mode as u32),
        st_nlink: nlink(s),
        st_uid: crate::userns::to_ns(s.st_uid, false),
        st_gid: crate::userns::to_ns(s.st_gid, true),
        st_rdev: rdev,
        __pad1: 0,
        st_size: s.st_size as i64,
        st_blksize: s.st_blksize as i32,
        __pad2: 0,
        st_blocks: s.st_blocks as i64,
        st_atime: s.st_atime as i64,
        st_atime_nsec: s.st_atime_nsec as u64,
        st_mtime: s.st_mtime as i64,
        st_mtime_nsec: s.st_mtime_nsec as u64,
        st_ctime: s.st_ctime as i64,
        st_ctime_nsec: s.st_ctime_nsec as u64,
        __unused4: 0,
        __unused5: 0,
    }
}

/// Linux's `STATX_ATTR_IMMUTABLE`, `APPEND` and `NODUMP`: the attributes
/// a file's `statx` reports, from its host flags, which a file's owner can
/// set (`FS_IOC_SETFLAGS`), as on Linux's tmpfs.
const STATX_ATTR_IMMUTABLE: u64 = 0x10;
const STATX_ATTR_APPEND: u64 = 0x20;
const STATX_ATTR_NODUMP: u64 = 0x40;
/// `STATX_ATTR_MOUNT_ROOT`: the root of a mount.
const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
const STATX_ATTRS_KNOWN: u64 =
    STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND | STATX_ATTR_NODUMP | STATX_ATTR_MOUNT_ROOT;

/// The `statx` attributes of a file with host status `s`, no-dump if
/// `nodump` (the host's flag is also the mark of a kept mode, see
/// [`crate::modes::nodump_fd`]).
#[cfg(target_os = "macos")]
fn statx_attributes(s: &libc::stat, nodump: bool) -> u64 {
    let f = s.st_flags;
    let mut a = if nodump { STATX_ATTR_NODUMP } else { 0 };
    for (host, linux) in [
        (libc::UF_IMMUTABLE | libc::SF_IMMUTABLE, STATX_ATTR_IMMUTABLE),
        (libc::UF_APPEND | libc::SF_APPEND, STATX_ATTR_APPEND),
    ] {
        if f & host != 0 {
            a |= linux;
        }
    }
    a
}

#[cfg(not(target_os = "macos"))]
fn statx_attributes(_: &libc::stat, nodump: bool) -> u64 {
    if nodump { STATX_ATTR_NODUMP } else { 0 }
}

#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn statx_from(s: &libc::stat) -> Statx {
    let rdev = crate::devnodes::linux_numbers_of_host(s)
        .map_or(s.st_rdev as u64, |n| crate::devnodes::makedev(n.major, n.minor));
    let ts = |sec: i64, nsec: i64| fwe_abi::StatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    };
    let btime = birth_time(s);
    Statx {
        stx_mask: statx_mask::STATX_BASIC_STATS
            | if btime.is_some() { statx_mask::STATX_BTIME } else { 0 },
        stx_blksize: s.st_blksize as u32,
        stx_attributes: statx_attributes(s, false),
        stx_nlink: nlink(s),
        stx_uid: crate::userns::to_ns(s.st_uid, false),
        stx_gid: crate::userns::to_ns(s.st_gid, true),
        stx_mode: linux_mode(s.st_mode as u32) as u16,
        __spare0: 0,
        stx_ino: s.st_ino as u64,
        stx_size: s.st_size as u64,
        stx_blocks: s.st_blocks as u64,
        stx_attributes_mask: STATX_ATTRS_KNOWN,
        stx_atime: ts(s.st_atime as i64, s.st_atime_nsec as i64),
        stx_btime: btime.unwrap_or_default(),
        stx_ctime: ts(s.st_ctime as i64, s.st_ctime_nsec as i64),
        stx_mtime: ts(s.st_mtime as i64, s.st_mtime_nsec as i64),
        stx_rdev_major: crate::devnodes::major(rdev),
        stx_rdev_minor: crate::devnodes::minor(rdev),
        stx_dev_major: major(s.st_dev as u64),
        stx_dev_minor: minor(s.st_dev as u64),
        stx_mnt_id: 0,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        __spare3: [0; 12],
    }
}

/// What `statx` reports of a file beyond `stat`'s: its attributes and,
/// where the host keeps one, its birth time.
#[derive(Default)]
pub(crate) struct Extra {
    attrs: u64,
    btime: Option<fwe_abi::StatxTimestamp>,
}

impl Extra {
    /// Those of the file of host status `s`, no-dump if `nodump`.
    fn of(s: &libc::stat, nodump: bool) -> Extra {
        Extra { attrs: statx_attributes(s, nodump), btime: birth_time(s) }
    }
}

/// The birth time of the file of host status `s` (APFS keeps one).
#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn birth_time(s: &libc::stat) -> Option<fwe_abi::StatxTimestamp> {
    Some(fwe_abi::StatxTimestamp {
        tv_sec: s.st_birthtime as i64,
        tv_nsec: s.st_birthtime_nsec as u32,
        __reserved: 0,
    })
}

#[cfg(not(target_os = "macos"))]
fn birth_time(_: &libc::stat) -> Option<fwe_abi::StatxTimestamp> {
    None
}

/// `statx` of what Linux's `stat` reports as `s`.
fn statx_of(s: &Stat) -> Statx {
    let ts = |sec: i64, nsec: u64| fwe_abi::StatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    };
    Statx {
        stx_mask: statx_mask::STATX_BASIC_STATS,
        stx_blksize: s.st_blksize as u32,
        stx_nlink: s.st_nlink,
        stx_uid: s.st_uid,
        stx_gid: s.st_gid,
        stx_mode: s.st_mode as u16,
        stx_ino: s.st_ino,
        stx_size: s.st_size as u64,
        stx_blocks: s.st_blocks as u64,
        stx_atime: ts(s.st_atime, s.st_atime_nsec),
        stx_ctime: ts(s.st_ctime, s.st_ctime_nsec),
        stx_mtime: ts(s.st_mtime, s.st_mtime_nsec),
        stx_rdev_major: crate::devnodes::major(s.st_rdev),
        stx_rdev_minor: crate::devnodes::minor(s.st_rdev),
        stx_dev_major: crate::devnodes::major(s.st_dev),
        stx_dev_minor: crate::devnodes::minor(s.st_dev),
        ..Statx::default()
    }
}

/// A namespace, as nsfs shows one: its number is the inode, on nsfs's
/// device.
fn ns_stat(ino: u64) -> Stat {
    let mut s = synth_stat(fwe_abi::stat::S_IFREG | 0o444, 0);
    s.st_ino = ino;
    let (major, minor) = crate::nsfd::NSFS_DEV;
    s.st_dev = crate::devnodes::makedev(major, minor);
    s
}

/// A process descriptor of host process `host`, as pidfs shows one: a
/// file only its owner may use, its inode the process's.
fn pidfd_stat(host: i32) -> Stat {
    let mut s = synth_stat(fwe_abi::stat::S_IFREG | 0o700, 0);
    s.st_ino = host as u64;
    let (major, minor) = crate::nsfd::NSFS_DEV;
    s.st_dev = crate::devnodes::makedev(major, minor + 1);
    s
}

/// The number of the namespace a `/proc/<pid>/ns` link's target names
/// (`pid:[4026531836]`), if it is one.
fn namespace_inode(target: &[u8]) -> Option<u64> {
    let open = target.iter().position(|&b| b == b'[')?;
    let digits = target[open + 1..].strip_suffix(b"]")?;
    if open == 0 || target[open - 1] != b':' {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// If `path` is `/dev/pts/<n>` with a decimal `<n>`, return `n`.
fn pts_number(path: &[u8]) -> Option<u32> {
    let rest = path.strip_prefix(b"/dev/pts/")?;
    if rest.is_empty() || !rest.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(rest).ok()?.parse().ok()
}

pub(crate) fn major(dev: u64) -> u32 {
    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff)) as u32
}

pub(crate) fn minor(dev: u64) -> u32 {
    (((dev >> 12) & 0xffff_ff00) | (dev & 0xff)) as u32
}

/// Fetch host metadata for the resolved path (symlink already resolved),
/// with the guest's permission bits ([`crate::modes`]) and owner, in the
/// initial user namespace's ids ([`crate::owners`]).
fn stat_at(dir: i32, name: &CString) -> Result<libc::stat, i32> {
    stat_at_with(dir, name, libc::AT_SYMLINK_NOFOLLOW)
}

/// [`stat_at`] of what `r` resolved to, the host's view taken from the
/// lookup where it looked.
fn resolved_stat(r: &crate::fs::Resolved) -> Option<libc::stat> {
    // A file of fwe's store keeps the guest's mode and owner.
    if r.store.is_some() {
        return r.lstat();
    }
    let mut out = r.lstat()?;
    let name = r.name_c().ok()?;
    let dir = r.dir.as_raw_fd();
    let perm = crate::modes::guest_perm_at(dir, &name, &out);
    let owner = crate::owners::of_at(dir, &name, &out);
    crate::modes::apply(&mut out, perm);
    crate::owners::apply(&mut out, owner);
    Some(out)
}

/// The guest's status of what `r` resolved to, not following a link:
/// [`stat_at`], or a file of fwe's store's own.
fn resolved_guest_stat(r: &crate::fs::Resolved) -> Result<libc::stat, i32> {
    if let Some(d) = &r.store {
        let (ino, _) = d.find(&r.name)?;
        return d.host_stat(ino);
    }
    stat_at(r.dir.as_raw_fd(), &r.name_c()?)
}

/// [`stat_at`] with `fstatat` flags `flags`.
fn stat_at_with(dir: i32, name: &CString, flags: i32) -> Result<libc::stat, i32> {
    // SAFETY: `out` is a valid out-parameter; `name` is NUL-terminated.
    let mut out = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: `name` is NUL-terminated; `dir` is a live directory fd; `out` valid.
    let r = unsafe { libc::fstatat(dir, name.as_ptr(), &mut out, flags) };
    if r < 0 {
        return Err(host::errno_to_linux(host::last_errno()));
    }
    let perm = crate::modes::guest_perm_at(dir, name, &out);
    let owner = crate::owners::of_at(dir, name, &out);
    crate::modes::apply(&mut out, perm);
    crate::owners::apply(&mut out, owner);
    Ok(out)
}

/// The Linux status of `name` in directory `dir`, whose host status is
/// `s`, in a mount of type `fstype` and id `mount_id`; with its `statx`
/// attributes.
fn stat_result(
    dir: i32,
    name: &CString,
    s: &libc::stat,
    fstype: crate::mounts::FsType,
    mount_id: u32,
) -> (Stat, Extra) {
    let node = crate::devnodes::marked(s).then(|| crate::devnodes::node_at(dir, name)).flatten();
    let mut out = as_node(stat_to_linux(s), node);
    if fstype == crate::mounts::FsType::Tmpfs {
        on_tmpfs(&mut out, mount_id);
    }
    let nodump = crate::modes::nodump_at(dir, name, s);
    (out, Extra::of(s, nodump))
}

/// The Linux status of a file of fwe's store whose host-laid status is
/// `s` ([`crate::filestore::io::host_stat`]): its device and numbers its
/// own, with its `statx` attributes.
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
pub(crate) fn store_stat_result(s: &libc::stat) -> (Stat, Extra) {
    let mut out = stat_to_linux(s);
    out.st_rdev = s.st_rdev as u64;
    out.st_nlink = s.st_nlink as u32;
    (out, Extra::of(s, false))
}

/// The host device and inode of the file open as `fd`.
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
pub(crate) fn host_identity(fd: i32) -> Option<(u64, u64)> {
    let mut st = zeroed_stat();
    // SAFETY: plain host call with a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino as u64))
}

/// `fstat` of `fd` in Linux's layout, with the guest's mode and owner.
pub(crate) fn linux_fstat(fd: i32) -> Result<Stat, i32> {
    stat_fd_of(fd).map(|(s, stored)| stat_to_linux_fd(fd, &s, stored))
}

/// The Linux status of the file open as `fd`, whose host status is `s`
/// (`stored`: a file of fwe's store's, [`stat_fd_of`]): that of a tmpfs's
/// file if it was opened in one.
fn stat_to_linux_fd(fd: i32, s: &libc::stat, stored: bool) -> Stat {
    // A file of fwe's store has its own numbers (a FIFO's too, open on
    // its node).
    if stored {
        return store_stat_result(s).0;
    }
    let mut out = stat_to_linux(s);
    if let Some(m) = tmpfs_of(fd, s) {
        on_tmpfs(&mut out, m);
    }
    out
}

/// The tmpfs mount the file open as `fd` (host status `s`) was opened in.
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
fn tmpfs_of(fd: i32, s: &libc::stat) -> Option<u32> {
    crate::fdmarks::tmpfs_mount(fd, s.st_dev as u64, s.st_ino as u64)
}

/// A file of the tmpfs mounted as mount `id`: on a device of its own, the
/// one `/proc/<pid>/mountinfo` gives the mount (`0:<20 + id>`), in blocks
/// of a page, as Linux's tmpfs is.
fn on_tmpfs(st: &mut Stat, id: u32) {
    st.st_dev = crate::devnodes::makedev(0, 20 + id);
    st.st_blksize = crate::maps::page_size().max(4096) as i32;
}

/// `/proc` path `p` as Linux names the file it opens (`/proc/self/fd`'s
/// links): `self` as the process's pid, `thread-self` as its pid's task
/// of the thread.
fn named_by_pid(p: &[u8]) -> Vec<u8> {
    let under =
        |dir: &[u8]| p.strip_prefix(dir).filter(|rest| rest.is_empty() || rest.starts_with(b"/"));
    if let Some(rest) = under(b"/proc/self") {
        return [format!("/proc/{}", crate::thread::tgid()).as_bytes(), rest].concat();
    }
    if let Some(rest) = under(b"/proc/thread-self") {
        let task = format!("/proc/{}/task/{}", crate::thread::tgid(), crate::thread::tid());
        return [task.as_bytes(), rest].concat();
    }
    p.to_vec()
}

/// Host metadata of open descriptor `fd` (of the file an `O_PATH`
/// stand-in names), with the guest's permission bits ([`crate::modes`])
/// and owner ([`crate::owners`]).
fn stat_fd(fd: i32) -> Result<libc::stat, i32> {
    stat_fd_of(fd).map(|(st, _)| st)
}

/// [`stat_fd`], and whether the file is one of fwe's store's (a FIFO's
/// too, open on its node).
fn stat_fd_of(fd: i32) -> Result<(libc::stat, bool), i32> {
    if let Some(st) = crate::filestore::io::stat(fd) {
        return st.map(|st| (st, true));
    }
    if let Some(host) = crate::fdmarks::stand_in(fd) {
        // A stand-in `O_PATH` descriptor: the file it names.
        let c = CString::new(host).map_err(|_| errno::EINVAL)?;
        let mut out = zeroed_stat();
        // SAFETY: a NUL-terminated path and a valid out-parameter.
        if unsafe { libc::lstat(c.as_ptr(), &mut out) } < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        let perm = crate::modes::guest_perm_path(&c, &out);
        let owner = crate::owners::of_path(&c, &out);
        crate::modes::apply(&mut out, perm);
        crate::owners::apply(&mut out, owner);
        return Ok((out, false));
    }
    let mut out = zeroed_stat();
    // SAFETY: plain host call with a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut out) } < 0 {
        return Err(host::errno_to_linux(host::last_errno()));
    }
    // A FIFO of fwe's store, open on its node: the store's file.
    if let Some(file) = crate::storenodes::fifo_file(fd, &out) {
        let fs = file.fs()?;
        let t = fs.lock()?;
        return Ok((crate::filestore::io::host_stat(t.dev(), &t.stat(file.ino)?), true));
    }
    // A program or map of bpf's is an object of fwe's in host shared memory.
    let bpf = || crate::memobj::may_be(&out) && crate::bpf::is_bpf_fd(fd);
    if crate::mountapi::is_context(fd) || crate::landlock::is_ruleset(fd) || bpf() {
        // An anonymous inode: owner read and write, of no file type.
        out.st_mode = 0o600;
        let owner = crate::owners::host_owner(&out);
        crate::owners::apply(&mut out, owner);
        return Ok((out, false));
    }
    // A socket's own inode: its maker's, every bit allowed until an
    // `fchmod` (the host keeps neither).
    if out.st_mode & libc::S_IFMT == libc::S_IFSOCK {
        let s = crate::net::socket_inode(fd);
        let owner = s.and_then(|s| s.owner).unwrap_or_else(|| crate::owners::host_owner(&out));
        crate::modes::apply(&mut out, s.map_or(0o777, |s| s.perm));
        crate::owners::apply(&mut out, owner);
        return Ok((out, false));
    }
    let perm = crate::modes::guest_perm_fd(fd, &out);
    let owner = crate::owners::of_fd(fd, &out);
    crate::modes::apply(&mut out, perm);
    crate::owners::apply(&mut out, owner);
    Ok((out, false))
}

/// What a path names, as a walk sees it ([`Kernel::link_kind`]).
pub(crate) enum LinkKind {
    /// Not a link (or nothing there yet, with the error).
    None,
    /// A symbolic link, and its target.
    Symlink(Vec<u8>),
    /// One of `/proc`'s links to an open file or a place (`exe`, `cwd`,
    /// `root`, `fd/<n>`, `ns/<kind>`, `map_files/...`).
    Magic,
}

/// Whether `/proc` path `abs`, a link there, is one of its magic links.
fn magic_link(abs: &[u8]) -> bool {
    let Some(rest) = abs.strip_prefix(b"/proc/") else { return false };
    let (parent, name) = match rest.iter().rposition(|&b| b == b'/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => return false,
    };
    matches!(name, b"exe" | b"cwd" | b"root")
        || parent.ends_with(b"/fd")
        || parent.ends_with(b"/ns")
        || parent.ends_with(b"/map_files")
}

/// The access (`R_OK`, `W_OK` bits) an `open` with Linux `flags` asks of
/// an existing file.
fn open_wants(flags: u64) -> u32 {
    let mut want = match flags & fcntl::O_ACCMODE {
        fcntl::O_RDONLY => 4,
        fcntl::O_WRONLY => 2,
        _ => 6,
    };
    if flags & fcntl::O_TRUNC != 0 {
        want |= 2;
    }
    want
}

impl<P: Platform> Kernel<P> {
    /// The calling thread's filesystem view and namespaces: its own
    /// ([`crate::threadfs`]) or the process's.
    pub fn fs(&self) -> &Fs {
        self.fs_opt().expect("filesystem configured")
    }

    /// [`fs`](Self::fs), to change.
    pub fn fs_mut(&mut self) -> &mut Fs {
        self.fs_opt_mut().expect("filesystem configured")
    }

    /// [`fs`](Self::fs), if there is one.
    pub fn fs_opt(&self) -> Option<&Fs> {
        match crate::threadfs::current() {
            // SAFETY: this thread's own view, which only it uses; a call
            // of another thread that changes it holds the kernel lock
            // alone, which `&self` excludes.
            Some(p) => Some(unsafe { &*p }),
            None => self.fs.as_ref(),
        }
    }

    /// [`fs_opt`](Self::fs_opt), to change.
    pub fn fs_opt_mut(&mut self) -> Option<&mut Fs> {
        match crate::threadfs::current() {
            // SAFETY: as in `fs_opt`, with `&mut self` for the lock.
            Some(p) => Some(unsafe { &mut *p }),
            None => self.fs.as_mut(),
        }
    }

    pub(crate) fn sys_openat(&mut self, dirfd: u64, path: u64, flags: u64, mode: u64) -> i64 {
        let path = match uaccess::read_cstr(path, uaccess::PATH_MAX) {
            Ok(p) => p,
            Err(e) => {
                crate::fs::drop_fifo();
                crate::fs::ahead::clear();
                return err(e);
            }
        };
        let r = self.open_with(dirfd, path, flags, mode);
        // A resolution made ahead serves only the call it was made for.
        crate::fs::ahead::clear();
        r
    }

    /// `openat` of guest path `path` (`openat2`'s too, once walked).
    pub(crate) fn open_with(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        if let Some(e) = self.proc_refused(dirfd as i32, &path) {
            crate::fs::drop_fifo();
            return err(e);
        }
        let r = self.open_path(dirfd, path, flags, mode);
        crate::fs::drop_fifo();
        // An `O_PATH` descriptor, whatever kind of file it names (one of
        // `/proc` or `/sys` too), is open for nothing but naming it (one of
        // a `/proc` link is marked as that already, one of fwe's store's
        // file by its description).
        if r >= 0
            && flags & fcntl::O_PATH != 0
            && crate::fdmarks::proc_link(r as i32).is_none()
            && crate::filestore::desc::of(r as i32).is_none()
        {
            crate::fdmarks::mark(r as i32, crate::fdmarks::Mark::Path);
        }
        r
    }

    /// Open the namespace `/proc/<pid>/ns/<kind>` (`path` from `dirfd`)
    /// names, its link reading `link`.
    fn open_ns_path(&mut self, dirfd: i32, path: &[u8], link: &[u8], flags: u64) -> i64 {
        match self.ns_at(dirfd, path, link) {
            Ok(n) => crate::nsfd::open(n, flags & fcntl::O_CLOEXEC != 0),
            Err(e) => err(e),
        }
    }

    /// The namespace `/proc/<pid>/ns/<kind>` or
    /// `/proc/<pid>/task/<tid>/ns/<kind>` (`path` from `dirfd`) names, its
    /// link reading `link`.
    pub(crate) fn ns_at(
        &self,
        dirfd: i32,
        path: &[u8],
        link: &[u8],
    ) -> Result<crate::nsfd::NsRef, i32> {
        let (who, sub) = self.fs().proc_target(dirfd, path).ok_or(errno::ENOENT)?;
        // A thread's (`/proc/<pid>/task/<tid>/ns/<kind>`): its own
        // namespaces, if it has them ([`crate::threadfs`]).
        let task = sub.strip_prefix(b"/task/").and_then(|rest| {
            let i = rest.iter().position(|&b| b == b'/')?;
            let tid = std::str::from_utf8(&rest[..i]).ok()?.parse::<i32>().ok()?;
            Some((tid, &rest[i..]))
        });
        let (tid, sub) = match (who, task) {
            (None, Some((tid, rest))) => (Some(tid), rest.to_vec()),
            _ => (None, sub),
        };
        let name = sub.strip_prefix(b"/ns/").ok_or(errno::ENOENT)?;
        let dirs = match who {
            None => match tid {
                Some(t) if t != crate::thread::tid() => crate::threadfs::view_of(t, Fs::ns_dirs)
                    .unwrap_or_else(|| self.fs.as_ref().map_or_else(Vec::new, Fs::ns_dirs)),
                _ => self.fs().ns_dirs(),
            },
            Some(host) => match host.and_then(crate::procreg::read) {
                Some(rec) => rec.ns,
                None => return Err(errno::ENOENT),
            },
        };
        self.ns_ref(name, &dirs, link)
    }

    /// `openat` of `path`, read from the guest. A symbolic link of the
    /// host's to a file of fwe's `/proc` or `/sys` (`/etc/mtab`), which the
    /// host cannot open, is opened as that file.
    pub(crate) fn open_path(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        // A trailing slash names a directory: `O_CREAT` cannot make one
        // (`EISDIR`), and anything else is `ENOTDIR` (below).
        let dir_only = path.len() > 1 && path.ends_with(b"/");
        if dir_only && flags & fcntl::O_CREAT != 0 {
            return err(errno::EISDIR);
        }
        if dir_only
            && let Ok(st) = self.linux_stat(dirfd as i32, &path, true, 0)
            && st.st_mode & fwe_abi::stat::S_IFMT != fwe_abi::stat::S_IFDIR
        {
            return err(errno::ENOTDIR);
        }
        let r = self.open_path_inner(dirfd, path, flags, mode);
        if r >= 0 && flags & fwe_abi::fcntl::O_NOATIME != 0 {
            crate::atime::opened_noatime(r as i32);
        }
        // `O_CREAT` of a directory that exists (through a link too) is
        // `EISDIR`, which the host lets open.
        if r >= 0 && flags & fcntl::O_CREAT != 0 {
            // SAFETY: an all-zero `stat` is a valid out-parameter.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above, on the descriptor just opened.
            if unsafe { libc::fstat(r as i32, &mut st) } == 0
                && st.st_mode & libc::S_IFMT == libc::S_IFDIR
            {
                let _ = self.syscall(fwe_abi::nr::CLOSE, [r as u64, 0, 0, 0, 0, 0]);
                return err(errno::EISDIR);
            }
        }
        r
    }

    fn open_path_inner(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        let r = self.open_path_once(dirfd, path.clone(), flags, mode);
        if (r == err(errno::ENOENT) || r == err(errno::ELOOP))
            && flags & fcntl::O_NOFOLLOW == 0
            && let Some(to) = self.fs().synthetic_target(dirfd as i32, &path)
        {
            return self.open_path_once(fcntl::AT_FDCWD as u64, to, flags, mode);
        }
        r
    }

    fn open_path_once(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        // Pseudo-terminal devices are synthesized, not served from the rootfs.
        if path == b"/dev/ptmx" {
            return crate::pty::open_master(flags);
        }
        if let Some(n) = pts_number(&path) {
            return crate::pty::open_slave(n, host::open_flags_to_host(flags));
        }
        #[cfg(target_os = "macos")]
        if let Some(r) = self.open_direct(dirfd as i32, &path, flags) {
            return r;
        }
        let r = self.open_found(dirfd, path, flags, mode);
        // A file of the no-access-time flag (`FS_NOATIME_FL`) is read as
        // through `O_NOATIME` (the one-call open above takes no file whose
        // host flag marks something kept, as this one's does).
        if r >= 0 && flags & fcntl::O_NOATIME == 0 && crate::modes::noatime_fd(r as i32) {
            crate::atime::opened_noatime(r as i32);
        }
        r
    }

    /// [`Self::open_path_once`] of what the one-call open does not take.
    fn open_found(&mut self, dirfd: u64, path: Vec<u8>, flags: u64, mode: u64) -> i64 {
        // Synthetic /proc and /sys files take priority over the host rootfs.

        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            return match entry {
                // A namespace's file bound to a path.
                crate::procfs::Entry::Ns(n) => crate::nsfd::open(n, flags & fcntl::O_CLOEXEC != 0),
                crate::procfs::Entry::File(_)
                    if self.fs().proc_path(dirfd as i32, &path).as_deref()
                        == Some(b"/proc/self/status") =>
                {
                    self.synthetic_fd(
                        self.proc_file(dirfd as i32, &path, self.self_status(), flags),
                        dirfd as i32,
                        &path,
                    )
                }
                crate::procfs::Entry::File(_)
                    if self.fs().proc_path(dirfd as i32, &path).as_deref()
                        == Some(b"/proc/keys") =>
                {
                    let text = crate::keys::proc_keys(&self.key_caller());
                    self.synthetic_fd(
                        self.proc_file(dirfd as i32, &path, text, flags),
                        dirfd as i32,
                        &path,
                    )
                }
                // Another process's memory (`crate::procmem`).
                crate::procfs::Entry::File(_)
                    if let Some(id) = self.other_mem(dirfd as i32, &path) =>
                {
                    match id {
                        Ok(id) => {
                            let fd = self.synthetic_fd(
                                self.proc_file(dirfd as i32, &path, Vec::new(), flags),
                                dirfd as i32,
                                &path,
                            );
                            if fd >= 0 {
                                crate::fdmarks::mark(
                                    fd as i32,
                                    crate::fdmarks::Mark::RemoteMem { id },
                                );
                            }
                            fd
                        }
                        Err(e) => err(e),
                    }
                }
                crate::procfs::Entry::File(_)
                    if let Some(tid) = self.fs().proc_path(dirfd as i32, &path).and_then(|p| {
                        let t = p.strip_prefix(b"/proc/self/task/")?.strip_suffix(b"/status")?;
                        std::str::from_utf8(t).ok()?.parse::<i32>().ok()
                    }) =>
                {
                    self.synthetic_fd(
                        self.proc_file(dirfd as i32, &path, self.task_status(tid), flags),
                        dirfd as i32,
                        &path,
                    )
                }
                crate::procfs::Entry::File(_)
                    if let Some(pagemap) =
                        self.fs().proc_path(dirfd as i32, &path).and_then(|p| match &p[..] {
                            b"/proc/self/mem" => Some(false),
                            b"/proc/self/pagemap" => Some(true),
                            _ => None,
                        }) =>
                {
                    // `pagemap` is only read.
                    if pagemap && flags & fcntl::O_ACCMODE != fcntl::O_RDONLY {
                        return err(errno::EACCES);
                    }
                    if flags & fcntl::O_ACCMODE != fcntl::O_RDONLY
                        && self.synthetic_read_only(dirfd as i32, &path)
                    {
                        return err(errno::EROFS);
                    }
                    let fd = self.synthetic_fd(
                        self.proc_file(dirfd as i32, &path, Vec::new(), flags),
                        dirfd as i32,
                        &path,
                    );
                    if fd >= 0 {
                        crate::procmem::opened(fd as i32, pagemap);
                    }
                    fd
                }
                crate::procfs::Entry::File(content)
                    if flags & fcntl::O_ACCMODE != fcntl::O_RDONLY =>
                {
                    // The map files and the network namespace's sysctls
                    // take a write; the rest are read-only.
                    let sysctl = || {
                        let p = self.fs().proc_path(dirfd as i32, &path)?;
                        crate::sysctl::open_for_write(&p, &self.creds)
                    };
                    let mark = match self.map_file(dirfd as i32, &path) {
                        Some(mark) => Ok(mark),
                        None => match self
                            .oom_file(dirfd as i32, &path)
                            .or_else(|| self.name_file(dirfd as i32, &path))
                        {
                            Some(mark) => mark,
                            None => sysctl().unwrap_or(Err(errno::EACCES)),
                        },
                    };
                    // Permitted, through a read-only mount (a container's
                    // `/proc/sys`): `EROFS`, as Linux checks after.
                    let mark = mark.and_then(|m| {
                        if self.synthetic_read_only(dirfd as i32, &path) {
                            Err(errno::EROFS)
                        } else {
                            Ok(m)
                        }
                    });
                    match mark {
                        Ok(mark) => {
                            let fd = self.proc_file(dirfd as i32, &path, content, flags);
                            if fd >= 0 {
                                crate::fdmarks::mark(fd as i32, mark);
                            }
                            fd
                        }
                        Err(e) => err(e),
                    }
                }
                crate::procfs::Entry::File(content) => {
                    let fd = self.synthetic_fd(
                        self.proc_file(dirfd as i32, &path, content, flags),
                        dirfd as i32,
                        &path,
                    );
                    // A mounts file reports its namespace's changes.
                    let p = self.fs().proc_path(dirfd as i32, &path).unwrap_or_default();
                    if fd >= 0 && matches!(&p[..], b"/proc/self/mounts" | b"/proc/self/mountinfo") {
                        crate::mountwatch::opened(fd as i32, self.fs().mount_ns().clone());
                    }
                    fd
                }
                crate::procfs::Entry::Symlink(target) if namespace_inode(&target).is_some() => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return self.open_proc_link(dirfd as i32, &path, flags);
                    }
                    self.open_ns_path(dirfd as i32, &path, &target, flags)
                }
                crate::procfs::Entry::Symlink(target) => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return self.open_proc_link(dirfd as i32, &path, flags);
                    }
                    // Follow the link, from the directory it is in.
                    let target = self.fs().link_target(dirfd as i32, &path, &target);
                    self.open_path(fcntl::AT_FDCWD as u64, target, flags, mode)
                }
                crate::procfs::Entry::Fd { fd, target } => {
                    if flags & fcntl::O_NOFOLLOW != 0 {
                        return self.open_proc_link(dirfd as i32, &path, flags);
                    }
                    // A descriptor of a link: followed, a link again.
                    if crate::fdmarks::proc_link(fd).is_some() {
                        return self.open_proc_link(dirfd as i32, &path, flags);
                    }
                    if crate::fs::has_path(fd, &target) {
                        // Reopen the file, as Linux does: the same one, in
                        // the mount it was opened through, whatever has
                        // become of its path; copied up first, to write a
                        // file of an overlay.
                        let writes = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY
                            || flags & fcntl::O_TRUNC != 0;
                        if writes && let Err(e) = self.fd_change(fd) {
                            return err(e);
                        }
                        return reopen(fd, flags);
                    }
                    // A file of fwe's store (a memfd's): a new description
                    // of it, as Linux opens the file again.
                    if let Some(file) = crate::filestore::desc::of(fd) {
                        return self.reopen_stored(fd, file, flags);
                    }
                    // A pipe, socket or the like: a new descriptor for it.
                    let cmd = if flags & fcntl::O_CLOEXEC != 0 {
                        libc::F_DUPFD_CLOEXEC
                    } else {
                        libc::F_DUPFD
                    };
                    // SAFETY: plain host call on an open guest descriptor.
                    ret(unsafe { libc::fcntl(fd, cmd, 0) })
                }
                crate::procfs::Entry::Dir => match self.fs().synth_children(dirfd as i32, &path) {
                    Some(mut entries) => {
                        let at = self.fs().absolute_path(dirfd as i32, &path).unwrap_or_default();
                        // A `proc` mount's root lists what its options do
                        // not hide from the reader.
                        let (m, fs_path) = self.fs().mount_of(&at);
                        if m.fstype == crate::mounts::FsType::Proc && fs_path == b"/" {
                            entries.retain(|(n, _)| {
                                n == b"."
                                    || n == b".."
                                    || self.hidden_in(&m.options, &[b"/", &n[..]].concat())
                                        != Some(errno::ENOENT)
                            });
                        }
                        let fd = crate::synthdir::open(at, entries);

                        let fd = self.synthetic_fd(fd, dirfd as i32, &path);
                        if fd >= 0 && self.fs().lists_fds(dirfd as i32, &path) {
                            // Linux lists the listing's own descriptor too.
                            let name = fd.to_string().into_bytes();
                            crate::synthdir::add(fd as i32, name, crate::procfs::DT_LNK);
                        }
                        fd
                    }
                    None => err(errno::ENOENT),
                },
                crate::procfs::Entry::Missing => err(errno::ENOENT),
            };
        }
        self.sys_openat_bytes(dirfd, &path, flags, mode)
    }

    /// An open only to read, of a file the host finds in one call from the
    /// root where the walk would find it ([`crate::fs::Fs::direct`]): a
    /// regular file or a directory with no mode or owner kept apart from
    /// the host's, while no lease is taken anywhere and the process holds
    /// no record lock (one this opens to look at and closes again would
    /// lose it: [`crate::reclocks`]). `None` for any other, which takes the
    /// whole way ([`Self::sys_openat_bytes`]).
    #[cfg(target_os = "macos")]
    fn open_direct(&mut self, dirfd: i32, path: &[u8], flags: u64) -> Option<i64> {
        use crate::procstore::{Count, count};
        // (A FIFO opened already, waiting for its other end, is its.)
        if !crate::fs::reads_only(flags)
            || crate::fs::fifo_preopened()
            || crate::reclocks::held()
            || count(Count::Leases).load(std::sync::atomic::Ordering::SeqCst) != 0
        {
            return None;
        }
        let mut d = self.fs().direct(dirfd, path)?;
        // Opened already, without the lock ([`crate::fs::open_fifo_unlocked`]),
        // or here.
        let (fd, st) = match d.opened.take() {
            Some((fd, st)) => (std::os::fd::IntoRawFd::into_raw_fd(fd), st),
            None => {
                // No link anywhere on the way (the host refuses
                // `O_NOFOLLOW` beside it, which it covers).
                let host_flags =
                    host::open_flags_to_host(flags) & !libc::O_NOFOLLOW | libc::O_NOFOLLOW_ANY;
                // SAFETY: the root's descriptor and a NUL-terminated name.
                let fd = unsafe { host::openat(d.dir, &d.name, host_flags, 0) };
                if fd < 0 {
                    // A missing name on a way with no link, as the walk
                    // finds; a link, or a refusal root may pass, takes the
                    // whole way.
                    let e = host::last_errno();
                    return matches!(e, libc::ENOENT | libc::ENOTDIR).then(last_error);
                }
                // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: the descriptor just opened.
                if unsafe { libc::fstat(fd, &mut st) } != 0 {
                    // SAFETY: closing the descriptor just opened.
                    unsafe { libc::close(fd) };
                    return None;
                }
                (fd, st)
            }
        };
        let plain = crate::fs::plain_file(&st);
        let mut guest = st;
        crate::owners::apply(&mut guest, crate::owners::host_owner(&st));
        if !plain || !self.permits(&guest, open_wants(flags)) {
            // SAFETY: closing the descriptor just opened.
            unsafe { libc::close(fd) };
            return None;
        }
        #[allow(clippy::unnecessary_cast)] // `st_dev` is narrower on macOS
        let file = (st.st_dev as u64, st.st_ino as u64);
        // Where it is in the mount namespace: the root's place, and the
        // way below it.
        let ns = crate::mounts::join(self.fs().proc_root(), d.name.to_bytes());
        crate::fdmarks::opened_as(fd, file, ns, d.mount_id, d.mount_flags, d.fstype, None);
        // A number reused keeps no earlier open's word.
        crate::fdstate::update(fd, |s| s.created = false);
        Some(fd as i64)
    }

    fn sys_openat_bytes(&mut self, dirfd: u64, path: &[u8], flags: u64, mode: u64) -> i64 {
        // `O_TMPFILE`: a new file under a hidden name in the directory, for
        // writing ([`crate::tmpfile`]).
        if flags & fcntl::O_TMPFILE == fcntl::O_TMPFILE {
            if flags & fcntl::O_ACCMODE == fcntl::O_RDONLY {
                return err(errno::EINVAL);
            }
            let dir = match self.fs().resolve(dirfd as i32, path, true) {
                Ok(r) => r,
                Err(e) => return err(e),
            };
            // In fwe's store: a file of it with no name.
            if let Some(d) = &dir.store {
                let d = match d.find(&dir.name) {
                    Ok((ino, st))
                        if st.mode & crate::filestore::tree::S_IFMT
                            == crate::filestore::tree::S_IFDIR =>
                    {
                        crate::fs::StoreDir { fs: d.fs.clone(), ino }
                    }
                    Ok(_) => return err(errno::ENOTDIR),
                    Err(e) => return err(e),
                };
                let mut at = dir;
                at.store = Some(d);
                at.name = b".".to_vec();
                return self.store_tmpfile(
                    &at,
                    &at.store.clone().expect("in the store"),
                    flags,
                    mode,
                );
            }
            match dir.name_c().ok().and_then(|n| stat_at(dir.dir.as_raw_fd(), &n).ok()) {
                Some(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                Some(_) => return err(errno::ENOTDIR),
                None => return err(errno::ENOENT),
            }
            let mut name = path.to_vec();
            if !name.ends_with(b"/") {
                name.push(b'/');
            }
            name.extend_from_slice(&crate::tmpfile::fresh_name());
            let made = flags & !fcntl::O_TMPFILE | fcntl::O_CREAT | fcntl::O_EXCL;
            let fd = self.sys_openat_bytes(dirfd, &name, made, mode);
            if fd >= 0 {
                crate::tmpfile::made(fd as i32, flags & fcntl::O_EXCL != 0);
            }
            return fd;
        }
        // With O_PATH every flag but these is ignored, as on Linux: nothing
        // is made, truncated or opened for writing.
        let flags = if flags & fcntl::O_PATH != 0 {
            flags & (fcntl::O_PATH | fcntl::O_CLOEXEC | fcntl::O_DIRECTORY | fcntl::O_NOFOLLOW)
        } else {
            flags
        };
        let follow_final = flags & fcntl::O_NOFOLLOW == 0
            && flags & (fcntl::O_CREAT | fcntl::O_EXCL) != fcntl::O_CREAT | fcntl::O_EXCL;
        let mut resolved = match self.fs().resolve(dirfd as i32, path, follow_final) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // A file of fwe's store (a tmpfs's).
        if let Some(d) = resolved.store.clone() {
            let slash = path.last() == Some(&b'/');
            return self.store_open(&resolved, &d, flags, mode, slash);
        }
        // O_TMPFILE includes O_DIRECTORY's bit: all of it, or not at all.
        let writes = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY
            || flags & fcntl::O_TRUNC != 0
            || flags & fcntl::O_TMPFILE == fcntl::O_TMPFILE;
        if writes || flags & fcntl::O_CREAT != 0 {
            // A file that exists on a read-only mount may still be opened
            // to read with O_CREAT; a device, FIFO or socket to write as
            // well (Linux refuses only regular files, directories and
            // links), and one in an overlay is not copied up to be.
            let found = resolved_stat(&resolved);
            let exists = found.is_some();
            let special = found.is_some_and(|st| {
                crate::devnodes::marked(&st)
                    || matches!(
                        st.st_mode & libc::S_IFMT,
                        libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK
                    )
            });
            if (writes || !exists)
                && !special
                && let Err(e) = resolved.writable()
            {
                return err(e);
            }
            // In an overlay, the file is copied up to be written, or its
            // directory to make it in.
            let how = match (exists, special) {
                (true, true) => None,
                (true, false) => writes.then_some(Change::Modify),
                (false, _) => Some(Change::Create),
            };
            if flags & fcntl::O_PATH == 0
                && let Some(how) = how
                && let Err(e) = resolved.prepare(how)
            {
                return err(e);
            }
        }
        let name = match resolved.name_c() {
            Ok(n) => n,
            Err(e) => return err(e),
        };
        let mut host_flags = host::open_flags_to_host(flags);
        if flags & fcntl::O_PATH != 0 {
            // The host has no O_PATH: the file is opened to read, which
            // must not wait as a FIFO's open does for a writer, nor make a
            // terminal the controlling one. The descriptor only names it.
            host_flags |= libc::O_NONBLOCK | libc::O_NOCTTY;
        }
        if flags & fcntl::O_DIRECTORY == 0 && resolved.name == b"." {
            // Opening the directory itself.
            host_flags |= libc::O_DIRECTORY;
        }
        let asked = mode as u32;
        let mode = if flags & fcntl::O_CREAT != 0 { self.fs().apply_umask(mode as u32) } else { 0 };
        // An existing file's kept mode, for a caller that does not pass
        // permission bits; a new one is made with what its owner must have
        // on the host ([`crate::modes`]).
        let existing = resolved_stat(&resolved);
        // A lease on the file this open conflicts with is broken first.
        if let Some(st) = &existing
            && st.st_mode & libc::S_IFMT == libc::S_IFREG
            && flags & fcntl::O_PATH == 0
        {
            let write = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY || flags & fcntl::O_TRUNC != 0;
            let nonblock = flags & fcntl::O_NONBLOCK != 0;
            // `st_dev` is narrower on macOS.
            #[allow(clippy::unnecessary_cast)]
            let dev = st.st_dev as u64;
            // A running program's file is not to be written.
            if write && crate::textbusy::is_running(dev, st.st_ino) {
                return err(errno::ETXTBSY);
            }
            if let Err(e) = crate::leases::break_for(dev, st.st_ino, write, nonblock) {
                return err(e);
            }
        }
        if let Some(st) = &existing
            && flags & fcntl::O_PATH == 0
            && st.st_mode & libc::S_IFMT != libc::S_IFLNK
            && !self.permits(st, open_wants(flags))
        {
            return err(errno::EACCES);
        }
        // `O_NOATIME` is the file's owner's to ask for (`EPERM`).
        if let Some(st) = &existing
            && flags & 0o1000000 != 0
            && st.st_uid != self.creds.fsuid
            && !self.creds.has_over(crate::caps::CAP_FOWNER, st.st_uid, st.st_gid)
        {
            return err(errno::EPERM);
        }
        let host_mode = crate::modes::made_file_perm(mode);
        if resolved.fstype == crate::mounts::FsType::Cgroup2
            && let Some(host) = crate::fs::host_path_in(resolved.dir.as_raw_fd(), &resolved.name)
            && let Some((cg, Some(file))) = crate::cgroupfs::locate(&host)
        {
            // What the file reports is what is so as it is opened.
            let dir = crate::cgroupfs::host_dir(&cg).unwrap_or_default();
            crate::cgroupfs::refresh(&dir, &cg, &file);
            use std::os::unix::ffi::OsStrExt;
            if flags & fcntl::O_CREAT != 0
                && !std::path::Path::new(std::ffi::OsStr::from_bytes(&host)).exists()
            {
                // A cgroup has only the files the kernel makes.
                return err(errno::EACCES);
            }
        }
        let dirfd = resolved.dir.as_raw_fd();
        // SAFETY: `dir` is a live directory fd.
        let open = || unsafe { host::openat(dirfd, &name, host_flags, host_mode as libc::c_uint) };
        // Whether `fd` is a stand-in for the file (see `Origin::stand_in`).
        let mut stand_in = false;
        let cloexec = host_flags & libc::O_CLOEXEC;
        let mut fd = match &existing {
            // Made here: a change of the directory.
            None if flags & fcntl::O_CREAT != 0 => {
                // Made here, or found made meanwhile, whose mode is its own.
                let made = std::cell::Cell::new(true);
                let r = self.change_in(dirfd, || {
                    // SAFETY: `dir` is a live directory fd.
                    let fd = unsafe {
                        host::openat(
                            dirfd,
                            &name,
                            host_flags | libc::O_EXCL,
                            host_mode as libc::c_uint,
                        )
                    };
                    if fd < 0 && host::last_errno() == libc::EEXIST && flags & fcntl::O_EXCL == 0 {
                        made.set(false);
                        let fd = open();
                        return if fd < 0 { last_error() } else { fd as i64 };
                    }
                    if fd < 0 { last_error() } else { fd as i64 }
                });
                if r >= 0 && made.get() && host_mode != mode & 0o7777 {
                    let _ = crate::modes::keep_fd(r as i32, mode);
                }
                if r >= 0 && made.get() {
                    self.own_new(dirfd, &name, Some(r as i32), false, mode, asked);
                }
                if r >= 0 {
                    crate::fdstate::update(r as i32, |s| s.created = made.get());
                }
                if let Err(e) = resolved.finish(r >= 0)
                    && r >= 0
                {
                    // SAFETY: closing the descriptor just opened.
                    unsafe { libc::close(r as i32) };
                    return err(e);
                }
                if r < 0 {
                    return r;
                }
                r as i32
            }
            Some(st)
                if matches!(st.st_mode & libc::S_IFMT, libc::S_IFIFO | libc::S_IFLNK)
                    && flags & fcntl::O_PATH != 0 =>
            {
                // Any open of a FIFO is a reader or a writer of it, which an
                // O_PATH descriptor is not, and the host opens no symbolic
                // link itself (O_PATH | O_NOFOLLOW does): a stand-in names it.
                stand_in = true;
                // SAFETY: a constant NUL-terminated path.
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | cloexec) }
            }
            Some(st)
                if st.st_mode & libc::S_IFMT == libc::S_IFIFO
                    && let Some(fd) = crate::fs::take_fifo(flags, st) =>
            {
                // Opened already, waiting for the other end without the
                // lock ([`crate::fs::open_fifo_unlocked`]).
                fifo_flags(fd, flags)
            }
            Some(st) => {
                let fd = open();
                if fd < 0
                    && host::last_errno() == libc::EACCES
                    && self.passes_dac(st, open_wants(flags))
                    && crate::modes::keep_at(dirfd, &name, crate::modes::perm_of(st)).is_ok()
                {
                    // Root, refused by the host's bits: they are the owner's
                    // now, the mode kept.
                    open()
                } else {
                    fd
                }
            }
            None => open(),
        };
        if fd < 0
            && flags & fcntl::O_PATH != 0
            && matches!(
                host::last_errno(),
                libc::ENXIO | libc::ENODEV | libc::EBUSY | libc::EOPNOTSUPP
            )
        {
            // O_PATH names a device or a socket without opening it; the host
            // has no such open, so a stand-in holds the node's place (where
            // it was opened, which is what an O_PATH descriptor is used for).
            // SAFETY: a constant NUL-terminated path.
            fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | cloexec) };
            stand_in = true;
        }
        if fd < 0 {
            return last_error();
        }
        // A device: allowed by the cgroup's device programs, and the host's
        // own device behind one of fwe's nodes.
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // An O_PATH descriptor is of the node itself, the device untouched.
        // SAFETY: a valid out-parameter.
        let looked = flags & fcntl::O_PATH == 0 && unsafe { libc::fstat(fd, &mut st) } == 0;
        if looked {
            // A file open to write, which is not to be run meanwhile.
            if st.st_mode & libc::S_IFMT == libc::S_IFREG
                && flags & fcntl::O_ACCMODE != fcntl::O_RDONLY
            {
                #[allow(clippy::unnecessary_cast)] // `st_dev` is narrower on macOS
                crate::textbusy::opened_for_writing(st.st_dev as u64, st.st_ino);
                crate::modes::opened_for_writing(fd, &st);
            }
            let node = if crate::devnodes::marked(&st) {
                crate::devnodes::node_of(fd)
            } else {
                crate::devnodes::linux_numbers_of_host(&st)
            };
            if let Some(n) = node {
                // Not through a mount that has no devices.
                if resolved.mount_flags & crate::mounts::ms::NODEV != 0 {
                    // SAFETY: closing the node's own descriptor.
                    unsafe { libc::close(fd) };
                    return err(errno::EACCES);
                }
                let device = open_device(fd, n, flags, crate::devnodes::marked(&st));
                // A device fwe makes of its node keeps the node's
                // descriptor; another has the host's device opened for it.
                if device < 0 || (crate::devnodes::marked(&st) && device != fd as i64) {
                    // SAFETY: closing the node's own descriptor.
                    unsafe { libc::close(fd) };
                }
                if device < 0 {
                    return device;
                }
                if crate::devnodes::marked(&st) {
                    // Linked to the node, where it was opened.
                    if let Some(ns) = resolved.ns_path {
                        crate::fdmarks::opened(
                            device as i32,
                            ns,
                            resolved.mount_id,
                            resolved.mount_flags,
                            resolved.fstype,
                            None,
                        );
                    }
                    if crate::loopdev::is_loop_node(n) {
                        crate::loopdev::opened(device as i32, n);
                    }
                    return device;
                }
            }
        }
        let layers = resolved.ovl.as_ref().map(|o| o.layers.clone());
        if resolved.ns_path.is_some() || layers.is_some() || stand_in {
            let ns = resolved.ns_path.clone().unwrap_or_default();
            let (id, flags, fstype) = (resolved.mount_id, resolved.mount_flags, resolved.fstype);
            if looked {
                #[allow(clippy::unnecessary_cast)] // `st_dev` is narrower on macOS
                let file = (st.st_dev as u64, st.st_ino as u64);
                crate::fdmarks::opened_as(fd, file, ns, id, flags, fstype, layers);
            } else {
                crate::fdmarks::opened(fd, ns, id, flags, fstype, layers);
            }
        }
        if stand_in && let Some(host) = crate::fs::host_path_in(dirfd, &resolved.name) {
            crate::fdmarks::set_stand_in(fd, host);
        }
        // An open of a file that was there made nothing (a number reused
        // keeps no earlier open's word).
        if existing.is_some() {
            crate::fdstate::update(fd, |s| s.created = false);
        }
        fd as i64
    }

    pub(crate) fn sys_faccessat(&self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        if flags & !(fcntl::AT_EACCESS | fcntl::AT_SYMLINK_NOFOLLOW | fcntl::AT_EMPTY_PATH) != 0
            || mode & !7 != 0
        {
            return err(errno::EINVAL);
        }
        let mut path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            if dirfd as i64 != fcntl::AT_FDCWD {
                return self.access_fd(dirfd as i32, mode);
            }
            path = b".".to_vec();
        }
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        self.access_path(dirfd as i32, &path, mode, follow, flags & fcntl::AT_EACCESS != 0)
    }

    /// Whether `path` (from `dirfd`; followed if `follow`) allows the access
    /// `mode` asks (`R_OK`, `W_OK`, `X_OK`): 0, or the error, as `faccessat`
    /// (with `eaccess`, `AT_EACCESS`) reports it. The walk and the file are
    /// checked as `open` checks them, by the guest's metadata (kept mode
    /// and owner), with the ids [`access_creds`](Self::access_creds) gives.
    pub(crate) fn access_path(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u64,
        follow: bool,
        eaccess: bool,
    ) -> i64 {
        if self.fs().synthetic(dirfd, path).is_some() {
            return self.access_synthetic(dirfd, path, mode, follow, eaccess);
        }
        let a = self.access_creds(eaccess);
        let resolved =
            crate::creds::walking_as(a.clone(), || self.fs().resolve(dirfd, path, follow));
        let r = match resolved {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let st = match resolved_guest_stat(&r) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let special = r.store.is_none() && crate::devnodes::marked(&st);
        self.access_result(&st, mode, &a, special, r.writable().is_err())
    }

    /// The access `faccessat` checks with: by default the caller's real
    /// user and group, with the capabilities Linux gives them (the
    /// permitted set for a real root, none for another, unless
    /// `SECBIT_NO_SETUID_FIXUP`); with `eaccess` (`AT_EACCESS`), the ids
    /// and capabilities it acts on files with.
    fn access_creds(&self, eaccess: bool) -> crate::creds::Access {
        let c = &self.creds;
        let mut a = crate::creds::Access::of(c);
        if eaccess {
            return a;
        }
        a.fsuid = c.uid;
        a.fsgid = c.gid;
        if c.caps.securebits & crate::caps::SECBIT_NO_SETUID_FIXUP == 0 {
            let caps = if crate::userns::to_ns(c.uid, false) == 0 { c.caps.permitted } else { 0 };
            a.dac_override = caps & 1 << crate::caps::CAP_DAC_OVERRIDE != 0;
            a.dac_read_search = caps & 1 << crate::caps::CAP_DAC_READ_SEARCH != 0;
        }
        a
    }

    /// The `faccessat` answer for the file of guest metadata `st`, asked
    /// `mode` by a caller of access `a`: the permission bits first, as
    /// Linux checks them, then `EROFS` (on a `read_only` mount) for asking
    /// to write a file that is not a device (`special`), FIFO or socket. A
    /// symbolic link's own bits are all set.
    fn access_result(
        &self,
        st: &libc::stat,
        mode: u64,
        a: &crate::creds::Access,
        special: bool,
        read_only: bool,
    ) -> i64 {
        const W_OK: u64 = 2;
        let kind = st.st_mode & libc::S_IFMT;
        // Without a root filesystem, the host's own files (root's, with no
        // owner kept) are the host user's to allow ([`Self::permits`]).
        let host_own =
            st.st_uid == 0 && st.st_gid == 0 && self.fs_opt().is_some_and(|f| f.root_is_host());
        if kind != libc::S_IFLNK && !host_own && !a.permits(st, mode as u32 & 7) {
            return err(errno::EACCES);
        }
        let special = special
            || [libc::S_IFIFO, libc::S_IFSOCK, libc::S_IFCHR, libc::S_IFBLK].contains(&kind);
        if mode & W_OK != 0 && read_only && !special {
            return err(errno::EROFS);
        }
        0
    }

    /// `faccessat` of a file of fwe's `/proc` or `/sys`: whether it exists,
    /// and the caller's access by the mode `stat` shows for it, as
    /// [`access_result`](Self::access_result) checks it. A process's
    /// `oom_score_adj` is writable as opening it to write is.
    fn access_synthetic(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u64,
        follow: bool,
        eaccess: bool,
    ) -> i64 {
        const W_OK: u64 = 2;
        let st = match self.linux_stat(dirfd, path, follow, 0) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let kind = st.st_mode & fwe_abi::stat::S_IFMT;
        if kind == fwe_abi::stat::S_IFLNK {
            // A symbolic link's own bits are all set.
            return 0;
        }
        let read_only = self.synthetic_read_only(dirfd, path);
        if mode & W_OK != 0
            && let Some(open) = self.oom_file(dirfd, path)
        {
            return match (open, mode & !W_OK) {
                (Err(e), _) => err(e),
                (Ok(_), _) if read_only => err(errno::EROFS),
                (Ok(_), 0) => 0,
                (Ok(_), rest) => self.access_synthetic(dirfd, path, rest, follow, eaccess),
            };
        }
        let mut host = zeroed_stat();
        let kind = if kind == fwe_abi::stat::S_IFDIR { libc::S_IFDIR } else { libc::S_IFREG };
        host.st_mode = kind | (st.st_mode & 0o7777) as libc::mode_t;
        // The file's ids as the initial namespace has them (`stat` shows
        // them as the caller's namespace does; one it has no mapping for
        // is no one's).
        host.st_uid = crate::userns::from_ns(st.st_uid, false).unwrap_or(u32::MAX);
        host.st_gid = crate::userns::from_ns(st.st_gid, true).unwrap_or(u32::MAX);
        self.access_result(&host, mode, &self.access_creds(eaccess), false, read_only)
    }

    /// `faccessat2(fd, "", mode, AT_EMPTY_PATH)`: the access the caller has
    /// to the file `fd` is open on (or, for an `O_PATH` stand-in, names),
    /// by its guest metadata, as [`access_path`](Self::access_path) checks.
    /// A pipe or socket of no path is its maker's, as Linux's are.
    fn access_fd(&self, fd: i32, mode: u64) -> i64 {
        let mut st = match stat_fd(fd) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let a = self.access_creds(false);
        let kind = st.st_mode & libc::S_IFMT;
        if (kind == libc::S_IFIFO || kind == libc::S_IFSOCK)
            && crate::fdmarks::stand_in(fd).is_none()
            && crate::fs::host_path_of(fd).is_none()
        {
            st.st_uid = a.fsuid;
            st.st_gid = a.fsgid;
        }
        let read_only =
            crate::fdmarks::origin(fd).is_some_and(|o| o.flags & crate::mounts::ms::RDONLY != 0);
        self.access_result(&st, mode, &a, crate::devnodes::marked(&st), read_only)
    }

    /// `statfs(path, buf)`: the filesystem of the directory holding `path`
    /// (a rootfs has no mount points within it, so it is the same one).
    pub(crate) fn sys_statfs(&mut self, path: u64, buf: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Some(entry) = self.fs().synthetic(fcntl::AT_FDCWD as i32, &path) {
            if matches!(entry, crate::procfs::Entry::Missing) {
                return err(errno::ENOENT);
            }
            // A filesystem of fwe's: its mount says what it is.
            let absolute = crate::fs::normalize(self.fs().cwd(), &path);
            let (m, _) = self.fs().mount_of(&absolute);
            let root = self.fs().resolve(fcntl::AT_FDCWD as i32, b"/", true);
            return match root {
                Ok(r) => statfs_fd(r.dir.as_raw_fd(), buf, Some((m.fstype, m.flags))),
                Err(e) => err(e),
            };
        }
        let r = match self.fs().resolve(fcntl::AT_FDCWD as i32, &path, true) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            return match d.find(&r.name) {
                Ok((ino, _)) => store_statfs(
                    crate::filestore::desc::File { fs: d.fs.id, ino },
                    r.mount_flags,
                    buf,
                ),
                Err(e) => err(e),
            };
        }
        // What the path names must be there (`ENOENT`, `ENOTDIR`).
        if let Err(e) = r.name_c().and_then(|n| stat_at(r.dir.as_raw_fd(), &n)) {
            return err(e);
        }
        let mount = r.ns_path.is_some().then_some((r.fstype, r.mount_flags));
        statfs_fd(r.dir.as_raw_fd(), buf, mount)
    }

    /// `fstatfs(fd, buf)`.
    pub(crate) fn sys_fstatfs(&mut self, fd: u64, buf: u64) -> i64 {
        let fd = fd as i32;
        if let Some(file) = crate::filestore::desc::of(fd) {
            let flags = crate::fdmarks::origin(fd).map_or(0, |o| o.flags);
            return store_statfs(file, flags, buf);
        }
        // A pipe's or socket's filesystem is the kernel's own (pipefs,
        // sockfs), which the host does not report.
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } == 0 {
            const PIPEFS_MAGIC: i64 = 0x5049_5045;
            const SOCKFS_MAGIC: i64 = 0x534f_434b;
            const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;
            // An eventfd, timerfd, signalfd or the like is an anonymous
            // inode, whatever stands in for it on the host.
            let anon = crate::specialfd::anon_name(fd).is_some()
                || crate::signalfd::is_signalfd(fd)
                || crate::bpf::is_bpf_fd(fd);
            let magic = match st.st_mode & libc::S_IFMT {
                _ if anon => Some(ANON_INODE_FS_MAGIC),
                libc::S_IFIFO if crate::fs::fd_path(fd).is_none() => Some(PIPEFS_MAGIC),
                libc::S_IFSOCK => Some(SOCKFS_MAGIC),
                _ => None,
            };
            if let Some(f_type) = magic {
                let page = 4096;
                let out = fwe_abi::Statfs {
                    f_type,
                    f_bsize: page,
                    f_namelen: 255,
                    f_frsize: page,
                    f_flags: fwe_abi::statfs::ST_VALID,
                    ..Default::default()
                };
                guest!(uaccess::write(buf, out));
                return 0;
            }
        }
        if let Some((_, flags, fstype)) = crate::mountapi::detached_root(fd) {
            return statfs_fd(fd, buf, Some((fstype, flags)));
        }
        if let Some(o) = crate::fdmarks::origin(fd) {
            return statfs_fd(fd, buf, Some((o.fstype, o.flags)));
        }
        let mount = self.fs_opt().and_then(|fs| fs.ns_path_of_fd(fd)).map(|ns| {
            let table = self.fs().mounts();
            let (m, _) = table.locate(&ns);
            (m.fstype, m.flags)
        });
        statfs_fd(fd, buf, mount)
    }

    pub(crate) fn sys_newfstatat(&self, dirfd: u64, path: u64, buf: u64, flags: u64) -> i64 {
        // The flags Linux's `vfs_statx` takes; any other is refused.
        const AT_STATX_SYNC_TYPE: u64 = 0x6000;
        if flags
            & !(fcntl::AT_SYMLINK_NOFOLLOW
                | fcntl::AT_NO_AUTOMOUNT
                | fcntl::AT_EMPTY_PATH
                | AT_STATX_SYNC_TYPE)
            != 0
        {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            return self.sys_fstat(dirfd, buf);
        }
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        match self.linux_stat(dirfd as i32, &path, follow, 0) {
            Ok(st) => {
                guest!(uaccess::write(buf, st));
                0
            }
            Err(e) => err(e),
        }
    }

    /// What `stat` (`follow`) or `lstat` reports for `path` from `dirfd`,
    /// in Linux's layout: a file of fwe's `/proc` or `/sys`, a link there
    /// followed (to a descriptor's file, a path, or a namespace), a device
    /// node of fwe's as the device, or the host file. `depth` counts the
    /// links followed.
    fn linux_stat(&self, dirfd: i32, path: &[u8], follow: bool, depth: u32) -> Result<Stat, i32> {
        self.linux_stat_attrs(dirfd, path, follow, depth).map(|(s, _)| s)
    }

    /// [`Self::linux_stat`], with the file's `statx` attributes.
    fn linux_stat_attrs(
        &self,
        dirfd: i32,
        path: &[u8],
        follow: bool,
        depth: u32,
    ) -> Result<(Stat, Extra), i32> {
        match self.stat_once(dirfd, path, follow, depth) {
            // A link of the host's to a file of fwe's, which the host cannot
            // follow: that file.
            Err(errno::ENOENT | errno::ELOOP) if follow && depth < 40 => {
                match self.fs().synthetic_target(dirfd, path) {
                    Some(to) => self.stat_once(fcntl::AT_FDCWD as i32, &to, true, depth + 1),
                    None => self.stat_once(dirfd, path, follow, depth),
                }
            }
            r => r,
        }
    }

    /// `st`, a synthetic file's, owned as Linux owns the files of
    /// `/proc/<pid>`: by the process's effective user and group (root's,
    /// for a process that is not dumpable).
    fn proc_owned(&self, dirfd: i32, path: &[u8], mut st: Stat) -> Stat {
        // A dumpable process's files are its effective user's and group's;
        // another's are root's of its user namespace (Linux's
        // `task_dump_owner`).
        let owner_of = |dumpable: u8, ids: (u32, u32), ns: &[u8]| {
            if dumpable == crate::coredump::SUID_DUMP_USER {
                ids
            } else {
                crate::userns::root_of(ns)
            }
        };
        let owner = match self.fs().proc_target(dirfd, path) {
            Some((None, _)) => Some(owner_of(
                crate::coredump::dumpable(),
                (self.creds.euid, self.creds.egid),
                &crate::userns::own_dir(),
            )),
            Some((Some(Some(host)), _)) => crate::procreg::read(host).map(|r| {
                let ns = crate::nsfd::dir_among(b"user", &r.ns).unwrap_or_default();
                owner_of(r.sec.dumpable, (r.ids[1], r.ids[5]), &ns)
            }),
            _ => None,
        };
        if let Some((uid, gid)) = owner {
            st.st_uid = crate::userns::to_ns(uid, false);
            st.st_gid = crate::userns::to_ns(gid, true);
        }
        st
    }

    fn stat_once(
        &self,
        dirfd: i32,
        path: &[u8],
        follow: bool,
        depth: u32,
    ) -> Result<(Stat, Extra), i32> {
        // In one host call where it finds what the walk would: on a way
        // with no mount but the root's, none of fwe's own files, and no
        // link.
        #[cfg(target_os = "macos")]
        if let Some(d) = self.fs().direct(dirfd, path) {
            match stat_at_with(d.dir, &d.name, crate::fs::AT_SYMLINK_NOFOLLOW_ANY) {
                Ok(s) if !(follow && s.st_mode & libc::S_IFMT == libc::S_IFLNK) => {
                    return Ok(stat_result(d.dir, &d.name, &s, d.fstype, d.mount_id));
                }
                // A missing name on a way with no link, as the walk finds.
                Err(e @ (errno::ENOENT | errno::ENOTDIR)) => return Err(e),
                // A link: followed by the walk.
                _ => {}
            }
        }
        use crate::procfs::Entry;
        use fwe_abi::stat as st;
        if let Some(entry) = self.fs().synthetic(dirfd, path) {
            if let Some(e) = self.proc_hidden(dirfd, path) {
                return Err(e);
            }
            let st = match entry {
                Entry::Ns(n) => ns_stat(n.id),
                Entry::File(c) => synth_stat(st::S_IFREG | 0o444, c.len() as u64),
                Entry::Symlink(t) if follow => {
                    if let Some(ino) = namespace_inode(&t) {
                        return Ok((ns_stat(ino), Extra::default()));
                    }
                    if depth >= 40 {
                        return Err(errno::ELOOP);
                    }
                    // /proc/self/exe and the like follow to the real target.
                    let target = self.fs().link_target(dirfd, path, &t);
                    return self.linux_stat_attrs(fcntl::AT_FDCWD as i32, &target, true, depth + 1);
                }
                Entry::Symlink(t) => synth_stat(st::S_IFLNK | 0o777, t.len() as u64),
                Entry::Fd { fd, .. } if follow => {
                    if let Some(path) = crate::procfile::path_of(fd) {
                        return self.linux_stat_attrs(
                            fcntl::AT_FDCWD as i32,
                            &path,
                            true,
                            depth + 1,
                        );
                    }
                    if crate::synthdir::fstat_is_dir(fd) {
                        let path = crate::synthdir::path_of(fd).unwrap_or_default();
                        let stat = self.synth_dir_stat(fcntl::AT_FDCWD as i32, &path);
                        return Ok((stat, Extra::default()));
                    }
                    let s = stat_fd(fd)?;
                    let node =
                        crate::devnodes::marked(&s).then(|| crate::devnodes::node_of(fd)).flatten();
                    let extra = Extra::of(&s, crate::modes::nodump_fd(fd, &s));
                    return Ok((as_node(stat_to_linux(&s), node), extra));
                }
                Entry::Fd { target, .. } => synth_stat(st::S_IFLNK | 0o700, target.len() as u64),
                Entry::Dir => self.synth_dir_stat(dirfd, path),
                Entry::Missing => return Err(errno::ENOENT),
            };
            return Ok((self.proc_owned(dirfd, path, st), Extra::default()));
        }
        let r = self.fs().resolve(dirfd, path, follow)?;
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            let (ino, _) = d.find(&r.name)?;
            return Ok(store_stat_result(&d.host_stat(ino)?));
        }
        let name = r.name_c()?;
        let s = stat_at(r.dir.as_raw_fd(), &name)?;
        let fstype = if r.ns_path.is_some() { r.fstype } else { crate::mounts::FsType::Ext4 };
        Ok(stat_result(r.dir.as_raw_fd(), &name, &s, fstype, r.mount_id))
    }

    /// `open` with `O_NOFOLLOW` of the link of fwe's `/proc` at `path`:
    /// with `O_PATH`, a stand-in descriptor that names the link
    /// ([`crate::fdmarks::Mark::ProcLink`]); else `ELOOP`, as for any link.
    fn open_proc_link(&self, dirfd: i32, path: &[u8], flags: u64) -> i64 {
        if flags & fcntl::O_PATH == 0 {
            return err(errno::ELOOP);
        }
        let Some(absolute) = self.fs().absolute_path(dirfd, path) else {
            return err(errno::ENOENT);
        };
        let ns = self.fs().to_ns(&absolute);
        let (m, _) = self.fs().mount_of(&absolute);
        let cloexec = if flags & fcntl::O_CLOEXEC != 0 { libc::O_CLOEXEC } else { 0 };
        // SAFETY: a constant NUL-terminated path.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | cloexec) };
        if fd < 0 {
            return last_error();
        }
        crate::fdmarks::opened(fd, ns, m.id, m.flags, m.fstype, None);
        crate::fdmarks::mark(fd, crate::fdmarks::Mark::ProcLink);
        fd as i64
    }

    /// The guest path of the `/proc` link `fd` names, if it is a descriptor
    /// of one ([`Self::open_proc_link`]).
    fn proc_link_path(&self, fd: i32) -> Option<Vec<u8>> {
        crate::fdmarks::proc_link(fd).and_then(|ns| self.fs().from_ns(&ns))
    }

    pub(crate) fn sys_fstat(&self, fd: u64, buf: u64) -> i64 {
        if let Some(link) = self.proc_link_path(fd as i32) {
            return match self.linux_stat(fcntl::AT_FDCWD as i32, &link, false, 0) {
                Ok(st) => {
                    guest!(uaccess::write(buf, st));
                    0
                }
                Err(e) => err(e),
            };
        }
        if let Some(n) = crate::nsfd::of(fd as i32) {
            guest!(uaccess::write(buf, ns_stat(n.id)));
            return 0;
        }
        if let Some(t) = crate::pidfd::of(fd as i32) {
            guest!(uaccess::write(buf, pidfd_stat(t.host)));
            return 0;
        }
        // A synthetic file: what its path is.
        if let Some(path) = crate::procfile::path_of(fd as i32) {
            return match self.linux_stat(fcntl::AT_FDCWD as i32, &path, true, 0) {
                Ok(st) => {
                    guest!(uaccess::write(buf, st));
                    0
                }
                Err(e) => err(e),
            };
        }
        if crate::synthdir::fstat_is_dir(fd as i32) {
            let path = crate::synthdir::path_of(fd as i32);
            let mut stat =
                self.synth_dir_stat(fcntl::AT_FDCWD as i32, path.as_deref().unwrap_or(b""));
            // A process's directory is its user's (newuidmap checks so).
            if let Some(path) = path {
                stat = self.proc_owned(fcntl::AT_FDCWD as i32, &path, stat);
            }
            guest!(uaccess::write(buf, stat));
            return 0;
        }
        let (out, stored) = match stat_fd_of(fd as i32) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let node =
            crate::devnodes::marked(&out).then(|| crate::devnodes::node_of(fd as i32)).flatten();
        let mut st = as_node(stat_to_linux_fd(fd as i32, &out, stored), node);
        if let Some((mode, uid, gid)) = crate::mqueue::owner_of(fd as i32) {
            // A message queue's descriptor: the queue's owner and mode.
            (st.st_mode, st.st_uid, st.st_gid) = (fwe_abi::stat::S_IFREG | mode, uid, gid);
        }
        guest!(uaccess::write(buf, st));
        0
    }

    pub(crate) fn sys_statx(&self, dirfd: u64, path: u64, flags: u64, mask: u64, buf: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        // Linux's checks of the request: the reserved mask bit, both sync
        // types at once, an unknown flag.
        const STATX_RESERVED: u64 = 0x8000_0000;
        const AT_STATX_SYNC_TYPE: u64 = 0x6000;
        let known = fcntl::AT_SYMLINK_NOFOLLOW
            | fcntl::AT_NO_AUTOMOUNT
            | fcntl::AT_EMPTY_PATH
            | AT_STATX_SYNC_TYPE;
        if mask & STATX_RESERVED != 0
            || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE
            || flags & !known != 0
        {
            return err(errno::EINVAL);
        }
        let empty = path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0;
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        // The mount it is in, if asked for: its id, or its unique id, as
        // Linux reports one or the other.
        use fwe_abi::statx_mask::{STATX_MNT_ID, STATX_MNT_ID_UNIQUE};
        let wants_mount = mask as u32 & (STATX_MNT_ID | STATX_MNT_ID_UNIQUE) != 0;
        let mount =
            wants_mount.then(|| self.statx_mount(dirfd as i32, &path, empty, follow)).flatten();
        let with_mount = |mut x: Statx| {
            if let Some(m) = &mount {
                if mask as u32 & STATX_MNT_ID_UNIQUE != 0 {
                    x.stx_mnt_id = m.unique_id();
                    x.stx_mask |= STATX_MNT_ID_UNIQUE;
                } else {
                    x.stx_mnt_id = u64::from(m.id);
                    x.stx_mask |= STATX_MNT_ID;
                }
            }
            x
        };
        if empty && let Some(n) = crate::nsfd::of(dirfd as i32) {
            guest!(uaccess::write(buf, with_mount(statx_of(&ns_stat(n.id)))));
            return 0;
        }
        if empty && let Some(t) = crate::pidfd::of(dirfd as i32) {
            guest!(uaccess::write(buf, with_mount(statx_of(&pidfd_stat(t.host)))));
            return 0;
        }
        let (host, node) = if empty {
            // A synthetic file's descriptor: what its path is.
            if let Some(path) = crate::procfile::path_of(dirfd as i32) {
                return match self.linux_stat(fcntl::AT_FDCWD as i32, &path, true, 0) {
                    Ok(st) => {
                        guest!(uaccess::write(buf, with_mount(statx_of(&st))));
                        0
                    }
                    Err(e) => err(e),
                };
            }
            // A synthetic directory's descriptor, as `fstat` reports it.
            if crate::synthdir::fstat_is_dir(dirfd as i32) {
                let path = crate::synthdir::path_of(dirfd as i32).unwrap_or_default();
                let stat = self.synth_dir_stat(fcntl::AT_FDCWD as i32, &path);
                let x = with_mount(statx_of(&stat));
                guest!(uaccess::write(buf, x));
                return 0;
            }
            let out = match stat_fd(dirfd as i32) {
                Ok(s) => s,
                Err(e) => return err(e),
            };
            let node = crate::devnodes::marked(&out)
                .then(|| crate::devnodes::node_of(dirfd as i32))
                .flatten();
            (out, node)
        } else {
            return match self.linux_stat_attrs(dirfd as i32, &path, follow, 0) {
                Ok((st, extra)) => {
                    let mut x = statx_of(&st);
                    x.stx_attributes = extra.attrs;
                    if let Some(b) = extra.btime {
                        x.stx_btime = b;
                        x.stx_mask |= statx_mask::STATX_BTIME;
                    }
                    if self.mount_root(dirfd as i32, &path, false) {
                        x.stx_attributes |= STATX_ATTR_MOUNT_ROOT;
                    }
                    x.stx_attributes_mask = STATX_ATTRS_KNOWN;
                    guest!(uaccess::write(buf, with_mount(x)));
                    0
                }
                Err(e) => err(e),
            };
        };
        let mut x = statx_from(&host);
        x.stx_attributes = statx_attributes(&host, crate::modes::nodump_fd(dirfd as i32, &host));
        if self.mount_root(dirfd as i32, &path, true) {
            x.stx_attributes |= STATX_ATTR_MOUNT_ROOT;
        }
        if let Some(m) = tmpfs_of(dirfd as i32, &host) {
            let mut st = stat_to_linux(&host);
            on_tmpfs(&mut st, m);
            x.stx_dev_major = crate::devnodes::major(st.st_dev);
            x.stx_dev_minor = crate::devnodes::minor(st.st_dev);
            x.stx_blksize = st.st_blksize as u32;
        }
        if let Some((mode, uid, gid)) = crate::mqueue::owner_of(dirfd as i32) {
            x.stx_mode = (fwe_abi::stat::S_IFREG | mode) as u16;
            (x.stx_uid, x.stx_gid) = (uid, gid);
        }
        if let Some(n) = node {
            x.stx_mode = (n.kind | (x.stx_mode as u32 & 0o7777)) as u16;
            x.stx_rdev_major = n.major;
            x.stx_rdev_minor = n.minor;
            x.stx_size = 0;
        }
        guest!(uaccess::write(buf, with_mount(x)));
        0
    }

    /// Whether what `path` from `dirfd` names (`dirfd` itself, `empty`)
    /// is the root of a mount, by where it is in the namespace.
    fn mount_root(&self, dirfd: i32, path: &[u8], empty: bool) -> bool {
        let fs = self.fs();
        let ns = if empty {
            fs.fd_ns_path(dirfd)
        } else {
            fs.absolute_path(dirfd, path).map(|a| fs.to_ns(&a))
        };
        ns.is_some_and(|ns| fs.mount_ns().table().locate(&ns).0.point == ns)
    }

    /// The mount `path` from `dirfd` (or with `empty`, the file `dirfd` is
    /// open on) is in, if fwe can place it.
    fn statx_mount(
        &self,
        dirfd: i32,
        path: &[u8],
        empty: bool,
        follow: bool,
    ) -> Option<crate::mounts::Mount> {
        let fs = self.fs();
        let table = fs.mount_ns().table();
        // A path's own mount: the one at it, for a mount point.
        let ns = if empty {
            fs.fd_ns_path(dirfd)?
        } else if let Some(ns) = fs.resolve(dirfd, path, follow).ok().and_then(|r| r.ns_path) {
            ns
        } else {
            fs.to_ns(&fs.absolute_path(dirfd, path)?)
        };
        Some(table.locate(&ns).0.clone())
    }

    /// What absolute path `abs` names, as a walk sees it: a link and its
    /// target, or no link (`ENOENT` if nothing is there).
    pub(crate) fn link_kind(&self, abs: &[u8]) -> Result<LinkKind, i32> {
        use crate::procfs::Entry;
        let cwd = fcntl::AT_FDCWD as i32;
        if let Some(e) = self.fs().synthetic(cwd, abs) {
            return match e {
                Entry::Symlink(_) if magic_link(abs) => Ok(LinkKind::Magic),
                Entry::Symlink(t) => Ok(LinkKind::Symlink(t)),
                Entry::Fd { .. } => Ok(LinkKind::Magic),
                Entry::Missing => Err(errno::ENOENT),
                Entry::File(_) | Entry::Dir | Entry::Ns(_) => Ok(LinkKind::None),
            };
        }
        let st = self.linux_stat(cwd, abs, false, 0)?;
        if st.st_mode & fwe_abi::stat::S_IFMT != fwe_abi::stat::S_IFLNK {
            return Ok(LinkKind::None);
        }
        let r = self.fs().resolve(cwd, abs, false)?;
        Ok(LinkKind::Symlink(r.readlink()?))
    }

    /// Whether the caller may follow the symbolic link at `abs` as the
    /// last name of a path, as the ordinary walk asks
    /// (`fs.protected_symlinks`, `EACCES`).
    pub(crate) fn may_follow_trailing(&self, abs: &[u8]) -> Result<(), i32> {
        if !crate::sysctl::protected_links().0 {
            return Ok(());
        }
        let r = self.fs().resolve(fcntl::AT_FDCWD as i32, abs, false)?;
        if let Some(d) = &r.store {
            let Ok((_, link)) = d.find(&r.name) else { return Ok(()) };
            return crate::fs::may_follow_in_store(d, &link, self.creds.fsuid);
        }
        let name = r.name_c()?;
        crate::fs::may_follow(r.dir.as_raw_fd(), &name, r.dir.as_raw_fd(), self.creds.fsuid)
    }

    pub(crate) fn sys_readlinkat(&self, dirfd: u64, path: u64, buf: u64, size: u64) -> i64 {
        // A buffer of no size, first (an `int` to Linux).
        if size as i32 <= 0 {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty()
            && let Some(link) = self.proc_link_path(dirfd as i32)
        {
            // A link of fwe's `/proc`: what it says now.
            return match self.fs().synthetic(fcntl::AT_FDCWD as i32, &link) {
                Some(
                    crate::procfs::Entry::Symlink(target) | crate::procfs::Entry::Fd { target, .. },
                ) => {
                    let n = target.len().min(size as usize);
                    guest!(uaccess::write_from(buf, &target[..n]));
                    n as i64
                }
                _ => err(errno::ENOENT),
            };
        }
        if path.is_empty()
            && let Some(file) = crate::filestore::desc::of(dirfd as i32)
        {
            // A link of fwe's store an O_PATH | O_NOFOLLOW descriptor names.
            let target = file.fs().and_then(|fs| fs.lock()?.readlink(file.ino));
            return match target {
                Ok(t) => {
                    let n = t.len().min(size as usize);
                    guest!(uaccess::write_from(buf, &t[..n]));
                    n as i64
                }
                Err(errno::EINVAL) => err(errno::ENOENT),
                Err(e) => err(e),
            };
        }
        if path.is_empty() {
            // The symbolic link an O_PATH | O_NOFOLLOW descriptor names (a
            // stand-in); any other descriptor has no link to read.
            let Some(host) = crate::fdmarks::stand_in(dirfd as i32) else {
                return err(errno::ENOENT);
            };
            let Ok(c) = CString::new(host) else { return err(errno::ENOENT) };
            let mut target = vec![0u8; uaccess::PATH_MAX];
            // SAFETY: a NUL-terminated path and a buffer of its length.
            let n = unsafe { libc::readlink(c.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
            if n < 0 {
                return last_error();
            }
            let n = (n as usize).min(size as usize);
            guest!(uaccess::write_from(buf, &target[..n]));
            return n as i64;
        }
        if let Some(e) = self.proc_refused(dirfd as i32, &path) {
            return err(e);
        }
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            return match entry {
                crate::procfs::Entry::Symlink(target) | crate::procfs::Entry::Fd { target, .. } => {
                    let n = target.len().min(size as usize);
                    guest!(uaccess::write_from(buf, &target[..n]));
                    n as i64
                }
                crate::procfs::Entry::File(_)
                | crate::procfs::Entry::Dir
                | crate::procfs::Entry::Ns(_) => err(errno::EINVAL),
                crate::procfs::Entry::Missing => err(errno::ENOENT),
            };
        }
        let r = match self.fs().resolve(dirfd as i32, &path, false) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // A link of fwe's store (a tmpfs's).
        if let Some(d) = &r.store {
            return match Self::store_readlink(&r, d) {
                Ok(t) => {
                    let n = t.len().min(size as usize);
                    guest!(uaccess::write_from(buf, &t[..n]));
                    n as i64
                }
                Err(e) => err(e),
            };
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let dir = r.dir;
        // SAFETY: the guest passed a buffer of `size` bytes; `name` NUL-terminated.
        ret(unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                name.as_ptr(),
                buf as *mut libc::c_char,
                size as usize,
            )
        } as i64)
    }

    pub(crate) fn sys_getcwd(&self, buf: u64, size: u64) -> i64 {
        // Outside the root (a `chroot` left it there): unreachable from it.
        let outside = self.fs().cwd_outside().map(|p| [&b"(unreachable)"[..], p].concat());
        let cwd = outside.as_deref().unwrap_or(self.fs().cwd());
        let need = cwd.len() + 1;
        if (size as usize) < need {
            return err(errno::ERANGE);
        }
        let mut out = cwd.to_vec();
        out.push(0);
        guest!(uaccess::write_from(buf, &out));
        need as i64
    }

    pub(crate) fn sys_chdir(&mut self, path: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        // The directory itself must be searchable by the caller.
        if let Ok(r) = self.fs().resolve(fcntl::AT_FDCWD as i32, &path, true)
            && let Ok(st) = resolved_guest_stat(&r)
            && st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && !self.permits(&st, 1)
        {
            return err(errno::EACCES);
        }
        let fs = self.fs_mut();
        match fs.chdir(fcntl::AT_FDCWD as i32, &path) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_fchdir(&mut self, fd: u64) -> i64 {
        // (A file of fwe's store that is no directory.)
        if crate::filestore::io::stat(fd as i32)
            .is_some_and(|st| st.is_ok_and(|st| st.st_mode & libc::S_IFMT != libc::S_IFDIR))
        {
            return err(errno::ENOTDIR);
        }
        if let Ok(st) = stat_fd(fd as i32)
            && st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && !self.permits(&st, 1)
        {
            return err(errno::EACCES);
        }
        let fs = self.fs_mut();
        match fs.fchdir(fd as i32) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_mkdirat(&mut self, dirfd: u64, path: u64, mode: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if let Some(entry) = self.fs().synthetic(dirfd as i32, &path) {
            // Nothing is made in fwe's own filesystems: what is there exists,
            // and proc has no room for more (sysfs refuses outright).
            let sysfs = self
                .fs()
                .absolute_path(dirfd as i32, &path)
                .is_some_and(|a| self.fs().mount_of(&a).0.fstype == crate::mounts::FsType::Sysfs);
            return err(match entry {
                crate::procfs::Entry::Missing if sysfs => errno::EPERM,
                crate::procfs::Entry::Missing => errno::ENOENT,
                _ => errno::EEXIST,
            });
        }
        // The name made, never followed (a trailing slash asks for the
        // directory this makes).
        let mut r = match self.fs().resolve_entry(dirfd as i32, &path) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // In fwe's store (a tmpfs).
        if let Some(d) = r.store.clone() {
            return self.store_mkdir(&r, &d, mode as u32);
        }
        if let Err(e) = r.writable() {
            return err(e);
        }
        if r.mount_root {
            return err(errno::EEXIST);
        }
        if let Err(e) = r.prepare(Change::Create) {
            return err(e);
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        // The permission and sticky bits, as Linux's `mkdir` takes: a
        // directory is set-group-ID only as one in a set-group-ID directory
        // ([`Self::own_new`]), and never set-user-ID.
        let mode = self.fs().apply_umask(mode as u32) & 0o1777;
        let host_mode = crate::modes::host_perm(mode, true);
        let dir = r.dir.as_raw_fd();
        // A new cgroup, within the limits of those above it, made whole
        // under the hierarchy's lock (no removal of its parent between).
        let _cgroups = if r.fstype == crate::mounts::FsType::Cgroup2 {
            match crate::cgroupfs::lock_tree() {
                Ok(l) => Some(l),
                Err(e) => return err(e),
            }
        } else {
            None
        };
        if r.fstype == crate::mounts::FsType::Cgroup2
            && stat_at(dir, &name).is_err()
            && let Some(parent) = crate::fs::host_path_in(dir, b".")
            && let Err(e) = crate::cgroupfs::may_make(&parent)
        {
            return err(e);
        }
        let made = self.change_in(dir, || {
            // SAFETY: `name` NUL-terminated; `dir` live.
            ret(unsafe { libc::mkdirat(dir, name.as_ptr(), host_mode as libc::mode_t) })
        });
        if made == 0 && host_mode != mode & 0o7777 {
            let _ = crate::modes::keep_at(dir, &name, mode);
        }
        if made == 0 {
            self.own_new(dir, &name, None, true, mode, mode);
        }
        if let Err(e) = r.finish(made == 0)
            && made == 0
        {
            return err(e);
        }
        if made == 0 && r.fstype == crate::mounts::FsType::Cgroup2 {
            // A new cgroup, with its interface files.
            if let Some(host) = crate::fs::host_path_in(r.dir.as_raw_fd(), &r.name) {
                crate::cgroupfs::made(&host);
            }
        }
        made
    }

    /// `mknodat(dirfd, path, mode, dev)`: a regular file, a FIFO, or a
    /// device node of fwe's ([`crate::devnodes`]).
    pub(crate) fn sys_mknodat(&mut self, dirfd: u64, path: u64, mode: u64, dev: u64) -> i64 {
        use crate::devnodes::{Node, S_IFBLK, S_IFCHR};
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let kind = mode as u32 & 0o170000;
        let asked = mode as u32 & 0o7777;
        let perm = self.fs().apply_umask(asked);
        let mut r = match self.resolve_p(dirfd, &path, false, false, Change::Create) {
            Ok(r) => r,
            Err(errno::EBUSY) => return err(errno::EEXIST),
            Err(e) => return err(e),
        };
        if let Err(e) = made_not_dir(&r, &path) {
            return err(e);
        }
        // In fwe's store (a tmpfs).
        if let Some(sd) = r.store.clone() {
            let kind = if kind == 0 { 0o100000 } else { kind };
            if !matches!(kind, 0o100000 | 0o010000 | S_IFCHR | S_IFBLK | 0o140000) {
                return err(errno::EINVAL);
            }
            return self.store_mknod(&r, &sd, kind, asked, dev);
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let d = r.dir.as_raw_fd();
        let host_perm = crate::modes::host_perm(perm, false);
        let made = match kind {
            0 | 0o100000 => self.change_in(d, || {
                // SAFETY: a NUL-terminated name; `dir` live.
                let fd = unsafe {
                    libc::openat(
                        d,
                        name.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                        host_perm as libc::c_uint,
                    )
                };
                if fd < 0 {
                    return last_error();
                }
                // SAFETY: closing the descriptor just made.
                unsafe { libc::close(fd) };
                0
            }),
            0o010000 => self.change_in(d, || {
                // SAFETY: a NUL-terminated name; `dir` live.
                ret(unsafe { libc::mkfifoat(d, name.as_ptr(), host_perm as libc::mode_t) })
            }),
            S_IFCHR | S_IFBLK => {
                // The directory's permission first, as Linux checks it.
                if stat_fd(d).is_ok_and(|st| !self.permits(&st, 2 | 1)) {
                    return err(errno::EACCES);
                }
                let node = Node {
                    kind,
                    major: crate::devnodes::major(dev),
                    minor: crate::devnodes::minor(dev),
                };
                // A whiteout (a 0:0 character device) needs no CAP_MKNOD,
                // as on Linux since 5.8: rootless overlay storage makes one.
                let whiteout = kind == S_IFCHR && node.major == 0 && node.minor == 0;
                if !whiteout && !self.creds.has(crate::caps::CAP_MKNOD) {
                    return err(errno::EPERM);
                }
                if r.ovl.is_some() && kind == S_IFCHR && node.major == 0 && node.minor == 0 {
                    // A whiteout is the overlay's own, as on Linux.
                    return err(errno::EPERM);
                }
                if let Err(e) = crate::cgroupfs::check_device(
                    crate::bpf::BPF_DEVCG_ACC_MKNOD,
                    node.bpf_type(),
                    node.major,
                    node.minor,
                ) {
                    return err(e);
                }
                self.change_in(d, || match crate::devnodes::make(d, &name, node, host_perm) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                })
            }
            // A socket node, as binding a socket there leaves one.
            0o140000 => {
                self.change_in(d, || match crate::net::make_socket_node(d, &name, host_perm) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                })
            }
            _ => return err(errno::EINVAL),
        };
        if made == 0 && host_perm != perm {
            let _ = crate::modes::keep_at(d, &name, perm);
        }
        if made == 0 {
            self.own_new(d, &name, None, false, perm, asked);
        }
        match r.finish(made == 0) {
            Err(e) if made == 0 => err(e),
            _ => made,
        }
    }

    pub(crate) fn sys_unlinkat(&mut self, dirfd: u64, path: u64, flags: u64) -> i64 {
        if flags & !fcntl::AT_REMOVEDIR != 0 {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        self.unlink_path(dirfd, path, flags)
    }

    /// `unlinkat` of guest path `path`.
    pub(crate) fn unlink_path(&mut self, dirfd: u64, path: Vec<u8>, flags: u64) -> i64 {
        let found = self.fs().resolve_entry(dirfd as i32, &path);
        if let Ok(r) = &found
            && r.fstype == crate::mounts::FsType::Cgroup2
        {
            // A cgroup goes with its files when empty; its files stay.
            let Some(host) = crate::fs::host_path_in(r.dir.as_raw_fd(), &r.name) else {
                return err(errno::ENOENT);
            };
            if flags & fcntl::AT_REMOVEDIR == 0 {
                return err(errno::EPERM);
            }
            return match crate::cgroupfs::remove(&host) {
                Ok(()) => 0,
                Err(e) => err(e),
            };
        }
        let r = match found.and_then(|r| Self::changeable(r, false, Change::Remove)) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        if let Err(e) = removed_dir_only(&r, crate::fs::trailing_slash(&path)) {
            return err(e);
        }
        // In fwe's store (a tmpfs).
        if let Some(d) = r.store.clone() {
            return self.store_unlink(&r, &d, flags & fcntl::AT_REMOVEDIR != 0);
        }
        if let Some(o) = &r.ovl {
            if let Err(e) = self.may_remove_in_overlay(o, &r.name) {
                return err(e);
            }
            // The directory copied up, then the name removed from the
            // upper layer, or covered there.
            let up = match crate::overlay::upper_dir(&o.layers, &o.parent) {
                Ok(up) => up,
                Err(e) => return err(e),
            };
            let rmdir = flags & fcntl::AT_REMOVEDIR != 0;
            return self.change_in(up.as_raw_fd(), || {
                match crate::overlay::remove(&o.layers, &o.parent, &r.name, rmdir) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            });
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let dir = r.dir;
        let host_flags = if flags & fcntl::AT_REMOVEDIR != 0 { libc::AT_REMOVEDIR } else { 0 };
        let d = dir.as_raw_fd();
        if let Err(e) = self.may_remove(d, &name) {
            return err(e);
        }
        // SAFETY: `name` NUL-terminated; `dir` live.
        let r = self.change_in(d, || ret(unsafe { libc::unlinkat(d, name.as_ptr(), host_flags) }));
        // A directory holding nothing but `O_TMPFILE` files is empty to
        // Linux, whose have no names: their hidden ones go, and it goes.
        let r = if r == err(errno::ENOTEMPTY) && crate::tmpfile::clear_hidden(d, &name) {
            // SAFETY: as above.
            self.change_in(d, || ret(unsafe { libc::unlinkat(d, name.as_ptr(), host_flags) }))
        } else {
            r
        };
        if r == err(errno::EPERM) && host_flags == 0 {
            // macOS refuses to unlink a directory with EPERM; Linux says
            // what it is.
            let mut st = zeroed_stat();
            // SAFETY: `name` NUL-terminated; `dir` live; `st` an out-parameter.
            let r = unsafe {
                libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
            };
            if r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return err(errno::EISDIR);
            }
        }
        r
    }

    pub(crate) fn sys_symlinkat(&mut self, target: u64, dirfd: u64, path: u64) -> i64 {
        let target = guest!(uaccess::read_cstr(target, uaccess::PATH_MAX));
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let target = match CString::new(target) {
            Ok(t) => t,
            Err(_) => return err(errno::EINVAL),
        };
        let mut r = match self.resolve_p(dirfd, &path, false, false, Change::Create) {
            Ok(r) => r,
            Err(errno::EBUSY) => return err(errno::EEXIST),
            Err(e) => return err(e),
        };
        if let Err(e) = made_not_dir(&r, &path) {
            return err(e);
        }
        // In fwe's store (a tmpfs).
        if let Some(d) = r.store.clone() {
            return self.store_symlink(&r, &d, target.as_bytes());
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let d = r.dir.as_raw_fd();
        let made = self.change_in(d, || {
            // SAFETY: both strings NUL-terminated; `dir` live.
            ret(unsafe { libc::symlinkat(target.as_ptr(), d, name.as_ptr()) })
        });
        if made == 0 {
            self.own_new(d, &name, None, false, 0o777, 0o777);
        }
        match r.finish(made == 0) {
            Err(e) if made == 0 => err(e),
            _ => made,
        }
    }

    pub(crate) fn sys_linkat(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
    ) -> i64 {
        if flags & !(fcntl::AT_SYMLINK_FOLLOW | fcntl::AT_EMPTY_PATH) != 0 {
            return err(errno::EINVAL);
        }
        let oldpath = guest!(uaccess::read_cstr(oldpath, uaccess::PATH_MAX));
        let newpath = guest!(uaccess::read_cstr(newpath, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_FOLLOW != 0;
        // A file fwe makes up (under `/proc` or `/sys`) is on another
        // filesystem than anything it could be linked into.
        if !oldpath.is_empty()
            && matches!(
                self.fs().synthetic(olddirfd as i32, &oldpath),
                Some(crate::procfs::Entry::File(_) | crate::procfs::Entry::Dir)
            )
        {
            return err(errno::EXDEV);
        }
        if oldpath.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            // A name for the descriptor's own file (an O_TMPFILE one, say).
            return self.link_fd(olddirfd as i32, newdirfd, &newpath);
        }
        let old = match self.fs().resolve(olddirfd as i32, &oldpath, follow) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let new = match self.fs().resolve_entry(newdirfd as i32, &newpath) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        if let Err(e) = made_not_dir(&new, &newpath) {
            return err(e);
        }
        if old.mount_id != new.mount_id && old.mount_id != 0 && new.mount_id != 0 {
            // Across mounts, even of one filesystem.
            return err(errno::EXDEV);
        }
        // In fwe's store (a tmpfs): both, or not one filesystem.
        if old.store.is_some() || new.store.is_some() {
            let (Some(od), Some(nd)) = (&old.store, &new.store) else { return err(errno::EXDEV) };
            let ino = match od.find(&old.name) {
                Ok((ino, _)) => ino,
                Err(e) => return err(e),
            };
            if new.mount_root {
                return err(errno::EEXIST);
            }
            return self.store_link(od.fs.id, ino, &new, nd, false);
        }
        if crate::sysctl::protected_links().1
            && let Err(e) = self.may_hardlink(&old)
        {
            return err(e);
        }
        let (mut old, mut new) = (old, new);
        if let Err(e) = old.prepare(Change::Modify) {
            return err(e);
        }
        if new.mount_root {
            return err(errno::EEXIST);
        }
        if let Err(e) = new.prepare(Change::Create) {
            return err(e);
        }
        let (Ok(on), Ok(nn)) = (old.name_c(), new.name_c()) else { return err(errno::EINVAL) };
        let (o, n) = (old.dir.as_raw_fd(), new.dir.as_raw_fd());
        // SAFETY: names NUL-terminated; dirs live. We resolved symlinks, so 0.
        let made =
            self.change_in(n, || ret(unsafe { libc::linkat(o, on.as_ptr(), n, nn.as_ptr(), 0) }));
        match new.finish(made == 0) {
            Err(e) if made == 0 => err(e),
            _ => made,
        }
    }

    /// Whether the caller may link to the file `old` names, with
    /// `fs.protected_hardlinks` on: its owner (or `CAP_FOWNER`), or one who
    /// may read and write it, a regular file that is not set-user-ID or
    /// set-group-ID and executable by its group (`EPERM`).
    fn may_hardlink(&self, old: &crate::fs::Resolved) -> Result<(), i32> {
        let name = old.name_c()?;
        self.may_hardlink_to(&stat_at(old.dir.as_raw_fd(), &name)?)
    }

    /// [`Self::may_hardlink`] for the file whose guest status is `st`.
    #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
    fn may_hardlink_to(&self, st: &libc::stat) -> Result<(), i32> {
        let c = &self.creds;
        if c.fsuid == st.st_uid || c.has_over(crate::caps::CAP_FOWNER, st.st_uid, st.st_gid) {
            return Ok(());
        }
        let mode = st.st_mode as u32;
        let safe = mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
            && mode & 0o4000 == 0
            && mode & 0o2010 != 0o2010;
        if safe && self.permits(st, 6) { Ok(()) } else { Err(errno::EPERM) }
    }

    pub(crate) fn sys_renameat2(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
    ) -> i64 {
        let old = guest!(uaccess::read_cstr(oldpath, uaccess::PATH_MAX));
        let new = guest!(uaccess::read_cstr(newpath, uaccess::PATH_MAX));
        // Where both are in the namespace's view, their directories'
        // links followed: the working directory is kept so too.
        let place = |dirfd: u64, p: &[u8]| self.fs().resolve(dirfd as i32, p, false).ok()?.ns_path;
        let from = place(olddirfd, &old);
        let to = place(newdirfd, &new);
        let r = self.rename_paths(olddirfd, old, newdirfd, new, flags);
        // The working directory is a directory, wherever it moves: one
        // renamed with it is where it went (`RENAME_EXCHANGE`: each where
        // the other was).
        if r == 0
            && let (Some(from), Some(to)) = (from, to)
        {
            let cwd = self.fs().to_ns(self.fs().cwd());
            let moved = |a: &[u8], b: &[u8]| {
                crate::mounts::under(&cwd, a).map(|rest| crate::mounts::join(b, rest))
            };
            let now = moved(&from, &to)
                .or_else(|| (flags & RENAME_EXCHANGE != 0).then(|| moved(&to, &from)).flatten());
            if let Some(now) = now.and_then(|ns| self.fs().from_ns(&ns)) {
                let fs = self.fs_mut();
                let root = fs.proc_root().to_vec();
                fs.set_root(root, now);
            }
        }
        r
    }

    /// [`sys_renameat2`](Self::sys_renameat2) of paths read.
    fn rename_paths(
        &mut self,
        olddirfd: u64,
        oldpath: Vec<u8>,
        newdirfd: u64,
        newpath: Vec<u8>,
        flags: u64,
    ) -> i64 {
        let how = match rename_mode(flags) {
            Ok(how) => how,
            Err(e) => return err(e),
        };
        if flags & RENAME_WHITEOUT != 0 && !self.creds.has(crate::caps::CAP_MKNOD) {
            return err(errno::EPERM);
        }
        let old = match self.resolve_p(olddirfd, &oldpath, false, false, Change::Remove) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let new = match self.resolve_p(newdirfd, &newpath, false, false, Change::Remove) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // A trailing slash on either asks for a directory to move.
        let slash = crate::fs::trailing_slash(&oldpath) || crate::fs::trailing_slash(&newpath);
        if let Err(e) = removed_dir_only(&old, slash) {
            return err(e);
        }
        if old.mount_id != new.mount_id && old.mount_id != 0 && new.mount_id != 0 {
            // Across mounts, even of one filesystem.
            return err(errno::EXDEV);
        }
        if old.ovl.is_some() != new.ovl.is_some() {
            // One in an overlay, the other not (a directory fwe cannot
            // place): not one filesystem.
            return err(errno::EXDEV);
        }
        // In fwe's store (a tmpfs): both, or not one filesystem.
        if old.store.is_some() || new.store.is_some() {
            let (Some(od), Some(nd)) = (&old.store, &new.store) else { return err(errno::EXDEV) };
            return self.store_rename(&old, od, &new, nd, flags);
        }
        if let (Some(a), Some(b)) = (&old.ovl, &new.ovl) {
            if flags & RENAME_WHITEOUT != 0 {
                return err(errno::EINVAL);
            }
            if let Err(e) = self
                .may_remove_in_overlay(a, &old.name)
                .and_then(|()| self.may_remove_in_overlay(b, &new.name))
            {
                return err(e);
            }
            let up = |o: &crate::fs::Ovl| crate::overlay::upper_dir(&o.layers, &o.parent);
            let (ua, ub) = match (up(a), up(b)) {
                (Ok(x), Ok(y)) => (x, y),
                (Err(e), _) | (_, Err(e)) => return err(e),
            };
            return self.change_in(ua.as_raw_fd(), || {
                self.change_in(ub.as_raw_fd(), || {
                    let from = (&a.parent[..], &old.name[..]);
                    let to = (&b.parent[..], &new.name[..]);
                    match crate::overlay::rename(&a.layers, from, to, how) {
                        Ok(()) => 0,
                        Err(e) => err(e),
                    }
                })
            });
        }
        let (Ok(on), Ok(nn)) = (old.name_c(), new.name_c()) else { return err(errno::EINVAL) };
        let (o, n) = (old.dir.as_raw_fd(), new.dir.as_raw_fd());
        if let Err(e) = self.may_remove(o, &on).and_then(|()| self.may_remove(n, &nn)) {
            return err(e);
        }
        self.change_in(o, || {
            self.change_in(n, || match rename(o, &on, n, &nn, how, flags & RENAME_WHITEOUT != 0) {
                Ok(()) => 0,
                Err(e) => err(e),
            })
        })
    }

    /// `fchmodat2(dirfd, path, mode, flags)`: `fchmodat` with flags,
    /// `AT_SYMLINK_NOFOLLOW` (a link's mode cannot change: `EOPNOTSUPP`) and
    /// `AT_EMPTY_PATH` (the descriptor's own file).
    pub(crate) fn sys_fchmodat2(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        if flags & !(fcntl::AT_SYMLINK_NOFOLLOW | fcntl::AT_EMPTY_PATH) != 0 {
            return err(errno::EINVAL);
        }
        if flags & fcntl::AT_EMPTY_PATH != 0 {
            let p = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
            if p.is_empty() {
                return self.sys_fchmod(dirfd, mode);
            }
        }
        self.sys_fchmodat(dirfd, path, mode, flags)
    }

    pub(crate) fn sys_fchmodat(&mut self, dirfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            return self.sys_fchmod(fd as u64, mode);
        }
        let r = match self.resolve_p(dirfd, &path, follow, true, Change::Modify) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            let (ino, st) = match d.find(&r.name).and_then(|(i, _)| Ok((i, d.host_stat(i)?))) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return err(errno::EOPNOTSUPP);
            }
            return match self.chmod_to(&st, mode as u32) {
                Ok(m) => crate::filestore::io::chmod_file(
                    crate::filestore::desc::File { fs: d.fs.id, ino },
                    m,
                ),
                Err(e) => err(e),
            };
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let dir = r.dir;
        if !follow {
            // A symbolic link's mode cannot be changed on Linux.
            let mut st = zeroed_stat();
            // SAFETY: `name` NUL-terminated; `dir` live; `st` an out-parameter.
            let r = unsafe {
                libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
            };
            if r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return err(errno::EOPNOTSUPP);
            }
        }
        let mode =
            match stat_at(dir.as_raw_fd(), &name).and_then(|st| self.chmod_to(&st, mode as u32)) {
                Ok(m) => m,
                Err(e) => return err(e),
            };
        match crate::modes::keep_at(dir.as_raw_fd(), &name, mode) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_fchownat(
        &mut self,
        dirfd: u64,
        path: u64,
        uid: u64,
        gid: u64,
        flags: u64,
    ) -> i64 {
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 {
            // The descriptor's own file.
            return self.sys_fchown(dirfd, uid, gid);
        }
        if flags & !(fcntl::AT_SYMLINK_NOFOLLOW | fcntl::AT_EMPTY_PATH) != 0 {
            return err(errno::EINVAL);
        }
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            return self.sys_fchown(fd as u64, uid, gid);
        }
        // A file of an overlay is copied up, as a change of owner does.
        let r = match self.resolve_p(dirfd, &path, follow, true, Change::Modify) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            let (ino, st) = match d.find(&r.name).and_then(|(i, _)| Ok((i, d.host_stat(i)?))) {
                Ok(v) => v,
                Err(e) => return err(e),
            };
            return match self.chown_to(&st, uid as u32, gid as u32) {
                Ok((owner, mode)) => crate::filestore::io::chown_file(
                    crate::filestore::desc::File { fs: d.fs.id, ino },
                    owner,
                    mode,
                ),
                Err(e) => err(e),
            };
        }
        let name = match r.name_c() {
            Ok(n) => n,
            Err(e) => return err(e),
        };
        let dir = r.dir.as_raw_fd();
        let st = match stat_at(dir, &name) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let (owner, mode) = match self.chown_to(&st, uid as u32, gid as u32) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if let Err(e) = crate::owners::keep_at(dir, &name, owner) {
            return err(e);
        }
        if let Some(m) = mode
            && let Err(e) = crate::modes::keep_at(dir, &name, m)
        {
            return err(e);
        }
        // A file not a directory loses its file capabilities, as Linux's
        // `chown` has it (`ATTR_KILL_PRIV`).
        if st.st_mode & libc::S_IFMT == libc::S_IFREG
            && let Some(d) = crate::fs::host_path_of(dir)
            && let Ok(host) = CString::new([&d[..], b"/", name.as_bytes()].concat())
        {
            crate::xattr::kill_file_caps(&crate::xattr::Target::Path(&host));
        }
        0
    }

    /// `truncate(path, len)`: Linux's checks in its order (a directory
    /// `EISDIR`, another file not regular `EINVAL`, a read-only mount
    /// `EROFS`, write permission `EACCES`, a running program `ETXTBSY`),
    /// leases broken, an overlay's file copied up; then the host's
    /// `truncate` of its path. The file is never opened: a close would
    /// drop the caller's record locks on it ([`crate::reclocks`]).
    pub(crate) fn sys_truncate(&mut self, path: u64, len: u64) -> i64 {
        if (len as i64) < 0 {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        let at = fcntl::AT_FDCWD as u64;
        match self.fs().synthetic(at as i32, &path) {
            // A link of `/proc/self/fd` to a file of fwe's store (a
            // memfd's): its own truncation, as its seals allow.
            Some(crate::procfs::Entry::Fd { fd, .. })
                if crate::filestore::desc::of(fd).is_some() =>
            {
                if let Err(e) = self.permitted_fd(fd, 2) {
                    return err(e);
                }
                return self.sys_ftruncate(fd as u64, len);
            }
            Some(crate::procfs::Entry::Fd { .. }) | None => {}
            // fwe's `/proc` and `/sys` files: as an open to write would.
            Some(_) => return self.truncate_by_open(&path, len),
        }
        let r = match self.fs().resolve(at as i32, &path, true) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        if r.fstype == crate::mounts::FsType::Cgroup2 {
            return self.truncate_by_open(&path, len);
        }
        let Some(st) = resolved_stat(&r) else { return err(errno::ENOENT) };
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => return err(errno::EISDIR),
            libc::S_IFREG if !crate::devnodes::marked(&st) => {}
            _ => return err(errno::EINVAL),
        }
        if let Err(e) = r.writable() {
            return err(e);
        }
        if !self.permits(&st, 2) {
            return err(errno::EACCES);
        }
        #[allow(clippy::unnecessary_cast)] // `st_dev` is narrower on macOS
        let dev = st.st_dev as u64;
        if crate::textbusy::is_running(dev, st.st_ino) {
            return err(errno::ETXTBSY);
        }
        if let Err(e) = crate::leases::break_for(dev, st.st_ino, true, false) {
            return err(e);
        }
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            #[allow(clippy::unnecessary_cast)] // `ino_t` differs by host
            let file = crate::filestore::desc::File { fs: d.fs.id, ino: st.st_ino as u64 };
            let r = crate::filestore::io::truncate_file(file, len).map_or_else(err, |()| 0);
            // A set-ID file cut by a caller without `CAP_FSETID` loses its
            // bits, as one written does.
            #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
            let perm = st.st_mode as u32 & 0o7777;
            let kept = crate::modes::written_perm(perm);
            if r == 0 && kept != perm && !self.creds.has(crate::caps::CAP_FSETID) {
                let _ = crate::filestore::io::chmod_file(file, kept);
            }
            return r;
        }
        let mut r = r;
        if let Err(e) = r.prepare(crate::fs::Change::Modify) {
            return err(e);
        }
        let Ok(name) = r.name_c() else { return err(errno::ENOENT) };
        let dir = r.dir.as_raw_fd();
        let cut = || {
            crate::host::at_path(dir, &name, |p| {
                // SAFETY: a NUL-terminated path, a regular file's.
                ret(unsafe { libc::truncate(p.as_ptr(), len as libc::off_t) })
            })
            .unwrap_or_else(err)
        };
        let r = match cut() {
            // A mode that denies its owner writing, which fwe let through:
            // kept apart, then again.
            r if r == err(errno::EACCES) => {
                match crate::host::at_path(dir, &name, crate::modes::own_path) {
                    Ok(Ok(())) => cut(),
                    _ => r,
                }
            }
            r => r,
        };
        // A set-ID file cut by a caller without `CAP_FSETID` loses its bits,
        // as one written does.
        let perm = crate::modes::perm_of(&st);
        let kept = crate::modes::written_perm(perm);
        if r == 0 && kept != perm && !self.creds.has(crate::caps::CAP_FSETID) {
            let _ = crate::modes::keep_at(dir, &name, kept);
        }
        r
    }

    /// `truncate` of a file of fwe's own (`/proc`, `/sys`, a cgroup's):
    /// opened to write as `openat` opens it, cut, and closed as the guest's
    /// `close` closes it.
    fn truncate_by_open(&mut self, path: &[u8], len: u64) -> i64 {
        let fd = self.open_with(fcntl::AT_FDCWD as u64, path.to_vec(), fcntl::O_WRONLY, 0);
        if fd < 0 {
            return fd;
        }
        let r = self.sys_ftruncate(fd as u64, len);
        let _ = self.syscall(fwe_abi::nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
        r
    }

    /// Whether the caller may do `want` to the file open as `fd`, by its
    /// guest metadata.
    fn permitted_fd(&self, fd: i32, want: u32) -> Result<(), i32> {
        let st = stat_fd(fd)?;
        if self.permits(&st, want) { Ok(()) } else { Err(errno::EACCES) }
    }

    pub(crate) fn sys_ftruncate(&mut self, fd: u64, len: u64) -> i64 {
        if let Some(r) = crate::loopdev::ftruncate(fd as i32) {
            return r;
        }
        if let Some(r) = crate::filestore::io::ftruncate(fd as i32, len as i64) {
            return r;
        }
        // Opened in a Landlock domain that let it not truncate the file,
        // whoever holds it now.
        if let Err(e) = crate::landlock::may_ftruncate(fd as i32) {
            return err(e);
        }
        // SAFETY: plain host call on a guest fd.
        let r = ret(unsafe { libc::ftruncate(fd as i32, len as libc::off_t) });
        // A truncation takes set-ID bits and file capabilities as a write.
        if r == 0 {
            crate::modes::wrote(fd as i32);
        }
        r
    }

    /// `fadvise64(fd, offset, len, advice)`: checked as Linux checks it;
    /// `POSIX_FADV_WILLNEED` starts the host reading the range ahead,
    /// `POSIX_FADV_DONTNEED` writes its changes back and drops its pages
    /// from the host's cache, and the rest only describe how the file will
    /// be used, which the host's cache works out for itself.
    pub(crate) fn sys_fadvise(&mut self, fd: u64, offset: u64, len: u64, advice: u64) -> i64 {
        use fwe_abi::fadvise::*;
        let fd = fd as i32;
        if crate::fdmarks::stand_in(fd).is_some() {
            return err(errno::EBADF);
        }
        let mut st = zeroed_stat();
        // SAFETY: plain host call with a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            return err(errno::EBADF);
        }
        if st.st_mode & libc::S_IFMT == libc::S_IFIFO {
            return err(errno::ESPIPE);
        }
        if advice > POSIX_FADV_NOREUSE || (len as i64) < 0 {
            return err(errno::EINVAL);
        }
        #[cfg(target_os = "macos")]
        if advice == POSIX_FADV_WILLNEED && st.st_mode & libc::S_IFMT == libc::S_IFREG {
            // Up to the end of the file when `len` is 0, as Linux reads.
            let count = if len == 0 { (st.st_size as u64).saturating_sub(offset) } else { len };
            let ra = libc::radvisory {
                ra_offset: offset as libc::off_t,
                ra_count: count.min(i32::MAX as u64) as libc::c_int,
            };
            // SAFETY: a valid advisory for a guest descriptor; advice only.
            unsafe { libc::fcntl(fd, libc::F_RDADVISE, &ra) };
        }
        #[cfg(target_os = "macos")]
        if advice == POSIX_FADV_DONTNEED && st.st_mode & libc::S_IFMT == libc::S_IFREG {
            drop_cached(fd, offset, len, st.st_size as u64);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = offset;
        0
    }

    pub(crate) fn sys_fallocate(&mut self, fd: u64, mode: u64, offset: u64, len: u64) -> i64 {
        if let Some(r) = crate::loopdev::fallocate(fd as i32, mode, offset, len) {
            return r;
        }
        if let Some(r) = crate::filestore::io::fallocate(fd as i32, mode, offset, len) {
            return r;
        }
        match crate::host::fallocate(fd as i32, mode, offset as i64, len as i64) {
            Ok(()) => {
                // A set-ID file changed loses its bits, as one written does.
                crate::modes::wrote(fd as i32);
                0
            }
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_umask(&mut self, mask: u64) -> i64 {
        let fs = self.fs_mut();
        fs.set_umask(mask as u32) as i64
    }

    pub(crate) fn sys_pipe2(&mut self, buf: u64, flags: u64) -> i64 {
        let mut fds = [0i32; 2];
        if let Err(e) = make_pipe(&mut fds, flags) {
            return err(e);
        }
        crate::exclusive::made(fds[0]);
        // Its ends, one pipe; its capacity, as the maker's privilege and
        // `pipe-max-size` allow.
        let id = |fd: i32| {
            // SAFETY: an all-zero `stat` is a valid out-parameter.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above, on the pipe just made.
            (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino))
        };
        if let (Some(read), Some(write)) = (id(fds[0]), id(fds[1])) {
            crate::fdstate::pipe_made(read, write);
            let privileged = self.creds.has(crate::caps::CAP_SYS_RESOURCE);
            let size = crate::fdstate::new_pipe_size(privileged, self.page_size);
            if size != crate::fdstate::default_pipe_size() {
                crate::fdstate::set_pipe_size(read, size);
            }
        }
        if uaccess::write(buf, fds).is_err() {
            // SAFETY: closing the pipe just made.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return err(errno::EFAULT);
        }
        0
    }

    pub(crate) fn sys_getdents64(&mut self, fd: u64, buf: u64, count: u64) -> i64 {
        // SAFETY: the guest passed a buffer of `count` bytes.
        if let Some(r) = unsafe { crate::synthdir::getdents64(fd as i32, buf, count) } {
            return r;
        }
        if let Some(r) = crate::filestore::io::getdents64(fd as i32, buf, count) {
            return r;
        }
        // Not a directory (`ENOTDIR`), or one removed since it was opened
        // (`ENOENT`), as Linux tells them.
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::fstat(fd as i32, &mut st) } == 0 {
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return err(errno::ENOTDIR);
            }
            // Removed: no links left, or its path names it no more.
            let gone = st.st_nlink == 0
                || crate::fs::fd_path(fd as i32).is_some_and(|p| {
                    let Ok(c) = std::ffi::CString::new(p) else { return false };
                    // SAFETY: an all-zero `stat` is a valid out-parameter.
                    let mut at: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: a NUL-terminated path and a valid out-parameter.
                    let r = unsafe { libc::lstat(c.as_ptr(), &mut at) };
                    r != 0 || (at.st_dev, at.st_ino) != (st.st_dev, st.st_ino)
                });
            if gone {
                return err(errno::ENOENT);
            }
        }
        if let Some(l) = crate::fdmarks::origin(fd as i32).and_then(|o| o.ovl) {
            // The overlay's directory: its layers' entries merged.
            return crate::overlay::getdents64(fd as i32, buf, count, || {
                let path = crate::overlay::path_of(&l, fd as i32).ok_or(errno::ENOENT)?;
                crate::overlay::list(&crate::overlay::open(&l, &path)?)
            });
        }
        getdents64(fd as i32, buf, count as usize, &listing_hides(fd as i32))
    }

    pub(crate) fn sys_utimensat(&mut self, dirfd: u64, path: u64, times: u64, flags: u64) -> i64 {
        // The times, with Linux's `UTIME_NOW` and `UTIME_OMIT` as the host's.
        let host_times = if times == 0 {
            None
        } else {
            let t: [fwe_abi::Timespec; 2] = guest!(uaccess::read(times));
            Some(t.map(|t| libc::timespec {
                tv_sec: t.tv_sec as libc::time_t,
                tv_nsec: match t.tv_nsec {
                    fwe_abi::UTIME_NOW => libc::UTIME_NOW,
                    fwe_abi::UTIME_OMIT => libc::UTIME_OMIT,
                    n => n as libc::c_long,
                },
            }))
        };
        let times_ptr = host_times.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
        // What the times ask of the caller: to set them to now, the
        // file's owner or one who may write to it (`EACCES`); to set them
        // to a time, its owner (`EPERM`); `CAP_FOWNER` passes both.
        let kinds = host_times.map(|t| t.map(|x| x.tv_nsec));
        let explicit =
            kinds.is_some_and(|k| k.iter().any(|&n| n != libc::UTIME_NOW && n != libc::UTIME_OMIT));
        let all_omitted = kinds.is_some_and(|k| k.iter().all(|&n| n == libc::UTIME_OMIT));
        // Both set to now (what an append-only file takes).
        let touch = kinds.is_none_or(|k| k.iter().all(|&n| n == libc::UTIME_NOW));
        let may = |st: &libc::stat| -> Result<(), i32> {
            let c = &self.creds;
            if all_omitted
                || c.fsuid == st.st_uid
                || c.has_over(crate::caps::CAP_FOWNER, st.st_uid, st.st_gid)
            {
                Ok(())
            } else if explicit {
                Err(errno::EPERM)
            } else if self.permits(st, 2) {
                Ok(())
            } else {
                Err(errno::EACCES)
            }
        };
        // No path from the working directory names nothing to read.
        if path == 0 && dirfd as i64 == fcntl::AT_FDCWD {
            return err(errno::EFAULT);
        }
        if path == 0 {
            // futimens-style: operate on the fd in dirfd, which takes no
            // flags.
            if flags != 0 {
                return err(errno::EINVAL);
            }
            if let Err(e) = self.fd_change(dirfd as i32) {
                return err(e);
            }
            if let Err(e) = stat_fd(dirfd as i32).and_then(|st| may(&st)) {
                return err(e);
            }
            return set_times_fd(dirfd as i32, times_ptr, touch);
        }
        if flags & !(fcntl::AT_SYMLINK_NOFOLLOW | fcntl::AT_EMPTY_PATH) != 0 {
            return err(errno::EINVAL);
        }
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 && dirfd as i64 != fcntl::AT_FDCWD {
            // The descriptor's own file; an O_PATH stand-in's is the one it
            // names.
            if let Err(e) = self.fd_change(dirfd as i32) {
                return err(e);
            }
            if let Err(e) = stat_fd(dirfd as i32).and_then(|st| may(&st)) {
                return err(e);
            }
            if let Some(host) = crate::fdmarks::stand_in(dirfd as i32) {
                let Ok(c) = CString::new(host) else { return err(errno::ENOENT) };
                // SAFETY: a NUL-terminated path; times valid or null.
                return ret(unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        c.as_ptr(),
                        times_ptr,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                });
            }
            return set_times_fd(dirfd as i32, times_ptr, touch);
        }
        let path =
            if path.is_empty() && flags & fcntl::AT_EMPTY_PATH != 0 { b".".to_vec() } else { path };
        let follow = flags & fcntl::AT_SYMLINK_NOFOLLOW == 0;
        if let Some(fd) = self.fd_link(dirfd, &path, follow) {
            if let Err(e) = self.fd_change(fd) {
                return err(e);
            }
            if let Err(e) = stat_fd(fd).and_then(|st| may(&st)) {
                return err(e);
            }
            return set_times_fd(fd, times_ptr, touch);
        }
        let r = match self.resolve_p(dirfd, &path, follow, true, Change::Modify) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        // In fwe's store (a tmpfs).
        if let Some(d) = &r.store {
            let ino = match d.find(&r.name) {
                Ok((ino, _)) => ino,
                Err(e) => return err(e),
            };
            if let Err(e) = d.host_stat(ino).and_then(|st| may(&st)) {
                return err(e);
            }
            let file = crate::filestore::desc::File { fs: d.fs.id, ino };
            return crate::filestore::io::set_times_file(file, host_times, touch);
        }
        let Ok(name) = r.name_c() else { return err(errno::EINVAL) };
        let dir = r.dir;
        if let Err(e) = stat_at(dir.as_raw_fd(), &name).and_then(|st| may(&st)) {
            return err(e);
        }
        // Not followed: a symbolic link's own times.
        let host_flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
        // SAFETY: `name` NUL-terminated; `dir` live; times valid or null.
        let r = unsafe { libc::utimensat(dir.as_raw_fd(), name.as_ptr(), times_ptr, host_flags) };
        #[cfg(target_os = "macos")]
        if r != 0 && host::last_errno() == libc::EPERM && touch {
            // An append-only file's times set to now (see `set_times_fd`), by
            // its path ([`crate::reclocks`]).
            return host::at_path(dir.as_raw_fd(), &name, |p| touch_append_only(p, times_ptr))
                .unwrap_or_else(err);
        }
        ret(r)
    }

    /// The open file a `/proc/self/fd/N` link (or `/proc/self/exe`) at
    /// `path` leads to, when the call follows it: Linux acts on that file
    /// itself, whatever has become of its path.
    fn fd_link(&self, dirfd: u64, path: &[u8], follow: bool) -> Option<i32> {
        if !follow {
            return None;
        }
        match self.fs().synthetic(dirfd as i32, path)? {
            crate::procfs::Entry::Fd { fd, .. } => Some(fd),
            _ => None,
        }
    }

    /// Whether the file of fwe's `/proc` or `/sys` at `path` (from `dirfd`)
    /// is reached through a read-only mount.
    fn synthetic_read_only(&self, dirfd: i32, path: &[u8]) -> bool {
        self.fs()
            .absolute_path(dirfd, path)
            .is_some_and(|a| self.fs().mount_of(&a).0.flags & crate::mounts::ms::RDONLY != 0)
    }

    /// `fd` (or an error), just opened on a file of fwe's `/proc` or `/sys`
    /// at `path`: recorded as of that mount, so `fstatfs` reports `proc`
    /// or `sysfs` as runtimes check, not what stands in for it on the host.
    /// A descriptor of the synthetic file at `path` (from `dirfd`) holding
    /// `contents`, as the guest's open `flags` ask ([`crate::procfile`]).
    fn proc_file(&self, dirfd: i32, path: &[u8], contents: Vec<u8>, flags: u64) -> i64 {
        let at = self.fs().absolute_path(dirfd, path).unwrap_or_else(|| path.to_vec());
        crate::procfile::open(&named_by_pid(&at), contents, flags)
    }

    fn synthetic_fd(&self, fd: i64, dirfd: i32, path: &[u8]) -> i64 {
        if fd >= 0
            && let Some(absolute) = self.fs().absolute_path(dirfd, path)
        {
            let ns = self.fs().to_ns(&absolute);
            let (m, _) = self.fs().mount_of(&absolute);
            crate::fdmarks::opened(fd as i32, ns, m.id, m.flags, m.fstype, None);
        }
        fd
    }

    /// For a `comm` of `/proc` or `/proc/sys/kernel/hostname` or
    /// `domainname` at `path`, what a write to it acts on: a thread of the
    /// caller's (another process's refuses the write), the UTS
    /// namespace's names (with `CAP_SYS_ADMIN`, else `EACCES`).
    fn name_file(&self, dirfd: i32, path: &[u8]) -> Option<Result<crate::fdmarks::Mark, i32>> {
        use crate::fdmarks::Mark;
        let p = self.fs().proc_path(dirfd, path)?;
        match &p[..] {
            b"/proc/sys/kernel/hostname" | b"/proc/sys/kernel/domainname" => {
                let domain = p.ends_with(b"domainname");
                let owner = self.fs().ns.owner(fwe_abi::clone::CLONE_NEWUTS);
                return Some(if self.creds.has_in(&owner, crate::caps::CAP_SYS_ADMIN) {
                    Ok(Mark::UtsName { domain })
                } else {
                    Err(errno::EACCES)
                });
            }
            b"/proc/self/comm" => return Some(Ok(Mark::Comm { tid: 0 })),
            _ => {}
        }
        let rest = p.strip_prefix(b"/proc/")?.strip_suffix(b"/comm")?;
        if let Some(t) = rest.strip_prefix(b"self/task/") {
            let tid = std::str::from_utf8(t).ok()?.parse().ok()?;
            return Some(Ok(Mark::Comm { tid }));
        }
        Some(Ok(Mark::Comm { tid: -1 }))
    }

    /// What the `proc` mount `path` is in hides of it from the caller
    /// (`hidepid=`, `subset=pid`, [`crate::procfs::Hiding`]): `ENOENT` or
    /// `EPERM`.
    pub(crate) fn proc_hidden(&self, dirfd: i32, path: &[u8]) -> Option<i32> {
        let a = self.fs().absolute_path(dirfd, path)?;
        let (m, fs_path) = self.fs().mount_of(&a);
        if m.fstype != crate::mounts::FsType::Proc {
            return None;
        }
        self.hidden_in(&m.options, &fs_path)
    }

    /// [`Self::proc_hidden`] of `fs_path` in a `proc` mount of options
    /// `options`: a process is hidden from a reader that may not trace it
    /// (`PTRACE_MODE_READ_FSCREDS`) and is not in the mount's `gid=`.
    fn hidden_in(&self, options: &[u8], fs_path: &[u8]) -> Option<i32> {
        if !options.windows(7).any(|w| w == b"hidepid" || w == b"subset=") {
            return None;
        }
        let h = crate::procfs::Hiding::of(options);
        if !h.any() {
            return None;
        }
        h.refuses(fs_path, |pid| self.proc_visible(pid, &h))
    }

    /// Whether process `pid` (a number in the caller's pid namespace) is
    /// one the `proc` mount hiding `h` shows the caller.
    fn proc_visible(&self, pid: i32, h: &crate::procfs::Hiding) -> bool {
        if pid == crate::thread::tgid() {
            return true;
        }
        let c = &self.creds;
        if h.gid.is_some_and(|g| c.fsgid == g || c.groups().contains(&g)) {
            return true;
        }
        crate::pidns::to_host(pid).is_some_and(|host| self.may_access(host, false, true))
    }

    /// Whether the caller is refused another process's `/proc/<pid>` file
    /// at `path`: one its `proc` mount hides ([`Self::proc_hidden`]), or
    /// one that only a reader that may trace it reads
    /// ([`crate::procpid::TRACER_ONLY`]): `EACCES` then.
    pub(crate) fn proc_refused(&self, dirfd: i32, path: &[u8]) -> Option<i32> {
        // A path found ahead under no mount but the root's is not in /proc.
        if self.fs().found_direct(dirfd, path) {
            return None;
        }
        let a = self.fs().absolute_path(dirfd, path)?;
        let (m, fs_path) = self.fs().mount_of(&a);
        if m.fstype != crate::mounts::FsType::Proc {
            return None;
        }
        if let Some(e) = self.hidden_in(&m.options, &fs_path) {
            return Some(e);
        }
        let in_proc = crate::mounts::join(b"/proc", &fs_path);
        let (Some(Some(host)), sub) = crate::fs::proc_target_of(&in_proc)? else { return None };

        // Linux's `PTRACE_MODE_READ_FSCREDS`.
        if !crate::procpid::TRACER_ONLY.contains(&&sub[..]) || self.may_access(host, false, true) {
            return None;
        }
        Some(errno::EACCES)
    }

    /// For `/proc/<pid>/oom_score_adj` or `oom_adj` at `path`, what a write
    /// to it acts on, or why it may not be opened to write (another owner's,
    /// to a caller without `CAP_DAC_OVERRIDE`).
    fn oom_file(&self, dirfd: i32, path: &[u8]) -> Option<Result<crate::fdmarks::Mark, i32>> {
        let p = self.fs().proc_path(dirfd, path).or_else(|| {
            let a = self.fs().absolute_path(dirfd, path)?;
            let (m, fs_path) = self.fs().mount_of(&a);
            (m.fstype == crate::mounts::FsType::Proc)
                .then(|| crate::mounts::join(b"/proc", &fs_path))
        })?;
        let rest = p.strip_prefix(b"/proc/")?;
        let (who, file) = rest.split_at(rest.iter().position(|&b| b == b'/')?);
        let legacy = match file {
            b"/oom_score_adj" => false,
            b"/oom_adj" => true,
            b"/timerslack_ns" => {
                let host = if who == b"self" {
                    crate::host::pid()
                } else {
                    crate::pidns::to_host(std::str::from_utf8(who).ok()?.parse().ok()?)?
                };
                // Another process's takes CAP_SYS_NICE, as on Linux.
                let own = host == crate::host::pid();
                if !own
                    && !self.creds.has_in(&crate::procreg::user_ns(host), crate::caps::CAP_SYS_NICE)
                {
                    return Some(Err(errno::EPERM));
                }
                return Some(Ok(crate::fdmarks::Mark::TimerSlack { host }));
            }
            _ => return None,
        };
        let host = if who == b"self" {
            crate::host::pid()
        } else {
            crate::pidns::to_host(std::str::from_utf8(who).ok()?.parse().ok()?)?
        };
        let own = host == crate::host::pid();
        // The file is its process's effective user's and group's, mode
        // 0644.
        let ids = crate::procreg::ids(host);
        if !own
            && !self.creds.has_over(crate::caps::CAP_DAC_OVERRIDE, ids[1], ids[5])
            && ids[1] != self.creds.fsuid
        {
            return Some(Err(errno::EACCES));
        }
        let privileged = self.creds.has(crate::caps::CAP_SYS_RESOURCE);
        Some(Ok(crate::fdmarks::Mark::OomScore { host, legacy, privileged }))
    }

    /// For another process's `/proc/<pid>/mem` (or a thread's,
    /// `/proc/<pid>/task/<tid>/mem`) at `path`: the tracee it reaches, as
    /// ptrace names it, if the caller may (it traces it, or may trace
    /// it); `EACCES` if not.
    fn other_mem(&self, dirfd: i32, path: &[u8]) -> Option<Result<i32, i32>> {
        let a = self.fs().absolute_path(dirfd, path)?;
        let (m, fs_path) = self.fs().mount_of(&a);
        if m.fstype != crate::mounts::FsType::Proc {
            return None;
        }
        let rest = fs_path.strip_prefix(b"/")?.strip_suffix(b"/mem")?;
        let num = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<i32>().ok();
        let (pid, tid) = match rest.iter().position(|&b| b == b'/') {
            None => (num(rest)?, None),
            Some(i) => (num(&rest[..i])?, Some(num(rest[i..].strip_prefix(b"/task/")?)?)),
        };
        let host = crate::pidns::to_host(pid)?;
        if host == crate::host::pid() {
            return None;
        }
        let id = match tid {
            Some(t) if t != pid => crate::ptrace::target_of(t)?,
            _ => host,
        };
        // Only an fwe process's memory can be reached (through its mailbox):
        // any other is one the caller may not attach to.
        if !crate::host::is_fwe(host) {
            return Some(Err(errno::EACCES));
        }
        Some(if crate::ptrace::traces(id) || self.may_access(host, true, true) {
            Ok(id)
        } else {
            Err(errno::EACCES)
        })
    }

    /// For `/proc/<pid>/uid_map`, `gid_map` or `setgroups` at `path`, what
    /// a write to it acts on, with the opener's standing (see `userns`).
    fn map_file(&self, dirfd: i32, path: &[u8]) -> Option<crate::fdmarks::Mark> {
        let p = self.fs().proc_path(dirfd, path).or_else(|| {
            // Another process's: /proc/<pid>/...
            let a = self.fs().absolute_path(dirfd, path)?;
            let (m, fs_path) = self.fs().mount_of(&a);
            (m.fstype == crate::mounts::FsType::Proc)
                .then(|| crate::mounts::join(b"/proc", &fs_path))
        })?;
        let rest = p.strip_prefix(b"/proc/")?;
        let (who, file) = rest.split_at(rest.iter().position(|&b| b == b'/')?);
        let which = match file {
            b"/uid_map" => 0,
            b"/gid_map" => 1,
            b"/setgroups" => 2,
            _ => return None,
        };
        let me = crate::host::pid();
        let host = if who == b"self" {
            me
        } else {
            crate::pidns::to_host(std::str::from_utf8(who).ok()?.parse().ok()?)?
        };
        let target = crate::procreg::read(host).and_then(|r| crate::procpid::user_record(&r.ns));
        let (privileged, own) = match &target {
            Some(t) => {
                let gid = which == 1;
                let cap = if gid { crate::caps::CAP_SETGID } else { crate::caps::CAP_SETUID };
                let kid = if gid { self.creds.egid } else { self.creds.euid };
                // The capability counts in the namespace's parent.
                let parent = t.get().parent.as_ref().map_or_else(Vec::new, |p| p.0.clone());
                crate::userns::standing(t, kid, gid, self.creds.has_in(&parent, cap))
            }
            None => (false, 0),
        };
        Some(crate::fdmarks::Mark::ProcMap { host, which, privileged, own })
    }

    /// `setxattr`, `lsetxattr` (`!follow`): set attribute `name` of the
    /// file at `path` (from `dirfd`) to the `size` bytes at `value`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_setxattr(
        &mut self,
        dirfd: i32,
        path: u64,
        name: u64,
        value: u64,
        size: u64,
        flags: u64,
        follow: bool,
    ) -> i64 {
        let (name, value) = match self.xattr_args(name, value, size) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
        if self.fs().synthetic(dirfd, &path).is_some() {
            return err(errno::EPERM);
        }
        let r = self.resolve_p(dirfd as u64, &path, follow, true, Change::Modify).and_then(|r| {
            Self::overlay_own(r.ovl.as_ref().map(|o| &*o.layers), &name)?;
            let (file, plain) = Self::xattr_resolved(&r)?;
            let space = crate::xattr::space(&name)?;
            self.xattr_who(plain).may_write(&name, space)?;
            let value = Self::xattr_stored(&name, value)?;
            crate::xattr::set(&file.target(), &name, &value, flags)
        });
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// The value attribute `name` is kept as, written as `value`: file
    /// capabilities checked and converted ([`crate::xattr::store_file_caps`]).
    fn xattr_stored(name: &[u8], value: Vec<u8>) -> Result<Vec<u8>, i32> {
        if name == crate::xattr::CAPABILITY {
            crate::xattr::store_file_caps(&value)
        } else {
            Ok(value)
        }
    }

    /// `fsetxattr`.
    pub(crate) fn sys_fsetxattr(
        &mut self,
        fd: u64,
        name: u64,
        value: u64,
        size: u64,
        flags: u64,
    ) -> i64 {
        let (name, value) = match self.xattr_args(name, value, size) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let fd = fd as i32;
        let r = self.fd_change(fd).and_then(|()| {
            Self::overlay_own(self.fd_overlay(fd).as_deref(), &name)?;
            let plain = Self::xattr_fd(fd)?;
            let space = crate::xattr::space(&name)?;
            self.xattr_who(plain).may_write(&name, space)?;
            let value = Self::xattr_stored(&name, value)?;
            crate::xattr::set(&crate::xattr::Target::Fd(fd), &name, &value, flags)
        });
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `getxattr`, `lgetxattr` (`!follow`), and `fgetxattr` (`path` 0,
    /// `fd` set): attribute `name` into the `size` bytes at `value` (its
    /// length, if `size` is 0).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_getxattr(
        &mut self,
        dirfd: i32,
        fd: Option<i32>,
        path: u64,
        name: u64,
        value: u64,
        size: u64,
        follow: bool,
    ) -> i64 {
        let name = guest!(uaccess::read_cstr(name, 256));
        let got = self.xattr_target(dirfd, fd, path, follow, |t, who, layers| {
            Self::overlay_own(layers, &name)?;
            who.may_read(crate::xattr::space(&name)?)?;
            let v = crate::xattr::get(t, &name)?;
            if name == crate::xattr::CAPABILITY { crate::xattr::show_file_caps(v) } else { Ok(v) }
        });
        self.xattr_out(got, value, size)
    }

    /// `listxattr`, `llistxattr` (`!follow`), and `flistxattr`: the names
    /// of the attributes the caller sees, into the `size` bytes at `list`.
    pub(crate) fn sys_listxattr(
        &mut self,
        dirfd: i32,
        fd: Option<i32>,
        path: u64,
        list: u64,
        size: u64,
        follow: bool,
    ) -> i64 {
        let got = self.xattr_target(dirfd, fd, path, follow, |t, who, layers| {
            let all = crate::xattr::list(t, who)?;
            // An overlay's file does not show the overlay's own.
            let Some(l) = layers else { return Ok(all) };
            let mut out = Vec::new();
            for n in all.split(|&b| b == 0).filter(|n| !n.is_empty()) {
                if !n.starts_with(l.private_prefix()) {
                    out.extend_from_slice(n);
                    out.push(0);
                }
            }
            Ok(out)
        });
        // A file fwe makes up has none.
        let got = if got == Err(SYNTHETIC) { Ok(Vec::new()) } else { got };
        self.xattr_out(got, list, size)
    }

    /// `removexattr`, `lremovexattr` (`!follow`), and `fremovexattr`.
    pub(crate) fn sys_removexattr(
        &mut self,
        dirfd: i32,
        fd: Option<i32>,
        path: u64,
        name: u64,
        follow: bool,
    ) -> i64 {
        let name = guest!(uaccess::read_cstr(name, 256));
        let r = match fd {
            Some(fd) => self.fd_change(fd).and_then(|()| {
                Self::overlay_own(self.fd_overlay(fd).as_deref(), &name)?;
                let plain = Self::xattr_fd(fd)?;
                let space = crate::xattr::space(&name)?;
                self.xattr_who(plain).may_write(&name, space)?;
                crate::xattr::remove(&crate::xattr::Target::Fd(fd), &name)
            }),
            None => {
                let path = guest!(uaccess::read_cstr(path, uaccess::PATH_MAX));
                if self.fs().synthetic(dirfd, &path).is_some() {
                    return err(errno::EPERM);
                }
                self.resolve_p(dirfd as u64, &path, follow, true, Change::Modify).and_then(|r| {
                    Self::overlay_own(r.ovl.as_ref().map(|o| &*o.layers), &name)?;
                    let (file, plain) = Self::xattr_resolved(&r)?;
                    let space = crate::xattr::space(&name)?;
                    self.xattr_who(plain).may_write(&name, space)?;
                    crate::xattr::remove(&file.target(), &name)
                })
            }
        };
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// An attribute's name and value from the guest.
    fn xattr_args(&self, name: u64, value: u64, size: u64) -> Result<(Vec<u8>, Vec<u8>), i32> {
        let name = uaccess::read_cstr(name, 256).map_err(|_| errno::EFAULT)?;
        if size as usize > crate::xattr::SIZE_MAX {
            return Err(errno::E2BIG);
        }
        let mut v = vec![0u8; size as usize];
        if size > 0 {
            uaccess::read_into(value, &mut v).map_err(|_| errno::EFAULT)?;
        }
        Ok((name, v))
    }

    /// Run `f` on the file a reading attribute call names: descriptor `fd`,
    /// or the file at guest `path` (followed if `follow`), with the
    /// caller's standing toward it. A file fwe makes up has no attributes
    /// ([`SYNTHETIC`]).
    fn xattr_target<T>(
        &self,
        dirfd: i32,
        fd: Option<i32>,
        path: u64,
        follow: bool,
        f: impl FnOnce(
            &crate::xattr::Target,
            &crate::xattr::Who,
            Option<&crate::overlay::Layers>,
        ) -> Result<T, i32>,
    ) -> Result<T, i32> {
        match fd {
            Some(fd) => {
                let plain = Self::xattr_fd(fd)?;
                let layers = self.fd_overlay(fd);
                f(&crate::xattr::Target::Fd(fd), &self.xattr_who(plain), layers.as_deref())
            }
            None => {
                let path = uaccess::read_cstr(path, uaccess::PATH_MAX)?;
                if self.fs().synthetic(dirfd, &path).is_some() {
                    return Err(SYNTHETIC);
                }
                let r = self.fs().resolve(dirfd, &path, follow)?;
                let (file, plain) = Self::xattr_resolved(&r)?;
                f(&file.target(), &self.xattr_who(plain), r.ovl.as_ref().map(|o| &*o.layers))
            }
        }
    }

    /// `setxattrat`, `getxattrat`, `listxattrat` and `removexattrat`
    /// (`nr`, arguments `a`): the attribute calls on the file at a path
    /// from a directory descriptor (`AT_SYMLINK_NOFOLLOW`; with
    /// `AT_EMPTY_PATH` and no path, the descriptor's file), the value of a
    /// set or get in a `struct xattr_args`.
    pub(crate) fn sys_xattrat(&mut self, nr: u64, a: [u64; 6]) -> i64 {
        use fwe_abi::fcntl::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
        let (dirfd, path, at) = (a[0] as i32, a[1], a[2]);
        if at & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
            return err(errno::EINVAL);
        }
        let follow = at & AT_SYMLINK_NOFOLLOW == 0;
        // The descriptor's own file: an empty path, as `AT_EMPTY_PATH` allows.
        let own = at & AT_EMPTY_PATH != 0
            && dirfd != fcntl::AT_FDCWD as i32
            && uaccess::read_cstr(path, uaccess::PATH_MAX).is_ok_and(|p| p.is_empty());
        let fd = own.then_some(dirfd);
        // `struct xattr_args`: the value's address and size, and flags.
        let args = |at: u64, size: u64| -> Result<(u64, u64, u64), i32> {
            if size < 16 {
                return Err(errno::EINVAL);
            }
            if size > 4096 {
                return Err(errno::E2BIG);
            }
            let mut b = vec![0u8; size as usize];
            uaccess::read_into(at, &mut b)?;
            if b[16..].iter().any(|&c| c != 0) {
                return Err(errno::E2BIG);
            }
            let word = |o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
            Ok((word(0), word(8) & 0xffff_ffff, word(8) >> 32))
        };
        match nr {
            fwe_abi::nr::SETXATTRAT => {
                let (value, size, flags) = match args(a[4], a[5]) {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                match fd {
                    Some(fd) => self.sys_fsetxattr(fd as u64, a[3], value, size, flags),
                    None => self.sys_setxattr(dirfd, path, a[3], value, size, flags, follow),
                }
            }
            fwe_abi::nr::GETXATTRAT => {
                let (value, size, flags) = match args(a[4], a[5]) {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                if flags != 0 {
                    return err(errno::EINVAL);
                }
                self.sys_getxattr(dirfd, fd, path, a[3], value, size, follow)
            }
            fwe_abi::nr::LISTXATTRAT => self.sys_listxattr(dirfd, fd, path, a[3], a[4], follow),
            _ => self.sys_removexattr(dirfd, fd, path, a[3], follow),
        }
    }

    /// Copy what a reading attribute call got to the `size` bytes at `buf`:
    /// its length when `size` is 0, `ERANGE` when it does not fit.
    fn xattr_out(&self, got: Result<Vec<u8>, i32>, buf: u64, size: u64) -> i64 {
        let data = match got {
            Ok(d) => d,
            Err(e) if e == SYNTHETIC => return err(errno::ENODATA),
            Err(e) => return err(e),
        };
        if size == 0 {
            return data.len() as i64;
        }
        if data.len() > size as usize {
            return err(errno::ERANGE);
        }
        guest!(uaccess::write_from(buf, &data));
        data.len() as i64
    }

    /// The host path of `name` in `dir`, and what kind of file it is.
    fn xattr_file(
        dir: &std::os::fd::OwnedFd,
        name: &CString,
    ) -> Result<(CString, crate::xattr::Kind), i32> {
        let mut st: libc::stat = zeroed_stat();
        // SAFETY: `name` NUL-terminated; `dir` live; `st` an out-parameter.
        if unsafe {
            libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
        } != 0
        {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let perm = crate::modes::guest_perm_at(dir.as_raw_fd(), name, &st);
        let owner = crate::owners::of_at(dir.as_raw_fd(), name, &st);
        let mut host = crate::fs::fd_path(dir.as_raw_fd()).ok_or(errno::ENOENT)?;
        host.push(b'/');
        host.extend_from_slice(name.as_bytes());
        let kind = crate::xattr::Kind::of(&st, perm, owner);
        Ok((CString::new(host).map_err(|_| errno::EINVAL)?, kind))
    }

    /// The file `r` resolved to, for its attributes, and its kind: its
    /// host path, or a file of fwe's store.
    fn xattr_resolved(r: &crate::fs::Resolved) -> Result<(XattrFile, crate::xattr::Kind), i32> {
        if let Some(file) = r.store_file()? {
            let st = r.lstat().ok_or(errno::ENOENT)?;
            #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
            let kind =
                crate::xattr::Kind::of(&st, st.st_mode as u32 & 0o7777, (st.st_uid, st.st_gid));
            return Ok((XattrFile::Store(file), kind));
        }
        let (host, kind) = Self::xattr_file(&r.dir, &r.name_c()?)?;
        Ok((XattrFile::Path(host), kind))
    }

    /// What kind of file open descriptor `fd` is of.
    fn xattr_fd(fd: i32) -> Result<crate::xattr::Kind, i32> {
        // A file of fwe's store keeps its own mode and owner.
        if let Some(st) = crate::filestore::io::stat(fd) {
            let st = st?;
            return Ok(crate::xattr::Kind::of(
                &st,
                #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
                (st.st_mode as u32 & 0o7777),
                (st.st_uid, st.st_gid),
            ));
        }
        let mut st: libc::stat = zeroed_stat();
        // SAFETY: `st` an out-parameter.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let perm = crate::modes::guest_perm_fd(fd, &st);
        let owner = crate::owners::of_fd(fd, &st);
        Ok(crate::xattr::Kind::of(&st, perm, owner))
    }

    /// The caller's standing toward a file of kind `kind`, for its
    /// attributes.
    fn xattr_who(&self, kind: crate::xattr::Kind) -> crate::xattr::Who {
        let mut st = zeroed_stat();
        st.st_mode = kind.meta.0 as libc::mode_t;
        (st.st_uid, st.st_gid) = (kind.meta.1, kind.meta.2);
        crate::xattr::Who {
            admin: self.creds.has(crate::caps::CAP_SYS_ADMIN),
            setfcap: self.creds.has_over(crate::caps::CAP_SETFCAP, st.st_uid, st.st_gid),
            read_any: self.permits(&st, 4),
            write_any: self.permits(&st, 2),
            owner: self.creds.fsuid == st.st_uid
                || self.creds.has_over(crate::caps::CAP_FOWNER, st.st_uid, st.st_gid),
            kind,
        }
    }

    /// Whether the caller may do `want` (`R_OK`, `W_OK`, `X_OK` bits) to a
    /// file whose guest metadata (owner and mode, [`stat_at`]) is `st`, as
    /// Linux's permission check has it: `CAP_DAC_OVERRIDE` passes all but
    /// running a file nobody may run, `CAP_DAC_READ_SEARCH` reading and
    /// searching; else the owner's, the group's or the others' bits, by the
    /// caller's file-system ids and groups.
    pub(crate) fn permits(&self, st: &libc::stat, want: u32) -> bool {
        // Without a root filesystem, the host's own files (root's, with no
        // owner kept) are the host user's to allow, as they always were.
        if st.st_uid == 0 && st.st_gid == 0 && self.fs_opt().is_some_and(|f| f.root_is_host()) {
            return true;
        }
        self.creds.permits(st, want)
    }

    /// A file `name` made in directory `dir` (open as `fd`, if it is),
    /// with permission bits `perm`, a directory if `is_dir`: its owner is
    /// the caller's file-system user, its group the caller's or, in a
    /// set-group-ID directory, the directory's, whose bit a directory made
    /// there inherits; a file made set-group-ID for a group the caller is
    /// not in loses the bit (without `CAP_FSETID`), judged by the mode
    /// `asked` before the umask, as Linux makes one.
    pub(crate) fn own_new(
        &self,
        dir: i32,
        name: &std::ffi::CStr,
        fd: Option<i32>,
        is_dir: bool,
        perm: u32,
        asked: u32,
    ) {
        let c = &self.creds;
        let parent = stat_fd(dir).ok();
        let setgid_dir = parent.as_ref().is_some_and(|p| p.st_mode & 0o2000 != 0);
        let gid = match &parent {
            Some(p) if setgid_dir => p.st_gid,
            _ => c.fsgid,
        };
        let mut kept = perm & 0o7777;
        if setgid_dir && is_dir {
            kept |= 0o2000;
        } else if !is_dir
            && kept & 0o2000 != 0
            && asked & 0o010 != 0
            && gid != c.fsgid
            && !c.groups().contains(&gid)
            && !c.has_over(crate::caps::CAP_FSETID, c.fsuid, gid)
        {
            kept &= !0o2000;
        }
        let owner = (c.fsuid, gid);
        match fd {
            // The set-ID and sticky bits are given again: the host drops
            // them from a new file of a group it is not in, and from a new
            // directory.
            Some(fd) => {
                let _ = crate::owners::keep_fd(fd, owner);
                if kept != perm & 0o7777 || kept & 0o7000 != 0 {
                    let _ = crate::modes::keep_fd(fd, kept);
                }
            }
            None => {
                let _ = crate::owners::keep_at(dir, name, owner);
                if kept != perm & 0o7777 || kept & 0o7000 != 0 {
                    let _ = crate::modes::keep_at(dir, name, kept);
                }
            }
        }
    }

    /// Whether the caller passes the permission bits of the file whose
    /// guest metadata is `st` for access `want` (`R_OK`, `W_OK`, `X_OK`
    /// bits): `CAP_DAC_OVERRIDE`, or `CAP_DAC_READ_SEARCH` to read, over
    /// the file ([`crate::creds::Creds::has_over`]).
    fn passes_dac(&self, st: &libc::stat, want: u32) -> bool {
        let over = |cap| self.creds.has_over(cap, st.st_uid, st.st_gid);
        over(crate::caps::CAP_DAC_OVERRIDE)
            || want & !4 == 0 && over(crate::caps::CAP_DAC_READ_SEARCH)
    }

    /// Whether the caller may remove (or rename away, or replace) `name`
    /// in directory `dir`: in a sticky directory, only the file's owner,
    /// the directory's, or a caller with `CAP_FOWNER` may (`EPERM`), as
    /// Linux restricts deletion. Nothing there passes.
    fn may_remove(&self, dir: i32, name: &CString) -> Result<(), i32> {
        let Ok(d) = stat_fd(dir) else { return Ok(()) };
        if d.st_mode & 0o1000 == 0 {
            return Ok(());
        }
        let Ok(f) = stat_at(dir, name) else { return Ok(()) };
        self.sticky_allows(&d, &f)
    }

    /// Whether a caller may remove (or rename away, or replace) the file of
    /// guest metadata `f` from a directory of guest metadata `d`: the
    /// sticky bit's restriction ([`Self::may_remove`]).
    fn sticky_allows(&self, d: &libc::stat, f: &libc::stat) -> Result<(), i32> {
        let c = &self.creds;
        if d.st_mode & 0o1000 == 0
            || c.fsuid == f.st_uid
            || c.fsuid == d.st_uid
            || c.has_over(crate::caps::CAP_FOWNER, f.st_uid, f.st_gid)
        {
            Ok(())
        } else {
            Err(errno::EPERM)
        }
    }

    /// [`Self::may_remove`] for what `o` found as `name` in an overlay
    /// directory: the directory as its topmost layer shows it, the name as
    /// the layer it is found in has it.
    fn may_remove_in_overlay(&self, o: &crate::fs::Ovl, name: &[u8]) -> Result<(), i32> {
        use crate::overlay::Found;
        let Ok(d) = crate::overlay::open(&o.layers, &o.parent) else { return Ok(()) };
        let Ok(dir) = stat_fd(d.top().1.as_raw_fd()) else { return Ok(()) };
        if dir.st_mode & 0o1000 == 0 {
            return Ok(());
        }
        let file = match &o.found {
            Found::Other { layer, .. } => match (&d.fds[*layer], CString::new(name)) {
                (Some(l), Ok(n)) => stat_at(l.as_raw_fd(), &n),
                _ => return Ok(()),
            },
            Found::Dir(child) => stat_fd(child.top().1.as_raw_fd()),
            Found::Missing => return Ok(()),
        };
        match file {
            Ok(f) => self.sticky_allows(&dir, &f),
            Err(_) => Ok(()),
        }
    }

    /// Change the entries of directory `dir` with `op` (a host call, as a
    /// raw Linux result). A caller that does not pass permission bits
    /// needs the write and search bits of the directory's kept mode; one
    /// that does is not refused by the host's: refused with `EACCES`, the
    /// directory's mode is kept apart and `op` tried again
    /// ([`crate::modes`]).
    fn change_in(&self, dir: i32, op: impl Fn() -> i64) -> i64 {
        let st = match stat_fd(dir) {
            Ok(st) => st,
            Err(_) => return op(),
        };
        if crate::fs::is_empty_dir(&st) {
            // What a name an overlay does not show is resolved in: nothing
            // is ever made there.
            self.note_refused("an overlay's hidden name", dir, &st);
            return err(errno::EACCES);
        }
        let perm = crate::modes::perm_of(&st);
        if !self.passes_dac(&st, 2) {
            if !self.permits(&st, 2 | 1) {
                self.note_refused("the directory's bits", dir, &st);
                return err(errno::EACCES);
            }
            return op();
        }
        let r = op();
        if r == err(errno::EACCES) && crate::modes::keep_fd(dir, perm).is_ok() {
            op()
        } else {
            if r == err(errno::EACCES) {
                self.note_refused("the host, past the capability", dir, &st);
            }
            r
        }
    }

    /// Under `--strace` to a file: why a change of a directory was refused
    /// (`EACCES`), with what it was judged on, for a refusal to be traced.
    fn note_refused(&self, by: &str, dir: i32, st: &libc::stat) {
        if crate::trace::file().is_none() {
            return;
        }
        let c = &self.creds;
        let mut host = zeroed_stat();
        // SAFETY: plain host call with a valid out-parameter.
        unsafe { libc::fstat(dir, &mut host) };
        let path = crate::fs::host_path_of(dir).unwrap_or_default();
        #[cfg(target_os = "macos")]
        let flags = host.st_flags;
        #[cfg(not(target_os = "macos"))]
        let flags = 0;
        crate::trace::note_to_file(&format!(
            "refused by {by}: directory {} (host mode {:o}, flags {:#x}, kept mode {}) {}:{} \
             mode {:o}; caller fsuid {} fsgid {} groups {:?} user namespace nested {}",
            String::from_utf8_lossy(&path),
            host.st_mode & 0o7777,
            flags,
            crate::modes::marked(&host),
            st.st_uid,
            st.st_gid,
            st.st_mode & 0o7777,
            c.fsuid,
            c.fsgid,
            c.groups(),
            crate::userns::nested()
        ));
    }

    /// `linkat(fd, "", newdirfd, newpath, AT_EMPTY_PATH)`: give the file
    /// open as `fd` the name `newpath`, in the same mount (`EXDEV`) and as
    /// `fs.protected_hardlinks` allows, as for a path.
    fn link_fd(&self, fd: i32, newdirfd: u64, newpath: &[u8]) -> i64 {
        if !self.creds.has(crate::caps::CAP_DAC_READ_SEARCH) {
            return err(errno::ENOENT);
        }
        // A file of fwe's store (an `O_TMPFILE` of a tmpfs, say): named
        // there, in its own filesystem.
        if let Some(file) = crate::filestore::desc::of(fd) {
            let new = match self.fs().resolve(newdirfd as i32, newpath, false) {
                Ok(r) => r,
                Err(e) => return err(e),
            };
            let Some(nd) = new.store.clone() else { return err(errno::EXDEV) };
            if new.mount_root {
                return err(errno::EEXIST);
            }
            return self.store_link(file.fs, file.ino, &new, &nd, true);
        }
        let Some(host) = crate::fs::host_path_of(fd) else { return err(errno::ENOENT) };
        let Ok(src) = CString::new(host) else { return err(errno::EINVAL) };
        let mut new = match self.fs().resolve(newdirfd as i32, newpath, false) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let old_mount = crate::fdmarks::origin(fd).map_or(0, |o| o.mount);
        if old_mount != new.mount_id && old_mount != 0 && new.mount_id != 0 {
            return err(errno::EXDEV);
        }
        if crate::sysctl::protected_links().1 {
            let checked = stat_fd(fd).and_then(|st| self.may_hardlink_to(&st));
            if let Err(e) = checked {
                return err(e);
            }
        }
        if new.mount_root {
            return err(errno::EEXIST);
        }
        if let Err(e) = new.prepare(Change::Create) {
            return err(e);
        }
        let Ok(nn) = new.name_c() else { return err(errno::EINVAL) };
        let n = new.dir.as_raw_fd();
        // SAFETY: names NUL-terminated; `n` live.
        let made = self.change_in(n, || {
            // SAFETY: names NUL-terminated; `n` live.
            ret(unsafe { libc::linkat(libc::AT_FDCWD, src.as_ptr(), n, nn.as_ptr(), 0) })
        });
        match new.finish(made == 0) {
            Err(e) if made == 0 => err(e),
            _ => made,
        }
    }

    /// Get ready for a call that changes the file open as `fd`: `EROFS`
    /// for one opened through a read-only mount; for one of an overlay's
    /// lower layers, the file copied up and `fd` moved onto the copy, as
    /// Linux moves an open file to its copy (the same offset and flags).
    pub(crate) fn fd_change(&self, fd: i32) -> Result<(), i32> {
        let Some(o) = crate::fdmarks::origin(fd) else { return Ok(()) };
        if o.flags & crate::mounts::ms::RDONLY != 0 {
            return Err(errno::EROFS);
        }
        let Some(layers) = o.ovl.clone() else { return Ok(()) };
        if let Some(host) = o.stand_in {
            // An O_PATH stand-in names its file by path: copied up by it,
            // the stand-in names the copy.
            let upper = layers.upper.as_deref().ok_or(errno::EROFS)?;
            if crate::mounts::under(&host, upper).is_some() {
                return Ok(());
            }
            let path = crate::overlay::path_of(&layers, fd).ok_or(errno::ESTALE)?;
            let up = crate::overlay::copy_up(&layers, &path)?;
            let name = path.rsplit(|&b| b == b'/').next().unwrap_or_default();
            if let Some(dir) = crate::fs::host_path_of(up.as_raw_fd()) {
                crate::fdmarks::set_stand_in(fd, crate::mounts::join(&dir, name));
            }
            return Ok(());
        }
        // The descriptor's own file, copied up if it is a lower one.
        let Some((up, name)) = crate::overlay::copy_up_open(&layers, fd)? else { return Ok(()) };
        // SAFETY: plain host calls on an open descriptor.
        let (status, fd_flags) =
            unsafe { (libc::fcntl(fd, libc::F_GETFL), libc::fcntl(fd, libc::F_GETFD)) };
        let keep = libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK;
        let dir = stat_fd(fd).is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR);
        let open_flags = status & keep
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if dir { libc::O_DIRECTORY } else { 0 };
        // SAFETY: a NUL-terminated name in a live directory.
        let copy = unsafe { libc::openat(up.as_raw_fd(), name.as_ptr(), open_flags) };
        if copy < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        // SAFETY: plain host calls on the two open descriptors; `copy`
        // replaces `fd`, then goes.
        unsafe {
            let offset = libc::lseek(fd, 0, libc::SEEK_CUR);
            if offset > 0 {
                libc::lseek(copy, offset, libc::SEEK_SET);
            }
            let r = libc::dup2(copy, fd);
            libc::close(copy);
            if r < 0 {
                return Err(host::errno_to_linux(host::last_errno()));
            }
            libc::fcntl(fd, libc::F_SETFD, fd_flags);
        }
        crate::fdmarks::opened(fd, o.ns_path, o.mount, o.flags, o.fstype, o.ovl);
        if dir {
            crate::overlay::moved(fd);
        }
        Ok(())
    }

    /// The layers of the overlay `fd` was opened in, if it was.
    fn fd_overlay(&self, fd: i32) -> Option<std::sync::Arc<crate::overlay::Layers>> {
        crate::fdmarks::origin(fd)?.ovl
    }

    /// `EOPNOTSUPP` for an overlay's own attributes on its files (in
    /// `layers`), which they neither show nor take.
    fn overlay_own(layers: Option<&crate::overlay::Layers>, name: &[u8]) -> Result<(), i32> {
        match layers {
            Some(l) if name.starts_with(l.private_prefix()) => Err(errno::EOPNOTSUPP),
            _ => Ok(()),
        }
    }

    /// The open of `/proc/self/fd/<fd>` with Linux `flags`, `fd` a file of
    /// fwe's store: a new description of the file, as its mode allows the
    /// caller, emptied first with `O_TRUNC` as its seals allow.
    fn reopen_stored(&mut self, fd: i32, file: crate::filestore::desc::File, flags: u64) -> i64 {
        let st = match stat_fd(fd) {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        if flags & fcntl::O_DIRECTORY != 0 && st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return err(errno::ENOTDIR);
        }
        if !self.permits(&st, open_wants(flags)) {
            return err(errno::EACCES);
        }
        let new = match crate::filestore::desc::open(
            file,
            flags,
            crate::filestore::desc::new_id(flags),
        ) {
            Ok(new) => new,
            Err(e) => return err(e),
        };
        if flags & fcntl::O_TRUNC != 0 && flags & fcntl::O_ACCMODE != fcntl::O_RDONLY {
            let r = crate::filestore::io::ftruncate(new, 0).unwrap_or(0);
            if r < 0 {
                let _ = self.syscall(fwe_abi::nr::CLOSE, [new as u64, 0, 0, 0, 0, 0]);
                return r;
            }
        }
        new as i64
    }

    /// `fchmod(fd, mode)`.
    pub(crate) fn sys_fchmod(&mut self, fd: u64, mode: u64) -> i64 {
        let fd = fd as i32;
        if let Err(e) = self.fd_change(fd) {
            return err(e);
        }
        // A symbolic link's mode (one an `O_PATH` descriptor names) is not
        // to be changed.
        let mode = match stat_fd(fd).and_then(|st| {
            if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(errno::EOPNOTSUPP);
            }
            self.chmod_to(&st, mode as u32)
        }) {
            Ok(m) => m,
            Err(e) => return err(e),
        };
        // A file of fwe's store keeps its own, as its seals allow.
        if let Some(r) = crate::filestore::io::fchmod(fd, mode) {
            return r;
        }
        // A mode that denies the owner is kept apart (see `modes`); an
        // `O_PATH` stand-in's is its file's.
        let kept = match stand_in_at(fd) {
            Some(Ok((dir, name))) => crate::modes::keep_at(dir.as_raw_fd(), &name, mode),
            Some(Err(e)) => Err(e),
            None => crate::modes::keep_fd(fd, mode),
        };
        match kept {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `fchown(fd, uid, gid)`: the owner kept for the file
    /// ([`crate::owners`]), changed as Linux allows ([`Self::chown_to`]).
    pub(crate) fn sys_fchown(&mut self, fd: u64, uid: u64, gid: u64) -> i64 {
        let fd = fd as i32;
        if let Err(e) = self.fd_change(fd) {
            return err(e);
        }
        let st = match stat_fd(fd) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let (owner, mode) = match self.chown_to(&st, uid as u32, gid as u32) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if let Some(r) = crate::filestore::io::fchown(fd, owner, mode) {
            return r;
        }
        // An `O_PATH` stand-in's owner is its file's (a link's own).
        let kept = match stand_in_at(fd) {
            Some(Ok((dir, name))) => crate::owners::keep_at(dir.as_raw_fd(), &name, owner)
                .and_then(|()| {
                    mode.map_or(Ok(()), |m| crate::modes::keep_at(dir.as_raw_fd(), &name, m))
                }),
            Some(Err(e)) => Err(e),
            None => crate::owners::keep_fd(fd, owner)
                .and_then(|()| mode.map_or(Ok(()), |m| crate::modes::keep_fd(fd, m))),
        };
        match kept {
            Ok(()) => {
                // A regular file loses its file capabilities, as Linux's
                // `chown` has it (`ATTR_KILL_PRIV`).
                if st.st_mode & libc::S_IFMT == libc::S_IFREG && stand_in_at(fd).is_none() {
                    crate::xattr::kill_file_caps(&crate::xattr::Target::Fd(fd));
                }
                0
            }
            Err(e) => err(e),
        }
    }

    /// The permission bits `chmod` to `mode` gives a file whose guest
    /// metadata is `st`, as Linux allows it: only its owner, or a caller
    /// with `CAP_FOWNER`, changes them (`EPERM`); a caller not in the
    /// file's group, without `CAP_FSETID`, cannot make it set-group-ID.
    pub(crate) fn chmod_to(&self, st: &libc::stat, mode: u32) -> Result<u32, i32> {
        let c = &self.creds;
        if c.fsuid != st.st_uid && !c.has_over(crate::caps::CAP_FOWNER, st.st_uid, st.st_gid) {
            return Err(errno::EPERM);
        }
        let mut perm = mode & 0o7777;
        if perm & 0o2000 != 0
            && st.st_gid != c.fsgid
            && !c.groups().contains(&st.st_gid)
            && !c.has_over(crate::caps::CAP_FSETID, st.st_uid, st.st_gid)
        {
            perm &= !0o2000;
        }
        Ok(perm)
    }

    /// What `chown` to `uid` and `gid` (in the caller's user namespace;
    /// -1 leaves one as it is) makes of a file whose guest metadata is
    /// `st`, as Linux allows it: its owner (initial-namespace ids), and its
    /// permission bits if they change. Only `CAP_CHOWN` gives a file to
    /// another user, or to a group its owner is not in; an id no mapping
    /// has is `EINVAL`. A file not a directory loses its set-user-ID bit,
    /// and its set-group-ID bit where group execution is allowed.
    #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
    pub(crate) fn chown_to(
        &self,
        st: &libc::stat,
        uid: u32,
        gid: u32,
    ) -> Result<((u32, u32), Option<u32>), i32> {
        let to = |id: u32, g: bool| {
            if id == u32::MAX {
                Ok(None)
            } else {
                crate::userns::from_ns(id, g).map(Some).ok_or(errno::EINVAL)
            }
        };
        let (new_uid, new_gid) = (to(uid, false)?, to(gid, true)?);
        let c = &self.creds;
        let owns = c.fsuid == st.st_uid;
        let cap = c.has_over(crate::caps::CAP_CHOWN, st.st_uid, st.st_gid);
        if new_uid.is_some_and(|u| !(owns && u == st.st_uid) && !cap)
            || new_gid.is_some_and(|g| {
                !(owns && (g == st.st_gid || g == c.fsgid || c.groups().contains(&g))) && !cap
            })
        {
            return Err(errno::EPERM);
        }
        let owner = (new_uid.unwrap_or(st.st_uid), new_gid.unwrap_or(st.st_gid));
        let perm = st.st_mode as u32 & 0o7777;
        let kind = st.st_mode & libc::S_IFMT;
        let mut kept = perm;
        if kind != libc::S_IFDIR && kind != libc::S_IFLNK {
            kept &= !0o4000;
            if kept & 0o2010 == 0o2010 {
                kept &= !0o2000;
            }
        }
        Ok((owner, (kept != perm).then_some(kept)))
    }

    /// Resolve `path` for a call that changes what it names, `how`
    /// ([`Resolved::prepare`]; [`Change::Remove`] only checks): `EROFS` on
    /// a read-only mount, and, unless `mount_root_ok`, `EBUSY` for a
    /// mount's root.
    fn resolve_p(
        &self,
        dirfd: u64,
        path: &[u8],
        follow: bool,
        mount_root_ok: bool,
        how: Change,
    ) -> Result<Resolved, i32> {
        // A name made or removed is never followed; a trailing slash on it
        // is the caller's to judge ([`crate::fs::Fs::resolve_entry`]).
        let r = match how {
            Change::Create | Change::Remove => self.fs().resolve_entry(dirfd as i32, path)?,
            Change::Modify => self.fs().resolve(dirfd as i32, path, follow)?,
        };
        Self::changeable(r, mount_root_ok, how)
    }

    /// What [`Self::resolve_p`] resolved, checked and made ready for
    /// change `how`.
    fn changeable(mut r: Resolved, mount_root_ok: bool, how: Change) -> Result<Resolved, i32> {
        // A mount's root is busy whatever the mount: the change is the
        // directory's above it (a read-only mount's root too).
        if r.mount_root && !mount_root_ok {
            return Err(errno::EBUSY);
        }
        r.writable()?;
        r.prepare(how)?;
        Ok(r)
    }
}

/// A file an attribute call by path acts on ([`crate::xattr::Target`]).
enum XattrFile {
    Path(CString),
    Store(crate::filestore::desc::File),
}

impl XattrFile {
    fn target(&self) -> crate::xattr::Target<'_> {
        match self {
            XattrFile::Path(p) => crate::xattr::Target::Path(p),
            XattrFile::Store(f) => crate::xattr::Target::Store(*f),
        }
    }
}

/// What an attribute call on a file fwe makes up (under `/proc`) finds:
/// no attributes. Never a Linux errno.
const SYNTHETIC: i32 = -1;

/// A zeroed `stat`, an out-parameter.
pub(crate) fn zeroed_stat() -> libc::stat {
    // SAFETY: zeroed bytes are a valid `stat`.
    unsafe { std::mem::zeroed() }
}

/// A stat as a device node shows it.
fn as_node(mut s: Stat, node: Option<crate::devnodes::Node>) -> Stat {
    if let Some(n) = node {
        s.st_mode = n.kind | (s.st_mode & 0o7777);
        s.st_rdev = crate::devnodes::makedev(n.major, n.minor);
        s.st_size = 0;
    }
    s
}

/// An `open` with Linux `flags` of a device: checked against the cgroup's
/// device programs, then, for one of fwe's nodes (`node_file`, open on
/// `fd`), the host device its numbers name, or `fd` itself for a loop
/// device.
pub(crate) fn open_device(
    fd: i32,
    node: crate::devnodes::Node,
    flags: u64,
    node_file: bool,
) -> i64 {
    use crate::bpf::{BPF_DEVCG_ACC_READ, BPF_DEVCG_ACC_WRITE};
    let access = match flags & fcntl::O_ACCMODE {
        fcntl::O_RDONLY => BPF_DEVCG_ACC_READ,
        fcntl::O_WRONLY => BPF_DEVCG_ACC_WRITE,
        _ => BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE,
    };
    if let Err(e) = crate::cgroupfs::check_device(access, node.bpf_type(), node.major, node.minor) {
        return err(e);
    }
    if !node_file {
        return fd as i64;
    }
    // A loop device is its node's descriptor, marked as the device by the
    // caller ([`crate::loopdev`]).
    if crate::loopdev::is_loop_node(node) {
        return match crate::loopdev::check_open(node) {
            Ok(()) => fd as i64,
            Err(e) => err(e),
        };
    }
    let Some(host) = crate::devnodes::host_device(node) else {
        return err(crate::devnodes::NO_DEVICE);
    };
    let host_flags = host::open_flags_to_host(
        flags & !(fcntl::O_CREAT | fcntl::O_EXCL | fcntl::O_TRUNC | fcntl::O_DIRECTORY),
    );
    // SAFETY: a NUL-terminated host path.
    let dev = unsafe { libc::open(host.as_ptr(), host_flags, 0) };
    if dev < 0 {
        return last_error();
    }
    if crate::devnodes::full(node) {
        crate::fdmarks::mark(dev, crate::fdmarks::Mark::DevFull);
    }
    dev as i64
}

/// Open the file `fd` is open on afresh, with Linux open `flags`: a new
/// open file description of it, as opening `/proc/self/fd/N` makes.
/// A FIFO opened ahead ([`crate::fs::take_fifo`]), close-on-exec as the
/// guest's Linux `flags` ask.
pub(crate) fn fifo_flags(fd: i32, flags: u64) -> i32 {
    if flags & fcntl::O_CLOEXEC == 0 {
        // SAFETY: plain host call on the descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    }
    fd
}

fn reopen(fd: i32, flags: u64) -> i64 {
    let origin = crate::fdmarks::origin(fd);
    let writes = flags & fcntl::O_ACCMODE != fcntl::O_RDONLY || flags & fcntl::O_TRUNC != 0;
    if writes && origin.as_ref().is_some_and(|o| o.flags & crate::mounts::ms::RDONLY != 0) {
        return err(errno::EROFS);
    }
    let Some(host) = crate::fs::host_path_of(fd) else { return err(errno::ENOENT) };
    let Ok(p) = CString::new(host) else { return err(errno::EINVAL) };
    // A FIFO opened already, waiting for its other end without the lock.
    let st = stat_fd(fd).ok();
    if let Some(st) = st.filter(|st| st.st_mode & libc::S_IFMT == libc::S_IFIFO)
        && let Some(new) = crate::fs::take_fifo(flags, &st)
    {
        let new = fifo_flags(new, flags);
        crate::fdmarks::duplicated(fd, new);
        return new as i64;
    }
    // The host flags, without those that would make a new file.
    let host_flags = host::open_flags_to_host(flags & !(fcntl::O_CREAT | fcntl::O_EXCL));
    // SAFETY: a NUL-terminated host path.
    let new = unsafe { libc::open(p.as_ptr(), host_flags, 0) };
    if new < 0 {
        return last_error();
    }
    match crate::mountapi::detached_root(fd) {
        // Through a detached tree's descriptor: a file open in that tree's
        // mount, with its flags (a read-only clone stays read-only).
        Some((id, mflags, fstype)) => crate::fdmarks::opened_in_tree(new, id, mflags, fstype),
        None => crate::fdmarks::duplicated(fd, new),
    }
    new as i64
}

/// The filesystem holding host descriptor `fd`, written to `buf` in Linux
/// layout, as the mount it is in shows it: its type and its flags.
fn statfs_fd(fd: i32, buf: u64, mount: Option<(crate::mounts::FsType, u64)>) -> i64 {
    // SAFETY: zeroed bytes are a valid `statfs`; `fstatfs` fills it.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out parameter.
    if unsafe { libc::fstatfs(fd, &mut s) } < 0 {
        return last_error();
    }
    let mut out = host::statfs_to_linux(&s);
    if let Some((fstype, flags)) = mount {
        out.f_type = fstype.magic();
        out.f_flags = statfs_flags(flags);
    }
    guest!(uaccess::write(buf, out));
    0
}

/// `statfs`'s `f_flags` of a mount with `flags`.
fn statfs_flags(flags: u64) -> i64 {
    use crate::mounts::ms;
    use fwe_abi::statfs::*;
    let mut f = ST_VALID;
    for (m, st) in [
        (ms::RDONLY, ST_RDONLY),
        (ms::NOSUID, ST_NOSUID),
        (ms::NODEV, ST_NODEV),
        (ms::NOEXEC, ST_NOEXEC),
        (ms::NOATIME, ST_NOATIME),
        (ms::NODIRATIME, ST_NODIRATIME),
        (ms::RELATIME, ST_RELATIME),
        (ms::NOSYMFOLLOW, ST_NOSYMFOLLOW),
    ] {
        if flags & m != 0 {
            f |= st;
        }
    }
    f
}

/// `statfs` of the filesystem of fwe's store `file` is in, through a mount
/// with `flags`, into guest `buf`.
fn store_statfs(file: crate::filestore::desc::File, flags: u64, buf: u64) -> i64 {
    match crate::filestore::io::statfs_file(file) {
        Ok(mut out) => {
            out.f_flags = statfs_flags(flags);
            guest!(uaccess::write(buf, out));
            0
        }
        Err(e) => err(e),
    }
}

/// `renameat2`'s flags.
const RENAME_NOREPLACE: u64 = 1;
const RENAME_EXCHANGE: u64 = 2;
const RENAME_WHITEOUT: u64 = 4;

/// What `renameat2`'s `flags` ask for: `EINVAL` for an unknown flag or
/// one that cannot go with another.
fn rename_mode(flags: u64) -> Result<host::Rename, i32> {
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || flags & RENAME_EXCHANGE != 0 && flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0
    {
        return Err(errno::EINVAL);
    }
    Ok(if flags & RENAME_EXCHANGE != 0 {
        host::Rename::Exchange
    } else if flags & RENAME_NOREPLACE != 0 {
        host::Rename::NoReplace
    } else {
        host::Rename::Replace
    })
}

/// Rename `on` in `od` to `nn` in `nd` as `how` says, leaving a whiteout
/// (one of fwe's device nodes numbered 0:0) at the old name if
/// `whiteout`.
fn rename(
    od: i32,
    on: &CString,
    nd: i32,
    nn: &CString,
    how: host::Rename,
    whiteout: bool,
) -> Result<(), i32> {
    host::rename_at(od, on, nd, nn, how)?;
    if whiteout {
        let node = crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: 0, minor: 0 };
        crate::devnodes::make(od, on, node, 0o600)?;
    }
    Ok(())
}

fn make_pipe(fds: &mut [i32; 2], flags: u64) -> Result<(), i32> {
    // Linux's flags (`O_NOTIFICATION_PIPE` is `O_EXCL`'s bit); a
    // notification pipe needs the watch queue, which a kernel without one
    // refuses with `ENOPKG`.
    if flags & !(fcntl::O_CLOEXEC | fcntl::O_NONBLOCK | fcntl::O_DIRECT | fcntl::O_EXCL) != 0 {
        return Err(errno::EINVAL);
    }
    if flags & fcntl::O_EXCL != 0 {
        return Err(errno::ENOPKG);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut host = 0;
        if flags & fcntl::O_NONBLOCK != 0 {
            host |= libc::O_NONBLOCK;
        }
        if flags & fcntl::O_CLOEXEC != 0 {
            host |= libc::O_CLOEXEC;
        }
        // SAFETY: `fds` is a valid array of two ints.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), host) } < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `fds` is a valid array of two ints.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        for &fd in fds.iter() {
            if flags & fcntl::O_CLOEXEC != 0 {
                // SAFETY: plain host call on a fresh fd.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            if flags & fcntl::O_NONBLOCK != 0 {
                // SAFETY: plain host call on a fresh fd.
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn getdents64(fd: i32, buf: u64, count: usize, _hide: &dyn Fn(&[u8]) -> bool) -> i64 {
    // On a Linux host the kernel produces the exact arm64 layout.
    // SAFETY: the guest passed a buffer of `count` bytes.
    ret(unsafe { libc::syscall(libc::SYS_getdents64, fd, buf as *mut libc::c_void, count) })
}

#[cfg(target_os = "macos")]
fn getdents64(fd: i32, buf: u64, count: usize, hide: &dyn Fn(&[u8]) -> bool) -> i64 {
    use fwe_abi::DIRENT64_HEADER;

    // The `__getdirentries64` syscall produces the 64-bit-inode layout (the
    // plain `getdirentries` C symbol is the legacy 32-bit variant). Entries:
    // struct dirent { u64 d_ino; u64 d_seekoff; u16 d_reclen; u16 d_namlen;
    // u8 d_type; char d_name[]; }.
    const SYS___GETDIRENTRIES64: libc::c_int = 344;
    const BSD_HEADER: usize = 21;

    // Where the stream stands, so entries fetched from the host but not
    // delivered can be re-read next time. `d_seekoff` is 0 on APFS, so the
    // position has to come from the descriptor itself.
    // SAFETY: plain host call on a guest fd.
    let start = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if start < 0 {
        return last_error();
    }
    // The entries listed so far; each one's `d_off` is the count through it.
    let base = listed_of(fd).unwrap_or(0);
    // A translated record can be up to 4 bytes longer than the host's (they
    // round to 8 and 4 bytes), so a host buffer of `count` bytes may yield a
    // little more than fits. When it does, the stream is rewound and re-read
    // with exactly the host bytes that did fit.
    let mut size = count;
    loop {
        let mut bsd = vec![0u8; size];
        let mut position: libc::off_t = 0;
        // SAFETY: `bsd` is a valid buffer; the syscall advances the fd offset
        // and writes the new position through `position`.
        let n = unsafe {
            libc::syscall(
                SYS___GETDIRENTRIES64,
                fd,
                bsd.as_mut_ptr(),
                bsd.len(),
                &mut position as *mut libc::off_t,
            )
        };
        if n < 0 {
            return last_error();
        }
        let n = n as usize;
        let mut src = 0usize;
        let mut out: Vec<u8> = Vec::with_capacity(count);
        let mut overflow = false;
        let mut listed = 0u64;
        while src + BSD_HEADER <= n {
            let rec = &bsd[src..];
            let d_ino = u64::from_ne_bytes(rec[0..8].try_into().unwrap());
            let d_reclen = u16::from_ne_bytes(rec[16..18].try_into().unwrap()) as usize;
            let d_namlen = u16::from_ne_bytes(rec[18..20].try_into().unwrap()) as usize;
            let d_type = rec[20];
            if d_reclen == 0 || src + BSD_HEADER + d_namlen > n {
                break;
            }
            let name = &rec[BSD_HEADER..BSD_HEADER + d_namlen];
            if hide(name) {
                src += d_reclen;
                continue;
            }

            let out_len = (DIRENT64_HEADER + d_namlen + 1).div_ceil(8) * 8;
            if out.len() + out_len > count {
                overflow = true;
                break;
            }

            // The linux_dirent64 header (packed in the ABI), the name, then
            // zeros for its terminator and the padding.
            let at = out.len();
            out.resize(at + out_len, 0);
            let rec = &mut out[at..];
            rec[0..8].copy_from_slice(&d_ino.to_ne_bytes());
            // Its position: entries listed through it ([`dir_lseek`]).
            listed += 1;
            rec[8..16].copy_from_slice(&((base + listed) as i64).to_ne_bytes());
            rec[16..18].copy_from_slice(&(out_len as u16).to_ne_bytes());
            rec[18] = d_type;
            rec[DIRENT64_HEADER..DIRENT64_HEADER + d_namlen].copy_from_slice(name);
            src += d_reclen;
        }
        if !overflow {
            if crate::uaccess::write_from(buf, &out).is_err() {
                // Leave the stream where it was, as if nothing was read.
                // SAFETY: plain host call on a guest fd.
                unsafe { libc::lseek(fd, start, libc::SEEK_SET) };
                return err(errno::EFAULT);
            }
            set_listed(fd, base + listed);
            return out.len() as i64;
        }
        if src == 0 {
            // Not even the first entry fits: the guest's buffer is too small.
            return err(errno::EINVAL);
        }
        // SAFETY: plain host call on a guest fd, back to where this call began.
        if unsafe { libc::lseek(fd, start, libc::SEEK_SET) } < 0 {
            return last_error();
        }
        size = src;
    }
}

/// What a listing of the host directory open as `fd` leaves out: the
/// hidden names of `O_TMPFILE` files, and what fwe keeps in a cgroup's
/// directory.
fn listing_hides(fd: i32) -> impl Fn(&[u8]) -> bool {
    let cgroup =
        crate::fdmarks::origin(fd).is_some_and(|o| o.fstype == crate::mounts::FsType::Cgroup2);
    move |name: &[u8]| {
        (cgroup && (name == crate::cgroupfs::PRIVATE || name.ends_with(b".fwe-new")))
            || name.starts_with(crate::tmpfile::PREFIX)
    }
}

/// `lseek` of a host directory `getdents64` listed (`None` for any other
/// descriptor): its entries' `d_off` are positions in the listing (APFS
/// gives none), so a position is reached by listing that many entries
/// from the start again; `SEEK_CUR` counts from the position reached.
#[cfg(target_os = "macos")]
pub(crate) fn dir_lseek(fd: i32, off: i64, whence: i32) -> Option<i64> {
    if !crate::fdstate::DIRS_LISTED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let at = listed_of(fd)?;
    let to = match whence {
        libc::SEEK_SET => off,
        libc::SEEK_CUR => (at as i64).saturating_add(off),
        _ => return Some(err(errno::EINVAL)),
    };
    if to < 0 {
        return Some(err(errno::EINVAL));
    }
    if whence == libc::SEEK_CUR && off == 0 {
        return Some(to);
    }
    // SAFETY: plain host call on the guest's directory.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Some(last_error());
    }
    if let Err(e) = skip_entries(fd, to as u64, &listing_hides(fd)) {
        return Some(err(e));
    }
    set_listed(fd, to as u64);
    Some(to)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn dir_lseek(_fd: i32, _off: i64, _whence: i32) -> Option<i64> {
    None
}

/// How many entries of the directory open as `fd` `getdents64` listed from
/// its start, if it listed this directory through `fd`.
#[cfg(target_os = "macos")]
fn listed_of(fd: i32) -> Option<u64> {
    let (dev, ino, n) = crate::fdstate::get(fd).dir_pos?;
    (host_identity(fd)? == (dev, ino)).then_some(n)
}

/// `n` entries of the directory open as `fd` are listed from its start.
#[cfg(target_os = "macos")]
fn set_listed(fd: i32, n: u64) {
    let Some((dev, ino)) = host_identity(fd) else { return };
    crate::fdstate::update(fd, |s| s.dir_pos = Some((dev, ino, n)));
    crate::fdstate::DIRS_LISTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Read past the next `n` entries of the directory open as `fd` (those
/// `hide` leaves out not counted), the host's position left right after
/// the last of them.
#[cfg(target_os = "macos")]
fn skip_entries(fd: i32, mut n: u64, hide: &dyn Fn(&[u8]) -> bool) -> Result<(), i32> {
    const SYS___GETDIRENTRIES64: libc::c_int = 344;
    const BSD_HEADER: usize = 21;
    let mut bsd = vec![0u8; 1 << 16];
    while n > 0 {
        // SAFETY: plain host call on the guest's directory.
        let start = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        let mut position: libc::off_t = 0;
        // SAFETY: a valid buffer; the call writes the new position.
        let got = unsafe {
            libc::syscall(SYS___GETDIRENTRIES64, fd, bsd.as_mut_ptr(), bsd.len(), &mut position)
        };
        if got <= 0 {
            // The end, or an error: as far as the directory goes.
            return if got < 0 {
                Err(crate::host::errno_to_linux(crate::host::last_errno()))
            } else {
                Ok(())
            };
        }
        // The bytes of the entries up to the `n`th shown, and how many
        // shown entries the first `upto` bytes hold.
        let walk = |bsd: &[u8], got: usize, upto: Option<u64>| {
            let (mut src, mut seen) = (0usize, 0u64);
            while src + BSD_HEADER <= got && upto.is_none_or(|u| seen < u) {
                let rec = &bsd[src..];
                let reclen = u16::from_ne_bytes(rec[16..18].try_into().unwrap()) as usize;
                let namlen = u16::from_ne_bytes(rec[18..20].try_into().unwrap()) as usize;
                if reclen == 0 || src + BSD_HEADER + namlen > got {
                    break;
                }
                if !hide(&rec[BSD_HEADER..BSD_HEADER + namlen]) {
                    seen += 1;
                }
                src += reclen;
            }
            (src, seen)
        };
        let got = got as usize;
        let (src, seen) = walk(&bsd, got, Some(n));
        if src >= got {
            n -= seen;
            continue;
        }
        // Past the last one in this batch: read again just up to it (the
        // host may give fewer records than the bytes hold; the loop takes
        // the rest).
        // SAFETY: plain host calls on the guest's directory, a buffer of
        // at least `src` bytes.
        let again = unsafe {
            libc::lseek(fd, start, libc::SEEK_SET);
            libc::syscall(SYS___GETDIRENTRIES64, fd, bsd.as_mut_ptr(), src, &mut position)
        };
        if again <= 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        n -= walk(&bsd, again as usize, None).1;
    }
    Ok(())
}

impl<P: Platform> Kernel<P> {
    /// A synthetic `/proc` or `/sys` directory's status: links as Linux
    /// counts a directory's, its `.`, its entry in its parent and each
    /// subdirectory's `..` (a process's `task` directory 2 and its threads,
    /// which sandboxes read to tell a process is single-threaded).
    fn synth_dir_stat(&self, dirfd: i32, path: &[u8]) -> Stat {
        let subdirs = self.fs().synth_children(dirfd, path).map_or(0, |entries| {
            entries
                .iter()
                .filter(|(n, t)| *t == crate::procfs::DT_DIR && n != b"." && n != b"..")
                .count()
        });
        Stat { st_nlink: 2 + subdirs as u32, ..synth_stat(fwe_abi::stat::S_IFDIR | 0o555, 0) }
    }
}

/// Build a synthetic `struct stat` for a `/proc` or `/sys` entry.
fn synth_stat(mode: u32, size: u64) -> Stat {
    Stat {
        st_mode: mode,
        st_nlink: 1,
        st_size: size as i64,
        st_blksize: 4096,
        st_blocks: size.div_ceil(512) as i64,
        ..Stat::default()
    }
}

/// Write back and drop from the host's cache the pages of the regular file
/// open at `fd` (`size` bytes long) over `[offset, offset + len)`, to its
/// end if `len` is 0: what `POSIX_FADV_DONTNEED` asks. A shared mapping of
/// the range, synced and invalidated, does it: changes made through any
/// other mapping or `write` are written first, so none is lost.
#[cfg(target_os = "macos")]
fn drop_cached(fd: i32, offset: u64, len: u64, size: u64) {
    // SAFETY: plain host call.
    let page = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as u64;
    let start = offset & !(page - 1);
    let end = if len == 0 { size } else { offset.saturating_add(len).min(size) };
    if end <= start {
        return;
    }
    let span = (end - start) as usize;
    let map = |fd: i32| {
        // SAFETY: a fresh read-only shared mapping of part of the file.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                span,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                start as libc::off_t,
            )
        };
        (m != libc::MAP_FAILED).then_some(m)
    };
    match map(fd) {
        // SAFETY: the mapping made above, synced, invalidated and unmapped.
        Some(m) => unsafe {
            libc::msync(m, span, libc::MS_SYNC | libc::MS_INVALIDATE);
            libc::munmap(m, span);
        },
        // A write-only descriptor cannot be mapped, and fwe opens no other
        // of the file ([`crate::reclocks`]): its changes are written back,
        // its pages left.
        // SAFETY: plain host call on the guest's descriptor.
        None => unsafe {
            libc::fsync(fd);
        },
    }
}

/// For a call that makes a file not a directory at `path`, resolved as `r`
/// ([`crate::fs::Fs::resolve_entry`]): a trailing slash asks for a
/// directory, so a name that is missing is `ENOENT`, as Linux says (one
/// that is there is the call's own `EEXIST`).
fn made_not_dir(r: &crate::fs::Resolved, path: &[u8]) -> Result<(), i32> {
    let missing = match &r.ovl {
        Some(o) => matches!(o.found, crate::overlay::Found::Missing),
        None => r.lstat().is_none(),
    };
    if crate::fs::trailing_slash(path) && missing { Err(errno::ENOENT) } else { Ok(()) }
}

/// For a call that removes or renames the name resolved as `r`
/// ([`crate::fs::Fs::resolve_entry`]): with a trailing slash (`slash`),
/// the name must be a directory (not a link to one), else `ENOTDIR`.
fn removed_dir_only(r: &crate::fs::Resolved, slash: bool) -> Result<(), i32> {
    if !slash {
        return Ok(());
    }
    let other = match &r.ovl {
        Some(o) => matches!(o.found, crate::overlay::Found::Other { .. }),
        None => r.lstat().is_some_and(|st| st.st_mode & libc::S_IFMT != libc::S_IFDIR),
    };
    if other { Err(errno::ENOTDIR) } else { Ok(()) }
}

/// For an `O_PATH` stand-in descriptor (`fd` is host `/dev/null`, see
/// [`crate::fdmarks::stand_in`]): the directory and name of the file it
/// names, for a change of that file; `None` for any other descriptor.
fn stand_in_at(fd: i32) -> Option<Result<(std::os::fd::OwnedFd, CString), i32>> {
    let host = crate::fdmarks::stand_in(fd)?;
    let i = host.iter().rposition(|&b| b == b'/')?;
    let dir = if i == 0 { b"/".to_vec() } else { host[..i].to_vec() };
    Some((|| {
        let name = CString::new(&host[i + 1..]).map_err(|_| errno::ENOENT)?;
        let dir = CString::new(dir).map_err(|_| errno::ENOENT)?;
        // SAFETY: a NUL-terminated path; the result is checked and owned.
        let d = unsafe {
            libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if d < 0 {
            return Err(host::errno_to_linux(host::last_errno()));
        }
        // SAFETY: a descriptor just opened, owned here.
        Ok((unsafe { std::os::fd::FromRawFd::from_raw_fd(d) }, name))
    })())
}

/// [`set_times_fd`]'s touch of an append-only file, for the file at host
/// path `path` (the name itself, not followed).
#[cfg(target_os = "macos")]
fn touch_append_only(path: &std::ffi::CStr, times: *const libc::timespec) -> i64 {
    let mut st = zeroed_stat();
    // SAFETY: a NUL-terminated path and a valid out-parameter.
    if unsafe { libc::lstat(path.as_ptr(), &mut st) } != 0 {
        return err(errno::EPERM);
    }
    let fixed = libc::UF_IMMUTABLE | libc::SF_IMMUTABLE | libc::SF_APPEND;
    if st.st_flags & libc::UF_APPEND == 0 || st.st_flags & fixed != 0 {
        return err(errno::EPERM);
    }
    // SAFETY: plain host calls on a NUL-terminated path; the flags go back.
    unsafe {
        if libc::lchflags(path.as_ptr(), st.st_flags & !libc::UF_APPEND) != 0 {
            return err(errno::EPERM);
        }
        let r = libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times, libc::AT_SYMLINK_NOFOLLOW);
        let e = host::last_errno();
        libc::lchflags(path.as_ptr(), st.st_flags);
        if r == 0 { 0 } else { err(host::errno_to_linux(e)) }
    }
}

/// Set the times of the file open as `fd` (`times` as `futimens` takes
/// them). Linux lets an append-only file's times both be set to now
/// (`touch`), and no other way; the host refuses any (`EPERM`), so for a
/// touch the flag is taken off the file for the change, by its owner.
fn set_times_fd(fd: i32, times: *const libc::timespec, touch: bool) -> i64 {
    // SAFETY: `times` is null or the caller's array of two.
    let both = (!times.is_null()).then(|| unsafe { [*times, *times.add(1)] });
    if let Some(r) = crate::filestore::io::set_times(fd, both, touch) {
        return r;
    }
    // SAFETY: valid timespec array pointer or null.
    let r = unsafe { libc::futimens(fd, times) };
    #[cfg(target_os = "macos")]
    if r != 0 && host::last_errno() == libc::EPERM && touch {
        let Ok(st) = stat_fd(fd) else { return err(errno::EPERM) };
        let fixed = libc::UF_IMMUTABLE | libc::SF_IMMUTABLE | libc::SF_APPEND;
        if st.st_flags & libc::UF_APPEND == 0 || st.st_flags & fixed != 0 {
            return err(errno::EPERM);
        }
        // SAFETY: plain host calls on the descriptor; the flags go back.
        unsafe {
            if libc::fchflags(fd, st.st_flags & !libc::UF_APPEND) != 0 {
                return err(errno::EPERM);
            }
            let r = libc::futimens(fd, times);
            let e = host::last_errno();
            libc::fchflags(fd, st.st_flags);
            return if r == 0 { 0 } else { err(host::errno_to_linux(e)) };
        }
    }
    let _ = touch;
    ret(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Kernel, Platform, Tracer};
    use fwe_abi::{Stat, nr};
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// `pipe2` takes Linux's flags only (`EINVAL` for others), and a
    /// notification pipe, which needs the watch queue, is `ENOPKG`.
    #[test]
    fn pipe2_flags_are_checked() {
        let mut fds = [0i32; 2];
        assert_eq!(make_pipe(&mut fds, 0o1), Err(errno::EINVAL));
        assert_eq!(make_pipe(&mut fds, fcntl::O_EXCL), Err(errno::ENOPKG));
        assert_eq!(make_pipe(&mut fds, fcntl::O_CLOEXEC | fcntl::O_DIRECT), Ok(()));
        // SAFETY: the pipe just made.
        unsafe { (libc::close(fds[0]), libc::close(fds[1])) };
    }

    struct NoPlatform;
    impl Platform for NoPlatform {
        fn prepare_exec(
            &mut self,
            _addr: u64,
            _len: u64,
            _known: Option<&[(u64, u64)]>,
            _cache: Option<&[u8]>,
        ) -> Result<(), crate::PrepareFailed> {
            Ok(())
        }
        fn exit(&mut self, code: i32) -> ! {
            panic!("exit({code})")
        }
        fn exit_thread(&mut self, code: i32) -> ! {
            panic!("exit_thread({code})")
        }
        fn kill_self(&mut self, sig: libc::c_int) -> ! {
            panic!("killed by {sig}")
        }
    }

    /// A test's temporary root directory, removed when the test is done.
    struct TempRoot(std::path::PathBuf);

    impl std::ops::Deref for TempRoot {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl AsRef<std::path::Path> for TempRoot {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A kernel rooted at a fresh temporary directory, returned with it.
    fn rooted() -> (Kernel<NoPlatform>, TempRoot) {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fwe-fs-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Fs::new(Some(dir.as_os_str().as_encoded_bytes())).unwrap();
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let k = Kernel::new(
            NoPlatform,
            page,
            Brk { start: 0, current: 0, limit: 0 },
            Some(root),
            Tracer::default(),
        );
        (k, TempRoot(dir))
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    const AT_FDCWD: u64 = -100i64 as u64;

    fn open(k: &mut Kernel<NoPlatform>, path: &CString, flags: u64, mode: u64) -> i64 {
        k.syscall(nr::OPENAT, [AT_FDCWD, path.as_ptr() as u64, flags, mode, 0, 0])
    }

    /// `setns` into the caller's own user namespace is refused (`EINVAL`),
    /// with or without `CAP_SYS_ADMIN`, and its capabilities stay as they
    /// were, as Linux's `userns_install` has it.
    #[test]
    fn setns_into_its_own_user_namespace_is_invalid() {
        use fwe_abi::clone::CLONE_NEWUSER;
        let (mut k, _d) = rooted();
        let fd =
            crate::nsfd::open(crate::nsfd::NsRef { kind: CLONE_NEWUSER, id: 1, dir: None }, true)
                as i32;
        assert!(fd >= 0);
        assert_eq!(k.sys_setns(fd as u64, CLONE_NEWUSER), err(errno::EINVAL));
        k.creds.caps.effective &= !(1 << crate::caps::CAP_SYS_ADMIN);
        let before = k.creds.caps;
        assert_eq!(k.sys_setns(fd as u64, 0), err(errno::EINVAL));
        assert_eq!(k.creds.caps, before);
        crate::nsfd::closed(fd);
        // SAFETY: the descriptor `open` made.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn open_write_read_stat() {
        use fwe_abi::fcntl::{O_CREAT, O_RDWR};
        let (mut k, _d) = rooted();
        let p = cstr("/hello.txt");
        let fd = open(&mut k, &p, O_CREAT | O_RDWR, 0o644);
        assert!(fd >= 0, "openat: {fd}");
        let data = b"filesystem works\n";
        assert_eq!(
            k.syscall(nr::WRITE, [fd as u64, data.as_ptr() as u64, data.len() as u64, 0, 0, 0]),
            data.len() as i64
        );
        assert_eq!(k.syscall(nr::LSEEK, [fd as u64, 0, 0, 0, 0, 0]), 0);
        let mut buf = [0u8; 64];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], data);

        let mut st = Stat::default();
        assert_eq!(k.syscall(nr::FSTAT, [fd as u64, &mut st as *mut _ as u64, 0, 0, 0, 0]), 0);
        assert_eq!(st.st_size, data.len() as i64);
        assert_eq!(st.st_mode & fwe_abi::stat::S_IFMT, fwe_abi::stat::S_IFREG);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // newfstatat by path agrees.
        let mut st2 = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, p.as_ptr() as u64, &mut st2 as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(st2.st_size, data.len() as i64);
    }

    /// A buffer too small for a whole directory delivers every entry exactly
    /// once across calls: what the host returned but did not fit is re-read,
    /// not dropped and not repeated.
    #[test]
    fn getdents_small_buffer_delivers_each_entry_once() {
        use fwe_abi::fcntl::{O_DIRECTORY, O_RDONLY};
        let (mut k, _d) = rooted();
        let want: Vec<String> = (0..40).map(|i| format!("entry-number-{i:02}")).collect();
        for name in &want {
            let path = cstr(&format!("/{name}"));
            assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, path.as_ptr() as u64, 0o755, 0, 0, 0]), 0);
        }
        let root = cstr("/");
        let fd = open(&mut k, &root, O_RDONLY | O_DIRECTORY, 0);
        assert!(fd >= 0);
        let mut buf = [0u8; 100];
        let mut names = Vec::new();
        for _ in 0..1000 {
            let n = k.syscall(
                nr::GETDENTS64,
                [fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0],
            );
            assert!(n >= 0, "getdents64: {n}");
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n as usize {
                let reclen =
                    u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 19..off + reclen];
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                names.push(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
                off += reclen;
            }
        }
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        names.retain(|n| n != "." && n != "..");
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "an entry was delivered twice: {names:?}");
        assert_eq!(sorted, want);
    }

    #[test]
    fn mkdir_and_getdents() {
        use fwe_abi::fcntl::{O_DIRECTORY, O_RDONLY};
        let (mut k, _d) = rooted();
        for name in ["/a", "/b", "/c"] {
            assert_eq!(
                k.syscall(nr::MKDIRAT, [AT_FDCWD, cstr(name).as_ptr() as u64, 0o755, 0, 0, 0]),
                0
            );
        }
        let root = cstr("/");
        let fd = open(&mut k, &root, O_RDONLY | O_DIRECTORY, 0);
        assert!(fd >= 0);
        let mut buf = [0u8; 4096];
        let mut names = Vec::new();
        loop {
            let n = k.syscall(
                nr::GETDENTS64,
                [fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0],
            );
            assert!(n >= 0, "getdents64: {n}");
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n as usize {
                let reclen =
                    u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 19..off + reclen];
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                names.push(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
                off += reclen;
            }
        }
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        for want in ["a", "b", "c"] {
            assert!(names.iter().any(|n| n == want), "missing {want} in {names:?}");
        }
    }

    #[test]
    fn symlinks_are_contained() {
        use fwe_abi::fcntl::O_WRONLY;
        let (mut k, dir) = rooted();
        // A file reachable only within the root.
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/secret"), b"in-root").unwrap();
        // An absolute symlink that would escape on the host.
        assert_eq!(
            k.syscall(
                nr::SYMLINKAT,
                [cstr("/etc").as_ptr() as u64, AT_FDCWD, cstr("/esc").as_ptr() as u64, 0, 0, 0]
            ),
            0
        );
        // "/esc/passwd" resolves under the root, not the host's /etc.
        let fd = open(&mut k, &cstr("/esc/passwd"), O_WRONLY, 0);
        assert_eq!(fd, err(errno::ENOENT), "symlink escaped the root");

        // ".." cannot climb above the root.
        let fd = open(&mut k, &cstr("/../../real/secret"), 0, 0);
        assert!(fd >= 0, "dotdot clamp: {fd}");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // A relative symlink within the root resolves normally.
        assert_eq!(
            k.syscall(
                nr::SYMLINKAT,
                [
                    cstr("real/secret").as_ptr() as u64,
                    AT_FDCWD,
                    cstr("/link").as_ptr() as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        let fd = open(&mut k, &cstr("/link"), 0, 0);
        assert!(fd >= 0, "relative symlink: {fd}");
        let mut buf = [0u8; 16];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 16, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"in-root");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // readlinkat returns the stored target without following it.
        let mut link = [0u8; 64];
        let n = k.syscall(
            nr::READLINKAT,
            [AT_FDCWD, cstr("/esc").as_ptr() as u64, link.as_mut_ptr() as u64, 64, 0, 0],
        );
        assert_eq!(&link[..n as usize], b"/etc");
    }

    #[test]
    fn cwd_and_relative_paths() {
        use fwe_abi::fcntl::{O_CREAT, O_WRONLY};
        let (mut k, _d) = rooted();
        assert_eq!(
            k.syscall(nr::MKDIRAT, [AT_FDCWD, cstr("/sub").as_ptr() as u64, 0o755, 0, 0, 0]),
            0
        );
        assert_eq!(k.syscall(nr::CHDIR, [cstr("/sub").as_ptr() as u64, 0, 0, 0, 0, 0]), 0);

        let mut buf = [0u8; 64];
        let n = k.syscall(nr::GETCWD, [buf.as_mut_ptr() as u64, 64, 0, 0, 0, 0]);
        assert!(n > 0);
        assert_eq!(&buf[..n as usize], b"/sub\0");

        // A relative create lands in /sub.
        let fd = open(&mut k, &cstr("f"), O_CREAT | O_WRONLY, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let mut st = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/sub/f").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
    }

    /// An `O_CREAT` open succeeds while another process keeps unlinking and
    /// recreating the name, as on Linux (the macOS host fails such opens
    /// with `ENOENT` now and then).
    #[cfg(target_os = "macos")]
    #[test]
    fn create_survives_a_racing_unlink() {
        use fwe_abi::fcntl::{O_CLOEXEC, O_CREAT, O_RDWR};
        let (mut k, dir) = rooted();
        let host = std::ffi::CString::new(dir.join("f").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the child makes only raw system calls until it is killed.
        let child = unsafe { libc::fork() };
        if child == 0 {
            loop {
                // SAFETY: plain host calls on a NUL-terminated path.
                unsafe {
                    libc::unlink(host.as_ptr());
                    let fd = libc::open(host.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644);
                    libc::close(fd);
                }
            }
        }
        let failures = (0..20_000)
            .filter(|_| {
                let fd = open(&mut k, &cstr("/f"), O_CREAT | O_RDWR | O_CLOEXEC, 0o644);
                // SAFETY: closing a test fd (or nothing, on failure).
                unsafe { libc::close(fd as i32) };
                fd < 0
            })
            .count();
        // SAFETY: ending and reaping the child forked above.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(failures, 0);
    }

    #[test]
    fn statfs_of_a_path_in_the_root() {
        let (mut k, _d) = rooted();
        let mut st = fwe_abi::Statfs::default();
        let p = &mut st as *mut _ as u64;
        assert_eq!(k.syscall(nr::STATFS, [cstr("/").as_ptr() as u64, p, 0, 0, 0, 0]), 0);
        assert!(st.f_bsize > 0 && st.f_blocks > 0, "{st:?}");
        let missing = cstr("/no/such/dir/x");
        assert_eq!(
            k.syscall(nr::STATFS, [missing.as_ptr() as u64, p, 0, 0, 0, 0]),
            err(errno::ENOENT)
        );
    }

    #[test]
    fn unlink_and_rename() {
        use fwe_abi::fcntl::{O_CREAT, O_WRONLY};
        let (mut k, _d) = rooted();
        let fd = open(&mut k, &cstr("/x"), O_CREAT | O_WRONLY, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        assert_eq!(
            k.syscall(
                nr::RENAMEAT2,
                [AT_FDCWD, cstr("/x").as_ptr() as u64, AT_FDCWD, cstr("/y").as_ptr() as u64, 0, 0]
            ),
            0
        );
        let mut st = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/x").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            err(errno::ENOENT)
        );
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            0
        );
        // The flagless renameat, which glibc's `rename` uses on arm64.
        assert_eq!(
            k.syscall(
                nr::RENAMEAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, AT_FDCWD, cstr("/z").as_ptr() as u64, 0, 0]
            ),
            0
        );
        assert_eq!(k.syscall(nr::UNLINKAT, [AT_FDCWD, cstr("/z").as_ptr() as u64, 0, 0, 0, 0]), 0);
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, cstr("/y").as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0]
            ),
            err(errno::ENOENT)
        );
    }

    #[test]
    fn synthetic_proc_and_sys() {
        use fwe_abi::stat as st;
        let (mut k, _d) = rooted();
        k.fs.as_mut().unwrap().set_proc_info(
            b"/bin/prog".to_vec(),
            b"prog\0-x\0".to_vec(),
            4,
            b"host".to_vec(),
        );

        // Read a known /proc file.
        let fd = open(&mut k, &cstr("/proc/sys/kernel/ostype"), 0, 0);
        assert!(fd >= 0, "open: {fd}");
        let mut buf = [0u8; 64];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"Linux\n");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // cmdline round-trips the NUL-joined argv.
        let fd = open(&mut k, &cstr("/proc/self/cmdline"), 0, 0);
        assert!(fd >= 0);
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(&buf[..n as usize], b"prog\0-x\0");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };

        // /proc/self/exe is a symlink to the program.
        let n = k.syscall(
            nr::READLINKAT,
            [AT_FDCWD, cstr("/proc/self/exe").as_ptr() as u64, buf.as_mut_ptr() as u64, 64, 0, 0],
        );
        assert_eq!(&buf[..n as usize], b"/bin/prog");

        // A /proc file stats as a regular file; an unknown one is ENOENT.
        let mut stbuf = Stat::default();
        assert_eq!(
            k.syscall(
                nr::NEWFSTATAT,
                [
                    AT_FDCWD,
                    cstr("/proc/cpuinfo").as_ptr() as u64,
                    &mut stbuf as *mut _ as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(stbuf.st_mode & st::S_IFMT, st::S_IFREG);
        assert_eq!(open(&mut k, &cstr("/proc/nonexistent"), 0, 0), err(errno::ENOENT));
    }

    /// A directory entry's `d_off` is a position `lseek` returns to (as
    /// `telldir` and `seekdir` use it): listing from there goes on with
    /// the next entry.
    #[cfg(target_os = "macos")]
    #[test]
    fn getdents_offsets_seek_back() {
        use fwe_abi::fcntl::{O_DIRECTORY, O_RDONLY};
        let (mut k, _d) = rooted();
        for i in 0..30 {
            let path = cstr(&format!("/entry-{i:02}"));
            assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, path.as_ptr() as u64, 0o755, 0, 0, 0]), 0);
        }
        let fd = open(&mut k, &cstr("/"), O_RDONLY | O_DIRECTORY, 0) as u64;
        let list = |k: &mut Kernel<NoPlatform>, size: usize| {
            let mut buf = vec![0u8; size];
            let n = k.syscall(nr::GETDENTS64, [fd, buf.as_mut_ptr() as u64, size as u64, 0, 0, 0]);
            assert!(n >= 0);
            let mut out = Vec::new();
            let mut at = 0usize;
            while at < n as usize {
                let off = i64::from_ne_bytes(buf[at + 8..at + 16].try_into().unwrap());
                let len = u16::from_ne_bytes(buf[at + 16..at + 18].try_into().unwrap()) as usize;
                let name = &buf[at + 19..at + len];
                let name = name[..name.iter().position(|&b| b == 0).unwrap()].to_vec();
                out.push((name, off));
                at += len;
            }
            out
        };
        let mut all = Vec::new();
        loop {
            let got = list(&mut k, 120);
            if got.is_empty() {
                break;
            }
            all.extend(got);
        }
        assert!(all.len() >= 32, "{}", all.len());
        let (_, tenth) = &all[9];
        assert_eq!(k.syscall(nr::LSEEK, [fd, *tenth as u64, 0, 0, 0, 0]), *tenth);
        assert_eq!(k.syscall(nr::LSEEK, [fd, 0, 1, 0, 0, 0]), *tenth);
        assert_eq!(list(&mut k, 120)[0], all[10]);
        assert_eq!(k.syscall(nr::LSEEK, [fd, 0, 0, 0, 0, 0]), 0);
        assert_eq!(list(&mut k, 120)[0], all[0]);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
    }

    /// A trailing slash names a directory in every call, as on Linux: a
    /// lookup follows a final link and finds anything else `ENOTDIR`; a
    /// call that removes or renames the name needs a directory there (a
    /// link to one is not); one that makes a file finds no directory to
    /// make (`ENOENT`), or the name taken (`EEXIST`).
    #[test]
    fn a_trailing_slash_names_a_directory() {
        use fwe_abi::fcntl::{AT_REMOVEDIR, AT_SYMLINK_NOFOLLOW, O_CREAT, O_RDWR};
        let (mut k, _d) = rooted();
        let fd = open(&mut k, &cstr("/f"), O_CREAT | O_RDWR, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let call = |k: &mut Kernel<NoPlatform>, n: u64, a: [u64; 5]| {
            k.syscall(n, [a[0], a[1], a[2], a[3], a[4], 0])
        };
        let p = |s: &str| cstr(s);
        let at = AT_FDCWD;
        assert_eq!(call(&mut k, nr::MKDIRAT, [at, p("/d").as_ptr() as u64, 0o755, 0, 0]), 0);
        for (t, l) in [("/d", "/l"), ("/f", "/lf")] {
            let r =
                call(&mut k, nr::SYMLINKAT, [p(t).as_ptr() as u64, at, p(l).as_ptr() as u64, 0, 0]);
            assert_eq!(r, 0);
        }
        let stat = |k: &mut Kernel<NoPlatform>, s: &str, flags: u64| {
            let mut st = Stat::default();
            let path = p(s);
            let r = k.syscall(
                nr::NEWFSTATAT,
                [at, path.as_ptr() as u64, &mut st as *mut _ as u64, flags, 0, 0],
            );
            if r < 0 { Err(r) } else { Ok(st.st_mode & fwe_abi::stat::S_IFMT) }
        };
        let nofollow = AT_SYMLINK_NOFOLLOW;
        assert_eq!(stat(&mut k, "/f/", 0), Err(err(errno::ENOTDIR)));
        assert_eq!(stat(&mut k, "/d/", 0), Ok(fwe_abi::stat::S_IFDIR));
        assert_eq!(stat(&mut k, "/l/", nofollow), Ok(fwe_abi::stat::S_IFDIR));
        assert_eq!(stat(&mut k, "/lf/", nofollow), Err(err(errno::ENOTDIR)));
        let path_call = |k: &mut Kernel<NoPlatform>, n: u64, s: &str, b: u64, c: u64| {
            let path = p(s);
            k.syscall(n, [at, path.as_ptr() as u64, b, c, 0, 0])
        };
        assert_eq!(path_call(&mut k, nr::FCHMODAT, "/f/", 0o600, 0), err(errno::ENOTDIR));
        assert_eq!(path_call(&mut k, nr::UNLINKAT, "/f/", 0, 0), err(errno::ENOTDIR));
        assert_eq!(path_call(&mut k, nr::UNLINKAT, "/d/", 0, 0), err(errno::EISDIR));
        assert_eq!(path_call(&mut k, nr::UNLINKAT, "/l/", AT_REMOVEDIR, 0), err(errno::ENOTDIR));
        let node = u64::from(libc::S_IFREG) | 0o644;
        assert_eq!(path_call(&mut k, nr::MKNODAT, "/new/", node, 0), err(errno::ENOENT));
        assert_eq!(path_call(&mut k, nr::MKNODAT, "/f/", node, 0), err(errno::EEXIST));
        assert_eq!(path_call(&mut k, nr::MKDIRAT, "/f/", 0o755, 0), err(errno::EEXIST));
        assert_eq!(path_call(&mut k, nr::MKDIRAT, "/n/", 0o755, 0), 0);
        let rename = |k: &mut Kernel<NoPlatform>, a: &str, b: &str| {
            let (a, b) = (p(a), p(b));
            k.syscall(nr::RENAMEAT2, [at, a.as_ptr() as u64, at, b.as_ptr() as u64, 0, 0])
        };
        assert_eq!(rename(&mut k, "/f/", "/g"), err(errno::ENOTDIR));
        assert_eq!(rename(&mut k, "/f", "/g/"), err(errno::ENOTDIR));
        assert_eq!(rename(&mut k, "/n/", "/m/"), 0);
        assert_eq!(path_call(&mut k, nr::UNLINKAT, "/m/", AT_REMOVEDIR, 0), 0);
    }

    /// `mkdir` keeps the permission and sticky bits of its mode: a set-ID
    /// bit asked for is dropped, and a directory is set-group-ID only in a
    /// set-group-ID directory.
    #[test]
    fn mkdir_takes_no_set_id_bits_of_its_mode() {
        let (mut k, _d) = rooted();
        let mode_of = |k: &mut Kernel<NoPlatform>, p: &CString| {
            let mut st = Stat::default();
            let r = k.syscall(
                nr::NEWFSTATAT,
                [AT_FDCWD, p.as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0],
            );
            assert_eq!(r, 0);
            st.st_mode & 0o7777
        };
        k.fs.as_mut().unwrap().set_umask(0);
        let mut mkdir = |p: &CString, mode: u64| {
            assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, p.as_ptr() as u64, mode, 0, 0, 0]), 0);
        };
        let (a, b) = (cstr("/a"), cstr("/a/b"));
        mkdir(&a, 0o7777);
        mkdir(&b, 0o755);
        assert_eq!(mode_of(&mut k, &a), 0o1777);
        assert_eq!(mode_of(&mut k, &b), 0o755);
        let r = k.syscall(nr::FCHMODAT, [AT_FDCWD, a.as_ptr() as u64, 0o2777, 0, 0, 0]);
        assert_eq!(r, 0);
        let c = cstr("/a/c");
        assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, c.as_ptr() as u64, 0o4755, 0, 0, 0]), 0);
        assert_eq!(mode_of(&mut k, &c), 0o2755, "set-group-ID from its directory");
    }

    /// `statx` reports the host's birth time (`STATX_BTIME`), by path and
    /// by descriptor.
    #[cfg(target_os = "macos")]
    #[test]
    fn statx_reports_the_birth_time() {
        use fwe_abi::fcntl::{AT_EMPTY_PATH, O_CREAT, O_RDWR};
        let (mut k, _d) = rooted();
        let p = cstr("/born");
        let fd = open(&mut k, &p, O_CREAT | O_RDWR, 0o644);
        assert!(fd >= 0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        for (dirfd, path, flags) in [(AT_FDCWD, &p, 0), (fd as u64, &cstr(""), AT_EMPTY_PATH)] {
            let mut x = Statx::default();
            let r = k.syscall(
                nr::STATX,
                [dirfd, path.as_ptr() as u64, flags, 0xfff, &mut x as *mut _ as u64, 0],
            );
            assert_eq!(r, 0);
            assert_ne!(x.stx_mask & statx_mask::STATX_BTIME, 0);
            let born = x.stx_btime.tv_sec as u64;
            assert!(born > 0 && born <= now.as_secs() + 1, "{born}");
            assert!(x.stx_btime.tv_sec <= x.stx_mtime.tv_sec);
        }
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
    }

    /// A device node outside `/dev`, opened only to read by a path the host
    /// could look up in one call, is the device, not the empty file that
    /// stands for it; its `stat` is the device's too.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_device_node_opened_to_read_is_the_device() {
        let (mut k, _d) = rooted();
        let p = cstr("/zero");
        let mode = u64::from(libc::S_IFCHR) | 0o666;
        let dev = (1 << 8) | 5;
        let r = k.syscall(nr::MKNODAT, [AT_FDCWD, p.as_ptr() as u64, mode, dev, 0, 0]);
        assert_eq!(r, 0);
        let fd = open(&mut k, &p, 0, 0);
        assert!(fd >= 0, "open: {fd}");
        let mut buf = [1u8; 4];
        let n = k.syscall(nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 4, 0, 0, 0]);
        assert_eq!((n, buf), (4, [0; 4]), "read as /dev/zero");
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let mut st = Stat::default();
        let r = k.syscall(
            nr::NEWFSTATAT,
            [AT_FDCWD, p.as_ptr() as u64, &mut st as *mut _ as u64, 0, 0, 0],
        );
        assert_eq!(r, 0);
        assert_eq!(st.st_mode & fwe_abi::stat::S_IFMT, fwe_abi::stat::S_IFCHR);
        assert_eq!(st.st_rdev, dev);
    }

    /// `faccessat` checks the guest's ids against the file's guest owner
    /// and mode as `open` does: the real ids by default (without the
    /// capabilities of an effective root), the effective ones with
    /// `AT_EACCESS`; the walk searches as the same ids; root passes all but
    /// running a file nobody may run, and searches a directory of no
    /// execute bit.
    #[test]
    fn access_checks_the_guests_ids_as_open_does() {
        use fwe_abi::fcntl::{AT_EACCESS, F_OK, O_CREAT, O_RDWR, R_OK, W_OK, X_OK};
        let (mut k, _d) = rooted();
        let f = cstr("/f");
        let fd = open(&mut k, &f, O_CREAT | O_RDWR, 0o640);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let dir = cstr("/d");
        assert_eq!(k.syscall(nr::MKDIRAT, [AT_FDCWD, dir.as_ptr() as u64, 0o600, 0, 0, 0]), 0);
        let inner = cstr("/d/g");
        let fd = open(&mut k, &inner, O_CREAT | O_RDWR, 0o644);
        assert!(fd >= 0);
        // SAFETY: closing a test fd.
        unsafe { libc::close(fd as i32) };
        let access = |k: &Kernel<NoPlatform>, p: &CString, mode: u64, flags: u64| {
            k.sys_faccessat(AT_FDCWD, p.as_ptr() as u64, mode, flags)
        };
        // Root: everything but executing a file of no execute bit; a
        // directory of none is searched.
        assert_eq!(access(&k, &f, R_OK | W_OK, 0), 0);
        assert_eq!(access(&k, &f, X_OK, 0), err(errno::EACCES));
        assert_eq!(access(&k, &dir, X_OK, 0), 0);
        // Called directly, never published: other tests' walks are not
        // this user's.
        let c = &mut k.creds;
        (c.uid, c.euid, c.suid, c.fsuid) = (1000, 1000, 1000, 1000);
        (c.gid, c.egid, c.sgid, c.fsgid) = (1000, 1000, 1000, 1000);
        c.groups = vec![1000];
        c.caps.effective = 0;
        c.caps.permitted = 0;
        assert_eq!(access(&k, &f, F_OK, 0), 0);
        assert_eq!(access(&k, &f, R_OK, 0), err(errno::EACCES), "others may not read");
        // The group's bits for a member of the file's group.
        k.creds.groups = vec![1000, 0];
        assert_eq!(access(&k, &f, R_OK, 0), 0);
        assert_eq!(access(&k, &f, W_OK, 0), err(errno::EACCES));
        // A directory the caller may not search hides what is in it.
        assert_eq!(access(&k, &inner, F_OK, 0), err(errno::EACCES));
        // An effective root whose real user is not: the real ids, with no
        // capabilities, unless asked for the effective ones.
        k.creds.groups = vec![1000];
        (k.creds.euid, k.creds.fsuid) = (0, 0);
        k.creds.caps.effective = crate::caps::INITIAL;
        k.creds.caps.permitted = crate::caps::INITIAL;
        assert_eq!(access(&k, &f, R_OK, 0), err(errno::EACCES));
        assert_eq!(access(&k, &inner, F_OK, 0), err(errno::EACCES));
        assert_eq!(access(&k, &f, R_OK | W_OK, AT_EACCESS), 0);
        assert_eq!(access(&k, &inner, R_OK, AT_EACCESS), 0);
        // A real root that is not effective: its permitted capabilities.
        (k.creds.uid, k.creds.euid, k.creds.fsuid) = (0, 1000, 1000);
        k.creds.caps.effective = 0;
        assert_eq!(access(&k, &f, R_OK | W_OK, 0), 0);
        assert_eq!(access(&k, &f, R_OK, AT_EACCESS), err(errno::EACCES));
    }
}
