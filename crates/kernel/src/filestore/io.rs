//! The guest's calls on descriptors of the store's files ([`super::desc`]):
//! reads and writes, the position, status, size, space and seals.
//!
//! A descriptor's access mode, status flags (`O_APPEND`, `O_NONBLOCK`) and
//! position are its host stand-in's, so duplicates and processes sharing
//! the description share them as Linux's share an open file's. A call
//! holds the file's filesystem for its whole transfer, so a write is
//! atomic against the file's other writes and reads, as Linux's are under
//! the inode's lock.

use super::desc::{self, File};
use super::tree::{self, Ino, Stat, Tx};
use super::{data, fs::Writable};
use crate::uaccess;
use fwe_abi::{err, errno, fcntl};

/// Seals that freeze the contents.
pub const WRITE_SEALS: u32 = fcntl::F_SEAL_WRITE | fcntl::F_SEAL_FUTURE_WRITE;

/// The host status flags of `fd`.
fn status(fd: i32) -> Result<i32, i32> {
    // SAFETY: plain host call on the guest's descriptor.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 { Err(last()) } else { Ok(fl) }
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// Whether `fd` (of the store) is open for reading and for writing.
pub fn access(fd: i32) -> Result<(bool, bool), i32> {
    let mode = status(fd)? & libc::O_ACCMODE;
    Ok((mode != libc::O_WRONLY, mode != libc::O_RDONLY))
}

/// The position of `fd`.
fn position(fd: i32) -> Result<u64, i32> {
    // SAFETY: plain host call on the guest's descriptor.
    match unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } {
        p if p < 0 => Err(last()),
        p => Ok(p as u64),
    }
}

fn set_position(fd: i32, at: u64) {
    // SAFETY: plain host call on the guest's descriptor.
    unsafe { libc::lseek(fd, at as libc::off_t, libc::SEEK_SET) };
}

/// The mount flags a read through `fd` moves the access time by
/// ([`Tx::accessed`]): its mount's, or `noatime`'s for a descriptor opened
/// with `O_NOATIME`.
fn atime_flags(fd: i32) -> u64 {
    if crate::atime::noatime_fd(fd) {
        return crate::mounts::ms::NOATIME;
    }
    crate::fdmarks::origin(fd).map_or(0, |o| o.flags)
}

/// The file `fd` is a descriptor of, held.
fn with_file<R>(
    fd: i32,
    f: impl FnOnce(File, &mut Tx) -> Result<R, i32>,
) -> Option<Result<R, i32>> {
    Some(in_file(desc::of(fd)?, f))
}

/// `f` on `file`, its filesystem held.
fn in_file<R>(file: File, f: impl FnOnce(File, &mut Tx) -> Result<R, i32>) -> Result<R, i32> {
    let fs = file.fs()?;
    let mut t = fs.lock()?;
    f(file, &mut t)
}

/// The host `stat` of `ino` of a filesystem on device `dev`, as the guest's
/// own file's is kept ([`crate::fsops`] makes it Linux's).
pub fn host_stat(dev: u64, st: &Stat) -> libc::stat {
    // SAFETY: an all-zero `stat` is a valid value.
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    s.st_dev = dev as libc::dev_t;
    s.st_ino = st.ino as libc::ino_t;
    s.st_mode = st.mode as libc::mode_t;
    s.st_nlink = st.nlink as libc::nlink_t;
    s.st_uid = st.uid;
    s.st_gid = st.gid;
    s.st_rdev = st.rdev as libc::dev_t;
    s.st_size = st.size as libc::off_t;
    s.st_blocks = (st.allocated / 512) as libc::blkcnt_t;
    // The immutable and append-only flags as the host's own are kept.
    #[cfg(target_os = "macos")]
    {
        if st.flags & FS_IMMUTABLE_FL != 0 {
            s.st_flags |= libc::UF_IMMUTABLE;
        }
        if st.flags & FS_APPEND_FL != 0 {
            s.st_flags |= libc::UF_APPEND;
        }
    }
    s.st_blksize = crate::maps::page_size().max(4096) as libc::blksize_t;
    let split = |t: i64| (t.div_euclid(1_000_000_000), t.rem_euclid(1_000_000_000));
    (s.st_atime, s.st_atime_nsec) = split(st.atime);
    (s.st_mtime, s.st_mtime_nsec) = split(st.mtime);
    (s.st_ctime, s.st_ctime_nsec) = split(st.ctime);
    #[cfg(target_os = "macos")]
    {
        (s.st_birthtime, s.st_birthtime_nsec) = split(st.btime);
    }
    s
}

/// The host `stat` of the file `fd` is a descriptor of, if it is one of
/// the store's.
pub fn stat(fd: i32) -> Option<Result<libc::stat, i32>> {
    with_file(fd, |file, t| Ok(host_stat(t.dev(), &t.stat(file.ino)?)))
}

/// Copy `n` bytes at `off` of `object` (none yet: zeroes) to the guest's
/// memory at host address `to`.
fn copy_out(object: u64, off: u64, to: u64, n: u64) -> Result<(), i32> {
    if object == 0 {
        const ZEROES: [u8; 4096] = [0; 4096];
        let mut done = 0;
        while done < n {
            let k = (n - done).min(ZEROES.len() as u64);
            uaccess::write_host(to + done, &ZEROES[..k as usize])?;
            done += k;
        }
        return Ok(());
    }
    data::with_bytes(object, off, n, |p| {
        // SAFETY: `n` bytes of the object's mapping, kept for the call.
        uaccess::write_host(to, unsafe { std::slice::from_raw_parts(p, n as usize) })
    })?
}

/// Copy `n` bytes of the guest's memory at host address `from` to `off` of
/// `object`.
fn copy_in(m: &data::Mapped, off: u64, from: u64, n: u64) -> Result<(), i32> {
    // SAFETY: `n` bytes of the object's mapping, which `m` keeps.
    uaccess::read_host(from, unsafe { std::slice::from_raw_parts_mut(m.at(off), n as usize) })
}

/// The read and write calls (`read`, `pwrite64`, `readv`, `pwritev2`, ...)
/// on a descriptor of the store (`None` for another descriptor).
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    let single = matches!(nr, n::READ | n::WRITE | n::PREAD64 | n::PWRITE64);
    let vectored =
        matches!(nr, n::READV | n::WRITEV | n::PREADV | n::PWRITEV | n::PREADV2 | n::PWRITEV2);
    if !single && !vectored {
        return None;
    }
    let fd = a[0] as i32;
    let file = desc::of(fd)?;
    let write = matches!(nr, n::WRITE | n::WRITEV | n::PWRITE64 | n::PWRITEV | n::PWRITEV2);
    let pos = match nr {
        n::READ | n::WRITE | n::READV | n::WRITEV => None,
        n::PREADV2 | n::PWRITEV2 if a[3] as i64 == -1 => None,
        _ if (a[3] as i64) < 0 => return Some(err(errno::EINVAL)),
        _ => Some(a[3]),
    };
    let mut append_flag = false;
    if matches!(nr, n::PREADV2 | n::PWRITEV2) {
        use fwe_abi::rwf;
        if a[5] & !(rwf::HIPRI | rwf::DSYNC | rwf::SYNC | rwf::NOWAIT | rwf::APPEND) != 0 {
            return Some(err(errno::EOPNOTSUPP));
        }
        append_flag = write && a[5] & rwf::APPEND != 0;
    }
    let bufs = if single {
        uaccess::host_buffer(a[1], a[2], !write).map(|v| vec![v])
    } else {
        uaccess::host_iovecs(a[1], a[2], !write)
    };
    Some(match bufs.and_then(|iov| transfer(fd, file, &iov, pos, write, append_flag)) {
        Ok(n) => n as i64,
        Err(e) => err(e),
    })
}

/// Read or write the buffers `iov` (host addresses of the guest's memory)
/// at `pos` (`None`: the descriptor's position, which moves on).
fn transfer(
    fd: i32,
    file: File,
    iov: &[libc::iovec],
    pos: Option<u64>,
    write: bool,
    append_flag: bool,
) -> Result<u64, i32> {
    let fl = status(fd)?;
    let mode = fl & libc::O_ACCMODE;
    if (write && mode == libc::O_RDONLY) || (!write && mode == libc::O_WRONLY) {
        return Err(errno::EBADF);
    }
    let total: u64 = iov.iter().map(|v| v.iov_len as u64).sum();
    if total > isize::MAX as u64 {
        return Err(errno::EINVAL);
    }
    // Linux appends with `O_APPEND` whatever the offset says.
    let append = write && (fl & libc::O_APPEND != 0 || append_flag);
    let start = match pos {
        Some(p) => p,
        None => position(fd)?,
    };
    let fs = file.fs()?;
    let mut t = fs.lock()?;
    let (done, end, object, mapped) = if write {
        write_locked(&mut t, file.ino, start, iov, total, append)?
    } else {
        let (object, n) = t.readable(file.ino, start, total)?;
        if n > 0 {
            t.accessed(file.ino, atime_flags(fd))?;
        }
        let mut done = 0;
        for v in iov.iter().filter(|v| v.iov_len > 0) {
            let k = (v.iov_len as u64).min(n - done);
            if k == 0 {
                break;
            }
            if let Err(e) = copy_out(object, start + done, v.iov_base as u64, k) {
                if done == 0 {
                    return Err(e);
                }
                break;
            }
            done += k;
        }
        (done, start + done, object, None)
    };
    drop(t);
    if object != 0 {
        desc::made_data(file, object, mapped);
    }
    if pos.is_none() {
        set_position(fd, end);
    }
    Ok(done)
}

/// A write of `total` bytes of `iov` at `start` (the end if `append`) of
/// `ino`, as its seals allow: how many were written, where they ended, the
/// file's data object.
fn write_locked(
    t: &mut Tx,
    ino: Ino,
    start: u64,
    iov: &[libc::iovec],
    total: u64,
    append: bool,
) -> Result<(u64, u64, u64, Option<data::Mapped>), i32> {
    unchangeable(t, ino, append)?;
    let seals = t.seals(ino)?;
    if seals & WRITE_SEALS != 0 {
        return Err(errno::EPERM);
    }
    let size = t.stat(ino)?.size;
    let start = if append { size } else { start };
    let mut total = total;
    if seals & fcntl::F_SEAL_GROW != 0 && start.saturating_add(total) > size {
        // What lies within the file goes; none of it: refused.
        total = size.saturating_sub(start);
        if total == 0 {
            return Err(errno::EPERM);
        }
    }
    if total == 0 {
        return Ok((0, start, t.data(ino)?, None));
    }
    let Writable { object, off, fits } = t.writable(ino, start, total, false)?;
    let m = data::mapped(object, off + fits)?;
    let mut done = 0;
    for v in iov.iter().filter(|v| v.iov_len > 0) {
        let k = (v.iov_len as u64).min(fits - done);
        if k == 0 {
            break;
        }
        if let Err(e) = copy_in(&m, off + done, v.iov_base as u64, k) {
            if done == 0 {
                return Err(e);
            }
            break;
        }
        done += k;
    }
    if done > 0 {
        t.wrote(ino, off + done)?;
    }
    Ok((done, off + done, object, Some(m)))
}

/// `lseek` on a descriptor of the store (`None` for another).
pub fn lseek(fd: i32, off: i64, whence: i32) -> Option<i64> {
    const SEEK_DATA: i32 = 3;
    const SEEK_HOLE: i32 = 4;
    let r = with_file(fd, |file, t| {
        let st = t.stat(file.ino)?;
        let size = st.size as i64;
        let cur = position(fd)? as i64;
        let data_at = |from: u64| -> Result<Option<(u64, u64)>, i32> {
            // The ranges that hold memory are the file's data; the rest of
            // it, holes.
            let page = data::PAGE;
            Ok(t.ranges_of(file.ino)?
                .into_iter()
                .map(|(s, e)| (s * page, (e * page).min(st.size)))
                .find(|&(_, e)| e > from))
        };
        // A directory's position is an entry's number, set or moved only.
        if st.mode & tree::S_IFMT == tree::S_IFDIR
            && !matches!(whence, libc::SEEK_SET | libc::SEEK_CUR)
        {
            return Err(errno::EINVAL);
        }
        let new = match whence {
            libc::SEEK_SET => off,
            libc::SEEK_CUR => cur.checked_add(off).ok_or(errno::EOVERFLOW)?,
            libc::SEEK_END => size.checked_add(off).ok_or(errno::EOVERFLOW)?,
            SEEK_DATA | SEEK_HOLE if off < 0 || off >= size => return Err(errno::ENXIO),
            SEEK_DATA => match data_at(off as u64)? {
                Some((s, _)) => s.max(off as u64) as i64,
                None => return Err(errno::ENXIO),
            },
            SEEK_HOLE => match data_at(off as u64)? {
                Some((s, e)) if s <= off as u64 => e as i64,
                _ => off,
            },
            _ => return Err(errno::EINVAL),
        };
        if new < 0 {
            return Err(errno::EINVAL);
        }
        set_position(fd, new as u64);
        Ok(new)
    })?;
    Some(r.unwrap_or_else(err))
}

/// `ftruncate` of a descriptor of the store (`None` for another), as the
/// file's seals allow.
pub fn ftruncate(fd: i32, len: i64) -> Option<i64> {
    desc::of(fd)?;
    let r = (|| {
        if len < 0 {
            return Err(errno::EINVAL);
        }
        if !access(fd)?.1 {
            return Err(errno::EINVAL);
        }
        truncate_file(desc::of(fd).ok_or(errno::EBADF)?, len as u64)
    })();
    Some(r.map_or_else(err, |()| 0))
}

/// Cut or grow regular file `file` to `len` bytes, as its seals and flags
/// allow (`EPERM`).
pub fn truncate_file(file: File, len: u64) -> Result<(), i32> {
    in_file(file, |file, t| {
        let st = t.stat(file.ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::EINVAL);
        }
        unchangeable(t, file.ino, false)?;
        let seals = t.seals(file.ino)?;
        if (len < st.size && seals & fcntl::F_SEAL_SHRINK != 0)
            || (len > st.size && seals & fcntl::F_SEAL_GROW != 0)
        {
            return Err(errno::EPERM);
        }
        t.truncate(file.ino, len)
    })
}

/// `fallocate` of a descriptor of the store (`None` for another).
pub fn fallocate(fd: i32, mode: u64, off: u64, len: u64) -> Option<i64> {
    use fwe_abi::falloc::*;
    desc::of(fd)?;
    let r = (|| {
        if (off as i64) < 0 || (len as i64) <= 0 {
            return Err(errno::EINVAL);
        }
        if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0 {
            return Err(errno::EOPNOTSUPP);
        }
        let punch = mode & FALLOC_FL_PUNCH_HOLE != 0;
        let zero = mode & FALLOC_FL_ZERO_RANGE != 0;
        // A hole is punched only keeping the size, and not with zeroing.
        if punch && (mode & FALLOC_FL_KEEP_SIZE == 0 || zero) {
            return Err(errno::EOPNOTSUPP);
        }
        if !access(fd)?.1 {
            return Err(errno::EBADF);
        }
        if (off as i64).checked_add(len as i64).is_none() {
            return Err(errno::EFBIG);
        }
        with_file(fd, |file, t| {
            let st = t.stat(file.ino)?;
            // Allocating at the end of an append-only file appends.
            unchangeable(t, file.ino, !punch && !zero)?;
            let seals = t.seals(file.ino)?;
            if (punch || zero) && seals & WRITE_SEALS != 0 {
                return Err(errno::EPERM);
            }
            let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
            if !keep && off + len > st.size && seals & fcntl::F_SEAL_GROW != 0 {
                return Err(errno::EPERM);
            }
            if zero {
                // Zeroes, the range's memory taken as an allocation's.
                t.allocate_data(file.ino, off, len, true, true)?;
                return t.allocate_data(file.ino, off, len, keep, false);
            }
            t.allocate_data(file.ino, off, len, keep, punch)
        })
        .unwrap_or(Err(errno::EBADF))
    })();
    Some(r.map_or_else(err, |()| 0))
}

/// `F_GET_SEALS` of a descriptor of the store (`None` for another).
pub fn get_seals(fd: i32) -> Option<i64> {
    let r = with_file(fd, |file, t| t.seals(file.ino))?;
    Some(r.map_or_else(err, |s| s as i64))
}

/// `F_ADD_SEALS` of a descriptor of the store (`None` for another): only
/// on a descriptor open for writing, of a file that allows sealing; a seal
/// freezing the contents not while the file is mapped shared and writable
/// (`EBUSY`).
pub fn add_seals(fd: i32, add: u64) -> Option<i64> {
    const ALL: u32 = fcntl::F_SEAL_SEAL
        | fcntl::F_SEAL_SHRINK
        | fcntl::F_SEAL_GROW
        | fcntl::F_SEAL_WRITE
        | fcntl::F_SEAL_FUTURE_WRITE
        | fcntl::F_SEAL_EXEC;
    desc::of(fd)?;
    let r = (|| {
        if add & !(ALL as u64) != 0 {
            return Err(errno::EINVAL);
        }
        if !access(fd)?.1 {
            return Err(errno::EPERM);
        }
        with_file(fd, |file, t| {
            let now = t.seals(file.ino)?;
            if now & fcntl::F_SEAL_SEAL != 0 {
                return Err(errno::EPERM);
            }
            let add = add as u32;
            if add & fcntl::F_SEAL_WRITE != 0 && now & fcntl::F_SEAL_WRITE == 0 {
                let dev = t.dev();
                if crate::maps::record().shared_writable(dev, file.ino) {
                    return Err(errno::EBUSY);
                }
            }
            t.set_seals(file.ino, now | add)
        })
        .unwrap_or(Err(errno::EBADF))
    })();
    Some(r.map_or_else(err, |()| 0))
}

/// For `mmap` of a descriptor of the store (`None` for another), with
/// Linux's `prot` and `flags`: the host descriptor of the file's data to
/// map (its object, made if the file had none), open for writing only for a
/// shared mapping of a descriptor that may write, and whether a shared
/// mapping may never be made writable (the contents are sealed).
pub fn map_source(
    fd: i32,
    prot: u64,
    flags: u64,
) -> Option<Result<(std::os::fd::OwnedFd, bool), i32>> {
    use fwe_abi::mman;
    let file = desc::of(fd)?;
    Some((|| {
        let (reads, writes) = access(fd)?;
        // A mapping reads the file.
        if !reads {
            return Err(errno::EACCES);
        }
        let shared = flags & mman::MAP_TYPE != mman::MAP_PRIVATE;
        // A shared mapping to write needs a descriptor that may, before any
        // seal is looked at.
        if shared && prot & mman::PROT_WRITE != 0 && !writes {
            return Err(errno::EACCES);
        }
        let fs = file.fs()?;
        let mut t = fs.lock()?;
        if t.stat(file.ino)?.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::ENODEV);
        }
        let seals = t.seals(file.ino)?;
        let sealed = seals & WRITE_SEALS != 0;
        if shared && prot & mman::PROT_WRITE != 0 && sealed {
            return Err(errno::EPERM);
        }
        let object = match t.data(file.ino)? {
            0 => {
                let o = data::make()?;
                t.set_data(file.ino, o)?;
                o
            }
            o => o,
        };
        drop(t);
        desc::made_data(file, object, None);
        let host = data::open(object, !(shared && writes))?;
        Ok((host, shared && sealed))
    })())
}

/// `fchmod` of a descriptor of the store (`None` for another) to `mode`,
/// the bits the caller may give: refused (`EPERM`) where it changes the
/// execute bits of a file sealed against it (`F_SEAL_EXEC`).
pub fn fchmod(fd: i32, mode: u32) -> Option<i64> {
    Some(chmod_file(desc::of(fd)?, mode))
}

/// [`fchmod`] of `file`.
pub fn chmod_file(file: File, mode: u32) -> i64 {
    let r = in_file(file, |file, t| {
        unchangeable(t, file.ino, false)?;
        let old = t.stat(file.ino)?.mode;
        if (old ^ mode) & 0o111 != 0 && t.seals(file.ino)? & fcntl::F_SEAL_EXEC != 0 {
            return Err(errno::EPERM);
        }
        t.set_mode(file.ino, mode)
    });
    r.map_or_else(err, |()| 0)
}

/// `fchown` of a descriptor of the store (`None` for another) to `owner`,
/// with the mode it leaves the file (set-ID bits taken), if it changes it.
pub fn fchown(fd: i32, owner: (u32, u32), mode: Option<u32>) -> Option<i64> {
    Some(chown_file(desc::of(fd)?, owner, mode))
}

/// [`fchown`] of `file`; a regular file loses its file capabilities, as
/// Linux's change of owner takes them (`ATTR_KILL_PRIV`).
pub fn chown_file(file: File, owner: (u32, u32), mode: Option<u32>) -> i64 {
    let r = in_file(file, |file, t| {
        unchangeable(t, file.ino, false)?;
        t.set_owner(file.ino, Some(owner.0), Some(owner.1))?;
        if t.stat(file.ino)?.mode & tree::S_IFMT == tree::S_IFREG
            && t.xattr(file.ino, b"security.capability").is_ok()
        {
            t.set_xattr(file.ino, b"security.capability", None)?;
        }
        match mode {
            Some(m) => t.set_mode(file.ino, m),
            None => Ok(()),
        }
    });
    r.map_or_else(err, |()| 0)
}

/// Linux's inode flags a file of the store keeps (`FS_IOC_SETFLAGS`), as
/// its tmpfs does: immutable, append-only, no-dump, no-access-time.
const FS_IMMUTABLE_FL: u32 = 0x10;
const FS_APPEND_FL: u32 = 0x20;
const FS_NODUMP_FL: u32 = 0x40;
const FS_NOATIME_FL: u32 = 0x80;
const KEPT_FLAGS: u32 = FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL;

/// `getdents64` of a descriptor of the store (`None` for another) into
/// guest `buf` of `count` bytes: the directory's entries from the
/// description's position (an entry's own number, which `d_off` gives for
/// the next), as many as fit (`EINVAL` if not one does); a file that is no
/// directory has none (`ENOTDIR`), nor a directory removed (`ENOENT`).
pub fn getdents64(fd: i32, buf: u64, count: u64) -> Option<i64> {
    /// `struct linux_dirent64`'s fixed part: inode, offset, length, type.
    const HEAD: usize = 19;
    let r = with_file(fd, |file, t| {
        let st = t.stat(file.ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFDIR {
            return Err(errno::ENOTDIR);
        }
        if st.nlink == 0 {
            return Err(errno::ENOENT);
        }
        let pos = position(fd)?;
        // Each takes its fixed part, its name and a NUL, rounded up to 8.
        let entries = t.list(file.ino, pos, count as usize, HEAD + 1 + 7)?;
        if !entries.is_empty() {
            t.accessed(file.ino, atime_flags(fd))?;
        }
        Ok(entries)
    })?;
    let entries = match r {
        Ok(e) => e,
        Err(e) => return Some(err(e)),
    };
    if entries.is_empty() {
        // Nothing left, or a buffer too small for the next entry.
        let more = with_file(fd, |file, t| {
            Ok(!t.list(file.ino, position(fd)?, usize::MAX, 0)?.is_empty())
        })?;
        return Some(match more {
            Ok(true) => err(errno::EINVAL),
            Ok(false) => 0,
            Err(e) => err(e),
        });
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut last = 0;
    for e in &entries {
        let len = (HEAD + e.name.len() + 1 + 7) & !7;
        if out.len() + len > count as usize {
            break;
        }
        out.extend_from_slice(&e.ino.to_ne_bytes());
        out.extend_from_slice(&(e.pos as i64).to_ne_bytes());
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.push((e.kind >> 12) as u8);
        out.extend_from_slice(&e.name);
        out.resize(out.len() + len - HEAD - e.name.len(), 0);
        last = e.pos;
    }
    if let Err(e) = crate::uaccess::write_from(buf, &out) {
        return Some(err(e));
    }
    set_position(fd, last);
    Some(out.len() as i64)
}

/// `fstatfs` of a descriptor of the store (`None` for another): a tmpfs,
/// its size and inodes (none: no limit), what is left of them.
pub fn statfs(fd: i32) -> Option<Result<fwe_abi::Statfs, i32>> {
    Some(statfs_file(desc::of(fd)?))
}

/// [`statfs`] of the filesystem `file` is in.
pub fn statfs_file(file: File) -> Result<fwe_abi::Statfs, i32> {
    in_file(file, |_, t| {
        let bsize = crate::maps::page_size().max(4096);
        let (bytes, inodes) = t.limits();
        let (used, files) = t.usage();
        let (blocks, free) =
            if bytes == 0 { (0, 0) } else { (bytes / bsize, bytes.saturating_sub(used) / bsize) };
        let ffree = if inodes == 0 { 0 } else { inodes.saturating_sub(files) };
        Ok(fwe_abi::Statfs {
            f_type: crate::mounts::FsType::Tmpfs.magic(),
            f_bsize: bsize as i64,
            f_blocks: blocks,
            f_bfree: free,
            f_bavail: free,
            f_files: inodes,
            f_ffree: ffree,
            f_namelen: 255,
            f_frsize: bsize as i64,
            f_flags: fwe_abi::statfs::ST_VALID,
            ..Default::default()
        })
    })
}

/// Whether the file's inode flags keep it from changing (immutable), or
/// from changing but at its end (append-only): `EPERM` for the call.
fn unchangeable(t: &Tx, ino: Ino, appending: bool) -> Result<(), i32> {
    let flags = t.stat(ino)?.flags;
    if flags & FS_IMMUTABLE_FL != 0 || (flags & FS_APPEND_FL != 0 && !appending) {
        return Err(errno::EPERM);
    }
    Ok(())
}

/// `ioctl` of a descriptor of the store (`None` for another, or for a
/// request on the descriptor itself: `FIOCLEX`, `FIONBIO` and the like),
/// for a caller of `creds`: what Linux's tmpfs answers for a regular
/// file.
pub fn ioctl(fd: i32, req: u64, arg: u64, creds: &crate::creds::Creds) -> Option<i64> {
    use fwe_abi::ioctl as io;
    if matches!(req, io::FIOCLEX | io::FIONCLEX | io::FIONBIO | io::FIOASYNC) {
        return None;
    }
    let r = with_file(fd, |file, t| {
        let st = t.stat(file.ino)?;
        match req {
            io::FIONREAD => {
                let left = st.size.saturating_sub(position(fd)?);
                uaccess::write(arg, left.min(i32::MAX as u64) as i32)?;
            }
            io::FIGETBSZ => {
                uaccess::write(arg, crate::maps::page_size().max(4096) as i32)?;
            }
            io::FS_IOC_GETFLAGS => uaccess::write(arg, st.flags)?,
            io::FS_IOC_FSGETXATTR => {
                let mut x = [0u32; 7];
                x[0] = to_xflags(st.flags);
                uaccess::write(arg, x)?;
            }
            io::FS_IOC_SETFLAGS => {
                let f: u32 = uaccess::read(arg)?;
                set_flags(t, file.ino, &st, f, creds)?;
            }
            io::FS_IOC_FSSETXATTR => {
                let x: [u32; 7] = uaccess::read(arg)?;
                // Extent sizes and projects are XFS's alone.
                if x[1] != 0 || x[3] != 0 || x[4] != 0 {
                    return Err(errno::EOPNOTSUPP);
                }
                set_flags(t, file.ino, &st, from_xflags(x[0])?, creds)?;
            }
            // `FICLONE`, `FICLONERANGE`, `FIDEDUPERANGE`: no shared extents.
            0x4004_9409 | 0x4020_940d | 0xc018_9436 => return Err(errno::EOPNOTSUPP),
            _ => return Err(errno::ENOTTY),
        }
        Ok(0)
    })?;
    Some(r.unwrap_or_else(err))
}

/// The inode flags of `file`, a regular file or directory (`ENOTTY` for
/// another, which has none).
pub fn flags_of(file: File) -> Result<u32, i32> {
    in_file(file, |file, t| {
        let st = t.stat(file.ino)?;
        if !matches!(st.mode & tree::S_IFMT, tree::S_IFREG | tree::S_IFDIR) {
            return Err(errno::ENOTTY);
        }
        Ok(st.flags)
    })
}

/// Set the inode flags of `file` to `f` ([`set_flags`]; `ENOTTY` for a
/// file that has none).
pub fn set_flags_of(file: File, f: u32, creds: &crate::creds::Creds) -> Result<(), i32> {
    in_file(file, |file, t| {
        let st = t.stat(file.ino)?;
        if !matches!(st.mode & tree::S_IFMT, tree::S_IFREG | tree::S_IFDIR) {
            return Err(errno::ENOTTY);
        }
        set_flags(t, file.ino, &st, f, creds)
    })
}

/// The XFS extended flags of inode flags `f`, and back.
fn to_xflags(f: u32) -> u32 {
    let pairs =
        [(FS_IMMUTABLE_FL, 0x8), (FS_APPEND_FL, 0x10), (FS_NOATIME_FL, 0x40), (FS_NODUMP_FL, 0x80)];
    pairs.iter().filter(|(fl, _)| f & fl != 0).map(|(_, x)| x).sum()
}

fn from_xflags(x: u32) -> Result<u32, i32> {
    let pairs =
        [(FS_IMMUTABLE_FL, 0x8), (FS_APPEND_FL, 0x10), (FS_NOATIME_FL, 0x40), (FS_NODUMP_FL, 0x80)];
    if x & !0xd8 != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    Ok(pairs.iter().filter(|(_, xf)| x & xf != 0).map(|(f, _)| f).sum())
}

/// Set `ino`'s inode flags to `f`, as Linux allows: the file's owner's
/// (or `CAP_FOWNER`'s) to change, the immutable and append-only flags
/// only with `CAP_LINUX_IMMUTABLE`, and no other flag (`EOPNOTSUPP`).
fn set_flags(
    t: &mut Tx,
    ino: Ino,
    st: &Stat,
    f: u32,
    creds: &crate::creds::Creds,
) -> Result<(), i32> {
    if st.uid != creds.fsuid && !creds.has_over(crate::caps::CAP_FOWNER, st.uid, st.gid) {
        return Err(errno::EPERM);
    }
    let fixed = FS_IMMUTABLE_FL | FS_APPEND_FL;
    if (f ^ st.flags) & fixed != 0 && !creds.has(crate::caps::CAP_LINUX_IMMUTABLE) {
        return Err(errno::EPERM);
    }
    if f & !KEPT_FLAGS != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    t.set_flags(ino, f)
}

/// Up to `len` bytes at `off` of the file `fd` is a descriptor of, if it
/// is one of the store's (its position as it was): what fwe reads of it
/// for itself (a program to run).
pub fn read_at(fd: i32, off: u64, len: u64) -> Option<Result<Vec<u8>, i32>> {
    with_file(fd, |file, t| {
        let (object, n) = t.readable(file.ino, off, len)?;
        if n > 0 {
            t.accessed(file.ino, atime_flags(fd))?;
        }
        let mut out = vec![0u8; n as usize];
        data::read(object, off, &mut out)?;
        Ok(out)
    })
}

/// The whole of regular file `file`, read through a mount with `flags`:
/// what fwe reads of it for itself (a program to run).
pub fn read_file(file: File, flags: u64) -> Result<Vec<u8>, i32> {
    in_file(file, |file, t| {
        let (object, n) = t.readable(file.ino, 0, u64::MAX)?;
        if n > 0 {
            t.accessed(file.ino, flags)?;
        }
        let mut out = vec![0u8; n as usize];
        data::read(object, 0, &mut out)?;
        Ok(out)
    })
}

/// Whether a description open for writing holds `file`, in a process that
/// lives: running it is `ETXTBSY`.
pub fn written(file: File) -> bool {
    in_file(file, |file, t| t.written(file.ino, desc::alive)).unwrap_or(false)
}

/// For `sendfile`, `splice` and `copy_file_range`: read up to `buf.len()`
/// bytes of the file `fd` is a descriptor of into fwe's `buf`, at `pos` or
/// at the descriptor's position (`None` for a descriptor not the store's).
pub fn read_into(fd: i32, buf: &mut [u8], pos: Option<u64>) -> Option<i64> {
    let file = desc::of(fd)?;
    let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    Some(transfer(fd, file, &[iov], pos, false, false).map_or_else(err, |n| n as i64))
}

/// For `sendfile`, `splice` and `copy_file_range`: write fwe's `buf` to the
/// file `fd` is a descriptor of, at `pos` or at the descriptor's position
/// (`None` for a descriptor not the store's).
pub fn write_at_pos(fd: i32, buf: &[u8], pos: Option<u64>) -> Option<i64> {
    let file = desc::of(fd)?;
    let iov = libc::iovec { iov_base: buf.as_ptr() as *mut _, iov_len: buf.len() };
    Some(transfer(fd, file, &[iov], pos, true, false).map_or_else(err, |n| n as i64))
}

/// `futimens` of a descriptor of the store (`None` for another), `times`
/// the host's (none: both now), `touch` if both are now: an immutable
/// file's are refused (`EPERM`), and an append-only file's but now.
pub fn set_times(fd: i32, times: Option<[libc::timespec; 2]>, touch: bool) -> Option<i64> {
    Some(set_times_file(desc::of(fd)?, times, touch))
}

/// [`set_times`] of `file`.
pub fn set_times_file(file: File, times: Option<[libc::timespec; 2]>, touch: bool) -> i64 {
    let r = in_file(file, |file, t| {
        let flags = t.stat(file.ino)?.flags;
        if flags & FS_IMMUTABLE_FL != 0 || (flags & FS_APPEND_FL != 0 && !touch) {
            return Err(errno::EPERM);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        let pick = |i: usize| -> Option<i64> {
            let Some(times) = times else { return Some(now) };
            match times[i].tv_nsec {
                libc::UTIME_OMIT => None,
                libc::UTIME_NOW => Some(now),
                n => Some(times[i].tv_sec * 1_000_000_000 + n),
            }
        };
        t.set_times(file.ino, pick(0), pick(1))
    });
    r.map_or_else(err, |()| 0)
}
