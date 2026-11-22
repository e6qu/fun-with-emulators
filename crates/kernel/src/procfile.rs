//! Open synthetic `/proc` and `/sys` files, served from memory.
//!
//! Such a file has no file on the host. Its contents are made as it is
//! opened and kept here, by descriptor, for the reads to take them from
//! ([`io`]). The guest's descriptor is one of the host's `/dev/null`,
//! open for what the guest asked (reading, writing or both): a number the
//! guest's other descriptors cannot take, closed as any is, and a position
//! (`lseek`) macOS keeps in the open file, shared by every duplicate and
//! fork child of it as Linux shares an open file's. An open costs a
//! descriptor, not a file made on disk.
//!
//! What the guest sees is a file of `/proc`'s: `fstat` reports what its
//! path does ([`path_of`]); `poll` and `select` find it ready to read and
//! write, as Linux finds a file with no wait of its own ([`is`]), and
//! `epoll` refuses it ([`crate::epoll`]); it seeks only from its start or
//! its position, as Linux's sequence files do ([`lseek`]).

use fwe_abi::{err, errno, fcntl};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct File {
    /// What the file held when it was opened.
    contents: Arc<[u8]>,
    /// Its guest path, for `fstat`.
    path: Arc<[u8]>,
    /// Opened only to write: reads fail (`EBADF`).
    write_only: bool,
}

static REG: crate::kept::Kept<Option<HashMap<i32, File>>> = crate::kept::Kept::new(None);

/// Whether such a file was ever opened: until one is, a call asking about a
/// descriptor takes no lock.
static ANY: AtomicBool = AtomicBool::new(false);

fn with<R>(f: impl FnOnce(&mut HashMap<i32, File>) -> R) -> R {
    f(REG.lock().get_or_insert_with(HashMap::new))
}

/// Whether `fd` is still a descriptor of `/dev/null`, as every stand-in
/// is: a record whose descriptor was closed behind fwe's back (and its
/// number taken again) is not trusted.
pub(crate) fn null_stand_in(fd: i32) -> bool {
    static NULL: std::sync::OnceLock<Option<libc::dev_t>> = std::sync::OnceLock::new();
    let null = *NULL.get_or_init(|| {
        // SAFETY: an all-zero `stat` is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a constant NUL-terminated path.
        (unsafe { libc::stat(c"/dev/null".as_ptr(), &mut st) } == 0).then_some(st.st_rdev)
    });
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let open = unsafe { libc::fstat(fd, &mut st) } == 0;
    open && st.st_mode & libc::S_IFMT == libc::S_IFCHR && Some(st.st_rdev) == null
}

/// The file `fd` is, if it is one (a stale record is dropped).
fn file_of<R>(fd: i32, f: impl FnOnce(&File) -> R) -> Option<R> {
    if !ANY.load(Ordering::Relaxed) || !with(|m| m.contains_key(&fd)) {
        return None;
    }
    if !null_stand_in(fd) {
        with(|m| m.remove(&fd));
        return None;
    }
    with(|m| m.get(&fd).map(f))
}

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = REG.lock();
    f()
}

/// Write the registry into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    with(|m| {
        crate::snapshot::fd_map(e, m, |e, f| {
            e.bytes(&f.contents);
            e.bytes(&f.path);
            e.bool(f.write_only);
        })
    })
}

/// Rebuild the registry in a fork child, or after `execve`.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let reg = crate::snapshot::read_fd_map(d, |d| File {
        contents: d.bytes().into(),
        path: d.bytes().into(),
        write_only: d.bool(),
    });
    if !reg.is_empty() {
        ANY.store(true, Ordering::SeqCst);
    }
    with(|m| *m = reg);
}

/// Open the synthetic file at guest path `path` holding `contents`, as
/// the guest's open `flags` ask: a guest descriptor.
pub fn open(path: &[u8], contents: Vec<u8>, flags: u64) -> i64 {
    let mode = match flags & fcntl::O_ACCMODE {
        fcntl::O_WRONLY => libc::O_WRONLY,
        fcntl::O_RDWR => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };
    // SAFETY: a constant NUL-terminated path and plain open flags.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), mode) };
    if fd < 0 {
        return crate::host::last_error();
    }
    ANY.store(true, Ordering::SeqCst);
    let file =
        File { contents: contents.into(), path: path.into(), write_only: mode == libc::O_WRONLY };
    with(|m| m.insert(fd, file));
    fd as i64
}

/// Whether `fd` is such a file.
pub fn is(fd: i32) -> bool {
    file_of(fd, |_| ()).is_some()
}

/// The guest path of the file `fd` is, if it is one.
pub fn path_of(fd: i32) -> Option<Vec<u8>> {
    file_of(fd, |f| f.path.to_vec())
}

/// `new` is a duplicate of `old` now.
pub fn duplicated(old: i32, new: i32) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    with(|m| match m.get(&old) {
        Some(f) => {
            let copy = File {
                contents: f.contents.clone(),
                path: f.path.clone(),
                write_only: f.write_only,
            };
            m.insert(new, copy);
        }
        None => {
            m.remove(&new);
        }
    });
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    if ANY.load(Ordering::Relaxed) {
        with(|m| m.remove(&fd));
    }
}

/// `lseek` on such a file: from its start or its position, as the host
/// keeps it; Linux's sequence files take no other (`EINVAL`).
pub fn lseek(fd: i32, whence: u64) -> Option<i64> {
    (is(fd) && whence > 1).then(|| err(errno::EINVAL))
}

/// The reads, of such a file: `read`, `readv`, `pread64`, `preadv` and
/// `preadv2`, from its contents.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    if !ANY.load(Ordering::Relaxed)
        || !matches!(nr, n::READ | n::READV | n::PREAD64 | n::PREADV | n::PREADV2)
    {
        return None;
    }
    let fd = a[0] as i32;
    // The call's own offset, or the descriptor's position (`preadv2`'s
    // offset -1 too).
    let at = match nr {
        n::PREAD64 | n::PREADV => Some(a[3] as i64),
        n::PREADV2 if a[3] as i64 != -1 => Some(a[3] as i64),
        _ => None,
    };
    let buffers = match nr {
        n::READ | n::PREAD64 => vec![(a[1], a[2])],
        _ => match read_iovecs(a[1], a[2]) {
            Ok(v) => v,
            Err(e) => return Some(err(e)),
        },
    };
    let r = read(fd, at, |mut left| {
        let mut done = 0;
        for &(base, len) in &buffers {
            let n = (len as usize).min(left.len());
            if n == 0 {
                continue;
            }
            if let Err(e) = crate::uaccess::write_from(base, &left[..n]) {
                return if done == 0 { Err(e) } else { Ok(done) };
            }
            left = &left[n..];
            done += n;
        }
        Ok(done)
    })?;
    Some(r.map_or_else(err, |n| n as i64))
}

/// A read of such a file `fd` into fwe's `buf`, at `at` or its position
/// (`splice`, `sendfile` and `copy_file_range` read so).
pub fn read_into(fd: i32, buf: &mut [u8], at: Option<u64>) -> Option<Result<usize, i32>> {
    read(fd, at.map(|p| p as i64), |left| {
        let n = buf.len().min(left.len());
        buf[..n].copy_from_slice(&left[..n]);
        Ok(n)
    })
}

/// A read of such a file `fd`, at `at` or its position: `put` takes the
/// contents from there on and says how many it took, which the position
/// moves past.
fn read(
    fd: i32,
    at: Option<i64>,
    put: impl FnOnce(&[u8]) -> Result<usize, i32>,
) -> Option<Result<usize, i32>> {
    let (contents, write_only) = file_of(fd, |f| (f.contents.clone(), f.write_only))?;
    if write_only {
        return Some(Err(errno::EBADF));
    }
    let pos = match at {
        Some(at) if at < 0 => return Some(Err(errno::EINVAL)),
        Some(at) => at as u64,
        // SAFETY: plain host call on the guest's descriptor.
        None => match unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } {
            p if p < 0 => return Some(Err(crate::host::errno_to_linux(crate::host::last_errno()))),
            p => p as u64,
        },
    };
    let left = &contents[pos.min(contents.len() as u64) as usize..];
    let done = match put(left) {
        Ok(n) => n,
        Err(e) => return Some(Err(e)),
    };
    if at.is_none() && done > 0 {
        // SAFETY: plain host call on the guest's descriptor.
        unsafe { libc::lseek(fd, (pos + done as u64) as libc::off_t, libc::SEEK_SET) };
    }
    Some(Ok(done))
}

/// The `iovec`s at guest `at`, `count` of them (`EINVAL` past
/// `UIO_MAXIOV`).
fn read_iovecs(at: u64, count: u64) -> Result<Vec<(u64, u64)>, i32> {
    if count > crate::uaccess::UIO_MAXIOV {
        return Err(errno::EINVAL);
    }
    let raw = crate::uaccess::read_bytes(at, count as usize * 16)?;
    Ok(raw
        .as_chunks::<16>()
        .0
        .iter()
        .map(|v| {
            let w = |i: usize| u64::from_ne_bytes(v[i..i + 8].try_into().unwrap());
            (w(0), w(8))
        })
        .collect())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// A file's reads take its contents from its position, which a
    /// duplicate shares (macOS keeps it; Linux's `/dev/null` keeps none);
    /// it seeks from its start or position only, and a positioned read
    /// moves nothing.
    #[test]
    fn reads_share_the_position_of_duplicates() {
        let fd = open(b"/proc/self/test", b"hello, world".to_vec(), fcntl::O_RDONLY) as i32;
        assert!(fd >= 0 && is(fd));
        let mut b = [0u8; 5];
        assert_eq!(read_into(fd, &mut b, None), Some(Ok(5)));
        assert_eq!(&b, b"hello");
        // SAFETY: plain host call.
        let dup = unsafe { libc::dup(fd) };
        duplicated(fd, dup);
        assert_eq!(read_into(dup, &mut b, None), Some(Ok(5)));
        assert_eq!(&b, b", wor");
        assert_eq!(read_into(fd, &mut b, Some(0)), Some(Ok(5)));
        assert_eq!(&b, b"hello");
        assert_eq!(read_into(fd, &mut b, None), Some(Ok(2)));
        assert_eq!(&b[..2], b"ld");
        assert_eq!(read_into(fd, &mut b, None), Some(Ok(0)));
        assert_eq!(lseek(fd, 2), Some(err(errno::EINVAL)));
        assert_eq!(lseek(fd, 0), None);
        assert_eq!(path_of(dup).as_deref(), Some(&b"/proc/self/test"[..]));
        for d in [fd, dup] {
            closed(d);
            // SAFETY: closing the descriptors made above.
            unsafe { libc::close(d) };
        }
        assert!(!is(fd) && !is(dup));
        let w = open(b"/proc/self/w", b"x".to_vec(), fcntl::O_WRONLY) as i32;
        assert_eq!(read_into(w, &mut b, None), Some(Err(errno::EBADF)));
        closed(w);
        // SAFETY: as above.
        unsafe { libc::close(w) };
    }
}
