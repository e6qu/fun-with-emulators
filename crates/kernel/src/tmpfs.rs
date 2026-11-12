//! A tmpfs mount's size (`size=`), which its host directory does not have.
//!
//! A tmpfs mount is a directory of fwe's ([`crate::mountops`]); one given a
//! size keeps it in a file beside the directory (`<dir>.limit`), so every
//! process that writes there finds it. What the filesystem holds is what
//! its files take on the host (their blocks), counted again when the count
//! is more than a moment old; a write past the size writes what fits, or
//! fails with `ENOSPC`, and `statfs` reports the size and what is left, as
//! Linux's tmpfs does.

use fwe_abi::errno;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Whether this process may write into a tmpfs that has a size (one it
/// mounted, or found when it first looked).
static SIZED: AtomicBool = AtomicBool::new(false);
/// Whether it looked for those mounted before it started.
static LOOKED: AtomicBool = AtomicBool::new(false);

/// What each sized tmpfs holds, by its directory: bytes, and when counted.
pub(crate) static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// Bytes held, and when counted, by tmpfs directory.
type Held = HashMap<Vec<u8>, (u64, Instant)>;

/// How long a count of what a tmpfs holds stands.
const FRESH: Duration = Duration::from_millis(250);

/// The size `size=` in tmpfs options `data` asks for, in bytes: a number
/// with a `k`, `m`, `g` or `%` (of the host's memory) suffix, or none.
pub fn size_option(data: &[u8]) -> Option<u64> {
    let v = data.split(|&b| b == b',').find_map(|o| o.strip_prefix(b"size="))?;
    let s = std::str::from_utf8(v).ok()?;
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1u64 << 10),
        b'm' | b'M' => (&s[..s.len() - 1], 1 << 20),
        b'g' | b'G' => (&s[..s.len() - 1], 1 << 30),
        b'%' => (&s[..s.len() - 1], 0),
        _ => (s, 1),
    };
    let n: u64 = num.parse().ok()?;
    if mult == 0 {
        return Some(memory_bytes() / 100 * n);
    }
    n.checked_mul(mult)
}

/// The host's memory, in bytes.
fn memory_bytes() -> u64 {
    // SAFETY: plain host calls.
    let (pages, page) =
        unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    (pages.max(0) as u64).saturating_mul(page.max(0) as u64)
}

/// The tmpfs at host directory `dir` was mounted with size `limit`.
pub fn mounted(dir: &[u8], limit: u64) {
    let mut p = dir.to_vec();
    p.extend_from_slice(b".limit");
    use std::os::unix::ffi::OsStrExt;
    let _ = std::fs::write(std::ffi::OsStr::from_bytes(&p), limit.to_string());
    SIZED.store(true, Ordering::Relaxed);
}

/// The directory of the sized tmpfs host path `path` is in, and its size.
fn sized(path: &[u8]) -> Option<(Vec<u8>, u64)> {
    let base = crate::fs::shm::user_dir().ok()?;
    let rest = path.strip_prefix(base.as_slice())?.strip_prefix(b"/tmpfs-")?;
    let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
    let dir = path[..base.len() + 7 + end].to_vec();
    let mut p = dir.clone();
    p.extend_from_slice(b".limit");
    use std::os::unix::ffi::OsStrExt;
    let text = std::fs::read_to_string(std::ffi::OsStr::from_bytes(&p)).ok()?;
    Some((dir, text.trim().parse().ok()?))
}

/// Whether this process may write into a sized tmpfs: one it mounted, or
/// one a file beside fwe's directory says was mounted before it started.
fn any_sized() -> bool {
    if !LOOKED.swap(true, Ordering::Relaxed)
        && let Ok(base) = crate::fs::shm::user_dir()
    {
        use std::os::unix::ffi::OsStrExt;
        let found = std::fs::read_dir(std::ffi::OsStr::from_bytes(&base))
            .is_ok_and(|d| d.flatten().any(|e| e.file_name().as_bytes().ends_with(b".limit")));
        if found {
            SIZED.store(true, Ordering::Relaxed);
        }
    }
    SIZED.load(Ordering::Relaxed)
}

/// What the files under host directory `dir` take: their blocks.
fn count(dir: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut total = 0;
    for e in entries.flatten() {
        let Ok(m) = e.metadata() else { continue };
        total += m.blocks() * 512;
        if m.is_dir() {
            total += count(&e.path());
        }
    }
    total
}

/// What the sized tmpfs at `dir` holds, counted again if the count is old.
fn held(dir: &[u8]) -> u64 {
    let mut h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    let map = h.get_or_insert_with(HashMap::new);
    if let Some(&(n, at)) = map.get(dir)
        && at.elapsed() < FRESH
    {
        return n;
    }
    use std::os::unix::ffi::OsStrExt;
    let n = count(std::path::Path::new(std::ffi::OsStr::from_bytes(dir)));
    map.insert(dir.to_vec(), (n, Instant::now()));
    n
}

/// `n` more bytes are held in the tmpfs at `dir` (by this process's write).
fn grew(dir: &[u8], n: u64) {
    let mut h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((held, _)) = h.get_or_insert_with(HashMap::new).get_mut(dir) {
        *held += n;
    }
}

/// The sized tmpfs the file open as `fd` is in, if it is in one.
fn of_fd(fd: i32) -> Option<(Vec<u8>, u64)> {
    if !any_sized() {
        return None;
    }
    sized(&crate::fs::fd_path(fd)?)
}

/// How much of a write of `len` bytes at `offset` (the file's end, for
/// `None`, or its position) to the file open as `fd` fits: all of it unless
/// the file is in a sized tmpfs, where what it writes past the file's end
/// takes the room left (`ENOSPC` for none at all); a hole it leaves takes
/// none.
pub fn room(fd: i32, offset: Option<u64>, len: u64) -> Result<u64, i32> {
    let Some((dir, limit)) = of_fd(fd) else { return Ok(len) };
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(len);
    }
    let size = st.st_size.max(0) as u64;
    let at = offset.unwrap_or_else(|| {
        // SAFETY: plain host call on an open descriptor.
        let append = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_APPEND != 0;
        // SAFETY: as above.
        let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if append || pos < 0 { size } else { pos as u64 }
    });
    // What it adds past the end: no more than it writes (a hole it leaves
    // takes no room, as tmpfs's do not).
    let growth = (at + len).saturating_sub(size).min(len);
    if growth == 0 {
        return Ok(len);
    }
    let left = limit.saturating_sub(held(&dir));
    if growth <= left {
        grew(&dir, growth);
        return Ok(len);
    }
    // What lies within the file now, and as much past it as there is room.
    let fits = (len - growth + left).min(len);
    if fits == 0 {
        return Err(errno::ENOSPC);
    }
    grew(&dir, left);
    Ok(fits)
}

/// Whether `fallocate` of `len` bytes at `offset` of the file open as `fd`
/// fits its sized tmpfs (`ENOSPC` if it does not; it is all or nothing).
pub fn allocate(fd: i32, offset: u64, len: u64) -> Result<(), i32> {
    let Some((dir, limit)) = of_fd(fd) else { return Ok(()) };
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Ok(());
    }
    // What the range adds: no more than its length, less what the file
    // holds already.
    let growth = (offset + len).saturating_sub((st.st_blocks.max(0) as u64) * 512).min(len);
    if growth > limit.saturating_sub(held(&dir)) {
        return Err(errno::ENOSPC);
    }
    grew(&dir, growth);
    Ok(())
}

/// The file open as `fd` gave space back (a hole punched): what its sized
/// tmpfs holds is counted afresh.
pub fn freed(fd: i32) {
    if let Some((dir, _)) = of_fd(fd) {
        HELD.lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(HashMap::new)
            .remove(&dir);
    }
}

/// The size and what is left of the sized tmpfs host path `path` is in,
/// in bytes, for `statfs`.
pub fn space(path: &[u8]) -> Option<(u64, u64)> {
    if !any_sized() {
        return None;
    }
    let (dir, limit) = sized(path)?;
    // Counted afresh: a `statfs` sees what is there now.
    HELD.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).remove(&dir);
    Some((limit, limit.saturating_sub(held(&dir))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_as_linux_reads_them() {
        assert_eq!(size_option(b"mode=755,size=32M"), Some(32 << 20));
        assert_eq!(size_option(b"size=4k"), Some(4096));
        assert_eq!(size_option(b"size=2G,nr_inodes=10"), Some(2 << 30));
        assert_eq!(size_option(b"size=100"), Some(100));
        assert_eq!(size_option(b"mode=755"), None);
        assert!(size_option(b"size=50%").is_some_and(|n| n > 0));
    }
}
