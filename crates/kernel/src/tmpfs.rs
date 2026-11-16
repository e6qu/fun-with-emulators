//! A tmpfs mount's limits (`size=`, `nr_inodes=`), which its host
//! directory does not have, and its options as Linux reads them
//! ([`parse`]).
//!
//! A tmpfs mount is a directory of fwe's ([`crate::mountops`]); one given a
//! size keeps it in a file beside the directory (`<dir>.limit`), and one
//! given a number of inodes in another (`<dir>.inodes`), so every process
//! that writes there finds them. What the filesystem holds is what its
//! files take on the host (their blocks), and the inodes it uses are its
//! root and each name in it (a hard link takes one, as on Linux's tmpfs),
//! counted again when the count is more than a moment old; a write past
//! the size writes what fits, or fails with `ENOSPC`, a name made past the
//! inodes fails with `ENOSPC`, and `statfs` reports the size, the inodes
//! and what is left of them, as Linux's tmpfs does.

use fwe_abi::errno;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Whether this process may write into a tmpfs that has a size (one it
/// mounted, or found when it first looked).
static SIZED: AtomicBool = AtomicBool::new(false);
/// Whether it may make a name in a tmpfs that has a number of inodes.
static COUNTED: AtomicBool = AtomicBool::new(false);
/// Whether it looked for those mounted before it started.
static LOOKED: AtomicBool = AtomicBool::new(false);

/// What each sized tmpfs holds, by its directory: bytes, and when counted.
pub(crate) static HELD: Mutex<Option<Held>> = Mutex::new(None);
/// The inodes each tmpfs of a number of them uses, by its directory, and
/// when counted.
pub(crate) static USED: Mutex<Option<Held>> = Mutex::new(None);

/// Bytes (or inodes) held, and when counted, by tmpfs directory.
type Held = HashMap<Vec<u8>, (u64, Instant)>;

/// How long a count of what a tmpfs holds stands.
const FRESH: Duration = Duration::from_millis(250);

/// The suffixes of the files beside a tmpfs's directory that hold its
/// size and its number of inodes.
const SIZE_FILE: &[u8] = b".limit";
const INODES_FILE: &[u8] = b".inodes";

/// What a tmpfs's options (`mount`'s data, `fsconfig`'s parameters) ask
/// for, of what fwe acts on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// `size=` (or `nr_blocks=`), in bytes.
    pub size: Option<u64>,
    /// `nr_inodes=`: 0 is no limit.
    pub inodes: Option<u64>,
    /// `mode=`, of the root.
    pub mode: Option<u32>,
    /// `uid=` and `gid=`, of the root, as the mounter's namespace has
    /// them.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Tmpfs options `data` (comma-separated), as Linux's `shmem_parse_one`
/// reads them: a value it refuses is `EINVAL`; an option fwe does not act
/// on is taken as given.
pub fn parse(data: &[u8]) -> Result<Options, i32> {
    let mut o = Options::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        let text = || value.and_then(|v| std::str::from_utf8(v).ok()).ok_or(errno::EINVAL);
        match key {
            b"size" => {
                let s = text()?;
                o.size = Some(match s.strip_suffix('%') {
                    Some(p) => memory_bytes() / 100 * memparse(p)?,
                    None => memparse(s)?,
                });
            }
            b"nr_blocks" => {
                o.size = Some(memparse(text()?)?.checked_mul(4096).ok_or(errno::EINVAL)?)
            }
            b"nr_inodes" => o.inodes = Some(memparse(text()?)?),
            b"mode" => {
                o.mode = Some(u32::from_str_radix(text()?, 8).map_err(|_| errno::EINVAL)? & 0o7777)
            }
            b"uid" => o.uid = Some(number(text()?)?),
            b"gid" => o.gid = Some(number(text()?)?),
            _ => {}
        }
    }
    Ok(o)
}

/// A number as the kernel's `kstrtouint` with base 0 reads it: decimal,
/// `0x` hexadecimal or `0` octal.
fn number(s: &str) -> Result<u32, i32> {
    let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8)
    } else {
        s.parse()
    };
    n.map_err(|_| errno::EINVAL)
}

/// A size as the kernel's `memparse` reads it: a number (decimal, `0x`
/// hexadecimal or `0` octal) and a `K`, `M`, `G`, `T`, `P` or `E` suffix
/// (either case), and nothing after.
fn memparse(s: &str) -> Result<u64, i32> {
    let (num, shift) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 10),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 20),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 30),
        Some(b't' | b'T') => (&s[..s.len() - 1], 40),
        Some(b'p' | b'P') => (&s[..s.len() - 1], 50),
        Some(b'e' | b'E') => (&s[..s.len() - 1], 60),
        _ => (s, 0),
    };
    let n = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else if num.len() > 1 && num.starts_with('0') {
        u64::from_str_radix(&num[1..], 8)
    } else {
        num.parse()
    };
    let n = n.map_err(|_| errno::EINVAL)?;
    n.checked_mul(1 << shift).ok_or(errno::EINVAL)
}

/// The size `size=` in tmpfs options `data` asks for, in bytes, if it is
/// one Linux takes.
pub fn size_option(data: &[u8]) -> Option<u64> {
    parse(data).ok()?.size
}

/// The host's memory, in bytes.
fn memory_bytes() -> u64 {
    // SAFETY: plain host calls.
    let (pages, page) =
        unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    (pages.max(0) as u64).saturating_mul(page.max(0) as u64)
}

/// Write `value` to the file beside tmpfs directory `dir` named by
/// `suffix` (or remove it, for `None`).
fn note(dir: &[u8], suffix: &[u8], value: Option<u64>) {
    use std::os::unix::ffi::OsStrExt;
    let p = [dir, suffix].concat();
    let p = std::ffi::OsStr::from_bytes(&p);
    match value {
        Some(v) => drop(std::fs::write(p, v.to_string())),
        None => drop(std::fs::remove_file(p)),
    }
}

/// The tmpfs at host directory `dir` was mounted with size `limit`.
pub fn mounted(dir: &[u8], limit: u64) {
    note(dir, SIZE_FILE, Some(limit));
    SIZED.store(true, Ordering::Relaxed);
}

/// The tmpfs at host directory `dir` was mounted with `inodes` inodes (0:
/// as many as it takes).
pub fn mounted_inodes(dir: &[u8], inodes: u64) {
    note(dir, INODES_FILE, (inodes > 0).then_some(inodes));
    COUNTED.store(true, Ordering::Relaxed);
    USED.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).remove(dir);
}

/// The directory of the tmpfs host path `path` is in, if it is in one.
fn tmpfs_of(path: &[u8]) -> Option<Vec<u8>> {
    let base = crate::fs::shm::user_dir().ok()?;
    let rest = path.strip_prefix(base.as_slice())?.strip_prefix(b"/tmpfs-")?;
    let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
    Some(path[..base.len() + 7 + end].to_vec())
}

/// The directory of the tmpfs host path `path` is in, and the limit the
/// file beside it named by `suffix` holds, if it has one.
fn limited(path: &[u8], suffix: &[u8]) -> Option<(Vec<u8>, u64)> {
    let dir = tmpfs_of(path)?;
    use std::os::unix::ffi::OsStrExt;
    let p = [&dir[..], suffix].concat();
    let text = std::fs::read_to_string(std::ffi::OsStr::from_bytes(&p)).ok()?;
    Some((dir, text.trim().parse().ok()?))
}

/// The directory of the sized tmpfs host path `path` is in, and its size.
fn sized(path: &[u8]) -> Option<(Vec<u8>, u64)> {
    limited(path, SIZE_FILE)
}

/// Look, once, for the limits of tmpfs mounts made before this process
/// started: files beside fwe's directories.
fn look() {
    if LOOKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Ok(base) = crate::fs::shm::user_dir() else { return };
    use std::os::unix::ffi::OsStrExt;
    let Ok(d) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&base)) else { return };
    for e in d.flatten() {
        let name = e.file_name();
        if name.as_bytes().ends_with(SIZE_FILE) {
            SIZED.store(true, Ordering::Relaxed);
        }
        if name.as_bytes().ends_with(INODES_FILE) {
            COUNTED.store(true, Ordering::Relaxed);
        }
    }
}

/// Whether this process may write into a sized tmpfs: one it mounted, or
/// one a file beside fwe's directory says was mounted before it started.
fn any_sized() -> bool {
    look();
    SIZED.load(Ordering::Relaxed)
}

/// Whether this process may make a name in a tmpfs of a number of inodes.
pub fn any_counted() -> bool {
    look();
    COUNTED.load(Ordering::Relaxed)
}

/// The names under host directory `dir`, each a link to an inode.
fn names(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut total = 0;
    for e in entries.flatten() {
        total += 1;
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            total += names(&e.path());
        }
    }
    total
}

/// The inodes the tmpfs at `dir` uses (its root and each name), counted
/// again if the count is old.
fn used(dir: &[u8]) -> u64 {
    let mut h = USED.lock().unwrap_or_else(|e| e.into_inner());
    let map = h.get_or_insert_with(HashMap::new);
    if let Some(&(n, at)) = map.get(dir)
        && at.elapsed() < FRESH
    {
        return n;
    }
    use std::os::unix::ffi::OsStrExt;
    let n = 1 + names(std::path::Path::new(std::ffi::OsStr::from_bytes(dir)));
    map.insert(dir.to_vec(), (n, Instant::now()));
    n
}

/// A name is to be made in the host directory open as `dir`: an inode of
/// its tmpfs taken, if it has a number of them (`ENOSPC` with none left).
pub fn take_inode(dir: i32) -> Result<(), i32> {
    let Some((tmpfs, limit)) = crate::fs::fd_path(dir).and_then(|p| limited(&p, INODES_FILE))
    else {
        return Ok(());
    };
    if used(&tmpfs) >= limit {
        return Err(errno::ENOSPC);
    }
    if let Some((n, _)) = USED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .get_mut(&tmpfs)
    {
        *n += 1;
    }
    Ok(())
}

/// The inodes and those free of the tmpfs host path `path` is in, if it
/// has a number of them, for `statfs`.
pub fn inodes(path: &[u8]) -> Option<(u64, u64)> {
    if !any_counted() {
        return None;
    }
    let (dir, limit) = limited(path, INODES_FILE)?;
    // Counted afresh: a `statfs` sees what is there now.
    USED.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).remove(&dir);
    Some((limit, limit.saturating_sub(used(&dir))))
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

    /// `nr_inodes=`, `mode=`, `uid=` and `gid=` read as Linux reads them;
    /// a value it refuses is `EINVAL`, an option fwe does not act on is
    /// taken.
    #[test]
    fn options_parse_as_linux_reads_them() {
        let o = parse(b"nr_inodes=1k,mode=01777,uid=1000,gid=0x10,huge=never").unwrap();
        let want = Options {
            size: None,
            inodes: Some(1024),
            mode: Some(0o1777),
            uid: Some(1000),
            gid: Some(16),
        };
        assert_eq!(o, want);
        assert_eq!(parse(b"nr_blocks=2").unwrap().size, Some(8192));
        assert_eq!(parse(b"mode=17777").unwrap().mode, Some(0o7777));
        for bad in [&b"size=lots"[..], b"nr_inodes=1%", b"uid=-1", b"gid=", b"mode=9", b"nr_inodes"]
        {
            assert_eq!(parse(bad), Err(errno::EINVAL), "{}", String::from_utf8_lossy(bad));
        }
    }

    /// A tmpfs's inodes are its root and each name in it, at any depth.
    #[test]
    fn inodes_are_the_root_and_each_name() {
        let dir = std::env::temp_dir().join(format!("fwe-tmpfs-inodes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("a"), b"").unwrap();
        std::fs::write(dir.join("d/b"), b"").unwrap();
        std::fs::hard_link(dir.join("a"), dir.join("d/c")).unwrap();
        assert_eq!(names(&dir), 4);
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(used(dir.as_os_str().as_bytes()), 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
