//! The filesystems of the store, each mapped once by a process that uses
//! it ([`get`]), and what is done to a file's data through one: read,
//! written, cut and grown, its memory counted against the filesystem's
//! size.

use super::arena::Arena;
use super::data;
use super::tree::{self, Ino, New, Stat, Tx};
use fwe_abi::errno;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A filesystem of the store.
pub struct Fs {
    pub id: u64,
    arena: Arena,
}

/// The filesystems this process has mapped.
static MAPPED: Mutex<BTreeMap<u64, Arc<Fs>>> = Mutex::new(BTreeMap::new());

/// The filesystem memfds are files of (none has a name in it): one for
/// the user, of this layout.
pub fn memfd_id() -> u64 {
    0x6d66_0000_0000_0000 | crate::shared::FORMAT as u64
}

/// Filesystem `id`, made if `make` and it is not there.
pub fn get(id: u64, make: bool) -> Result<Arc<Fs>, i32> {
    let mut mapped = MAPPED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = mapped.get(&id) {
        return Ok(f.clone());
    }
    let f = Arc::new(Fs { id, arena: Arena::open(id, make)? });
    mapped.insert(id, f.clone());
    Ok(f)
}

/// A new filesystem, its root directory owned by `uid` and `gid` with
/// `mode`, holding at most `bytes` of data and `inodes` inodes (0: no
/// limit): its id.
pub fn make(mode: u32, uid: u32, gid: u32, bytes: u64, inodes: u64) -> Result<u64, i32> {
    let id = crate::shared::unique();
    let f = get(id, true)?;
    let mut t = f.lock_with(|| New { mode: tree::S_IFDIR | (mode & 0o7777), uid, gid, rdev: 0 })?;
    t.set_limits(bytes, inodes);
    Ok(id)
}

/// Filesystem `id` goes: its metadata, and the data of every file in it
/// (the caller knows no process uses it).
pub fn remove(id: u64) {
    if let Ok(f) = get(id, false)
        && let Ok(t) = f.lock()
    {
        for object in t.data_objects() {
            data::remove(object);
        }
    }
    MAPPED.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    Arena::remove(id);
}

impl Fs {
    /// The filesystem held, to read and change.
    pub fn lock(&self) -> Result<Tx<'_>, i32> {
        self.lock_with(|| New { mode: tree::S_IFDIR | 0o1777, uid: 0, gid: 0, rdev: 0 })
    }

    fn lock_with(&self, root: impl FnOnce() -> New) -> Result<Tx<'_>, i32> {
        tree::lock(&self.arena, root)
    }

    /// Read up to `buf.len()` bytes at `off` of regular file `ino`: how
    /// many (none at or past its end).
    pub fn read(&self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize, i32> {
        let mut t = self.lock()?;
        let st = t.stat(ino)?;
        if st.mode & tree::S_IFMT == tree::S_IFDIR {
            return Err(errno::EISDIR);
        }
        if off >= st.size {
            return Ok(0);
        }
        let n = buf.len().min((st.size - off) as usize);
        data::read(t.data(ino)?, off, &mut buf[..n])?;
        t.touch_accessed(ino)?;
        Ok(n)
    }

    /// Write `bytes` at `off` of regular file `ino` (at its end if
    /// `append`): how many were written (fewer once the filesystem is
    /// full, `ENOSPC` if none) and where it ended.
    pub fn write(
        &self,
        ino: Ino,
        off: u64,
        bytes: &[u8],
        append: bool,
    ) -> Result<(usize, u64), i32> {
        let mut t = self.lock()?;
        let st = t.stat(ino)?;
        let off = if append { st.size } else { off };
        if bytes.is_empty() {
            return Ok((0, off));
        }
        let end =
            off.checked_add(bytes.len() as u64).filter(|&e| e <= data::SIZE).ok_or(errno::EFBIG)?;
        let page = data::PAGE;
        let first = off / page;
        let room = t.allocate(ino, first, end.div_ceil(page))?;
        // What fits: up to the end of the pages that hold memory.
        let fits = ((first * page + room).min(end) - off) as usize;
        if fits == 0 {
            return Err(errno::ENOSPC);
        }
        let object = match t.data(ino)? {
            0 => {
                let o = data::make()?;
                t.set_data(ino, o)?;
                o
            }
            o => o,
        };
        data::write(object, off, &bytes[..fits])?;
        let ended = off + fits as u64;
        if ended > st.size {
            t.set_size(ino, ended)?;
        }
        t.touch_modified(ino)?;
        Ok((fits, ended))
    }

    /// Regular file `ino` made `size` long: what is cut off gives its
    /// memory back (and reads as zeroes if it grows again).
    pub fn truncate(&self, ino: Ino, size: u64) -> Result<(), i32> {
        if size > data::SIZE {
            return Err(errno::EFBIG);
        }
        let mut t = self.lock()?;
        let st = t.stat(ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::EINVAL);
        }
        if size < st.size {
            let object = t.data(ino)?;
            data::zero(object, size, st.size)?;
            let page = data::PAGE;
            t.release(ino, size.div_ceil(page), st.size.div_ceil(page))?;
        }
        if size != st.size {
            t.set_size(ino, size)?;
        }
        t.touch_modified(ino)
    }

    /// `fallocate` of regular file `ino`: `[off, off + len)` holds memory
    /// (and the file grows to it unless `keep_size`), or with `punch` reads
    /// as zeroes and gives its memory back.
    pub fn allocate(
        &self,
        ino: Ino,
        off: u64,
        len: u64,
        keep_size: bool,
        punch: bool,
    ) -> Result<(), i32> {
        let end = off.checked_add(len).filter(|&e| e <= data::SIZE).ok_or(errno::EFBIG)?;
        let mut t = self.lock()?;
        let st = t.stat(ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::ENODEV);
        }
        let page = data::PAGE;
        if punch {
            let end = end.min(st.size);
            if end > off {
                data::zero(t.data(ino)?, off, end)?;
                // Only the pages wholly inside give their memory back.
                t.release(ino, off.div_ceil(page), end / page)?;
                t.touch_modified(ino)?;
            }
            return Ok(());
        }
        let (first, past) = (off / page, end.div_ceil(page));
        let room = t.allocate(ino, first, past)?;
        if room < (past - first) * page {
            // All or nothing: what was taken goes back.
            t.release(ino, first, past)?;
            return Err(errno::ENOSPC);
        }
        if t.data(ino)? == 0 {
            let o = data::make()?;
            t.set_data(ino, o)?;
        }
        if !keep_size && end > st.size {
            t.set_size(ino, end)?;
        }
        t.touch_modified(ino)
    }

    pub fn stat(&self, ino: Ino) -> Result<Stat, i32> {
        self.lock()?.stat(ino)
    }
}

impl Tx<'_> {
    /// Every data object of the filesystem's files.
    pub fn data_objects(&self) -> Vec<u64> {
        self.inodes().into_iter().filter_map(|i| self.data(i).ok().filter(|&o| o != 0)).collect()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// A file written, read, cut and grown (zeroes where it was cut),
    /// appended to, and filled to its filesystem's size.
    #[test]
    fn a_files_data_is_written_read_cut_and_counted() {
        let id = make(0o1777, 0, 0, 3 * data::PAGE, 0).unwrap();
        let f = get(id, false).unwrap();
        let ino = {
            let mut t = f.lock().unwrap();
            let root = t.root();
            t.create(root, b"f", &New { mode: tree::S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0 })
                .unwrap()
        };
        assert_eq!(f.write(ino, 0, b"hello world", false), Ok((11, 11)));
        let mut b = [0u8; 32];
        assert_eq!(f.read(ino, 6, &mut b), Ok(5));
        assert_eq!(&b[..5], b"world");
        f.truncate(ino, 3).unwrap();
        f.truncate(ino, 8).unwrap();
        assert_eq!(f.read(ino, 0, &mut b), Ok(8));
        assert_eq!(&b[..8], b"hel\0\0\0\0\0");
        assert_eq!(f.write(ino, 0, b"!", true), Ok((1, 9)));
        // Three pages at most: a write over four takes what fits.
        let big = vec![7u8; 4 * data::PAGE as usize];
        assert_eq!(f.write(ino, 0, &big, false), Ok((3 * data::PAGE as usize, 3 * data::PAGE)));
        assert_eq!(f.write(ino, 3 * data::PAGE, b"x", false), Err(errno::ENOSPC));
        assert_eq!(f.allocate(ino, 3 * data::PAGE, 1, false, false), Err(errno::ENOSPC));
        // A hole punched gives its page back; then the write fits.
        f.allocate(ino, data::PAGE, data::PAGE, true, true).unwrap();
        assert_eq!(f.write(ino, 3 * data::PAGE, b"x", false), Ok((1, 3 * data::PAGE + 1)));
        assert_eq!(f.read(ino, data::PAGE + 5, &mut b[..1]), Ok(1));
        assert_eq!(b[0], 0);
        remove(id);
    }
}
