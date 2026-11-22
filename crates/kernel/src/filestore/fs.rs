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

/// The filesystem of memfds, on Linux's device of its internal mount of
/// them (`0:1`).
pub fn memfds() -> Result<Arc<Fs>, i32> {
    let f = get(memfd_id(), true)?;
    let mut t = f.lock()?;
    if t.dev() == 0 {
        t.set_dev(crate::devnodes::makedev(0, 1));
    }
    drop(t);
    Ok(f)
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

/// The name a filesystem is registered under, for fwe's collection of
/// what no process uses ([`crate::shared::collect`]).
fn registered(id: u64) -> Result<Vec<u8>, i32> {
    let base = crate::fs::shm::user_dir()?;
    Ok(format!("{}/v{}-store-{id:x}", String::from_utf8_lossy(&base), crate::shared::FORMAT)
        .into_bytes())
}

/// A new filesystem, its root directory owned by `uid` and `gid` with
/// `mode`, holding at most `bytes` of data and `inodes` inodes (0: no
/// limit), on a device of its own: its id.
pub fn make(mode: u32, uid: u32, gid: u32, bytes: u64, inodes: u64) -> Result<u64, i32> {
    let id = crate::shared::unique();
    make_as(id, mode, uid, gid, bytes, inodes)?;
    Ok(id)
}

/// Filesystem `id`, made as [`make`] makes one if it is not there.
pub fn make_as(
    id: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    bytes: u64,
    inodes: u64,
) -> Result<Arc<Fs>, i32> {
    crate::procstore::named::find_or_make(&registered(id)?);
    let f = get(id, true)?;
    let mut t = f.lock_with(|| New { mode: tree::S_IFDIR | (mode & 0o7777), uid, gid, rdev: 0 })?;
    if t.dev() == 0 {
        t.set_limits(bytes, inodes);
        t.set_dev(anonymous_dev(id));
    }
    drop(t);
    Ok(f)
}

/// Filesystem `id`, one of the user's that lasts (never collected, as
/// [`make`]'s are once nothing shows them): made if it is not there, its
/// root directory root's with `mode`, holding as much as memory allows, on
/// a device of its own.
pub fn lasting(id: u64, mode: u32) -> Result<Arc<Fs>, i32> {
    let f = get(id, true)?;
    let mut t =
        f.lock_with(|| New { mode: tree::S_IFDIR | (mode & 0o7777), uid: 0, gid: 0, rdev: 0 })?;
    if t.dev() == 0 {
        t.set_dev(anonymous_dev(id));
    }
    drop(t);
    Ok(f)
}

/// An anonymous device's number for filesystem `id`, as Linux gives a
/// tmpfs one: of its own for each filesystem (past those fwe numbers
/// mounts with).
fn anonymous_dev(id: u64) -> u64 {
    let minor = 0x1000 + (crate::shared::hash(&id.to_le_bytes()) % 0xf_f000) as u32;
    crate::devnodes::makedev(0, minor)
}

/// Whether a live process holds a file of filesystem `id` (open, or
/// mapped through a descriptor it holds).
pub fn in_use(id: u64) -> bool {
    let Ok(f) = get(id, false) else { return false };
    let Ok(mut t) = f.lock() else { return false };
    for ino in t.inodes() {
        let _ = t.reap(ino, super::desc::alive);
        if t.holders(ino).unwrap_or(0) > 0 {
            return true;
        }
    }
    false
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
        // The host's nodes behind its FIFOs and sockets.
        for ino in t.inodes() {
            if t.stat(ino)
                .is_ok_and(|s| matches!(s.mode & tree::S_IFMT, tree::S_IFIFO | tree::S_IFSOCK))
            {
                crate::storenodes::gone(id, ino);
            }
        }
    }
    MAPPED.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    Arena::remove(id);
}

impl Fs {
    /// The word to wait on for what the filesystem's waiters wait for (a
    /// lock let go): read while the filesystem is held, then waited on
    /// once it is not ([`super::wait::wait`]).
    pub fn changes(&self) -> &std::sync::atomic::AtomicU32 {
        self.arena.changes()
    }

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
        let (object, n) = t.readable(ino, off, buf.len() as u64)?;
        t.accessed(ino, 0)?;
        data::read(object, off, &mut buf[..n as usize])?;
        Ok(n as usize)
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
        let w = t.writable(ino, off, bytes.len() as u64, append)?;
        data::write(w.object, w.off, &bytes[..w.fits as usize])?;
        let end = w.off + w.fits;
        t.wrote(ino, end)?;
        Ok((w.fits as usize, end))
    }

    pub fn truncate(&self, ino: Ino, size: u64) -> Result<(), i32> {
        self.lock()?.truncate(ino, size)
    }

    pub fn allocate(
        &self,
        ino: Ino,
        off: u64,
        len: u64,
        keep_size: bool,
        punch: bool,
    ) -> Result<(), i32> {
        self.lock()?.allocate_data(ino, off, len, keep_size, punch)
    }

    pub fn stat(&self, ino: Ino) -> Result<Stat, i32> {
        self.lock()?.stat(ino)
    }
}

/// Where a write goes: the file's data object, the offset (its end for an
/// append) and how many of the bytes fit.
pub struct Writable {
    pub object: u64,
    pub off: u64,
    pub fits: u64,
}

impl Tx<'_> {
    /// For a read of up to `len` bytes at `off` of regular file `ino`: its
    /// data object and how many of the bytes there are (none at or past its
    /// end). The reader notes the access ([`Tx::accessed`]).
    pub fn readable(&mut self, ino: Ino, off: u64, len: u64) -> Result<(u64, u64), i32> {
        let st = self.stat(ino)?;
        if st.mode & tree::S_IFMT == tree::S_IFDIR {
            return Err(errno::EISDIR);
        }
        if off >= st.size || len == 0 {
            return Ok((0, 0));
        }
        let n = len.min(st.size - off);
        Ok((self.data(ino)?, n))
    }

    /// For a write of `len` bytes at `off` of regular file `ino` (at its end
    /// if `append`): where it goes, its data object made if it had none, its
    /// pages' memory taken (`EFBIG` past the largest file, `ENOSPC` if
    /// none of it fits). The writer then copies the bytes and says where it
    /// ended ([`Tx::wrote`]).
    pub fn writable(
        &mut self,
        ino: Ino,
        off: u64,
        len: u64,
        append: bool,
    ) -> Result<Writable, i32> {
        let st = self.stat(ino)?;
        let off = if append { st.size } else { off };
        if len == 0 {
            return Ok(Writable { object: self.data(ino)?, off, fits: 0 });
        }
        let end = off.checked_add(len).filter(|&e| e <= data::SIZE).ok_or(errno::EFBIG)?;
        let page = data::PAGE;
        let first = off / page;
        let room = self.allocate(ino, first, end.div_ceil(page))?;
        // What fits: up to the end of the pages that hold memory.
        let fits = (first * page + room).min(end) - off;
        if fits == 0 {
            return Err(errno::ENOSPC);
        }
        let object = match self.data(ino)? {
            0 => {
                let o = data::make()?;
                self.set_data(ino, o)?;
                o
            }
            o => o,
        };
        Ok(Writable { object, off, fits })
    }

    /// A write of `ino` ended at `end`: the file grows to it.
    pub fn wrote(&mut self, ino: Ino, end: u64) -> Result<(), i32> {
        if end > self.stat(ino)?.size {
            self.set_size(ino, end)?;
        }
        self.touch_modified(ino)
    }

    /// Regular file `ino` made `size` long: what is cut off gives its
    /// memory back (and reads as zeroes if it grows again).
    pub fn truncate(&mut self, ino: Ino, size: u64) -> Result<(), i32> {
        if size > data::SIZE {
            return Err(errno::EFBIG);
        }
        let st = self.stat(ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::EINVAL);
        }
        if size < st.size {
            data::zero(self.data(ino)?, size, st.size)?;
            let page = data::PAGE;
            self.release(ino, size.div_ceil(page), st.size.div_ceil(page))?;
        }
        if size != st.size {
            self.set_size(ino, size)?;
        }
        self.touch_modified(ino)
    }

    /// `fallocate` of regular file `ino`: `[off, off + len)` holds memory
    /// (and the file grows to it unless `keep_size`), or with `punch` reads
    /// as zeroes and gives its memory back.
    pub fn allocate_data(
        &mut self,
        ino: Ino,
        off: u64,
        len: u64,
        keep_size: bool,
        punch: bool,
    ) -> Result<(), i32> {
        let end = off.checked_add(len).filter(|&e| e <= data::SIZE).ok_or(errno::EFBIG)?;
        let st = self.stat(ino)?;
        if st.mode & tree::S_IFMT != tree::S_IFREG {
            return Err(errno::ENODEV);
        }
        let page = data::PAGE;
        if punch {
            let end = end.min(st.size);
            if end > off {
                data::zero(self.data(ino)?, off, end)?;
                // Only the pages wholly inside give their memory back.
                self.release(ino, off.div_ceil(page), end / page)?;
                self.touch_modified(ino)?;
            }
            return Ok(());
        }
        let (first, past) = (off / page, end.div_ceil(page));
        let before = self.ranges_of(ino)?;
        let room = self.allocate(ino, first, past)?;
        if room < (past - first) * page {
            // All or nothing: what this call took goes back.
            self.restore_ranges(ino, &before)?;
            return Err(errno::ENOSPC);
        }
        if self.data(ino)? == 0 {
            let o = data::make()?;
            self.set_data(ino, o)?;
        }
        if !keep_size && end > st.size {
            self.set_size(ino, end)?;
        }
        self.touch_modified(ino)
    }

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
