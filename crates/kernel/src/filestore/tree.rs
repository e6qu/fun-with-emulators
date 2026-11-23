//! A filesystem in an arena ([`super::arena`]): its inodes, directories,
//! symbolic links' targets, extended attributes, the processes holding
//! each file open, and the ranges of each file's data that hold memory.
//! File data itself is in objects of its own ([`super::data`]); an inode
//! names its object.
//!
//! - **Inodes** are slots of a table, an inode's number its slot and the
//!   slot's generation, so a slot used again is another number.
//! - **Directories** keep their entries in the order they were made, each
//!   numbered (a listing's position is the number of the last entry it
//!   gave, which stays good whatever is added or removed meanwhile, as
//!   Linux's tmpfs cursor does), with an index by name made again from the
//!   entries whenever it may be wrong ([`Tx::repair`]).
//! - **Holders**: each process that has the file open, and how many of its
//!   descriptors do, so a file with no names left goes once the last
//!   process holding it lets go or ends.
//!
//! Every call runs under the filesystem's lock ([`Tx`]).

use super::arena::{Arena, Mem};
use fwe_abi::errno;

pub type Ino = u64;

/// Extended attributes: each name and value.
pub type Xattrs = Vec<(Vec<u8>, Vec<u8>)>;

/// The file types, as `st_mode` has them.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;

/// The hidden attribute marking a file with no names that may be named
/// (`linkat`): an `O_TMPFILE` made without `O_EXCL`.
const LINKABLE: &[u8] = b"\0linkable";

/// The hidden attribute of a held file with no names: the directory and
/// name it last had ([`Tx::last_name`]).
const LAST_NAME: &[u8] = b"\0last";

/// Owner words of the arena.
const R_TABLE: usize = 0;
const R_CAP: usize = 1;
const R_FREE: usize = 2;
const R_USED: usize = 3;
const R_GEN: usize = 4;
const R_ROOT: usize = 5;
const R_LIMIT_BYTES: usize = 6;
const R_LIMIT_INODES: usize = 7;
const R_BYTES: usize = 8;
const R_DEV: usize = 9;
/// The processes waiting for a record lock, and for whose ([`Tx::waiters`]).
const R_WAIT: usize = 10;
const R_WAIT_LEN: usize = 11;
/// The first owner word [`super`] may use for itself.
pub const R_OWNER: usize = 16;

const INODE: u64 = 144;

/// Fields of an inode slot, by offset.
const I_GEN: u64 = 0;
const I_MODE: u64 = 4;
const I_NLINK: u64 = 8;
const I_FLAGS: u64 = 12;
const I_UID: u64 = 16;
const I_GID: u64 = 20;
const I_SIZE: u64 = 24;
const I_RDEV: u64 = 32;
const I_ATIME: u64 = 40;
const I_MTIME: u64 = 48;
const I_CTIME: u64 = 56;
const I_BTIME: u64 = 64;
/// A regular file's data object (0: none yet); a directory's entries; a
/// link's target.
const I_A: u64 = 72;
/// A directory's parent; a link's target's length.
const I_B: u64 = 80;
const I_XATTRS: u64 = 88;
const I_XATTRS_LEN: u64 = 96;
const I_SEALS: u64 = 100;
const I_HOLDERS: u64 = 104;
const I_HOLDERS_LEN: u64 = 112;
/// A regular file's ranges of pages that hold memory (pairs of page
/// numbers, start and end); their count at `I_RANGES_LEN`.
const I_RANGES: u64 = 116;
const I_RANGES_LEN: u64 = 124;
/// The file's locks ([`Lock`]), and their bytes.
const I_LOCKS: u64 = 128;
const I_LOCKS_LEN: u64 = 136;

/// What `stat` reports of an inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: Ino,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// The bytes of memory its data holds.
    pub allocated: u64,
    pub rdev: u64,
    pub flags: u32,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub btime: i64,
}

/// An inode to make: its type and permissions, owner and device.
pub struct New {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
}

/// One entry of a listing: its position (what a listing resumes after),
/// inode, type (`S_IFMT` bits) and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pos: u64,
    pub ino: Ino,
    pub kind: u32,
    pub name: Vec<u8>,
}

/// A directory's header: where its entries are, how many slots they have
/// and use (removed ones too), how many are live, the next entry's
/// number, and its index by name.
const D_ENTRIES: u64 = 0;
const D_CAP: u64 = 8;
const D_LEN: u64 = 16;
const D_LIVE: u64 = 24;
const D_NEXT: u64 = 32;
const D_INDEX: u64 = 40;
const D_INDEX_CAP: u64 = 48;
const DIR: usize = 56;

/// An entry: its number, inode (0: removed), name and its length, type.
const E_POS: u64 = 0;
const E_INO: u64 = 8;
const E_NAME: u64 = 16;
const E_LEN: u64 = 24;
const E_KIND: u64 = 28;
const ENTRY: u64 = 32;

/// Listing positions: `.` and `..` come first.
pub const POS_DOT: u64 = 1;
pub const POS_DOTDOT: u64 = 2;
const FIRST_POS: u64 = 3;

/// An index slot left by a removed entry.
const GONE: u32 = u32::MAX;

/// A filesystem held: the arena under its lock.
pub struct Tx<'a> {
    m: Mem<'a>,
}

/// What a filesystem begins with: its root directory, made by `root`.
pub fn lock<'a>(arena: &'a Arena, root: impl FnOnce() -> New) -> Result<Tx<'a>, i32> {
    let mut t = Tx { m: arena.lock() };
    if t.m.repairs() {
        t.repair();
    }
    if t.m.root(R_ROOT) == 0 {
        let r = root();
        let ino = t.new_inode(&r)?;
        t.make_dir(ino, ino)?;
        t.set_u32(ino, I_NLINK, 2)?;
        t.m.set_root(R_ROOT, ino);
    }
    Ok(t)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64)
}

/// The FNV-1a hash of a name.
fn hash(name: &[u8]) -> u32 {
    name.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193))
}

impl Tx<'_> {
    pub fn root(&self) -> Ino {
        self.m.root(R_ROOT)
    }

    /// Where inode `ino`'s slot is: `ENOENT` if it is no live inode.
    fn slot(&self, ino: Ino) -> Result<u64, i32> {
        let (index, generation) = (ino & 0xffff_ffff, (ino >> 32) as u32);
        if index == 0 || index > self.m.root(R_CAP) {
            return Err(errno::ENOENT);
        }
        let at = self.m.root(R_TABLE) + (index - 1) * INODE;
        let slot_gen = u32::from_le_bytes(self.m.bytes(at + I_GEN, 4).try_into().unwrap());
        let mode = u32::from_le_bytes(self.m.bytes(at + I_MODE, 4).try_into().unwrap());
        if slot_gen != generation || mode == 0 {
            return Err(errno::ENOENT);
        }
        Ok(at)
    }

    fn get_u32(&self, ino: Ino, f: u64) -> Result<u32, i32> {
        let at = self.slot(ino)?;
        Ok(u32::from_le_bytes(self.m.bytes(at + f, 4).try_into().unwrap()))
    }

    fn set_u32(&mut self, ino: Ino, f: u64, v: u32) -> Result<(), i32> {
        let at = self.slot(ino)?;
        self.m.bytes_mut(at + f, 4).copy_from_slice(&v.to_le_bytes());
        Ok(())
    }

    fn get_u64(&self, ino: Ino, f: u64) -> Result<u64, i32> {
        let at = self.slot(ino)?;
        Ok(self.m.u64_at(at + f))
    }

    fn set_u64(&mut self, ino: Ino, f: u64, v: u64) -> Result<(), i32> {
        let at = self.slot(ino)?;
        self.m.set_u64(at + f, v);
        Ok(())
    }

    pub fn stat(&self, ino: Ino) -> Result<Stat, i32> {
        let at = self.slot(ino)?;
        let u32_at = |f: u64| u32::from_le_bytes(self.m.bytes(at + f, 4).try_into().unwrap());
        let i64_at = |f: u64| self.m.u64_at(at + f) as i64;
        let mode = u32_at(I_MODE);
        Ok(Stat {
            ino,
            mode,
            nlink: u32_at(I_NLINK),
            uid: u32_at(I_UID),
            gid: u32_at(I_GID),
            size: self.m.u64_at(at + I_SIZE),
            allocated: if mode & S_IFMT == S_IFREG { self.allocated_of(at) } else { 0 },
            rdev: self.m.u64_at(at + I_RDEV),
            flags: u32_at(I_FLAGS),
            atime: i64_at(I_ATIME),
            mtime: i64_at(I_MTIME),
            ctime: i64_at(I_CTIME),
            btime: i64_at(I_BTIME),
        })
    }

    /// One more of the filesystem's inodes in use, if its limit allows
    /// (`ENOSPC`): an inode's, or a file's name past its first, which
    /// Linux's tmpfs counts as one (`shmem_link`: each name holds memory
    /// until it goes).
    fn reserve_inode(&mut self) -> Result<(), i32> {
        let limit = self.m.root(R_LIMIT_INODES);
        if limit != 0 && self.m.root(R_USED) >= limit {
            return Err(errno::ENOSPC);
        }
        self.m.set_root(R_USED, self.m.root(R_USED) + 1);
        Ok(())
    }

    /// A file's name past its first went ([`Self::reserve_inode`]).
    fn release_name(&mut self) {
        self.m.set_root(R_USED, self.m.root(R_USED).saturating_sub(1));
    }

    /// A new inode like `n`, with no names: its number.
    fn new_inode(&mut self, n: &New) -> Result<Ino, i32> {
        let limit = self.m.root(R_LIMIT_INODES);
        if limit != 0 && self.m.root(R_USED) >= limit {
            return Err(errno::ENOSPC);
        }
        let index = match self.m.root(R_FREE) {
            0 => {
                let cap = self.m.root(R_CAP);
                let table = self.m.root(R_TABLE);
                let grown = (cap * 2).max(64);
                let new =
                    self.m.realloc(table, (cap * INODE) as usize, (grown * INODE) as usize)?;
                self.m.set_root(R_TABLE, new);
                self.m.set_root(R_CAP, grown);
                // Slots cap+1.. are free, in order (each holds the next).
                for i in cap + 1..=grown {
                    let at = new + (i - 1) * INODE;
                    self.m.set_u64(at + I_A, if i < grown { i + 1 } else { 0 });
                }
                cap + 1
            }
            free => free,
        };
        let at = self.m.root(R_TABLE) + (index - 1) * INODE;
        self.m.set_root(R_FREE, self.m.u64_at(at + I_A));
        let generation = (self.m.root(R_GEN) + 1) as u32;
        self.m.set_root(R_GEN, generation as u64);
        let t = now_ns();
        let slot = self.m.bytes_mut(at, INODE as usize);
        slot.fill(0);
        slot[I_GEN as usize..][..4].copy_from_slice(&generation.to_le_bytes());
        slot[I_UID as usize..][..4].copy_from_slice(&n.uid.to_le_bytes());
        slot[I_GID as usize..][..4].copy_from_slice(&n.gid.to_le_bytes());
        slot[I_RDEV as usize..][..8].copy_from_slice(&n.rdev.to_le_bytes());
        for f in [I_ATIME, I_MTIME, I_CTIME, I_BTIME] {
            slot[f as usize..][..8].copy_from_slice(&t.to_le_bytes());
        }
        // The mode last: it makes the slot live.
        slot[I_MODE as usize..][..4].copy_from_slice(&n.mode.to_le_bytes());
        self.m.set_root(R_USED, self.m.root(R_USED) + 1);
        Ok((generation as u64) << 32 | index)
    }

    /// Free inode `ino`'s slot and what it holds (its data object is the
    /// caller's: [`Tx::data`] before).
    fn free_inode(&mut self, ino: Ino) -> Result<(), i32> {
        let at = self.slot(ino)?;
        let mode = self.get_u32(ino, I_MODE)?;
        match mode & S_IFMT {
            S_IFDIR => {
                let d = self.m.u64_at(at + I_A);
                if d != 0 {
                    let (entries, cap) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_CAP));
                    let len = self.m.u64_at(d + D_LEN);
                    for i in 0..len {
                        let e = entries + i * ENTRY;
                        if self.m.u64_at(e + E_INO) != 0 {
                            let (name, nlen) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
                            self.m.free(name, nlen as usize);
                        }
                    }
                    self.m.free(entries, (cap * ENTRY) as usize);
                    let (index, icap) =
                        (self.m.u64_at(d + D_INDEX), self.m.u64_at(d + D_INDEX_CAP));
                    self.m.free(index, (icap * 4) as usize);
                    self.m.free(d, DIR);
                }
            }
            S_IFLNK => {
                let (target, len) = (self.m.u64_at(at + I_A), self.m.u64_at(at + I_B));
                self.m.free(target, len as usize);
            }
            S_IFREG => {
                let bytes = self.allocated_of(at);
                self.m.set_root(R_BYTES, self.m.root(R_BYTES).saturating_sub(bytes));
                let (r, n) = (self.m.u64_at(at + I_RANGES), self.u32_raw(at + I_RANGES_LEN));
                self.m.free(r, n as usize * 16);
            }
            _ => {}
        }
        let (x, xl) = (self.m.u64_at(at + I_XATTRS), self.u32_raw(at + I_XATTRS_LEN));
        self.m.free(x, xl as usize);
        for (f, fl) in [(I_HOLDERS, I_HOLDERS_LEN), (I_LOCKS, I_LOCKS_LEN)] {
            let (b, len) = (self.m.u64_at(at + f), self.u32_raw(at + fl));
            self.m.free(b, len as usize);
        }
        let generation = self.u32_raw(at + I_GEN);
        let slot = self.m.bytes_mut(at, INODE as usize);
        slot.fill(0);
        slot[I_GEN as usize..][..4].copy_from_slice(&generation.to_le_bytes());
        self.m.set_u64(at + I_A, self.m.root(R_FREE));
        self.m.set_root(R_FREE, ino & 0xffff_ffff);
        self.m.set_root(R_USED, self.m.root(R_USED).saturating_sub(1));
        Ok(())
    }

    fn u32_raw(&self, at: u64) -> u32 {
        u32::from_le_bytes(self.m.bytes(at, 4).try_into().unwrap())
    }

    fn set_u32_raw(&mut self, at: u64, v: u32) {
        self.m.bytes_mut(at, 4).copy_from_slice(&v.to_le_bytes());
    }

    fn make_dir(&mut self, ino: Ino, parent: Ino) -> Result<(), i32> {
        let d = self.m.alloc(DIR)?;
        self.m.set_u64(d + D_NEXT, FIRST_POS);
        self.set_u64(ino, I_A, d)?;
        self.set_u64(ino, I_B, parent)
    }

    /// Directory `ino`'s header: `ENOTDIR` if it is none.
    fn dir(&self, ino: Ino) -> Result<u64, i32> {
        if self.get_u32(ino, I_MODE)? & S_IFMT != S_IFDIR {
            return Err(errno::ENOTDIR);
        }
        self.get_u64(ino, I_A)
    }

    /// The entry named `name` in directory header `d`: its index slot and
    /// its offset.
    fn find(&self, d: u64, name: &[u8]) -> Option<(u64, u64)> {
        let (index, cap) = (self.m.u64_at(d + D_INDEX), self.m.u64_at(d + D_INDEX_CAP));
        if cap == 0 {
            return None;
        }
        let entries = self.m.u64_at(d + D_ENTRIES);
        let mut i = hash(name) as u64 & (cap - 1);
        loop {
            let slot = index + i * 4;
            match self.u32_raw(slot) {
                0 => return None,
                GONE => {}
                n => {
                    let e = entries + (n as u64 - 1) * ENTRY;
                    let (nm, len) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
                    if len as usize == name.len() && self.m.bytes(nm, name.len()) == name {
                        return Some((slot, e));
                    }
                }
            }
            i = (i + 1) & (cap - 1);
        }
    }

    /// Directory `ino`'s path from the root (`/` for the root), its names
    /// as they are now: `None` for a directory removed, or no directory.
    pub fn path(&self, ino: Ino) -> Option<Vec<u8>> {
        let root = self.m.root(R_ROOT);
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut at = ino;
        while at != root {
            self.dir(at).ok()?;
            if self.get_u32(at, I_NLINK).ok()? == 0 {
                return None;
            }
            let parent = self.get_u64(at, I_B).ok()?;
            let d = self.dir(parent).ok()?;
            let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
            let name = (0..len).find_map(|n| {
                let e = entries + n * ENTRY;
                (self.m.u64_at(e + E_INO) == at).then(|| {
                    let (nm, l) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
                    self.m.bytes(nm, l as usize).to_vec()
                })
            })?;
            names.push(name);
            at = parent;
        }
        let mut path = Vec::new();
        for n in names.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(n);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        Some(path)
    }

    /// A path from the filesystem's root of `ino`, of any type: a
    /// directory's own ([`Tx::path`]), another's first name found, the
    /// directories searched from the root (`None` for one with no name).
    pub fn any_path(&self, ino: Ino) -> Option<Vec<u8>> {
        if self.get_u32(ino, I_MODE).ok()? & S_IFMT == S_IFDIR {
            return self.path(ino);
        }
        if self.get_u32(ino, I_NLINK).ok()? == 0 {
            return None;
        }
        let mut todo = vec![(self.m.root(R_ROOT), Vec::new())];
        while let Some((dir, path)) = todo.pop() {
            let d = self.dir(dir).ok()?;
            let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
            for n in 0..len {
                let e = entries + n * ENTRY;
                let at = self.m.u64_at(e + E_INO);
                if at == 0 {
                    continue;
                }
                let (nm, l) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
                let mut p: Vec<u8> = path.clone();
                p.push(b'/');
                p.extend_from_slice(self.m.bytes(nm, l as usize));
                if at == ino {
                    return Some(p);
                }
                if self.u32_raw(e + E_KIND) == S_IFDIR {
                    todo.push((at, p));
                }
            }
        }
        None
    }

    /// The inode named `name` in directory `dir` (`.` and `..` too).
    pub fn lookup(&self, dir: Ino, name: &[u8]) -> Result<Ino, i32> {
        let d = self.dir(dir)?;
        match name {
            b"." => Ok(dir),
            b".." => self.get_u64(dir, I_B),
            _ => {
                let (_, e) = self.find(d, name).ok_or(errno::ENOENT)?;
                Ok(self.m.u64_at(e + E_INO))
            }
        }
    }

    /// Index the entry at entries index `n` (from 0) under `name`. The
    /// index's used slots are its live entries' and those removed ones
    /// left (`GONE`), together never more than the entries made since it
    /// was last made (`n`, the removed ones still in the entries counted):
    /// kept at most half full by that count, a lookup always ends at an
    /// empty slot.
    fn index_entry(&mut self, d: u64, name: &[u8], n: u64) -> Result<(), i32> {
        let mut cap = self.m.u64_at(d + D_INDEX_CAP);
        if (n + 1) * 2 > cap {
            self.reindex(d, ((n + 1) * 4).next_power_of_two().max(16))?;
            cap = self.m.u64_at(d + D_INDEX_CAP);
        }
        let index = self.m.u64_at(d + D_INDEX);
        let mut i = hash(name) as u64 & (cap - 1);
        loop {
            let slot = index + i * 4;
            if matches!(self.u32_raw(slot), 0 | GONE) {
                self.set_u32_raw(slot, n as u32 + 1);
                return Ok(());
            }
            i = (i + 1) & (cap - 1);
        }
    }

    /// Make directory header `d`'s index again, of `cap` slots, from its
    /// live entries.
    fn reindex(&mut self, d: u64, cap: u64) -> Result<(), i32> {
        let (old, old_cap) = (self.m.u64_at(d + D_INDEX), self.m.u64_at(d + D_INDEX_CAP));
        let index = self.m.alloc((cap * 4) as usize)?;
        self.m.free(old, (old_cap * 4) as usize);
        self.m.set_u64(d + D_INDEX, index);
        self.m.set_u64(d + D_INDEX_CAP, cap);
        let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
        for n in 0..len {
            let e = entries + n * ENTRY;
            if self.m.u64_at(e + E_INO) == 0 {
                continue;
            }
            let (nm, nlen) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
            let mut i = hash(self.m.bytes(nm, nlen as usize)) as u64 & (cap - 1);
            while self.u32_raw(index + i * 4) != 0 {
                i = (i + 1) & (cap - 1);
            }
            self.set_u32_raw(index + i * 4, n as u32 + 1);
        }
        Ok(())
    }

    /// Add `name` for `ino` (of type `kind`) to directory header `d`.
    fn add_entry(&mut self, d: u64, name: &[u8], ino: Ino, kind: u32) -> Result<(), i32> {
        let (mut entries, cap, len) =
            (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_CAP), self.m.u64_at(d + D_LEN));
        if len == cap {
            let live = self.m.u64_at(d + D_LIVE);
            if live * 2 < len && len >= 64 {
                self.compact(d)?;
                return self.add_entry(d, name, ino, kind);
            }
            let grown = (cap * 2).max(8);
            entries = self.m.realloc(entries, (cap * ENTRY) as usize, (grown * ENTRY) as usize)?;
            self.m.set_u64(d + D_ENTRIES, entries);
            self.m.set_u64(d + D_CAP, grown);
        }
        let nm = self.m.alloc(name.len())?;
        self.m.bytes_mut(nm, name.len()).copy_from_slice(name);
        let pos = self.m.u64_at(d + D_NEXT);
        let e = entries + len * ENTRY;
        self.m.set_u64(e + E_POS, pos);
        self.m.set_u64(e + E_NAME, nm);
        self.set_u32_raw(e + E_LEN, name.len() as u32);
        self.set_u32_raw(e + E_KIND, kind);
        self.m.set_u64(e + E_INO, ino);
        // Indexed before it counts: an index made again for it is made of
        // the entries before it, so it is indexed once.
        if let Err(err) = self.index_entry(d, name, len) {
            self.m.set_u64(e + E_INO, 0);
            self.m.free(nm, name.len());
            return Err(err);
        }
        // Written whole before it counts.
        self.m.set_u64(d + D_NEXT, pos + 1);
        self.m.set_u64(d + D_LEN, len + 1);
        self.m.set_u64(d + D_LIVE, self.m.u64_at(d + D_LIVE) + 1);
        Ok(())
    }

    /// Entries without the removed ones, their numbers kept.
    fn compact(&mut self, d: u64) -> Result<(), i32> {
        let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
        let mut kept = 0;
        for n in 0..len {
            let e = entries + n * ENTRY;
            if self.m.u64_at(e + E_INO) != 0 {
                if kept != n {
                    let bytes = self.m.bytes(e, ENTRY as usize).to_vec();
                    self.m
                        .bytes_mut(entries + kept * ENTRY, ENTRY as usize)
                        .copy_from_slice(&bytes);
                }
                kept += 1;
            }
        }
        self.m.set_u64(d + D_LEN, kept);
        self.m.set_u64(d + D_LIVE, kept);
        let cap = (kept * 4).next_power_of_two().max(16);
        self.reindex(d, cap)
    }

    /// Remove the entry at index slot `slot`, entry `e`, of directory
    /// header `d`.
    fn remove_entry(&mut self, d: u64, slot: u64, e: u64) {
        let (nm, nlen) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
        self.m.set_u64(e + E_INO, 0);
        self.set_u32_raw(slot, GONE);
        self.m.free(nm, nlen as usize);
        self.m.set_u64(d + D_LIVE, self.m.u64_at(d + D_LIVE) - 1);
    }

    /// A new inode like `n` named `name` in directory `dir`: `EEXIST` if
    /// the name is taken.
    pub fn create(&mut self, dir: Ino, name: &[u8], n: &New) -> Result<Ino, i32> {
        let d = self.dir(dir)?;
        if self.find(d, name).is_some() || matches!(name, b"." | b"..") {
            return Err(errno::EEXIST);
        }
        let ino = self.new_inode(n)?;
        let kind = n.mode & S_IFMT;
        if kind == S_IFDIR {
            self.make_dir(ino, dir)?;
            self.set_u32(ino, I_NLINK, 2)?;
            let parent_links = self.get_u32(dir, I_NLINK)?;
            self.set_u32(dir, I_NLINK, parent_links + 1)?;
        } else {
            self.set_u32(ino, I_NLINK, 1)?;
        }
        if let Err(e) = self.add_entry(d, name, ino, kind) {
            self.free_inode(ino)?;
            return Err(e);
        }
        self.touch_changed(dir)?;
        Ok(ino)
    }

    /// A new inode like `n` with no name (a memfd's, an `O_TMPFILE`'s): it
    /// lives while it is held ([`Tx::hold`]).
    pub fn create_unnamed(&mut self, n: &New) -> Result<Ino, i32> {
        self.new_inode(n)
    }

    /// A symbolic link named `name` in `dir` to `target`.
    pub fn symlink(
        &mut self,
        dir: Ino,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<Ino, i32> {
        let ino = self.create(dir, name, &New { mode: S_IFLNK | 0o777, uid, gid, rdev: 0 })?;
        let t = self.m.alloc(target.len())?;
        self.m.bytes_mut(t, target.len()).copy_from_slice(target);
        self.set_u64(ino, I_A, t)?;
        self.set_u64(ino, I_B, target.len() as u64)?;
        self.set_u64(ino, I_SIZE, target.len() as u64)?;
        Ok(ino)
    }

    pub fn readlink(&self, ino: Ino) -> Result<Vec<u8>, i32> {
        if self.get_u32(ino, I_MODE)? & S_IFMT != S_IFLNK {
            return Err(errno::EINVAL);
        }
        let (t, len) = (self.get_u64(ino, I_A)?, self.get_u64(ino, I_B)?);
        Ok(self.m.bytes(t, len as usize).to_vec())
    }

    /// Another name, `name` in `dir`, for `ino` (no directory).
    pub fn link(&mut self, ino: Ino, dir: Ino, name: &[u8]) -> Result<(), i32> {
        let mode = self.get_u32(ino, I_MODE)?;
        if mode & S_IFMT == S_IFDIR {
            return Err(errno::EPERM);
        }
        let d = self.dir(dir)?;
        if self.find(d, name).is_some() || matches!(name, b"." | b"..") {
            return Err(errno::EEXIST);
        }
        let links = self.get_u32(ino, I_NLINK)?;
        // A name past the first counts as an inode (not an `O_TMPFILE`
        // file's first).
        if links > 0 {
            self.reserve_inode()?;
        }
        if let Err(e) = self.add_entry(d, name, ino, mode & S_IFMT) {
            if links > 0 {
                self.release_name();
            }
            return Err(e);
        }
        self.set_u32(ino, I_NLINK, links + 1)?;
        self.touch_changed(ino)?;
        self.touch_changed(dir)
    }

    /// Remove `name` from `dir` (`EISDIR` for a directory unless `rmdir`,
    /// `ENOTDIR` for another file if it is, `ENOTEMPTY` for a directory
    /// with entries): the inode it named, and whether that has gone (no
    /// names and no holders: its data object is then to be removed, as
    /// the returned `data` says).
    pub fn unlink(&mut self, dir: Ino, name: &[u8], rmdir: bool) -> Result<Gone, i32> {
        let d = self.dir(dir)?;
        if matches!(name, b"." | b"..") {
            return Err(if rmdir { errno::EINVAL } else { errno::EISDIR });
        }
        let (slot, e) = self.find(d, name).ok_or(errno::ENOENT)?;
        let ino = self.m.u64_at(e + E_INO);
        let is_dir = self.get_u32(ino, I_MODE)? & S_IFMT == S_IFDIR;
        match (is_dir, rmdir) {
            (true, false) => return Err(errno::EISDIR),
            (false, true) => return Err(errno::ENOTDIR),
            (true, true) if self.m.u64_at(self.dir(ino)? + D_LIVE) != 0 => {
                return Err(errno::ENOTEMPTY);
            }
            _ => {}
        }
        self.remove_entry(d, slot, e);
        self.touch_changed(dir)?;
        let links = self.get_u32(ino, I_NLINK)?;
        if is_dir {
            self.set_u32(ino, I_NLINK, 0)?;
            let parent_links = self.get_u32(dir, I_NLINK)?;
            self.set_u32(dir, I_NLINK, parent_links.saturating_sub(1))?;
        } else {
            if links > 1 {
                self.release_name();
            }
            self.set_u32(ino, I_NLINK, links.saturating_sub(1))?;
            self.touch_changed(ino)?;
        }
        self.note_last(ino, dir, name)?;
        self.drop_if_gone(ino)
    }

    /// File `ino`, held, lost its last name, `name` in `dir`: kept with it
    /// ([`Tx::last_name`]).
    fn note_last(&mut self, ino: Ino, dir: Ino, name: &[u8]) -> Result<(), i32> {
        if self.get_u32(ino, I_NLINK)? != 0 || self.holders(ino)? == 0 {
            return Ok(());
        }
        let v = [&dir.to_le_bytes()[..], name].concat();
        self.set_xattr(ino, LAST_NAME, Some(&v))
    }

    /// The last name a file that has none had, and the directory it was
    /// in, as Linux's `/proc/<pid>/fd` links show it once removed.
    pub fn last_name(&self, ino: Ino) -> Option<(Ino, Vec<u8>)> {
        let v = self.xattr(ino, LAST_NAME).ok()?;
        Some((u64::from_le_bytes(v.get(..8)?.try_into().ok()?), v[8..].to_vec()))
    }

    /// Inode `ino` goes if it has no names and no holders.
    fn drop_if_gone(&mut self, ino: Ino) -> Result<Gone, i32> {
        if self.get_u32(ino, I_NLINK)? != 0 || self.holders(ino)? != 0 {
            return Ok(Gone { ino, data: None, node: false });
        }
        let node = matches!(self.get_u32(ino, I_MODE)? & S_IFMT, S_IFIFO | S_IFSOCK);
        let data = self.data(ino)?;
        self.free_inode(ino)?;
        Ok(Gone { ino, data: Some(data), node })
    }

    /// Rename `oname` in `odir` to `nname` in `ndir`, as `renameat2`
    /// with `flags` (`RENAME_NOREPLACE` 1, `RENAME_EXCHANGE` 2): what
    /// it replaced, if that has gone.
    pub fn rename(
        &mut self,
        odir: Ino,
        oname: &[u8],
        ndir: Ino,
        nname: &[u8],
        flags: u32,
    ) -> Result<Option<Gone>, i32> {
        const NOREPLACE: u32 = 1;
        const EXCHANGE: u32 = 2;
        let (od, nd) = (self.dir(odir)?, self.dir(ndir)?);
        if matches!(oname, b"." | b"..") || matches!(nname, b"." | b"..") {
            return Err(errno::EBUSY);
        }
        let (oslot, oe) = self.find(od, oname).ok_or(errno::ENOENT)?;
        let ino = self.m.u64_at(oe + E_INO);
        let kind = self.get_u32(ino, I_MODE)? & S_IFMT;
        // A directory is not moved into itself or below it.
        if kind == S_IFDIR && (odir != ndir) {
            let mut at = ndir;
            loop {
                if at == ino {
                    return Err(errno::EINVAL);
                }
                let up = self.get_u64(at, I_B)?;
                if up == at {
                    break;
                }
                at = up;
            }
        }
        let target = self.find(nd, nname);
        if flags & EXCHANGE != 0 {
            let (nslot, ne) = target.ok_or(errno::ENOENT)?;
            let other = self.m.u64_at(ne + E_INO);
            let okind = self.get_u32(other, I_MODE)? & S_IFMT;
            if okind == S_IFDIR && odir != ndir {
                let mut at = odir;
                loop {
                    if at == other {
                        return Err(errno::EINVAL);
                    }
                    let up = self.get_u64(at, I_B)?;
                    if up == at {
                        break;
                    }
                    at = up;
                }
            }
            let _ = (oslot, nslot);
            self.m.set_u64(oe + E_INO, other);
            self.set_u32_raw(oe + E_KIND, okind);
            self.m.set_u64(ne + E_INO, ino);
            self.set_u32_raw(ne + E_KIND, kind);
            if kind == S_IFDIR {
                self.set_u64(ino, I_B, ndir)?;
            }
            if okind == S_IFDIR {
                self.set_u64(other, I_B, odir)?;
            }
            if (kind == S_IFDIR) != (okind == S_IFDIR) && odir != ndir {
                let (to_new, to_old) = if kind == S_IFDIR { (1i64, -1i64) } else { (-1, 1) };
                for (dir, by) in [(ndir, to_new), (odir, to_old)] {
                    let l = self.get_u32(dir, I_NLINK)? as i64;
                    self.set_u32(dir, I_NLINK, (l + by) as u32)?;
                }
            }
            for i in [ino, other, odir, ndir] {
                self.touch_changed(i)?;
            }
            return Ok(None);
        }
        let mut replaced = None;
        if let Some((nslot, ne)) = target {
            if flags & NOREPLACE != 0 {
                return Err(errno::EEXIST);
            }
            let other = self.m.u64_at(ne + E_INO);
            if other == ino {
                return Ok(None);
            }
            let okind = self.get_u32(other, I_MODE)? & S_IFMT;
            match (kind == S_IFDIR, okind == S_IFDIR) {
                (true, false) => return Err(errno::ENOTDIR),
                (false, true) => return Err(errno::EISDIR),
                (true, true) if self.m.u64_at(self.dir(other)? + D_LIVE) != 0 => {
                    return Err(errno::ENOTEMPTY);
                }
                _ => {}
            }
            self.remove_entry(nd, nslot, ne);
            if okind == S_IFDIR {
                self.set_u32(other, I_NLINK, 0)?;
                let l = self.get_u32(ndir, I_NLINK)?;
                self.set_u32(ndir, I_NLINK, l.saturating_sub(1))?;
            } else {
                let l = self.get_u32(other, I_NLINK)?;
                if l > 1 {
                    self.release_name();
                }
                self.set_u32(other, I_NLINK, l.saturating_sub(1))?;
                self.touch_changed(other)?;
            }
            self.note_last(other, ndir, nname)?;
            replaced = Some(other);
        }
        // The entry looked up again: removing the target may have moved
        // nothing (entries move only as a directory is compacted, on adds).
        let (oslot, oe) = self.find(od, oname).ok_or(errno::ENOENT)?;
        self.remove_entry(od, oslot, oe);
        self.add_entry(nd, nname, ino, kind)?;
        if kind == S_IFDIR && odir != ndir {
            self.set_u64(ino, I_B, ndir)?;
            let ol = self.get_u32(odir, I_NLINK)?;
            self.set_u32(odir, I_NLINK, ol.saturating_sub(1))?;
            let nl = self.get_u32(ndir, I_NLINK)?;
            self.set_u32(ndir, I_NLINK, nl + 1)?;
        }
        for i in [ino, odir, ndir] {
            self.touch_changed(i)?;
        }
        match replaced {
            Some(other) => self.drop_if_gone(other).map(Some),
            None => Ok(None),
        }
    }

    /// Directory `dir`'s entries after position `pos` (`.` and `..`
    /// first), as many as `room` takes (each entry's name length plus
    /// `per`).
    pub fn list(&self, dir: Ino, pos: u64, room: usize, per: usize) -> Result<Vec<Entry>, i32> {
        let d = self.dir(dir)?;
        let mut out = Vec::new();
        let mut used = 0;
        let mut push = |e: Entry, out: &mut Vec<Entry>| {
            let n = per + e.name.len();
            if used + n > room {
                return false;
            }
            used += n;
            out.push(e);
            true
        };
        if pos < POS_DOT
            && !push(Entry { pos: POS_DOT, ino: dir, kind: S_IFDIR, name: b".".to_vec() }, &mut out)
        {
            return Ok(out);
        }
        if pos < POS_DOTDOT {
            let parent = self.get_u64(dir, I_B)?;
            let e = Entry { pos: POS_DOTDOT, ino: parent, kind: S_IFDIR, name: b"..".to_vec() };
            if !push(e, &mut out) {
                return Ok(out);
            }
        }
        let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
        // Entries are in order of their numbers: the first past `pos`.
        let (mut lo, mut hi) = (0, len);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.m.u64_at(entries + mid * ENTRY + E_POS) <= pos {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        for n in lo..len {
            let e = entries + n * ENTRY;
            let ino = self.m.u64_at(e + E_INO);
            if ino == 0 {
                continue;
            }
            let (nm, nlen) = (self.m.u64_at(e + E_NAME), self.u32_raw(e + E_LEN));
            let entry = Entry {
                pos: self.m.u64_at(e + E_POS),
                ino,
                kind: self.u32_raw(e + E_KIND),
                name: self.m.bytes(nm, nlen as usize).to_vec(),
            };
            if !push(entry, &mut out) {
                break;
            }
        }
        Ok(out)
    }

    /// Whether directory `dir` has no entries.
    pub fn is_empty_dir(&self, dir: Ino) -> Result<bool, i32> {
        Ok(self.m.u64_at(self.dir(dir)? + D_LIVE) == 0)
    }

    pub fn set_mode(&mut self, ino: Ino, mode: u32) -> Result<(), i32> {
        let old = self.get_u32(ino, I_MODE)?;
        self.set_u32(ino, I_MODE, (old & S_IFMT) | (mode & !S_IFMT))?;
        self.touch_changed(ino)
    }

    pub fn set_owner(&mut self, ino: Ino, uid: Option<u32>, gid: Option<u32>) -> Result<(), i32> {
        if let Some(u) = uid {
            self.set_u32(ino, I_UID, u)?;
        }
        if let Some(g) = gid {
            self.set_u32(ino, I_GID, g)?;
        }
        self.touch_changed(ino)
    }

    pub fn set_flags(&mut self, ino: Ino, flags: u32) -> Result<(), i32> {
        self.set_u32(ino, I_FLAGS, flags)?;
        self.touch_changed(ino)
    }

    /// Set the access and modification times (nanoseconds since the
    /// epoch); the change time is now.
    pub fn set_times(
        &mut self,
        ino: Ino,
        atime: Option<i64>,
        mtime: Option<i64>,
    ) -> Result<(), i32> {
        if let Some(a) = atime {
            self.set_u64(ino, I_ATIME, a as u64)?;
        }
        if let Some(m) = mtime {
            self.set_u64(ino, I_MTIME, m as u64)?;
        }
        self.touch_changed(ino)
    }

    /// The file was read through a mount with `flags`: its access time
    /// moved as Linux moves it (`touch_atime`), never on a `noatime` mount
    /// (nor a directory's on a `nodiratime` one), always on a
    /// `strictatime` one, and otherwise (`relatime`) when it is not after
    /// the file's last modification or change, or is a day old.
    pub fn accessed(&mut self, ino: Ino, flags: u64) -> Result<(), i32> {
        use crate::mounts::ms;
        let st = self.stat(ino)?;
        let dir = st.mode & S_IFMT == S_IFDIR;
        // (A file of `FS_NOATIME_FL` as one on a `noatime` mount.)
        const FS_NOATIME_FL: u32 = 0x80;
        if flags & ms::NOATIME != 0
            || st.flags & FS_NOATIME_FL != 0
            || (dir && flags & ms::NODIRATIME != 0)
        {
            return Ok(());
        }
        let now = now_ns();
        const DAY: i64 = 86_400 * 1_000_000_000;
        if flags & ms::STRICTATIME == 0
            && st.atime > st.mtime
            && st.atime > st.ctime
            && now - st.atime < DAY
        {
            return Ok(());
        }
        self.set_u64(ino, I_ATIME, now as u64)
    }

    /// The file's data changed: its modification and change times are
    /// now.
    pub fn touch_modified(&mut self, ino: Ino) -> Result<(), i32> {
        let t = now_ns() as u64;
        self.set_u64(ino, I_MTIME, t)?;
        self.set_u64(ino, I_CTIME, t)
    }

    fn touch_changed(&mut self, ino: Ino) -> Result<(), i32> {
        let t = now_ns() as u64;
        if self.get_u32(ino, I_MODE)? & S_IFMT == S_IFDIR {
            self.set_u64(ino, I_MTIME, t)?;
        }
        self.set_u64(ino, I_CTIME, t)
    }

    /// A regular file's data object (0: none yet).
    pub fn data(&self, ino: Ino) -> Result<u64, i32> {
        if self.get_u32(ino, I_MODE)? & S_IFMT != S_IFREG {
            return Ok(0);
        }
        self.get_u64(ino, I_A)
    }

    pub fn set_data(&mut self, ino: Ino, object: u64) -> Result<(), i32> {
        self.set_u64(ino, I_A, object)
    }

    pub fn set_size(&mut self, ino: Ino, size: u64) -> Result<(), i32> {
        self.set_u64(ino, I_SIZE, size)
    }

    pub fn seals(&self, ino: Ino) -> Result<u32, i32> {
        self.get_u32(ino, I_SEALS)
    }

    pub fn set_seals(&mut self, ino: Ino, seals: u32) -> Result<(), i32> {
        self.set_u32(ino, I_SEALS, seals)
    }

    /// The filesystem's limits: bytes of data and inodes (0: none).
    pub fn limits(&self) -> (u64, u64) {
        (self.m.root(R_LIMIT_BYTES), self.m.root(R_LIMIT_INODES))
    }

    /// A remount's new size and number of inodes (`None`: as they are; 0:
    /// none), as Linux's tmpfs takes them: no limit set where there was
    /// none, and none below what is in use (`EINVAL`).
    pub fn limit(&mut self, bytes: Option<u64>, inodes: Option<u64>) -> Result<(), i32> {
        let (had_bytes, had_inodes) = self.limits();
        let (used_bytes, used_inodes) = self.usage();
        if let Some(b) = bytes.filter(|&b| b != 0)
            && (had_bytes == 0 || b < used_bytes)
        {
            return Err(errno::EINVAL);
        }
        if let Some(n) = inodes.filter(|&n| n != 0)
            && (had_inodes == 0 || n < used_inodes)
        {
            return Err(errno::EINVAL);
        }
        self.set_limits(bytes.unwrap_or(had_bytes), inodes.unwrap_or(had_inodes));
        Ok(())
    }

    pub fn set_limits(&mut self, bytes: u64, inodes: u64) {
        self.m.set_root(R_LIMIT_BYTES, bytes);
        self.m.set_root(R_LIMIT_INODES, inodes);
    }

    /// The device number (Linux's) its files are on.
    pub fn dev(&self) -> u64 {
        self.m.root(R_DEV)
    }

    pub fn set_dev(&mut self, dev: u64) {
        self.m.set_root(R_DEV, dev);
    }

    /// What it uses: bytes of data and inodes.
    pub fn usage(&self) -> (u64, u64) {
        (self.m.root(R_BYTES), self.m.root(R_USED))
    }

    fn allocated_of(&self, at: u64) -> u64 {
        let (r, n) = (self.m.u64_at(at + I_RANGES), self.u32_raw(at + I_RANGES_LEN));
        (0..n as u64)
            .map(|i| self.m.u64_at(r + i * 16 + 8) - self.m.u64_at(r + i * 16))
            .sum::<u64>()
            * super::data::PAGE
    }

    fn ranges(&self, ino: Ino) -> Result<Vec<(u64, u64)>, i32> {
        let at = self.slot(ino)?;
        let (r, n) = (self.m.u64_at(at + I_RANGES), self.u32_raw(at + I_RANGES_LEN));
        Ok((0..n as u64)
            .map(|i| (self.m.u64_at(r + i * 16), self.m.u64_at(r + i * 16 + 8)))
            .collect())
    }

    fn set_ranges(&mut self, ino: Ino, ranges: &[(u64, u64)]) -> Result<(), i32> {
        let at = self.slot(ino)?;
        let (r, n) = (self.m.u64_at(at + I_RANGES), self.u32_raw(at + I_RANGES_LEN));
        let new = if ranges.is_empty() {
            self.m.free(r, n as usize * 16);
            0
        } else {
            let new = self.m.realloc(r, n as usize * 16, ranges.len() * 16)?;
            for (i, &(s, e)) in ranges.iter().enumerate() {
                self.m.set_u64(new + i as u64 * 16, s);
                self.m.set_u64(new + i as u64 * 16 + 8, e);
            }
            new
        };
        self.m.set_u64(at + I_RANGES, new);
        self.set_u32_raw(at + I_RANGES_LEN, ranges.len() as u32);
        Ok(())
    }

    /// The ranges of pages of `ino`'s data that hold memory.
    pub fn ranges_of(&self, ino: Ino) -> Result<Vec<(u64, u64)>, i32> {
        self.ranges(ino)
    }

    /// `ino`'s ranges as [`Tx::ranges_of`] gave them before: what was taken
    /// since goes back to the filesystem.
    pub fn restore_ranges(&mut self, ino: Ino, before: &[(u64, u64)]) -> Result<(), i32> {
        let count = |r: &[(u64, u64)]| r.iter().map(|(s, e)| e - s).sum::<u64>();
        let now = count(&self.ranges(ino)?);
        self.set_ranges(ino, before)?;
        let used = self.m.root(R_BYTES);
        let taken = now.saturating_sub(count(before)) * super::data::PAGE;
        self.m.set_root(R_BYTES, used.saturating_sub(taken));
        Ok(())
    }

    /// Pages `[start, end)` of `ino`'s data are to hold memory: `ENOSPC`
    /// past the filesystem's size, the pages that fit taken (how many
    /// bytes from `start`'s page on now hold memory, at most what was
    /// asked).
    pub fn allocate(&mut self, ino: Ino, start: u64, end: u64) -> Result<u64, i32> {
        let ranges = self.ranges(ino)?;
        let page = super::data::PAGE;
        let (limit, used) = (self.m.root(R_LIMIT_BYTES), self.m.root(R_BYTES));
        let mut room = if limit == 0 { u64::MAX } else { limit.saturating_sub(used) / page };
        // The pages not yet held, in order, each granted while there is
        // room; `reach`: the first page from `start` not held after.
        let mut granted = Vec::new();
        let mut at = start;
        let mut reach = None;
        let held = ranges.iter().copied().filter(|&(s, e)| e > start && s < end);
        for (s, e) in held.chain(std::iter::once((end, end))) {
            if s > at {
                let n = (s - at).min(room);
                if n > 0 {
                    granted.push((at, at + n));
                    room -= n;
                }
                if at + n < s {
                    reach = Some(at + n);
                    break;
                }
            }
            at = at.max(e);
        }
        let reach = reach.unwrap_or(end);
        if reach == start && end > start {
            return Err(errno::ENOSPC);
        }
        let taken: u64 = granted.iter().map(|(s, e)| e - s).sum();
        let mut all: Vec<(u64, u64)> = ranges.into_iter().chain(granted).collect();
        all.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(all.len());
        for (s, e) in all {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.set_ranges(ino, &merged)?;
        self.m.set_root(R_BYTES, used + taken * page);
        Ok((reach - start) * page)
    }

    /// Pages `[start, end)` of `ino`'s data hold no memory now (cut off
    /// or punched out).
    pub fn release(&mut self, ino: Ino, start: u64, end: u64) -> Result<(), i32> {
        let ranges = self.ranges(ino)?;
        let mut kept = Vec::with_capacity(ranges.len() + 1);
        let mut freed = 0;
        for (s, e) in ranges {
            if e <= start || s >= end {
                kept.push((s, e));
                continue;
            }
            if s < start {
                kept.push((s, start));
            }
            if e > end {
                kept.push((end, e));
            }
            freed += e.min(end) - s.max(start);
        }
        self.set_ranges(ino, &kept)?;
        let used = self.m.root(R_BYTES);
        self.m.set_root(R_BYTES, used.saturating_sub(freed * super::data::PAGE));
        Ok(())
    }

    /// The extended attribute `name` of `ino`.
    pub fn xattr(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>, i32> {
        self.xattrs(ino)?.into_iter().find(|(n, _)| n == name).map(|(_, v)| v).ok_or(errno::ENODATA)
    }

    /// All of `ino`'s extended attributes, in the order they were set.
    pub fn xattrs(&self, ino: Ino) -> Result<Xattrs, i32> {
        let at = self.slot(ino)?;
        let (x, len) = (self.m.u64_at(at + I_XATTRS), self.u32_raw(at + I_XATTRS_LEN));
        let bytes = if x == 0 { Vec::new() } else { self.m.bytes(x, len as usize).to_vec() };
        let mut out = Vec::new();
        let mut i = 0;
        while i + 8 <= bytes.len() {
            let n = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
            let v = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
            i += 8;
            out.push((bytes[i..i + n].to_vec(), bytes[i + n..i + n + v].to_vec()));
            i += n + v;
        }
        Ok(out)
    }

    /// Set (or with `None` remove) `ino`'s attribute `name`.
    pub fn set_xattr(&mut self, ino: Ino, name: &[u8], value: Option<&[u8]>) -> Result<(), i32> {
        let mut all = self.xattrs(ino)?;
        let had = all.iter().position(|(n, _)| n == name);
        match (had, value) {
            (Some(i), Some(v)) => all[i].1 = v.to_vec(),
            (None, Some(v)) => all.push((name.to_vec(), v.to_vec())),
            (Some(i), None) => {
                all.remove(i);
            }
            (None, None) => return Err(errno::ENODATA),
        }
        let mut bytes = Vec::new();
        for (n, v) in &all {
            bytes.extend_from_slice(&(n.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
            bytes.extend_from_slice(n);
            bytes.extend_from_slice(v);
        }
        let at = self.slot(ino)?;
        let (x, len) = (self.m.u64_at(at + I_XATTRS), self.u32_raw(at + I_XATTRS_LEN));
        let new = if bytes.is_empty() {
            self.m.free(x, len as usize);
            0
        } else {
            let n = self.m.realloc(x, len as usize, bytes.len())?;
            self.m.bytes_mut(n, bytes.len()).copy_from_slice(&bytes);
            n
        };
        self.m.set_u64(at + I_XATTRS, new);
        self.set_u32_raw(at + I_XATTRS_LEN, bytes.len() as u32);
        self.touch_changed(ino)
    }

    /// The bytes kept at `ino`'s fields `f` (where) and `fl` (how many).
    fn blob(&self, ino: Ino, f: u64, fl: u64) -> Result<Vec<u8>, i32> {
        let at = self.slot(ino)?;
        let (b, len) = (self.m.u64_at(at + f), self.u32_raw(at + fl));
        Ok(if b == 0 { Vec::new() } else { self.m.bytes(b, len as usize).to_vec() })
    }

    fn set_blob(&mut self, ino: Ino, f: u64, fl: u64, bytes: &[u8]) -> Result<(), i32> {
        let at = self.slot(ino)?;
        let (b, len) = (self.m.u64_at(at + f), self.u32_raw(at + fl));
        let new = if bytes.is_empty() {
            self.m.free(b, len as usize);
            0
        } else {
            let n = self.m.realloc(b, len as usize, bytes.len())?;
            self.m.bytes_mut(n, bytes.len()).copy_from_slice(bytes);
            n
        };
        self.m.set_u64(at + f, new);
        self.set_u32_raw(at + fl, bytes.len() as u32);
        Ok(())
    }

    /// Whether `ino`, with no names, may be named ([`LINKABLE`]).
    pub fn linkable(&self, ino: Ino) -> Result<bool, i32> {
        Ok(self.xattrs(ino)?.iter().any(|(n, _)| n == LINKABLE))
    }

    pub fn set_linkable(&mut self, ino: Ino, linkable: bool) -> Result<(), i32> {
        if linkable == self.linkable(ino)? {
            return Ok(());
        }
        self.set_xattr(ino, LINKABLE, linkable.then_some(&b""[..]))
    }

    /// How many descriptors hold `ino` open, in every process.
    pub fn holders(&self, ino: Ino) -> Result<u64, i32> {
        Ok(self.holder_list(ino)?.iter().map(|h| h.count as u64).sum())
    }

    fn holder_list(&self, ino: Ino) -> Result<Vec<Holder>, i32> {
        let b = self.blob(ino, I_HOLDERS, I_HOLDERS_LEN)?;
        Ok(b.as_chunks::<HOLDER>().0.iter().map(|c| Holder::decode(c)).collect())
    }

    fn set_holder_list(&mut self, ino: Ino, list: &[Holder]) -> Result<(), i32> {
        let bytes: Vec<u8> = list.iter().flat_map(Holder::encode).collect();
        self.set_blob(ino, I_HOLDERS, I_HOLDERS_LEN, &bytes)
    }

    /// `ino`'s locks.
    pub fn locks(&self, ino: Ino) -> Result<Vec<Lock>, i32> {
        let b = self.blob(ino, I_LOCKS, I_LOCKS_LEN)?;
        Ok(b.as_chunks::<LOCK>().0.iter().map(|c| Lock::decode(c)).collect())
    }

    /// `ino`'s locks are `locks` now; with fewer than before, the arena's
    /// waiters are woken to look again.
    pub fn set_locks(&mut self, ino: Ino, locks: &[Lock]) -> Result<(), i32> {
        let before = self.locks(ino)?;
        let bytes: Vec<u8> = locks.iter().flat_map(Lock::encode).collect();
        self.set_blob(ino, I_LOCKS, I_LOCKS_LEN, &bytes)?;
        if before.iter().any(|l| !locks.contains(l)) {
            self.m.changed();
        }
        Ok(())
    }

    /// Let go of the locks of `ino` `gone` says are no longer anyone's.
    fn drop_locks(&mut self, ino: Ino, gone: impl Fn(&Lock) -> bool) -> Result<(), i32> {
        let locks = self.locks(ino)?;
        if locks.iter().any(&gone) {
            let kept: Vec<Lock> = locks.into_iter().filter(|l| !gone(l)).collect();
            self.set_locks(ino, &kept)?;
        }
        Ok(())
    }

    /// The processes waiting for a record lock of the filesystem, each with
    /// the process that holds the lock in its way (host pids and starts):
    /// what finds a wait that would never end ([`super::locks`]).
    pub fn waiters(&self) -> Vec<[(i32, u64); 2]> {
        let (b, len) = (self.m.root(R_WAIT), self.m.root(R_WAIT_LEN));
        if b == 0 {
            return Vec::new();
        }
        self.m
            .bytes(b, len as usize)
            .as_chunks::<24>()
            .0
            .iter()
            .map(|c| [(le32(c, 0) as i32, le64(c, 8)), (le32(c, 4) as i32, le64(c, 16))])
            .collect()
    }

    pub fn set_waiters(&mut self, list: &[[(i32, u64); 2]]) -> Result<(), i32> {
        let mut bytes = Vec::with_capacity(list.len() * 24);
        for [(p, ps), (q, qs)] in list {
            bytes.extend_from_slice(&p.to_le_bytes());
            bytes.extend_from_slice(&q.to_le_bytes());
            bytes.extend_from_slice(&ps.to_le_bytes());
            bytes.extend_from_slice(&qs.to_le_bytes());
        }
        let (b, len) = (self.m.root(R_WAIT), self.m.root(R_WAIT_LEN));
        let new = if bytes.is_empty() {
            self.m.free(b, len as usize);
            0
        } else {
            let n = self.m.realloc(b, len as usize, bytes.len())?;
            self.m.bytes_mut(n, bytes.len()).copy_from_slice(&bytes);
            n
        };
        self.m.set_root(R_WAIT, new);
        self.m.set_root(R_WAIT_LEN, bytes.len() as u64);
        Ok(())
    }

    /// Process `p` (host pid, start) no longer holds record locks of `ino`
    /// (`F_SETLK`'s: it closed a descriptor of the file, or ended).
    pub fn drop_record_locks(&mut self, ino: Ino, p: (i32, u64)) -> Result<(), i32> {
        self.drop_locks(ino, |l| l.kind == LockKind::Posix && (l.pid, l.owner) == p)
    }

    /// Process `p` (host pid, start) holds `ino` with `descs`, the open file
    /// descriptions it has of it and how many descriptors of each (none:
    /// it holds it no more). A description no process holds any more lets
    /// go of its locks (`flock`'s, `F_OFD_SETLK`'s); with no descriptor
    /// left anywhere and no names, the file goes.
    pub fn hold(&mut self, ino: Ino, p: (i32, u64), descs: &[(u64, u32)]) -> Result<Gone, i32> {
        let before = self.holder_list(ino)?;
        let mut list: Vec<Holder> =
            before.iter().copied().filter(|h| (h.pid, h.start) != p).collect();
        list.extend(descs.iter().filter(|d| d.1 > 0).map(|&(desc, count)| Holder {
            pid: p.0,
            start: p.1,
            desc,
            count,
        }));
        self.set_holder_list(ino, &list)?;
        self.released(ino, &before, &list)?;
        self.drop_if_gone(ino)
    }

    /// The descriptions held in `before` and in no holder of `now` let go of
    /// their locks.
    fn released(&mut self, ino: Ino, before: &[Holder], now: &[Holder]) -> Result<(), i32> {
        let gone: Vec<u64> =
            before.iter().map(|h| h.desc).filter(|d| !now.iter().any(|h| h.desc == *d)).collect();
        if gone.is_empty() {
            return Ok(());
        }
        self.drop_locks(ino, |l| l.kind != LockKind::Posix && gone.contains(&l.owner))
    }

    /// Process `p` holds `ino` with `descs` unless it counted itself
    /// already: a fork child counted from its parent's side, which knows
    /// better once it counted itself.
    pub fn hold_unless_counted(
        &mut self,
        ino: Ino,
        p: (i32, u64),
        descs: &[(u64, u32)],
    ) -> Result<(), i32> {
        let mut list = self.holder_list(ino)?;
        if list.iter().any(|h| (h.pid, h.start) == p) {
            return Ok(());
        }
        list.extend(descs.iter().filter(|d| d.1 > 0).map(|&(desc, count)| Holder {
            pid: p.0,
            start: p.1,
            desc,
            count,
        }));
        self.set_holder_list(ino, &list)
    }

    /// Forget the holders `alive` says have ended, of `ino`, and the record
    /// locks they owned; the descriptions only they held let go of theirs:
    /// whether the file has gone.
    /// Whether a description open for writing ([`WRITER`]) holds `ino`,
    /// in a process `alive` says lives: running it is `ETXTBSY`.
    pub fn written(&self, ino: Ino, alive: impl Fn((i32, u64)) -> bool) -> Result<bool, i32> {
        Ok(self.holder_list(ino)?.iter().any(|h| h.desc & WRITER != 0 && alive((h.pid, h.start))))
    }

    pub fn reap(&mut self, ino: Ino, alive: impl Fn((i32, u64)) -> bool) -> Result<Gone, i32> {
        let before = self.holder_list(ino)?;
        let list: Vec<Holder> =
            before.iter().copied().filter(|h| alive((h.pid, h.start))).collect();
        if list.len() != before.len() {
            self.set_holder_list(ino, &list)?;
            self.released(ino, &before, &list)?;
        }
        self.drop_locks(ino, |l| l.kind == LockKind::Posix && !alive((l.pid, l.owner)))?;
        self.drop_if_gone(ino)
    }

    /// Every live inode.
    pub fn inodes(&self) -> Vec<Ino> {
        let (table, cap) = (self.m.root(R_TABLE), self.m.root(R_CAP));
        (1..=cap)
            .filter_map(|i| {
                let at = table + (i - 1) * INODE;
                (self.u32_raw(at + I_MODE) != 0)
                    .then(|| (self.u32_raw(at + I_GEN) as u64) << 32 | i)
            })
            .collect()
    }

    /// Every inode with no names (held only, or left by processes that
    /// ended): for a sweep that reaps their holders.
    pub fn unnamed(&self) -> Vec<Ino> {
        let (table, cap) = (self.m.root(R_TABLE), self.m.root(R_CAP));
        (1..=cap)
            .filter_map(|i| {
                let at = table + (i - 1) * INODE;
                let mode = self.u32_raw(at + I_MODE);
                (mode != 0 && self.u32_raw(at + I_NLINK) == 0)
                    .then(|| (self.u32_raw(at + I_GEN) as u64) << 32 | i)
            })
            .collect()
    }

    /// Make again what may be wrong after a holder died mid-change: each
    /// directory's index, from its entries.
    pub fn repair(&mut self) {
        let (table, cap) = (self.m.root(R_TABLE), self.m.root(R_CAP));
        for i in 1..=cap {
            let at = table + (i - 1) * INODE;
            if self.u32_raw(at + I_MODE) & S_IFMT != S_IFDIR {
                continue;
            }
            let d = self.m.u64_at(at + I_A);
            if d == 0 {
                continue;
            }
            let (entries, len) = (self.m.u64_at(d + D_ENTRIES), self.m.u64_at(d + D_LEN));
            let live =
                (0..len).filter(|&n| self.m.u64_at(entries + n * ENTRY + E_INO) != 0).count();
            self.m.set_u64(d + D_LIVE, live as u64);
            let icap = ((live as u64 + 1) * 4).next_power_of_two().max(16);
            let _ = self.reindex(d, icap);
        }
    }
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A process's holding of a file through one open file description: the
/// process (its host pid and start), the description, how many of its
/// descriptors are of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Holder {
    pid: i32,
    start: u64,
    desc: u64,
    count: u32,
}

const HOLDER: usize = 24;

/// The bit of a description's id that marks it open for writing.
pub const WRITER: u64 = 1 << 63;

impl Holder {
    fn encode(&self) -> [u8; HOLDER] {
        let mut b = [0u8; HOLDER];
        b[0..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.count.to_le_bytes());
        b[8..16].copy_from_slice(&self.start.to_le_bytes());
        b[16..24].copy_from_slice(&self.desc.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> Holder {
        Holder { pid: le32(b, 0) as i32, count: le32(b, 4), start: le64(b, 8), desc: le64(b, 16) }
    }
}

/// Whose a lock is: an open file description's (`flock`, apart from the
/// rest; `F_OFD_SETLK`), or a process's (`F_SETLK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    Flock,
    Posix,
    Ofd,
}

/// A lock of a file: its kind, whether it excludes all others (a write
/// lock) or only writers (a read lock), its owner (a description's id, or
/// for a process's its start, with its host pid), and its range of bytes,
/// `[start, end)` (`u64::MAX`: to the end of the file, however far).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    pub kind: LockKind,
    pub write: bool,
    pub pid: i32,
    pub owner: u64,
    pub start: u64,
    pub end: u64,
}

const LOCK: usize = 32;

impl Lock {
    fn encode(&self) -> [u8; LOCK] {
        let mut b = [0u8; LOCK];
        b[0] = match self.kind {
            LockKind::Flock => 1,
            LockKind::Posix => 2,
            LockKind::Ofd => 3,
        };
        b[1] = self.write as u8;
        b[4..8].copy_from_slice(&self.pid.to_le_bytes());
        b[8..16].copy_from_slice(&self.owner.to_le_bytes());
        b[16..24].copy_from_slice(&self.start.to_le_bytes());
        b[24..32].copy_from_slice(&self.end.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> Lock {
        Lock {
            kind: match b[0] {
                1 => LockKind::Flock,
                2 => LockKind::Posix,
                _ => LockKind::Ofd,
            },
            write: b[1] != 0,
            pid: le32(b, 4) as i32,
            owner: le64(b, 8),
            start: le64(b, 16),
            end: le64(b, 24),
        }
    }
}

/// What a call left of an inode: gone, its data object to remove too.
#[derive(Debug, PartialEq, Eq)]
pub struct Gone {
    pub ino: Ino,
    /// The inode went: its data object (0: it had none).
    pub data: Option<u64>,
    /// It went, and was a FIFO or a socket: the host's node behind it goes
    /// too ([`crate::storenodes`]).
    pub node: bool,
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn fresh() -> (u64, Arena) {
        let id = crate::shared::unique();
        Arena::remove(id);
        (id, Arena::open(id, true).expect("made"))
    }

    fn root_dir() -> New {
        New { mode: S_IFDIR | 0o1777, uid: 0, gid: 0, rdev: 0 }
    }

    fn file(mode: u32) -> New {
        New { mode: S_IFREG | mode, uid: 1000, gid: 100, rdev: 0 }
    }

    /// Files and directories made, found, linked, renamed and removed,
    /// with their link counts as Linux keeps them.
    #[test]
    fn names_are_made_found_and_removed() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let root = t.root();
        assert_eq!(t.stat(root).unwrap().nlink, 2);
        let f = t.create(root, b"f", &file(0o644)).unwrap();
        assert_eq!(t.create(root, b"f", &file(0o644)), Err(errno::EEXIST));
        let d =
            t.create(root, b"d", &New { mode: S_IFDIR | 0o755, uid: 0, gid: 0, rdev: 0 }).unwrap();
        assert_eq!(t.stat(root).unwrap().nlink, 3);
        assert_eq!(t.lookup(root, b"f"), Ok(f));
        assert_eq!(t.lookup(d, b".."), Ok(root));
        assert_eq!(t.lookup(f, b"x"), Err(errno::ENOTDIR));
        t.link(f, d, b"g").unwrap();
        assert_eq!(t.stat(f).unwrap().nlink, 2);
        assert_eq!(t.unlink(root, b"d", true), Err(errno::ENOTEMPTY));
        assert_eq!(t.unlink(root, b"d", false), Err(errno::EISDIR));
        // Renamed over another name of itself: nothing happens.
        assert_eq!(t.rename(d, b"g", root, b"f", 0), Ok(None));
        let gone = t.unlink(root, b"f", false).unwrap();
        assert_eq!(gone.data, None);
        let gone = t.unlink(d, b"g", false).unwrap();
        assert_eq!(gone, Gone { ino: f, data: Some(0), node: false });
        assert_eq!(t.stat(f), Err(errno::ENOENT));
        // A slot used again is another inode number.
        let f2 = t.create(root, b"f2", &file(0o600)).unwrap();
        assert_ne!(f2, f);
        assert_eq!(f2 & 0xffff_ffff, f & 0xffff_ffff);
        // A directory moved into itself is refused; elsewhere, its parent
        // follows.
        let e = t.create(d, b"e", &New { mode: S_IFDIR | 0o755, uid: 0, gid: 0, rdev: 0 }).unwrap();
        assert_eq!(t.rename(root, b"d", e, b"x", 0), Err(errno::EINVAL));
        t.rename(d, b"e", root, b"e", 0).unwrap();
        assert_eq!(t.lookup(e, b".."), Ok(root));
        assert_eq!(t.stat(root).unwrap().nlink, 4);
        assert_eq!(t.stat(d).unwrap().nlink, 2);
        t.unlink(root, b"d", true).unwrap();
        assert_eq!(t.stat(root).unwrap().nlink, 3);
        drop(t);
        Arena::remove(id);
    }

    /// Names made and removed one after another, from a directory's first
    /// entry on, a few live at a time, as `/dev/shm`'s temporary files are
    /// (`sem_open`'s): each is found while it is there and missing before
    /// and after, however many were removed before it, of names of the
    /// same length.
    #[test]
    fn a_missing_name_is_found_missing_after_many_removals() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let root = t.root();
        for n in 0..1000 {
            if n == 500 {
                t.create(root, b"kept", &file(0o600)).unwrap();
            }
            let name = format!("tmp.{n:04}");
            assert_eq!(t.lookup(root, name.as_bytes()), Err(errno::ENOENT), "{name}");
            let ino = t.create(root, name.as_bytes(), &file(0o600)).unwrap();
            assert_eq!(t.lookup(root, name.as_bytes()), Ok(ino), "{name}");
            t.unlink(root, name.as_bytes(), false).unwrap();
        }
        assert_eq!(t.lookup(root, b"missing"), Err(errno::ENOENT));
        assert!(t.lookup(root, b"kept").is_ok());
        drop(t);
        Arena::remove(id);
    }

    /// A listing resumes after the last entry it gave, whatever was added
    /// and removed meanwhile, past compactions too.
    #[test]
    fn listings_resume_where_they_left_off() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let root = t.root();
        for i in 0..300 {
            t.create(root, format!("n{i}").as_bytes(), &file(0o644)).unwrap();
        }
        // A listing stops at its room: entries of 20 bytes and a name.
        assert_eq!(t.list(root, 0, 21 + 22, 20).unwrap().len(), 2);
        let first: Vec<_> = t.list(root, 0, usize::MAX, 20).unwrap().into_iter().take(10).collect();
        assert_eq!(first[0].name, b".");
        assert_eq!(first[1].name, b"..");
        let last = first.last().unwrap().pos;
        // Most removed (compacting the directory as names are added), one
        // added.
        for i in 0..290 {
            t.unlink(root, format!("n{i}").as_bytes(), false).unwrap();
        }
        for i in 0..100 {
            t.create(root, format!("m{i}").as_bytes(), &file(0o644)).unwrap();
        }
        let rest = t.list(root, last, usize::MAX, 20).unwrap();
        let names: Vec<_> =
            rest.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()).collect();
        assert_eq!(names.len(), 110);
        assert_eq!(names[0], "n290");
        assert_eq!(names[10], "m0");
        assert!(t.lookup(root, b"m99").is_ok());
        assert_eq!(t.lookup(root, b"n5"), Err(errno::ENOENT));
        drop(t);
        Arena::remove(id);
    }

    /// A file with no names lives while it is held; holders that ended are
    /// reaped.
    #[test]
    fn unnamed_files_live_while_held() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let root = t.root();
        let f = t.create(root, b"f", &file(0o644)).unwrap();
        t.set_data(f, 7).unwrap();
        t.hold(f, (1, 10), &[(100, 2)]).unwrap();
        assert_eq!(t.unlink(root, b"f", false).unwrap().data, None);
        assert_eq!(t.unnamed(), vec![f]);
        assert_eq!(t.hold(f, (2, 20), &[(100, 1)]).unwrap().data, None);
        assert_eq!(t.hold(f, (1, 10), &[]).unwrap().data, None);
        assert_eq!(t.reap(f, |p| p != (2, 20)).unwrap().data, Some(7));
        assert!(t.unnamed().is_empty());
        drop(t);
        Arena::remove(id);
    }

    /// Data's memory is counted against the filesystem's size: a write
    /// past it takes what fits, then none; a range given back is room
    /// again.
    #[test]
    fn data_is_counted_against_the_size() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let page = super::super::data::PAGE;
        t.set_limits(4 * page, 0);
        let f = t.create(t.root(), b"f", &file(0o644)).unwrap();
        assert_eq!(t.allocate(f, 0, 2), Ok(2 * page));
        // Already held: free.
        assert_eq!(t.allocate(f, 1, 2), Ok(page));
        assert_eq!(t.allocate(f, 4, 10), Ok(2 * page));
        assert_eq!(t.allocate(f, 6, 7), Err(errno::ENOSPC));
        assert_eq!(t.stat(f).unwrap().allocated, 4 * page);
        t.release(f, 1, 5).unwrap();
        assert_eq!(t.usage().0, 2 * page);
        assert_eq!(t.allocate(f, 2, 3), Ok(page));
        drop(t);
        Arena::remove(id);
    }

    /// A file's names past its first count as inodes, as Linux's tmpfs
    /// counts them: a link past the limit is refused, and a name removed
    /// is room again.
    #[test]
    fn extra_names_count_as_inodes() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        // The root, a file and one more name.
        t.set_limits(0, 3);
        let f = t.create(t.root(), b"f", &file(0o644)).unwrap();
        t.link(f, t.root(), b"g").unwrap();
        assert_eq!(t.usage().1, 3);
        assert_eq!(t.link(f, t.root(), b"h"), Err(errno::ENOSPC));
        t.unlink(t.root(), b"g", false).unwrap();
        assert_eq!(t.usage().1, 2);
        t.link(f, t.root(), b"h").unwrap();
        t.unlink(t.root(), b"f", false).unwrap();
        t.unlink(t.root(), b"h", false).unwrap();
        assert_eq!(t.usage().1, 1);
        drop(t);
        Arena::remove(id);
    }

    /// Extended attributes, set, replaced, listed and removed.
    #[test]
    fn extended_attributes_are_kept() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let f = t.create(t.root(), b"f", &file(0o644)).unwrap();
        t.set_xattr(f, b"user.a", Some(b"1")).unwrap();
        t.set_xattr(f, b"user.b", Some(b"22")).unwrap();
        t.set_xattr(f, b"user.a", Some(b"333")).unwrap();
        assert_eq!(t.xattr(f, b"user.a"), Ok(b"333".to_vec()));
        t.set_xattr(f, b"user.b", None).unwrap();
        assert_eq!(t.xattrs(f).unwrap(), vec![(b"user.a".to_vec(), b"333".to_vec())]);
        assert_eq!(t.set_xattr(f, b"user.b", None), Err(errno::ENODATA));
        drop(t);
        Arena::remove(id);
    }

    /// A directory's index made again (as after a holder died mid-change)
    /// finds the same names.
    #[test]
    fn a_repair_makes_the_indexes_again() {
        let (id, a) = fresh();
        let mut t = lock(&a, root_dir).unwrap();
        let root = t.root();
        for i in 0..50 {
            t.create(root, format!("x{i}").as_bytes(), &file(0o644)).unwrap();
        }
        t.unlink(root, b"x3", false).unwrap();
        t.repair();
        assert!(t.lookup(root, b"x49").is_ok());
        assert_eq!(t.lookup(root, b"x3"), Err(errno::ENOENT));
        assert!(!t.is_empty_dir(root).unwrap());
        drop(t);
        Arena::remove(id);
    }
}
