//! eBPF maps (`BPF_MAP_CREATE` and the element commands): arrays and hash
//! tables, which programs and their loaders share.
//!
//! A map is an unlinked file of fwe's that its descriptor is open on, so a
//! fork child, or a program loaded with it, reaches the same elements. Its
//! shape (type, key and value sizes, entries, flags, identity) is an
//! attribute of the file. An array holds `max_entries` values, all there
//! from the start, zero-filled; a hash table holds as many slots, each a
//! used byte, the key and the value. A program's lookup returns a place in
//! the file ([`Map::find`]), which it then reads and writes.

use fwe_abi::errno;

pub const BPF_MAP_CREATE: u64 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u64 = 1;
pub const BPF_MAP_UPDATE_ELEM: u64 = 2;
pub const BPF_MAP_DELETE_ELEM: u64 = 3;
pub const BPF_MAP_GET_NEXT_KEY: u64 = 4;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;

/// The largest key and value Linux takes (`KMALLOC_MAX_SIZE` for values is
/// larger; a map past this is refused, as one too big to allocate).
const MAX_KEY: u32 = 512;
const MAX_BYTES: u64 = 64 << 20;

#[cfg(target_os = "macos")]
const MAP_ATTR: &std::ffi::CStr = c"org.fwe.bpf.map";

/// A map's shape, and the descriptor its elements are read through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Map {
    pub fd: i32,
    pub ty: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub id: u32,
}

impl Map {
    fn slot_size(&self) -> u64 {
        match self.ty {
            BPF_MAP_TYPE_ARRAY => u64::from(self.value_size),
            _ => 1 + u64::from(self.key_size) + u64::from(self.value_size),
        }
    }

    fn read(&self, at: u64, len: usize) -> Result<Vec<u8>, i32> {
        let mut b = vec![0u8; len];
        // SAFETY: a valid buffer of `len` bytes.
        let n = unsafe { libc::pread(self.fd, b.as_mut_ptr().cast(), len, at as libc::off_t) };
        if n < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        // Past the end of what was written: zeros.
        Ok(b)
    }

    fn write(&self, at: u64, data: &[u8]) -> Result<(), i32> {
        // SAFETY: a valid buffer of its length.
        let n =
            unsafe { libc::pwrite(self.fd, data.as_ptr().cast(), data.len(), at as libc::off_t) };
        if n != data.len() as isize {
            return Err(errno::ENOMEM);
        }
        Ok(())
    }

    /// Where the value for `key` is in the file, if the map holds one.
    pub fn find(&self, key: &[u8]) -> Result<Option<u64>, i32> {
        if self.ty == BPF_MAP_TYPE_ARRAY {
            let i = u32::from_le_bytes(key[..4].try_into().map_err(|_| errno::EINVAL)?);
            return Ok((i < self.max_entries).then(|| u64::from(i) * self.slot_size()));
        }
        for i in 0..u64::from(self.max_entries) {
            let at = i * self.slot_size();
            let head = self.read(at, 1 + self.key_size as usize)?;
            if head[0] == 1 && head[1..] == *key {
                return Ok(Some(at + 1 + u64::from(self.key_size)));
            }
        }
        Ok(None)
    }

    /// The value for `key`.
    pub fn lookup(&self, key: &[u8]) -> Result<Vec<u8>, i32> {
        let at = self.find(key)?.ok_or(errno::ENOENT)?;
        self.read(at, self.value_size as usize)
    }

    /// Set the value for `key`, as `flags` allow.
    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), i32> {
        if flags > BPF_EXIST {
            return Err(errno::EINVAL);
        }
        if self.ty == BPF_MAP_TYPE_ARRAY {
            let i = u32::from_le_bytes(key[..4].try_into().map_err(|_| errno::EINVAL)?);
            if i >= self.max_entries {
                return Err(errno::E2BIG);
            }
            // Every element of an array is there.
            if flags == BPF_NOEXIST {
                return Err(errno::EEXIST);
            }
            return self.write(u64::from(i) * self.slot_size(), value);
        }
        if let Some(at) = self.find(key)? {
            if flags == BPF_NOEXIST {
                return Err(errno::EEXIST);
            }
            return self.write(at, value);
        }
        if flags == BPF_EXIST {
            return Err(errno::ENOENT);
        }
        for i in 0..u64::from(self.max_entries) {
            let at = i * self.slot_size();
            if self.read(at, 1)?[0] != 1 {
                let mut slot = Vec::with_capacity(self.slot_size() as usize);
                slot.push(1);
                slot.extend_from_slice(key);
                slot.extend_from_slice(value);
                return self.write(at, &slot);
            }
        }
        Err(errno::E2BIG)
    }

    /// Remove `key`'s element (an array's are always there: `EINVAL`).
    pub fn delete(&self, key: &[u8]) -> Result<(), i32> {
        if self.ty == BPF_MAP_TYPE_ARRAY {
            return Err(errno::EINVAL);
        }
        let at = self.find(key)?.ok_or(errno::ENOENT)?;
        self.write(at - 1 - u64::from(self.key_size), &[0])
    }

    /// The key after `key` (the first, for none).
    pub fn next_key(&self, key: Option<&[u8]>) -> Result<Vec<u8>, i32> {
        if self.ty == BPF_MAP_TYPE_ARRAY {
            let next = match key {
                Some(k) => {
                    let i = u32::from_le_bytes(k[..4].try_into().map_err(|_| errno::EINVAL)?);
                    if i >= self.max_entries { 0 } else { i + 1 }
                }
                None => 0,
            };
            if next >= self.max_entries {
                return Err(errno::ENOENT);
            }
            return Ok(next.to_le_bytes().to_vec());
        }
        let keys: Vec<Vec<u8>> = (0..u64::from(self.max_entries))
            .filter_map(|i| {
                let head = self.read(i * self.slot_size(), 1 + self.key_size as usize).ok()?;
                (head[0] == 1).then(|| head[1..].to_vec())
            })
            .collect();
        let start = match key.and_then(|k| keys.iter().position(|x| x == k)) {
            Some(i) => i + 1,
            // None, or a key not there: the first.
            None => 0,
        };
        keys.get(start).cloned().ok_or(errno::ENOENT)
    }
}

/// The map `fd` is a descriptor of.
#[cfg(target_os = "macos")]
pub fn of(fd: i32) -> Option<Map> {
    let mut b = [0u8; 20];
    // SAFETY: a valid buffer of its length.
    let n = unsafe { libc::fgetxattr(fd, MAP_ATTR.as_ptr(), b.as_mut_ptr().cast(), 20, 0, 0) };
    if n != 20 {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    Some(Map { fd, ty: w(0), key_size: w(4), value_size: w(8), max_entries: w(12), id: w(16) })
}

#[cfg(not(target_os = "macos"))]
pub fn of(_fd: i32) -> Option<Map> {
    None
}

/// `BPF_MAP_CREATE` with `attr`: a descriptor of a new map.
pub fn create(attr: &[u8]) -> Result<i64, i32> {
    let w = |i: usize| attr.get(i..i + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let (ty, key_size, value_size, max_entries) = (w(0), w(4), w(8), w(12));
    if !matches!(ty, BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_ARRAY) {
        return Err(errno::EINVAL);
    }
    if key_size == 0 || key_size > MAX_KEY || value_size == 0 || max_entries == 0 {
        return Err(errno::EINVAL);
    }
    if ty == BPF_MAP_TYPE_ARRAY && key_size != 4 {
        return Err(errno::EINVAL);
    }
    let shape =
        Map { fd: -1, ty, key_size, value_size, max_entries, id: crate::bpf::fresh_map_id() };
    if shape.slot_size().saturating_mul(u64::from(max_entries)) > MAX_BYTES {
        return Err(errno::ENOMEM);
    }
    make(shape).map(i64::from)
}

#[cfg(target_os = "macos")]
fn make(m: Map) -> Result<i32, i32> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let last = || crate::host::errno_to_linux(crate::host::last_errno());
    let mut path = crate::fs::shm::user_dir()?;
    let pid = crate::host::pid();
    path.extend_from_slice(
        format!("/bpf-map-{pid}-{}", N.fetch_add(1, Ordering::Relaxed)).as_bytes(),
    );
    let p = std::ffi::CString::new(path).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    let fd = unsafe {
        libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC, 0o600)
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: fwe's own file, its name no longer needed.
    unsafe { libc::unlink(p.as_ptr()) };
    let mut b = Vec::with_capacity(20);
    for v in [m.ty, m.key_size, m.value_size, m.max_entries, m.id] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    let size = m.slot_size() * u64::from(m.max_entries);
    // SAFETY: valid buffers; the file is fwe's own.
    let ok = unsafe {
        libc::fsetxattr(fd, MAP_ATTR.as_ptr(), b.as_ptr().cast(), b.len(), 0, 0) == 0
            && libc::ftruncate(fd, size as libc::off_t) == 0
    };
    if !ok {
        let e = last();
        // SAFETY: closing the descriptor just made.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

#[cfg(not(target_os = "macos"))]
fn make(_m: Map) -> Result<i32, i32> {
    Err(errno::ENOSYS)
}

/// The element commands, with `attr` as the guest gave it.
pub fn command(cmd: u64, attr: &[u8]) -> Result<i64, i32> {
    let w = |i: usize| attr.get(i..i + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let d = |i: usize| attr.get(i..i + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
    let m = of(w(0) as i32).ok_or(errno::EBADF)?;
    let (key_ptr, value_ptr, flags) = (d(8), d(16), d(24));
    let key = |p: u64| crate::uaccess::read_bytes(p, m.key_size as usize);
    match cmd {
        BPF_MAP_LOOKUP_ELEM => {
            let v = m.lookup(&key(key_ptr)?)?;
            crate::uaccess::write_from(value_ptr, &v)?;
        }
        BPF_MAP_UPDATE_ELEM => {
            let v = crate::uaccess::read_bytes(value_ptr, m.value_size as usize)?;
            m.update(&key(key_ptr)?, &v, flags)?;
        }
        BPF_MAP_DELETE_ELEM => m.delete(&key(key_ptr)?)?,
        BPF_MAP_GET_NEXT_KEY => {
            let k = if key_ptr == 0 { None } else { Some(key(key_ptr)?) };
            let next = m.next_key(k.as_deref())?;
            crate::uaccess::write_from(value_ptr, &next)?;
        }
        _ => return Err(errno::EINVAL),
    }
    Ok(0)
}
