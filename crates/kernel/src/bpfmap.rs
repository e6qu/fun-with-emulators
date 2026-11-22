//! eBPF maps (`BPF_MAP_CREATE` and the element commands): arrays and hash
//! tables, which programs and their loaders share.
//!
//! A map is an object of fwe's in host shared memory
//! ([`crate::memobj`]) that its descriptor is open on, so a fork child, a
//! process it is passed to, or a program loaded with it, reaches the same
//! elements. Its shape (type, key and value sizes, entries, identity) is
//! in the object's first bytes, its elements after. An array holds
//! `max_entries` values, all there from the start, zero-filled; a hash
//! table holds as many slots, each a used byte, the key and the value. A
//! program's lookup returns a place in the elements ([`Map::find`]), which
//! it then reads and writes.

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

/// Where the elements start, past the shape.
const ELEMENTS: usize = 64;

/// A map's shape, and its memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    pub mem: std::sync::Arc<crate::memobj::Mapping>,
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

    pub(crate) fn read(&self, at: u64, len: usize) -> Result<Vec<u8>, i32> {
        self.mem.read(ELEMENTS + at as usize, len).ok_or(errno::EFAULT)
    }

    pub(crate) fn write(&self, at: u64, data: &[u8]) -> Result<(), i32> {
        self.mem.write(ELEMENTS + at as usize, data).ok_or(errno::EFAULT)
    }

    /// Where the value for `key` is among the elements, if the map holds
    /// one.
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
pub fn of(fd: i32) -> Option<Map> {
    let (kind, _, size) = crate::memobj::identify(fd)?;
    if kind != crate::memobj::MAP {
        return None;
    }
    let mem = crate::memobj::Mapping::of(fd, size).ok()?;
    let shape = mem.read(0, 20)?;
    let w = |i: usize| u32::from_le_bytes(shape[i..i + 4].try_into().unwrap());
    let m = Map {
        mem: std::sync::Arc::new(mem),
        ty: w(0),
        key_size: w(4),
        value_size: w(8),
        max_entries: w(12),
        id: w(16),
    };
    (ELEMENTS as u64 + m.slot_size() * u64::from(m.max_entries) <= size as u64).then_some(m)
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
    let slot = match ty {
        BPF_MAP_TYPE_ARRAY => u64::from(value_size),
        _ => 1 + u64::from(key_size) + u64::from(value_size),
    };
    let bytes = slot.saturating_mul(u64::from(max_entries));
    if bytes > MAX_BYTES {
        return Err(errno::ENOMEM);
    }
    let shape = [ty, key_size, value_size, max_entries, crate::bpf::fresh_map_id()];
    make(&shape, ELEMENTS + bytes as usize).map(i64::from)
}

/// A new map of `shape` (type, key and value sizes, entries, identity),
/// `len` bytes in all: its descriptor.
#[cfg(target_os = "macos")]
fn make(shape: &[u32; 5], len: usize) -> Result<i32, i32> {
    let (fd, mem) = crate::memobj::make(crate::memobj::MAP, u64::from(shape[4]), len)?;
    let b: Vec<u8> = shape.iter().flat_map(|v| v.to_le_bytes()).collect();
    mem.write(0, &b).ok_or(errno::EFAULT)?;
    Ok(fd)
}

#[cfg(not(target_os = "macos"))]
fn make(_shape: &[u32; 5], _len: usize) -> Result<i32, i32> {
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
