//! What fwe learns of a program file's code, kept on disk by the file's
//! identity and reused, as Rosetta 2 keeps its translations: the file's
//! executable and known-code ranges (its ELF headers and unwind table,
//! parsed), and for each range of code prepared, what the preparation found
//! in it (see the backend's `prepare`). A program or library is then
//! looked through once, not at every start: the next start reads the
//! record, checks the words it names, and changes only the pages that hold
//! them.
//!
//! An entry is a file in fwe's private directory named by a hash of its
//! key, and holds the key itself, so a hash shared by two keys finds
//! nothing. A file changed in place keeps its identity only if its size
//! and modification time stay too; the preparation's own check of every
//! word it changes catches the rest.

use crate::snapshot::{Dec, Enc};
use std::os::unix::ffi::OsStrExt;

/// What names a file's contents: device, inode, size and modification
/// time, as `fstat` reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId([u64; 5]);

impl FileId {
    /// The identity of the regular file open as `fd`.
    pub fn of_fd(fd: i32) -> Option<FileId> {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
            return None;
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        #[allow(clippy::unnecessary_cast)] // field types differ by host
        Some(FileId([
            st.st_dev as u64,
            st.st_ino as u64,
            st.st_size as u64,
            st.st_mtime as u64,
            st.st_mtime_nsec as u64,
        ]))
    }

    fn encode(&self, e: &mut Enc) {
        for v in self.0 {
            e.u64(v);
        }
    }
}

/// The key of the preparation of code at file offset `offset`, `len`
/// bytes, of file `id`, with known-code ranges `known` (offsets from the
/// range's start).
pub fn code_key(id: FileId, offset: u64, len: u64, known: Option<&[(u64, u64)]>) -> Vec<u8> {
    let mut e = Enc::new();
    e.bytes(b"code");
    id.encode(&mut e);
    e.u64(offset);
    e.u64(len);
    match known {
        None => e.bool(false),
        Some(k) => {
            e.bool(true);
            e.u64(k.len() as u64);
            for &(o, l) in k {
                e.u64(o);
                e.u64(l);
            }
        }
    }
    e.into_bytes()
}

/// The entry kept under `key`, if there is one.
pub fn load(key: &[u8]) -> Option<Vec<u8>> {
    let path = path_of(key)?;
    let data = std::fs::read(std::ffi::OsStr::from_bytes(&path)).ok()?;
    let mut d = Dec::new(&data);
    let (k, v) = (d.bytes(), d.bytes());
    (d.finish().is_ok() && k == key).then_some(v)
}

/// Keep `value` under `key`. A failure leaves no entry: the work is done
/// again next time.
pub fn store(key: &[u8], value: &[u8]) {
    let Some(path) = path_of(key) else { return };
    let mut e = Enc::new();
    e.bytes(key);
    e.bytes(value);
    // Written aside and moved into place: a reader finds a whole entry or
    // none.
    let tmp = [&path[..], format!(".{}", crate::host::pid()).as_bytes()].concat();
    let (tmp, path) = (std::ffi::OsStr::from_bytes(&tmp), std::ffi::OsStr::from_bytes(&path));
    if std::fs::write(tmp, e.into_bytes()).is_err() || std::fs::rename(tmp, path).is_err() {
        let _ = std::fs::remove_file(tmp);
    }
}

/// The directory of the entries.
pub fn dir() -> Option<Vec<u8>> {
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-prepared", crate::shared::FORMAT).as_bytes());
    Some(d)
}

fn path_of(key: &[u8]) -> Option<Vec<u8>> {
    let d = dir()?;
    // SAFETY: a NUL-terminated path in fwe's private directory; an
    // existing directory is fine.
    unsafe {
        let c = std::ffi::CString::new(d.clone()).ok()?;
        libc::mkdir(c.as_ptr(), 0o700);
    }
    // Two FNV-1a hashes with different starts: 128 bits.
    let fnv =
        |seed: u64| key.iter().fold(seed, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100000001b3));
    let name = format!("/{:016x}{:016x}", fnv(0xcbf29ce484222325), fnv(0x84222325cbf29ce4));
    Some([&d[..], name.as_bytes()].concat())
}

/// Remove the entries made more than `age` ago: their files may be gone
/// or changed (one still in use is made again).
pub fn collect(age: std::time::Duration) {
    let Some(d) = dir() else { return };
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&d)) else { return };
    for e in entries.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|a| a > age);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The ranges of a file's executable sections and of its known code, as
/// the kernel's loader looks them up ([`crate::mm`]), kept by the file's
/// identity.
pub type ExecRanges = (Vec<(u64, u64)>, Option<Vec<(u64, u64)>>);

/// [`ExecRanges`] of file `id`, if kept; `found(None)` is kept as "not an
/// ELF file" too.
pub fn exec_ranges(id: FileId) -> Option<Option<ExecRanges>> {
    let mut key = Enc::new();
    key.bytes(b"ranges");
    id.encode(&mut key);
    let v = load(&key.into_bytes())?;
    let mut d = Dec::new(&v);
    let ranges = |d: &mut Dec| -> Vec<(u64, u64)> {
        let n = d.count(16);
        (0..n).map(|_| (d.u64(), d.u64())).collect()
    };
    let out = if d.bool() {
        let sections = ranges(&mut d);
        let known = d.bool().then(|| ranges(&mut d));
        Some((sections, known))
    } else {
        None
    };
    d.finish().ok()?;
    Some(out)
}

/// Keep `ranges` as file `id`'s [`ExecRanges`].
pub fn keep_exec_ranges(id: FileId, ranges: Option<&ExecRanges>) {
    let mut key = Enc::new();
    key.bytes(b"ranges");
    id.encode(&mut key);
    let mut e = Enc::new();
    let put = |e: &mut Enc, r: &[(u64, u64)]| {
        e.u64(r.len() as u64);
        for &(o, l) in r {
            e.u64(o);
            e.u64(l);
        }
    };
    match ranges {
        None => e.bool(false),
        Some((sections, known)) => {
            e.bool(true);
            put(&mut e, sections);
            e.bool(known.is_some());
            if let Some(k) = known {
                put(&mut e, k);
            }
        }
    }
    store(&key.into_bytes(), &e.into_bytes());
}

/// The key of what is kept of file `id` under `tag` (the loader's figures,
/// see the backend).
pub fn about(id: FileId, tag: &[u8]) -> Vec<u8> {
    let mut e = Enc::new();
    e.bytes(tag);
    id.encode(&mut e);
    e.into_bytes()
}

/// Encode ranges `r` (or none) for [`store`].
pub fn encode_ranges(r: Option<&[(u64, u64)]>) -> Vec<u8> {
    let mut e = Enc::new();
    e.bool(r.is_some());
    if let Some(r) = r {
        e.u64(r.len() as u64);
        for &(a, l) in r {
            e.u64(a);
            e.u64(l);
        }
    }
    e.into_bytes()
}

/// The ranges [`encode_ranges`] encoded.
pub fn decode_ranges(v: &[u8]) -> Option<Option<Vec<(u64, u64)>>> {
    let mut d = Dec::new(v);
    let out = if d.bool() {
        let n = d.count(16);
        Some((0..n).map(|_| (d.u64(), d.u64())).collect())
    } else {
        None
    };
    d.finish().ok()?;
    Some(out)
}
