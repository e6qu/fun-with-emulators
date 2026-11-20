//! What fwe learns of a program file's code, kept on disk by the file's
//! identity and reused, as Rosetta 2 keeps its translations: the file's
//! executable and known-code ranges (its ELF headers and unwind table,
//! parsed), and for each range of code prepared, what the preparation found
//! in it (see the backend's `prepare`). A program or library is then
//! looked through once, not at every start: the next start reads the
//! record, checks the words it names, and changes only the pages that hold
//! them.
//!
//! A mapping of a file's code also keeps its pages as preparation left
//! them, an image, which a later mapping of the same range maps in their
//! place ([`store_image`]): its pages then come from the host's file
//! cache, shared by every process, and none is written or copied.
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
        FileId::of_stat(&st)
    }

    /// The identity of the regular file whose metadata is `st`.
    fn of_stat(st: &libc::stat) -> Option<FileId> {
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

    /// The file's size.
    pub fn size(&self) -> u64 {
        self.0[2]
    }

    /// The file's device and inode.
    pub fn dev_ino(&self) -> (u64, u64) {
        (self.0[0], self.0[1])
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
    let data = crate::fs::read_all_path(&path).ok()?;
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

/// The key of the prepared image of the mapping of `len` bytes at file
/// offset `offset` of file `id` ([`store_image`]).
pub fn image_key(id: FileId, offset: u64, len: u64) -> Vec<u8> {
    let mut e = Enc::new();
    e.bytes(b"image");
    id.encode(&mut e);
    e.u64(offset);
    e.u64(len);
    e.into_bytes()
}

/// Keep `image`, a mapping's pages as preparation left them, and `layout`
/// (where its stubs go, see the backend) under `key`: the image in a file
/// of its own beside the entry, which a later mapping maps in place of the
/// program's file, its pages shared through the host's cache. The image
/// is written first, so an entry found has its image whole.
pub fn store_image(key: &[u8], layout: &[u8], image: &[u8]) {
    let Some(path) = image_path(key) else { return };
    let tmp = [&path[..], format!(".{}", crate::host::pid()).as_bytes()].concat();
    let (tmp, path) = (std::ffi::OsStr::from_bytes(&tmp), std::ffi::OsStr::from_bytes(&path));
    if std::fs::write(tmp, image).is_err() || std::fs::rename(tmp, path).is_err() {
        let _ = std::fs::remove_file(tmp);
        return;
    }
    store(key, layout);
}

/// The layout and image kept under `key`, the image open for mapping, if
/// both are there and the image is `len` bytes.
pub fn open_image(key: &[u8], len: u64) -> Option<(Vec<u8>, std::fs::File)> {
    let layout = load(key)?;
    let path = image_path(key)?;
    let f = std::fs::File::open(std::ffi::OsStr::from_bytes(&path)).ok()?;
    (f.metadata().ok()?.len() == len).then_some((layout, f))
}

fn image_path(key: &[u8]) -> Option<Vec<u8>> {
    let mut p = path_of(key)?;
    p.extend_from_slice(b".img");
    Some(p)
}

/// The directory of the entries.
pub fn dir() -> Option<Vec<u8>> {
    beside("prepared")
}

/// A directory of fwe's private one for what is kept like these entries,
/// named `name` (the translations of the backend's code cache).
pub fn beside(name: &str) -> Option<Vec<u8>> {
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-{name}", crate::shared::FORMAT).as_bytes());
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

/// Remove the entries made more than `age` ago (their files may be gone
/// or changed; one still in use is made again), and at once each image
/// whose file is gone or changed: an image is as large as the code it
/// holds, and a fresh copy of a library (a test's root, a container's
/// layer) is a file of its own.
pub fn collect(age: std::time::Duration) {
    let Some(d) = dir() else { return };
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&d)) else { return };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "img") {
            // With its entry.
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|a| a > age);
        let image = std::fs::read(&path).ok().and_then(|data| image_source(&data));
        if old || image.is_some_and(|id| !id.exists()) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("img"));
        }
    }
    // Images whose entry is gone.
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&d)) else { return };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "img") && !path.with_extension("").exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The file an image entry (as [`store`] wrote it) was made from, if the
/// entry is an image's.
fn image_source(entry: &[u8]) -> Option<FileId> {
    let mut d = Dec::new(entry);
    let key = d.bytes();
    let mut k = Dec::new(&key);
    if k.bytes() != b"image" {
        return None;
    }
    Some(FileId([k.u64(), k.u64(), k.u64(), k.u64(), k.u64()]))
}

impl FileId {
    /// Whether the file is still there, unchanged: found by its device and
    /// inode (`/.vol` on macOS), with the same size and modification time.
    fn exists(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            let [dev, ino, ..] = self.0;
            let Ok(c) = std::ffi::CString::new(format!("/.vol/{}/{ino}", dev as i32)) else {
                return true;
            };
            match FileId::of_path(&c) {
                Some(now) => now == *self,
                None => false,
            }
        }
        #[cfg(not(target_os = "macos"))]
        true
    }

    /// The identity of the regular file at `path` (not opened: fwe opens
    /// no guest file for its own ends).
    #[cfg(target_os = "macos")]
    fn of_path(path: &std::ffi::CStr) -> Option<FileId> {
        // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a valid out-parameter.
        if unsafe { libc::stat(path.as_ptr(), &mut st) } != 0 {
            return None;
        }
        FileId::of_stat(&st)
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// An image is found while its file is there unchanged, and the
    /// collector removes it, image and entry, once the file is gone.
    #[test]
    fn an_image_goes_with_its_file() {
        let src = std::env::temp_dir().join(format!("fwe-image-src-{}", std::process::id()));
        std::fs::write(&src, [7u8; 4096]).unwrap();
        let f = std::fs::File::open(&src).unwrap();
        let id = FileId::of_fd(std::os::fd::AsRawFd::as_raw_fd(&f)).unwrap();
        let key = image_key(id, 0, 4096);
        store_image(&key, b"layout", &[1u8; 4096]);
        assert_eq!(open_image(&key, 4096).map(|(l, _)| l), Some(b"layout".to_vec()));
        let day = std::time::Duration::from_secs(86400);
        collect(day);
        assert!(open_image(&key, 4096).is_some());
        drop(f);
        std::fs::remove_file(&src).unwrap();
        collect(day);
        assert!(open_image(&key, 4096).is_none());
        assert!(
            !std::path::Path::new(std::ffi::OsStr::from_bytes(&image_path(&key).unwrap())).exists()
        );
    }
}
