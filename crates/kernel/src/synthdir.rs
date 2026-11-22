//! Open synthetic `/proc` and `/sys` directories.
//!
//! The synthetic `/proc` and `/sys` trees have no backing directory on the
//! host, so an opened directory fd is tracked here and `getdents64`, `lseek`,
//! `fstat` and `close` on it are served from an in-memory entry list rather
//! than the host. A real `/dev/null` descriptor is opened to reserve a unique
//! fd number (so the guest sees an ordinary descriptor and `close` works),
//! whose position the host keeps (`lseek`): the next entry to list, shared
//! by every duplicate and fork child of it, as a directory's is.

use crate::host::last_error;
use fwe_abi::{err, errno};
use std::collections::HashMap;

#[derive(Clone)]
struct Dir {
    /// Its guest path, for paths relative to it.
    path: Vec<u8>,
    /// `(name, d_type)` entries, including `.` and `..`.
    entries: Vec<(Vec<u8>, u8)>,
}

static REG: crate::kept::Kept<Option<HashMap<i32, Dir>>> = crate::kept::Kept::new(None);

/// Whether a synthetic directory was ever opened: until one is, a call
/// asking about a descriptor takes no lock.
static ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn with<R>(f: impl FnOnce(&mut HashMap<i32, Dir>) -> R) -> R {
    let mut g = REG.lock();
    f(g.get_or_insert_with(HashMap::new))
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
        crate::snapshot::fd_map(e, m, |e, dir| {
            e.bytes(&dir.path);
            e.u64(dir.entries.len() as u64);
            for (name, t) in &dir.entries {
                e.bytes(name);
                e.u8(*t);
            }
        })
    })
}

/// Rebuild the registry in a fork child.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let reg = crate::snapshot::read_fd_map(d, |d| {
        let path = d.bytes();
        let n = d.count(9);
        let entries = (0..n).map(|_| (d.bytes(), d.u8())).collect();
        Dir { path, entries }
    });
    with(|m| *m = reg);
}

/// Open the synthetic directory at guest path `path` with the given
/// entries, returning a guest fd.
pub fn open(path: Vec<u8>, entries: Vec<(Vec<u8>, u8)>) -> i64 {
    // Reserve a real, unique descriptor number backed by /dev/null.
    // SAFETY: a constant NUL-terminated path and plain open flags.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return last_error();
    }
    ANY.store(true, std::sync::atomic::Ordering::SeqCst);
    with(|m| m.insert(fd, Dir { path, entries }));
    fd as i64
}

/// Append an entry to open synthetic directory `fd`.
pub fn add(fd: i32, name: Vec<u8>, dtype: u8) {
    with(|m| {
        if let Some(dir) = m.get_mut(&fd) {
            dir.entries.push((name, dtype));
        }
    });
}

/// `new` is a duplicate of `old` now.
pub fn duplicated(old: i32, new: i32) {
    if !ANY.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    with(|m| match m.get(&old).cloned() {
        Some(dir) => {
            m.insert(new, dir);
        }
        None => {
            m.remove(&new);
        }
    });
}

/// The guest path of synthetic directory `fd`.
pub fn path_of(fd: i32) -> Option<Vec<u8>> {
    if !is_synth(fd) {
        return None;
    }
    with(|m| m.get(&fd).map(|d| d.path.clone()))
}

/// Whether `fd` is a synthetic directory (a record whose descriptor is no
/// longer its stand-in, closed behind fwe's back, is dropped).
pub fn is_synth(fd: i32) -> bool {
    if !ANY.load(std::sync::atomic::Ordering::SeqCst) || !with(|m| m.contains_key(&fd)) {
        return false;
    }
    if !crate::procfile::null_stand_in(fd) {
        with(|m| m.remove(&fd));
        return false;
    }
    true
}

/// Serve `getdents64` for a synthetic directory. `Some` if `fd` is one of ours.
///
/// # Safety
/// `buf` must point to `count` writable bytes.
pub unsafe fn getdents64(fd: i32, buf: u64, count: u64) -> Option<i64> {
    const HEADER: usize = fwe_abi::DIRENT64_HEADER; // 19
    if !is_synth(fd) {
        return None;
    }
    with(|m| {
        let dir = m.get(&fd)?;
        // SAFETY: plain host call on the guest's descriptor.
        let at = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if at < 0 {
            return Some(last_error());
        }
        let mut out = Vec::new();
        let mut offset = at as usize;
        while offset < dir.entries.len() {
            let (name, dtype) = &dir.entries[offset];
            // d_ino(8) d_off(8) d_reclen(2) d_type(1) name + NUL, padded to 8.
            let reclen = (HEADER + name.len() + 1 + 7) & !7;
            if out.len() + reclen > count as usize {
                break;
            }
            let start = out.len();
            out.resize(start + reclen, 0);
            let rec = &mut out[start..];
            rec[0..8].copy_from_slice(&1u64.to_ne_bytes()); // d_ino (arbitrary nonzero)
            rec[8..16].copy_from_slice(&((offset + 1) as i64).to_ne_bytes()); // d_off
            rec[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
            rec[18] = *dtype;
            // The name, then zeros for its terminator and the padding.
            rec[HEADER..HEADER + name.len()].copy_from_slice(name);
            offset += 1;
        }
        if out.is_empty() && offset < dir.entries.len() {
            // The next entry does not fit in the caller's buffer.
            return Some(err(errno::EINVAL));
        }
        if let Err(e) = crate::uaccess::write_from(buf, &out) {
            return Some(err(e));
        }
        // SAFETY: plain host call on the guest's descriptor.
        unsafe { libc::lseek(fd, offset as libc::off_t, libc::SEEK_SET) };
        Some(out.len() as i64)
    })
}

/// Serve `lseek` for a synthetic directory (only rewind to 0 is meaningful).
/// `Some` if `fd` is one of ours.
pub fn lseek(fd: i32, offset: i64, whence: i32) -> Option<i64> {
    if !is_synth(fd) {
        return None;
    }
    Some(match (whence, offset) {
        (libc::SEEK_SET | libc::SEEK_CUR, 0) => {
            // SAFETY: plain host call on the guest's descriptor.
            crate::host::ret(unsafe { libc::lseek(fd, 0, whence) } as i64)
        }
        _ => err(errno::EINVAL),
    })
}

/// Whether `fd` is a synthetic directory, for `fstat` to report `S_IFDIR`.
pub fn fstat_is_dir(fd: i32) -> bool {
    is_synth(fd)
}

/// Release a synthetic directory on `close`. `Some(0)` if it was ours.
pub fn try_close(fd: i32) -> Option<i64> {
    REG.if_used()?.as_mut()?.remove(&fd)?;
    // SAFETY: `fd` is the /dev/null descriptor we reserved.
    unsafe { libc::close(fd) };
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::{DT_DIR, DT_REG};

    #[test]
    fn lists_entries_and_rewinds() {
        let entries =
            vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR), (b"cpuinfo".to_vec(), DT_REG)];
        let fd = open(b"/proc".to_vec(), entries) as i32;
        assert!(fd >= 0);
        assert!(is_synth(fd));

        let mut buf = [0u8; 256];
        // SAFETY: 256 writable bytes.
        let n = unsafe { getdents64(fd, buf.as_mut_ptr() as u64, 256) }.unwrap();
        assert!(n > 0);
        // Parse the three records and check the names.
        let names = parse_names(&buf[..n as usize]);
        assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"cpuinfo".to_vec()]);

        // At EOF the next call returns 0.
        // SAFETY: 256 writable bytes.
        assert_eq!(unsafe { getdents64(fd, buf.as_mut_ptr() as u64, 256) }.unwrap(), 0);

        // Rewind re-reads from the start.
        assert_eq!(lseek(fd, 0, libc::SEEK_SET), Some(0));
        // SAFETY: 256 writable bytes.
        let n2 = unsafe { getdents64(fd, buf.as_mut_ptr() as u64, 256) }.unwrap();
        assert_eq!(n2, n);

        assert_eq!(try_close(fd), Some(0));
        assert!(!is_synth(fd));
    }

    #[test]
    fn tiny_buffer_is_einval() {
        let fd = open(b"/proc".to_vec(), vec![(b"cpuinfo".to_vec(), DT_REG)]) as i32;
        let mut buf = [0u8; 8];
        // SAFETY: buffer too small for one record.
        assert_eq!(unsafe { getdents64(fd, buf.as_mut_ptr() as u64, 8) }, Some(err(errno::EINVAL)));
        try_close(fd);
    }

    fn parse_names(buf: &[u8]) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let mut off = 0;
        while off + 19 <= buf.len() {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > buf.len() {
                break;
            }
            let name_bytes = &buf[off + 19..off + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            names.push(name_bytes[..end].to_vec());
            off += reclen;
        }
        names
    }
}
