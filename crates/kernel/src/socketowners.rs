//! Owners of Unix socket nodes, which macOS keeps no extended attribute on
//! ([`crate::owners`] keeps every other file's in one).
//!
//! A socket node with an owner kept is flagged as any such file is
//! ([`crate::modes::marked`]), and its owner is a file of eight bytes in
//! fwe's directory for the user, named by the node's host identity: its
//! device, inode and birth time, which a node made later never has. One
//! whose node is gone is removed with the other leftovers
//! ([`crate::shared::collect`]), as `/.vol` finds the node by its device
//! and inode no more.

use std::ffi::CStr;

/// The owner, in the initial user namespace's ids, kept for the socket
/// node whose host metadata is `st`.
pub fn read(st: &libc::stat) -> Option<(u32, u32)> {
    let mut buf = [0u8; 8];
    let n = std::fs::File::open(entry(st)?)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut buf))
        .ok()?;
    (n == 8).then(|| {
        (
            u32::from_le_bytes(buf[..4].try_into().unwrap()),
            u32::from_le_bytes(buf[4..].try_into().unwrap()),
        )
    })
}

/// Keep `owner` for the socket node whose host metadata is `st`, or forget
/// a kept one (`None`).
pub fn write(st: &libc::stat, owner: Option<(u32, u32)>) -> Result<(), i32> {
    let path = entry(st).ok_or(fwe_abi::errno::EACCES)?;
    let Some((uid, gid)) = owner else {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    };
    let mut v = [0u8; 8];
    v[..4].copy_from_slice(&uid.to_le_bytes());
    v[4..].copy_from_slice(&gid.to_le_bytes());
    // Whole or not at all: written beside it, then put in its place. (Its
    // name is no entry's: [`collect`] leaves it while its writer runs.)
    let tmp = std::path::PathBuf::from(format!("{}.{}.tmp", path.display(), crate::host::pid()));
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &v))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| e.raw_os_error().map_or(fwe_abi::errno::EIO, crate::host::errno_to_linux))
}

/// Remove the owners of socket nodes that are gone, and what a writer
/// that ended left half written.
pub fn collect() {
    let Some(dir) = dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(rest) = name.strip_suffix(".tmp") {
            let writer = rest.rsplit('.').next().and_then(|p| p.parse::<i32>().ok());
            if writer.is_none_or(|p| !alive(p)) {
                let _ = std::fs::remove_file(e.path());
            }
            continue;
        }
        let mut f = name.split(['-', '.']);
        let (Some(dev), Some(ino)) = (f.next(), f.next()) else { continue };
        let node = format!("/.vol/{}/{}", i64::from_str_radix(dev, 16).unwrap_or(-1), ino_dec(ino));
        let Ok(c) = std::ffi::CString::new(node) else { continue };
        let st = lstat(&c);
        if st.is_none_or(|st| entry_name(&st) != name) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Whether host process `pid` exists (none at or below 0 is one).
fn alive(pid: i32) -> bool {
    crate::ids::HostPid::new(pid).is_some_and(|p| crate::host::probe(p).exists())
}

fn ino_dec(hex: &str) -> u64 {
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

fn lstat(path: &CStr) -> Option<libc::stat> {
    // SAFETY: zeroed bytes are a valid `stat`; `lstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a valid out-parameter.
    (unsafe { libc::lstat(path.as_ptr(), &mut st) } == 0).then_some(st)
}

/// The directory of the entries, made on first use.
fn dir() -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let base = crate::fs::shm::user_dir().ok()?;
    let d = std::path::Path::new(std::ffi::OsStr::from_bytes(&base)).join("socket-owners");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&d)
        .or_else(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .ok()?;
    Some(d)
}

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// The name of the entry for the node of host metadata `st`.
fn entry_name(st: &libc::stat) -> String {
    format!(
        "{:x}-{:x}-{:x}.{:x}",
        st.st_dev as u32, st.st_ino, st.st_birthtime as u64, st.st_birthtime_nsec as u64
    )
}

fn entry(st: &libc::stat) -> Option<std::path::PathBuf> {
    Some(dir()?.join(entry_name(st)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_socket_nodes_owner_is_kept_by_its_identity_until_it_is_gone() {
        let dir = std::env::temp_dir().join(format!("fwe-so-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let node = dir.join("s");
        let listener = std::os::unix::net::UnixListener::bind(&node).unwrap();
        let c = std::ffi::CString::new(node.to_str().unwrap()).unwrap();
        let st = super::lstat(&c).unwrap();
        super::write(&st, Some((1000, 100))).unwrap();
        assert_eq!(super::read(&st), Some((1000, 100)));
        // Gone: its entry goes with the leftovers.
        drop(listener);
        std::fs::remove_file(&node).unwrap();
        super::collect();
        assert_eq!(super::read(&st), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
