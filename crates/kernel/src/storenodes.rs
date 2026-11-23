//! The host's nodes behind FIFOs and sockets in fwe's file store.
//!
//! A FIFO and a socket are the host's to run: their data passes between
//! processes through the host's kernel. Their names in a tmpfs are the
//! store's, and each has a node of the host's in fwe's private directory
//! (`nodes/<filesystem>-<inode>`): a FIFO's, made with it; a socket's,
//! made by the `bind` that makes its name. Opening the FIFO opens its node;
//! connecting to the socket connects to its node. A node goes with its
//! file, and with its filesystem.

use crate::filestore::desc::File;
use crate::filestore::tree::{self, Ino, S_IFIFO, S_IFMT, S_IFSOCK};
use crate::fs::StoreDir;
use fwe_abi::errno;
use std::ffi::CString;

/// The attribute of a socket's file holding the address it was bound by,
/// as `getsockname` and `getpeername` give it (fwe's own: a NUL first).
const BOUND: &[u8] = b"\0bound";

/// The directory holding the nodes, made on first use.
pub fn dir() -> Result<Vec<u8>, i32> {
    static DIR: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(d) = DIR.get() {
        return Ok(d.clone());
    }
    let d = crate::mounts::join(&crate::fs::shm::user_dir()?, b"nodes");
    let c = CString::new(d.clone()).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::mkdir(c.as_ptr(), 0o700) };
    Ok(DIR.get_or_init(|| d).clone())
}

/// The file of the store whose FIFO's node `fd` is open on, if it is one
/// (its host status `st`): what its status is.
pub fn fifo_file(fd: i32, st: &libc::stat) -> Option<File> {
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return None;
    }
    static DEV: std::sync::OnceLock<Option<libc::dev_t>> = std::sync::OnceLock::new();
    let dev = DEV.get_or_init(|| {
        let c = CString::new(dir().ok()?).ok()?;
        // SAFETY: an all-zero `stat` is a valid out-parameter; a
        // NUL-terminated path.
        let mut d: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        (unsafe { libc::stat(c.as_ptr(), &mut d) } == 0).then_some(d.st_dev)
    });
    if *dev != Some(st.st_dev) {
        return None;
    }
    file_of(&crate::fs::fd_path(fd)?)
}

/// The name of the node of `ino` of filesystem `fs` in [`dir`].
pub fn name(fs: u64, ino: Ino) -> Vec<u8> {
    format!("{fs:x}-{ino:x}").into_bytes()
}

/// The host path of the node of `ino` of filesystem `fs`.
pub fn path(fs: u64, ino: Ino) -> Result<Vec<u8>, i32> {
    Ok(crate::mounts::join(&dir()?, &name(fs, ino)))
}

/// The file of the store whose node is at host path `host`, if it is one:
/// a path in [`dir`], or a node's bare name (as a socket bound from that
/// directory, its path too long for an address, reports it) with a node of
/// that name there.
pub fn file_of(host: &[u8]) -> Option<File> {
    let d = dir().ok()?;
    let rest = match host.strip_prefix(d.as_slice()) {
        Some(r) => r.strip_prefix(b"/")?,
        None if !host.contains(&b'/') => {
            let c = CString::new(crate::mounts::join(&d, host)).ok()?;
            // SAFETY: an all-zero `stat` is a valid out-parameter; a
            // NUL-terminated path.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
                return None;
            }
            host
        }
        None => return None,
    };
    let s = std::str::from_utf8(rest).ok()?;
    let (fs, ino) = s.split_once('-')?;
    Some(File { fs: u64::from_str_radix(fs, 16).ok()?, ino: u64::from_str_radix(ino, 16).ok()? })
}

/// For `bind` at `name` in `d` (the guest's address `guest`): the socket's
/// file made there, owned by the caller, and the host path of its node to
/// bind. A name there is an address in use (`EADDRINUSE`); the caller
/// needs to write and search the directory (`EACCES`).
pub fn bind_at(
    d: &StoreDir,
    name: &[u8],
    guest: &[u8],
    over: Option<&'static [u8]>,
) -> Result<Vec<u8>, i32> {
    let a = crate::creds::access();
    let mut t = d.fs.lock()?;
    if over.is_none() && t.lookup(d.ino, name).is_ok() {
        return Err(errno::EADDRINUSE);
    }
    let dir = crate::filestore::io::host_stat(t.dev(), &t.stat(d.ino)?);
    if !a.permits(&dir, 2 | 1) {
        return Err(errno::EACCES);
    }
    // A set-group-ID directory's group, as for any file made there.
    #[allow(clippy::unnecessary_cast)] // `mode_t` differs by host
    let gid = if dir.st_mode as u32 & 0o2000 != 0 { dir.st_gid } else { a.fsgid };
    let new = tree::New { mode: S_IFSOCK, uid: a.fsuid, gid, rdev: 0 };
    let ino =
        crate::storeops::make_over(&mut t, d.ino, name, over, |t| t.create(d.ino, name, &new))?;
    t.set_xattr(ino, BOUND, Some(guest))?;
    let host = path(d.fs.id, ino)?;
    let c = CString::new(host.clone()).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::unlink(c.as_ptr()) };
    Ok(host)
}

/// For `connect` (or a send) to `name` in `d`: the host path of its
/// socket's node. Nothing there is `ENOENT`; a file that is no bound
/// socket refuses (`ECONNREFUSED`).
pub fn connect_to(d: &StoreDir, name: &[u8]) -> Result<Vec<u8>, i32> {
    let (ino, st) = d.find(name)?;
    let host = path(d.fs.id, ino)?;
    let c = CString::new(host.clone()).map_err(|_| errno::EINVAL)?;
    // SAFETY: an all-zero `stat` is a valid out-parameter; a NUL-terminated
    // path.
    let mut node: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let there = unsafe { libc::lstat(c.as_ptr(), &mut node) } == 0;
    if st.mode & S_IFMT != S_IFSOCK || !there {
        return Err(errno::ECONNREFUSED);
    }
    Ok(host)
}

/// The socket bound to node `host` took its address: its file takes the
/// socket's mode `mode` (`bound`), or, the bind having failed, goes.
pub fn bound(host: &[u8], mode: Option<u32>) {
    let Some(file) = file_of(host) else { return };
    let Ok(fs) = file.fs() else { return };
    let Ok(mut t) = fs.lock() else { return };
    match mode {
        Some(m) => {
            let _ = t.set_mode(file.ino, m & 0o7777);
        }
        None => {
            let Some(p) = t.any_path(file.ino) else { return };
            let mut names: Vec<&[u8]> = p.split(|&b| b == b'/').filter(|n| !n.is_empty()).collect();
            let Some(name) = names.pop() else { return };
            let mut dir = t.root();
            for n in names {
                match t.lookup(dir, n) {
                    Ok(i) => dir = i,
                    Err(_) => return,
                }
            }
            let _ = t.unlink(dir, name, false);
        }
    }
}

/// The guest address a socket's node at `host` was bound by, if it is a
/// node of the store's.
pub fn guest_of(host: &[u8]) -> Option<Vec<u8>> {
    let file = file_of(host)?;
    file.fs().ok()?.lock().ok()?.xattr(file.ino, BOUND).ok()
}

/// The status of the socket's file whose node is at `host`, if it is a
/// node of the store's.
pub fn stat_of(host: &[u8]) -> Option<libc::stat> {
    let file = file_of(host)?;
    let fs = file.fs().ok()?;
    let t = fs.lock().ok()?;
    Some(crate::filestore::io::host_stat(t.dev(), &t.stat(file.ino).ok()?))
}

/// The node of new file `ino` (of type `kind`) in `d`'s filesystem: a
/// FIFO's is made now (a socket's by its `bind`).
pub fn make(d: &StoreDir, ino: Ino, kind: u32) -> Result<(), i32> {
    if kind != S_IFIFO {
        return Ok(());
    }
    let c = CString::new(path(d.fs.id, ino)?).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    unsafe { libc::unlink(c.as_ptr()) };
    // SAFETY: as above.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    Ok(())
}

/// File `ino` of filesystem `fs` has gone: its node with it.
pub fn gone(fs: u64, ino: Ino) {
    if let Ok(p) = path(fs, ino)
        && let Ok(c) = CString::new(p)
    {
        // SAFETY: a NUL-terminated path in fwe's private directory.
        unsafe { libc::unlink(c.as_ptr()) };
    }
}
