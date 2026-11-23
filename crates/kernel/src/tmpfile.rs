//! `O_TMPFILE`: a file with no name in a directory, which `linkat` with
//! `AT_EMPTY_PATH` may give one. The host has no such file, so fwe makes
//! it under a hidden name in the directory (one `getdents` leaves out, and
//! a link count does not count), and removes the name when the last of
//! the process's descriptors of it is closed, or the process ends; one
//! made with `O_EXCL`, which can never be given a name, loses it at once.
//! The name is its maker's: a fork child's descriptors leave it.
//!
//! A file being made is hidden the same way, under a name of its own
//! ([`making_name`]), until it is whole and renamed onto its name
//! ([`crate::fsops`]'s `make_whole`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The prefix of the hidden names.
pub const PREFIX: &[u8] = b".fwe-tmpfile-";
/// The prefix of the hidden names of files being made.
pub const MAKING: &[u8] = b".fwe-making-";

/// Whether `name` is a hidden one, which a listing leaves out.
pub fn hidden_name(name: &[u8]) -> bool {
    name.starts_with(PREFIX) || name.starts_with(MAKING)
}

/// A hidden file: the descriptor it is held by, its host path and its
/// host identity (device, inode).
type Hidden = (i32, std::ffi::CString, (u64, u64));

/// Each hidden file ([`Hidden`]).
pub(crate) static NAMES: Mutex<Vec<Hidden>> = Mutex::new(Vec::new());
/// Whether any is held (until then a close looks no further).
static ANY: AtomicBool = AtomicBool::new(false);

fn names() -> std::sync::MutexGuard<'static, Vec<Hidden>> {
    NAMES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether the file of host identity `id` has a hidden name, which its
/// link count leaves out.
pub fn hidden(id: (u64, u64)) -> bool {
    ANY.load(Ordering::Relaxed) && names().iter().any(|(_, _, i)| *i == id)
}

/// The process ends: its hidden names go.
pub fn exiting() {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    for (_, path, _) in names().drain(..) {
        // SAFETY: a NUL-terminated host path of a file fwe made.
        unsafe { libc::unlink(path.as_ptr()) };
    }
}

/// In a fork child: the hidden names are the parent's to remove.
pub fn forked_child() {
    names().clear();
    ANY.store(false, Ordering::Relaxed);
}

/// A hidden name for a new file.
pub fn fresh_name() -> Vec<u8> {
    unique(PREFIX)
}

/// A hidden name for a file being made.
pub fn making_name() -> Vec<u8> {
    unique(MAKING)
}

fn unique(prefix: &[u8]) -> Vec<u8> {
    static N: AtomicU64 = AtomicU64::new(0);
    let pid = crate::host::pid();
    let mut name = prefix.to_vec();
    name.extend_from_slice(format!("{pid}-{}", N.fetch_add(1, Ordering::Relaxed)).as_bytes());
    name
}

/// The file open as `fd` was made under a hidden name: removed at once
/// (`now`), or when `fd` is closed.
pub fn made(fd: i32, now: bool) {
    let Some(path) = crate::fs::fd_path(fd).and_then(|p| std::ffi::CString::new(p).ok()) else {
        return;
    };
    if now {
        // SAFETY: a NUL-terminated host path of the file fwe just made.
        unsafe { libc::unlink(path.as_ptr()) };
        return;
    }
    let Some(id) = crate::fsops::host_identity(fd) else { return };
    names().push((fd, path, id));
    ANY.store(true, Ordering::Relaxed);
}

/// Descriptor `fd` is about to be closed: its hidden name goes, unless
/// another descriptor of the process has the file open (a duplicate),
/// which holds it from then on.
pub fn closed(fd: i32) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut names = names();
    let Some(i) = names.iter().position(|(f, _, _)| *f == fd) else { return };
    let id = names[i].2;
    let other = crate::fdtable::open_fds()
        .into_iter()
        .find(|&o| o != fd && crate::fsops::host_identity(o) == Some(id));
    match other {
        Some(o) => names[i].0 = o,
        None => {
            let (_, path, _) = names.swap_remove(i);
            // SAFETY: a NUL-terminated host path of a file fwe made.
            unsafe { libc::unlink(path.as_ptr()) };
        }
    }
}

/// Directory `name` in directory `parent` holds hidden names only (and
/// some): remove them. Whether it did.
pub fn clear_hidden(parent: i32, name: &std::ffi::CStr) -> bool {
    // SAFETY: a valid directory descriptor and a NUL-terminated name.
    let dir = unsafe {
        libc::openat(parent, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if dir < 0 {
        return false;
    }
    // SAFETY: a fresh duplicate for the listing, which closes it.
    let list = unsafe { libc::fdopendir(libc::dup(dir)) };
    let mut names = Vec::new();
    let mut only_hidden = !list.is_null();
    while !list.is_null() {
        // SAFETY: an open directory stream.
        let e = unsafe { libc::readdir(list) };
        if e.is_null() {
            break;
        }
        // SAFETY: a NUL-terminated name in the entry just read.
        let n = unsafe { std::ffi::CStr::from_ptr((*e).d_name.as_ptr()) }.to_owned();
        match n.as_bytes() {
            b"." | b".." => {}
            b if hidden_name(b) => names.push(n),
            _ => only_hidden = false,
        }
    }
    if !list.is_null() {
        // SAFETY: the stream opened above.
        unsafe { libc::closedir(list) };
    }
    let cleared = only_hidden && !names.is_empty();
    if cleared {
        for n in &names {
            // SAFETY: a NUL-terminated name in the directory open as `dir`;
            // one being made may be a directory.
            if unsafe { libc::unlinkat(dir, n.as_ptr(), 0) } != 0 {
                // SAFETY: as above.
                unsafe { libc::unlinkat(dir, n.as_ptr(), libc::AT_REMOVEDIR) };
            }
        }
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(dir) };
    cleared
}
