//! `O_TMPFILE`: a file with no name in a directory, which `linkat` with
//! `AT_EMPTY_PATH` may give one. The host has no such file, so fwe makes
//! it under a hidden name in the directory (one `getdents` leaves out),
//! and removes the name when the descriptor is closed; one made with
//! `O_EXCL`, which can never be given a name, loses it at once.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The prefix of the hidden names.
pub const PREFIX: &[u8] = b".fwe-tmpfile-";

/// Each descriptor's hidden file: its host path.
pub(crate) static NAMES: Mutex<Vec<(i32, std::ffi::CString)>> = Mutex::new(Vec::new());
/// Whether any is held (until then a close looks no further).
static ANY: AtomicBool = AtomicBool::new(false);

/// A hidden name for a new file.
pub fn fresh_name() -> Vec<u8> {
    static N: AtomicU64 = AtomicU64::new(0);
    let pid = crate::host::pid();
    let mut name = PREFIX.to_vec();
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
    NAMES.lock().unwrap_or_else(|e| e.into_inner()).push((fd, path));
    ANY.store(true, Ordering::Relaxed);
}

/// Descriptor `fd` was closed: its hidden name goes.
pub fn closed(fd: i32) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = names.iter().position(|(f, _)| *f == fd) {
        let (_, path) = names.swap_remove(i);
        // SAFETY: a NUL-terminated host path of a file fwe made.
        unsafe { libc::unlink(path.as_ptr()) };
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
            b if b.starts_with(PREFIX) => names.push(n),
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
            // SAFETY: a NUL-terminated name in the directory open as `dir`.
            unsafe { libc::unlinkat(dir, n.as_ptr(), 0) };
        }
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(dir) };
    cleared
}
