//! `memfd_create` and file seals.
//!
//! A memfd is an anonymous file. On macOS it is a file created in fwe's
//! private directory and unlinked at once, so it lives as long as a
//! descriptor of it does, as Linux's does. What makes it a memfd is an
//! extended attribute carrying its name, and its seals (`F_ADD_SEALS`) are
//! another, so every process that holds it, a fork child or one it was
//! passed to, sees the same ones. On a Linux host both calls pass through.
//!
//! Seals are kept as Linux keeps them:
//!
//! - `F_SEAL_SHRINK` and `F_SEAL_GROW` are checked by `ftruncate` and
//!   `fallocate` here, and `F_SEAL_GROW` by a write past the end (looked
//!   at only once some memfd of the process has it).
//! - `F_SEAL_WRITE` (and `F_SEAL_FUTURE_WRITE`) freezes the contents: the file
//!   is cloned, and every descriptor this process has of it is replaced by a
//!   read-only one of the clone, at the same offset and with the same flags
//!   and sharing. The host then refuses writes and writable shared mappings,
//!   and the kernel reports those as `EPERM` ([`write_refused`]). Its size
//!   still changes as the other seals allow, through a writable descriptor
//!   of the clone fwe keeps; a writable shared mapping of it makes the seal
//!   `EBUSY`.
//! - `F_SEAL_EXEC` is checked by `fchmod`.

use fwe_abi::{err, errno, fcntl, memfd as mfd};

/// The extended attribute holding a memfd's name; its presence is what
/// makes a file a memfd.
#[cfg(target_os = "macos")]
const NAME_ATTR: &std::ffi::CStr = c"org.fwe.memfd.name";
/// The extended attribute holding a memfd's seals, as a little-endian u32.
#[cfg(target_os = "macos")]
const SEALS_ATTR: &std::ffi::CStr = c"org.fwe.memfd.seals";

const ALL_SEALS: u32 = fcntl::F_SEAL_SEAL
    | fcntl::F_SEAL_SHRINK
    | fcntl::F_SEAL_GROW
    | fcntl::F_SEAL_WRITE
    | fcntl::F_SEAL_FUTURE_WRITE
    | fcntl::F_SEAL_EXEC;

/// Seals that freeze the contents.
const WRITE_SEALS: u32 = fcntl::F_SEAL_WRITE | fcntl::F_SEAL_FUTURE_WRITE;

fn last_errno() -> i32 {
    crate::host::errno_to_linux(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `memfd_create(name, flags)`: a new memfd, or a negated errno.
pub fn create(name: &[u8], flags: u64) -> i64 {
    let known = mfd::MFD_CLOEXEC
        | mfd::MFD_ALLOW_SEALING
        | mfd::MFD_HUGETLB
        | mfd::MFD_NOEXEC_SEAL
        | mfd::MFD_EXEC;
    if flags & !known != 0
        || name.len() > mfd::NAME_MAX
        || flags & (mfd::MFD_NOEXEC_SEAL | mfd::MFD_EXEC) == (mfd::MFD_NOEXEC_SEAL | mfd::MFD_EXEC)
    {
        return err(errno::EINVAL);
    }
    if flags & mfd::MFD_HUGETLB != 0 {
        // No huge pages: Linux fails it the same way without them.
        return err(errno::EINVAL);
    }
    let mut seals = if flags & mfd::MFD_ALLOW_SEALING != 0 { 0 } else { fcntl::F_SEAL_SEAL };
    let mode = if flags & mfd::MFD_NOEXEC_SEAL != 0 {
        // Not executable, and sealable so that it stays so.
        seals = (seals & !fcntl::F_SEAL_SEAL) | fcntl::F_SEAL_EXEC;
        0o666
    } else {
        0o777
    };
    match imp::create(name, flags & mfd::MFD_CLOEXEC != 0, mode, seals) {
        Ok(fd) => fd as i64,
        Err(e) => err(e),
    }
}

/// The name of the memfd `fd` is open on, if it is one.
pub fn name(fd: i32) -> Option<Vec<u8>> {
    imp::name(fd)
}

/// `F_GET_SEALS`.
pub fn get_seals(fd: i32) -> i64 {
    match imp::seals(fd) {
        Some(s) => s as i64,
        None => err(errno::EINVAL),
    }
}

/// `F_ADD_SEALS`.
pub fn add_seals(fd: i32, add: u64) -> i64 {
    if add & !(ALL_SEALS as u64) != 0 {
        return err(errno::EINVAL);
    }
    if ANY_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed)
        && READ_ONLY.lock().unwrap_or_else(|e| e.into_inner()).contains(&fd)
    {
        return err(errno::EPERM);
    }
    match imp::add_seals(fd, add as u32) {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// Whether resizing the file `fd` is open on from its current size to
/// `len` is refused by its seals (`EPERM`).
pub fn check_resize(fd: i32, len: i64) -> Result<(), i32> {
    if cfg!(target_os = "linux") {
        // The host enforces its own seals.
        return Ok(());
    }
    let Some(seals) = imp::seals(fd) else { return Ok(()) };
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(last_errno());
    }
    let size = st.st_size as i64;
    let refused = (len < size && seals & fcntl::F_SEAL_SHRINK != 0)
        || (len > size && seals & fcntl::F_SEAL_GROW != 0);
    if refused { Err(errno::EPERM) } else { Ok(()) }
}

/// Memfd descriptors opened read-only again (through `/proc/self/fd`),
/// which the host made sharing a writable description: no seals through
/// them, as Linux's need one open for writing. With whether any is.
pub(crate) static READ_ONLY: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());
static ANY_READ_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Memfd descriptor `fd` was opened again read-only.
pub fn reopened_read_only(fd: i32) {
    READ_ONLY.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
    ANY_READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Descriptor `fd` was closed.
pub fn closed(fd: i32) {
    if ANY_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
        READ_ONLY.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
    }
}

/// Whether a memfd of this process was sealed against growing (until then
/// a write looks no further).
static GROW_SEALED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a write of `len` bytes to `fd` at `offset` (its position, for
/// `None`) would grow a memfd sealed against it (`F_SEAL_GROW`: `EPERM`).
pub fn grow_refused(fd: i32, offset: Option<u64>, len: u64) -> bool {
    if cfg!(target_os = "linux") || !GROW_SEALED.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    if imp::seals(fd).is_none_or(|s| s & fcntl::F_SEAL_GROW == 0) {
        return false;
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    let at = offset.unwrap_or_else(|| {
        // SAFETY: plain host calls on an open descriptor.
        let append = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_APPEND != 0;
        // SAFETY: as above.
        let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if append || pos < 0 { st.st_size as u64 } else { pos as u64 }
    });
    at + len > st.st_size.max(0) as u64
}

/// fwe's own writable descriptor of the memfd `fd` is open on, if its
/// contents are frozen (`F_SEAL_WRITE`): what resizes it.
pub fn frozen_resizer(fd: i32) -> Option<i32> {
    if cfg!(target_os = "linux") || imp::seals(fd)? & WRITE_SEALS == 0 {
        return None;
    }
    imp::resizer(fd)
}

/// `ftruncate` of `fd` to `len`, if it is a memfd whose contents are
/// frozen (`F_SEAL_WRITE`): its descriptors are read-only, so the clone
/// is resized through one of fwe's own that may write, as Linux lets a
/// write-sealed memfd shrink and grow.
pub fn truncate_frozen(fd: i32, len: i64) -> Option<i64> {
    let w = frozen_resizer(fd)?;
    // SAFETY: plain host call on fwe's own descriptor of the clone.
    let r = unsafe { libc::ftruncate(w, len as libc::off_t) };
    Some(if r == 0 { 0 } else { crate::host::last_error() })
}

/// Whether `fchmod` of `fd` is refused by `F_SEAL_EXEC`.
pub fn chmod_sealed(fd: i32) -> bool {
    cfg!(target_os = "macos") && imp::seals(fd).is_some_and(|s| s & fcntl::F_SEAL_EXEC != 0)
}

/// Whether a write to `fd` that the host failed (`EBADF` for a write,
/// `EACCES` for a writable shared mapping) did so because `fd` is a memfd
/// sealed against writing, which Linux reports as `EPERM`.
pub fn write_refused(fd: i32) -> bool {
    cfg!(target_os = "macos") && imp::seals(fd).is_some_and(|s| s & WRITE_SEALS != 0)
}

/// The result of system call `nr` with arguments `a`, with a host refusal
/// to write to a sealed memfd ([`write_refused`]) reported as Linux reports
/// it.
pub fn linux_write_error(nr: u64, a: &[u64; 6], r: i64) -> i64 {
    use fwe_abi::{mman, nr as n};
    let fd = match nr {
        n::WRITE | n::WRITEV | n::PWRITE64 | n::PWRITEV | n::PWRITEV2 if r == err(errno::EBADF) => {
            a[0]
        }
        n::MMAP
            if r == err(errno::EACCES)
                && a[3] & mman::MAP_SHARED != 0
                && a[2] & mman::PROT_WRITE != 0 =>
        {
            a[4]
        }
        _ => return r,
    };
    if write_refused(fd as i32) { err(errno::EPERM) } else { r }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::last_errno;

    pub fn create(name: &[u8], cloexec: bool, _mode: u32, seals: u32) -> Result<i32, i32> {
        let name = std::ffi::CString::new(name).map_err(|_| fwe_abi::errno::EINVAL)?;
        let mut flags = libc::MFD_ALLOW_SEALING;
        if cloexec {
            flags |= libc::MFD_CLOEXEC;
        }
        // SAFETY: a NUL-terminated name.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), flags) };
        if fd < 0 {
            return Err(last_errno());
        }
        if seals != 0 {
            // SAFETY: plain host call on the fresh descriptor.
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals as libc::c_int) };
        }
        Ok(fd)
    }

    pub fn name(fd: i32) -> Option<Vec<u8>> {
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
        let t = target.into_os_string().into_encoded_bytes();
        let rest = t.strip_prefix(b"/memfd:")?;
        Some(rest.strip_suffix(b" (deleted)").unwrap_or(rest).to_vec())
    }

    pub fn seals(fd: i32) -> Option<u32> {
        // SAFETY: plain host call.
        let r = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        (r >= 0).then_some(r as u32)
    }

    pub fn add_seals(fd: i32, add: u32) -> Result<(), i32> {
        // SAFETY: plain host call.
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, add as libc::c_int) } < 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    /// The host keeps a sealed memfd's descriptors as they are.
    pub(super) fn resizer(_: i32) -> Option<i32> {
        None
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{NAME_ATTR, SEALS_ATTR, WRITE_SEALS, last_errno};
    use fwe_abi::{errno, fcntl};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh name for a file in fwe's directory.
    fn fresh_path(what: &str) -> Result<std::ffi::CString, i32> {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut path = crate::fs::shm::user_dir()?;
        // SAFETY: getpid cannot fail.
        let pid = unsafe { libc::getpid() };
        let n = N.fetch_add(1, Ordering::Relaxed);
        path.extend_from_slice(format!("/{what}-{pid}-{n}").as_bytes());
        std::ffi::CString::new(path).map_err(|_| errno::EINVAL)
    }

    fn set_attr(fd: i32, attr: &std::ffi::CStr, value: &[u8]) -> Result<(), i32> {
        // SAFETY: a valid attribute name and value buffer.
        let r =
            unsafe { libc::fsetxattr(fd, attr.as_ptr(), value.as_ptr().cast(), value.len(), 0, 0) };
        if r < 0 { Err(last_errno()) } else { Ok(()) }
    }

    fn get_attr(fd: i32, attr: &std::ffi::CStr) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 256];
        // SAFETY: `buf` is valid for its length.
        let n =
            unsafe { libc::fgetxattr(fd, attr.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), 0, 0) };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    pub fn create(name: &[u8], cloexec: bool, mode: u32, seals: u32) -> Result<i32, i32> {
        let path = fresh_path("memfd")?;
        let mut flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
        if cloexec {
            flags |= libc::O_CLOEXEC;
        }
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: as above; the file is fwe's own.
        unsafe { libc::unlink(path.as_ptr()) };
        let made = set_attr(fd, NAME_ATTR, name)
            .and_then(|()| set_attr(fd, SEALS_ATTR, &seals.to_le_bytes()))
            .map(|()| {
                // SAFETY: plain host call on the fresh descriptor.
                unsafe { libc::fchmod(fd, mode as libc::mode_t) };
            });
        if let Err(e) = made {
            // SAFETY: closing the descriptor just opened.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(fd)
    }

    pub fn name(fd: i32) -> Option<Vec<u8>> {
        get_attr(fd, NAME_ATTR)
    }

    pub fn seals(fd: i32) -> Option<u32> {
        let v = get_attr(fd, SEALS_ATTR)?;
        Some(u32::from_le_bytes(v.get(..4)?.try_into().ok()?))
    }

    pub fn add_seals(fd: i32, add: u32) -> Result<(), i32> {
        let current = seals(fd).ok_or(errno::EINVAL)?;
        // SAFETY: plain host call.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(last_errno());
        }
        // Linux needs a descriptor open for writing. One whose contents are
        // frozen was, before it became read-only here.
        if fl & libc::O_ACCMODE == libc::O_RDONLY && current & WRITE_SEALS == 0 {
            return Err(errno::EPERM);
        }
        if current & fcntl::F_SEAL_SEAL != 0 {
            return Err(errno::EPERM);
        }
        let new = current | add;
        if new == current {
            return Ok(());
        }
        if add & WRITE_SEALS != 0 && current & WRITE_SEALS == 0 {
            // Not while it is mapped shared and writable (`EBUSY`).
            if file_id(fd).is_some_and(|(_, ino)| crate::maps::record().shared_writable(ino)) {
                return Err(errno::EBUSY);
            }
            freeze(fd, new)?;
        }
        if new & fcntl::F_SEAL_GROW != 0 {
            super::GROW_SEALED.store(true, Ordering::Relaxed);
        }
        // Recorded on the file, after the freeze, so that both the original
        // (which other processes may hold) and the clone carry it.
        set_attr(fd, SEALS_ATTR, &new.to_le_bytes())
    }

    /// Identity of an open file.
    fn file_id(fd: i32) -> Option<(libc::dev_t, libc::ino_t)> {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-parameter.
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    }

    /// Replace every guest descriptor of the file `fd` is open on with a
    /// read-only descriptor of a clone of it, carrying seals `seals`.
    /// Descriptors that shared an open file description share one again,
    /// at the same offset and with the same status flags.
    fn freeze(fd: i32, seals: u32) -> Result<(), i32> {
        let id = file_id(fd).ok_or(errno::EBADF)?;
        let fds: Vec<i32> =
            crate::fdtable::open_fds().into_iter().filter(|&g| file_id(g) == Some(id)).collect();
        let clone = clone_read_only(fd, seals)?;
        keep_resizer(&clone);
        // Which descriptors share an open file description: give each its
        // own offset in turn, and see which offset each ends up with.
        let offsets: Vec<i64> = fds
            .iter()
            // SAFETY: `lseek` on descriptors of a regular file.
            .map(|&g| unsafe { libc::lseek(g, 0, libc::SEEK_CUR) })
            .collect();
        const MARK: i64 = 1 << 50;
        for (i, &g) in fds.iter().enumerate() {
            // SAFETY: as above.
            unsafe { libc::lseek(g, MARK + i as i64, libc::SEEK_SET) };
        }
        let class: Vec<i64> = fds
            .iter()
            // SAFETY: as above.
            .map(|&g| unsafe { libc::lseek(g, 0, libc::SEEK_CUR) } - MARK)
            .collect();
        // One new open file description per class, then the descriptors.
        let mut opened: Vec<(i64, i32)> = Vec::new();
        let mut result = Ok(());
        for (i, &g) in fds.iter().enumerate() {
            let c = class[i];
            let desc = match opened.iter().find(|(k, _)| *k == c) {
                Some(&(_, d)) => d,
                None => {
                    // A new description of the clone: reopened through its
                    // descriptor's path, which the clone keeps while linked.
                    let d = match clone.reopen() {
                        Ok(d) => d,
                        Err(e) => {
                            // What was opened goes; what was swapped stays.
                            for (_, d) in opened {
                                // SAFETY: closing a descriptor made here.
                                unsafe { libc::close(d) };
                            }
                            return Err(e);
                        }
                    };
                    // SAFETY: plain host calls on descriptors this process holds.
                    unsafe {
                        let fl =
                            libc::fcntl(g, libc::F_GETFL) & (libc::O_APPEND | libc::O_NONBLOCK);
                        libc::fcntl(d, libc::F_SETFL, fl);
                        libc::lseek(d, offsets[i], libc::SEEK_SET);
                    }
                    opened.push((c, d));
                    d
                }
            };
            // SAFETY: plain host calls; `g` is replaced in place, keeping
            // its close-on-exec flag.
            unsafe {
                let fdflags = libc::fcntl(g, libc::F_GETFD);
                if libc::dup2(desc, g) < 0 {
                    result = Err(last_errno());
                    libc::lseek(g, offsets[i], libc::SEEK_SET);
                    continue;
                }
                libc::fcntl(g, libc::F_SETFD, fdflags);
            }
        }
        for (_, d) in opened {
            // SAFETY: closing the descriptors made above.
            unsafe { libc::close(d) };
        }
        drop(clone);
        result
    }

    /// A read-only clone of a file, linked under a name of fwe's until
    /// dropped, so that it can be opened once per open file description.
    struct Clone {
        path: std::ffi::CString,
    }

    impl Clone {
        fn reopen(&self) -> Result<i32, i32> {
            // SAFETY: a NUL-terminated path of fwe's own file.
            let d = unsafe { libc::open(self.path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if d < 0 { Err(last_errno()) } else { Ok(d) }
        }
    }

    impl Drop for Clone {
        fn drop(&mut self) {
            // SAFETY: unlinking fwe's own file.
            unsafe { libc::unlink(self.path.as_ptr()) };
        }
    }

    /// A writable descriptor of each frozen clone, by its identity, in
    /// fwe's reserved range: its size may still change (shrink and grow
    /// seals allowing), though its contents may not.
    static RESIZERS: std::sync::Mutex<Vec<((libc::dev_t, u64), i32)>> =
        std::sync::Mutex::new(Vec::new());

    fn keep_resizer(clone: &Clone) {
        // SAFETY: a NUL-terminated path of fwe's own file.
        let w = unsafe { libc::open(clone.path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        let Ok(w) = crate::fdtable::reserve(w) else { return };
        match file_id(w) {
            Some(id) => RESIZERS.lock().unwrap_or_else(|e| e.into_inner()).push((id, w)),
            // SAFETY: closing the descriptor just opened.
            None => unsafe {
                libc::close(w);
            },
        }
    }

    /// The writable descriptor of the frozen clone `fd` is open on.
    pub(super) fn resizer(fd: i32) -> Option<i32> {
        let id = file_id(fd)?;
        RESIZERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, w)| *w)
    }

    fn clone_read_only(fd: i32, seals: u32) -> Result<Clone, i32> {
        let path = fresh_path("memfd-sealed")?;
        // SAFETY: a valid descriptor and a NUL-terminated path.
        if unsafe { libc::fclonefileat(fd, libc::AT_FDCWD, path.as_ptr(), 0) } != 0 {
            copy_file(fd, &path)?;
        }
        let clone = Clone { path };
        let d = clone.reopen()?;
        // The clone keeps the name; record the seals on it as well.
        let set = set_attr(d, SEALS_ATTR, &seals.to_le_bytes()).and_then(|()| {
            match get_attr(d, NAME_ATTR) {
                Some(_) => Ok(()),
                None => set_attr(d, NAME_ATTR, &get_attr(fd, NAME_ATTR).unwrap_or_default()),
            }
        });
        // SAFETY: closing the descriptor just opened.
        unsafe { libc::close(d) };
        set.map(|()| clone)
    }

    /// Copy the file `fd` is open on to a new file at `path`, where the
    /// filesystem cannot clone it.
    fn copy_file(fd: i32, path: &std::ffi::CStr) -> Result<(), i32> {
        // SAFETY: a NUL-terminated path of fwe's own.
        let out = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if out < 0 {
            return Err(last_errno());
        }
        let mut buf = vec![0u8; 1 << 16];
        let mut at: libc::off_t = 0;
        let result = loop {
            // SAFETY: `buf` is valid for its length.
            let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), at) };
            if n < 0 {
                break Err(last_errno());
            }
            if n == 0 {
                break Ok(());
            }
            // SAFETY: the first `n` bytes of `buf` are initialized.
            if unsafe { libc::pwrite(out, buf.as_ptr().cast(), n as usize, at) } != n {
                break Err(last_errno());
            }
            at += n as libc::off_t;
        };
        // SAFETY: plain host calls on the copy.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) == 0 {
                libc::fchmod(out, st.st_mode & 0o7777);
            }
            libc::close(out);
        }
        result
    }
}

// On a Linux host the calls are the host's own.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn write(fd: i32, data: &[u8]) -> isize {
        // SAFETY: a valid buffer.
        unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) }
    }

    /// A memfd has its name and no seals until sealing is allowed; seals
    /// hold against resizing and writing, through every descriptor.
    #[test]
    fn seals_hold() {
        let fd = create(b"test", mfd::MFD_CLOEXEC) as i32;
        assert!(fd >= 0);
        assert_eq!(name(fd).as_deref(), Some(&b"test"[..]));
        assert_eq!(get_seals(fd), fcntl::F_SEAL_SEAL as i64);
        assert_eq!(add_seals(fd, fcntl::F_SEAL_WRITE as u64), err(errno::EPERM));

        let fd = create(b"sealed", mfd::MFD_ALLOW_SEALING) as i32;
        assert_eq!(get_seals(fd), 0);
        assert_eq!(write(fd, b"hello"), 5);
        // SAFETY: plain host call.
        let dup = unsafe { libc::dup(fd) };
        assert_eq!(add_seals(fd, (fcntl::F_SEAL_SHRINK | fcntl::F_SEAL_GROW) as u64), 0);
        assert_eq!(check_resize(fd, 2), Err(errno::EPERM));
        assert_eq!(check_resize(fd, 9), Err(errno::EPERM));
        assert_eq!(check_resize(fd, 5), Ok(()));
        assert_eq!(add_seals(fd, fcntl::F_SEAL_WRITE as u64), 0);
        // Both descriptors are read-only now, still sharing their offset.
        assert!(write(dup, b"x") < 0);
        assert!(write_refused(dup));
        // SAFETY: plain host calls.
        unsafe {
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 5);
            libc::lseek(fd, 1, libc::SEEK_SET);
            assert_eq!(libc::lseek(dup, 0, libc::SEEK_CUR), 1);
        }
        let mut buf = [0u8; 4];
        // SAFETY: a valid buffer.
        assert_eq!(unsafe { libc::read(dup, buf.as_mut_ptr().cast(), 4) }, 4);
        assert_eq!(&buf, b"ello");
        assert_eq!(add_seals(fd, fcntl::F_SEAL_SEAL as u64), 0);
        assert_eq!(add_seals(fd, fcntl::F_SEAL_EXEC as u64), err(errno::EPERM));
        let all =
            fcntl::F_SEAL_SEAL | fcntl::F_SEAL_SHRINK | fcntl::F_SEAL_GROW | fcntl::F_SEAL_WRITE;
        assert_eq!(get_seals(dup), all as i64);
        assert_eq!(name(dup).as_deref(), Some(&b"sealed"[..]));
        // SAFETY: closing the test's descriptors.
        unsafe {
            libc::close(fd);
            libc::close(dup);
        }
        assert_eq!(create(b"x", mfd::MFD_HUGETLB), err(errno::EINVAL));
        assert_eq!(create(&[b'n'; 250], 0), err(errno::EINVAL));
    }
}
