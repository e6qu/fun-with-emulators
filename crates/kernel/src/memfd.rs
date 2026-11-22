//! `memfd_create` and file seals.
//!
//! A memfd is a file of fwe's own file store ([`crate::filestore`]): a file
//! with no name in the store's filesystem of memfds, its data in memory
//! every process holding it maps, living while some process has a
//! descriptor of it or a mapping of its data. Its name (what
//! `/proc/self/fd` shows) and its seals (`F_ADD_SEALS`) are the file's
//! own, so every process that holds it, a fork child or one it was passed
//! to, sees the same ones; the store's calls hold them
//! ([`crate::filestore::io`]). On a Linux host both calls pass through.

use crate::creds::Creds;
use fwe_abi::{err, errno, fcntl, memfd as mfd};

/// `memfd_create(name, flags)` for a process of `creds`: a new memfd, or a
/// negated errno.
pub fn create(name: &[u8], flags: u64, creds: &Creds) -> i64 {
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
    match imp::create(name, flags & mfd::MFD_CLOEXEC != 0, mode, seals, creds) {
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
    imp::get_seals(fd)
}

/// `F_ADD_SEALS`.
pub fn add_seals(fd: i32, add: u64) -> i64 {
    imp::add_seals(fd, add)
}

#[cfg(target_os = "linux")]
mod imp {
    use crate::creds::Creds;
    use fwe_abi::{err, errno};

    fn last_errno() -> i32 {
        crate::host::errno_to_linux(crate::host::last_errno())
    }

    pub fn create(
        name: &[u8],
        cloexec: bool,
        _mode: u32,
        seals: u32,
        _creds: &Creds,
    ) -> Result<i32, i32> {
        let name = std::ffi::CString::new(name).map_err(|_| errno::EINVAL)?;
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

    pub fn get_seals(fd: i32) -> i64 {
        // SAFETY: plain host call.
        let r = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        if r < 0 { err(last_errno()) } else { r as i64 }
    }

    pub fn add_seals(fd: i32, add: u64) -> i64 {
        // SAFETY: plain host call.
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, add as libc::c_int) } < 0 {
            return err(last_errno());
        }
        0
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::creds::Creds;
    use crate::filestore::desc::{self, File};
    use crate::filestore::{fs as sfs, io, tree};
    use fwe_abi::{err, errno, fcntl};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The attribute holding a memfd's name: one no guest can name (its
    /// first byte is NUL), so none sees or changes it.
    pub const NAME: &[u8] = b"\0memfd.name";

    /// The count of files in the filesystem of memfds when this process
    /// last swept it: it sweeps again once there are twice as many.
    static SWEPT_AT: AtomicU64 = AtomicU64::new(0);

    pub fn create(
        name: &[u8],
        cloexec: bool,
        mode: u32,
        seals: u32,
        creds: &Creds,
    ) -> Result<i32, i32> {
        let fs = sfs::memfds()?;
        // Not counted as open for writing, as Linux's `alloc_file_pseudo`
        // counts no writer: a program runs from it (`fexecve`) while it is
        // held to write (a reopen of it to write is counted).
        let id = desc::new_id(fcntl::O_RDONLY);
        let ino = {
            let mut t = fs.lock()?;
            let files = t.usage().1;
            if files >= 64 && files >= 2 * SWEPT_AT.load(Ordering::Relaxed) {
                drop(t);
                desc::sweep(&fs);
                t = fs.lock()?;
                SWEPT_AT.store(t.usage().1, Ordering::Relaxed);
            }
            let new = tree::New {
                mode: tree::S_IFREG | mode,
                uid: creds.fsuid,
                gid: creds.fsgid,
                rdev: 0,
            };
            let ino = t.create_unnamed(&new)?;
            // Held from the start, so no sweep takes it before its
            // descriptor counts.
            let made = t
                .hold(ino, crate::sysvipc::me(), &[(id, 1)])
                .and_then(|_| t.set_seals(ino, seals))
                .and_then(|()| t.set_xattr(ino, NAME, Some(name)));
            if let Err(e) = made {
                let _ = t.hold(ino, crate::sysvipc::me(), &[]);
                return Err(e);
            }
            ino
        };
        let flags = fcntl::O_RDWR | if cloexec { fcntl::O_CLOEXEC } else { 0 };
        let file = File { fs: fs.id, ino };
        desc::open(file, flags, id).inspect_err(|_| {
            if let Ok(mut t) = fs.lock()
                && let Ok(gone) = t.hold(ino, crate::sysvipc::me(), &[])
                && let Some(o) = gone.data
            {
                crate::filestore::data::remove(o);
            }
        })
    }

    pub fn name(fd: i32) -> Option<Vec<u8>> {
        let file = desc::of(fd)?;
        file.fs().ok()?.lock().ok()?.xattr(file.ino, NAME).ok()
    }

    pub fn get_seals(fd: i32) -> i64 {
        io::get_seals(fd).unwrap_or(err(errno::EINVAL))
    }

    pub fn add_seals(fd: i32, add: u64) -> i64 {
        io::add_seals(fd, add).unwrap_or(err(errno::EINVAL))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn write(fd: i32, data: &[u8]) -> i64 {
        crate::filestore::io::io(
            fwe_abi::nr::WRITE,
            &[fd as u64, data.as_ptr() as u64, data.len() as u64, 0, 0, 0],
        )
        .expect("a memfd")
    }

    /// A memfd has its name and no seals until sealing is allowed; seals
    /// hold against resizing and writing, through every descriptor.
    #[test]
    fn seals_hold() {
        let creds = Creds::default();
        let fd = create(b"test", mfd::MFD_CLOEXEC, &creds) as i32;
        assert!(fd >= 0);
        assert_eq!(name(fd).as_deref(), Some(&b"test"[..]));
        assert_eq!(get_seals(fd), fcntl::F_SEAL_SEAL as i64);
        assert_eq!(add_seals(fd, fcntl::F_SEAL_WRITE as u64), err(errno::EPERM));

        let fd = create(b"sealed", mfd::MFD_ALLOW_SEALING, &creds) as i32;
        assert_eq!(get_seals(fd), 0);
        assert_eq!(write(fd, b"hello"), 5);
        let ftruncate = |len: i64| crate::filestore::io::ftruncate(fd, len).expect("a memfd");
        assert_eq!(add_seals(fd, (fcntl::F_SEAL_SHRINK | fcntl::F_SEAL_GROW) as u64), 0);
        assert_eq!(ftruncate(2), err(errno::EPERM));
        assert_eq!(ftruncate(9), err(errno::EPERM));
        assert_eq!(ftruncate(5), 0);
        // Within the file a write goes; past it, refused.
        assert_eq!(write(fd, b"!"), err(errno::EPERM));
        assert_eq!(add_seals(fd, fcntl::F_SEAL_WRITE as u64), 0);
        assert_eq!(write(fd, b"x"), err(errno::EPERM));
        assert_eq!(add_seals(fd, fcntl::F_SEAL_SEAL as u64), 0);
        assert_eq!(add_seals(fd, fcntl::F_SEAL_EXEC as u64), err(errno::EPERM));
        let all =
            fcntl::F_SEAL_SEAL | fcntl::F_SEAL_SHRINK | fcntl::F_SEAL_GROW | fcntl::F_SEAL_WRITE;
        assert_eq!(get_seals(fd), all as i64);
        assert_eq!(create(b"x", mfd::MFD_HUGETLB, &creds), err(errno::EINVAL));
        assert_eq!(create(&[b'n'; 250], 0, &creds), err(errno::EINVAL));
    }
}
