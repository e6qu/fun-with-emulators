//! fwe's own objects behind a guest's descriptor that Linux keeps in
//! kernel memory (an eBPF map or program): host shared memory objects,
//! unlinked once made, so each lives as long as a descriptor or mapping of
//! it does, in memory, as Linux's does.
//!
//! The host gives such a descriptor no identity of its own (no device,
//! inode, path or attribute: `fstat` reports a mode of no file type and
//! inode 0), but keeps the name the object was made with for its life,
//! and tells it for a descriptor (`proc_pidfdinfo`). That name says what
//! the object is: `/fwe<euid><kind><id>`, the id in hex. What else it
//! holds is in its memory, which [`Mapping`] maps.

/// Kinds of object, the letter in its name.
pub const MAP: u8 = b'm';
pub const PROG: u8 = b'p';

/// Whether host `st` might be one of these objects (a host shared memory
/// object's: no file type, inode 0), before asking its name ([`identify`]).
pub fn may_be(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == 0 && st.st_ino == 0
}

/// A shared mapping of an object, unmapped when dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct Mapping {
    at: usize,
    len: usize,
}

impl Mapping {
    /// Map `len` bytes of object `fd`, shared, for reading and writing.
    pub fn of(fd: i32, len: usize) -> Result<Mapping, i32> {
        // SAFETY: a new shared mapping of the caller's descriptor, at an
        // address the host picks.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        Ok(Mapping { at: p as usize, len })
    }

    /// `len` bytes of zeroed memory of this process's alone (for tests).
    #[cfg(test)]
    pub fn anonymous(len: usize) -> Mapping {
        // SAFETY: a new private anonymous mapping.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        Mapping { at: p as usize, len }
    }

    /// `len` bytes at `at`, if inside.
    pub fn read(&self, at: usize, len: usize) -> Option<Vec<u8>> {
        if at.checked_add(len)? > self.len {
            return None;
        }
        let mut b = vec![0u8; len];
        // SAFETY: inside the mapping, which lives as long as `self`; other
        // processes can write it meanwhile, as they can Linux's map.
        unsafe { std::ptr::copy_nonoverlapping((self.at + at) as *const u8, b.as_mut_ptr(), len) };
        Some(b)
    }

    /// Write `data` at `at`, if inside.
    pub fn write(&self, at: usize, data: &[u8]) -> Option<()> {
        if at.checked_add(data.len())? > self.len {
            return None;
        }
        // SAFETY: as in `read`.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), (self.at + at) as *mut u8, data.len())
        };
        Some(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping `of` made, used by nothing after `self`.
        unsafe { libc::munmap(self.at as *mut libc::c_void, self.len) };
    }
}

/// A host shared memory object of `len` bytes (zeroes) with no name (made
/// unlinked): memory a fork child maps as its parent does, as Linux's
/// shared anonymous memory is, never a file's pages to be written back to
/// the disk. Its descriptor, out of the guest's range (close-on-exec).
#[cfg(not(target_os = "linux"))]
pub fn nameless(len: u64) -> Result<std::os::fd::OwnedFd, i32> {
    use std::os::fd::FromRawFd;
    let last = || crate::host::errno_to_linux(crate::host::last_errno());
    let name = format!("/fwe{}a{:x}", crate::host::euid(), crate::shared::unique());
    let name = std::ffi::CString::new(name).map_err(|_| fwe_abi::errno::EINVAL)?;
    // (No `O_CLOEXEC`, which macOS 26 refuses: the descriptor moves into
    // fwe's range, close-on-exec, below.)
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
    // SAFETY: a NUL-terminated name.
    let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: fwe's own object, open above, held by its descriptor.
    unsafe { libc::shm_unlink(name.as_ptr()) };
    // SAFETY: a descriptor just opened, owned from here on.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    use std::os::fd::AsRawFd;
    // SAFETY: a plain host call on the object just made.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
        return Err(last());
    }
    let moved = crate::fdtable::reserve(std::os::fd::IntoRawFd::into_raw_fd(fd))?;
    // SAFETY: the descriptor `reserve` moved it to, owned from here on.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(moved) })
}

/// A new object of `kind` with identity `id`, of `len` bytes (zeroes): a
/// descriptor of it (the guest's, at the lowest free number), and a
/// mapping of it.
#[cfg(target_os = "macos")]
pub fn make(kind: u8, id: u64, len: usize) -> Result<(i32, Mapping), i32> {
    let last = || crate::host::errno_to_linux(crate::host::last_errno());
    let name = format!("/fwe{}{}{id:x}", crate::host::euid(), kind as char);
    let name = std::ffi::CString::new(name).map_err(|_| fwe_abi::errno::EINVAL)?;
    // `O_CLOEXEC` is set after: macOS 26 refuses it here.
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
    // SAFETY: a NUL-terminated name.
    let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: a plain host call on the descriptor just opened. (Linux's
    // `bpf` makes its descriptors close-on-exec.)
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: fwe's own object, open above, held by its descriptor.
    unsafe { libc::shm_unlink(name.as_ptr()) };
    // SAFETY: a plain host call on the object just made.
    let sized = unsafe { libc::ftruncate(fd, len as libc::off_t) } == 0;
    let made = if sized { Mapping::of(fd, len) } else { Err(last()) };
    match made {
        Ok(m) => Ok((fd, m)),
        Err(e) => {
            // SAFETY: closing the descriptor opened above.
            unsafe { libc::close(fd) };
            Err(e)
        }
    }
}

/// What object `fd` is a descriptor of, if one of these: its kind, its
/// identity and its size (whole pages).
#[cfg(target_os = "macos")]
pub fn identify(fd: i32) -> Option<(u8, u64, usize)> {
    // `struct pshm_fdinfo`: the size at 112 (`pshm_stat.vst_size`), the
    // name at 168.
    const PROC_PIDFDPSHMINFO: libc::c_int = 5;
    const INFO: usize = 1192;
    let mut info = [0u8; INFO];
    // SAFETY: a buffer of the size the call is given.
    let n = unsafe {
        libc::proc_pidfdinfo(
            crate::host::pid().get(),
            fd,
            PROC_PIDFDPSHMINFO,
            info.as_mut_ptr().cast(),
            INFO as libc::c_int,
        )
    };
    if n != INFO as libc::c_int {
        return None;
    }
    let size = i64::from_le_bytes(info[112..120].try_into().ok()?);
    let name = &info[168..];
    let name = &name[..name.iter().position(|&b| b == 0)?];
    let rest = name.strip_prefix(format!("/fwe{}", crate::host::euid()).as_bytes())?;
    let (&kind, hex) = rest.split_first()?;
    let id = u64::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
    Some((kind, id, usize::try_from(size).ok()?))
}

#[cfg(not(target_os = "macos"))]
pub fn identify(_fd: i32) -> Option<(u8, u64, usize)> {
    None
}
