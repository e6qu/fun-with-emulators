//! File data: one host shared memory object for each regular file that
//! holds any, sized once to [`SIZE`] (the host gives memory only to the
//! pages written), named by an id no other object has. The host refuses
//! `read`, `write` and `lseek` on such an object's descriptor, so fwe
//! reads and writes it through a mapping of its own ([`View`]), kept
//! while this process holds the file open; a guest's shared mapping of the
//! file maps the object itself.
//!
//! The object keeps its name while its inode lives (one with no names
//! lives while a process holds it open), so a process maps it again by
//! name as it needs more of it; it goes with its inode ([`remove`]).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The page of a file's memory: the host's.
pub const PAGE: u64 = 16384;

/// The largest file: what an object is sized to.
pub const SIZE: u64 = 1 << 44;

/// The least this process maps of an object at once.
const LEAST_VIEW: u64 = 2 << 20;

/// The host name of object `id`.
/// The kind letter of a data object's name ([`crate::memobj::identify`]).
pub const KIND: u8 = b'd';

fn name(id: u64) -> std::ffi::CString {
    // (macOS allows names of 31 bytes: "/fwe" and a uid, "d", 16 digits.)
    let n = format!("/fwe{}{}{id:x}", crate::host::euid(), KIND as char);
    std::ffi::CString::new(n).expect("no NUL")
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// A new object, of a new id: the id.
pub fn make() -> Result<u64, i32> {
    loop {
        let id = crate::shared::unique();
        let n = name(id);
        // SAFETY: a NUL-terminated name. (No `O_CLOEXEC`: macOS 26 refuses
        // it; the descriptor is closed below.)
        let fd = unsafe {
            libc::shm_open(
                n.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            if crate::host::last_errno() == libc::EEXIST {
                continue;
            }
            return Err(last());
        }
        // SAFETY: plain host calls on the object just made.
        let sized = unsafe {
            let ok = libc::ftruncate(fd, SIZE as libc::off_t) == 0;
            libc::close(fd);
            ok
        };
        if !sized {
            // SAFETY: the name made above.
            unsafe { libc::shm_unlink(n.as_ptr()) };
            return Err(fwe_abi::errno::ENOMEM);
        }
        return Ok(id);
    }
}

/// Object `id` goes (its memory once no mapping of it is left); this
/// process's view of it too.
pub fn remove(id: u64) {
    if id == 0 {
        return;
    }
    VIEWS.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    // SAFETY: a NUL-terminated name of fwe's own object.
    unsafe { libc::shm_unlink(name(id).as_ptr()) };
}

/// A descriptor of object `id`, for reading and writing unless
/// `read_only` (a guest's shared mapping maps it).
pub fn open(id: u64, read_only: bool) -> Result<std::os::fd::OwnedFd, i32> {
    let flags = if read_only { libc::O_RDONLY } else { libc::O_RDWR };
    // SAFETY: a NUL-terminated name.
    let fd = unsafe { libc::shm_open(name(id).as_ptr(), flags, 0) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: the descriptor just opened, owned from here on.
    Ok(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

/// This process's mapping of the first `len` bytes of an object.
struct View {
    base: usize,
    len: u64,
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: the mapping `view` made, used by nothing past this.
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.len as usize) };
    }
}

/// The views this process keeps, by object, each while it holds the file
/// open ([`keep`], [`let_go`]); a call on a file it does not hold maps the
/// data for the call alone.
static VIEWS: Mutex<BTreeMap<u64, (Arc<View>, u32)>> = Mutex::new(BTreeMap::new());

/// A view of object `id` of at least `end` bytes.
fn view(id: u64, end: u64) -> Result<Arc<View>, i32> {
    if end > SIZE {
        return Err(fwe_abi::errno::EFBIG);
    }
    let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((v, _)) = views.get(&id)
        && v.len >= end
    {
        return Ok(v.clone());
    }
    let len = end.next_power_of_two().clamp(LEAST_VIEW, SIZE);
    let fd = open(id, false)?;
    // SAFETY: a new shared mapping of the object, where the host places it.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(last());
    }
    let v = Arc::new(View { base: p as usize, len });
    if let Some(kept) = views.get_mut(&id) {
        kept.0 = v.clone();
    }
    Ok(v)
}

/// This process holds a file whose data is object `id` open once more:
/// its view is kept until it lets go of the last ([`let_go`]).
pub fn keep(id: u64) {
    if id == 0 {
        return;
    }
    let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, n)) = views.get_mut(&id) {
        *n += 1;
        return;
    }
    drop(views);
    if let Ok(v) = view(id, LEAST_VIEW) {
        VIEWS.lock().unwrap_or_else(|e| e.into_inner()).entry(id).or_insert((v, 0)).1 += 1;
    }
}

/// This process holds the file of object `id` open once less: with no
/// holding left, its view goes.
pub fn let_go(id: u64) {
    if id == 0 {
        return;
    }
    let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, n)) = views.get_mut(&id) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            views.remove(&id);
        }
    }
}

/// `f` given the address of bytes `[off, off + len)` of object `id` in a
/// mapping of it that lasts the call.
pub fn with_bytes<R>(id: u64, off: u64, len: u64, f: impl FnOnce(*mut u8) -> R) -> Result<R, i32> {
    let v = view(id, off + len)?;
    Ok(f((v.base + off as usize) as *mut u8))
}

/// Copy `buf.len()` bytes at `off` of object `id` into `buf` (the caller
/// keeps it within the file).
pub fn read(id: u64, off: u64, buf: &mut [u8]) -> Result<(), i32> {
    if buf.is_empty() {
        return Ok(());
    }
    if id == 0 {
        buf.fill(0);
        return Ok(());
    }
    let v = view(id, off + buf.len() as u64)?;
    // SAFETY: inside the view, which `v` keeps mapped; other processes may
    // write it meanwhile, as they may a file's page.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (v.base + off as usize) as *const u8,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    Ok(())
}

/// Write `data` at `off` of object `id`.
pub fn write(id: u64, off: u64, data: &[u8]) -> Result<(), i32> {
    if data.is_empty() {
        return Ok(());
    }
    let v = view(id, off + data.len() as u64)?;
    // SAFETY: inside the view, as in `read`.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), (v.base + off as usize) as *mut u8, data.len())
    };
    Ok(())
}

/// Bytes `[start, end)` of object `id` read as zeroes again, their whole
/// pages giving their memory back.
pub fn zero(id: u64, start: u64, end: u64) -> Result<(), i32> {
    if id == 0 || end <= start {
        return Ok(());
    }
    let v = view(id, end)?;
    let first = start.next_multiple_of(PAGE);
    let past = end / PAGE * PAGE;
    // SAFETY: inside the view, as in `read`.
    unsafe {
        let at = |o: u64| (v.base + o as usize) as *mut u8;
        if first >= past {
            std::ptr::write_bytes(at(start), 0, (end - start) as usize);
            return Ok(());
        }
        std::ptr::write_bytes(at(start), 0, (first - start) as usize);
        std::ptr::write_bytes(at(past), 0, (end - past) as usize);
        give_back(at(first) as *mut libc::c_void, (past - first) as usize);
    }
    Ok(())
}

/// The whole pages at `at`, `len` bytes of a shared mapping, read as
/// zeroes and hold no memory now.
///
/// # Safety
/// Pages of a shared mapping no one else uses as memory of their own.
pub(super) unsafe fn give_back(at: *mut libc::c_void, len: usize) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        #[cfg(target_os = "macos")]
        {
            // Zeroed in place (the object's pages are its contents), then
            // their memory given back until written again.
            libc::madvise(at, len, libc::MADV_ZERO);
            libc::madvise(at, len, libc::MADV_FREE_REUSABLE);
        }
        #[cfg(not(target_os = "macos"))]
        libc::madvise(at, len, libc::MADV_REMOVE);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Written, read back from another view, zeroed in part (whole pages
    /// given back), and gone once removed.
    #[test]
    fn data_is_written_read_and_zeroed() {
        let id = make().unwrap();
        write(id, 5, b"hello").unwrap();
        // Far past the first view: a bigger one is made.
        write(id, 40 << 20, b"far").unwrap();
        let mut b = [0u8; 5];
        read(id, 5, &mut b).unwrap();
        assert_eq!(&b, b"hello");
        let mut f = [0u8; 3];
        read(id, 40 << 20, &mut f).unwrap();
        assert_eq!(&f, b"far");
        // Another descriptor of it sees the same bytes.
        let fd = open(id, true).unwrap();
        // SAFETY: a read-only shared mapping of the object just opened.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ,
                libc::MAP_SHARED,
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        // SAFETY: inside the mapping just made.
        assert_eq!(unsafe { std::slice::from_raw_parts((p as *const u8).add(5), 5) }, b"hello");
        zero(id, 6, 3 * PAGE).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { std::slice::from_raw_parts((p as *const u8).add(5), 5) }, b"h\0\0\0\0");
        // SAFETY: the mapping made above.
        unsafe { libc::munmap(p, 16384) };
        remove(id);
        assert_eq!(open(id, true).err(), Some(fwe_abi::errno::ENOENT));
    }
}
