//! File data: what a regular file holds lies in host shared memory
//! objects, the file's extents. The first is sized to the file when it
//! first holds data ([`make`]: at least [`LEAST_FIRST`]); each further one
//! is as long as all before it, so a file of `n` bytes has
//! `log2(n / first) + 2` at most. Each extent's object is sized to the end
//! of its range and holds data only in that range (the pages before it
//! are never touched, holding no memory), so that a mapping of the file
//! maps an extent's object at the file's own offsets.
//!
//! An object's size is what the host's memory compressor sizes its index
//! of the object's pages to (8 bytes for every 128 pages, wired kernel
//! memory, made once any page of it is compressed): objects sized to what
//! their file holds keep that index to a few bytes in a thousand of the
//! data, where one object the size of the largest file
//! ([`SIZE`]) would cost 64 MiB a file.
//!
//! The host refuses `read`, `write` and `lseek` on such an object's
//! descriptor, so fwe reads and writes the data through mappings of its
//! own ([`View`]), kept while this process holds the file open; a guest's
//! shared mapping of the file maps the objects themselves.
//!
//! The objects keep their names while the inode lives (one with no names
//! lives while a process holds it open), so a process maps them again by
//! name as it needs more; they go with the inode ([`remove`]).

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

/// The page of a file's memory: the host's.
pub const PAGE: u64 = 16384;

/// The largest file.
pub const SIZE: u64 = 1 << 44;

/// The least a file's first extent holds: a few pages of a small file,
/// which the host's compressor indexes inside its own record of the
/// object (an object of up to 128 pages has no index of its own).
pub const LEAST_FIRST: u64 = 128 * PAGE;

/// The least this process maps of an extent at once.
const LEAST_VIEW: u64 = 2 << 20;

/// The kind letter of a data object's name ([`crate::memobj::identify`]).
pub const KIND: u8 = b'd';

/// A file's data id holds its own number in these low bits, and above
/// them the log2 of its first extent's length.
const NUMBER_BITS: u32 = 48;

/// An extent's object is named by its file's id shifted by this, with its
/// extent's index in the bits below.
const EXTENT_BITS: u32 = 5;

/// The length of the first extent of file data `id`.
fn first(id: u64) -> u64 {
    1 << (id >> NUMBER_BITS)
}

/// The range `[start, end)` of the file extent `k` of data `id` holds.
pub fn extent(id: u64, k: u32) -> (u64, u64) {
    let f = first(id);
    if k == 0 { (0, f) } else { (f << (k - 1), f << k) }
}

/// The extent of data `id` byte `off` lies in.
pub fn extent_at(id: u64, off: u64) -> u32 {
    let n = off / first(id);
    if n == 0 { 0 } else { 64 - n.leading_zeros() }
}

/// The identity of the object of extent `k` of data `id` (its name's).
fn object_id(id: u64, k: u32) -> u64 {
    id << EXTENT_BITS | u64::from(k)
}

/// The data id and extent of the object whose identity is `object`
/// ([`crate::memobj::identify`]'s).
pub fn of_object(object: u64) -> (u64, u32) {
    (object >> EXTENT_BITS, (object & ((1 << EXTENT_BITS) - 1)) as u32)
}

/// The host name of the object whose identity is `object`.
fn name(object: u64) -> std::ffi::CString {
    // (macOS allows names of 31 bytes: "/fwe" and a uid, "d", 15 digits.)
    let n = format!("/fwe{}{}{object:x}", crate::host::euid(), KIND as char);
    std::ffi::CString::new(n).expect("no NUL")
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// New data for a file that is to hold `hint` bytes: its id, its first
/// extent made (sized to hold them, at least [`LEAST_FIRST`]).
pub fn make(hint: u64) -> Result<u64, i32> {
    let f = hint.clamp(LEAST_FIRST, SIZE).next_power_of_two();
    loop {
        let id = crate::shared::unique() & ((1 << NUMBER_BITS) - 1)
            | u64::from(f.trailing_zeros()) << NUMBER_BITS;
        if id == 0 {
            continue;
        }
        match create(object_id(id, 0), f) {
            Ok(_) => return Ok(id),
            Err(e) if e.is(libc::EEXIST) => continue,
            Err(e) => return Err(e.linux()),
        }
    }
}

/// Make the object whose identity is `object`, `len` bytes long: its
/// descriptor, or the host's errno (`EEXIST` if it is there).
fn create(object: u64, len: u64) -> Result<OwnedFd, crate::host::HostErrno> {
    let n = name(object);
    // SAFETY: a NUL-terminated name. (No `O_CLOEXEC`: macOS 26 refuses
    // it; the descriptor is moved into fwe's range or closed by its owner.)
    let fd = unsafe {
        libc::shm_open(
            n.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(crate::host::last_errno());
    }
    // SAFETY: the descriptor just opened, owned from here on.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a plain host call on the object just made.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
        let e = crate::host::last_errno();
        // SAFETY: the name made above.
        unsafe { libc::shm_unlink(n.as_ptr()) };
        return Err(e);
    }
    Ok(fd)
}

/// A descriptor of the object of extent `k` of data `id`, for reading and
/// writing unless `read_only`; made (with every extent before it) if
/// `make`, else `None` where it was never made (the file holds nothing
/// there).
fn object(id: u64, k: u32, read_only: bool, make: bool) -> Result<Option<OwnedFd>, i32> {
    let flags = if read_only { libc::O_RDONLY } else { libc::O_RDWR };
    let n = name(object_id(id, k));
    loop {
        // SAFETY: a NUL-terminated name.
        let fd = unsafe { libc::shm_open(n.as_ptr(), flags, 0) };
        if fd >= 0 {
            // SAFETY: the descriptor just opened, owned from here on.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // Another process making it at once sizes it: waited for.
            crate::procstore::sized(fd.as_raw_fd()).ok_or_else(last)?;
            return Ok(Some(fd));
        }
        let e = crate::host::last_errno();
        if !e.is(libc::ENOENT) {
            return Err(e.linux());
        }
        if !make {
            return Ok(None);
        }
        if k > 0 {
            object(id, k - 1, true, true)?;
        }
        match create(object_id(id, k), extent(id, k).1) {
            Ok(fd) if !read_only => return Ok(Some(fd)),
            // Opened again as asked.
            Ok(_) => continue,
            Err(e) if e.is(libc::EEXIST) => continue,
            Err(e) => return Err(e.linux()),
        }
    }
}

/// Data `id` goes (each object's memory once no mapping of it is left);
/// this process's views of it too.
pub fn remove(id: u64) {
    if id == 0 {
        return;
    }
    VIEWS.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    // The extents were made in order: the first not there ends them.
    for k in 0.. {
        // SAFETY: a NUL-terminated name of fwe's own object.
        if unsafe { libc::shm_unlink(name(object_id(id, k)).as_ptr()) } != 0 {
            break;
        }
    }
}

/// The objects holding `[off, off + len)` of data `id` (made if they were
/// not), each with the range of the file in it it holds there: what a
/// mapping of that range maps, each at the file's own offsets, for reading
/// and writing unless `read_only`.
pub fn pieces(
    id: u64,
    off: u64,
    len: u64,
    read_only: bool,
) -> Result<Vec<(OwnedFd, u64, u64)>, i32> {
    let end = off.checked_add(len).filter(|&e| e <= SIZE).ok_or(fwe_abi::errno::EFBIG)?;
    let mut out = Vec::new();
    let mut at = off;
    while at < end {
        let k = extent_at(id, at);
        let stop = extent(id, k).1.min(end);
        let fd = object(id, k, read_only, true)?.expect("made");
        out.push((fd, at, stop));
        at = stop;
    }
    Ok(out)
}

/// A descriptor of the object holding all of data `id`'s first `len`
/// bytes, for reading and writing unless `read_only`; `None` if they lie
/// in more than one (the file grew past its first extent).
pub fn whole(id: u64, len: u64, read_only: bool) -> Result<Option<OwnedFd>, i32> {
    if extent_at(id, len.saturating_sub(1)) != 0 {
        return Ok(None);
    }
    object(id, 0, read_only, true)
}

/// A descriptor of the object whose identity is `object`
/// ([`crate::memobj::identify`]'s), for reading and writing.
pub fn open_object(object: u64) -> Result<OwnedFd, i32> {
    let (id, k) = of_object(object);
    self::object(id, k, false, false)?.ok_or(fwe_abi::errno::ENOENT)
}

/// This process's mapping of bytes `[start, start + len)` of an extent's
/// object, within the extent's range.
struct View {
    base: usize,
    start: u64,
    len: u64,
}

impl View {
    /// The address of byte `off` of the file (within the view).
    fn at(&self, off: u64) -> *mut u8 {
        (self.base + (off - self.start) as usize) as *mut u8
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: the mapping `view` made, used by nothing past this.
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.len as usize) };
    }
}

/// A file's views, one for each extent mapped.
type Views = Vec<Option<Arc<View>>>;

/// The views this process keeps, by data id, each while it holds the
/// file open ([`keep`], [`let_go`]); a call on a file it does not hold maps
/// the data for the call alone.
static VIEWS: Mutex<BTreeMap<u64, (Views, u32)>> = Mutex::new(BTreeMap::new());

/// A view of extent `k` of data `id` reaching to byte `end` of the file
/// at least (made if `make`, else `None` where the extent was never made).
fn view(id: u64, k: u32, end: u64, make: bool) -> Result<Option<Arc<View>>, i32> {
    let (start, stop) = extent(id, k);
    let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(Some(v)) = views.get(&id).and_then(|(vs, _)| vs.get(k as usize))
        && v.start + v.len >= end
    {
        return Ok(Some(v.clone()));
    }
    let len = (end - start).next_power_of_two().clamp(LEAST_VIEW.min(stop - start), stop - start);
    let Some(fd) = object(id, k, false, make)? else { return Ok(None) };
    // SAFETY: a new shared mapping of the object's extent, where the host
    // places it.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            start as libc::off_t,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(last());
    }
    let v = Arc::new(View { base: p as usize, start, len });
    if let Some((kept, _)) = views.get_mut(&id) {
        if kept.len() <= k as usize {
            kept.resize(k as usize + 1, None);
        }
        kept[k as usize] = Some(v.clone());
    }
    Ok(Some(v))
}

/// `f` for each part of bytes `[off, off + len)` of data `id` that lies in
/// one extent: given how far into the range the part starts, its address
/// in a view that lasts the call (`None` for an extent never made, which
/// reads as zeroes, unless `make`), and its length.
fn each(
    id: u64,
    off: u64,
    len: u64,
    make: bool,
    mut f: impl FnMut(u64, Option<*mut u8>, u64) -> Result<(), i32>,
) -> Result<(), i32> {
    let end = off.checked_add(len).filter(|&e| e <= SIZE).ok_or(fwe_abi::errno::EFBIG)?;
    let mut at = off;
    while at < end {
        let k = extent_at(id, at);
        let stop = extent(id, k).1.min(end);
        let v = view(id, k, stop, make)?;
        f(at - off, v.as_ref().map(|v| v.at(at)), stop - at)?;
        at = stop;
    }
    Ok(())
}

/// This process holds a file whose data is `id` open once more: its views
/// are kept until it lets go of the last ([`let_go`]).
pub fn keep(id: u64) {
    keep_mapped(id, None);
}

/// [`keep`], the views `made` if there are none yet (a call's mapping of
/// the data: not mapped again).
pub fn keep_mapped(id: u64, made: Option<Mapped>) {
    if id == 0 {
        return;
    }
    let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = views.entry(id).or_insert_with(|| (Vec::new(), 0));
    entry.1 += 1;
    if let Some(Mapped { views: m, .. }) = made {
        if entry.0.len() < m.len() {
            entry.0.resize(m.len(), None);
        }
        for (kept, v) in entry.0.iter_mut().zip(m) {
            if kept.is_none() {
                *kept = v;
            }
        }
    }
}

/// This process holds the file of data `id` open once less: with no
/// holding left, its views go.
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

/// Views of data an object made for a call, reaching to an end of the
/// file: kept on as the process's views of it if the process holds its
/// file ([`keep_mapped`]).
pub struct Mapped {
    id: u64,
    views: Views,
}

impl Mapped {
    /// `f` for each part of `[off, off + len)` (within the end the views
    /// reach) that lies in one extent: how far into the range it starts,
    /// its address and its length.
    pub fn each(
        &self,
        off: u64,
        len: u64,
        mut f: impl FnMut(u64, *mut u8, u64) -> Result<(), i32>,
    ) -> Result<(), i32> {
        let end = off + len;
        let mut at = off;
        while at < end {
            let k = extent_at(self.id, at);
            let stop = extent(self.id, k).1.min(end);
            let v = self.views[k as usize].as_ref().expect("mapped to the end");
            f(at - off, v.at(at), stop - at)?;
            at = stop;
        }
        Ok(())
    }
}

/// Views of data `id`'s first `end` bytes at least (its extents made).
pub fn mapped(id: u64, end: u64) -> Result<Mapped, i32> {
    if end > SIZE {
        return Err(fwe_abi::errno::EFBIG);
    }
    let last = extent_at(id, end.saturating_sub(1));
    let mut views = Vec::with_capacity(last as usize + 1);
    for k in 0..=last {
        let stop = extent(id, k).1.min(end.max(1));
        views.push(view(id, k, stop, true)?);
    }
    Ok(Mapped { id, views })
}

/// `f` for each part of bytes `[off, off + len)` of data `id` that lies in
/// one extent: how far into the range it starts, its bytes (`None` where
/// the file holds nothing, read as zeroes) and its length.
pub fn each_read(
    id: u64,
    off: u64,
    len: u64,
    mut f: impl FnMut(u64, Option<&[u8]>) -> Result<(), i32>,
) -> Result<(), i32> {
    each(id, off, len, false, |done, p, n| {
        // SAFETY: `n` bytes of a view that lasts the call; other processes
        // can write them meanwhile, as they can a file's page.
        f(done, p.map(|p| unsafe { std::slice::from_raw_parts(p, n as usize) }))
    })
}

/// Copy `buf.len()` bytes at `off` of data `id` into `buf` (the caller
/// keeps it within the file).
pub fn read(id: u64, off: u64, buf: &mut [u8]) -> Result<(), i32> {
    if id == 0 {
        buf.fill(0);
        return Ok(());
    }
    each_read(id, off, buf.len() as u64, |done, bytes| {
        let to = &mut buf[done as usize..];
        match bytes {
            Some(b) => to[..b.len()].copy_from_slice(b),
            None => to.fill(0),
        }
        Ok(())
    })
}

/// Write `data` at `off` of data `id`.
pub fn write(id: u64, off: u64, data: &[u8]) -> Result<(), i32> {
    each(id, off, data.len() as u64, true, |done, p, n| {
        let from = &data[done as usize..(done + n) as usize];
        // SAFETY: `n` bytes of a view that lasts the call.
        unsafe { std::ptr::copy_nonoverlapping(from.as_ptr(), p.expect("made"), n as usize) };
        Ok(())
    })
}

/// Bytes `[start, end)` of data `id` read as zeroes again, their whole
/// pages giving their memory back.
pub fn zero(id: u64, start: u64, end: u64) -> Result<(), i32> {
    if id == 0 || end <= start {
        return Ok(());
    }
    each(id, start, end - start, false, |done, p, n| {
        let Some(p) = p else { return Ok(()) };
        let (from, to) = (start + done, start + done + n);
        let first = from.next_multiple_of(PAGE).min(to);
        let past = (to / PAGE * PAGE).max(first);
        // SAFETY: inside a view that lasts the call; whole pages of it
        // given back, which no one uses as memory of their own.
        unsafe {
            let at = |o: u64| p.add((o - from) as usize);
            std::ptr::write_bytes(at(from), 0, (first - from) as usize);
            std::ptr::write_bytes(at(past), 0, (to - past) as usize);
            if past > first {
                give_back(at(first) as *mut libc::c_void, (past - first) as usize);
            }
        }
        Ok(())
    })
}

/// The whole pages at `at`, `len` bytes of a shared mapping, read as
/// zeroes, their memory the host's again. On Linux they go
/// (`MADV_REMOVE`). On macOS, which takes no page of a shared object back
/// for good, they are zeroed (`MADV_ZERO`, which writes no page that held
/// nothing and pages none back in) and left for the host to take first
/// when it runs short (`MADV_FREE_REUSABLE`, as macOS's `malloc` leaves
/// freed memory): a page written again after is dirty, and kept.
///
/// # Safety
/// Pages of a shared mapping no one else uses as memory of their own.
pub(super) unsafe fn give_back(at: *mut libc::c_void, len: usize) {
    #[cfg(target_os = "macos")]
    {
        /// `<sys/mman.h>`'s, which the libc crate does not have.
        const MADV_ZERO: libc::c_int = 11;
        // SAFETY: whole pages of the caller's mapping, which no one uses.
        let zeroed = unsafe { libc::madvise(at, len, MADV_ZERO) };
        assert_eq!(zeroed, 0, "MADV_ZERO of fwe's own pages: {}", std::io::Error::last_os_error());
        // SAFETY: as above.
        let reusable = unsafe { libc::madvise(at, len, libc::MADV_FREE_REUSABLE) };
        assert_eq!(
            reusable,
            0,
            "MADV_FREE_REUSABLE of fwe's own pages: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: guaranteed by the caller.
    #[cfg(not(target_os = "macos"))]
    unsafe {
        libc::madvise(at, len, libc::MADV_REMOVE);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Written across extents, read back, seen through each extent's
    /// object at the file's own offsets, zeroed in part (whole pages given
    /// back), and gone once removed.
    #[test]
    fn data_is_written_read_and_zeroed() {
        let id = make(5).unwrap();
        assert_eq!(extent(id, 0), (0, LEAST_FIRST));
        write(id, 5, b"hello").unwrap();
        // Far past the first extent: the ones up to it are made.
        let far = 40 << 20;
        let k = extent_at(id, far);
        assert_eq!(extent(id, k), (32 << 20, 64 << 20));
        write(id, far, b"far").unwrap();
        // Across the boundary of the first two extents.
        write(id, LEAST_FIRST - 2, b"edge").unwrap();
        let mut b = [0u8; 5];
        read(id, 5, &mut b).unwrap();
        assert_eq!(&b, b"hello");
        let mut f = [0u8; 3];
        read(id, far, &mut f).unwrap();
        assert_eq!(&f, b"far");
        let mut e = [0u8; 4];
        read(id, LEAST_FIRST - 2, &mut e).unwrap();
        assert_eq!(&e, b"edge");
        // Another descriptor of each piece sees the same bytes, at the
        // file's offsets.
        let pieces = pieces(id, 0, far + PAGE, true).unwrap();
        assert_eq!(pieces.len() as u32, k + 1);
        let map = |fd: &OwnedFd, at: u64| {
            // SAFETY: a read-only shared mapping of an object of fwe's.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE as usize,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    (at / PAGE * PAGE) as libc::off_t,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            p as *const u8
        };
        let first = map(&pieces[0].0, 0);
        let last = map(&pieces[k as usize].0, far);
        // SAFETY: inside the mappings just made.
        unsafe {
            assert_eq!(std::slice::from_raw_parts(first.add(5), 5), b"hello");
            assert_eq!(std::slice::from_raw_parts(last.add((far % PAGE) as usize), 3), b"far");
        }
        zero(id, 6, 3 * PAGE).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { std::slice::from_raw_parts(first.add(5), 5) }, b"h\0\0\0\0");
        // SAFETY: the mappings made above.
        unsafe {
            libc::munmap(first as *mut libc::c_void, PAGE as usize);
            libc::munmap(last as *mut libc::c_void, PAGE as usize);
        }
        drop(pieces);
        remove(id);
        for k in 0..=k {
            assert_eq!(object(id, k, true, false).unwrap().map(|_| ()), None);
        }
    }

    /// A file's first extent is sized to what it was to hold, and the
    /// object of each extent to the end of its range.
    #[test]
    fn extents_are_sized_to_the_file() {
        let id = make(40 << 20).unwrap();
        assert_eq!(extent(id, 0), (0, 64 << 20));
        assert_eq!(extent(id, 1), (64 << 20, 128 << 20));
        assert_eq!(extent_at(id, (64 << 20) - 1), 0);
        assert_eq!(extent_at(id, 64 << 20), 1);
        assert_eq!(extent_at(id, 200 << 20), 2);
        assert!(whole(id, 64 << 20, true).unwrap().is_some());
        assert!(whole(id, (64 << 20) + 1, true).unwrap().is_none());
        let p = pieces(id, 60 << 20, 8 << 20, false).unwrap();
        let size = |fd: &OwnedFd| {
            // SAFETY: zeroed bytes are a valid `stat`, which fstat fills.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) }, 0);
            st.st_size as u64
        };
        assert_eq!(
            p.iter().map(|(fd, s, e)| (size(fd), *s, *e)).collect::<Vec<_>>(),
            [(64 << 20, 60 << 20, 64 << 20), (128 << 20, 64 << 20, 68 << 20)]
        );
        drop(p);
        remove(id);
    }

    /// Zeroed whole pages read as zeroes, through another mapping too, and
    /// no longer count against the process's memory; written again, they
    /// keep what is written.
    #[test]
    fn zeroed_pages_read_as_zeroes_and_go_back() {
        // `task_vm_info`'s `phys_footprint`: its 19th 64-bit word
        // (`<mach/task_info.h>`, flavor `TASK_VM_INFO`).
        let footprint = || {
            const TASK_VM_INFO: libc::task_flavor_t = 22;
            let mut info = [0u64; 64];
            let mut n = (std::mem::size_of_val(&info) / 4) as libc::mach_msg_type_number_t;
            // SAFETY: a valid out-buffer of `n` 32-bit words, for this task.
            let r = unsafe {
                #[allow(deprecated)]
                libc::task_info(
                    libc::mach_task_self(),
                    TASK_VM_INFO,
                    info.as_mut_ptr().cast(),
                    &mut n,
                )
            };
            assert_eq!(r, 0);
            info[18]
        };
        let id = make(0).unwrap();
        // Held open: its pages are this process's while its view is mapped.
        keep(id);
        // Enough that other tests' memory, which the process's footprint
        // counts too, does not hide what goes back.
        let len = 512 * PAGE;
        write(id, 0, &vec![9u8; len as usize]).unwrap();
        let before = footprint();
        zero(id, 0, len).unwrap();
        let after = footprint();
        assert!(before - after >= len / 2, "{before} -> {after}");
        let mut b = vec![1u8; len as usize];
        read(id, 0, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 0));
        write(id, PAGE, b"kept").unwrap();
        let mut k = [0u8; 4];
        read(id, PAGE, &mut k).unwrap();
        assert_eq!(&k, b"kept");
        let_go(id);
        remove(id);
    }
}
