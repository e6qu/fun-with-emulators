//! Memory every fwe process of the user can map, holding one filesystem's
//! metadata ([`super`]): a POSIX shared memory object of its own, sized
//! once to [`SIZE`] bytes, of which the host gives memory only to the pages
//! written. What is in it is found by offsets from its start (each process
//! maps it where the host places it), taken from and given back to an
//! allocator in it ([`Mem::alloc`], [`Mem::free`]).
//!
//! One lock ([`Arena::lock`]) guards it all: a reader holds it too. The
//! lock names its holder's pid, and is taken over from a holder that died
//! holding it; a change is marked in progress while the lock is held, so
//! the one that takes it over knows the holder might have left a change half
//! made ([`Mem::repairs`]).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};

/// The bytes an arena can hold: metadata only (file data is in objects of
/// its own, [`super::data`]).
pub const SIZE: usize = 1 << 32;

/// The words the owner of an arena keeps at fixed places ([`Mem::root`]).
pub const ROOTS: usize = 64;

/// Small sizes, each a power of two: from 16 bytes up to 1 MiB.
const SMALLEST: u32 = 4;
const CLASSES: usize = 17;
const LARGEST_SMALL: u64 = 1 << (SMALLEST as usize + CLASSES - 1);

const PAGE: u64 = 16384;

/// What an arena begins with: it was made ([`MAGIC`]), its lock, its
/// change mark, where the allocator has not given out yet, its free lists
/// and its owner's roots.
#[repr(C)]
struct Header {
    magic: AtomicU64,
    lock: AtomicU32,
    changing: AtomicU32,
    /// Bumped as what processes wait for changes (a file lock let go), for
    /// them to wait on ([`Arena::changes`]).
    changes: AtomicU32,
    _pad: u32,
    bump: AtomicU64,
    free: [AtomicU64; CLASSES],
    /// Free runs of whole pages, by address: each holds the next run's
    /// offset and its own length in pages.
    runs: AtomicU64,
    roots: [AtomicU64; ROOTS],
}

const MAGIC: u64 = u64::from_le_bytes(*b"fwefsar2");

/// Where the allocator starts: past the header, on a page.
const START: u64 = PAGE;

/// A mapped arena.
pub struct Arena {
    base: usize,
}

// SAFETY: the mapping is shared memory every user of it reaches under the
// arena's lock; the struct only holds its address.
unsafe impl Send for Arena {}
// SAFETY: as above.
unsafe impl Sync for Arena {}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: the mapping `open` made, which nothing uses past `self`.
        unsafe { libc::munmap(self.base as *mut libc::c_void, SIZE) };
    }
}

/// The host name of arena `id`.
fn name(id: u64) -> std::ffi::CString {
    // (macOS allows names of 31 bytes: "/fwe" and a uid, "a", 16 digits.)
    let n = format!("/fwe{}a{id:x}", crate::host::euid());
    std::ffi::CString::new(n).expect("a name without NUL")
}

impl Arena {
    /// Arena `id`, made (empty) if `make` and it is not there: `ENOENT`
    /// if not and it is not.
    pub fn open(id: u64, make: bool) -> Result<Arena, i32> {
        let name = name(id);
        let last = || crate::host::errno_to_linux(crate::host::last_errno());
        let flags = libc::O_RDWR | if make { libc::O_CREAT } else { 0 };
        // SAFETY: a NUL-terminated name. (No `O_CLOEXEC`: macOS 26 refuses
        // it; the descriptor is closed below.)
        let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(last());
        }
        // SAFETY: the descriptor just opened, owned from here on.
        let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        // Its size is set once: refused if it was made already, or while
        // another process making it at once sizes it, which `sized` waits
        // for.
        // SAFETY: a plain host call on the descriptor.
        unsafe { libc::ftruncate(raw, SIZE as libc::off_t) };
        let st = crate::procstore::sized(raw).ok_or_else(last)?;
        if st.st_uid != crate::host::euid() {
            return Err(fwe_abi::errno::EACCES);
        }
        if (st.st_size as usize) < SIZE {
            eprintln!("fwe: a store's arena {name:?} is {} bytes, not {SIZE}", st.st_size);
            return Err(fwe_abi::errno::EIO);
        }
        // Between guards: files every fwe process shares, which a stack
        // overflowing beside them cannot reach.
        let base =
            crate::host::map_shared_guarded(raw, SIZE).map_err(crate::host::errno_to_linux)?;
        drop(fd);
        let a = Arena { base };
        let h = a.header();
        // The first to get here sets it up; another waits under the lock.
        {
            let (_held, _) = crate::procstore::hold_word(a.static_word(&h.lock));
            if h.magic.load(SeqCst) != MAGIC {
                // New, or another layout's: begun afresh, all of it.
                h.changing.store(0, SeqCst);
                h.changes.store(0, SeqCst);
                h.bump.store(START, SeqCst);
                for w in h.free.iter().chain(h.roots.iter()).chain([&h.runs]) {
                    w.store(0, SeqCst);
                }
                h.magic.store(MAGIC, SeqCst);
            }
        }
        Ok(a)
    }

    /// Arena `id` goes once no process maps it (its name now).
    pub fn remove(id: u64) {
        // SAFETY: a NUL-terminated name of fwe's own object.
        unsafe { libc::shm_unlink(name(id).as_ptr()) };
    }

    fn header(&self) -> &Header {
        // SAFETY: the mapping starts with the header, all atomics.
        unsafe { &*(self.base as *const Header) }
    }

    /// `w`, a word of this arena's mapping, as the procstore lock wants
    /// it: the mapping lives while `self` does, which callers keep for the
    /// lock's life.
    fn static_word(&self, w: &AtomicU32) -> &'static AtomicU32 {
        // SAFETY: the mapping outlives every lock taken through `self`
        // (held only within a `Mem` borrowing `self`).
        unsafe { &*(w as *const AtomicU32) }
    }

    /// The word waiters on the arena's changes sleep on: bumped, and its
    /// waiters woken, by [`Mem::changed`].
    pub fn changes(&self) -> &AtomicU32 {
        &self.header().changes
    }

    /// The arena to read and change, for this process alone, while the
    /// result lives.
    pub fn lock(&self) -> Mem<'_> {
        let h = self.header();
        // A thread that holds it already would wait for itself for ever.
        let me = self.header() as *const Header as usize;
        LOCKED.with(|l| {
            let mut l = l.borrow_mut();
            assert!(!l.contains(&me), "a store's arena locked twice by one thread");
            l.push(me);
        });
        let (held, taken_over) = crate::procstore::hold_word(self.static_word(&h.lock));
        let half_made = taken_over && h.changing.load(SeqCst) != 0;
        h.changing.store(1, SeqCst);
        Mem { arena: self, _held: held, half_made }
    }
}

/// An arena held ([`Arena::lock`]).
pub struct Mem<'a> {
    arena: &'a Arena,
    _held: crate::procstore::Held,
    half_made: bool,
}

impl Drop for Mem<'_> {
    fn drop(&mut self) {
        self.arena.header().changing.store(0, SeqCst);
        let me = self.arena.header() as *const Header as usize;
        LOCKED.with(|l| l.borrow_mut().retain(|&a| a != me));
    }
}

thread_local! {
    /// The arenas this thread holds ([`Arena::lock`]), by their header's
    /// address.
    static LOCKED: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Mem<'_> {
    /// Whether the lock was taken over from a holder that died changing
    /// the arena: what it keeps that can be made again from the rest is to
    /// be made again.
    pub fn repairs(&self) -> bool {
        self.half_made
    }

    /// What waiters on the arena wait for changed: they are woken (once
    /// the lock is let go, they look again).
    pub fn changed(&mut self) {
        let w = &self.arena.header().changes;
        w.fetch_add(1, SeqCst);
        crate::filestore::wait::wake_all(w);
    }

    /// Owner word `i`.
    pub fn root(&self, i: usize) -> u64 {
        self.arena.header().roots[i].load(SeqCst)
    }

    pub fn set_root(&mut self, i: usize, v: u64) {
        self.arena.header().roots[i].store(v, SeqCst);
    }

    /// `len` bytes at `off`.
    pub fn bytes(&self, off: u64, len: usize) -> &[u8] {
        assert!(off >= START && off as usize + len <= SIZE, "arena bytes {off:#x}+{len}");
        // SAFETY: inside the mapping, read under the arena's lock.
        unsafe { std::slice::from_raw_parts((self.arena.base + off as usize) as *const u8, len) }
    }

    /// `len` bytes at `off`, to write.
    pub fn bytes_mut(&mut self, off: u64, len: usize) -> &mut [u8] {
        assert!(off >= START && off as usize + len <= SIZE, "arena bytes {off:#x}+{len}");
        // SAFETY: inside the mapping, written under the arena's lock by
        // this process alone; `&mut self` keeps other borrows out.
        unsafe { std::slice::from_raw_parts_mut((self.arena.base + off as usize) as *mut u8, len) }
    }

    pub fn u64_at(&self, off: u64) -> u64 {
        u64::from_le_bytes(self.bytes(off, 8).try_into().expect("8 bytes"))
    }

    pub fn set_u64(&mut self, off: u64, v: u64) {
        self.bytes_mut(off, 8).copy_from_slice(&v.to_le_bytes());
    }

    /// `n` bytes of zeroes: their offset. `ENOSPC` once the arena is full.
    pub fn alloc(&mut self, n: usize) -> Result<u64, i32> {
        let size = rounded(n);
        let h = self.arena.header();
        let off = if size <= LARGEST_SMALL {
            let list = &h.free[class(size)];
            match list.load(SeqCst) {
                0 => self.bump(size, size.min(PAGE))?,
                head => {
                    list.store(self.u64_at(head), SeqCst);
                    head
                }
            }
        } else {
            match self.take_run(size / PAGE) {
                Some(off) => off,
                None => self.bump(size, PAGE)?,
            }
        };
        self.bytes_mut(off, size as usize).fill(0);
        Ok(off)
    }

    /// Give back the `n` bytes at `off` ([`Mem::alloc`]'s).
    pub fn free(&mut self, off: u64, n: usize) {
        if off == 0 {
            return;
        }
        let size = rounded(n);
        if size <= LARGEST_SMALL {
            let list = &self.arena.header().free[class(size)];
            let head = list.load(SeqCst);
            self.set_u64(off, head);
            list.store(off, SeqCst);
        } else {
            // Its memory goes back to the host until taken again.
            // SAFETY: whole pages of the mapping no one uses now.
            unsafe {
                super::data::give_back(
                    (self.arena.base + off as usize) as *mut libc::c_void,
                    size as usize,
                )
            };
            self.give_run(off, size / PAGE);
        }
    }

    /// The `n` bytes at `off` made `m` long, what they held kept (the rest
    /// zeroes): where they are now.
    pub fn realloc(&mut self, off: u64, n: usize, m: usize) -> Result<u64, i32> {
        if off != 0 && rounded(n) == rounded(m) {
            if m < n {
                self.bytes_mut(off + m as u64, n - m).fill(0);
            }
            return Ok(off);
        }
        let new = self.alloc(m)?;
        if off != 0 {
            let keep = n.min(m);
            let old = self.bytes(off, keep).to_vec();
            self.bytes_mut(new, keep).copy_from_slice(&old);
            self.free(off, n);
        }
        Ok(new)
    }

    fn bump(&mut self, size: u64, align: u64) -> Result<u64, i32> {
        let h = self.arena.header();
        let at = h.bump.load(SeqCst).next_multiple_of(align);
        if at + size > SIZE as u64 {
            return Err(fwe_abi::errno::ENOSPC);
        }
        h.bump.store(at + size, SeqCst);
        Ok(at)
    }

    /// A free run of `pages` pages, the first that is long enough (the
    /// rest of it left free).
    fn take_run(&mut self, pages: u64) -> Option<u64> {
        let h = self.arena.header();
        let mut prev: Option<u64> = None;
        let mut at = h.runs.load(SeqCst);
        while at != 0 {
            let (next, len) = (self.u64_at(at), self.u64_at(at + 8));
            if len >= pages {
                let rest = len - pages;
                let after = if rest > 0 {
                    let r = at + pages * PAGE;
                    self.set_u64(r, next);
                    self.set_u64(r + 8, rest);
                    r
                } else {
                    next
                };
                match prev {
                    Some(p) => self.set_u64(p, after),
                    None => h.runs.store(after, SeqCst),
                }
                return Some(at);
            }
            prev = Some(at);
            at = next;
        }
        None
    }

    /// Run `off` of `pages` pages is free: kept in address order, joined
    /// with the runs it touches.
    fn give_run(&mut self, off: u64, pages: u64) {
        let h = self.arena.header();
        let mut prev: Option<u64> = None;
        let mut at = h.runs.load(SeqCst);
        while at != 0 && at < off {
            prev = Some(at);
            at = self.u64_at(at);
        }
        // Joined with the next run if it starts where this ends.
        let (mut next, mut len) = (at, pages);
        if at != 0 && off + pages * PAGE == at {
            next = self.u64_at(at);
            len += self.u64_at(at + 8);
        }
        // And with the previous if it ends where this starts.
        if let Some(p) = prev {
            let plen = self.u64_at(p + 8);
            if p + plen * PAGE == off {
                self.set_u64(p, next);
                self.set_u64(p + 8, plen + len);
                return;
            }
            self.set_u64(p, off);
        } else {
            h.runs.store(off, SeqCst);
        }
        self.set_u64(off, next);
        self.set_u64(off + 8, len);
    }
}

/// The size an allocation of `n` bytes takes: a power of two up to 1 MiB,
/// whole pages past it.
fn rounded(n: usize) -> u64 {
    let n = (n as u64).max(1 << SMALLEST);
    if n <= LARGEST_SMALL { n.next_power_of_two() } else { n.next_multiple_of(PAGE) }
}

fn class(size: u64) -> usize {
    (size.trailing_zeros() - SMALLEST) as usize
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn fresh() -> (u64, Arena) {
        let id = crate::shared::unique();
        Arena::remove(id);
        (id, Arena::open(id, true).expect("made"))
    }

    /// Small and large allocations come back zeroed, are given out again
    /// once freed, and keep their bytes through a reallocation.
    #[test]
    fn allocations_are_reused_and_kept_through_growth() {
        let (id, a) = fresh();
        {
            let mut m = a.lock();
            let x = m.alloc(10).unwrap();
            m.bytes_mut(x, 10).copy_from_slice(b"0123456789");
            let y = m.realloc(x, 10, 100).unwrap();
            assert_eq!(&m.bytes(y, 12)[..10], b"0123456789");
            assert_eq!(&m.bytes(y, 12)[10..], &[0, 0]);
            // The 16 bytes `x` took are given out again.
            assert_eq!(m.alloc(16).unwrap(), x);
            // Large ones, in pages, joined again as they are freed.
            let big = m.alloc(3 << 20).unwrap();
            let big2 = m.alloc(1 << 21).unwrap();
            assert_eq!(big % PAGE, 0);
            m.free(big, 3 << 20);
            m.free(big2, 1 << 21);
            let whole = m.alloc(5 << 20).unwrap();
            assert_eq!(whole, big);
            assert!(m.bytes(whole, 5 << 20).iter().all(|&b| b == 0));
            m.set_root(3, 77);
        }
        // Another mapping of it sees the same.
        let b = Arena::open(id, false).expect("there");
        assert_eq!(b.lock().root(3), 77);
        Arena::remove(id);
        assert!(Arena::open(id, false).is_err());
    }

    /// A lock its holder died holding is taken over, and the change it was
    /// making is known to be half made.
    #[test]
    fn a_lock_left_by_the_dead_is_taken_over_as_half_made() {
        let (id, a) = fresh();
        assert!(!a.lock().repairs());
        let h = a.header();
        // A holder that is no process, mid-change.
        h.lock.store(i32::MAX as u32, SeqCst);
        h.changing.store(1, SeqCst);
        assert!(a.lock().repairs());
        assert!(!a.lock().repairs());
        Arena::remove(id);
    }
}
