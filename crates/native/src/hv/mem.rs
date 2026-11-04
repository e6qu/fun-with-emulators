//! The guest's memory in the VM backend: Linux's memory system calls over
//! the slab and the guest's stage-1 tables ([`super::vm`]).
//!
//! Every mapping is a range of guest pages and what backs it:
//!
//! - **private memory** (anonymous, or a private file mapping, whose file
//!   data is copied in) is backed by a range of the slab. A mapping the
//!   guest did not place itself sits at the same address as guest address
//!   and host address; one the guest placed outside the slab (a program
//!   image linked low, a `MAP_FIXED` address) is backed by a slab range
//!   elsewhere and translated ([`fwe_kernel::uaccess::add_translation`]);
//! - **shared memory** (`MAP_SHARED`, of a file or anonymous) is a host
//!   mapping of its own outside the slab, a *segment*, mapped into the VM
//!   once ([`super::vm::map_segment`]) — anonymous shared memory is backed
//!   by an unlinked file, so a fork child can map the same pages.
//!
//! Changes only ever edit the guest's tables; host memory behind the VM is
//! never replaced. Memory the guest gives back is reused only after a TLB
//! flush covering the change ([`super::vm::Flush`]), so no vCPU can still
//! reach it through an old translation. The kernel's own accesses to guest
//! memory are checked against the mappings ([`valid`]): host memory stays
//! accessible where the guest's is not.

use super::pagetables::PAGE;
use super::{vm, window};
use fwe_abi::{err, errno, mman};
use fwe_kernel::mm::Brk;
use fwe_kernel::uaccess;
use fwe_kernel::vmas::{Mapping, Piece, Vmas};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};

/// What backs a mapping, seen from its start.
#[derive(Debug, Clone)]
pub enum Back {
    /// Slab memory at this host address.
    Slab { host: u64 },
    /// Segment `id`, from this offset into it.
    Segment { id: u64, off: u64 },
}

/// A private file mapping's file, for `MADV_DONTNEED` (which brings the
/// file's contents back).
#[derive(Debug, Clone)]
pub struct Source {
    file: Arc<OwnedFd>,
    offset: u64,
}

/// One mapping.
#[derive(Debug, Clone)]
pub struct Area {
    /// Linux protections.
    pub prot: u64,
    pub back: Back,
    pub source: Option<Source>,
}

impl PartialEq for Area {
    fn eq(&self, o: &Area) -> bool {
        let back = match (&self.back, &o.back) {
            (Back::Slab { host: a }, Back::Slab { host: b }) => a == b,
            (Back::Segment { id: a, off: x }, Back::Segment { id: b, off: y }) => a == b && x == y,
            _ => false,
        };
        let source = match (&self.source, &o.source) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(&a.file, &b.file) && a.offset == b.offset,
            _ => false,
        };
        self.prot == o.prot && back && source
    }
}

impl Mapping for Area {
    fn at(&self, offset: u64) -> Area {
        Area {
            prot: self.prot,
            back: match self.back {
                Back::Slab { host } => Back::Slab { host: host + offset },
                Back::Segment { id, off } => Back::Segment { id, off: off + offset },
            },
            source: self
                .source
                .as_ref()
                .map(|s| Source { file: s.file.clone(), offset: s.offset + offset }),
        }
    }
}

/// Shared memory mapped into the VM once.
#[derive(Debug)]
pub struct Segment {
    /// Host mapping, host-page aligned.
    pub host: u64,
    pub len: u64,
    pub ipa: u64,
    /// The file whose pages these are (for anonymous memory, an unlinked
    /// one), and the file offset of `host`.
    pub file: Arc<OwnedFd>,
    pub file_offset: u64,
    /// Guest bytes mapping it; at zero it goes.
    refs: u64,
}

/// The guest's memory.
#[derive(Default)]
pub struct Mem {
    pub vmas: Vmas<Area>,
    pub segments: BTreeMap<u64, Segment>,
    next_segment: u64,
    /// Slab ranges given back, `(generation, host, len)`, released once a
    /// flush covers their generation.
    pending: Vec<(u64, u64, u64)>,
    /// Segments no longer mapped, released likewise.
    pending_segments: Vec<(u64, u64)>,
    /// The program break's slab range, reserved for it whole; and how far
    /// up it has held data (pages below are zeroed when mapped again).
    brk_range: (u64, u64),
    brk_high: u64,
}

static MEM: Mutex<Option<Mem>> = Mutex::new(None);

pub fn mem() -> MutexGuard<'static, Option<Mem>> {
    MEM.lock().unwrap_or_else(|e| e.into_inner())
}

/// Start managing the guest's memory (after [`vm::create`]).
pub fn init() {
    *mem() = Some(Mem::default());
    uaccess::set_validator(valid);
    vm::on_flushed(flushed);
}

/// Take a fork parent's memory records (its contents are already copied).
pub fn install(m: Mem) {
    *mem() = Some(m);
    uaccess::set_validator(valid);
    vm::on_flushed(flushed);
}

fn page_up(a: u64) -> u64 {
    a.checked_add(PAGE - 1).map_or(!(PAGE - 1), |v| v & !(PAGE - 1))
}

/// Whether the guest may access `[addr, addr + len)` (writing, with
/// `write`): every page mapped, readable, and writable if `write`. The
/// kernel is given host addresses for guest pointers: one inside a
/// translated range's host memory stands for its guest address.
pub fn valid(addr: u64, len: u64, write: bool) -> bool {
    let addr = guest_of(addr, len);
    let Some(end) = addr.checked_add(len) else { return false };
    // A vfork child has its parent's memory fetched first.
    prepare_access(addr, len);
    let g = mem();
    let Some(m) = g.as_ref() else { return true };
    let (lo, hi) = (addr & !(PAGE - 1), page_up(end));
    let mut at = lo;
    for p in m.vmas.pieces(lo, hi) {
        let ok = if write {
            p.value.prot & mman::PROT_WRITE != 0
        } else {
            p.value.prot != mman::PROT_NONE
        };
        if p.start != at || !ok {
            return false;
        }
        at = p.end;
    }
    at >= hi
}

/// The guest address host address `addr` stands for: itself, or — inside
/// the host memory of a translated range — the guest address it backs.
fn guest_of(addr: u64, len: u64) -> u64 {
    for (g, l, h) in uaccess::translations() {
        if addr >= h && addr.saturating_add(len) <= h + l {
            return g + (addr - h);
        }
    }
    addr
}

/// A flush covering `generation` completed: what was given back before it
/// can be reused.
fn flushed(generation: u64) {
    let mut g = mem();
    let Some(m) = g.as_mut() else { return };
    let (now, later): (Vec<_>, Vec<_>) =
        m.pending.drain(..).partition(|&(g, _, _)| g <= generation);
    m.pending = later;
    for (_, host, len) in now {
        window::release(host, len);
    }
    let (now, later): (Vec<_>, Vec<_>) =
        m.pending_segments.drain(..).partition(|&(g, _)| g <= generation);
    m.pending_segments = later;
    for (_, id) in now {
        if let Some(s) = m.segments.remove(&id) {
            vm::unmap_segment(s.ipa);
            // SAFETY: the segment's own host mapping, no longer in the VM.
            unsafe { libc::munmap(s.host as *mut _, s.len as usize) };
        }
    }
}

impl Mem {
    /// The IPA guest page `start` of `area` maps to.
    fn ipa(&self, area: &Area) -> Option<u64> {
        match area.back {
            Back::Slab { host } => Some(vm::slab_ipa(host)),
            Back::Segment { id, off } => self.segments.get(&id).map(|s| s.ipa + off),
        }
    }

    /// Put `[start, end)` of `area` into the tables.
    fn install_pages(&self, start: u64, end: u64, area: &Area) -> Result<(), i32> {
        if area.prot == mman::PROT_NONE {
            vm::unmap_pages(start, end - start);
            return Ok(());
        }
        let ipa = self.ipa(area).ok_or(errno::ENOMEM)?;
        vm::map_pages(start, end - start, ipa, vm::perms(area.prot))
    }

    /// Unmap `[start, end)`: out of the tables, its memory released after
    /// the flush that follows.
    fn remove(&mut self, start: u64, end: u64) {
        let gone = self.vmas.remove(start, end);
        if gone.is_empty() {
            return;
        }
        vm::unmap_pages(start, end - start);
        // Released after the flush the unmapping needs: the generation the
        // edit bumped to.
        let generation = vm::generation();
        for Piece { start, end, value } in gone {
            match value.back {
                Back::Slab { host } => {
                    if host != start {
                        uaccess::remove_translation(start, end - start);
                    }
                    // The break's range stays reserved for it.
                    let (bs, be) = self.brk_range;
                    if host >= bs && host < be {
                        continue;
                    }
                    self.pending.push((generation, host, end - start));
                }
                Back::Segment { id, .. } => {
                    uaccess::remove_translation(start, end - start);
                    if let Some(s) = self.segments.get_mut(&id) {
                        s.refs = s.refs.saturating_sub(end - start);
                        if s.refs == 0 {
                            self.pending_segments.push((generation, id));
                        }
                    }
                }
            }
        }
    }

    /// Slab memory for `len` bytes at guest address `addr`: the same host
    /// address where it is free in the slab, else a range elsewhere.
    fn back(&mut self, addr: u64, len: u64) -> Result<u64, i32> {
        if window::take_fixed(addr, len) {
            return Ok(addr);
        }
        let host = window::alloc(len).ok_or(errno::ENOMEM)?;
        uaccess::add_translation(addr, len, host);
        Ok(host)
    }

    /// Map private memory at `[addr, addr + len)` (placed already), with
    /// file data from `source` copied in.
    fn map_private(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        source: Option<Source>,
    ) -> Result<(), i32> {
        let host = self.back(addr, len)?;
        if let Some(s) = &source {
            fill(host, len, s)?;
            code_written(host, len);
        }
        let area = Area { prot, back: Back::Slab { host }, source };
        if let Err(e) = self.install_pages(addr, addr + len, &area) {
            window::release(host, len);
            if host != addr {
                uaccess::remove_translation(addr, len);
            }
            return Err(e);
        }
        self.vmas.insert(addr, addr + len, area);
        Ok(())
    }

    /// Map shared memory of `file` (from `offset`) at `[addr, addr + len)`.
    fn map_shared(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        file: Arc<OwnedFd>,
        offset: u64,
    ) -> Result<(), i32> {
        const HOST_PAGE: u64 = 16 << 10;
        let base = offset & !(HOST_PAGE - 1);
        let delta = offset - base;
        let hlen = (delta + len).div_ceil(HOST_PAGE) * HOST_PAGE;
        let hprot =
            libc::PROT_READ | if prot & mman::PROT_WRITE != 0 { libc::PROT_WRITE } else { 0 };
        // SAFETY: a fresh shared mapping of the guest's file, fwe's own.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                hlen as usize,
                hprot,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                base as i64,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(last_errno());
        }
        let host = host as u64;
        let ipa = match vm::map_segment(host, hlen) {
            Ok(ipa) => ipa,
            Err(e) => {
                // SAFETY: the mapping just made.
                unsafe { libc::munmap(host as *mut _, hlen as usize) };
                return Err(e);
            }
        };
        let id = self.next_segment;
        self.next_segment += 1;
        self.segments
            .insert(id, Segment { host, len: hlen, ipa, file, file_offset: base, refs: len });
        let area = Area { prot, back: Back::Segment { id, off: delta }, source: None };
        if let Err(e) = self.install_pages(addr, addr + len, &area) {
            self.segments.remove(&id);
            vm::unmap_segment(ipa);
            // SAFETY: the mapping just made, no longer in the VM.
            unsafe { libc::munmap(host as *mut _, hlen as usize) };
            return Err(e);
        }
        uaccess::add_translation(addr, len, host + delta);
        self.vmas.insert(addr, addr + len, area);
        Ok(())
    }

    /// Where a mapping of `len` bytes the guest did not place goes: free
    /// in the slab and in the guest's address space.
    fn place(&mut self, len: u64) -> Result<u64, i32> {
        // The slab range is taken (and so not handed to anything else) and
        // given back to be taken again as this mapping's backing.
        let at = window::alloc(len).ok_or(errno::ENOMEM)?;
        if self.vmas.any(at, at + len) {
            // A guest mapping at a slab address backed elsewhere: rare; try
            // the guest's free space instead.
            window::release(at, len);
            return self
                .vmas
                .find_free(len, window::LO, window::hi(), PAGE, true)
                .ok_or(errno::ENOMEM);
        }
        window::release(at, len);
        Ok(at)
    }

    pub fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i32,
        offset: u64,
    ) -> i64 {
        if len == 0 || offset & (PAGE - 1) != 0 {
            return err(errno::EINVAL);
        }
        let len = page_up(len);
        let shared = match flags & mman::MAP_TYPE {
            mman::MAP_SHARED | mman::MAP_SHARED_VALIDATE => true,
            mman::MAP_PRIVATE => false,
            _ => return err(errno::EINVAL),
        };
        let anonymous = flags & mman::MAP_ANONYMOUS != 0;
        let fixed = flags & mman::MAP_FIXED != 0;
        let noreplace = flags & mman::MAP_FIXED_NOREPLACE != 0 && !fixed;
        if (fixed || noreplace) && addr & (PAGE - 1) != 0 {
            return err(errno::EINVAL);
        }
        if (fixed || noreplace) && addr.checked_add(len).is_none_or(|e| e > vm::CODE_VA) {
            return err(errno::ENOMEM);
        }
        let file = if anonymous {
            None
        } else {
            // SAFETY: duplicating the guest's descriptor, so the mapping
            // keeps its file as Linux's does.
            let d =
                unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, fwe_kernel::fdtable::guest_max()) };
            if d < 0 {
                return err(errno::EBADF);
            }
            // SAFETY: a descriptor just made, owned here.
            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(d) }))
        };
        let at = if fixed || noreplace {
            if noreplace && self.vmas.any(addr, addr + len) {
                return err(errno::EEXIST);
            }
            addr
        } else {
            match self.place(len) {
                Ok(a) => a,
                Err(e) => return err(e),
            }
        };
        // A fixed mapping replaces what is there.
        self.remove(at, at + len);
        let r = if shared {
            let file = match file {
                Some(f) => f,
                None => match anonymous_file(len) {
                    Ok(f) => Arc::new(f),
                    Err(e) => return err(e),
                },
            };
            self.map_shared(at, len, prot, file, if anonymous { 0 } else { offset })
        } else {
            self.map_private(at, len, prot, file.map(|file| Source { file, offset }))
        };
        match r {
            Ok(()) => at as i64,
            Err(e) => err(e),
        }
    }

    pub fn munmap(&mut self, addr: u64, len: u64) -> i64 {
        if addr & (PAGE - 1) != 0 || len == 0 {
            return err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(page_up(len)) else { return err(errno::EINVAL) };
        self.remove(addr, end);
        0
    }

    pub fn mprotect(&mut self, addr: u64, len: u64, prot: u64) -> i64 {
        if addr & (PAGE - 1) != 0 {
            return err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(page_up(len)) else { return err(errno::ENOMEM) };
        if !self.vmas.covered(addr, end) {
            return err(errno::ENOMEM);
        }
        let prot = prot & (mman::PROT_READ | mman::PROT_WRITE | mman::PROT_EXEC | mman::PROT_BTI);
        self.vmas.update(addr, end, |a| Area { prot, ..a.clone() });
        for p in self.vmas.pieces(addr, end) {
            if let Err(e) = self.install_pages(p.start, p.end, &p.value) {
                return err(e);
            }
        }
        0
    }

    pub fn brk(&mut self, brk: &mut Brk, addr: u64) -> i64 {
        if addr < brk.start || addr > brk.limit {
            return brk.current as i64;
        }
        let old_end = page_up(brk.current);
        let new_end = page_up(addr);
        if new_end > old_end {
            // Pages the break held before read as zero again.
            let dirty_end = new_end.min(self.brk_high);
            if dirty_end > old_end {
                // SAFETY: the break's own slab range, unmapped from the
                // guest since it shrank (and flushed since: a vCPU only
                // shrinks or grows it from a system call).
                unsafe {
                    std::ptr::write_bytes(old_end as *mut u8, 0, (dirty_end - old_end) as usize)
                };
            }
            let area = Area {
                prot: mman::PROT_READ | mman::PROT_WRITE,
                back: Back::Slab { host: old_end },
                source: None,
            };
            if self.install_pages(old_end, new_end, &area).is_err() {
                return brk.current as i64;
            }
            self.vmas.insert(old_end, new_end, area);
            self.brk_high = self.brk_high.max(new_end);
        } else if new_end < old_end {
            self.remove(new_end, old_end);
        }
        brk.current = addr;
        brk.current as i64
    }

    pub fn madvise(&mut self, addr: u64, len: u64, advice: u64) -> i64 {
        if addr & (PAGE - 1) != 0 {
            return err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(page_up(len)) else { return err(errno::EINVAL) };
        if advice == mman::MADV_DONTNEED {
            if !self.vmas.covered(addr, end) {
                return err(errno::ENOMEM);
            }
            // Private memory reads as zero again (or as the file, for a
            // file mapping); shared memory keeps its contents.
            for p in self.vmas.pieces(addr, end) {
                if let Back::Slab { host } = p.value.back {
                    let len = p.end - p.start;
                    // SAFETY: slab memory backing this guest mapping.
                    unsafe { std::ptr::write_bytes(host as *mut u8, 0, len as usize) };
                    if let Some(s) = &p.value.source {
                        if let Err(e) = fill(host, len, s) {
                            return err(e);
                        }
                        code_written(host, len);
                    }
                }
            }
        }
        0
    }

    pub fn msync(&mut self, addr: u64, len: u64, flags: u64) -> i64 {
        if addr & (PAGE - 1) != 0
            || (flags & fwe_abi::statfs::MS_SYNC != 0 && flags & fwe_abi::statfs::MS_ASYNC != 0)
        {
            return err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(page_up(len)) else { return err(errno::ENOMEM) };
        if !self.vmas.covered(addr, end) {
            return err(errno::ENOMEM);
        }
        for p in self.vmas.pieces(addr, end) {
            if let Back::Segment { id, off } = p.value.back {
                if let Some(s) = self.segments.get(&id) {
                    let h = s.host + off;
                    let lo = h & !((16 << 10) - 1);
                    let how = if flags & fwe_abi::statfs::MS_ASYNC != 0 {
                        libc::MS_ASYNC
                    } else {
                        libc::MS_SYNC
                    };
                    // SAFETY: part of the segment's own host mapping.
                    unsafe {
                        libc::msync(lo as *mut _, (h + (p.end - p.start) - lo) as usize, how)
                    };
                }
            }
        }
        0
    }

    pub fn mremap(&mut self, old: u64, old_len: u64, new_len: u64, flags: u64) -> i64 {
        if old & (PAGE - 1) != 0 || new_len == 0 {
            return err(errno::EINVAL);
        }
        if flags & !(mman::MREMAP_MAYMOVE) != 0 {
            // MREMAP_FIXED and MREMAP_DONTUNMAP are not supported.
            return err(errno::EINVAL);
        }
        let (old_len, new_len) = (page_up(old_len), page_up(new_len));
        let Some(old_end) = old.checked_add(old_len) else { return err(errno::EINVAL) };
        let pieces = self.vmas.pieces(old, old_end);
        if pieces.len() != 1 || pieces[0].start != old || pieces[0].end != old_end {
            return err(errno::EFAULT);
        }
        if new_len <= old_len {
            self.remove(old + new_len, old_end);
            return old as i64;
        }
        let area = pieces[0].value.clone();
        let Back::Slab { host } = area.back else { return err(errno::ENOMEM) };
        // In place, where both the guest's space and the slab behind it go on.
        let grow = new_len - old_len;
        if !self.vmas.any(old_end, old_end + grow) && window::take_fixed(host + old_len, grow) {
            let more = Area { back: Back::Slab { host: host + old_len }, source: None, ..area };
            if host != old {
                uaccess::add_translation(old_end, grow, host + old_len);
            }
            if let Err(e) = self.install_pages(old_end, old_end + grow, &more) {
                return err(e);
            }
            self.vmas.insert(old_end, old_end + grow, more);
            return old as i64;
        }
        if flags & mman::MREMAP_MAYMOVE == 0 {
            return err(errno::ENOMEM);
        }
        let to = match self.place(new_len) {
            Ok(a) => a,
            Err(e) => return err(e),
        };
        if let Err(e) = self.map_private(to, new_len, area.prot, None) {
            return err(e);
        }
        let to_host = uaccess::g2h(to);
        // SAFETY: slab memory of both mappings, distinct ranges.
        unsafe {
            std::ptr::copy_nonoverlapping(host as *const u8, to_host as *mut u8, old_len as usize)
        };
        code_written(to_host, old_len);
        self.remove(old, old_end);
        to as i64
    }
}

/// fwe wrote `[host, host + len)` of guest memory, which the guest may run
/// as code: the instruction cache is made to see it, as Apple's cores do
/// not keep it coherent with data writes (`CTR_EL0.DIC` is 0) — Linux does
/// the same when it loads code into a page. The stand-in drops its
/// translated code likewise.
pub fn code_written(host: u64, len: u64) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
    }
    // SAFETY: invalidating the instruction cache for memory of ours.
    unsafe { sys_icache_invalidate(host as *mut libc::c_void, len as usize) };
    if super::standin::active() {
        super::standin::code_written();
    }
}

/// Copy `len` bytes of `source`'s file into slab memory at `host` (short
/// of the file's end, the rest stays zero).
fn fill(host: u64, len: u64, s: &Source) -> Result<(), i32> {
    let mut done = 0u64;
    while done < len {
        // SAFETY: slab memory backing the mapping; the file is the guest's.
        let n = unsafe {
            libc::pread(
                s.file.as_raw_fd(),
                (host + done) as *mut libc::c_void,
                (len - done) as usize,
                (s.offset + done) as i64,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_errno());
        }
        if n == 0 {
            break;
        }
        done += n as u64;
    }
    Ok(())
}

/// An unlinked file of `len` bytes to back anonymous shared memory, so a
/// fork child can map the same pages.
fn anonymous_file(len: u64) -> Result<OwnedFd, i32> {
    let mut path = *b"/tmp/fwe-shared-XXXXXX\0";
    // SAFETY: a NUL-terminated template; the file is unlinked at once.
    let fd = unsafe { libc::mkstemp(path.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: the template now names the file just made.
    unsafe { libc::unlink(path.as_ptr().cast()) };
    let fd = fwe_kernel::fdtable::reserve(fd);
    // SAFETY: a descriptor just made, owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sizing the file just made.
    if unsafe { libc::ftruncate(owned.as_raw_fd(), len as i64) } != 0 {
        return Err(last_errno());
    }
    Ok(owned)
}

/// The host's last error as a Linux errno.
fn last_errno() -> i32 {
    fwe_kernel::host::errno_to_linux(fwe_kernel::host::last_errno())
}

/// Make private memory at `[addr, addr + len)` with `prot`, for the loader
/// (images, the stack, the trampoline): its host address, to fill.
pub fn map_fixed(addr: u64, len: u64, prot: u64) -> Result<u64, i32> {
    let mut g = mem();
    let m = g.as_mut().ok_or(errno::ENOMEM)?;
    let len = page_up(len);
    m.remove(addr, addr + len);
    m.map_private(addr, len, prot, None)?;
    Ok(uaccess::g2h(addr))
}

/// Place private memory of `len` bytes where the guest did not ask for an
/// address, for the loader: its guest address.
pub fn map_anywhere(len: u64, prot: u64) -> Result<u64, i32> {
    let mut g = mem();
    let m = g.as_mut().ok_or(errno::ENOMEM)?;
    let len = page_up(len);
    let at = m.place(len)?;
    m.map_private(at, len, prot, None)?;
    Ok(at)
}

/// Change the protections of loader-made memory.
pub fn protect(addr: u64, len: u64, prot: u64) -> Result<(), i32> {
    let mut g = mem();
    let m = g.as_mut().ok_or(errno::ENOMEM)?;
    let r = m.mprotect(addr, len, prot);
    if r < 0 { Err(-r as i32) } else { Ok(()) }
}

/// Reserve `len` bytes of guest space for the program break, its slab
/// range at the same address taken for it whole: nothing mapped until
/// `brk` maps it. Its start.
pub fn reserve_brk(len: u64) -> Result<u64, i32> {
    let mut g = mem();
    let m = g.as_mut().ok_or(errno::ENOMEM)?;
    let at = window::alloc(len).ok_or(errno::ENOMEM)?;
    m.brk_range = (at, at + len);
    m.brk_high = at;
    Ok(at)
}

/// Carry out a memory system call.
pub fn call(c: fwe_kernel::MemCall, brk: &mut Brk) -> i64 {
    use fwe_kernel::MemCall as C;
    let mut g = mem();
    let Some(m) = g.as_mut() else { return err(errno::ENOSYS) };
    match c {
        C::Brk { addr } => m.brk(brk, addr),
        C::Mmap { addr, len, prot, flags, fd, offset } => {
            m.mmap(addr, len, prot, flags, fd, offset)
        }
        C::Munmap { addr, len } => m.munmap(addr, len),
        C::Mprotect { addr, len, prot } => m.mprotect(addr, len, prot),
        C::Madvise { addr, len, advice } => m.madvise(addr, len, advice),
        C::Msync { addr, len, flags } => m.msync(addr, len, flags),
        C::Mremap { old, old_len, new_len, flags, .. } => m.mremap(old, old_len, new_len, flags),
    }
}

// --- Handing memory to a fork child -----------------------------------------

use fwe_kernel::snapshot::{Dec, Enc};

impl Mem {
    /// The records a fork child needs (not the memory's contents, which go
    /// separately). File descriptors are written as numbers: the child is
    /// given the same descriptors.
    pub fn save(&self, e: &mut Enc) {
        let pieces: Vec<Piece<&Area>> = self.vmas.iter().collect();
        e.u64(pieces.len() as u64);
        for p in pieces {
            e.u64(p.start);
            e.u64(p.end);
            e.u64(p.value.prot);
            match p.value.back {
                Back::Slab { host } => {
                    e.u8(0);
                    e.u64(host);
                }
                Back::Segment { id, off } => {
                    e.u8(1);
                    e.u64(id);
                    e.u64(off);
                }
            }
            match &p.value.source {
                Some(s) => {
                    e.bool(true);
                    e.i32(s.file.as_raw_fd());
                    e.u64(s.offset);
                }
                None => e.bool(false),
            }
        }
        // Segments still mapped (ones waiting to go are not handed on).
        let live: Vec<(&u64, &Segment)> =
            self.segments.iter().filter(|(_, s)| s.refs > 0).collect();
        e.u64(live.len() as u64);
        for (&id, s) in live {
            e.u64(id);
            e.u64(s.len);
            e.u64(s.ipa);
            e.i32(s.file.as_raw_fd());
            e.u64(s.file_offset);
            e.u64(s.refs);
        }
        e.u64(self.next_segment);
        e.u64(self.brk_range.0);
        e.u64(self.brk_range.1);
        e.u64(self.brk_high);
    }

    /// The records a fork parent saved; segments are mapped again by
    /// [`Mem::rebuild`].
    pub fn load(d: &mut Dec) -> Mem {
        let mut files: BTreeMap<i32, Arc<OwnedFd>> = BTreeMap::new();
        let mut file = |fd: i32| {
            // SAFETY: a descriptor the parent handed on, owned here.
            files.entry(fd).or_insert_with(|| Arc::new(unsafe { OwnedFd::from_raw_fd(fd) })).clone()
        };
        let mut m = Mem::default();
        for _ in 0..d.count(33) {
            let (start, end, prot) = (d.u64(), d.u64(), d.u64());
            let back = if d.u8() == 0 {
                Back::Slab { host: d.u64() }
            } else {
                Back::Segment { id: d.u64(), off: d.u64() }
            };
            let source = d.bool().then(|| {
                let fd = d.i32();
                Source { file: file(fd), offset: d.u64() }
            });
            m.vmas.insert(start, end, Area { prot, back, source });
        }
        for _ in 0..d.count(44) {
            let (id, len, ipa) = (d.u64(), d.u64(), d.u64());
            let f = file(d.i32());
            let (file_offset, refs) = (d.u64(), d.u64());
            m.segments.insert(id, Segment { host: 0, len, ipa, file: f, file_offset, refs });
        }
        m.next_segment = d.u64();
        m.brk_range = (d.u64(), d.u64());
        m.brk_high = d.u64();
        m
    }

    /// In a fork child with its VM made: map the segments again (each at
    /// its parent's IPA, its host mapping wherever it lands, translations
    /// following), then fill the page tables — every mapping, or for a
    /// `vfork` child (`lazy`) only the shared ones: its private pages are
    /// fetched from the parent as it touches them ([`demand`]).
    pub fn rebuild(&mut self, lazy: bool) -> Result<(), String> {
        for s in self.segments.values_mut() {
            // SAFETY: a fresh shared mapping of the segment's file.
            let host = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    s.len as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    s.file.as_raw_fd(),
                    s.file_offset as i64,
                )
            };
            if host == libc::MAP_FAILED {
                return Err(format!(
                    "mapping a shared segment failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            s.host = host as u64;
            vm::map_segment_at(s.host, s.len, s.ipa)
                .map_err(|e| format!("mapping a segment into the VM: errno {e}"))?;
        }
        let pieces: Vec<Piece<Area>> = self
            .vmas
            .iter()
            .map(|p| Piece { start: p.start, end: p.end, value: p.value.clone() })
            .collect();
        for p in &pieces {
            if let Back::Segment { id, off } = p.value.back {
                if let Some(s) = self.segments.get(&id) {
                    uaccess::add_translation(p.start, p.end - p.start, s.host + off);
                }
            }
            if lazy && matches!(p.value.back, Back::Slab { .. }) {
                continue;
            }
            self.install_pages(p.start, p.end, &p.value)
                .map_err(|e| format!("mapping {:#x}+{:#x}: errno {e}", p.start, p.end - p.start))?;
        }
        Ok(())
    }
}

// --- A vfork child's memory ---------------------------------------------------

/// Bytes a `vfork` child fetches from its parent at a time.
pub const CHUNK: u64 = 64 << 10;

/// What a `vfork` child fetched, and the channel to its parent.
struct Lazy {
    sock: i32,
    /// Each fetched chunk's contents as fetched, to send back what changed.
    fetched: BTreeMap<u64, Box<[u8]>>,
}

static LAZY: Mutex<Option<Lazy>> = Mutex::new(None);

/// This process is a `vfork` child that fetches its parent's private memory
/// over `sock` as it needs it.
pub fn start_lazy(sock: i32) {
    *LAZY.lock().unwrap_or_else(|e| e.into_inner()) = Some(Lazy { sock, fetched: BTreeMap::new() });
}

/// Requests a `vfork` child sends its parent.
pub const FETCH: u8 = 1;
pub const WRITE: u8 = 2;
pub const DONE: u8 = 3;

fn send_all(fd: i32, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: writing our buffer to our socket.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
}

pub fn recv_all(fd: i32, buf: &mut [u8]) -> bool {
    let mut at = 0;
    while at < buf.len() {
        // SAFETY: reading into our buffer from our socket.
        let n = unsafe { libc::read(fd, buf[at..].as_mut_ptr().cast(), buf.len() - at) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        at += n as usize;
    }
    true
}

/// In a `vfork` child: fetch every chunk of slab memory behind guest range
/// `[addr, addr + len)` not fetched yet, and map the guest pages those
/// chunks back. True if private memory of the range is now mapped.
fn fetch_range(m: &Mem, addr: u64, len: u64) -> bool {
    let (lo, hi) = (addr & !(PAGE - 1), page_up(addr.saturating_add(len.max(1))));
    let mut lazy = LAZY.lock().unwrap_or_else(|e| e.into_inner());
    let Some(lz) = lazy.as_mut() else { return false };
    // The guest pages to map: the parts of each private mapping whose slab
    // memory the chunks hold.
    let mut install = Vec::new();
    for p in m.vmas.pieces(lo, hi) {
        let Back::Slab { host } = p.value.back else { continue };
        let (h_lo, h_hi) = (host, host + (p.end - p.start));
        let (c_lo, c_hi) = (h_lo & !(CHUNK - 1), (h_hi + CHUNK - 1) & !(CHUNK - 1));
        let mut chunk = c_lo;
        while chunk < c_hi {
            if !lz.fetched.contains_key(&chunk) {
                let mut req = [0u8; 17];
                req[0] = FETCH;
                req[1..9].copy_from_slice(&chunk.to_le_bytes());
                req[9..17].copy_from_slice(&CHUNK.to_le_bytes());
                let mut data = vec![0u8; CHUNK as usize].into_boxed_slice();
                if !send_all(lz.sock, &req) || !recv_all(lz.sock, &mut data) {
                    return false;
                }
                // SAFETY: the child's own slab memory at the parent's
                // address, not yet touched by the child.
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), chunk as *mut u8, CHUNK as usize)
                };
                code_written(chunk, CHUNK);
                lz.fetched.insert(chunk, data);
            }
            chunk += CHUNK;
        }
        // The whole mapping piece within the chunks: `p` starts at `lo`
        // or later, its own start is where its slab memory is `host`.
        let whole = m.vmas.get(p.start).map(|w| (w.start, w.end, w.value.clone()));
        if let Some((ws, we, wv)) = whole {
            let Back::Slab { host: wh } = wv.back else { continue };
            let va_lo = ws + c_lo.saturating_sub(wh);
            let va_hi = (ws + (c_hi - wh)).min(we);
            let va_lo = va_lo.max(ws);
            install.push((va_lo, va_hi, wv.at(va_lo - ws)));
        }
    }
    drop(lazy);
    let mut ok = !install.is_empty();
    for (a, b, area) in install {
        ok &= m.install_pages(a, b, &area).is_ok();
    }
    ok
}

/// A guest access at `va` faulted for lack of a translation: in a `vfork`
/// child, fetch what is missing and map it. True if the access can be
/// tried again.
pub fn demand(va: u64) -> bool {
    let g = mem();
    let Some(m) = g.as_ref() else { return false };
    if m.vmas.get(va).is_none() {
        return false;
    }
    fetch_range(m, va, 1)
}

/// The kernel is about to touch guest range `[addr, addr + len)`: in a
/// `vfork` child, fetch what of it is missing first.
pub fn prepare_access(addr: u64, len: u64) {
    if LAZY.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
        return;
    }
    let addr = guest_of(addr, len);
    let g = mem();
    if let Some(m) = g.as_ref() {
        fetch_range(m, addr, len);
    }
}

/// In a `vfork` child about to exec or end: send the parent every byte it
/// changed in the memory it fetched, and wait until the parent has them.
pub fn finish_lazy() {
    let Some(lz) = LAZY.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
    for (&chunk, orig) in &lz.fetched {
        // SAFETY: the child's own slab memory, fetched from the parent.
        let now = unsafe { std::slice::from_raw_parts(chunk as *const u8, CHUNK as usize) };
        let mut i = 0;
        while i < now.len() {
            if now[i] == orig[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i < now.len() && now[i] != orig[i] {
                i += 1;
            }
            let mut msg = Vec::with_capacity(17 + i - start);
            msg.push(WRITE);
            msg.extend_from_slice(&(chunk + start as u64).to_le_bytes());
            msg.extend_from_slice(&((i - start) as u64).to_le_bytes());
            msg.extend_from_slice(&now[start..i]);
            if !send_all(lz.sock, &msg) {
                return;
            }
        }
    }
    let mut ack = [0u8; 1];
    if send_all(lz.sock, &[DONE]) {
        recv_all(lz.sock, &mut ack);
    }
    // SAFETY: closing our end of the channel.
    unsafe { libc::close(lz.sock) };
}

/// In a `vfork` parent: serve the child's requests on `sock` until it has
/// sent back its changes (or gone). Requests are confined to the slab.
pub fn serve_vfork_child(sock: i32) {
    loop {
        let mut op = [0u8; 1];
        if !recv_all(sock, &mut op) {
            return;
        }
        if op[0] == DONE {
            send_all(sock, &[1]);
            return;
        }
        let mut hdr = [0u8; 16];
        if !recv_all(sock, &mut hdr) {
            return;
        }
        let addr = u64::from_le_bytes(hdr[..8].try_into().unwrap());
        let len = u64::from_le_bytes(hdr[8..].try_into().unwrap());
        if !window::contains(addr, len) || len > CHUNK {
            return;
        }
        match op[0] {
            FETCH => {
                // SAFETY: the parent's own slab memory, always readable.
                let data = unsafe { std::slice::from_raw_parts(addr as *const u8, len as usize) };
                if !send_all(sock, data) {
                    return;
                }
            }
            WRITE => {
                let mut data = vec![0u8; len as usize];
                if !recv_all(sock, &mut data) {
                    return;
                }
                // SAFETY: the parent's own slab memory, as the vfork child
                // (sharing it, on Linux) wrote it.
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len())
                };
                code_written(addr, len);
            }
            _ => return,
        }
    }
}
