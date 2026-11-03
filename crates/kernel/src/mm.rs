//! Memory management system calls.

use crate::host::{last_error, ret};
use crate::{Kernel, Platform};
use fwe_abi::{err, errno, mman};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The program break: a reserved region after the executable image that
/// `brk` commits and releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brk {
    pub start: u64,
    pub current: u64,
    /// End of the reservation; the break cannot grow past it.
    pub limit: u64,
}

/// Every range of address space that belongs to the guest program: its
/// images, stack, break, code stubs and everything it maps. `execve` unmaps
/// them all before loading the new program, as Linux discards the old
/// address space; fwe's own memory is never in the set.
static GUEST_MAPS: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn guest_maps() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    GUEST_MAPS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record `[addr, addr + len)` as guest memory.
pub fn track(addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    let mut maps = guest_maps();
    let (mut start, mut end) = (addr, addr.saturating_add(len));
    // Absorb every range that overlaps or touches the new one.
    let touching: Vec<(u64, u64)> =
        maps.range(..=end).rev().take_while(|&(_, &e)| e >= start).map(|(&s, &e)| (s, e)).collect();
    for (s, e) in touching {
        maps.remove(&s);
        start = start.min(s);
        end = end.max(e);
    }
    maps.insert(start, end);
}

/// Forget `[addr, addr + len)` (the guest unmapped it).
pub fn untrack(addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    let mut maps = guest_maps();
    let end = addr.saturating_add(len);
    let overlapping: Vec<(u64, u64)> =
        maps.range(..end).rev().take_while(|&(_, &e)| e > addr).map(|(&s, &e)| (s, e)).collect();
    for (s, e) in overlapping {
        maps.remove(&s);
        if s < addr {
            maps.insert(s, addr);
        }
        if e > end {
            maps.insert(end, e);
        }
    }
}

/// The guest memory ranges, in address order.
pub fn tracked() -> Vec<(u64, u64)> {
    guest_maps().iter().map(|(&s, &e)| (s, e - s)).collect()
}

/// Unmap all guest memory (the old program, at `execve`).
pub fn release_guest_memory() {
    let ranges = std::mem::take(&mut *guest_maps());
    for (start, end) in ranges {
        // SAFETY: only guest memory is tracked, and the old program is
        // discarded; fwe runs on its own stacks.
        unsafe { libc::munmap(start as *mut libc::c_void, (end - start) as usize) };
    }
}

/// Run `f` holding the tracking lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = guest_maps();
    f()
}

impl Brk {
    /// Default size of the reservation.
    pub const RESERVATION: u64 = 1 << 30;

    /// Reserve `size` bytes of address space at page-aligned `start`.
    ///
    /// If the range is not available the break cannot grow; allocators then
    /// fall back to `mmap`, as they do on Linux when `brk` fails.
    pub fn reserve(start: u64, size: u64) -> Brk {
        match crate::host::reserve_fixed(start, size) {
            Ok(()) => {
                track(start, size);
                Brk { start, current: start, limit: start + size }
            }
            Err(_) => Brk { start, current: start, limit: start },
        }
    }
}

/// Map anonymous memory at a fixed address, replacing what is there.
fn map_fixed_anon(addr: u64, len: u64, prot: libc::c_int) -> bool {
    // SAFETY: callers only pass ranges owned by the guest.
    let p = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    p != libc::MAP_FAILED
}

/// `MADV_DONTNEED` on a Linux host is the real thing.
#[cfg(not(target_os = "macos"))]
fn dontneed(addr: u64, len: u64) -> i64 {
    // SAFETY: advisory call on guest memory.
    ret(unsafe { libc::madvise(addr as *mut libc::c_void, len as usize, libc::MADV_DONTNEED) })
}

/// `MADV_DONTNEED`: Linux zero-fills private anonymous pages on their next
/// touch, and drops shared or file-backed pages to be refilled from their
/// backing. macOS's own `MADV_DONTNEED` keeps the contents, so each private
/// anonymous piece of the range is replaced with a fresh mapping of the same
/// protection. Memory with other backing is left alone: replacing it would
/// sever the sharing or the file, and host `MADV_FREE` could lose shared data.
/// (A private file mapping therefore keeps its modified pages, where Linux
/// would restore the file's.) A hole in the range is `ENOMEM`, as on Linux,
/// after the mapped pieces are handled.
#[cfg(target_os = "macos")]
fn dontneed(addr: u64, len: u64) -> i64 {
    let end = addr + len;
    let mut at = addr;
    let mut hole = false;
    while at < end {
        let Some(r) = region::query(at) else {
            hole = true;
            break;
        };
        if r.start >= end {
            hole = true;
            break;
        }
        if r.start > at {
            hole = true;
        }
        let piece = (r.start.max(at), (r.start + r.size).min(end));
        if r.private_anonymous() {
            let prot = r.protection & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
            if !map_fixed_anon(piece.0, piece.1 - piece.0, prot) {
                return last_error();
            }
        }
        at = piece.1;
    }
    if hole { err(errno::ENOMEM) } else { 0 }
}

/// What backs a range of the host address space, from Mach.
#[cfg(target_os = "macos")]
mod region {
    use std::os::raw::{c_int, c_uchar, c_uint, c_ushort};

    /// `vm_region_basic_info_64`.
    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy)]
    struct BasicInfo {
        protection: c_int,
        max_protection: c_int,
        inheritance: c_uint,
        shared: c_uint,
        reserved: c_uint,
        offset: u64,
        behavior: c_int,
        user_wired_count: c_ushort,
    }

    /// `vm_region_extended_info`.
    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy)]
    struct ExtendedInfo {
        protection: c_int,
        user_tag: c_uint,
        pages_resident: c_uint,
        pages_shared_now_private: c_uint,
        pages_swapped_out: c_uint,
        pages_dirtied: c_uint,
        ref_count: c_uint,
        shadow_depth: c_ushort,
        external_pager: c_uchar,
        share_mode: c_uchar,
        pages_reusable: c_uint,
    }

    const VM_REGION_BASIC_INFO_64: c_int = 9;
    const VM_REGION_EXTENDED_INFO: c_int = 13;
    /// `VM_INHERIT_COPY`: what a `MAP_PRIVATE` mapping gets; `MAP_SHARED`
    /// mappings inherit by sharing (`VM_INHERIT_SHARE`, 0).
    const VM_INHERIT_COPY: c_uint = 1;

    unsafe extern "C" {
        /// This task's port (`mach_task_self()` is a macro over it).
        static mach_task_self_: libc::mach_port_t;
        fn mach_vm_region(
            task: libc::mach_port_t,
            address: *mut u64,
            size: *mut u64,
            flavor: c_int,
            info: *mut c_int,
            count: *mut u32,
            object_name: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
    }

    /// One query for `flavor` at `addr`, into a `T`-shaped info record.
    fn query_flavor<T: Default>(addr: u64, flavor: c_int) -> Option<(u64, u64, T)> {
        let mut start = addr;
        let mut size = 0u64;
        let mut info = T::default();
        let mut count = (size_of::<T>() / size_of::<c_int>()) as u32;
        let mut name: libc::mach_port_t = 0;
        // SAFETY: querying this task's own address space with valid
        // out-parameters; `count` bounds what the kernel writes into `info`.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut start,
                &mut size,
                flavor,
                (&mut info as *mut T).cast(),
                &mut count,
                &mut name,
            )
        };
        (kr == 0).then_some((start, size, info))
    }

    /// The region containing `addr`, or the next one above it.
    #[derive(Debug, Clone, Copy)]
    pub struct Region {
        pub start: u64,
        pub size: u64,
        pub protection: c_int,
        /// A file (an external pager) backs the region.
        file_backed: bool,
        /// The mapping is `MAP_PRIVATE` (inherits by copy). A `MAP_SHARED`
        /// anonymous mapping with a single reference looks private in every
        /// other respect, so this is what tells them apart.
        private: bool,
    }

    impl Region {
        /// Private anonymous memory: what Linux zero-fills on `MADV_DONTNEED`.
        pub fn private_anonymous(&self) -> bool {
            self.private && !self.file_backed
        }
    }

    pub fn query(addr: u64) -> Option<Region> {
        let (start, size, basic) = query_flavor::<BasicInfo>(addr, VM_REGION_BASIC_INFO_64)?;
        let (_, _, ext) = query_flavor::<ExtendedInfo>(start, VM_REGION_EXTENDED_INFO)?;
        Some(Region {
            start,
            size,
            protection: basic.protection,
            file_backed: ext.external_pager != 0,
            private: basic.inheritance == VM_INHERIT_COPY,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn map(len: usize, prot: libc::c_int, flags: libc::c_int) -> u64 {
        // SAFETY: a fresh anonymous mapping for the test.
        let p =
            unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags | libc::MAP_ANON, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        p as u64
    }

    /// Private anonymous memory reads back as zero after `MADV_DONTNEED`;
    /// shared memory keeps its contents; protections are preserved.
    #[test]
    fn tracking_merges_and_splits_ranges() {
        // Far from anything the tests map, so concurrent tests do not
        // interfere with the ranges checked here.
        let base = 0x7a00_0000_0000;
        let here = |t: Vec<(u64, u64)>| -> Vec<(u64, u64)> {
            t.into_iter().filter(|&(s, _)| (base..base + 0x10_0000).contains(&s)).collect()
        };
        track(base, 0x4000);
        track(base + 0x4000, 0x4000);
        track(base + 0x10000, 0x4000);
        assert_eq!(here(tracked()), vec![(base, 0x8000), (base + 0x10000, 0x4000)]);
        untrack(base + 0x2000, 0x1000);
        assert_eq!(
            here(tracked()),
            vec![(base, 0x2000), (base + 0x3000, 0x5000), (base + 0x10000, 0x4000)]
        );
        untrack(base, 0x20000);
        assert_eq!(here(tracked()), vec![]);
    }

    #[test]
    fn dontneed_zero_fills_private_and_keeps_shared() {
        let len = 1 << 16;
        let private = map(len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE);
        let shared = map(len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        let none = map(len, libc::PROT_NONE, libc::MAP_PRIVATE);
        // SAFETY: writing inside the mappings just made.
        unsafe {
            (private as *mut u8).write(0xaa);
            (shared as *mut u8).write(0xbb);
        }
        assert_eq!(dontneed(private, len as u64), 0);
        assert_eq!(dontneed(shared, len as u64), 0);
        assert_eq!(dontneed(none, len as u64), 0);
        // SAFETY: reading inside the mappings.
        unsafe {
            assert_eq!((private as *const u8).read(), 0);
            assert_eq!((shared as *const u8).read(), 0xbb);
        }
        let r = region::query(none).unwrap();
        assert_eq!(r.protection & 7, 0, "PROT_NONE must survive");
        // A hole in the range is ENOMEM.
        // SAFETY: unmapping the test's own mapping.
        unsafe { libc::munmap(none as *mut _, len) };
        assert_eq!(dontneed(none, len as u64), err(errno::ENOMEM));
        // SAFETY: unmapping the test's own mappings.
        unsafe {
            libc::munmap(private as *mut _, len);
            libc::munmap(shared as *mut _, len);
        }
    }
}

/// Largest backing file read to find its executable sections.
const MAX_EXEC_FILE: usize = 128 << 20;

/// The executable sections of the ELF file open at `fd`, as file-offset
/// ranges, or `None` if it is not a readable regular ELF with section headers
/// (then the caller translates the whole mapped region instead). Reads with
/// `pread`, so the guest's file position is untouched.
fn exec_file_ranges(fd: i32) -> Option<Vec<(u64, u64)>> {
    if fd < 0 {
        return None;
    }
    // SAFETY: zeroing a stat value, which is plain data.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fstat on a borrowed fd, writing into the stat just created.
    let fstat_ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    if !fstat_ok || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let size = st.st_size as usize;
    if !(64..=MAX_EXEC_FILE).contains(&size) {
        return None;
    }
    let mut buf = vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        // SAFETY: pread into the owned buffer at an explicit offset.
        let n = unsafe {
            libc::pread(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                size - done,
                done as libc::off_t,
            )
        };
        if n <= 0 {
            return None;
        }
        done += n as usize;
    }
    fwe_elf::Elf::parse(&buf).ok()?.exec_file_ranges()
}

fn host_prot(prot: u64) -> libc::c_int {
    let mut p = libc::PROT_NONE;
    if prot & mman::PROT_READ != 0 {
        p |= libc::PROT_READ;
    }
    if prot & mman::PROT_WRITE != 0 {
        p |= libc::PROT_WRITE;
    }
    if prot & mman::PROT_EXEC != 0 {
        p |= libc::PROT_EXEC;
    }
    p
}

impl<P: Platform> Kernel<P> {
    fn page_up(&self, a: u64) -> u64 {
        (a + self.page_size - 1) & !(self.page_size - 1)
    }

    pub(crate) fn sys_brk(&mut self, addr: u64) -> i64 {
        let b = self.brk;
        if addr < b.start || addr > b.limit {
            return b.current as i64;
        }
        let old_end = self.page_up(b.current);
        let new_end = self.page_up(addr);
        let rw = mman::PROT_READ | mman::PROT_WRITE;
        let ok = if new_end > old_end {
            map_fixed_anon(old_end, new_end - old_end, libc::PROT_READ | libc::PROT_WRITE)
                && self.platform.map_guest(old_end, new_end - old_end, rw).is_ok()
        } else if new_end < old_end {
            // Released pages must read as zero if the break grows again.
            self.platform.unmap_guest(new_end, old_end - new_end);
            map_fixed_anon(new_end, old_end - new_end, libc::PROT_NONE)
        } else {
            true
        };
        if ok {
            self.brk.current = addr;
        }
        self.brk.current as i64
    }

    pub(crate) fn sys_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> i64 {
        if len == 0 || offset & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let anonymous = flags & mman::MAP_ANONYMOUS != 0;
        let mut hflags = match flags & mman::MAP_TYPE {
            mman::MAP_SHARED | mman::MAP_SHARED_VALIDATE => libc::MAP_SHARED,
            mman::MAP_PRIVATE => libc::MAP_PRIVATE,
            _ => return err(errno::EINVAL),
        };
        if anonymous {
            hflags |= libc::MAP_ANON;
        }
        if flags & mman::MAP_FIXED != 0 {
            hflags |= libc::MAP_FIXED;
        }
        if flags & mman::MAP_NORESERVE != 0 {
            hflags |= libc::MAP_NORESERVE;
        }
        let noreplace = flags & mman::MAP_FIXED_NOREPLACE != 0 && flags & mman::MAP_FIXED == 0;

        // Executable mappings are created writable so the backend can prepare
        // the code, then switched to the requested protections. Shared file
        // mappings are made private for this, since the code is modified.
        let exec = prot & mman::PROT_EXEC != 0;
        let initial_prot = if exec {
            if hflags & libc::MAP_SHARED != 0 && !anonymous {
                hflags = (hflags & !libc::MAP_SHARED) | libc::MAP_PRIVATE;
            }
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            host_prot(prot)
        };

        let host_fd = if anonymous { -1 } else { fd as i32 };
        // SAFETY: guest-requested mapping. MAP_FIXED may replace guest memory,
        // which is the guest's own business, exactly as on Linux.
        let p = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                initial_prot,
                hflags,
                host_fd,
                offset as libc::off_t,
            )
        };
        if p == libc::MAP_FAILED {
            return last_error();
        }
        let p = p as u64;
        if noreplace && p != addr {
            // SAFETY: unmapping the mapping just created.
            unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
            return err(errno::EEXIST);
        }
        track(p, self.page_up(len));
        if let Err(e) = self.platform.map_guest(p, self.page_up(len), prot) {
            // SAFETY: unmapping the mapping just created.
            unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
            untrack(p, self.page_up(len));
            return err(e);
        }
        if exec {
            // Translate the code. For a file-backed mapping, confine the
            // rewrite to the file's executable sections, so data mapped into
            // the same region — the symbol, string and hash tables that a
            // shared library's code segment can hold, as glibc's `libc.so.6`
            // does — is left untouched. Without section headers, or for an
            // anonymous mapping, the whole region is translated as before.
            let prep = match if anonymous { None } else { exec_file_ranges(host_fd) } {
                Some(sections) => sections
                    .into_iter()
                    .filter_map(|(foff, fsize)| {
                        let start = foff.max(offset);
                        let end = (foff + fsize).min(offset + len);
                        (start < end).then_some((p + (start - offset), end - start))
                    })
                    .collect(),
                None => vec![(p, self.page_up(len))],
            };
            for (a, l) in prep {
                if let Err(e) = self.platform.prepare_exec(a, l) {
                    // SAFETY: unmapping the mapping just created.
                    unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
                    untrack(p, self.page_up(len));
                    return err(e);
                }
            }
            // SAFETY: changing protections of the mapping just created.
            if unsafe { libc::mprotect(p as *mut libc::c_void, len as usize, host_prot(prot)) } != 0
            {
                let e = last_error();
                // SAFETY: unmapping the mapping just created.
                unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
                untrack(p, self.page_up(len));
                return e;
            }
        }
        p as i64
    }

    pub(crate) fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        let host = crate::uaccess::g2h(addr) as *mut libc::c_void;
        // SAFETY: guest-requested unmapping of guest memory.
        let r = ret(unsafe { libc::munmap(host, len as usize) });
        if r == 0 {
            untrack(addr, self.page_up(len));
            self.platform.unmap_guest(addr, self.page_up(len));
        }
        r
    }

    pub(crate) fn sys_mprotect(&mut self, addr: u64, len: u64, prot: u64) -> i64 {
        let a = crate::uaccess::g2h(addr) as *mut libc::c_void;
        if prot & mman::PROT_EXEC != 0 {
            // SAFETY: guest-requested protection change of guest memory.
            if unsafe { libc::mprotect(a, len as usize, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
                return last_error();
            }
            if let Err(e) = self.platform.prepare_exec(addr, self.page_up(len)) {
                return err(e);
            }
        }
        // SAFETY: guest-requested protection change of guest memory.
        let r = ret(unsafe { libc::mprotect(a, len as usize, host_prot(prot)) });
        if r == 0 {
            self.platform.protect_guest(addr, self.page_up(len), prot);
        }
        r
    }

    pub(crate) fn sys_madvise(&mut self, addr: u64, len: u64, advice: u64) -> i64 {
        if addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let len = self.page_up(len);
        let host = crate::uaccess::g2h(addr);
        match advice {
            mman::MADV_DONTNEED => {
                let r = dontneed(host, len);
                if r == 0 {
                    // The host memory behind the range was replaced.
                    self.platform.remapped_guest(addr, len);
                }
                r
            }
            mman::MADV_FREE => {
                // SAFETY: advisory call on guest memory.
                unsafe { libc::madvise(host as *mut libc::c_void, len as usize, libc::MADV_FREE) };
                0
            }
            mman::MADV_NORMAL | mman::MADV_RANDOM | mman::MADV_SEQUENTIAL | mman::MADV_WILLNEED => {
                // SAFETY: advisory call on guest memory; values match the host's.
                ret(unsafe {
                    libc::madvise(host as *mut libc::c_void, len as usize, advice as libc::c_int)
                })
            }
            // Other advice (huge pages, dump control, ...) has no host
            // equivalent and no effect on program semantics.
            _ => 0,
        }
    }

    pub(crate) fn sys_mremap(&mut self, old: u64, old_len: u64, new_len: u64, flags: u64) -> i64 {
        if old & (self.page_size - 1) != 0 || new_len == 0 {
            return err(errno::EINVAL);
        }
        let old_len = self.page_up(old_len);
        let new_len = self.page_up(new_len);
        if new_len <= old_len {
            if new_len < old_len {
                let tail = crate::uaccess::g2h(old + new_len);
                // SAFETY: unmapping the tail of a guest mapping.
                unsafe { libc::munmap(tail as *mut libc::c_void, (old_len - new_len) as usize) };
                untrack(old + new_len, old_len - new_len);
                self.platform.unmap_guest(old + new_len, old_len - new_len);
            }
            return old as i64;
        }
        if flags & mman::MREMAP_MAYMOVE == 0 {
            // Cannot grow in place yet. Like Linux, report EFAULT for an
            // unmapped source range and ENOMEM otherwise.
            // SAFETY: msync only inspects the mapping state of the range.
            let mapped =
                unsafe { libc::msync(old as *mut libc::c_void, old_len as usize, libc::MS_ASYNC) }
                    == 0;
            return err(if mapped { errno::ENOMEM } else { errno::EFAULT });
        }
        err(errno::ENOMEM)
    }
}
