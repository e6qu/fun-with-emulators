//! Memory management system calls.

use crate::host::{last_error, ret};
use crate::{Kernel, MemCall, Platform};
use fwe_abi::{err, errno, mman};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
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

/// Every range of guest memory, `start -> end`.
pub fn guest_ranges() -> BTreeMap<u64, u64> {
    guest_maps().clone()
}

/// Take the guest memory ranges of the parent, in a fork child that has
/// mapped them.
pub fn set_guest_ranges(ranges: BTreeMap<u64, u64>) {
    *guest_maps() = ranges;
}

/// Record `[addr, addr + len)` as guest memory.
pub fn track(addr: u64, len: u64) {
    add_range(&mut guest_maps(), addr, len);
}

/// Forget `[addr, addr + len)` (the guest unmapped it).
pub fn untrack(addr: u64, len: u64) {
    remove_range(&mut guest_maps(), addr, len);
}

/// Add `[addr, addr + len)` to a set of ranges `start -> end`, merging it
/// with every range it overlaps or touches.
fn add_range(maps: &mut BTreeMap<u64, u64>, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
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

/// Remove `[addr, addr + len)` from a set of ranges, splitting any range it
/// covers part of.
fn remove_range(maps: &mut BTreeMap<u64, u64>, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
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

/// `MAP_GROWSDOWN` mappings, guest start to end: a fault in the space
/// just below one grows it down ([`Kernel::stack_fault`]; the native
/// backend's, whose guest addresses are host addresses).
static GROWS_DOWN: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn grows_down() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    GROWS_DOWN.lock().unwrap_or_else(|e| e.into_inner())
}

/// Guest ranges `MADV_HWPOISON` poisoned: inaccessible, and an access to
/// them is a `SIGBUS` ([`poisoned`]), as Linux reports a memory failure.
static POISONED: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn poisoned_ranges() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    POISONED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether guest address `addr` is in memory `MADV_HWPOISON` poisoned.
pub fn poisoned(addr: u64) -> bool {
    poisoned_ranges().range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
}

/// Guest ranges given `MADV_DONTDUMP` (until `MADV_DODUMP`): left out of
/// a core dump ([`dont_dump`]).
static DONT_DUMP: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn dont_dump_ranges() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    DONT_DUMP.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether guest address `addr` is in memory given `MADV_DONTDUMP`.
pub fn dont_dump(addr: u64) -> bool {
    dont_dump_ranges().range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
}

/// Host ranges given `MADV_WIPEONFORK`: a fork child finds them zero
/// ([`forked_child`]), and so does its own child.
static WIPE_ON_FORK: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn wipe_on_fork() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    WIPE_ON_FORK.lock().unwrap_or_else(|e| e.into_inner())
}

/// In a fork child: the ranges given `MADV_WIPEONFORK` are zero, as Linux
/// gives the child new memory there. They are zeroed in place, the
/// mappings left as they are (a backend may map the memory itself),
/// writable for the moment if they are not.
pub fn forked_child() {
    // Kept as start and end.
    let ranges: Vec<(u64, u64)> = wipe_on_fork().iter().map(|(&a, &e)| (a, e - a)).collect();
    for (addr, len) in ranges {
        let prot = region_prot(addr);
        // SAFETY: memory of the process's own that it mapped, made
        // writable for the zeroing and given back its protection.
        unsafe {
            let p = addr as *mut libc::c_void;
            if prot & libc::PROT_WRITE == 0 {
                libc::mprotect(p, len as usize, libc::PROT_READ | libc::PROT_WRITE);
            }
            std::ptr::write_bytes(addr as *mut u8, 0, len as usize);
            if prot & libc::PROT_WRITE == 0 {
                libc::mprotect(p, len as usize, prot);
            }
        }
    }
}

/// The host protection of the memory at host address `addr`.
/// The host's page size.
pub fn host_page_size() -> u64 {
    // SAFETY: sysconf only reads a system value.
    (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as u64
}

/// The host protection of the memory at host address `addr`.
pub fn host_prot_at(addr: u64) -> libc::c_int {
    region_prot(addr)
}

fn region_prot(addr: u64) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        region::query(addr).map_or(libc::PROT_READ | libc::PROT_WRITE, |r| r.protection)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = addr;
        libc::PROT_READ | libc::PROT_WRITE
    }
}

/// Guest memory the guest mapped both writable and executable, host
/// addresses `start -> end`. macOS never maps memory so, so the host keeps
/// these writable only: in the hypervisor backend the VM alone executes
/// them, and the native backend makes a page executable when the guest runs
/// code in it and writable again when it writes there
/// ([`Kernel::write_exec_fault`]), as a JIT compiler expects of such memory.
static WRITE_EXEC: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn write_exec() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    WRITE_EXEC.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether host address `addr` is in writable and executable guest memory.
fn is_write_exec(addr: u64) -> bool {
    write_exec().range(..=addr).next_back().is_some_and(|(_, &end)| addr < end)
}

/// If host address `addr` is in writable and executable guest memory, make
/// its page (of `page_size` bytes) writable, and report whether it was. Takes
/// no kernel lock, so fwe's own code may use it when a write it makes for the
/// guest faults.
pub fn write_exec_writable(addr: u64, page_size: u64) -> bool {
    if !is_write_exec(addr) {
        return false;
    }
    let page = addr & !(page_size - 1);
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    // SAFETY: a page of guest memory the guest mapped writable and
    // executable; only its host protections change.
    unsafe { libc::mprotect(page as *mut libc::c_void, page_size as usize, rw) == 0 }
}

/// Both `PROT_WRITE` and `PROT_EXEC`.
fn wants_write_exec(prot: u64) -> bool {
    prot & (mman::PROT_WRITE | mman::PROT_EXEC) == mman::PROT_WRITE | mman::PROT_EXEC
}

/// Unmap all guest memory (the old program, at `execve`).
pub fn release_guest_memory() {
    write_exec().clear();
    wipe_on_fork().clear();
    grows_down().clear();
    poisoned_ranges().clear();
    dont_dump_ranges().clear();
    crate::maps::clear();
    let ranges = std::mem::take(&mut *guest_maps());
    for (start, end) in ranges {
        // SAFETY: only guest memory is tracked, and the old program is
        // discarded; fwe runs on its own stacks.
        unsafe { libc::munmap(start as *mut libc::c_void, (end - start) as usize) };
    }
}

/// The memory fwe mapped for the guest, as `(start, end, Linux prot)` by
/// the host's protections: the native backend's, whose guest addresses are
/// host addresses (the VM's guest memory is not tracked here).
#[cfg(target_os = "macos")]
pub(crate) fn host_guest_memory() -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    for (start, len) in tracked() {
        let end = start + len;
        let mut at = start;
        while at < end {
            let Some(r) = region::query(at) else { break };
            if r.start >= end {
                break;
            }
            let (lo, hi) = (r.start.max(at), (r.start + r.size).min(end));
            let mut prot = 0;
            for (host, linux) in [
                (libc::PROT_READ, mman::PROT_READ),
                (libc::PROT_WRITE, mman::PROT_WRITE),
                (libc::PROT_EXEC, mman::PROT_EXEC),
            ] {
                if r.protection & host != 0 {
                    prot |= linux;
                }
            }
            out.push((lo, hi, prot));
            at = hi;
        }
    }
    out
}

/// No backend runs guests on other hosts (the kernel's unit tests do).
#[cfg(not(target_os = "macos"))]
pub(crate) fn host_guest_memory() -> Vec<(u64, u64, u64)> {
    Vec::new()
}

/// The memory regions of host process `pid` over its host range `[start,
/// end)`, as `(start, end, Linux prot, bytes resident)`, cut to the range.
/// The host counts a region's resident pages, not which they are: a part
/// of a larger region is counted as resident up to what the region has in
/// memory.
#[cfg(target_os = "macos")]
pub(crate) fn regions_of(pid: i32, start: u64, end: u64) -> Vec<(u64, u64, u64, u64)> {
    /// `struct proc_regioninfo` (`sys/proc_info.h`).
    #[repr(C)]
    #[derive(Default)]
    struct RegionInfo {
        protection: u32,
        max_protection: u32,
        inheritance: u32,
        flags: u32,
        offset: u64,
        behavior: u32,
        user_wired_count: u32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u32,
        share_mode: u32,
        private_pages_resident: u32,
        shared_pages_resident: u32,
        obj_id: u32,
        depth: u32,
        address: u64,
        size: u64,
    }
    const PROC_PIDREGIONINFO: libc::c_int = 7;
    // SAFETY: plain host call.
    let page = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as u64;
    let mut out = Vec::new();
    let mut at = start;
    while at < end {
        let mut r = RegionInfo::default();
        let size = std::mem::size_of::<RegionInfo>() as libc::c_int;
        // SAFETY: a valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDREGIONINFO,
                at,
                (&mut r as *mut RegionInfo).cast(),
                size,
            )
        };
        if n != size || r.size == 0 || r.address >= end {
            break;
        }
        let (lo, hi) = (r.address.max(at), (r.address + r.size).min(end));
        if hi <= lo {
            break;
        }
        let mut prot = 0;
        for (host, linux) in [
            (libc::PROT_READ as u32, mman::PROT_READ),
            (libc::PROT_WRITE as u32, mman::PROT_WRITE),
            (libc::PROT_EXEC as u32, mman::PROT_EXEC),
        ] {
            if r.protection & host != 0 {
                prot |= linux;
            }
        }
        // Exact where the region is the range; where it is larger, as much
        // of the range as the region has in memory (the host counts a
        // region's pages, not which they are).
        let resident = (r.pages_resident as u64).saturating_mul(page);
        out.push((lo, hi, prot, resident.min(hi - lo)));
        at = hi;
    }
    out
}

/// Another host than macOS has no fwe processes to ask about.
#[cfg(not(target_os = "macos"))]
pub(crate) fn regions_of(_pid: i32, _start: u64, _end: u64) -> Vec<(u64, u64, u64, u64)> {
    Vec::new()
}

/// The mappings of host process `pid` (this one's, or another fwe
/// process's as it published them), with the memory fwe mapped for its
/// guest, the record, and how many bytes of a range of it are resident.
pub(crate) struct MapsView {
    pub areas: Vec<crate::vmas::Piece<crate::maps::Area>>,
    pub record: crate::maps::Record,
    pub page: u64,
    other: Option<(i32, crate::maps::Published)>,
}

impl MapsView {
    pub(crate) fn of(pid: i32) -> Option<MapsView> {
        // SAFETY: getpid cannot fail.
        if pid == unsafe { libc::getpid() } {
            // The host's view first: its lock comes before the record's.
            let extra = host_guest_memory();
            let record = crate::maps::record().clone();
            let areas = record.with_extra(&extra);
            return Some(MapsView { areas, record, page: crate::maps::page_size(), other: None });
        }
        let p = crate::maps::of_process(pid)?;
        let extra: Vec<(u64, u64, u64)> = p
            .tracked
            .iter()
            .flat_map(|&(s, l)| regions_of(pid, s, s + l))
            .map(|(lo, hi, prot, _)| (lo, hi, prot))
            .collect();
        let areas = p.record.with_extra(&extra);
        Some(MapsView { areas, record: p.record.clone(), page: p.page, other: Some((pid, p)) })
    }

    /// Bytes of guest range `[start, end)` resident.
    pub(crate) fn resident(&self, start: u64, end: u64) -> u64 {
        match &self.other {
            None => resident(start, end),
            Some((pid, p)) => {
                let host = p.host_of(start);
                regions_of(*pid, host, host + (end - start)).iter().map(|r| r.3).sum()
            }
        }
    }

    /// The listing (`/proc/<pid>/maps`, or with `smaps` `smaps`).
    pub(crate) fn render(&self, smaps: bool) -> Vec<u8> {
        let usage = |s: u64, e: u64| crate::maps::Usage { resident: self.resident(s, e) };
        crate::maps::render(&self.areas, &self.record.exe(), self.page, smaps.then_some(&usage))
    }
}

/// How many bytes of guest memory `[start, end)` are in memory, by the
/// host's pages.
pub(crate) fn resident(start: u64, end: u64) -> u64 {
    // SAFETY: plain host call.
    let page = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as u64;
    let mut total = 0;
    let mut at = start;
    while at < end {
        let host = crate::uaccess::g2h(at) & !(page - 1);
        let next = ((at & !(page - 1)) + page).min(end);
        let mut byte = 0u8;
        // SAFETY: one byte of residency for one host page; a page not
        // mapped fails, and nothing else changes.
        let ok = unsafe {
            libc::mincore(host as *mut libc::c_void, page as usize, (&mut byte as *mut u8).cast())
        } == 0;
        if ok && byte & 1 != 0 {
            total += next - at;
        }
        at = next;
    }
    total
}

/// Run `f` holding the tracking lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = guest_maps();
    f()
}

impl Brk {
    /// Default size of the reservation.
    pub const RESERVATION: u64 = 1 << 30;

    /// Reserve up to `size` bytes of address space at page-aligned
    /// `start`: as much of it as is free, halving the size while something
    /// the host mapped is in the way (the break grows up to the next
    /// mapping, as on Linux).
    ///
    /// If none is free the break cannot grow; allocators then fall back to
    /// `mmap`, as they do on Linux when `brk` fails.
    pub fn reserve(start: u64, size: u64) -> Brk {
        let mut size = size;
        while size >= 1 << 16 {
            match crate::host::reserve_fixed(start, size) {
                Ok(()) => {
                    track(start, size);
                    return Brk { start, current: start, limit: start + size };
                }
                Err(crate::host::ReserveError::Occupied) => size /= 2,
                Err(_) => break,
            }
        }
        Brk { start, current: start, limit: start }
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

/// Whether any of guest range `[start, start + len)` is mapped (what
/// `shmat` without `SHM_REMAP` refuses to map over).
pub(crate) fn any_mapped(start: u64, len: u64) -> bool {
    let host = crate::uaccess::g2h(start);
    #[cfg(target_os = "macos")]
    {
        region::query(host).is_some_and(|r| r.start < host.saturating_add(len))
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: plain host call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
        let mut at = host & !(page - 1);
        let mut byte = 0u8;
        while at < host.saturating_add(len) {
            // SAFETY: one byte of residency for one page.
            if unsafe {
                libc::mincore(at as *mut libc::c_void, page as usize, (&mut byte as *mut u8).cast())
            } == 0
            {
                return true;
            }
            at += page;
        }
        false
    }
}

/// Whether all of guest range `[start, start + len)` is mapped.
pub(crate) fn mapped(start: u64, len: u64) -> bool {
    // A backend that knows the guest's memory says (the VM's); the host
    // knows what it has mapped.
    if !crate::uaccess::valid(start, len, false) {
        return false;
    }
    host_mapped(crate::uaccess::g2h(start), len)
}

/// Whether all of host range `[host, host + len)` is mapped, as Mach's
/// regions say (`mincore` does not fail for a hole on macOS).
#[cfg(target_os = "macos")]
pub(crate) fn host_mapped(host: u64, len: u64) -> bool {
    let end = host.saturating_add(len);
    let mut at = host;
    while at < end {
        match region::query(at) {
            Some(r) if r.start <= at => at = r.start + r.size,
            _ => return false,
        }
    }
    true
}

/// Whether all of host range `[host, host + len)` is mapped: `mincore`
/// fails with `ENOMEM` for a hole, and has no other effect.
#[cfg(not(target_os = "macos"))]
pub(crate) fn host_mapped(host: u64, len: u64) -> bool {
    // SAFETY: plain host call.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut vec = [0u8; 4096];
    let end = host.saturating_add(len);
    let mut at = host & !(page - 1);
    while at < end {
        let n = (end - at).min(vec.len() as u64 * page);
        // SAFETY: `vec` has room for one byte per page of `n` bytes.
        if unsafe { libc::mincore(at as *mut libc::c_void, n as usize, vec.as_mut_ptr().cast()) }
            != 0
        {
            return false;
        }
        at += n;
    }
    true
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
pub mod region {
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

    /// `vm_region_top_info`.
    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy)]
    struct TopInfo {
        obj_id: c_uint,
        ref_count: c_uint,
        private_pages_resident: c_uint,
        shared_pages_resident: c_uint,
        share_mode: c_uchar,
    }

    const VM_REGION_BASIC_INFO_64: c_int = 9;
    const VM_REGION_TOP_INFO: c_int = 12;
    const VM_REGION_EXTENDED_INFO: c_int = 13;
    /// `VM_INHERIT_COPY`: what a `MAP_PRIVATE` mapping gets; `MAP_SHARED`
    /// mappings inherit by sharing (`VM_INHERIT_SHARE`, 0).
    const VM_INHERIT_COPY: c_uint = 1;
    const VM_INHERIT_SHARE: c_uint = 0;

    unsafe extern "C" {
        fn minherit(addr: *mut libc::c_void, len: usize, inherit: c_int) -> c_int;
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
        /// The most `protection` may become.
        pub max_protection: c_int,
        /// A file (an external pager) backs the region.
        file_backed: bool,
        /// The mapping is `MAP_PRIVATE` (inherits by copy). A `MAP_SHARED`
        /// anonymous mapping with a single reference looks private in every
        /// other respect, so this is what tells them apart.
        private: bool,
    }

    impl Region {
        /// The mapping is `MAP_PRIVATE`: a child gets a copy, not a share.
        pub fn private(&self) -> bool {
            self.private
        }

        /// Private anonymous memory: what Linux zero-fills on `MADV_DONTNEED`.
        pub fn private_anonymous(&self) -> bool {
            self.private && !self.file_backed
        }
    }

    /// The parts of `ranges` (`(start, len)` pairs) mapped `MAP_PRIVATE`,
    /// as `(start, len)` in address order.
    pub fn private_parts(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let mut parts = Vec::new();
        for &(start, len) in ranges {
            let end = start + len;
            let mut at = start;
            while at < end {
                let Some(r) = query(at) else { break };
                if r.start >= end {
                    break;
                }
                let (lo, hi) = (r.start.max(at), (r.start + r.size).min(end));
                if r.private {
                    parts.push((lo, hi - lo));
                }
                at = hi;
            }
        }
        parts
    }

    /// Make a host `fork` share `[start, start + len)` with the child
    /// (`share`) or give it a copy, as `MAP_PRIVATE` memory normally is.
    pub fn set_shared_on_fork(start: u64, len: u64, share: bool) {
        let how = if share { VM_INHERIT_SHARE } else { VM_INHERIT_COPY };
        // SAFETY: changes only what a later fork does with this task's own
        // memory; the mapping itself is untouched.
        unsafe { minherit(start as *mut libc::c_void, len as usize, how as c_int) };
    }

    /// What memory host address `addr` is, as Linux tells futexes apart:
    /// `Some(None)` for private memory (a futex there is this process's,
    /// at this address), `Some(Some((object, offset)))` for shared memory,
    /// the same pair in every process that maps it, wherever (Mach's id of
    /// the memory object, the same for the system's life, and the offset
    /// into it); `None` where nothing is mapped.
    pub fn sharing(addr: u64) -> Option<Option<(u32, u64)>> {
        let (start, _, basic) = query_flavor::<BasicInfo>(addr, VM_REGION_BASIC_INFO_64)?;
        if start > addr {
            return None;
        }
        if basic.inheritance == VM_INHERIT_COPY {
            return Some(None);
        }
        let (_, _, top) = query_flavor::<TopInfo>(start, VM_REGION_TOP_INFO)?;
        Some(Some((top.obj_id, basic.offset + (addr - start))))
    }

    /// Move the pages of `[from, from + len)` to `to`, over whatever is
    /// there, contents and all (Mach's remap of the same memory, not a
    /// copy), inherited by a fork as they were. The old range is left
    /// mapped, for the caller to let go. Whether it moved.
    pub fn move_pages(from: u64, to: u64, len: u64) -> bool {
        unsafe extern "C" {
            fn mach_vm_remap(
                target: libc::mach_port_t,
                address: *mut u64,
                size: u64,
                mask: u64,
                flags: c_int,
                source: libc::mach_port_t,
                source_address: u64,
                copy: libc::boolean_t,
                cur: *mut c_int,
                max: *mut c_int,
                inheritance: c_uint,
            ) -> libc::kern_return_t;
        }
        // VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE
        const FIXED_OVERWRITE: c_int = 0x4000;
        let inherit =
            if query(from).is_some_and(|r| r.private) { VM_INHERIT_COPY } else { VM_INHERIT_SHARE };
        let mut at = to;
        let (mut cur, mut max) = (0, 0);
        // SAFETY: this task's own memory, a range the caller owns at both
        // ends; the protections come back through valid out-parameters.
        let kr = unsafe {
            mach_vm_remap(
                mach_task_self_,
                &mut at,
                len,
                0,
                FIXED_OVERWRITE,
                mach_task_self_,
                from,
                0,
                &mut cur,
                &mut max,
                inherit,
            )
        };
        kr == 0 && at == to
    }

    pub fn query(addr: u64) -> Option<Region> {
        let (start, size, basic) = query_flavor::<BasicInfo>(addr, VM_REGION_BASIC_INFO_64)?;
        let (_, _, ext) = query_flavor::<ExtendedInfo>(start, VM_REGION_EXTENDED_INFO)?;
        Some(Region {
            start,
            size,
            protection: basic.protection,
            max_protection: basic.max_protection,
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

    /// Private memory set to be shared on fork is written by the child for
    /// the parent to see (what a `vfork` child does), and goes back to
    /// being copied; `private_parts` leaves `MAP_SHARED` memory out.
    #[test]
    fn private_memory_can_be_shared_with_a_fork_child() {
        let len = 1 << 15;
        let private = map(len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE);
        let shared = map(len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        let ranges = [(private, len as u64), (shared, len as u64)];
        assert_eq!(region::private_parts(&ranges), vec![(private, len as u64)]);
        let child_writes = |value: u8| {
            // SAFETY: the child only writes into the mapping and exits.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: as above.
                unsafe {
                    (private as *mut u8).write(value);
                    libc::_exit(0)
                }
            }
            assert!(pid > 0);
            let mut status = 0;
            // SAFETY: reaping the child just made.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            // SAFETY: reading inside the mapping.
            unsafe { (private as *const u8).read() }
        };
        region::set_shared_on_fork(private, len as u64, true);
        assert_eq!(child_writes(7), 7);
        region::set_shared_on_fork(private, len as u64, false);
        assert_eq!(child_writes(9), 7);
        assert!(region::query(private).unwrap().private());
        // SAFETY: unmapping the test's own mappings.
        unsafe {
            libc::munmap(private as *mut _, len);
            libc::munmap(shared as *mut _, len);
        }
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
        let r = dontneed(none, len as u64);
        // Unless another test's thread has mapped some of it since.
        if !any_mapped(none, len as u64) {
            assert_eq!(r, err(errno::ENOMEM));
        }
        // SAFETY: unmapping the test's own mappings.
        unsafe {
            libc::munmap(private as *mut _, len);
            libc::munmap(shared as *mut _, len);
        }
    }
}

/// The known-code ranges given for memory a guest makes executable after
/// mapping it (JIT code): none, so `x18` lookalikes there are left alone.
/// JIT compilers for Linux arm64 do not use `x18` (V8 reserves it), while
/// their code pages hold data that can look like an instruction naming it.
const JIT_CODE: Option<&[(u64, u64)]> = Some(&[]);

/// The executable sections of the ELF file open at `fd`, as file-offset
/// ranges, or `None` if it is not a readable regular ELF with section headers
/// (then the caller translates the whole mapped region instead), with the
/// file-offset ranges its unwind table says are code, if it has a usable
/// one. Maps the file to read it, so the guest's file position is untouched.
type ExecFile = (Vec<(u64, u64)>, Option<Vec<(u64, u64)>>);
fn exec_file_ranges(fd: i32) -> Option<ExecFile> {
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
    if size < 64 {
        return None;
    }
    // Mapped for the parse and unmapped at once, rather than read into a
    // buffer: a library can be 100 MB, and a freed buffer that size stays
    // reserved by the host's allocator, right beside the code, where the
    // rewrite's stubs must be placed.
    // SAFETY: a fresh read-only private mapping of the whole file.
    let map = unsafe {
        libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ, libc::MAP_PRIVATE, fd, 0)
    };
    if map == libc::MAP_FAILED {
        return None;
    }
    // SAFETY: the mapping spans `size` readable bytes until it is unmapped
    // below, after the last use of `data`.
    let data = unsafe { std::slice::from_raw_parts(map as *const u8, size) };
    let ranges = fwe_elf::Elf::parse(data)
        .ok()
        .and_then(|elf| Some((elf.exec_file_ranges()?, elf.unwind_code_file_ranges())));
    // SAFETY: unmapping the mapping made above; `data` is not used again.
    unsafe { libc::munmap(map, size) };
    ranges
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

/// The host protections guest protections `prot` end up as: writable and
/// executable memory is only writable (see [`WRITE_EXEC`]).
fn final_prot(prot: u64) -> libc::c_int {
    let p = host_prot(prot);
    if wants_write_exec(prot) { p & !libc::PROT_EXEC } else { p }
}

/// The memory system calls, recorded for `/proc/self/maps` once they
/// succeed, whichever backend carried them out, and published for other
/// processes (see [`crate::maps`]).
impl<P: Platform> Kernel<P> {
    pub(crate) fn sys_brk(&mut self, addr: u64) -> i64 {
        let r = self.brk_call(addr);
        let b = self.brk;
        crate::maps::record().set_heap(b.start, self.page_up(b.current), b.limit);
        if r >= 0 {
            crate::maps::publish();
        }
        r
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
        // A file's offset is checked, then its descriptor, before anything
        // else, as Linux checks them.
        if flags & mman::MAP_ANONYMOUS == 0 {
            if offset & (self.page_size - 1) != 0 {
                return err(errno::EINVAL);
            }
            // (A guest's call never names fwe's own descriptors, which its
            // System V segments are mapped through.)
            // SAFETY: F_GETFD only queries the descriptor.
            if unsafe { libc::fcntl(fd as i32, libc::F_GETFD) } < 0 {
                return err(errno::EBADF);
            }
            // `MAP_SHARED_VALIDATE`: a flag past Linux's legacy ones (and
            // its huge-page size bits) is one no file here supports, not
            // even `MAP_SYNC`, which needs DAX.
            const LEGACY: u64 = mman::MAP_TYPE
                | mman::MAP_FIXED
                | mman::MAP_ANONYMOUS
                | mman::MAP_DENYWRITE
                | mman::MAP_EXECUTABLE
                | mman::MAP_GROWSDOWN
                | mman::MAP_LOCKED
                | mman::MAP_NORESERVE
                | mman::MAP_POPULATE
                | mman::MAP_NONBLOCK
                | mman::MAP_STACK
                | mman::MAP_HUGETLB
                | mman::MAP_FIXED_NOREPLACE
                | 0x3f << 26;
            if flags & mman::MAP_TYPE == mman::MAP_SHARED_VALIDATE && flags & !LEGACY != 0 {
                return err(errno::EOPNOTSUPP);
            }
        }
        // No more mappings than `vm.max_map_count` allows.
        if too_many_maps(0) {
            return err(errno::ENOMEM);
        }
        // Nothing of a mount that runs nothing is mapped to run, then or
        // later.
        let noexec = flags & mman::MAP_ANONYMOUS == 0
            && crate::fdmarks::origin(fd as i32)
                .is_some_and(|o| o.flags & crate::mounts::ms::NOEXEC != 0);
        if noexec && prot & mman::PROT_EXEC != 0 {
            return err(errno::EPERM);
        }
        // Not over a sealed mapping.
        if flags & mman::MAP_FIXED != 0 && self.sealed(addr, len) {
            return err(errno::EPERM);
        }
        // A loop device maps the file it shows.
        let source = if flags & mman::MAP_ANONYMOUS == 0 {
            crate::loopdev::map_source(fd as i32, self.page_size)
        } else {
            None
        };
        // A shared mapping of a file open only for reading may not be made
        // writable later.
        // SAFETY: F_GETFL only queries the descriptor.
        let nowrite = flags & mman::MAP_ANONYMOUS == 0
            && flags & mman::MAP_TYPE != mman::MAP_PRIVATE
            && unsafe { libc::fcntl(fd as i32, libc::F_GETFL) } & libc::O_ACCMODE == libc::O_RDONLY;
        // `/dev/zero` maps new memory, shared between the processes that
        // share the mapping (the host has no mapping of the device).
        let flags = if flags & mman::MAP_ANONYMOUS == 0 && is_dev_zero(fd as i32) {
            flags | mman::MAP_ANONYMOUS
        } else {
            flags
        };
        let r = match &source {
            Some(Ok((file, start))) => match offset.checked_add(*start) {
                Some(at) => {
                    let file = std::os::fd::AsRawFd::as_raw_fd(file) as u64;
                    self.mmap_call(addr, len, prot, flags, file, at)
                }
                None => err(errno::EOVERFLOW),
            },
            Some(Err(e)) => err(*e),
            None => self.mmap_call(addr, len, prot, flags, fd, offset),
        };
        drop(source);
        if r < 0 {
            return r;
        }
        let object = (flags & mman::MAP_ANONYMOUS == 0)
            .then(|| {
                let st = crate::fsops::linux_fstat(fd as i32).ok()?;
                let path = self.fs.as_ref().map_or_else(Vec::new, |f| f.fd_target(fd as i32));
                Some(crate::maps::Object::file(path, &st, offset))
            })
            .flatten();
        let shared = flags & mman::MAP_TYPE != mman::MAP_PRIVATE;
        let len = self.page_up(len);
        let prot = prot & (mman::PROT_READ | mman::PROT_WRITE | mman::PROT_EXEC);
        let locked = crate::maps::record().mapped(r as u64, len, prot, shared, object);
        if noexec {
            crate::maps::record().no_exec(r as u64, len);
        }
        if nowrite {
            crate::maps::record().no_write(r as u64, len);
        }
        remove_range(&mut grows_down(), r as u64, len);
        if flags & mman::MAP_GROWSDOWN != 0 {
            grows_down().insert(r as u64, r as u64 + len);
        }
        if flags & mman::MAP_LOCKED != 0 {
            crate::maps::record().lock(r as u64, len, true);
            populate(r as u64, len, self.page_size);
        } else if locked {
            populate(r as u64, len, self.page_size);
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }

    /// Whether `[addr, addr + len)` (page-aligned `addr`) has a sealed
    /// mapping (`mseal`), which most changes may not touch (`EPERM`).
    fn sealed(&self, addr: u64, len: u64) -> bool {
        addr & (self.page_size - 1) == 0
            && crate::maps::record().any_sealed(addr, addr.saturating_add(self.page_up(len)))
    }

    /// `mseal(addr, len, flags)`: seal the mappings of the range, every
    /// page of which must be mapped.
    pub(crate) fn sys_mseal(&mut self, addr: u64, len: u64, flags: u64) -> i64 {
        if flags != 0 || addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        // A length that rounds past the end of the address space.
        if len.checked_add(self.page_size - 1).is_none() {
            return err(errno::EINVAL);
        }
        let len = self.page_up(len);
        if len == 0 {
            return 0;
        }
        let Some(end) = addr.checked_add(len) else { return err(errno::EINVAL) };
        let r = crate::maps::record().seal(addr, end);
        match r {
            Ok(()) => {
                crate::maps::publish();
                0
            }
            Err(e) => err(e),
        }
    }

    /// `remap_file_pages(start, size, prot, pgoff, flags)`, as Linux does it
    /// since it stopped keeping non-linear mappings: the range of a shared
    /// file mapping mapped afresh at page `pgoff` of its file.
    pub(crate) fn sys_remap_file_pages(
        &mut self,
        start: u64,
        size: u64,
        prot: u64,
        pgoff: u64,
        flags: u64,
    ) -> i64 {
        let mask = !(self.page_size - 1);
        let (start, size) = (start & mask, size & mask);
        if prot != 0 || flags & !mman::MAP_NONBLOCK != 0 {
            return err(errno::EINVAL);
        }
        let (Some(end), Some(offset)) =
            (start.checked_add(size), pgoff.checked_mul(self.page_size))
        else {
            return err(errno::EINVAL);
        };
        if end <= start {
            return err(errno::EINVAL);
        }
        // One shared mapping of a file, the whole range in it.
        let areas = crate::maps::record().areas_in(start, end);
        let area = match &areas[..] {
            [p] if p.start <= start && p.end >= end && p.value.shared => p.value.clone(),
            _ => return err(errno::EINVAL),
        };
        if !matches!(area.object.name, crate::maps::Name::Exe | crate::maps::Name::Path(_)) {
            return err(errno::EINVAL);
        }
        let Some(file) = region_file(crate::uaccess::g2h(start)) else {
            return err(errno::EINVAL);
        };
        let write = area.prot & mman::PROT_WRITE != 0;
        let Ok(c) = std::ffi::CString::new(file) else { return err(errno::EINVAL) };
        // SAFETY: a NUL-terminated path; the descriptor is closed below.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                if write { libc::O_RDWR } else { libc::O_RDONLY } | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return crate::host::last_error();
        }
        let locked = if area.locked { mman::MAP_LOCKED } else { 0 };
        let flags = mman::MAP_SHARED | mman::MAP_FIXED | mman::MAP_POPULATE | locked;
        let r = self.sys_mmap(start, size, area.prot, flags, fd as u64, offset);
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
        if r < 0 { r } else { 0 }
    }

    pub(crate) fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        // Unmapping the middle of a mapping makes two of it: not past
        // `vm.max_map_count`.
        let end = addr.saturating_add(self.page_up(len));
        let splits = crate::maps::record()
            .span_at(addr)
            .is_some_and(|(start, stop)| start < addr && stop > end);
        if splits && too_many_maps(1) {
            return err(errno::ENOMEM);
        }
        if self.sealed(addr, len) {
            return err(errno::EPERM);
        }
        let r = self.munmap_call(addr, len);
        if r == 0 {
            crate::maps::record().unmapped(addr, self.page_up(len));
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }

    pub(crate) fn sys_mprotect(&mut self, addr: u64, len: u64, prot: u64) -> i64 {
        if self.sealed(addr, len) {
            return err(errno::EPERM);
        }
        if prot & mman::PROT_EXEC != 0 && crate::maps::record().any_noexec(addr, self.page_up(len))
            || prot & mman::PROT_WRITE != 0
                && crate::maps::record().any_nowrite(addr, self.page_up(len))
        {
            return err(errno::EACCES);
        }
        let r = self.mprotect_call(addr, len, prot);
        if r == 0 {
            let prot = prot & (mman::PROT_READ | mman::PROT_WRITE | mman::PROT_EXEC);
            crate::maps::record().protected(addr, self.page_up(len), prot);
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }

    pub(crate) fn sys_mremap(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: u64,
    ) -> i64 {
        if let Err(e) = self.mremap_check(old, old_len, new_len, flags, new_addr) {
            return err(e);
        }
        if self.sealed(old, old_len)
            || (flags & mman::MREMAP_FIXED != 0 && self.sealed(new_addr, new_len))
        {
            return err(errno::EPERM);
        }
        let kept = if flags & mman::MREMAP_DONTUNMAP != 0 {
            crate::maps::record().areas_in(old, old + self.page_up(old_len))
        } else {
            Vec::new()
        };
        let r = self.mremap_call(old, old_len, new_len, flags, new_addr);
        if r >= 0 {
            crate::maps::record().remapped(
                old,
                self.page_up(old_len),
                r as u64,
                self.page_up(new_len),
            );
            // The old range stays mapped, emptied, with `MREMAP_DONTUNMAP`.
            for p in kept {
                let a = p.value;
                crate::maps::record().mapped(
                    p.start,
                    p.end - p.start,
                    a.prot,
                    a.shared,
                    Some(a.object),
                );
            }
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }

    /// `mlock`, `mlock2` and `munlock`: locked memory is brought in
    /// (unless `MLOCK_ONFAULT`) and listed as locked.
    pub(crate) fn sys_mlock(&mut self, addr: u64, len: u64, flags: u64, lock: bool) -> i64 {
        let r = self.mlock_call(addr, len, flags, lock);
        if r == 0 && len > 0 {
            let start = addr & !(self.page_size - 1);
            let len = self.page_up(addr + len) - start;
            crate::maps::record().lock(start, len, lock);
            if lock && flags & mman::MLOCK_ONFAULT == 0 {
                populate(start, len, self.page_size);
            }
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }

    /// `mincore(addr, len, vec)`: a byte for each page of the range, bit 0
    /// set if the page is in memory.
    pub(crate) fn sys_mincore(&mut self, addr: u64, len: u64, vec: u64) -> i64 {
        if addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(len).map(|e| self.page_up(e)) else {
            return err(errno::ENOMEM);
        };
        if end == addr {
            return 0;
        }
        if !mapped(addr, end - addr) {
            return err(errno::ENOMEM);
        }
        let pages = (end - addr) / self.page_size;
        let mut out = Vec::with_capacity(pages as usize);
        for i in 0..pages {
            let at = addr + i * self.page_size;
            out.push(u8::from(resident(at, at + self.page_size) > 0));
        }
        match crate::uaccess::write_from(vec, &out) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `ioctl(fd, PROCMAP_QUERY, arg)` on a descriptor of host process
    /// `pid`'s `/proc/<pid>/maps`: the mapping `arg` asks about, described
    /// in it.
    pub(crate) fn procmap_query(&mut self, pid: i32, arg: u64) -> i64 {
        use fwe_abi::procmap::*;
        let size_of = std::mem::size_of::<Query>() as u64;
        let usize = match crate::uaccess::read::<u64>(arg) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if usize > self.page_size {
            return err(errno::E2BIG);
        }
        if usize < size_of {
            return err(errno::EINVAL);
        }
        // A larger structure's extra bytes must be zero.
        match crate::uaccess::read_bytes(arg + size_of, (usize - size_of) as usize) {
            Ok(rest) if rest.iter().any(|&b| b != 0) => return err(errno::E2BIG),
            Ok(_) => {}
            Err(e) => return err(e),
        }
        let mut q: Query = match crate::uaccess::read(arg) {
            Ok(q) => q,
            Err(e) => return err(e),
        };
        let valid = VMA_READABLE
            | VMA_WRITABLE
            | VMA_EXECUTABLE
            | VMA_SHARED
            | COVERING_OR_NEXT_VMA
            | FILE_BACKED_VMA;
        if q.query_flags & !valid != 0
            || (q.vma_name_size == 0) != (q.vma_name_addr == 0)
            || (q.build_id_size == 0) != (q.build_id_addr == 0)
        {
            return err(errno::EINVAL);
        }
        let Some(view) = MapsView::of(pid) else { return err(errno::ESRCH) };
        let Some(p) = crate::maps::query(&view.areas, q.query_addr, q.query_flags) else {
            return err(errno::ENOENT);
        };
        let exe = view.record.exe();
        let a = &p.value;
        let (name, (dev, ino)) = crate::maps::name_of(a, &exe);
        q.vma_start = p.start;
        q.vma_end = p.end;
        q.vma_flags = [
            (mman::PROT_READ, VMA_READABLE),
            (mman::PROT_WRITE, VMA_WRITABLE),
            (mman::PROT_EXEC, VMA_EXECUTABLE),
        ]
        .iter()
        .filter(|(prot, _)| a.prot & prot != 0)
        .fold(if a.shared { VMA_SHARED } else { 0 }, |f, (_, flag)| f | flag);
        q.vma_page_size = view.page;
        q.vma_offset = a.file_offset();
        q.inode = ino;
        q.dev_major = crate::devnodes::major(dev);
        q.dev_minor = crate::devnodes::minor(dev);
        // The file's build ID, read from its start as Linux reads it.
        if q.build_id_size != 0 {
            let file_backed =
                matches!(a.object.name, crate::maps::Name::Exe | crate::maps::Name::Path(_));
            let head = if file_backed { self.fs().read_head(name, 1 << 16).ok() } else { None };
            match head.as_deref().and_then(fwe_elf::build_id) {
                Some(id) => {
                    if (q.build_id_size as usize) < id.len() {
                        return err(errno::ENAMETOOLONG);
                    }
                    if let Err(e) = crate::uaccess::write_from(q.build_id_addr, id) {
                        return err(e);
                    }
                    q.build_id_size = id.len() as u32;
                }
                None => q.build_id_size = 0,
            }
        }
        if q.vma_name_size != 0 {
            if name.is_empty() {
                q.vma_name_size = 0;
            } else {
                if (q.vma_name_size as usize) < name.len() + 1 {
                    return err(errno::ENAMETOOLONG);
                }
                let named = [name, b"\0"].concat();
                if let Err(e) = crate::uaccess::write_from(q.vma_name_addr, &named) {
                    return err(e);
                }
                q.vma_name_size = named.len() as u32;
            }
        }
        match crate::uaccess::write(arg, q) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `mlockall` and `munlockall` (`flags` `None`).
    pub(crate) fn sys_mlockall(&mut self, flags: Option<u64>) -> i64 {
        let r = self.mlockall_call(flags);
        if r == 0 {
            match flags {
                Some(f) => {
                    let current = f & mman::MCL_CURRENT != 0;
                    crate::maps::record().lock_all(Some((current, f & mman::MCL_FUTURE != 0)));
                    if current && f & mman::MCL_ONFAULT == 0 {
                        let all = crate::maps::record().areas();
                        for p in all {
                            populate(p.start, p.end - p.start, self.page_size);
                        }
                    }
                }
                None => crate::maps::record().lock_all(None),
            }
        }
        if r >= 0 {
            crate::maps::publish();
        }
        r
    }
}

/// Bring the accessible pages of guest memory `[start, start + len)` in,
/// as locking memory does: a read of each (of `page` bytes).
fn populate(start: u64, len: u64, page: u64) {
    let areas = crate::maps::record().areas_in(start, start + len);
    for p in areas {
        // Writable memory is readable on the host (arm64 has no
        // write-only pages), and the VM's memory is the host's.
        if p.value.prot & (mman::PROT_READ | mman::PROT_WRITE) == 0 {
            continue;
        }
        let mut at = p.start;
        while at < p.end {
            let _ = crate::uaccess::read::<u8>(at);
            at += page;
        }
    }
}

/// Where the host is asked to put a mapping the guest left to it (2 TiB):
/// above the program, its break and fwe's own memory, below the top of
/// the address space a guest may use.
const MMAP_HINT: u64 = 0x200_0000_0000;

impl<P: Platform> Kernel<P> {
    /// `a` rounded up to a page; past the last page, the last page's start
    /// (what no range fits in, so a call given it fails as too long).
    fn page_up(&self, a: u64) -> u64 {
        a.saturating_add(self.page_size - 1) & !(self.page_size - 1)
    }

    fn brk_call(&mut self, addr: u64) -> i64 {
        if let Some(r) = self.platform.memory(MemCall::Brk { addr }, &mut self.brk) {
            return r;
        }
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

    fn mmap_call(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> i64 {
        let call = MemCall::Mmap { addr, len, prot, flags, fd: fd as i32, offset };
        if let Some(r) = self.platform.memory(call, &mut self.brk) {
            return r;
        }
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
        // A fixed address in the translated range is placed at its host
        // address; the guest gets its own address back. (Without a fixed
        // address, `addr` is only a hint.)
        let fixed = flags & (mman::MAP_FIXED | mman::MAP_FIXED_NOREPLACE) != 0;
        if fixed && crate::uaccess::crosses(addr, self.page_up(len)) {
            return err(errno::EINVAL);
        }
        let mut haddr = if fixed { crate::uaccess::g2h(addr) } else { addr };
        let mut placed = false;
        if !fixed {
            if let Some(at) = self.platform.place_mapping(self.page_up(len)) {
                haddr = at;
                hflags |= libc::MAP_FIXED;
                placed = true;
            } else if addr == 0 {
                // Left to the host, a mapping goes in the first gap it fits,
                // among the program's image, its break and fwe's own memory,
                // where code may find no room for its stubs within reach (a
                // library a dynamic loader maps). From a place well above
                // them, mappings fill upwards, the space past the latest one
                // free.
                haddr = MMAP_HINT;
            }
        }

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
        if flags & mman::MAP_FIXED != 0 {
            // A fixed mapping replaces what is there: the VM lets go of it
            // before the host frees it.
            self.platform.unmap_guest(addr, self.page_up(len));
        }
        let mut retried = false;
        let (p, guest) = 'map: loop {
            // SAFETY: guest-requested mapping. MAP_FIXED may replace guest memory,
            // which is the guest's own business, exactly as on Linux.
            let p = unsafe {
                libc::mmap(
                    haddr as *mut libc::c_void,
                    len as usize,
                    initial_prot,
                    hflags,
                    host_fd,
                    offset as libc::off_t,
                )
            };
            if p == libc::MAP_FAILED {
                let e = last_error();
                if placed {
                    // The range chosen for it goes back to the backend.
                    self.platform.release_host(haddr, self.page_up(len));
                } else if retried {
                    // SAFETY: the place reserved for it, not otherwise used.
                    unsafe { libc::munmap(haddr as *mut libc::c_void, len as usize) };
                }
                return e;
            }
            let p = p as u64;
            if noreplace && p != haddr {
                // SAFETY: unmapping the mapping just created.
                self.unmap_host(p, len);
                return err(errno::EEXIST);
            }
            let guest = if p == haddr && fixed { addr } else { p };
            track(p, self.page_up(len));
            if let Err(e) = self.platform.map_guest(guest, self.page_up(len), prot) {
                // SAFETY: unmapping the mapping just created.
                self.unmap_host(p, len);
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
                // File ranges in the mapping, as host addresses.
                let in_mapping = |ranges: Vec<(u64, u64)>| -> Vec<(u64, u64)> {
                    ranges
                        .into_iter()
                        .filter_map(|(foff, fsize)| {
                            let start = foff.max(offset);
                            let end = (foff + fsize).min(offset + len);
                            (start < end).then_some((p + (start - offset), end - start))
                        })
                        .collect()
                };
                let (prep, known) = match if anonymous { None } else { exec_file_ranges(host_fd) } {
                    Some((sections, code)) => (in_mapping(sections), code.map(in_mapping)),
                    None => (vec![(p, self.page_up(len))], None),
                };
                for (a, l) in prep {
                    if let Err(e) = self.platform.prepare_exec(a, l, known.as_deref()) {
                        // SAFETY: unmapping the mapping just created.
                        self.unmap_host(p, len);
                        untrack(p, self.page_up(len));
                        // Where the guest left the place to fwe, and the host
                        // put the code with no room for its stubs within
                        // reach: once more, where there is.
                        if !fixed && !placed && !retried {
                            if let Some(at) = Self::roomy_place(self.page_up(len)) {
                                self.tracer.note(&format!("code moved for room: {}", e.why));
                                haddr = at;
                                hflags |= libc::MAP_FIXED;
                                retried = true;
                                continue 'map;
                            }
                        }
                        return self.prepare_failed(e);
                    }
                }
                // SAFETY: changing protections of the mapping just created.
                if unsafe { libc::mprotect(p as *mut libc::c_void, len as usize, final_prot(prot)) }
                    != 0
                {
                    let e = last_error();
                    // SAFETY: unmapping the mapping just created.
                    self.unmap_host(p, len);
                    untrack(p, self.page_up(len));
                    return e;
                }
            }
            break (p, guest);
        };
        if wants_write_exec(prot) {
            add_range(&mut write_exec(), p, self.page_up(len));
        } else {
            remove_range(&mut write_exec(), p, self.page_up(len));
        }
        guest as i64
    }

    /// Unmap guest host memory, or have the backend take it back
    /// ([`Platform::release_host`]). Returns 0 or a negated Linux errno.
    fn unmap_host(&mut self, addr: u64, len: u64) -> i64 {
        if self.platform.release_host(addr, self.page_up(len)) {
            return 0;
        }
        // SAFETY: unmapping guest memory, at the guest's request or a
        // mapping fwe just made for it.
        ret(unsafe { libc::munmap(addr as *mut libc::c_void, len as usize) })
    }

    fn munmap_call(&mut self, addr: u64, len: u64) -> i64 {
        if let Some(r) = self.platform.memory(MemCall::Munmap { addr, len }, &mut self.brk) {
            return r;
        }
        if crate::uaccess::crosses(addr, self.page_up(len)) {
            return err(errno::EINVAL);
        }
        let host = crate::uaccess::g2h(addr) as *mut libc::c_void;
        // The VM lets go of the memory before the host frees it.
        self.platform.unmap_guest(addr, self.page_up(len));
        let r = self.unmap_host(host as u64, len);
        if r == 0 {
            untrack(host as u64, self.page_up(len));
            remove_range(&mut write_exec(), host as u64, self.page_up(len));
            remove_range(&mut wipe_on_fork(), host as u64, self.page_up(len));
            remove_range(&mut grows_down(), addr, self.page_up(len));
            remove_range(&mut poisoned_ranges(), addr, self.page_up(len));
            remove_range(&mut dont_dump_ranges(), addr, self.page_up(len));
        }
        r
    }

    /// A place for a mapping of `len` bytes with room after it for the stubs
    /// its code needs ([`Platform::prepare_exec`]): reserved (inaccessible),
    /// the room left free. None if the host has no such place.
    fn roomy_place(len: u64) -> Option<u64> {
        const ROOM: u64 = 64 << 20;
        // SAFETY: a fresh inaccessible mapping of fwe's; its tail is let go.
        unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                (len + ROOM) as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return None;
            }
            libc::munmap((p as u64 + len) as *mut libc::c_void, ROOM as usize);
            Some(p as u64)
        }
    }

    /// The guest's answer to a failed [`Platform::prepare_exec`], with the
    /// reason in the trace.
    fn prepare_failed(&self, e: crate::PrepareFailed) -> i64 {
        self.tracer.note(&format!("code not prepared: {}", e.why));
        err(e.errno)
    }

    fn mprotect_call(&mut self, addr: u64, len: u64, prot: u64) -> i64 {
        if let Some(r) = self.platform.memory(MemCall::Mprotect { addr, len, prot }, &mut self.brk)
        {
            return r;
        }
        if crate::uaccess::crosses(addr, self.page_up(len)) {
            return err(errno::EINVAL);
        }
        let a = crate::uaccess::g2h(addr) as *mut libc::c_void;
        if prot & mman::PROT_EXEC != 0 {
            // SAFETY: guest-requested protection change of guest memory.
            if unsafe { libc::mprotect(a, len as usize, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
                return last_error();
            }
            // Code made executable after it was mapped is a JIT's, with no
            // unwind table to tell its code from the data in it (V8 keeps
            // constant pools and metadata in its code pages), and JITs leave
            // x18 alone: only its system calls and thread-pointer accesses
            // are translated (see [`JIT_CODE`]).
            // Only what the file has (a page past its end has nothing to
            // read, and faults).
            let backed = self.backed_len(addr, self.page_up(len));
            if backed > 0
                && let Err(e) = self.platform.prepare_exec(a as u64, backed, JIT_CODE)
            {
                return self.prepare_failed(e);
            }
        }
        // SAFETY: guest-requested protection change of guest memory.
        let r = ret(unsafe { libc::mprotect(a, len as usize, final_prot(prot)) });
        if r == 0 {
            let mut wx = write_exec();
            if wants_write_exec(prot) {
                add_range(&mut wx, a as u64, self.page_up(len));
            } else {
                remove_range(&mut wx, a as u64, self.page_up(len));
            }
            drop(wx);
            self.platform.protect_guest(addr, self.page_up(len), prot);
        }
        r
    }

    /// How much of guest range `[addr, addr + len)`, from its start, has
    /// something behind it: all of it, but for a file mapping the pages up
    /// to the file's end.
    fn backed_len(&self, addr: u64, len: u64) -> u64 {
        use crate::vmas::Mapping;
        let Some(p) = crate::maps::record().areas_in(addr, addr + len).into_iter().next() else {
            return len;
        };
        let area = p.value.at(addr.saturating_sub(p.start));
        if !matches!(area.object.name, crate::maps::Name::Path(_) | crate::maps::Name::Exe) {
            return len;
        }
        let Some(path) = region_file(crate::uaccess::g2h(addr)) else { return len };
        let Ok(meta) = std::fs::metadata(std::ffi::OsStr::from_bytes(&path)) else { return len };
        self.page_up(meta.len().saturating_sub(area.object.offset)).min(len)
    }

    /// A fault the guest took at host address `addr`: if it is below a
    /// `MAP_GROWSDOWN` mapping, which nothing else is within Linux's guard
    /// gap (256 pages) of where it would then start, the mapping grows
    /// down to `addr`'s page, as Linux grows a stack, and the access is
    /// retried. Whether it grew.
    pub fn stack_fault(&mut self, addr: u64) -> bool {
        const GAP_PAGES: u64 = 256;
        let page = self.page_size;
        let Some((start, end)) = grows_down().range(addr..).next().map(|(&s, &e)| (s, e)) else {
            return false;
        };
        let new_start = addr & !(page - 1);
        let gap = GAP_PAGES * page;
        let below = crate::maps::record().areas_in(new_start.saturating_sub(gap), new_start);
        if !below.is_empty() || any_mapped(new_start, start - new_start) {
            return false;
        }
        let area = crate::maps::record().areas_in(start, start + page);
        let Some(top) = area.first() else { return false };
        let prot = host_prot(top.value.prot);
        let host = crate::uaccess::g2h(new_start);
        if !map_fixed_anon(host, start - new_start, prot) {
            return false;
        }
        track(host, start - new_start);
        crate::maps::record().mapped(new_start, start - new_start, top.value.prot, false, None);
        let mut g = grows_down();
        g.remove(&start);
        g.insert(new_start, end);
        drop(g);
        crate::maps::publish();
        true
    }

    /// A fault the guest took at host address `addr`, fetching an
    /// instruction (`exec`) or writing: if `addr` is in memory the guest
    /// mapped writable and executable, switch its page to what the access
    /// needs — executable, with its code prepared as any guest code is, or
    /// writable — and report it handled, so the access is retried.
    pub fn write_exec_fault(&mut self, addr: u64, exec: bool) -> bool {
        if !write_exec_writable(addr, self.page_size) {
            return false;
        }
        if exec {
            let page = addr & !(self.page_size - 1);
            if let Err(e) = self.platform.prepare_exec(page, self.page_size, JIT_CODE) {
                self.tracer.note(&format!("code at {page:#x} not prepared: {}", e.why));
                return false;
            }
            let rx = libc::PROT_READ | libc::PROT_EXEC;
            // SAFETY: a page of guest memory the guest mapped writable and
            // executable; only its host protections change.
            unsafe { libc::mprotect(page as *mut libc::c_void, self.page_size as usize, rx) };
        }
        true
    }

    /// `msync(addr, len, flags)`: the host's, on the same memory.
    pub(crate) fn sys_msync(&mut self, addr: u64, len: u64, flags: u64) -> i64 {
        if let Some(r) = self.platform.memory(MemCall::Msync { addr, len, flags }, &mut self.brk) {
            return r;
        }
        if addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let Some(flags) = crate::host::msync_flags_to_host(flags) else {
            return err(errno::EINVAL);
        };
        let len = self.page_up(len);
        if crate::uaccess::crosses(addr, len) {
            return err(errno::EINVAL);
        }
        // Each mapping in the range synced; locked memory is not to be
        // invalidated (`EBUSY`), and a hole fails the call (`ENOMEM`) once
        // the rest is synced, as Linux has it.
        let areas = crate::maps::record().areas_in(addr, addr + len);
        if flags & libc::MS_INVALIDATE != 0 && areas.iter().any(|p| p.value.locked) {
            return err(errno::EBUSY);
        }
        let mut at = addr;
        let mut hole = false;
        for p in &areas {
            hole |= p.start > at;
            at = p.end;
            let host = crate::uaccess::g2h(p.start);
            // SAFETY: syncing guest memory at the guest's request, a range
            // that is mapped.
            let r = ret(unsafe {
                libc::msync(host as *mut libc::c_void, (p.end - p.start) as usize, flags)
            });
            if r < 0 {
                return r;
            }
        }
        if hole || at < addr + len { err(errno::ENOMEM) } else { 0 }
    }

    /// `mlock`, `mlock2` (`flags`) and `munlock` (`lock` false): the range,
    /// widened to whole pages, must be mapped, and a caller without
    /// `CAP_IPC_LOCK` may lock no more than its `RLIMIT_MEMLOCK` (none at
    /// all if that is 0). The host is not asked to wire the pages: Linux's
    /// root may lock far more than the host lets a user process, and what
    /// a program sees of a locked page is the same.
    fn mlock_call(&mut self, addr: u64, len: u64, flags: u64, lock: bool) -> i64 {
        if lock && flags & !mman::MLOCK_ONFAULT != 0 {
            return err(errno::EINVAL);
        }
        let start = addr & !(self.page_size - 1);
        let Some(end) = addr.checked_add(len).map(|e| self.page_up(e)) else {
            return err(errno::ENOMEM);
        };
        if end == start {
            return 0;
        }
        if lock && !self.creds.has(crate::caps::CAP_IPC_LOCK) {
            let soft = crate::syscalls::own_limit_of(fwe_abi::resource::RLIMIT_MEMLOCK);
            if soft == 0 {
                return err(errno::EPERM);
            }
            // What it would have locked: this range and what else is.
            let (already, all) = {
                let r = crate::maps::record();
                (r.locked_in(start, end), r.locked_bytes())
            };
            if all - already + (end - start) > soft {
                return err(errno::ENOMEM);
            }
        }
        if mapped(start, end - start) { 0 } else { err(errno::ENOMEM) }
    }

    /// `mlockall(flags)` and `munlockall` (`flags` `None`): checked as Linux
    /// checks them, nothing wired (see [`Kernel::sys_mlock`]).
    fn mlockall_call(&mut self, flags: Option<u64>) -> i64 {
        let Some(flags) = flags else { return 0 };
        let all = mman::MCL_CURRENT | mman::MCL_FUTURE | mman::MCL_ONFAULT;
        if flags == 0 || flags & !all != 0 || flags == mman::MCL_ONFAULT {
            return err(errno::EINVAL);
        }
        if !self.creds.has(crate::caps::CAP_IPC_LOCK) {
            let soft = crate::syscalls::own_limit_of(fwe_abi::resource::RLIMIT_MEMLOCK);
            if soft == 0 {
                return err(errno::EPERM);
            }
            // Locking what is mapped now must fit the limit.
            if flags & mman::MCL_CURRENT != 0 && crate::maps::record().total_bytes() > soft {
                return err(errno::ENOMEM);
            }
        }
        0
    }

    pub(crate) fn sys_madvise(&mut self, addr: u64, len: u64, advice: u64) -> i64 {
        // MADV_HWPOISON and MADV_SOFT_OFFLINE are the administrator's.
        if matches!(advice, 100 | 101) && !self.creds.has(crate::caps::CAP_SYS_ADMIN) {
            return err(errno::EPERM);
        }
        let hole = match self.madvise_check(addr, len, advice) {
            Ok(None) => return 0,
            Ok(Some(hole)) => hole,
            Err(e) => return err(e),
        };
        if !hole {
            return self.madvise_apply(addr, len, advice);
        }
        // Given to each mapping in the range, then the hole reported.
        let end = addr + self.page_up(len);
        for p in crate::maps::record().areas_in(addr, end) {
            let r = self.madvise_apply(p.start, p.end - p.start, advice);
            if r < 0 {
                return r;
            }
        }
        err(errno::ENOMEM)
    }

    /// `madvise`'s arguments, checked as Linux checks them: advice it
    /// knows (no `MADV_MERGEABLE` without KSM), an aligned start, a range
    /// that does not wrap (`EINVAL`); then each mapping in the range for the
    /// advice: discarding locked memory, freeing or wiping on fork memory
    /// that is not private and anonymous, removing pages of what is not a
    /// shared file (`EINVAL`). `None` for an empty range (nothing to do),
    /// else whether the range has a hole, which fails the call (`ENOMEM`)
    /// once the advice is given to the rest.
    fn madvise_check(&self, addr: u64, len: u64, advice: u64) -> Result<Option<bool>, i32> {
        const KNOWN: [u64; 25] = [
            0, 1, 2, 3, 4, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 100, 101,
            102, 103,
        ];
        let end = addr.checked_add(self.page_up(len)).filter(|_| len <= u64::MAX - self.page_size);
        if !KNOWN.contains(&advice) || addr & (self.page_size - 1) != 0 || end.is_none() {
            return Err(errno::EINVAL);
        }
        if len == 0 {
            return Ok(None);
        }
        let end = end.unwrap_or(addr);
        let areas = crate::maps::record().areas_in(addr, end);
        let mut at = addr;
        let mut hole = false;
        for p in &areas {
            hole |= p.start > at;
            at = p.end;
            let a = &p.value;
            use crate::maps::Name;
            let anonymous =
                !a.shared && matches!(a.object.name, Name::Anonymous | Name::Heap | Name::Stack);
            let file = matches!(a.object.name, Name::Path(_) | Name::Exe);
            let bad = match advice {
                // MADV_DONTNEED, MADV_FREE, MADV_REMOVE: not locked memory.
                4 | 8 | 9 if a.locked => true,
                8 | 18 => !anonymous,
                9 => !(file && a.shared),
                _ => false,
            };
            if bad {
                return Err(errno::EINVAL);
            }
        }
        Ok(Some(hole || at < end))
    }

    /// [`Self::sys_madvise`]'s advice given, the arguments checked.
    fn madvise_apply(&mut self, addr: u64, len: u64, advice: u64) -> i64 {
        // Sealed memory, read-only and anonymous, is not to be discarded:
        // MADV_DONTNEED, FREE, REMOVE, DONTFORK, WIPEONFORK and
        // DONTNEED_LOCKED.
        if matches!(advice, 4 | 8 | 9 | 10 | 18 | 24)
            && addr & (self.page_size - 1) == 0
            && crate::maps::record()
                .any_sealed_read_only(addr, addr.saturating_add(self.page_up(len)))
        {
            return err(errno::EPERM);
        }
        let call = MemCall::Madvise { addr, len, advice };
        if let Some(r) = self.platform.memory(call, &mut self.brk) {
            return r;
        }
        if addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let len = self.page_up(len);
        if crate::uaccess::crosses(addr, len) {
            return err(errno::EINVAL);
        }
        let host = crate::uaccess::g2h(addr);
        match advice {
            mman::MADV_DONTNEED => {
                // The VM lets go of the pages before the host replaces them,
                // then maps the new ones (whatever the outcome, so the
                // guest keeps the mappings it had).
                self.platform.replacing_guest(addr, len);
                let r = dontneed(host, len);
                self.platform.remapped_guest(addr, len);
                r
            }
            mman::MADV_FREE => {
                // SAFETY: advisory call on guest memory.
                unsafe { libc::madvise(host as *mut libc::c_void, len as usize, libc::MADV_FREE) };
                0
            }
            mman::MADV_NORMAL | mman::MADV_RANDOM | mman::MADV_SEQUENTIAL | mman::MADV_WILLNEED => {
                // Hints, which Linux takes for any mapped memory (the host
                // refuses some, for memory it may not read).
                // SAFETY: advisory call on guest memory; values match the host's.
                unsafe {
                    libc::madvise(host as *mut libc::c_void, len as usize, advice as libc::c_int)
                };
                0
            }
            // MADV_HWPOISON: the pages fail, as memory that broke does.
            100 => {
                // SAFETY: guest memory the guest asked to poison.
                unsafe { libc::mprotect(host as *mut libc::c_void, len as usize, libc::PROT_NONE) };
                add_range(&mut poisoned_ranges(), addr, len);
                0
            }
            // Left out of a core dump, or back in it.
            mman::MADV_DONTDUMP => {
                add_range(&mut dont_dump_ranges(), addr, len);
                0
            }
            mman::MADV_DODUMP => {
                remove_range(&mut dont_dump_ranges(), addr, len);
                0
            }
            // MADV_WIPEONFORK, MADV_KEEPONFORK
            18 => {
                add_range(&mut wipe_on_fork(), host, len);
                0
            }
            19 => {
                remove_range(&mut wipe_on_fork(), host, len);
                0
            }
            // Other advice (huge pages, merging, ...) has no host
            // equivalent and no effect on program semantics.
            _ => 0,
        }
    }

    /// `mremap`'s arguments, checked as Linux checks them: its flags, an
    /// aligned old address, `MREMAP_FIXED` and `MREMAP_DONTUNMAP` only with
    /// `MREMAP_MAYMOVE` (the latter keeping the size), a new length, an
    /// aligned new address that does not overlap the old range (`EINVAL`);
    /// then the old range, which must be mapped, one mapping without a gap
    /// (`EFAULT`).
    fn mremap_check(
        &self,
        old: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: u64,
    ) -> Result<(), i32> {
        use mman::{MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE};
        let page = self.page_size;
        let may_move = flags & MREMAP_MAYMOVE != 0;
        if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
            || old & (page - 1) != 0
            || flags & MREMAP_FIXED != 0 && !may_move
            || flags & MREMAP_DONTUNMAP != 0 && (!may_move || old_len != new_len)
            || self.page_up(new_len) == 0
        {
            return Err(errno::EINVAL);
        }
        let (old_len, new_len) = (self.page_up(old_len), self.page_up(new_len));
        if flags & MREMAP_FIXED != 0
            && (new_addr & (page - 1) != 0
                || new_addr < old + old_len && old < new_addr.saturating_add(new_len))
        {
            return Err(errno::EINVAL);
        }
        let areas = crate::maps::record().areas_in(old, old + old_len.max(page));
        let mut at = old;
        for p in &areas {
            if p.start > at {
                break;
            }
            at = p.end;
        }
        if areas.is_empty() || at < old + old_len.max(page) {
            return Err(errno::EFAULT);
        }
        Ok(())
    }

    /// `mremap`, checked already ([`Self::mremap_check`]): a range shrunk
    /// in place, grown in place where the space after it is free, or moved
    /// (`MREMAP_MAYMOVE`, `MREMAP_FIXED`) with its pages, which keep their
    /// contents and sharing. A grown part continues the mapping: the same
    /// file, further on, or new anonymous memory. Code (an executable
    /// mapping, which fwe has prepared where it is) is not grown or moved
    /// (`ENOMEM`).
    fn mremap_call(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: u64,
    ) -> i64 {
        let call = MemCall::Mremap { old, old_len, new_len, flags, new_addr };
        if let Some(r) = self.platform.memory(call, &mut self.brk) {
            return r;
        }
        let old_len = self.page_up(old_len);
        let new_len = self.page_up(new_len);
        let fixed = flags & mman::MREMAP_FIXED != 0;
        if crate::uaccess::crosses(old, old_len)
            || fixed && crate::uaccess::crosses(new_addr, new_len)
        {
            return err(errno::EINVAL);
        }
        let host = crate::uaccess::g2h(old);
        if new_len <= old_len && !fixed {
            if new_len < old_len {
                let tail = host + new_len;
                // The VM lets go of the tail before the host frees it.
                self.platform.unmap_guest(old + new_len, old_len - new_len);
                self.unmap_host(tail, old_len - new_len);
                untrack(tail, old_len - new_len);
                remove_range(&mut write_exec(), tail, old_len - new_len);
            }
            return old as i64;
        }
        let areas = crate::maps::record().areas_in(old, old + old_len);
        if areas.iter().any(|p| p.value.prot & mman::PROT_EXEC != 0) {
            return err(errno::ENOMEM);
        }
        // What a grown part continues: the last mapping, from its end.
        use crate::vmas::Mapping;
        let Some(last) = areas.last().map(|p| (p.value.at(p.end - p.start), p.end)) else {
            return err(errno::EFAULT);
        };
        #[cfg(not(target_os = "macos"))]
        {
            let _ = last;
            // SAFETY: the guest's own memory, as it asks; the host is Linux.
            let r = unsafe {
                libc::mremap(
                    host as *mut libc::c_void,
                    old_len as usize,
                    new_len as usize,
                    flags as i32,
                    crate::uaccess::g2h(new_addr) as *mut libc::c_void,
                )
            };
            if r == libc::MAP_FAILED {
                return last_error();
            }
            untrack(host, old_len);
            track(r as u64, new_len);
            if r as u64 == crate::uaccess::g2h(new_addr) && fixed {
                new_addr as i64
            } else {
                r as i64
            }
        }
        #[cfg(target_os = "macos")]
        {
            let (area, end) = last;
            let extra = new_len.saturating_sub(old_len);
            // In place, where the space after it is free.
            if !fixed
                && !any_mapped(old + old_len, extra)
                && self.grow_at(host + old_len, extra, &area, host + (end - old))
            {
                track(host + old_len, extra);
                if let Err(e) = self.platform.map_guest(old + old_len, extra, area.prot) {
                    return err(e);
                }
                return old as i64;
            }
            if flags & mman::MREMAP_MAYMOVE == 0 {
                return err(errno::ENOMEM);
            }
            // Where it goes: the place asked for, emptied, or a new one.
            let (dest, guest) = if fixed {
                let r = self.munmap_call(new_addr, new_len);
                if r < 0 {
                    return r;
                }
                (crate::uaccess::g2h(new_addr), new_addr)
            } else {
                // SAFETY: a fresh inaccessible reservation for the move.
                let p = unsafe {
                    libc::mmap(
                        MMAP_HINT as *mut libc::c_void,
                        new_len as usize,
                        libc::PROT_NONE,
                        libc::MAP_ANON | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                };
                if p == libc::MAP_FAILED {
                    return err(errno::ENOMEM);
                }
                (p as u64, p as u64)
            };
            let keep = old_len.min(new_len);
            if !region::move_pages(host, dest, keep)
                || extra > 0 && !self.grow_at(dest + old_len, extra, &area, host + (end - old))
            {
                if !fixed {
                    // SAFETY: the reservation made above, nothing else.
                    unsafe { libc::munmap(dest as *mut libc::c_void, new_len as usize) };
                }
                return err(errno::ENOMEM);
            }
            // The old range: let go, or with `MREMAP_DONTUNMAP` mapped still,
            // its memory new (zero, for private anonymous memory).
            self.platform.unmap_guest(old, old_len);
            if flags & mman::MREMAP_DONTUNMAP != 0 {
                let prot = host_prot(areas[0].value.prot);
                map_fixed_anon(host, old_len, prot);
            } else {
                self.unmap_host(host, old_len);
                untrack(host, old_len);
            }
            // `MADV_WIPEONFORK` stays with the memory it was given.
            let wiped = wipe_on_fork().range(..host + old_len).any(|(_, &end)| end > host);
            remove_range(&mut wipe_on_fork(), host, old_len);
            if wiped {
                add_range(&mut wipe_on_fork(), dest, keep);
            }
            track(dest, new_len);
            if let Err(e) = self.platform.map_guest(guest, new_len, area.prot) {
                return err(e);
            }
            guest as i64
        }
    }

    /// Map `[at, at + len)` as the continuation of mapping `area`, whose
    /// last part ends at host address `end_of` (its file there, further on,
    /// or anonymous memory like it). Whether it did.
    #[cfg(target_os = "macos")]
    fn grow_at(&mut self, at: u64, len: u64, area: &crate::maps::Area, end_of: u64) -> bool {
        if len == 0 {
            return true;
        }
        let prot = host_prot(area.prot);
        let share = if area.shared { libc::MAP_SHARED } else { libc::MAP_PRIVATE };
        let file = match &area.object.name {
            crate::maps::Name::Path(_) | crate::maps::Name::Exe => region_file(end_of - 1),
            _ => None,
        };
        let Some(path) = file else {
            // SAFETY: a fixed mapping over a range the caller found free.
            let p = unsafe {
                libc::mmap(
                    at as *mut libc::c_void,
                    len as usize,
                    prot,
                    share | libc::MAP_ANON | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            return p as u64 == at;
        };
        let Ok(c) = std::ffi::CString::new(path) else { return false };
        let mode = if area.shared && area.prot & mman::PROT_WRITE != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        // SAFETY: a NUL-terminated path; the descriptor is closed below,
        // the mapping keeping the file.
        unsafe {
            let fd = libc::open(c.as_ptr(), mode | libc::O_CLOEXEC);
            if fd < 0 {
                return false;
            }
            let p = libc::mmap(
                at as *mut libc::c_void,
                len as usize,
                prot,
                share | libc::MAP_FIXED,
                fd,
                area.object.offset as libc::off_t,
            );
            libc::close(fd);
            p as u64 == at
        }
    }
}

/// Whether `fd` is `/dev/zero`.
fn is_dev_zero(fd: i32) -> bool {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    ok && crate::devnodes::linux_numbers_of_host(&st).is_some_and(|n| (n.major, n.minor) == (1, 5))
}

/// Whether `extra` more mappings would pass `vm.max_map_count` (Linux
/// refuses a new one once there are more than it). Read only where a
/// process has many: below a thousand, none passes.
fn too_many_maps(extra: usize) -> bool {
    let n = crate::maps::record().count() + extra;
    n >= 1024 && crate::sysctl::number(b"vm/max_map_count").is_some_and(|max| n as i64 > max.max(0))
}

/// The host path of the file mapped at host address `addr`.
#[cfg(target_os = "macos")]
fn region_file(addr: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: a buffer of its stated length.
    let n = unsafe {
        libc::proc_regionfilename(libc::getpid(), addr, buf.as_mut_ptr().cast(), buf.len() as u32)
    };
    (n > 0).then(|| {
        buf.truncate(n as usize);
        buf
    })
}

/// Another host than macOS has no fwe mappings to name.
#[cfg(not(target_os = "macos"))]
fn region_file(_addr: u64) -> Option<Vec<u8>> {
    None
}
