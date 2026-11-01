//! Applying [`crate::rewrite`] to guest memory: in-place rewrites, stub
//! regions placed within branch range of their sites, and instruction cache
//! maintenance.

use crate::rewrite::{self, BRANCH_RANGE, STUB_WORDS, Site};
use fwe_kernel::host::reserve_fixed;

/// Statistics of one preparation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Prepared {
    pub syscalls: usize,
    pub stubs: usize,
}

/// No stub region could be placed within branch range of some sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoStubSpace {
    pub near: u64,
}

/// Distance between candidate stub region placements.
const PLACEMENT_STEP: u64 = 1 << 20;

/// Sites grouped so that one stub region can reach all of them.
const GROUP_SPAN: u64 = BRANCH_RANGE / 4;

/// Prepare guest code in `[addr, addr + len)` for execution.
///
/// # Safety
/// The range must be readable and writable guest memory that no thread is
/// executing.
pub unsafe fn prepare(addr: u64, len: u64, slot: u32, page: u64) -> Result<Prepared, NoStubSpace> {
    let start = addr & !3;
    let len = (len + (addr - start)) & !3;
    // SAFETY: guaranteed by the caller.
    let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len as usize) };
    let patched = rewrite::patch(code);
    let mut stats = Prepared { syscalls: patched.syscalls, stubs: patched.sites.len() };

    let mut sites = patched.sites.as_slice();
    while let Some(&(first, _)) = sites.first() {
        let n = sites.iter().take_while(|(off, _)| off - first < GROUP_SPAN).count();
        let (group, rest) = sites.split_at(n);
        // SAFETY: the sites lie inside the caller's range.
        unsafe { redirect(start, group, slot, page, start, start + len) }?;
        sites = rest;
    }
    if stats.syscalls + stats.stubs > 0 {
        // SAFETY: the range is mapped.
        unsafe { flush_icache(start, len) };
    } else {
        stats = Prepared::default();
    }
    Ok(stats)
}

/// Write stubs for `group` (offsets from `base`) into a new region near
/// `[lo, hi)` and point each site at its stub.
///
/// # Safety
/// The sites must be writable guest code.
unsafe fn redirect(
    base: u64,
    group: &[(u64, Site)],
    slot: u32,
    page: u64,
    lo: u64,
    hi: u64,
) -> Result<(), NoStubSpace> {
    let first = base + group[0].0;
    let last = base + group[group.len() - 1].0;
    let size = ((group.len() * STUB_WORDS * 4) as u64).div_ceil(page) * page;
    let reachable =
        |region: u64| region + size <= first + BRANCH_RANGE && region + BRANCH_RANGE > last + size;
    let after = (hi + page - 1) & !(page - 1);
    let before = (lo & !(page - 1)).saturating_sub(size);
    let candidates = (0..64u64)
        .flat_map(|k| [after + k * PLACEMENT_STEP, before.saturating_sub(k * PLACEMENT_STEP)]);
    let region = candidates
        .filter(|&r| r != 0 && reachable(r))
        .find(|&r| reserve_fixed(r, size).is_ok())
        .ok_or(NoStubSpace { near: first })?;

    // SAFETY: the region was just reserved by us.
    unsafe {
        libc::mprotect(
            region as *mut libc::c_void,
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    let mut cursor = region;
    for &(offset, site) in group {
        let at = base + offset;
        let words = rewrite::stub(site, slot, cursor, at + 4);
        for (i, w) in words.iter().enumerate() {
            // SAFETY: inside the region, which is writable.
            unsafe { ((cursor + 4 * i as u64) as *mut u32).write(*w) };
        }
        let jump = rewrite::branch(at, cursor).expect("stub region within range");
        // SAFETY: the site is writable guest code (caller's guarantee).
        unsafe { (at as *mut u32).write(jump) };
        cursor += (STUB_WORDS * 4) as u64;
    }
    // SAFETY: making our stub region executable and visible to fetch.
    unsafe {
        libc::mprotect(
            region as *mut libc::c_void,
            size as usize,
            libc::PROT_READ | libc::PROT_EXEC,
        );
        flush_icache(region, size);
    }
    Ok(())
}

/// Invalidate the instruction cache for freshly written code.
///
/// # Safety
/// The range must be mapped.
#[cfg(target_os = "macos")]
pub unsafe fn flush_icache(addr: u64, len: u64) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
    }
    // SAFETY: guaranteed by the caller.
    unsafe { sys_icache_invalidate(addr as *mut libc::c_void, len as usize) }
}

/// Invalidate the instruction cache for freshly written code.
///
/// # Safety
/// The range must be mapped.
#[cfg(not(target_os = "macos"))]
pub unsafe fn flush_icache(_addr: u64, _len: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> u64 {
        // SAFETY: plain host call.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
    }

    #[test]
    fn redirects_thread_pointer_accesses_to_reachable_stubs() {
        let page = page();
        // SAFETY: a fresh mapping owned by the test.
        let code = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        } as u64;
        let insns: [u32; 3] = [0xd53b_d049, rewrite::SVC0, 0xd51b_d040];
        for (i, w) in insns.iter().enumerate() {
            // SAFETY: inside the mapping.
            unsafe { ((code + 4 * i as u64) as *mut u32).write(*w) };
        }
        // SAFETY: the mapping is ours, writable and not executing.
        let stats = unsafe { prepare(code, 12, 8, page) }.unwrap();
        assert_eq!(stats, Prepared { syscalls: 1, stubs: 2 });
        // SAFETY: reading the rewritten code.
        let read = |a: u64| unsafe { (a as *const u32).read() };
        assert_eq!(read(code + 4), rewrite::TRAP);
        for site in [code, code + 8] {
            let b = read(site);
            assert_eq!(b & 0xfc00_0000, 0x1400_0000, "site is a branch");
            let offset = (((b & 0x03ff_ffff) << 6) as i32 >> 4) as i64;
            let stub = (site as i64 + offset) as u64;
            // The stub ends with a branch back to the instruction after the site.
            let words = if site == code { 4 } else { 6 };
            let back = read(stub + 4 * (words - 1));
            assert_eq!(rewrite::branch(stub + 4 * (words - 1), site + 4), Some(back));
        }
    }
}
