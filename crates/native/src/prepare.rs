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
    /// Instructions naming `x18` that were left on the hardware register
    /// (the forms [`crate::decode`] does not cover). Non-zero means the code
    /// can misbehave under preemption; reported under `--strace`.
    pub x18_deferred: usize,
}

/// No stub region could be placed within branch range of some sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoStubSpace {
    pub near: u64,
    /// Why the last placement attempt failed.
    pub last_error: String,
}

impl std::fmt::Display for NoStubSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no room for code stubs near {:#x} ({})", self.near, self.last_error)
    }
}

/// Address space reserved (inaccessible) in advance for stubs, typically
/// right after a loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubArena {
    pub next: u64,
    pub end: u64,
}

impl StubArena {
    /// Take `size` bytes if they are reachable according to `reachable`.
    fn take(&mut self, size: u64, reachable: impl Fn(u64) -> bool) -> Option<u64> {
        let at = self.next;
        (at + size <= self.end && reachable(at)).then(|| {
            self.next += size;
            at
        })
    }
}

/// Bytes of stub space needed for the code in `code`, rounded for the
/// per-group page rounding in [`prepare`].
pub fn stub_space(code: &[u8], page: u64) -> u64 {
    let sites = rewrite::count_sites(code) as u64;
    if sites == 0 {
        return 0;
    }
    let groups = (code.len() as u64).div_ceil(GROUP_SPAN);
    (sites * (STUB_WORDS as u64) * 4).div_ceil(page) * page + groups * page
}

/// Distance between candidate stub region placements.
const PLACEMENT_STEP: u64 = 1 << 20;

/// Sites grouped so that one stub region can reach all of them.
const GROUP_SPAN: u64 = BRANCH_RANGE / 4;

/// Prepare guest code in `[addr, addr + len)` for execution. `known`, when
/// given, is the host address ranges known to be code (see
/// [`rewrite::patch`]).
///
/// # Safety
/// The range must be readable and writable guest memory that no thread is
/// executing.
pub unsafe fn prepare(
    addr: u64,
    len: u64,
    slot: u32,
    x18_slot: u32,
    page: u64,
    mut arena: Option<&mut StubArena>,
    known: Option<&[(u64, u64)]>,
) -> Result<Prepared, NoStubSpace> {
    let start = addr & !3;
    let len = (len + (addr - start)) & !3;
    // SAFETY: guaranteed by the caller.
    let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len as usize) };
    let known: Option<Vec<(u64, u64)>> = known.map(|ranges| {
        ranges
            .iter()
            .filter_map(|&(a, l)| {
                let lo = a.max(start);
                let hi = a.saturating_add(l).min(start + len);
                (lo < hi).then(|| (lo - start, hi - lo))
            })
            .collect()
    });
    let patched = rewrite::patch(code, known.as_deref());
    let stats = Prepared {
        syscalls: patched.syscalls,
        stubs: patched.sites.len(),
        x18_deferred: patched.x18_deferred,
    };

    let mut sites = patched.sites.as_slice();
    while let Some(&(first, _)) = sites.first() {
        let n = sites.iter().take_while(|(off, _)| off - first < GROUP_SPAN).count();
        let (group, rest) = sites.split_at(n);
        // SAFETY: the sites lie inside the caller's range.
        unsafe {
            redirect(start, group, slot, x18_slot, page, start, start + len, arena.as_deref_mut())
        }?;
        sites = rest;
    }
    if stats.syscalls + stats.stubs > 0 {
        // SAFETY: the range is mapped.
        unsafe { flush_icache(start, len) };
    }
    Ok(stats)
}

/// Write stubs for `group` (offsets from `base`) into a new region near
/// `[lo, hi)` and point each site at its stub.
///
/// # Safety
/// The sites must be writable guest code.
#[allow(clippy::too_many_arguments)]
unsafe fn redirect(
    base: u64,
    group: &[(u64, Site)],
    slot: u32,
    x18_slot: u32,
    page: u64,
    lo: u64,
    hi: u64,
    arena: Option<&mut StubArena>,
) -> Result<(), NoStubSpace> {
    let first = base + group[0].0;
    let last = base + group[group.len() - 1].0;
    let size = ((group.len() * STUB_WORDS * 4) as u64).div_ceil(page) * page;
    let reachable =
        |region: u64| region + size <= first + BRANCH_RANGE && region + BRANCH_RANGE > last + size;
    let region = match arena.and_then(|a| a.take(size, reachable)) {
        Some(r) => r,
        None => find_region(size, page, lo, hi, reachable)
            .map_err(|last_error| NoStubSpace { near: first, last_error })?,
    };

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
        let words = rewrite::stub(site, slot, x18_slot, cursor, at + 4);
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

/// Reserve `size` bytes near `[lo, hi)` satisfying `reachable`.
fn find_region(
    size: u64,
    page: u64,
    lo: u64,
    hi: u64,
    reachable: impl Fn(u64) -> bool,
) -> Result<u64, String> {
    let mut last_error = String::from("no candidate in range");
    let after = (hi + page - 1) & !(page - 1);
    let before = (lo & !(page - 1)).saturating_sub(size);
    let candidates = (0..64u64)
        .flat_map(|k| [after + k * PLACEMENT_STEP, before.saturating_sub(k * PLACEMENT_STEP)]);
    for r in candidates.filter(|&r| r != 0 && reachable(r)) {
        match reserve_fixed(r, size) {
            Ok(()) => {
                fwe_kernel::mm::track(r, size);
                return Ok(r);
            }
            Err(e) => last_error = format!("{r:#x}: {e}"),
        }
    }
    // Let the host pick a spot near the code.
    for hint in [after, before] {
        // SAFETY: a fresh inaccessible mapping; the address is only a hint.
        let p = unsafe {
            libc::mmap(
                hint as *mut libc::c_void,
                size as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            continue;
        }
        if reachable(p as u64) {
            fwe_kernel::mm::track(p as u64, size);
            return Ok(p as u64);
        }
        last_error = format!("host placed stubs at {:#x}, out of range", p as u64);
        // SAFETY: releasing the mapping just made.
        unsafe { libc::munmap(p, size as usize) };
    }
    Err(last_error)
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

    #[test]
    fn stub_space_estimate() {
        let page = 0x4000;
        assert_eq!(stub_space(&[0u8; 64], page), 0);
        let one = 0xd53b_d049u32.to_le_bytes(); // mrs x9, tpidr_el0
        assert_eq!(stub_space(&one, page), 2 * page);
    }

    #[test]
    fn arena_hands_out_reachable_space() {
        let mut arena = StubArena { next: 0x1000, end: 0x3000 };
        assert_eq!(arena.take(0x1000, |_| true), Some(0x1000));
        assert_eq!(arena.take(0x1000, |_| false), None);
        assert_eq!(arena.take(0x1000, |_| true), Some(0x2000));
        assert_eq!(arena.take(0x1000, |_| true), None);
    }

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
        let stats = unsafe { prepare(code, 12, 8, 16, page, None, None) }.unwrap();
        assert_eq!(stats, Prepared { syscalls: 1, stubs: 2, x18_deferred: 0 });
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
