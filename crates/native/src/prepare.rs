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

/// The stub regions holding a stub for an instruction that writes `sp`
/// from `x18`, as `(start, end)` pairs, for a signal to finish such a stub
/// first ([`in_sp_stub_region`]). Few programs have one; past the table's
/// room every pc is looked at.
static SP_STUB_REGIONS: [std::sync::atomic::AtomicU64; 2 * 256] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 2 * 256];
static SP_STUB_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn note_sp_stub_region(start: u64, end: u64) {
    use std::sync::atomic::Ordering::SeqCst;
    let i = SP_STUB_COUNT.load(SeqCst);
    if i < SP_STUB_REGIONS.len() / 2 {
        SP_STUB_REGIONS[2 * i].store(start, SeqCst);
        SP_STUB_REGIONS[2 * i + 1].store(end, SeqCst);
    }
    SP_STUB_COUNT.store(i + 1, SeqCst);
}

/// Whether `pc` may be in a stub for an instruction that writes `sp` from
/// `x18`. Async-signal-safe.
pub fn in_sp_stub_region(pc: u64) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    let n = SP_STUB_COUNT.load(SeqCst);
    if n > SP_STUB_REGIONS.len() / 2 {
        return true;
    }
    (0..n).any(|i| {
        let (start, end) =
            (SP_STUB_REGIONS[2 * i].load(SeqCst), SP_STUB_REGIONS[2 * i + 1].load(SeqCst));
        start <= pc && pc < end
    })
}

/// Distance between candidate stub region placements.
const PLACEMENT_STEP: u64 = 1 << 20;

/// Sites grouped so that one stub region can reach all of them.
const GROUP_SPAN: u64 = BRANCH_RANGE / 4;

/// The least code whose preparation is kept on disk
/// ([`fwe_kernel::prepcache`]): below it, looking through the code again
/// costs less than reading the record.
const KEEP_FROM: u64 = 64 << 10;

/// What was kept of a range of code: the words [`rewrite::patch`] noted,
/// the `x18` uses it left, and the pages runs wrote as they first ran
/// them (host pages, from the range's first; see
/// [`fwe_kernel::lazycode`]).
struct Kept {
    noted: Vec<rewrite::Noted>,
    deferred: usize,
    hot: Vec<u64>,
}

/// Keep `k` under `key`.
fn keep(key: &[u8], k: &Kept) {
    let mut e = fwe_kernel::snapshot::Enc::new();
    e.u64(k.deferred as u64);
    e.u64(k.noted.len() as u64);
    for &(off, orig, flags) in &k.noted {
        e.u64(off);
        e.u32(orig);
        e.u32(u32::from(flags));
    }
    e.u64(k.hot.len() as u64);
    for &p in &k.hot {
        e.u64(p);
    }
    fwe_kernel::prepcache::store(key, &e.into_bytes());
}

/// What was kept under `key`.
fn kept(key: &[u8]) -> Option<Kept> {
    let v = fwe_kernel::prepcache::load(key)?;
    let mut d = fwe_kernel::snapshot::Dec::new(&v);
    let deferred = d.u64() as usize;
    let n = d.count(16);
    let noted = (0..n).map(|_| (d.u64(), d.u32(), d.u32() as u8)).collect();
    let n = d.count(8);
    let hot = (0..n).map(|_| d.u64()).collect();
    d.finish().ok()?;
    Some(Kept { noted, deferred, hot })
}

/// As the process ends: the pages of each range of code it wrote as they
/// first ran, kept with the range's preparation for the next start (which
/// writes them at once, sparing a fault each), with those kept before.
pub fn keep_hot() {
    for (key, pages) in fwe_kernel::lazycode::written_pages() {
        let Some(mut k) = kept(&key) else { continue };
        let before = k.hot.len();
        k.hot.extend(pages);
        k.hot.sort_unstable();
        k.hot.dedup();
        if k.hot.len() != before {
            keep(&key, &k);
        }
    }
}

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
    (slot, x18_slot): (u32, u32),
    page: u64,
    mut arena: Option<&mut StubArena>,
    known: Option<&[(u64, u64)]>,
    cache: Option<&[u8]>,
) -> Result<Prepared, NoStubSpace> {
    let start = addr & !3;
    let len = (len + (addr - start)) & !3;
    // SAFETY: guaranteed by the caller.
    let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len as usize) };
    let known: Option<Vec<(u64, u64)>> = known
        .map(|ranges| {
            ranges
                .iter()
                .filter_map(|&(a, l)| {
                    let lo = a.max(start);
                    let hi = a.saturating_add(l).min(start + len);
                    (lo < hi).then(|| (lo - start, hi - lo))
                })
                .collect::<Vec<_>>()
        })
        // The unwind table tells code from data only where it describes
        // most of the range: a program built without unwind tables has
        // entries for a few functions only (musl's assembly), and the rest
        // of its code is code all the same.
        .filter(|r| r.iter().map(|&(_, l)| l).sum::<u64>() * 2 >= len);
    // Code mapped from a file whose preparation is known: its writes are
    // made as each page is first run ([`fwe_kernel::lazycode`]), not now.
    // The loader's images (`arena`) are copies, written already.
    let kept = cache.and_then(kept);
    let mut defer: Option<std::collections::BTreeMap<u64, (u32, u32)>> = None;
    let mut hot: Vec<u64> = Vec::new();
    let replayed = match kept {
        Some(k) if arena.is_none() => {
            let (p, words) = rewrite::plan(&k.noted, k.deferred);
            defer =
                Some(words.into_iter().map(|(off, was, now)| (start + off, (was, now))).collect());
            hot = k.hot;
            Some(p)
        }
        Some(k) => rewrite::replay(code, &k.noted, k.deferred),
        None => None,
    };
    let patched = match replayed {
        Some(p) => p,
        None => {
            let p = rewrite::patch(code, known.as_deref());
            if let Some(key) = cache
                && len >= KEEP_FROM
            {
                keep(
                    key,
                    &Kept { noted: p.noted.clone(), deferred: p.x18_deferred, hot: Vec::new() },
                );
            }
            p
        }
    };
    // A system call's site calls the gate through a stub, where there is
    // one; it is already the trap otherwise.
    let gate = crate::syscall_gate();
    let all: Vec<(u64, Site)> = patched
        .sites
        .iter()
        .filter_map(|&(off, site)| match site {
            Site::Syscall { .. } if gate == 0 => None,
            Site::Syscall { .. } => Some((off, Site::Syscall { gate })),
            _ => Some((off, site)),
        })
        .collect();
    let mut stats =
        Prepared { syscalls: patched.syscalls, stubs: 0, x18_deferred: patched.x18_deferred };

    let mut sites = all.as_slice();
    while let Some(&(first, _)) = sites.first() {
        let n = sites.iter().take_while(|(off, _)| off - first < GROUP_SPAN).count();
        let (group, rest) = sites.split_at(n);
        // SAFETY: the sites lie inside the caller's range.
        let placed = unsafe {
            redirect(
                start,
                group,
                (slot, x18_slot),
                page,
                (start, start + len),
                arena.as_deref_mut(),
                defer.as_mut(),
            )
        };
        match placed {
            Ok(()) => stats.stubs += group.len(),
            Err(e) => {
                // With no room for stubs, system calls keep the trap; the
                // other sites need theirs.
                let needed: Vec<(u64, Site)> = group
                    .iter()
                    .copied()
                    .filter(|(_, site)| !matches!(site, Site::Syscall { .. }))
                    .collect();
                if needed.len() == group.len() {
                    return Err(e);
                }
                if !needed.is_empty() {
                    // SAFETY: as above.
                    unsafe {
                        redirect(
                            start,
                            &needed,
                            (slot, x18_slot),
                            page,
                            (start, start + len),
                            arena.as_deref_mut(),
                            defer.as_mut(),
                        )
                    }?;
                    stats.stubs += needed.len();
                }
            }
        }
        sites = rest;
    }
    if let Some(d) = defer {
        // The pages earlier runs wrote as they first ran are written now,
        // while the range is still writable; the rest are owed.
        let host_page = fwe_kernel::mm::host_page_size();
        let first = start & !(host_page - 1);
        let hot: std::collections::BTreeSet<u64> = hot.into_iter().collect();
        let mut owed = Vec::new();
        let mut written = false;
        for (at, (was, now)) in d.into_iter().filter(|(_, (was, now))| was != now) {
            if hot.contains(&((at - first) / host_page)) {
                // SAFETY: a word of the range, writable now (the caller's
                // guarantee); one not as the preparation found it is left.
                unsafe {
                    if (at as *const u32).read() == was {
                        (at as *mut u32).write(now);
                    }
                }
                written = true;
            } else {
                owed.push((at, was, now));
            }
        }
        if written {
            // SAFETY: the range is mapped.
            unsafe { flush_icache(start, len) };
        }
        if let Some(key) = cache {
            fwe_kernel::lazycode::owe(owed, key, start);
        }
    } else if stats.syscalls + stats.stubs > 0 {
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
    (slot, x18_slot): (u32, u32),
    page: u64,
    (lo, hi): (u64, u64),
    arena: Option<&mut StubArena>,
    mut defer: Option<&mut std::collections::BTreeMap<u64, (u32, u32)>>,
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
        match defer.as_deref_mut().and_then(|d| d.get_mut(&at)) {
            // Owed until the page first runs.
            Some(word) => word.1 = jump,
            // SAFETY: the site is writable guest code (caller's guarantee).
            None => unsafe { (at as *mut u32).write(jump) },
        }
        cursor += (STUB_WORDS * 4) as u64;
    }
    if group
        .iter()
        .any(|&(_, site)| matches!(site, Site::X18 { insn } if crate::decode::x18_writes_sp(insn)))
    {
        note_sp_stub_region(region, region + size);
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
    // Outward from the code in both directions, over the whole window the
    // sites can reach: around a large library the nearest megabytes are
    // often taken (by its own reservation, its neighbours and earlier stub
    // regions).
    let steps = 2 * BRANCH_RANGE / PLACEMENT_STEP;
    let candidates = (0..steps).flat_map(|k| {
        [after.checked_add(k * PLACEMENT_STEP), before.checked_sub(k * PLACEMENT_STEP)]
    });
    for r in candidates.flatten().filter(|&r| r != 0 && reachable(r)) {
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
        let stats = unsafe { prepare(code, 12, (8, 16), page, None, None, None) }.unwrap();
        // The system call has a stub where there is a gate to call.
        let gate = crate::syscall_gate();
        let stubs = if gate == 0 { 2 } else { 3 };
        assert_eq!(stats, Prepared { syscalls: 1, stubs, x18_deferred: 0 });
        // SAFETY: reading the rewritten code.
        let read = |a: u64| unsafe { (a as *const u32).read() };
        let stub_of = |site: u64| {
            let b = read(site);
            assert_eq!(b & 0xfc00_0000, 0x1400_0000, "site is a branch");
            let offset = (((b & 0x03ff_ffff) << 6) as i32 >> 4) as i64;
            (site as i64 + offset) as u64
        };
        for site in [code, code + 8] {
            let stub = stub_of(site);
            // The stub ends with a branch back to the instruction after the site.
            let words = if site == code { 4 } else { 6 };
            let back = read(stub + 4 * (words - 1));
            assert_eq!(rewrite::branch(stub + 4 * (words - 1), site + 4), Some(back));
        }
        if gate == 0 {
            assert_eq!(read(code + 4), rewrite::TRAP);
        } else {
            // Its stub calls the gate, then branches back past it.
            let stub = stub_of(code + 4);
            assert_eq!(read(stub + 24) as u64 | (read(stub + 28) as u64) << 32, gate);
            assert_eq!(rewrite::branch(stub + 16, code + 8), Some(read(stub + 16)));
        }
    }

    /// A range's preparation is kept with the pages runs wrote, which a
    /// later run adds to.
    #[test]
    fn kept_preparation_carries_the_pages_written() {
        let key = format!("prepare-test-{}", std::process::id()).into_bytes();
        keep(&key, &Kept { noted: vec![(8, 0xd400_0001, 1)], deferred: 2, hot: vec![3, 1] });
        let k = kept(&key).unwrap();
        assert_eq!((k.noted, k.deferred, k.hot), (vec![(8, 0xd400_0001, 1)], 2, vec![3, 1]));
    }
}
