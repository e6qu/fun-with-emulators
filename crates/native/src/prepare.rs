//! Applying [`crate::rewrite`] to guest memory: in-place rewrites, stub
//! regions placed within branch range of their sites, and instruction cache
//! maintenance.

use crate::rewrite::{self, BRANCH_RANGE, STUB_WORDS, Site};
use fwe_kernel::host::reserve_fixed;

/// What stands for a file in the `mmap` of a stub region: on macOS, the
/// memory tag fwe's stubs carry (an application-specific one), so a memory
/// map (`vmmap`'s "Memory Tag 241") tells them from the program's own code;
/// the benchmarks count a program's time in them as fwe's.
#[cfg(target_os = "macos")]
const STUB_TAG: i32 = 241 << 24;
#[cfg(not(target_os = "macos"))]
const STUB_TAG: i32 = -1;

/// Statistics of one preparation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub syscalls: usize,
    pub stubs: usize,
    /// Instructions naming `x18` that were left on the hardware register
    /// (the forms [`crate::decode`] does not cover). Non-zero means the code
    /// can misbehave under preemption; reported under `--strace`.
    pub x18_deferred: usize,
    /// Host pages (address, length) of a loaded image holding sites no
    /// stub space reaches: the middle of an image larger than a branch
    /// reaches across, all of it the image's own. Their code is to run by
    /// translation ([`crate::jit::code`]); their other sites have stubs.
    pub beyond: Vec<(u64, u64)>,
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

/// Address space reserved (inaccessible) in advance for stubs: right after
/// a loaded image (`next` to `end`), and for an image larger than a branch
/// reaches, right before it too (`front_start` to `front_end`, taken from
/// its end down, nearest the code first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubArena {
    pub next: u64,
    pub end: u64,
    pub front_start: u64,
    pub front_end: u64,
}

impl StubArena {
    /// Take `size` bytes if they are reachable according to `reachable`:
    /// after the image, or else before it.
    fn take(&mut self, size: u64, reachable: impl Fn(u64) -> bool) -> Option<u64> {
        let at = self.next;
        if at + size <= self.end && reachable(at) {
            self.next += size;
            return Some(at);
        }
        let at = self.front_end.checked_sub(size)?;
        (at >= self.front_start && reachable(at)).then(|| {
            self.front_end = at;
            at
        })
    }

    /// Whether `[lo, hi)` lies within the arena's reservation (from before
    /// the image to after it).
    fn covers(&self, lo: u64, hi: u64) -> bool {
        self.front_start <= lo && hi <= self.end
    }
}

/// Bytes of stub space needed for the code in `code`, rounded for the
/// per-group page rounding in [`prepare`].
pub fn stub_space(code: &[u8], page: u64) -> u64 {
    let sites = rewrite::count_sites(code) as u64;
    if sites == 0 {
        // Room for call stubs alone.
        return page;
    }
    let groups = (code.len() as u64).div_ceil(GROUP_SPAN);
    // Each group's region rounded up, and a page more for call stubs.
    (sites * (STUB_WORDS as u64) * 4).div_ceil(page) * page + 2 * groups * page
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

/// Every stub region: start -> end. Stubs sit in slots of
/// [`STUB_WORDS`] words from their region's start.
static STUB_REGIONS: std::sync::Mutex<std::collections::BTreeMap<u64, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn note_stub_region(start: u64, end: u64) {
    STUB_REGIONS.lock().unwrap_or_else(|e| e.into_inner()).insert(start, end);
}

/// The sites given stubs, by address: what each stood for, so code read
/// through its site (to be translated) is had as the program wrote it.
static SITES: std::sync::Mutex<std::collections::BTreeMap<u64, Site>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn note_site(at: u64, site: Site) {
    SITES.lock().unwrap_or_else(|e| e.into_inner()).insert(at, site);
}

/// Call sites made a `bl` to a call stub ([`call_stub`]), by address: the
/// word the program wrote there.
static CALL_SITES: std::sync::Mutex<std::collections::BTreeMap<u64, u32>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Site `at`, which held `w`, made a `bl` or `b` to a call stub.
pub fn note_call_site(at: u64, w: u32) {
    CALL_SITES.lock().unwrap_or_else(|e| e.into_inner()).insert(at, w);
}

/// The instruction the program wrote at `at` in code fwe prepared, which
/// holds `w` now: `w` itself, unless it is fwe's own word there, the trap
/// a system call became, the branch to the stub a site became (whose
/// branch back leads past `at`) or the call or branch to a call stub a
/// call or branch site became ([`note_call_site`]).
pub fn original(at: u64, w: u32) -> u32 {
    if w == rewrite::TRAP {
        return rewrite::SVC0;
    }
    if w & 0x7c00_0000 == rewrite::B
        && let Some(&own) = CALL_SITES.lock().unwrap_or_else(|e| e.into_inner()).get(&at)
    {
        return own;
    }
    if w & 0xfc00_0000 == 0x9400_0000 {
        return w;
    }
    if w & 0xfc00_0000 != rewrite::B {
        return w;
    }
    let to = at.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4));
    if stub_region(to).is_none() {
        return w;
    }
    let Some(site) = SITES.lock().unwrap_or_else(|e| e.into_inner()).get(&at).copied() else {
        return w;
    };
    let back = (0..STUB_WORDS as u64).any(|i| {
        let a = to + 4 * i;
        // SAFETY: a word of a stub slot, in a stub region (readable).
        let x = unsafe { (a as *const u32).read() };
        x & 0xfc00_0000 == rewrite::B
            && a.wrapping_add_signed(i64::from(((x << 6) as i32) >> 4)) == at + 4
    });
    if !back {
        return w;
    }
    match site {
        Site::ReadThreadPointer { rt } => rewrite::MRS_TPIDR | rt,
        Site::WriteThreadPointer { rt } => rewrite::MSR_TPIDR | rt,
        Site::X18 { insn } => insn,
        Site::Syscall { .. } => rewrite::SVC0,
        Site::Flush { rt, .. } => rewrite::IC_IVAU | rt,
    }
}

/// Regions holding call stubs ([`call_stub`]): start, end, next free.
static CALL_STUBS: std::sync::Mutex<Vec<(u64, u64, u64)>> = std::sync::Mutex::new(Vec::new());

/// The rest of a loader's arena, `[start, end)` (reserved, inaccessible),
/// once the code it served is prepared: room for call stubs.
pub fn spare_arena(start: u64, end: u64) {
    if start >= end {
        return;
    }
    // SAFETY: replacing the rest of our own reservation with fresh memory
    // of fwe's.
    let p = unsafe {
        libc::mmap(
            start as *mut libc::c_void,
            (end - start) as usize,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            STUB_TAG,
            0,
        )
    };
    if p != libc::MAP_FAILED {
        note_stub_region(start, end);
        spare(start, end);
    }
}

/// `[start, end)`, the end of a stub region no stub took: room for call
/// stubs.
fn spare(start: u64, end: u64) {
    if start < end {
        CALL_STUBS.lock().unwrap_or_else(|e| e.into_inner()).push((start, end, start));
    }
}

/// Place `words` as a stub in a stub region within branch reach of
/// `site`, executable: its address, or `None` with no room in reach. Other
/// threads are to be stopped (a region in use is made writable a moment).
pub fn call_stub(site: u64, words: &[u32]) -> Option<u64> {
    let len = 4 * words.len() as u64;
    let page = fwe_kernel::mm::host_page_size();
    let mut regions = CALL_STUBS.lock().unwrap_or_else(|e| e.into_inner());
    let reach = |a: u64| a.abs_diff(site) + len < BRANCH_RANGE;
    let i = match regions.iter().position(|&(_, e, c)| c + len <= e && reach(c)) {
        Some(i) => i,
        None => {
            let r =
                find_region(page, page, site, site + 4, |r| r.abs_diff(site) + page < BRANCH_RANGE)
                    .ok()?;
            // SAFETY: replacing the region just reserved by us with fresh
            // memory, carrying fwe's tag.
            let p = unsafe {
                libc::mmap(
                    r as *mut libc::c_void,
                    page as usize,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                    STUB_TAG,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return None;
            }
            note_stub_region(r, r + page);
            regions.push((r, r + page, r));
            regions.len() - 1
        }
    };
    let (start, end, at) = regions[i];
    // SAFETY: a stub region of fwe's, no other thread running.
    unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            (end - start) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        for (k, &w) in words.iter().enumerate() {
            ((at + 4 * k as u64) as *mut u32).write(w);
        }
        libc::mprotect(
            start as *mut libc::c_void,
            (end - start) as usize,
            libc::PROT_READ | libc::PROT_EXEC,
        );
        flush_icache(at, len);
    }
    regions[i].2 = (at + len + 7) & !7;
    Some(at)
}

/// A new program in this process (an `execve` in place): the old one's
/// stub regions went with its memory, and with them what is known of them
/// (sites, room for call stubs).
pub fn reset() {
    STUB_REGIONS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    SP_STUB_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    SITES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    CALL_SITES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    CALL_STUBS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// The stub region holding `pc`, if any: (start, end).
pub fn stub_region(pc: u64) -> Option<(u64, u64)> {
    let regions = STUB_REGIONS.lock().unwrap_or_else(|e| e.into_inner());
    let (&start, &end) = regions.range(..=pc).next_back()?;
    (pc < end).then_some((start, end))
}

/// A fault at `pc` with the stack at `sp`, as if at the site of the stub
/// `pc` is in, if it is in one ([`rewrite::rewind`]): the program's own
/// instruction faulted, and its handler sees it there, with its registers.
pub fn rewind_fault(pc: u64, sp: u64) -> Option<rewrite::Rewound> {
    let (start, end) = {
        let regions = STUB_REGIONS.lock().unwrap_or_else(|e| e.into_inner());
        let (&start, &end) = regions.range(..=pc).next_back()?;
        (start, end)
    };
    if pc >= end {
        return None;
    }
    let slot = (STUB_WORDS * 4) as u64;
    let stub = start + (pc - start) / slot * slot;
    // SAFETY: a slot of a stub region, mapped and readable.
    let words = unsafe { std::slice::from_raw_parts(stub as *const u32, STUB_WORDS) };
    rewrite::rewind(words, stub, pc, sp, |off| {
        // SAFETY: the stack the stub pushed to, below which it faulted.
        Some(unsafe { ((sp + off) as *const u64).read() })
    })
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
    for (key, pages) in fwe_kernel::lazycode::new_written_pages() {
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
    // Code the host maps from its file, not written as a whole: only the
    // pages written need the instruction cache invalidated.
    let from_file = cache.is_some() && arena.is_none();
    let kept = cache.and_then(kept);
    let mut defer: Option<std::collections::BTreeMap<u64, (u32, u32)>> = None;
    let mut hot: Vec<u64> = Vec::new();
    let replayed = match kept {
        Some(k) if arena.is_none() && !imaging() => {
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
            Site::Syscall { .. } | Site::Flush { .. } if gate == 0 => None,
            Site::Syscall { .. } => Some((off, Site::Syscall { gate })),
            Site::Flush { rt, .. } => Some((off, Site::Flush { rt, gate })),
            _ => Some((off, site)),
        })
        .collect();
    let mut stats = Prepared {
        syscalls: patched.syscalls,
        x18_deferred: patched.x18_deferred,
        ..Prepared::default()
    };

    let mut sites = all.as_slice();
    let mut beyond = Vec::new();
    while let Some(&(first, _)) = sites.first() {
        let n = sites.iter().take_while(|(off, _)| off - first < GROUP_SPAN).count();
        let (group, rest) = sites.split_at(n);
        if let Some(arena) = arena.as_deref_mut() {
            // SAFETY: the sites lie inside the caller's range.
            stats.stubs += unsafe {
                place_in_image(
                    start,
                    group,
                    (slot, x18_slot),
                    page,
                    (start, start + len),
                    arena,
                    &mut beyond,
                )
            };
            sites = rest;
            continue;
        }
        // SAFETY: the sites lie inside the caller's range.
        let placed = unsafe {
            redirect(
                start,
                group,
                (slot, x18_slot),
                page,
                (start, start + len),
                None,
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
                            None,
                            defer.as_mut(),
                        )
                    }?;
                    stats.stubs += needed.len();
                }
            }
        }
        sites = rest;
    }
    // The host pages of the sites beyond reach, runs of them together.
    let host_page = fwe_kernel::mm::host_page_size();
    for at in beyond {
        let p = (start + at) & !(host_page - 1);
        match stats.beyond.last_mut() {
            Some((a, l)) if *a + *l >= p + host_page => {}
            Some((a, l)) if *a + *l == p => *l += host_page,
            _ => stats.beyond.push((p, host_page)),
        }
    }
    if let Some(d) = defer {
        // The pages earlier runs wrote as they first ran are written now,
        // while the range is still writable; the rest are owed.
        let host_page = fwe_kernel::mm::host_page_size();
        let first = start & !(host_page - 1);
        let kept_hot = hot.clone();
        let hot: std::collections::BTreeSet<u64> = hot.into_iter().collect();
        let mut owed = Vec::new();
        let mut written = Vec::new();
        for (at, (was, now)) in d.into_iter().filter(|(_, (was, now))| was != now) {
            if hot.contains(&((at - first) / host_page)) {
                // SAFETY: a word of the range, writable now (the caller's
                // guarantee); one not as the preparation found it is left.
                unsafe {
                    if (at as *const u32).read() == was {
                        (at as *mut u32).write(now);
                    }
                }
                written.push(at);
            } else {
                owed.push((at, was, now));
            }
        }
        // SAFETY: the pages are of the range, mapped.
        unsafe { flush_pages(written) };
        if let Some(key) = cache {
            fwe_kernel::lazycode::owe(owed, key, start, &kept_hot);
        }
    } else if from_file {
        // Mapped from its file by the host: the words changed in place,
        // and the sites' branches to their stubs, every one noted.
        // SAFETY: the pages are of the range, mapped.
        unsafe { flush_pages(patched.noted.iter().map(|&(off, ..)| start + off)) };
    } else {
        // Written as a whole (the loader's copies, memory the guest wrote):
        // all of it.
        // SAFETY: the range is mapped.
        unsafe { flush_icache(start, len) };
    }
    Ok(stats)
}

/// Invalidate the instruction cache for the pages holding the words at
/// `addrs` (in any order), neighbouring pages in one run: the cache is
/// walked a line at a time, and a page walked is a page brought in, so the
/// rest of a large library is left alone.
///
/// # Safety
/// The pages must be mapped.
unsafe fn flush_pages(addrs: impl IntoIterator<Item = u64>) {
    let page = fwe_kernel::mm::host_page_size();
    let pages: std::collections::BTreeSet<u64> =
        addrs.into_iter().map(|a| a & !(page - 1)).collect();
    let mut run: Option<(u64, u64)> = None;
    for p in pages {
        run = match run {
            Some((s, e)) if e == p => Some((s, p + page)),
            Some((s, e)) => {
                // SAFETY: the caller's guarantee.
                unsafe { flush_icache(s, e - s) };
                Some((p, p + page))
            }
            None => Some((p, p + page)),
        };
    }
    if let Some((s, e)) = run {
        // SAFETY: as above.
        unsafe { flush_icache(s, e - s) };
    }
}

/// Stubs for `group` (offsets from `base`) of a loaded image's code, whose
/// arena is `arena`: the number placed. A group no stub space reaches as a
/// whole is halved until its parts are placed; a site no stub space
/// reaches alone (in the middle of an image larger than a branch reaches
/// across) is a system call that keeps its trap, or goes into `beyond`
/// (its offset), its code to run by translation.
///
/// # Safety
/// As [`redirect`]'s.
unsafe fn place_in_image(
    base: u64,
    group: &[(u64, Site)],
    slots: (u32, u32),
    page: u64,
    near: (u64, u64),
    arena: &mut StubArena,
    beyond: &mut Vec<u64>,
) -> usize {
    // SAFETY: the caller's guarantee.
    if unsafe { redirect(base, group, slots, page, near, Some(arena), None) }.is_ok() {
        return group.len();
    }
    if let [(off, site)] = group {
        if !matches!(site, Site::Syscall { .. }) {
            beyond.push(*off);
        }
        return 0;
    }
    let (a, b) = group.split_at(group.len() / 2);
    // SAFETY: as above.
    unsafe {
        place_in_image(base, a, slots, page, near, arena, beyond)
            + place_in_image(base, b, slots, page, near, arena, beyond)
    }
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
    // A page more than the stubs take: room for call stubs in reach of
    // this code ([`call_stub`]).
    let used = ((group.len() * STUB_WORDS * 4) as u64).div_ceil(page) * page;
    let size = used + page;
    let reachable =
        |region: u64| region + size <= first + BRANCH_RANGE && region + BRANCH_RANGE > last + size;
    let region = match arena {
        Some(a) => match a.take(size, reachable) {
            Some(r) => r,
            // Every place in reach is in the arena's reservation, the
            // image's own or stubs' already: no room.
            None if a.covers(
                (last + size + 1).saturating_sub(BRANCH_RANGE),
                (first + BRANCH_RANGE).saturating_sub(size) + size,
            ) =>
            {
                let last_error = String::from("in reach is only the image itself");
                return Err(NoStubSpace { near: first, last_error });
            }
            None => find_region(size, page, lo, hi, reachable)
                .map_err(|last_error| NoStubSpace { near: first, last_error })?,
        },
        None => find_region(size, page, lo, hi, reachable)
            .map_err(|last_error| NoStubSpace { near: first, last_error })?,
    };

    // SAFETY: replacing the region just reserved by us with fresh writable
    // memory, carrying fwe's tag.
    let p = unsafe {
        libc::mmap(
            region as *mut libc::c_void,
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            STUB_TAG,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        let last_error = std::io::Error::last_os_error().to_string();
        return Err(NoStubSpace { near: first, last_error });
    }
    note_stub_region(region, region + size);
    let mut cursor = region;
    for &(offset, site) in group {
        let at = base + offset;
        note_site(at, site);
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
    if let Some(regions) = IMAGE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        regions.push(ImageRegion {
            at: region,
            size,
            sites: group.iter().map(|&(offset, site)| (base + offset, site)).collect(),
        });
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
    spare(region + used, region + size);
    Ok(())
}

/// A stub region of code being kept as an image
/// ([`fwe_kernel::Platform::image_begin`]): where it is, its size, and the
/// sites its stubs serve, in order.
struct ImageRegion {
    at: u64,
    size: u64,
    sites: Vec<(u64, Site)>,
}

/// The stub regions of the code being kept as an image, while some is.
static IMAGE: std::sync::Mutex<Option<Vec<ImageRegion>>> = std::sync::Mutex::new(None);

fn imaging() -> bool {
    IMAGE.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Code to be kept as an image is about to be prepared: its stub regions
/// are noted from now on, and each word is written at once.
pub fn image_begin() {
    *IMAGE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
}

/// The preparation [`image_begin`] began failed: nothing is kept.
pub fn image_abandon() {
    *IMAGE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The stub regions noted since [`image_begin`], which ends.
fn image_regions() -> Option<Vec<ImageRegion>> {
    IMAGE.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Encode site `s` for an image's layout.
fn put_site(e: &mut fwe_kernel::snapshot::Enc, s: Site) {
    let (kind, v) = match s {
        Site::ReadThreadPointer { rt } => (0, rt),
        Site::WriteThreadPointer { rt } => (1, rt),
        Site::X18 { insn } => (2, insn),
        Site::Syscall { .. } => (3, 0),
        Site::Flush { rt, .. } => (4, rt),
    };
    e.u32(kind);
    e.u32(v);
}

/// A site [`put_site`] encoded, a system call's calling `gate`.
fn get_site(d: &mut fwe_kernel::snapshot::Dec, gate: u64) -> Option<Site> {
    let (kind, v) = (d.u32(), d.u32());
    Some(match kind {
        0 => Site::ReadThreadPointer { rt: v },
        1 => Site::WriteThreadPointer { rt: v },
        2 => Site::X18 { insn: v },
        3 if gate != 0 => Site::Syscall { gate },
        4 if gate != 0 => Site::Flush { rt: v, gate },
        _ => return None,
    })
}

/// Encode `regions` as offsets from `origin`.
fn put_regions(e: &mut fwe_kernel::snapshot::Enc, regions: &[ImageRegion], origin: u64) {
    e.u64(regions.len() as u64);
    for r in regions {
        e.u64(r.at.wrapping_sub(origin));
        e.u64(r.size);
        e.u64(r.sites.len() as u64);
        for &(at, site) in &r.sites {
            e.u64(at.wrapping_sub(origin));
            put_site(e, site);
        }
    }
}

/// The regions [`put_regions`] encoded, placed from `origin`, their system
/// calls calling this process's gate; `None` if one cannot be made here.
fn get_regions(d: &mut fwe_kernel::snapshot::Dec, origin: u64) -> Option<Vec<ImageRegion>> {
    let gate = crate::syscall_gate();
    let n = d.count(24);
    let mut regions = Vec::with_capacity(n);
    for _ in 0..n {
        let (rel, size) = (d.u64(), d.u64());
        let m = d.count(16);
        let mut sites = Vec::with_capacity(m);
        for _ in 0..m {
            let at = origin.wrapping_add(d.u64());
            sites.push((at, get_site(d, gate)?));
        }
        regions.push(ImageRegion { at: origin.wrapping_add(rel), size, sites });
    }
    Some(regions)
}

/// Map stub region `r` (exactly where it was, or, without `fixed`, only if
/// nothing is there) and write its stubs for this process: false if it
/// cannot be.
fn place_region(r: &ImageRegion, fixed: bool, (slot, x18_slot): (u32, u32)) -> bool {
    let flags = libc::MAP_PRIVATE | libc::MAP_ANON | if fixed { libc::MAP_FIXED } else { 0 };
    // SAFETY: a fresh anonymous mapping of fwe's where the region was:
    // inside fwe's own reservation with `fixed`, else wherever the host
    // finds room, which must be that place.
    let p = unsafe {
        libc::mmap(
            r.at as *mut libc::c_void,
            r.size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            STUB_TAG,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return false;
    }
    if p as u64 != r.at {
        // SAFETY: the mapping just made, elsewhere.
        unsafe { libc::munmap(p, r.size as usize) };
        return false;
    }
    note_stub_region(r.at, r.at + r.size);
    // The guest's memory, as other stub regions are: an `execve` releases it.
    fwe_kernel::mm::track(r.at, r.size);
    let mut cursor = r.at;
    for &(at, site) in &r.sites {
        note_site(at, site);
        for (i, w) in rewrite::stub(site, slot, x18_slot, cursor, at + 4).iter().enumerate() {
            // SAFETY: inside the region just mapped, writable.
            unsafe { ((cursor + 4 * i as u64) as *mut u32).write(*w) };
        }
        cursor += (STUB_WORDS * 4) as u64;
    }
    true
}

/// Make placed stub regions executable and visible to instruction fetch.
fn finish_regions(regions: &[ImageRegion]) {
    for r in regions {
        if r.sites
            .iter()
            .any(|&(_, s)| matches!(s, Site::X18 { insn } if crate::decode::x18_writes_sp(insn)))
        {
            note_sp_stub_region(r.at, r.at + r.size);
        }
        // SAFETY: a stub region just written.
        unsafe {
            libc::mprotect(
                r.at as *mut libc::c_void,
                r.size as usize,
                libc::PROT_READ | libc::PROT_EXEC,
            );
            flush_icache(r.at, r.size);
        }
        let page = fwe_kernel::mm::host_page_size();
        spare(
            (r.at + (r.sites.len() * STUB_WORDS * 4) as u64).div_ceil(page) * page,
            r.at + r.size,
        );
    }
}

/// Map `len` bytes of image `file` from `offset` at `addr`, writable and
/// private (macOS maps no file executable at once; its pages stay the
/// host's cached ones until written).
fn map_image_pages(file: &std::fs::File, addr: u64, len: u64, offset: u64) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: replacing memory the caller owns for this code with the
    // image of it.
    let p = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            file.as_raw_fd(),
            offset as libc::off_t,
        )
    };
    p != libc::MAP_FAILED
}

/// The mapping [`image_begin`] began, `[addr, addr + len)`, is prepared:
/// its pages, and its stub regions as offsets from it with their sites,
/// are kept under `key`.
///
/// # Safety
/// The range must be readable guest memory.
pub unsafe fn keep_image(key: &[u8], addr: u64, len: u64) {
    let Some(regions) = image_regions() else { return };
    let mut e = fwe_kernel::snapshot::Enc::new();
    put_regions(&mut e, &regions, addr);
    // SAFETY: the caller's guarantee.
    let image = unsafe { std::slice::from_raw_parts(addr as *const u8, len as usize) };
    fwe_kernel::prepcache::store_image(key, &e.into_bytes(), image);
}

/// Map the image kept under `key` at `[addr, addr + len)` with host
/// protections `prot`, its stub regions at their places with stubs written
/// for this process: `Ok(false)`, with nothing changed, if there is none
/// or a place is taken; an error (the host's errno) if the image replaced
/// the mapping but could not be given its protections.
pub fn map_image(
    key: &[u8],
    addr: u64,
    len: u64,
    prot: i32,
    slots: (u32, u32),
) -> Result<bool, i32> {
    let Some((layout, file)) = fwe_kernel::prepcache::open_image(key, len) else {
        return Ok(false);
    };
    let mut d = fwe_kernel::snapshot::Dec::new(&layout);
    let Some(regions) = get_regions(&mut d, addr) else { return Ok(false) };
    if d.finish().is_err() {
        return Ok(false);
    }
    // The stub regions first, each only where nothing is.
    let undo = |placed: &[ImageRegion]| {
        for r in placed {
            // SAFETY: a region this call mapped.
            unsafe { libc::munmap(r.at as *mut libc::c_void, r.size as usize) };
        }
    };
    for (i, r) in regions.iter().enumerate() {
        if !place_region(r, false, slots) {
            undo(&regions[..i]);
            return Ok(false);
        }
    }
    if !map_image_pages(&file, addr, len, 0) {
        undo(&regions);
        return Ok(false);
    }
    // SAFETY: the mapping just made.
    if unsafe { libc::mprotect(addr as *mut libc::c_void, len as usize, prot) } != 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOMEM);
        undo(&regions);
        return Err(e);
    }
    finish_regions(&regions);
    Ok(true)
}

/// The loader's image of a program (see [`crate::loader::load`]): its runs
/// of pages `runs` (address and length), loaded from `base` with the stub
/// arena `arena` as its stubs left it and its code `translated` to run by
/// translation, kept under `key` once prepared.
///
/// # Safety
/// The runs must be readable memory.
pub unsafe fn keep_load_image(
    key: &[u8],
    base: u64,
    runs: &[(u64, u64)],
    arena: &StubArena,
    translated: &[(u64, u64)],
) {
    let Some(regions) = image_regions() else { return };
    let mut e = fwe_kernel::snapshot::Enc::new();
    e.u64(arena.next - base);
    e.u64(arena.front_end.wrapping_sub(base));
    e.u64(translated.len() as u64);
    for &(at, len) in translated {
        e.u64(at - base);
        e.u64(len);
    }
    put_regions(&mut e, &regions, base);
    let mut image = Vec::with_capacity(runs.iter().map(|r| r.1 as usize).sum());
    for &(at, len) in runs {
        // SAFETY: the caller's guarantee.
        image.extend_from_slice(unsafe {
            std::slice::from_raw_parts(at as *const u8, len as usize)
        });
    }
    fwe_kernel::prepcache::store_image(key, &e.into_bytes(), &image);
}

/// Where a kept image's stubs left its arenas ([`map_load_image`]).
pub struct MappedImage {
    /// The arena's next free place after the image.
    pub arena_next: u64,
    /// The end of what is free of the arena before the image.
    pub front_end: u64,
    /// Its code that runs by translation.
    pub translated: Vec<(u64, u64)>,
}

/// Map the loader's image kept under `key`, loaded from `base`, over runs
/// `runs` of fwe's own reservation `[start, end)` (mapped writable), with
/// its stubs where they were (in the reservation's arenas, or, where they
/// ran out, wherever nothing is): the arenas' next free places (after the
/// image, and the end of what is free before it) and the code to run by
/// translation, or `None` if there is no such image or a place is taken
/// (the runs may then hold some of it, to be written over).
pub fn map_load_image(
    key: &[u8],
    base: u64,
    (start, end): (u64, u64),
    runs: &[(u64, u64)],
    slots: (u32, u32),
) -> Option<MappedImage> {
    let total = runs.iter().map(|r| r.1).sum();
    let (layout, file) = fwe_kernel::prepcache::open_image(key, total)?;
    let mut d = fwe_kernel::snapshot::Dec::new(&layout);
    let arena_next = base + d.u64();
    let front_end = base.wrapping_add(d.u64());
    let translated: Vec<(u64, u64)> = (0..d.count(16)).map(|_| (base + d.u64(), d.u64())).collect();
    let regions = get_regions(&mut d, base)?;
    d.finish().ok()?;
    let mut offset = 0;
    for &(at, len) in runs {
        if !map_image_pages(&file, at, len, offset) {
            return None;
        }
        offset += len;
    }
    for (i, r) in regions.iter().enumerate() {
        let ours = r.at >= start && r.at + r.size <= end;
        if !place_region(r, ours, slots) {
            for r in regions[..i].iter().filter(|r| r.at < start || r.at + r.size > end) {
                // SAFETY: a region this call mapped outside the reservation.
                unsafe { libc::munmap(r.at as *mut libc::c_void, r.size as usize) };
            }
            return None;
        }
    }
    finish_regions(&regions);
    Some(MappedImage { arena_next, front_end, translated })
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
        // No sites: a page for call stubs.
        assert_eq!(stub_space(&[0u8; 64], page), page);
        // One: its stub's page, rounding room, and a page for call stubs.
        let one = 0xd53b_d049u32.to_le_bytes(); // mrs x9, tpidr_el0
        assert_eq!(stub_space(&one, page), 3 * page);
    }

    #[test]
    fn arena_hands_out_reachable_space() {
        let mut arena = StubArena { next: 0x1000, end: 0x3000, front_start: 0, front_end: 0 };
        assert_eq!(arena.take(0x1000, |_| true), Some(0x1000));
        assert_eq!(arena.take(0x1000, |_| false), None);
        assert_eq!(arena.take(0x1000, |_| true), Some(0x2000));
        assert_eq!(arena.take(0x1000, |_| true), None);
        // Before the image too: from its end down, where reachable.
        let mut arena =
            StubArena { next: 0x9000, end: 0xa000, front_start: 0x1000, front_end: 0x4000 };
        assert_eq!(arena.take(0x1000, |at| at < 0x5000), Some(0x3000));
        assert_eq!(arena.take(0x1000, |at| at == 0x9000), Some(0x9000));
        assert_eq!(arena.take(0x1000, |_| true), Some(0x2000));
        assert_eq!(arena.take(0x2000, |_| true), None);
        assert_eq!(arena.take(0x1000, |_| true), Some(0x1000));
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
        assert_eq!(stats, Prepared { syscalls: 1, stubs, ..Prepared::default() });
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
