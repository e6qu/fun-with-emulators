//! The VM: its guest-physical (IPA) layout, stage 2, the guest's stage-1
//! page tables, and the code fwe runs at EL1.
//!
//! Stage 2 is set up once, when the VM is made, and never changes while it
//! runs (only a shared segment adds or removes a mapping of its own): the
//! framework keeps the host pages it found at mapping time, and the
//! runtimes that run Linux programs this way without trouble (hyper-linux,
//! elfuse) never change it either. The IPA space holds, in order:
//!
//! - the slab ([`super::window`]): all private guest memory, at IPA
//!   `host - window::LO`;
//! - room for shared segments (`MAP_SHARED` memory, each mapped once);
//! - fwe's region at the top: the page-table pool and the code page.
//!
//! What the guest sees is its stage-1 tables ([`super::pagetables`], 4 KiB
//! pages): guest `mmap`, `munmap` and `mprotect` edit them, and nothing
//! else. The guest's addresses translate to IPAs; a guest page whose host
//! memory is in the slab at the same address (most of them) sits at IPA
//! `va - window::LO`.
//!
//! The code page, mapped for EL1 only at the top of the guest's address
//! space, holds the exception vector — every exception the guest takes at
//! EL0 runs `hvc #2`, so the vCPU stops and the backend reads `ESR_EL1` —
//! and the TLB stub: after the tables lost a translation, a vCPU resumes
//! through it, so `tlbi vmalle1is` invalidates every vCPU's TLBs before the
//! guest goes on (see [`Flush`]).

use super::ffi::*;
use super::pagetables::{PAGE, PageTables, Perms, Pool, VA_LIMIT};
use super::window;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The host's page size, the granule of stage 2.
const HOST_PAGE: u64 = 16 << 10;
/// fwe's region: the page-table pool, then the code page.
const POOL_SIZE: u64 = 512 << 20;
const SYS_SIZE: u64 = POOL_SIZE + HOST_PAGE;
/// Where the code page sits in the guest's address space (EL1 only).
pub const CODE_VA: u64 = VA_LIMIT - PAGE;
/// The TLB stub's offset in the code page, after the sixteen vectors.
const STUB_OFF: u64 = 0x800;

/// The IPA layout of this process's VM.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub ipa_bits: u32,
    /// Bytes of slab (the window's size).
    pub slab: u64,
    /// IPA range for shared segments.
    pub seg_base: u64,
    pub seg_end: u64,
    /// IPA of fwe's region.
    pub sys: u64,
}

static LAYOUT: OnceLock<Layout> = OnceLock::new();

/// The IPA layout this host allows: as many IPA bits as it offers, up to
/// 40 (the guest's address space). An M1 or M2 offers 36 (64 GiB).
pub fn layout() -> Result<Layout, String> {
    if let Some(l) = LAYOUT.get() {
        return Ok(*l);
    }
    let mut max = 0u32;
    // SAFETY: an out-parameter for the framework.
    check(unsafe { hv_vm_config_get_max_ipa_size(&mut max) }, "hv_vm_config_get_max_ipa_size")?;
    let bits = max.min(40);
    if bits < 36 {
        return Err(format!("the host offers only {bits}-bit guest-physical addresses"));
    }
    let space = 1u64 << bits;
    // Slab 7/16 of the space (448 GiB of 1 TiB), segments 1/4, the rest
    // spare below fwe's region.
    let slab = space / 16 * 7;
    let seg_base = slab;
    let seg_end = seg_base + space / 4;
    let sys = space - SYS_SIZE;
    let l = Layout { ipa_bits: bits, slab, seg_base, seg_end, sys };
    Ok(*LAYOUT.get_or_init(|| l))
}

/// The IPA of slab address `host`.
pub fn slab_ipa(host: u64) -> u64 {
    host - window::LO
}

// --- The page-table pool ----------------------------------------------------

/// Tables in fwe's region: a bump allocator with a free list.
struct SysPool {
    host: u64,
    ipa: u64,
    next: u64,
    free: Vec<u64>,
}

impl Pool for SysPool {
    fn alloc(&mut self) -> Option<(u64, *mut u64)> {
        let ipa = match self.free.pop() {
            Some(ipa) => ipa,
            None if self.next + PAGE <= POOL_SIZE => {
                self.next += PAGE;
                self.ipa + self.next - PAGE
            }
            None => return None,
        };
        let h = self.host(ipa);
        // SAFETY: a page-sized table inside fwe's region.
        unsafe { std::ptr::write_bytes(h, 0, 512) };
        Some((ipa, h))
    }
    fn free(&mut self, ipa: u64) {
        self.free.push(ipa);
    }
    fn host(&self, ipa: u64) -> *mut u64 {
        (self.host + (ipa - self.ipa)) as *mut u64
    }
}

// SAFETY: the pool's memory is fwe's, reached only under the TABLES lock.
unsafe impl Send for SysPool {}

static TABLES: Mutex<Option<PageTables<SysPool>>> = Mutex::new(None);

fn tables() -> MutexGuard<'static, Option<PageTables<SysPool>>> {
    TABLES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Host address of fwe's region, once made.
static SYS_HOST: AtomicU64 = AtomicU64::new(0);

// --- TLB invalidation -------------------------------------------------------

/// Generations of the tables: bumped when they lose a translation; a vCPU
/// resuming while its last flush is older goes through the TLB stub.
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// The newest generation a completed flush covers.
static FLUSHED: AtomicU64 = AtomicU64::new(0);

/// A flush a vCPU is taking: dispatched by [`Flush::needed`], done once the
/// vCPU next stops (the stub runs before anything else).
#[derive(Debug, Clone, Copy)]
pub struct Flush {
    generation: u64,
}

impl Flush {
    /// The flush a vCPU must take before resuming the guest, if any.
    pub fn needed() -> Option<Flush> {
        let g = GENERATION.load(SeqCst);
        (g != FLUSHED.load(SeqCst)).then_some(Flush { generation: g })
    }

    /// The vCPU ran the stub: every translation the tables lost up to this
    /// generation is gone from every TLB, and emptied tables can be reused.
    pub fn done(self) {
        if FLUSHED.fetch_max(self.generation, SeqCst) < self.generation
            && let Some(t) = tables().as_mut()
        {
            t.flushed(self.generation);
        }
        flushed_hook(self.generation);
    }
}

/// Called when a flush completes, so memory given back before it can be
/// reused (set by the memory manager).
static FLUSHED_HOOK: OnceLock<fn(u64)> = OnceLock::new();

pub fn on_flushed(f: fn(u64)) {
    let _ = FLUSHED_HOOK.set(f);
}

fn flushed_hook(generation: u64) {
    if let Some(f) = FLUSHED_HOOK.get() {
        f(generation);
    }
}

/// The generation an edit that lost a translation belongs to; memory it
/// freed is reusable once [`flushed`] reaches it.
pub fn generation() -> u64 {
    GENERATION.load(SeqCst)
}

/// The newest generation a completed flush covers: translations lost up
/// to it are in no TLB.
pub fn flushed_generation() -> u64 {
    FLUSHED.load(SeqCst)
}

/// The permissions the tables give guest page `va`, if it is mapped.
pub fn page_perms(va: u64) -> Option<Perms> {
    tables().as_ref()?.translate(va).map(|(_, p)| p)
}

/// Have every vCPU invalidate its TLBs before it next runs the guest,
/// although the tables lost nothing: a TLB holds an entry older than the
/// tables' (permissions they gave since, which a TLB may keep the old
/// ones of). The generation to wait for.
pub fn request_flush() -> u64 {
    // Under the tables' lock: an edit owns the generation it bumps to, and
    // a flush dispatched for this one must not count as covering it.
    let _t = tables();
    GENERATION.fetch_add(1, SeqCst) + 1
}

/// No vCPU can hold a translation (none has run, or none runs now): every
/// lost translation counts as flushed.
pub fn flushed_without_vcpus() {
    Flush { generation: GENERATION.load(SeqCst) }.done();
}

// --- Editing the guest's address space --------------------------------------

/// Linux protections as page permissions.
pub fn perms(prot: u64) -> Perms {
    use fwe_abi::mman::*;
    let read = prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0;
    Perms {
        // Write implies read, and so does exec, as Linux on arm64 gives them.
        read,
        write: prot & PROT_WRITE != 0,
        exec: prot & PROT_EXEC != 0,
        guarded: prot & PROT_BTI != 0,
    }
}

/// Edit the tables. An edit that loses a translation belongs to the
/// generation it bumps to, made under the tables' lock: a flush dispatched
/// before the bump does not cover it.
fn edit<T>(
    f: impl FnOnce(&mut PageTables<SysPool>) -> Result<(super::pagetables::Change, T), i32>,
) -> Result<T, i32> {
    let mut t = tables();
    let t = t.as_mut().ok_or(fwe_abi::errno::ENOMEM)?;
    t.set_generation(GENERATION.load(SeqCst) + 1);
    match f(t) {
        Ok((change, out)) => {
            if change.flush {
                GENERATION.fetch_add(1, SeqCst);
            }
            Ok(out)
        }
        Err(e) => {
            // It may have changed some of the range before it failed.
            GENERATION.fetch_add(1, SeqCst);
            Err(e)
        }
    }
}

/// Map guest pages `[va, va + len)` to IPAs from `ipa` with `p`.
pub fn map_pages(va: u64, len: u64, ipa: u64, p: Perms) -> Result<(), i32> {
    edit(|t| Ok((t.map(va, len, ipa, p).map_err(|()| fwe_abi::errno::ENOMEM)?, ())))
}

/// Unmap guest pages `[va, va + len)`.
pub fn unmap_pages(va: u64, len: u64) {
    let _ = edit(|t| Ok((t.unmap(va, len), ())));
}

// --- Shared segments ---------------------------------------------------------

/// Segment IPA ranges in use, `start -> end`.
static SEGMENTS: Mutex<std::collections::BTreeMap<u64, u64>> =
    Mutex::new(std::collections::BTreeMap::new());

/// Map host memory `[host, host + len)` (host-page aligned) into the VM as
/// a shared segment, returning its IPA. One of the two stage-2 changes
/// while the VM runs; its pages are the memory a `MAP_SHARED` mapping
/// shares. Host memory that is not `writable` (a file opened read-only)
/// is mapped readable and executable only: the framework refuses more.
pub fn map_segment(host: u64, len: u64, writable: bool) -> Result<u64, i32> {
    let l = layout().map_err(|_| fwe_abi::errno::ENOMEM)?;
    let len = len.div_ceil(HOST_PAGE) * HOST_PAGE;
    let mut segs = SEGMENTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut at = l.seg_base;
    for (&s, &e) in segs.iter() {
        if s >= at + len {
            break;
        }
        at = at.max(e);
    }
    if at + len > l.seg_end {
        return Err(fwe_abi::errno::ENOMEM);
    }
    let flags = segment_flags(writable);
    // SAFETY: host memory the caller keeps mapped until `unmap_segment`.
    let rc = unsafe { hv_vm_map(host as *mut _, at, len as usize, flags) };
    if rc != 0 {
        return Err(fwe_abi::errno::ENOMEM);
    }
    segs.insert(at, at + len);
    Ok(at)
}

/// Map a fork parent's segment again in the child, at the parent's IPA.
pub fn map_segment_at(host: u64, len: u64, ipa: u64, writable: bool) -> Result<(), i32> {
    let mut segs = SEGMENTS.lock().unwrap_or_else(|e| e.into_inner());
    let flags = segment_flags(writable);
    // SAFETY: host memory the caller keeps mapped until `unmap_segment`.
    let rc = unsafe { hv_vm_map(host as *mut _, ipa, len as usize, flags) };
    if rc != 0 {
        return Err(fwe_abi::errno::ENOMEM);
    }
    segs.insert(ipa, ipa + len);
    Ok(())
}

/// The stage-2 permissions of a segment.
fn segment_flags(writable: bool) -> u64 {
    HV_MEMORY_READ | HV_MEMORY_EXEC | if writable { HV_MEMORY_WRITE } else { 0 }
}

/// Take the segment at `ipa` out of the VM; the host may then free its
/// memory (the framework invalidates its translations of it).
pub fn unmap_segment(ipa: u64) {
    let mut segs = SEGMENTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(end) = segs.remove(&ipa) {
        // SAFETY: a mapping `map_segment` made.
        unsafe { hv_vm_unmap(ipa, (end - ipa) as usize) };
    }
}

// --- Making the VM --------------------------------------------------------------

/// `hvc #2` then `b .`, at each of the sixteen vector entries: `hvc #0` is
/// avoided, as the framework may take it for a firmware call when `x0`
/// holds a function number (found by Carrick).
const HVC_2: u32 = 0xd400_0042;
const B_SELF: u32 = 0x1400_0000;
/// The TLB stub: `tlbi vmalle1is; dsb ish; isb; eret`.
const STUB: [u32; 4] = [0xd508_831f, 0xd503_3b9f, 0xd503_3fdf, 0xd69f_03e0];

/// The address the vector's entries are at, for `VBAR_EL1`.
pub const VECTORS: u64 = CODE_VA;
/// The TLB stub's address.
pub const TLB_STUB: u64 = CODE_VA + STUB_OFF;

/// Create this process's VM: its stage 2 (the slab and fwe's region, each
/// mapped once), the page tables and the code page. Called once per
/// process, after [`window::reserve`].
pub fn create() -> Result<(), String> {
    let l = layout()?;
    let sys = alloc_host(SYS_SIZE)?;
    let code = sys + POOL_SIZE;
    for e in 0..16u64 {
        // SAFETY: within the code page, 4-aligned.
        unsafe {
            ((code + e * 0x80) as *mut u32).write(HVC_2);
            ((code + e * 0x80 + 4) as *mut u32).write(B_SELF);
        }
    }
    for (i, w) in STUB.iter().enumerate() {
        // SAFETY: within the code page, 4-aligned.
        unsafe { ((code + STUB_OFF + 4 * i as u64) as *mut u32).write(*w) };
    }
    SYS_HOST.store(sys, SeqCst);
    let pool = SysPool { host: sys, ipa: l.sys, next: 0, free: Vec::new() };
    let mut t = PageTables::new(pool).ok_or("making the page tables failed")?;
    t.map_el1_code(CODE_VA, l.sys + POOL_SIZE).map_err(|()| "mapping fwe's code failed")?;
    *tables() = Some(t);

    // SAFETY: a fresh configuration object, then a VM for this process.
    unsafe {
        let cfg = hv_vm_config_create();
        check(hv_vm_config_set_ipa_size(cfg, l.ipa_bits), "hv_vm_config_set_ipa_size")?;
        check(hv_vm_create(cfg), "hv_vm_create")?;
    }
    let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
    // SAFETY: the slab and fwe's region, host memory kept for the process's
    // life, each mapped once.
    let mapped = unsafe {
        check(hv_vm_map(window::LO as *mut _, 0, l.slab as usize, flags), "hv_vm_map (slab)")
            .and_then(|()| {
                check(hv_vm_map(sys as *mut _, l.sys, SYS_SIZE as usize, flags), "hv_vm_map")
            })
    };
    if mapped.is_err() {
        // No VM is left behind on failure: it has no vCPU yet.
        // SAFETY: destroying the VM just created.
        unsafe { hv_vm_destroy() };
    }
    mapped
}

/// Fresh zero-fill host memory of `len` bytes, kept for the process's life.
fn alloc_host(len: u64) -> Result<u64, String> {
    // SAFETY: a fresh anonymous mapping, never unmapped.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err("allocating the VM's own memory failed".into());
    }
    Ok(p as u64)
}

/// What the VM offers the guest beyond the base architecture, from its
/// vCPUs' ID registers (not the host's): pointer authentication of
/// addresses (`pac`) and generic (`pacg`), and BTI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    pub pac: bool,
    pub pacg: bool,
    pub bti: bool,
}

impl Features {
    /// From `ID_AA64ISAR1_EL1` (APA, API, GPA, GPI) and `ID_AA64PFR1_EL1`
    /// (BT).
    pub fn from_id_registers(isar1: u64, pfr1: u64) -> Features {
        let field = |v: u64, at: u32| (v >> at) & 0xf;
        Features {
            pac: field(isar1, 4) != 0 || field(isar1, 8) != 0,
            pacg: field(isar1, 24) != 0 || field(isar1, 28) != 0,
            bti: field(pfr1, 0) != 0,
        }
    }
}

static FEATURES: OnceLock<Features> = OnceLock::new();

/// Record what the VM offers (from the first vCPU).
pub fn set_features(f: Features) -> Features {
    *FEATURES.get_or_init(|| f)
}

/// What the VM offers, once a vCPU has been asked.
pub fn features() -> Features {
    FEATURES.get().copied().unwrap_or_default()
}

/// Values for the vCPU's EL1 system registers: the translation regime of
/// [`super::pagetables`], FP/SIMD enabled at EL0, EL0 allowed the cache,
/// timer and `dc zva` operations Linux allows user space, and pointer
/// authentication and BTI as Linux enables them where the VM offers them.
pub fn system_registers() -> Vec<(hv_sys_reg_t, u64)> {
    let l = layout().expect("the layout is known once the VM exists");
    let ips = match l.ipa_bits {
        36 => 0b001,
        40 => 0b010,
        _ => 0b001,
    };
    let tcr = (super::pagetables::tcr() & !(0b111 << 32)) | (ips << 32);
    let root = tables().as_ref().map_or(0, |t| t.root());
    // M, C, SA0, I, DZE, UCT, nTWI, nTWE, UCI, plus the RES1 bits.
    let res1 = (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23) | (1 << 28) | (1 << 29);
    let sctlr = res1
        | 1
        | (1 << 2)
        | (1 << 4)
        | (1 << 12)
        | (1 << 14)
        | (1 << 15)
        | (1 << 16)
        | (1 << 18)
        | (1 << 26);
    let f = features();
    // EnIA, EnIB, EnDA, EnDB; BT0 (PACIxSP is no landing pad for an
    // indirect branch through another register, as Linux sets it).
    let pac = if f.pac { (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13) } else { 0 };
    let bti = if f.bti { 1 << 35 } else { 0 };
    let sctlr = sctlr | pac | bti;
    vec![
        (HV_SYS_REG_MAIR_EL1, 0xff), // attribute 0: normal, write-back
        (HV_SYS_REG_TCR_EL1, tcr),
        (HV_SYS_REG_TTBR0_EL1, root),
        (HV_SYS_REG_VBAR_EL1, VECTORS),
        (HV_SYS_REG_CPACR_EL1, 0b11 << 20), // FPEN: no FP/SIMD traps
        (HV_SYS_REG_CNTKCTL_EL1, 0b11),     // EL0 may read the counters
        (HV_SYS_REG_SCTLR_EL1, sctlr),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_and_vectors_are_the_instructions_named() {
        // Encodings from the assembler (clang -c):
        //   hvc #2 = d4000042, tlbi vmalle1is = d508831f, dsb ish = d5033b9f,
        //   isb = d5033fdf, eret = d69f03e0.
        assert_eq!(HVC_2, 0xd400_0042);
        assert_eq!(STUB, [0xd508_831f, 0xd503_3b9f, 0xd503_3fdf, 0xd69f_03e0]);
    }
}
