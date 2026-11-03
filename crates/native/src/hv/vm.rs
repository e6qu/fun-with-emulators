//! The VM: its guest-physical address space, the stage-1 tables and the
//! exception vector every vCPU shares.
//!
//! Guest virtual addresses equal guest-physical ones. Stage 1 maps the whole
//! 40-bit space as identity 32 MiB blocks of normal memory, all accessible to
//! EL0, so it never faults; what the guest may actually touch, and how, is
//! decided at stage 2 by which host memory is mapped where
//! ([`map`]/[`protect`]/[`unmap`]). An access to anything else stops the vCPU
//! with an abort the backend turns into `SIGSEGV`.
//!
//! The top 32 MiB block holds fwe's own structures — the tables themselves
//! and the vector page — and is mapped for EL1 only. Every exception the
//! guest takes at EL0 enters that vector, which executes `hvc #0`: the vCPU
//! stops and the backend reads `ESR_EL1` to see what happened.

use super::ffi::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Size of the guest-physical (and virtual) address space.
pub const IPA_BITS: u32 = 40;
pub const IPA_LIMIT: u64 = 1 << IPA_BITS;
/// Granule of the stage-1 tables, and of guest pages.
const GRANULE: u64 = 16 << 10;
/// Span of one level-2 block (16 KiB granule).
const BLOCK: u64 = 32 << 20;
/// fwe's block: tables and vectors, out of EL0's reach.
pub const SYS_BASE: u64 = IPA_LIMIT - BLOCK;
/// Level-1 table, then sixteen level-2 tables, then the vector page.
const L1_OFF: u64 = 0;
const L2_OFF: u64 = GRANULE;
const L1_ENTRIES: u64 = IPA_LIMIT / (64 << 30); // 16 entries of 64 GiB
const VECTORS_OFF: u64 = L2_OFF + L1_ENTRIES * GRANULE;
const SYS_SIZE: u64 = VECTORS_OFF + GRANULE;
pub const VECTORS: u64 = SYS_BASE + VECTORS_OFF;
pub const TTBR0: u64 = SYS_BASE + L1_OFF;

// Descriptor bits (VMSAv8-64, 16 KiB granule).
const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const AP_EL0_RW: u64 = 0b01 << 6;
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

/// `hvc #0` then `b .`, at each of the sixteen vector entries.
const HVC_0: u32 = 0xd400_0002;
const B_SELF: u32 = 0x1400_0000;

/// The guest's mappings, `start -> (end, Linux prot, host address)`, so a
/// range can be mapped again after its host memory is replaced.
static MAPPINGS: Mutex<BTreeMap<u64, (u64, u64, u64)>> = Mutex::new(BTreeMap::new());

fn mappings() -> std::sync::MutexGuard<'static, BTreeMap<u64, (u64, u64, u64)>> {
    MAPPINGS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Every guest mapping as `(guest, len, Linux prot, host)`, for a fork child
/// to map again in its own VM.
pub fn mapping_list() -> Vec<(u64, u64, u64, u64)> {
    mappings().iter().map(|(&s, &(e, prot, host))| (s, e - s, prot, host)).collect()
}

/// Host address of fwe's tables and vectors, once built.
static SYS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Create this process's VM, with its tables and vectors mapped.
fn create_vm(sys: *mut libc::c_void) -> Result<(), String> {
    // SAFETY: a fresh configuration object, then a VM for this process.
    unsafe {
        let cfg = hv_vm_config_create();
        check(hv_vm_config_set_ipa_size(cfg, IPA_BITS), "hv_vm_config_set_ipa_size")?;
        check(hv_vm_create(cfg), "hv_vm_create")?;
    }
    let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
    // SAFETY: mapping the tables and vectors at the top of the IPA space.
    let mapped = check(unsafe { hv_vm_map(sys, SYS_BASE, SYS_SIZE as usize, flags) }, "hv_vm_map");
    if mapped.is_err() {
        // No VM is left behind on failure: it has no vCPU yet.
        // SAFETY: destroying the VM just created.
        unsafe { hv_vm_destroy() };
    }
    mapped
}

/// Create the VM and its shared structures. Called once per process.
pub fn create() -> Result<(), String> {
    // SAFETY: fresh host memory for the tables and vectors, never freed.
    let sys = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SYS_SIZE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if sys == libc::MAP_FAILED {
        return Err("allocating the VM's tables failed".into());
    }
    let word = |off: u64, v: u64| {
        // SAFETY: `off` lies within the SYS_SIZE mapping and is 8-aligned.
        unsafe { (sys.cast::<u8>().add(off as usize) as *mut u64).write(v) }
    };
    for i in 0..L1_ENTRIES {
        let l2 = L2_OFF + i * GRANULE;
        word(L1_OFF + i * 8, (SYS_BASE + l2) | DESC_TABLE);
        for j in 0..GRANULE / 8 {
            let va = i * (64 << 30) + j * BLOCK;
            let attrs = if va == SYS_BASE {
                // EL1 only (AP 00): the vectors execute here.
                UXN
            } else {
                AP_EL0_RW | PXN
            };
            word(l2 + j * 8, va | DESC_BLOCK | SH_INNER | AF | attrs);
        }
    }
    for e in 0..16u64 {
        let at = VECTORS_OFF + e * 0x80;
        // SAFETY: within the mapping, 4-aligned.
        unsafe {
            (sys.cast::<u8>().add(at as usize) as *mut u32).write(HVC_0);
            (sys.cast::<u8>().add(at as usize + 4) as *mut u32).write(B_SELF);
        }
    }
    SYS.store(sys as u64, std::sync::atomic::Ordering::SeqCst);
    create_vm(sys)
}

fn flags(prot: u64) -> u64 {
    use fwe_abi::mman::*;
    let mut f = 0;
    if prot & PROT_READ != 0 {
        f |= HV_MEMORY_READ;
    }
    if prot & PROT_WRITE != 0 {
        f |= HV_MEMORY_WRITE | HV_MEMORY_READ;
    }
    if prot & PROT_EXEC != 0 {
        f |= HV_MEMORY_EXEC | HV_MEMORY_READ;
    }
    f
}

/// Map host memory `[host, host + len)` at guest address `guest` with Linux
/// protections `prot`. Fails with a Linux errno.
pub fn map(guest: u64, host: u64, len: u64, prot: u64) -> Result<(), i32> {
    if guest.checked_add(len).is_none_or(|end| end > SYS_BASE) {
        return Err(fwe_abi::errno::ENOMEM);
    }
    // Replace whatever was mapped there.
    unmap(guest, len);
    if prot != 0 {
        // SAFETY: the guest's own memory, mapped into its address space.
        let rc = unsafe { hv_vm_map(host as *mut _, guest, len as usize, flags(prot)) };
        if rc != 0 {
            return Err(fwe_abi::errno::ENOMEM);
        }
    }
    mappings().insert(guest, (guest + len, prot, host));
    Ok(())
}

/// Remove guest addresses `[guest, guest + len)` from the VM.
pub fn unmap(guest: u64, len: u64) {
    let end = guest + len;
    let mut m = mappings();
    let hit: Vec<(u64, (u64, u64, u64))> = m
        .range(..end)
        .rev()
        .take_while(|&(_, &(e, _, _))| e > guest)
        .map(|(&s, &v)| (s, v))
        .collect();
    for (s, (e, prot, host)) in hit {
        m.remove(&s);
        let (lo, hi) = (s.max(guest), e.min(end));
        if prot != 0 {
            // SAFETY: removing part of a mapping this module made.
            unsafe { hv_vm_unmap(lo, (hi - lo) as usize) };
        }
        if s < lo {
            m.insert(s, (lo, prot, host));
        }
        if e > hi {
            m.insert(hi, (e, prot, host + (hi - s)));
        }
    }
}

/// Change the protections of guest addresses `[guest, guest + len)`. Any of
/// it not mapped in the VM yet (the break's reservation above the current
/// break, say) is mapped now, as the host's `mprotect` of the same memory
/// made it accessible there.
pub fn protect(guest: u64, len: u64, prot: u64) {
    let _ = map(guest, fwe_kernel::uaccess::g2h(guest), len, prot);
}

/// Map `[guest, guest + len)` again with the same protections, after the
/// host memory behind it was replaced.
pub fn refresh(guest: u64, len: u64) {
    let pieces: Vec<(u64, u64, u64, u64)> = {
        let m = mappings();
        m.range(..guest + len)
            .rev()
            .take_while(|&(_, &(e, _, _))| e > guest)
            .map(|(&s, &(e, prot, host))| {
                let (lo, hi) = (s.max(guest), e.min(guest + len));
                (lo, hi, host + (lo - s), prot)
            })
            .collect()
    };
    for (lo, hi, host, prot) in pieces {
        let _ = map(lo, host, hi - lo, prot);
    }
}

/// Values for the vCPU's EL1 system registers: the translation regime above,
/// FP/SIMD enabled at EL0, and EL0 allowed the cache, timer and `dc zva`
/// operations Linux allows user space.
pub fn system_registers() -> [(hv_sys_reg_t, u64); 7] {
    // T0SZ = 24 (40-bit), IRGN0/ORGN0 write-back, inner shareable, 16 KiB
    // granule, no TTBR1 walks, 40-bit physical addresses, top byte ignored
    // (as Linux does for user space).
    let tcr = 24
        | (1 << 8)
        | (1 << 10)
        | (0b11 << 12)
        | (0b10 << 14)
        | (1 << 23)
        | (0b010 << 32)
        | (1 << 37);
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
    [
        (HV_SYS_REG_MAIR_EL1, 0xff), // attribute 0: normal, write-back
        (HV_SYS_REG_TCR_EL1, tcr),
        (HV_SYS_REG_TTBR0_EL1, TTBR0),
        (HV_SYS_REG_VBAR_EL1, VECTORS),
        (HV_SYS_REG_CPACR_EL1, 0b11 << 20), // FPEN: no FP/SIMD traps
        (HV_SYS_REG_CNTKCTL_EL1, 0b11),     // EL0 may read the counters
        (HV_SYS_REG_SCTLR_EL1, sctlr),
    ]
}
