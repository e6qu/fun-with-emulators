//! Mapping an ELF image into the host process at its guest addresses.

use crate::prepare::{StubArena, stub_space};
use fwe_elf::{Elf, LoadPlan, PF_R, PF_W, PF_X};
use std::fmt;

/// A loaded image.
#[derive(Debug, Clone, Copy)]
pub struct Loaded {
    /// Difference between run-time and link-time addresses (0 for ET_EXEC).
    pub bias: u64,
    pub entry: u64,
    /// Run-time address of the program headers, if they are loaded.
    pub phdr: Option<u64>,
    pub phnum: u16,
    pub phent: u16,
    /// End of the highest segment.
    pub end: u64,
    /// Address of the lowest loaded segment (the ELF load base, for `AT_BASE`).
    pub load_base: u64,
    /// What is left of the stub space reserved after the image.
    pub stub_arena: StubArena,
}

#[derive(Debug)]
pub enum LoadError {
    /// The fixed addresses an ET_EXEC image needs are not available.
    AddressUnavailable {
        start: u64,
        len: u64,
        reason: fwe_kernel::host::ReserveError,
    },
    /// The image is linked below 4 GiB, which macOS reserves in every arm64
    /// process (`__PAGEZERO`).
    BelowHostMinimum {
        start: u64,
    },
    Map(std::io::Error),
    Prepare {
        start: u64,
        reason: String,
    },
    Protect {
        start: u64,
        len: u64,
        prot: u32,
        error: std::io::Error,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::AddressUnavailable { start, len, reason } => write!(
                f,
                "address range {start:#x}-{:#x} required by the executable is not available \
                 ({reason})",
                start + len
            ),
            LoadError::BelowHostMinimum { start } => write!(
                f,
                "executable is linked at {start:#x}, below 4 GiB, which macOS reserves; \
                 position-independent executables run, and executables linked at low \
                 addresses need the hypervisor backend (not available yet)"
            ),
            LoadError::Map(e) => write!(f, "mapping the image failed: {e}"),
            LoadError::Prepare { start, reason } => {
                write!(f, "preparing code at {start:#x} failed: {reason}")
            }
            LoadError::Protect { start, len, prot, error } => write!(
                f,
                "setting protections {} on {start:#x}-{:#x} failed: {error}",
                prot_str(*prot),
                start + len
            ),
        }
    }
}

fn prot_str(p: u32) -> String {
    [(PF_R, 'r'), (PF_W, 'w'), (PF_X, 'x')]
        .iter()
        .map(|&(bit, c)| if p & bit != 0 { c } else { '-' })
        .collect()
}

fn host_prot(p: u32) -> libc::c_int {
    let mut h = libc::PROT_NONE;
    if p & PF_R != 0 {
        h |= libc::PROT_READ;
    }
    if p & PF_W != 0 {
        h |= libc::PROT_WRITE;
    }
    if p & PF_X != 0 {
        h |= libc::PROT_EXEC;
    }
    h
}

/// Lowest address a process may map: macOS arm64 reserves the low 4 GiB.
pub fn host_min_address() -> u64 {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) { 1 << 32 } else { 0 }
}

/// Map `elf` for host pages of `page_size` bytes. `prepare_exec` is called
/// on every executable range while it is still writable.
pub fn load(
    elf: &Elf<'_>,
    page_size: u64,
    mut prepare_exec: impl FnMut(u64, u64, &mut StubArena) -> Result<(), String>,
) -> Result<Loaded, LoadError> {
    let plan = LoadPlan::new(elf, page_size);
    if !elf.is_pie() && plan.start < host_min_address() {
        return Err(LoadError::BelowHostMinimum { start: plan.start });
    }

    // Space for code stubs right after the image, so they are within branch
    // range of the code that needs them.
    let stub_len: u64 = elf
        .loads()
        .filter(|ph| ph.executable())
        .map(|ph| {
            stub_space(&elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize], page_size)
        })
        .sum();
    let total = plan.len + stub_len;

    // Reserve the whole range first so segments land at fixed offsets from
    // each other and gaps between them stay inaccessible.
    let base = if elf.is_pie() {
        // SAFETY: a fresh inaccessible reservation anywhere; not MAP_FIXED.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(LoadError::Map(std::io::Error::last_os_error()));
        }
        p as u64
    } else {
        fwe_kernel::host::reserve_fixed(plan.start, total).map_err(|reason| {
            LoadError::AddressUnavailable { start: plan.start, len: total, reason }
        })?;
        plan.start
    };
    fwe_kernel::mm::track(base, total);
    let bias = base - plan.start;
    let mut arena = StubArena { next: base + plan.len, end: base + total };

    for run in &plan.runs {
        // SAFETY: replacing part of our own reservation.
        let p = unsafe {
            libc::mmap(
                (run.start + bias) as *mut libc::c_void,
                run.len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(LoadError::Map(std::io::Error::last_os_error()));
        }
    }

    for ph in elf.loads() {
        let src = &elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize];
        // SAFETY: the destination lies inside a run mapped read-write above;
        // the source is the file image.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), (ph.vaddr + bias) as *mut u8, src.len())
        };
    }

    // Translate only the executable code, not every byte of an executable
    // segment: a segment can hold data (symbol/string/hash tables, read-only
    // constants) that must not be rewritten. `exec_ranges` reports the real
    // code extents from the section headers when present.
    for (vaddr, size) in elf.exec_ranges() {
        prepare_exec(vaddr + bias, size, &mut arena)
            .map_err(|reason| LoadError::Prepare { start: vaddr + bias, reason })?;
    }

    for run in &plan.runs {
        let addr = (run.start + bias) as *mut libc::c_void;
        // SAFETY: changing protections of the runs mapped above.
        if unsafe { libc::mprotect(addr, run.len as usize, host_prot(run.prot)) } != 0 {
            return Err(LoadError::Protect {
                start: run.start + bias,
                len: run.len,
                prot: run.prot,
                error: std::io::Error::last_os_error(),
            });
        }
    }

    let (lo, hi) = elf.bounds();
    Ok(Loaded {
        stub_arena: arena,
        bias,
        entry: elf.entry + bias,
        phdr: elf.phdr_vaddr().map(|a| a + bias),
        phnum: elf.phnum,
        phent: elf.phentsize,
        end: hi + bias,
        load_base: lo + bias,
    })
}
