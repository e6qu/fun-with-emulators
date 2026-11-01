//! Mapping an ELF image into the host process at its guest addresses.

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
    mut prepare_exec: impl FnMut(u64, u64),
) -> Result<Loaded, LoadError> {
    let plan = LoadPlan::new(elf, page_size);
    if !elf.is_pie() && plan.start < host_min_address() {
        return Err(LoadError::BelowHostMinimum { start: plan.start });
    }

    // Reserve the whole range first so segments land at fixed offsets from
    // each other and gaps between them stay inaccessible.
    let base = if elf.is_pie() {
        // SAFETY: a fresh inaccessible reservation anywhere; not MAP_FIXED.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                plan.len as usize,
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
        fwe_kernel::host::reserve_fixed(plan.start, plan.len).map_err(|reason| {
            LoadError::AddressUnavailable { start: plan.start, len: plan.len, reason }
        })?;
        plan.start
    };
    let bias = base - plan.start;

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

    for run in plan.runs.iter().filter(|r| r.prot & PF_X != 0) {
        prepare_exec(run.start + bias, run.len);
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

    let (_, hi) = elf.bounds();
    Ok(Loaded {
        bias,
        entry: elf.entry + bias,
        phdr: elf.phdr_vaddr().map(|a| a + bias),
        phnum: elf.phnum,
        phent: elf.phentsize,
        end: hi + bias,
    })
}
