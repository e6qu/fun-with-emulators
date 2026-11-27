//! Mapping an ELF image into the host process at its guest addresses.

use crate::prepare::{StubArena, stub_space};
use fwe_elf::{Elf, LoadPlan, PF_R, PF_W, PF_X, Patch};
use std::fmt;

/// A loaded image.
#[derive(Debug, Clone)]
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
    /// Mapped from its prepared image (nothing copied or written).
    pub from_image: bool,
    /// Its code that runs by translation (address, length): pages whose
    /// sites no stub space reaches ([`crate::prepare::Prepared::beyond`]),
    /// left readable but not executable.
    pub translated: Vec<(u64, u64)>,
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
    /// process (`__PAGEZERO`), and cannot be moved ([`moved`]): why.
    BelowHostMinimum {
        start: u64,
        why: String,
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
                "address range {start:#x}-{:#x} that the executable needs is not available \
                 ({reason})",
                start + len
            ),
            LoadError::BelowHostMinimum { start, why } => write!(
                f,
                "executable is linked at {start:#x}, below 4 GiB, which macOS reserves, and \
                 cannot be moved: {why}"
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

/// Lowest address a process can map: macOS arm64 reserves the low 4 GiB.
pub fn host_min_address() -> u64 {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) { 1 << 32 } else { 0 }
}

/// How far an executable linked below 4 GiB is moved: 1 TiB, a multiple
/// of 4 GiB (so the low 32 bits of every address, and with them all
/// PC-relative page arithmetic, stay as linked), clear of fwe's own image
/// just above 4 GiB and below the 2 TiB its mappings start at.
pub const MOVE: u64 = 1 << 40;

/// For an executable linked below 4 GiB: the patches that move it
/// [`MOVE`] higher, or why it cannot be (see [`fwe_elf::moves`]).
/// `None` for one the host can map where it is linked.
pub fn moved(elf: &Elf<'_>, page_size: u64) -> Option<Result<Vec<(u64, Patch)>, String>> {
    (!elf.is_pie() && LoadPlan::new(elf, page_size).start < host_min_address())
        .then(|| fwe_elf::moves(elf, MOVE))
}

/// Map `elf` for host pages of `page_size` bytes. `prepare_exec` is called
/// on every executable range while it is still writable.
/// [`load`]'s preparation of code: `(address, length, known code, stub
/// arena, cache key)`.
pub trait PrepareFn:
    FnMut(
    u64,
    u64,
    Option<&[(u64, u64)]>,
    &mut StubArena,
    Option<&[u8]>,
) -> Result<Vec<(u64, u64)>, String>
{
}
impl<
    F: FnMut(
        u64,
        u64,
        Option<&[(u64, u64)]>,
        &mut StubArena,
        Option<&[u8]>,
    ) -> Result<Vec<(u64, u64)>, String>,
> PrepareFn for F
{
}

/// Where a position-independent executable is asked to go: two thirds of
/// the host's 47 bits of address space, as Linux places one in a space of
/// 47 bits. Far from fwe's own memory and from the mappings left to fwe
/// ([`fwe_kernel::mm`]), it has free room below it, where a program can
/// map memory it wants within a branch's reach of its own code (LuaJIT
/// probes for its machine code there); its break grows above it.
pub const PIE_BASE: u64 = 0x5555_5555_0000;

/// Where the main stack is asked to end: near the top of the host's 47
/// bits, above the program's image, as Linux places it at the top of the
/// address space.
pub const STACK_TOP: u64 = 0x7fff_0000_0000;

/// Load `elf`, read from file `file` (its identity, under which what is
/// learned of its code is kept: [`fwe_kernel::prepcache`]); if it is
/// position-independent, at `at` where that is free, else where the host
/// finds room.
pub fn load(
    elf: &Elf<'_>,
    page_size: u64,
    file: Option<fwe_kernel::prepcache::FileId>,
    slots: crate::rewrite::Slots,
    at: Option<u64>,
    mut prepare_exec: impl PrepareFn,
) -> Result<Loaded, LoadError> {
    use fwe_kernel::prepcache as cache;
    let plan = LoadPlan::new(elf, page_size);
    // An executable linked below 4 GiB, loaded `MOVE` higher with its
    // absolute addresses changed to match.
    let patches = match moved(elf, page_size) {
        Some(Ok(p)) => Some(p),
        Some(Err(why)) => return Err(LoadError::BelowHostMinimum { start: plan.start, why }),
        None => None,
    };

    // Space for code stubs right after the image, so they are within branch
    // range of the code that needs them.
    let count = || -> u64 {
        elf.loads()
            .filter(|ph| ph.executable())
            .map(|ph| {
                stub_space(
                    &elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize],
                    page_size,
                )
            })
            .sum()
    };
    let stub_len = match file {
        Some(id) => {
            let key = cache::about(id, format!("stubs-{page_size}").as_bytes());
            match cache::load(&key).and_then(|v| Some(u64::from_le_bytes(v.try_into().ok()?))) {
                Some(n) => n,
                None => {
                    let n = count();
                    cache::store(&key, &n.to_le_bytes());
                    n
                }
            }
        }
        None => count(),
    };
    // An image larger than a branch reaches across has its code's stubs
    // before it too: the code nearer its start reaches those.
    let front = if elf.is_pie() && plan.len + stub_len > crate::rewrite::BRANCH_RANGE {
        stub_len
    } else {
        0
    };
    let total = front + plan.len + stub_len;

    // Reserve the whole range first so segments land at fixed offsets from
    // each other and gaps between them stay inaccessible.
    let base = if elf.is_pie() {
        // SAFETY: a fresh inaccessible reservation; not MAP_FIXED, `at` is
        // only a hint.
        let p = unsafe {
            libc::mmap(
                at.unwrap_or(0) as *mut libc::c_void,
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
        p as u64 + front
    } else {
        let at = plan.start + if patches.is_some() { MOVE } else { 0 };
        fwe_kernel::host::reserve_fixed(at, total)
            .map_err(|reason| LoadError::AddressUnavailable { start: at, len: total, reason })?;
        at
    };
    let start = base - front;
    fwe_kernel::mm::track(start, total);
    let bias = base - plan.start;
    let mut arena = StubArena {
        next: base + plan.len,
        end: start + total,
        front_start: start,
        front_end: base,
    };

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

    // Loaded and prepared before: its image, mapped in place
    // ([`crate::prepare::map_load_image`]), shared and written by no one.
    let runs: Vec<(u64, u64)> = plan.runs.iter().map(|r| (r.start + bias, r.len)).collect();
    let image = file.map(|id| cache::about(id, format!("image2-{page_size}").as_bytes()));
    if let Some(key) = &image
        && let Some(m) =
            crate::prepare::map_load_image(key, base, (start, start + total), &runs, slots)
    {
        arena.next = m.arena_next;
        arena.front_end = m.front_end;
        return finish(elf, &plan, bias, arena, true, m.translated);
    }
    if image.is_some() {
        crate::prepare::image_begin();
    }

    for ph in elf.loads() {
        let src = &elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize];
        // SAFETY: the destination lies inside a run mapped read-write above;
        // the source is the file image.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), (ph.vaddr + bias) as *mut u8, src.len())
        };
    }

    // A moved executable's absolute addresses, before its code is looked at.
    for &(at, patch) in patches.iter().flatten() {
        // SAFETY: a place of the image, in a run mapped read-write above.
        unsafe {
            match patch {
                Patch::Word(w) => ((at + bias) as *mut u64).write_unaligned(w),
                Patch::Insn(i) => ((at + bias) as *mut u32).write_unaligned(i),
            }
        }
    }

    // Translate only the executable code, not every byte of an executable
    // segment: a segment can hold data (symbol/string/hash tables, read-only
    // constants), which a rewrite would corrupt. `exec_ranges` reports the real
    // code extents from the section headers when present.
    // The unwind table tells code from data placed among it (see
    // `fwe_elf::Elf::unwind_code_ranges`).
    let unwind = match file {
        Some(id) => {
            let key = cache::about(id, b"unwind");
            match cache::load(&key).and_then(|v| cache::decode_ranges(&v)) {
                Some(r) => r,
                None => {
                    let r = elf.unwind_code_ranges();
                    cache::store(&key, &cache::encode_ranges(r.as_deref()));
                    r
                }
            }
        }
        None => elf.unwind_code_ranges(),
    };
    let known: Option<Vec<(u64, u64)>> =
        unwind.as_ref().map(|r| r.iter().map(|&(a, l)| (a + bias, l)).collect());
    let mut translated = Vec::new();
    for (vaddr, size) in elf.exec_ranges() {
        // Kept by the file and the code's place in the image, with the
        // known code as offsets from it.
        let key = file.map(|id| {
            let k = unwind.as_ref().map(|r| {
                r.iter()
                    .filter_map(|&(a, l)| {
                        let (lo, hi) = (a.max(vaddr), (a + l).min(vaddr + size));
                        (lo < hi).then(|| (lo - vaddr, hi - lo))
                    })
                    .collect::<Vec<_>>()
            });
            cache::code_key(id, vaddr | 1 << 63, size, k.as_deref())
        });
        translated.extend(
            prepare_exec(vaddr + bias, size, known.as_deref(), &mut arena, key.as_deref())
                .map_err(|reason| {
                    crate::prepare::image_abandon();
                    LoadError::Prepare { start: vaddr + bias, reason }
                })?,
        );
    }
    if let Some(key) = &image {
        // SAFETY: the runs, mapped readable and writable above.
        unsafe { crate::prepare::keep_load_image(key, base, &runs, &arena, &translated) };
    }
    finish(elf, &plan, bias, arena, false, translated)
}

/// The runs of a loaded image given their protections, and what was
/// loaded (`from_image`: mapped from its prepared image).
fn finish(
    elf: &Elf<'_>,
    plan: &LoadPlan,
    bias: u64,
    arena: StubArena,
    from_image: bool,
    translated: Vec<(u64, u64)>,
) -> Result<Loaded, LoadError> {
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
    // Code that runs by translation: read to be translated, never run.
    for &(at, len) in &translated {
        // SAFETY: pages of the runs just given their protections.
        if unsafe { libc::mprotect(at as *mut libc::c_void, len as usize, libc::PROT_READ) } != 0 {
            return Err(LoadError::Protect {
                start: at,
                len,
                prot: PF_R,
                error: std::io::Error::last_os_error(),
            });
        }
    }

    let (lo, hi) = elf.bounds();
    // What the code's stubs left of the arenas: room for call stubs.
    crate::prepare::spare_arena(arena.next, arena.end);
    crate::prepare::spare_arena(arena.front_start, arena.front_end);
    Ok(Loaded {
        stub_arena: arena,
        bias,
        entry: elf.entry + bias,
        phdr: elf.phdr_vaddr().map(|a| a + bias),
        phnum: elf.phnum,
        phent: elf.phentsize,
        end: hi + bias,
        load_base: lo + bias,
        from_image,
        translated,
    })
}
