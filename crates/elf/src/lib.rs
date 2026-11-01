//! ELF64 parsing and load planning for Linux arm64 executables.
//!
//! This crate is host-independent: it reads an image from bytes and computes
//! where each segment goes and which protections each host page needs. The
//! execution backend performs the actual mapping.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_AARCH64: u16 = 183;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_STACK: u32 = 0x6474_e551;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    BadVersion,
    WrongMachine(u16),
    WrongType(u16),
    BadProgramHeaders,
    NoLoadSegments,
    BadSegment { index: usize },
    OverlappingSegments,
    BadInterpreter,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort => write!(f, "file too short to be an ELF image"),
            Error::BadMagic => write!(f, "not an ELF file"),
            Error::Not64Bit => write!(f, "not a 64-bit ELF file"),
            Error::NotLittleEndian => write!(f, "not a little-endian ELF file"),
            Error::BadVersion => write!(f, "unsupported ELF version"),
            Error::WrongMachine(m) => write!(f, "not an arm64 binary (e_machine {m})"),
            Error::WrongType(t) => write!(f, "not an executable or shared object (e_type {t})"),
            Error::BadProgramHeaders => write!(f, "malformed program headers"),
            Error::NoLoadSegments => write!(f, "no loadable segments"),
            Error::BadSegment { index } => write!(f, "malformed segment {index}"),
            Error::OverlappingSegments => write!(f, "loadable segments overlap"),
            Error::BadInterpreter => write!(f, "malformed PT_INTERP"),
        }
    }
}

/// A program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn readable(&self) -> bool {
        self.flags & PF_R != 0
    }
    pub fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }
    pub fn executable(&self) -> bool {
        self.flags & PF_X != 0
    }
}

/// A parsed ELF image.
#[derive(Debug, Clone)]
pub struct Elf<'a> {
    pub data: &'a [u8],
    pub kind: u16,
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub phdrs: Vec<ProgramHeader>,
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < EHDR_SIZE {
            return Err(Error::TooShort);
        }
        if &data[0..4] != b"\x7fELF" {
            return Err(Error::BadMagic);
        }
        if data[4] != 2 {
            return Err(Error::Not64Bit);
        }
        if data[5] != 1 {
            return Err(Error::NotLittleEndian);
        }
        if data[6] != 1 {
            return Err(Error::BadVersion);
        }
        let kind = u16_at(data, 16);
        let machine = u16_at(data, 18);
        if machine != EM_AARCH64 {
            return Err(Error::WrongMachine(machine));
        }
        if kind != ET_EXEC && kind != ET_DYN {
            return Err(Error::WrongType(kind));
        }
        let entry = u64_at(data, 24);
        let phoff = u64_at(data, 32);
        let phentsize = u16_at(data, 54);
        let phnum = u16_at(data, 56);
        if phentsize as usize != PHDR_SIZE {
            return Err(Error::BadProgramHeaders);
        }
        let table_end = (phnum as u64)
            .checked_mul(PHDR_SIZE as u64)
            .and_then(|n| n.checked_add(phoff))
            .ok_or(Error::BadProgramHeaders)?;
        if table_end > data.len() as u64 {
            return Err(Error::BadProgramHeaders);
        }
        let mut phdrs = Vec::with_capacity(phnum as usize);
        for i in 0..phnum as usize {
            let o = phoff as usize + i * PHDR_SIZE;
            phdrs.push(ProgramHeader {
                kind: u32_at(data, o),
                flags: u32_at(data, o + 4),
                offset: u64_at(data, o + 8),
                vaddr: u64_at(data, o + 16),
                filesz: u64_at(data, o + 32),
                memsz: u64_at(data, o + 40),
                align: u64_at(data, o + 48),
            });
        }
        let elf = Elf { data, kind, entry, phoff, phentsize, phnum, phdrs };
        elf.validate()?;
        Ok(elf)
    }

    fn validate(&self) -> Result<(), Error> {
        let mut loads: Vec<&ProgramHeader> = self.loads().collect();
        if loads.is_empty() {
            return Err(Error::NoLoadSegments);
        }
        for (index, ph) in self.phdrs.iter().enumerate() {
            let file_end = ph.offset.checked_add(ph.filesz);
            let mem_end = ph.vaddr.checked_add(ph.memsz);
            let bad = match (file_end, mem_end) {
                (Some(fe), Some(_)) => fe > self.data.len() as u64 && ph.kind != PT_GNU_STACK,
                _ => true,
            };
            if bad || (ph.kind == PT_LOAD && ph.filesz > ph.memsz) {
                return Err(Error::BadSegment { index });
            }
        }
        loads.sort_by_key(|ph| ph.vaddr);
        for pair in loads.windows(2) {
            if pair[0].vaddr + pair[0].memsz > pair[1].vaddr {
                return Err(Error::OverlappingSegments);
            }
        }
        Ok(())
    }

    pub fn loads(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.phdrs.iter().filter(|ph| ph.kind == PT_LOAD)
    }

    pub fn is_pie(&self) -> bool {
        self.kind == ET_DYN
    }

    /// The program interpreter (dynamic loader) path, if any.
    pub fn interpreter(&self) -> Result<Option<&'a [u8]>, Error> {
        let Some(ph) = self.phdrs.iter().find(|ph| ph.kind == PT_INTERP) else {
            return Ok(None);
        };
        let bytes = &self.data[ph.offset as usize..(ph.offset + ph.filesz) as usize];
        match bytes.split_last() {
            Some((0, path)) if !path.is_empty() => Ok(Some(path)),
            _ => Err(Error::BadInterpreter),
        }
    }

    /// Lowest and highest (exclusive) virtual addresses of loadable segments.
    pub fn bounds(&self) -> (u64, u64) {
        let lo = self.loads().map(|ph| ph.vaddr).min().unwrap_or(0);
        let hi = self.loads().map(|ph| ph.vaddr + ph.memsz).max().unwrap_or(0);
        (lo, hi)
    }

    /// Virtual address of the program header table once loaded, if the
    /// table is covered by a loadable segment.
    pub fn phdr_vaddr(&self) -> Option<u64> {
        if let Some(ph) = self.phdrs.iter().find(|ph| ph.kind == PT_PHDR) {
            return Some(ph.vaddr);
        }
        self.loads()
            .find(|ph| ph.offset <= self.phoff && self.phoff < ph.offset + ph.filesz)
            .map(|ph| ph.vaddr + (self.phoff - ph.offset))
    }
}

/// Host page protections, as a combination of `PF_*` bits.
pub type Prot = u32;

/// One run of host pages with identical protections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRun {
    /// Start address relative to the image's link addresses.
    pub start: u64,
    pub len: u64,
    pub prot: Prot,
}

/// Where and how to map an image on a host with the given page size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan {
    /// Page-aligned start of the reservation (link address).
    pub start: u64,
    /// Page-aligned length of the reservation.
    pub len: u64,
    /// Protections per run of pages, covering every page that holds a
    /// segment. Pages between segments are left out and stay inaccessible.
    pub runs: Vec<PageRun>,
}

impl LoadPlan {
    /// Plan the load of `elf` for host pages of `page_size` bytes.
    ///
    /// Segments are not required to be aligned to `page_size`: a page shared
    /// by several segments receives the union of their protections.
    pub fn new(elf: &Elf<'_>, page_size: u64) -> LoadPlan {
        assert!(page_size.is_power_of_two());
        let down = |a: u64| a & !(page_size - 1);
        let up = |a: u64| (a + page_size - 1) & !(page_size - 1);

        let (lo, hi) = elf.bounds();
        let start = down(lo);
        let len = up(hi) - start;

        // Protection per page, then merged into runs.
        let pages = (len / page_size) as usize;
        let mut prot: Vec<Option<Prot>> = alloc::vec![None; pages];
        for ph in elf.loads().filter(|ph| ph.memsz > 0) {
            let first = ((down(ph.vaddr) - start) / page_size) as usize;
            let last = ((up(ph.vaddr + ph.memsz) - start) / page_size) as usize;
            for p in &mut prot[first..last] {
                *p = Some(p.unwrap_or(0) | (ph.flags & (PF_R | PF_W | PF_X)));
            }
        }

        let mut runs: Vec<PageRun> = Vec::new();
        for (i, p) in prot.iter().enumerate() {
            let Some(p) = *p else { continue };
            let addr = start + i as u64 * page_size;
            match runs.last_mut() {
                Some(run) if run.prot == p && run.start + run.len == addr => run.len += page_size,
                _ => runs.push(PageRun { start: addr, len: page_size, prot: p }),
            }
        }
        LoadPlan { start, len, runs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal ELF image with the given segments.
    fn image(kind: u16, phdrs: &[ProgramHeader], size: usize) -> Vec<u8> {
        let mut d = vec![0u8; size.max(EHDR_SIZE + PHDR_SIZE * phdrs.len())];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&kind.to_le_bytes());
        d[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        d[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        d[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
        d[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        d[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, ph) in phdrs.iter().enumerate() {
            let o = EHDR_SIZE + i * PHDR_SIZE;
            d[o..o + 4].copy_from_slice(&ph.kind.to_le_bytes());
            d[o + 4..o + 8].copy_from_slice(&ph.flags.to_le_bytes());
            d[o + 8..o + 16].copy_from_slice(&ph.offset.to_le_bytes());
            d[o + 16..o + 24].copy_from_slice(&ph.vaddr.to_le_bytes());
            d[o + 24..o + 32].copy_from_slice(&ph.vaddr.to_le_bytes());
            d[o + 32..o + 40].copy_from_slice(&ph.filesz.to_le_bytes());
            d[o + 40..o + 48].copy_from_slice(&ph.memsz.to_le_bytes());
            d[o + 48..o + 56].copy_from_slice(&ph.align.to_le_bytes());
        }
        d
    }

    fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> ProgramHeader {
        ProgramHeader { kind: PT_LOAD, flags, offset, vaddr, filesz, memsz, align: 0x1000 }
    }

    #[test]
    fn rejects_non_elf() {
        assert_eq!(Elf::parse(&[0u8; 64]).unwrap_err(), Error::BadMagic);
        assert_eq!(Elf::parse(b"\x7fELF").unwrap_err(), Error::TooShort);
    }

    #[test]
    fn rejects_other_machines() {
        let mut d = image(ET_EXEC, &[load(PF_R, 0, 0x1000, 0x100, 0x100)], 0x200);
        d[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert_eq!(Elf::parse(&d).unwrap_err(), Error::WrongMachine(62));
    }

    #[test]
    fn rejects_segments_past_end_of_file() {
        let d = image(ET_EXEC, &[load(PF_R, 0, 0x1000, 0x10000, 0x10000)], 0x200);
        assert_eq!(Elf::parse(&d).unwrap_err(), Error::BadSegment { index: 0 });
    }

    #[test]
    fn rejects_overlapping_segments() {
        let d = image(
            ET_EXEC,
            &[load(PF_R, 0, 0x1000, 0x100, 0x2000), load(PF_R, 0, 0x2000, 0x100, 0x100)],
            0x200,
        );
        assert_eq!(Elf::parse(&d).unwrap_err(), Error::OverlappingSegments);
    }

    #[test]
    fn parses_interpreter() {
        let interp = b"/lib/ld-linux-aarch64.so.1\0";
        let mut d = image(
            ET_DYN,
            &[
                load(PF_R | PF_X, 0, 0, 0x200, 0x200),
                ProgramHeader {
                    kind: PT_INTERP,
                    flags: PF_R,
                    offset: 0x180,
                    vaddr: 0x180,
                    filesz: interp.len() as u64,
                    memsz: interp.len() as u64,
                    align: 1,
                },
            ],
            0x200,
        );
        d[0x180..0x180 + interp.len()].copy_from_slice(interp);
        let elf = Elf::parse(&d).unwrap();
        assert!(elf.is_pie());
        assert_eq!(elf.interpreter().unwrap(), Some(&interp[..interp.len() - 1]));
        assert_eq!(elf.phdr_vaddr(), Some(EHDR_SIZE as u64));
    }

    #[test]
    fn plan_merges_protections_on_shared_pages() {
        // Text at 0x200000 (R+X) and data starting inside the same 16K page.
        let d = image(
            ET_EXEC,
            &[
                load(PF_R | PF_X, 0, 0x200000, 0x100, 0x2100),
                load(PF_R | PF_W, 0x100, 0x203000, 0x100, 0x8000),
            ],
            0x200,
        );
        let elf = Elf::parse(&d).unwrap();
        let plan = LoadPlan::new(&elf, 0x4000);
        assert_eq!(plan.start, 0x200000);
        assert_eq!(plan.len, 0xc000);
        assert_eq!(
            plan.runs,
            vec![
                PageRun { start: 0x200000, len: 0x4000, prot: PF_R | PF_W | PF_X },
                PageRun { start: 0x204000, len: 0x8000, prot: PF_R | PF_W },
            ]
        );
    }

    #[test]
    fn plan_leaves_gaps_unmapped() {
        let d = image(
            ET_EXEC,
            &[
                load(PF_R | PF_X, 0, 0x10000, 0x100, 0x100),
                load(PF_R | PF_W, 0x100, 0x30000, 0x100, 0x100),
            ],
            0x200,
        );
        let elf = Elf::parse(&d).unwrap();
        let plan = LoadPlan::new(&elf, 0x4000);
        assert_eq!(plan.len, 0x24000);
        assert_eq!(
            plan.runs,
            vec![
                PageRun { start: 0x10000, len: 0x4000, prot: PF_R | PF_X },
                PageRun { start: 0x30000, len: 0x4000, prot: PF_R | PF_W },
            ]
        );
    }
}
