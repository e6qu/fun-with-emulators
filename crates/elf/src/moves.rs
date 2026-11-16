//! Moving a non-PIE executable to another address: what must change, from
//! the relocations its link kept (`--emit-relocs`), or why it cannot be.
//!
//! arm64 code reaches its own code and data PC-relatively (`adrp`, `adr`,
//! branches, the low 12 bits of an address), so a whole image moved by a
//! multiple of 4 GiB keeps every such reference right. What changes is
//! each absolute address the image holds: a 64-bit pointer in its data
//! (`R_AARCH64_ABS64`), and an address built in code from 16-bit pieces
//! (`movz`/`movk`, `R_AARCH64_MOVW_UABS_G*`). Static glibc's table of
//! ifunc relocations (`.rela.iplt`), which its start-up applies, names
//! addresses too. A link that kept its relocations lists every such
//! place; one that did not, or one whose relocations include a kind whose
//! place cannot be followed (an address through a GOT whose entries are
//! not relocated, a 32-bit absolute address), is not moved, and the
//! reason says which.

use alloc::{format, string::String, vec::Vec};

use crate::{ET_EXEC, Elf, PT_DYNAMIC, PT_INTERP, SHDR_SIZE, SHF_ALLOC, u16_at, u32_at, u64_at};

/// One change a move makes, at a link-time address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Patch {
    /// The 64-bit word there becomes this.
    Word(u64),
    /// The 32-bit instruction there becomes this.
    Insn(u32),
}

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;

/// AArch64 relocation types this module knows.
mod r {
    pub const NONE: u32 = 0;
    pub const WITHDRAWN_NONE: u32 = 256;
    pub const ABS64: u32 = 257;
    pub const ABS32: u32 = 258;
    pub const ABS16: u32 = 259;
    pub const PREL64: u32 = 260;
    pub const PREL32: u32 = 261;
    pub const PREL16: u32 = 262;
    pub const MOVW_UABS_G0: u32 = 263;
    pub const MOVW_UABS_G3: u32 = 269;
    pub const LD_PREL_LO19: u32 = 273;
    pub const ADR_PREL_LO21: u32 = 274;
    pub const ADR_PREL_PG_HI21: u32 = 275;
    pub const ADR_PREL_PG_HI21_NC: u32 = 276;
    pub const ADD_ABS_LO12_NC: u32 = 277;
    pub const LDST8_ABS_LO12_NC: u32 = 278;
    pub const TSTBR14: u32 = 279;
    pub const CONDBR19: u32 = 280;
    pub const JUMP26: u32 = 282;
    pub const CALL26: u32 = 283;
    pub const LDST16_ABS_LO12_NC: u32 = 284;
    pub const LDST32_ABS_LO12_NC: u32 = 285;
    pub const LDST64_ABS_LO12_NC: u32 = 286;
    pub const LDST128_ABS_LO12_NC: u32 = 299;
    pub const PLT32: u32 = 314;
    /// The initial-exec and local-exec TLS forms: offsets from the thread
    /// pointer, not addresses.
    pub const TLSIE_FIRST: u32 = 539;
    pub const TLSLE_LAST: u32 = 559;
    pub const IRELATIVE: u32 = 1032;
}

/// A section header's fields this module reads.
#[derive(Clone, Copy)]
struct Shdr {
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

/// The patches that move `elf`, a non-PIE executable, by `delta` (a
/// multiple of 4 GiB), as `(link-time address, patch)`; or why it cannot
/// be moved.
pub fn moves(elf: &Elf<'_>, delta: u64) -> Result<Vec<(u64, Patch)>, String> {
    if elf.kind != ET_EXEC {
        return Err("it is not a fixed-address executable".into());
    }
    if elf.phdrs.iter().any(|p| p.kind == PT_INTERP || p.kind == PT_DYNAMIC) {
        return Err("it is linked dynamically, and its dynamic linker relocates it at its link \
                    address"
            .into());
    }
    let d = elf.data;
    let sections = sections(d).ok_or("it has no section headers")?;
    let symtab = sections
        .iter()
        .find(|s| s.kind == SHT_SYMTAB)
        .ok_or("it has no symbol table (it was stripped)")?;
    let syms = bytes(d, symtab).ok_or("its symbol table is truncated")?;
    // Whether symbol `i` is at an address the move changes (defined in a
    // section loaded with the image), and its value.
    let symbol = |i: u32| -> Option<(bool, u64)> {
        let o = (i as usize).checked_mul(24)?;
        let e = syms.get(o..o + 24)?;
        let shndx = u16_at(e, 6);
        let value = u64_at(e, 8);
        let moves = shndx != SHN_UNDEF
            && shndx < SHN_LORESERVE
            && sections.get(shndx as usize).is_some_and(|s| s.flags & SHF_ALLOC != 0);
        Some((moves, value))
    };
    // Where a link-time address is in the file.
    let file_at = |addr: u64, len: u64| -> Option<usize> {
        let ph = elf.loads().find(|p| p.vaddr <= addr && addr + len <= p.vaddr + p.filesz)?;
        Some((addr - ph.vaddr + ph.offset) as usize)
    };
    let word_at = |addr: u64| file_at(addr, 8).map(|o| u64_at(d, o));
    let insn_at = |addr: u64| file_at(addr, 4).map(|o| u32_at(d, o));
    let mut patches = Vec::new();
    let mut kept = false;
    for rela in sections.iter().filter(|s| s.kind == SHT_RELA) {
        let entries = bytes(d, rela).ok_or("a relocation section is truncated")?;
        if rela.entsize != 24 {
            return Err("a relocation section has entries of an unknown size".into());
        }
        if rela.flags & SHF_ALLOC != 0 {
            // A table the program reads as it starts: static glibc's
            // ifunc relocations, each naming a place and a resolver.
            for (i, e) in entries.as_chunks::<24>().0.iter().enumerate() {
                let (offset, info) = (u64_at(e, 0), u64_at(e, 8));
                match info as u32 {
                    r::NONE => {}
                    r::IRELATIVE => {
                        let entry = rela.addr + 24 * i as u64;
                        patches.push((entry, Patch::Word(offset + delta)));
                        patches.push((entry + 16, Patch::Word(u64_at(e, 16).wrapping_add(delta))));
                    }
                    t => return Err(format!("it has a dynamic relocation of type {t}")),
                }
            }
            continue;
        }
        // Relocations the link kept, of a loaded section's places.
        let Some(target) = sections.get(rela.info as usize) else { continue };
        if target.flags & SHF_ALLOC == 0 || rela.link as usize != index_of(&sections, symtab) {
            continue;
        }
        kept = true;
        for e in entries.as_chunks::<24>().0 {
            let (at, info, addend) = (u64_at(e, 0), u64_at(e, 8), u64_at(e, 16));
            let (t, sym) = (info as u32, (info >> 32) as u32);
            let (moves, value) =
                symbol(sym).ok_or_else(|| format!("a relocation names symbol {sym}, not there"))?;
            let target_addr = value.wrapping_add(addend);
            match t {
                r::NONE | r::WITHDRAWN_NONE => {}
                r::ABS64 if moves => {
                    let now = word_at(at).ok_or_else(|| format!("{at:#x} is not in the image"))?;
                    if now != target_addr {
                        return Err(format!(
                            "the pointer at {at:#x} is not what its relocation says"
                        ));
                    }
                    patches.push((at, Patch::Word(now + delta)));
                }
                r::ABS64 => {}
                r::ABS32 | r::ABS16 if moves => {
                    return Err(format!("it holds a 32- or 16-bit absolute address at {at:#x}"));
                }
                r::ABS32 | r::ABS16 => {}
                g @ r::MOVW_UABS_G0..=r::MOVW_UABS_G3 if moves => {
                    // G0, G1 and G2 checked, then their _NC forms, and G3:
                    // the piece's level, and whether the rest must be 0.
                    let (level, checked) = match g - r::MOVW_UABS_G0 {
                        0 => (0, true),
                        1 => (0, false),
                        2 => (1, true),
                        3 => (1, false),
                        4 => (2, true),
                        5 => (2, false),
                        _ => (3, false),
                    };
                    let moved = target_addr + delta;
                    if checked && moved >> (16 * (level + 1)) != 0 {
                        return Err(format!(
                            "code at {at:#x} builds an address in {} bits",
                            16 * (level + 1)
                        ));
                    }
                    let insn = insn_at(at).ok_or_else(|| format!("{at:#x} is not in the image"))?;
                    let piece = ((moved >> (16 * level)) & 0xffff) as u32;
                    patches.push((at, Patch::Insn((insn & !(0xffff << 5)) | piece << 5)));
                }
                r::MOVW_UABS_G0..=r::MOVW_UABS_G3 => {}
                // PC-relative, or the low 12 bits of an address: right
                // after the move when both ends move.
                r::PREL64
                | r::PREL32
                | r::PREL16
                | r::LD_PREL_LO19
                | r::ADR_PREL_LO21
                | r::ADR_PREL_PG_HI21
                | r::ADR_PREL_PG_HI21_NC
                | r::ADD_ABS_LO12_NC
                | r::LDST8_ABS_LO12_NC
                | r::LDST16_ABS_LO12_NC
                | r::LDST32_ABS_LO12_NC
                | r::LDST64_ABS_LO12_NC
                | r::LDST128_ABS_LO12_NC
                | r::TSTBR14
                | r::CONDBR19
                | r::JUMP26
                | r::CALL26
                | r::PLT32 => {
                    // (One to a weak symbol left undefined, at 0, would
                    // reach somewhere else once moved, where code that
                    // tests it for 0 finds something.)
                    if !moves {
                        return Err(format!(
                            "code at {at:#x} reaches a fixed address PC-relatively"
                        ));
                    }
                }
                r::TLSIE_FIRST..=r::TLSLE_LAST => {}
                t => return Err(format!("it has a relocation of type {t} at {at:#x}")),
            }
        }
    }
    if !kept {
        return Err("it keeps no relocations for its own addresses (linked without \
                    --emit-relocs)"
            .into());
    }
    Ok(patches)
}

fn index_of(sections: &[Shdr], s: &Shdr) -> usize {
    sections.iter().position(|x| core::ptr::eq(x, s)).unwrap_or(usize::MAX)
}

/// The section's bytes in the file.
fn bytes<'a>(d: &'a [u8], s: &Shdr) -> Option<&'a [u8]> {
    d.get(s.offset as usize..s.offset.checked_add(s.size)? as usize)
}

/// Every section header, or `None` without a readable table.
fn sections(d: &[u8]) -> Option<Vec<Shdr>> {
    let shoff = u64_at(d, 40) as usize;
    let shentsize = u16_at(d, 58) as usize;
    let shnum = u16_at(d, 60) as usize;
    if shoff == 0 || shnum == 0 || shentsize < SHDR_SIZE {
        return None;
    }
    (0..shnum)
        .map(|i| {
            let o = shoff.checked_add(i * shentsize)?;
            d.get(o..o + SHDR_SIZE)?;
            Some(Shdr {
                kind: u32_at(d, o + 4),
                flags: u64_at(d, o + 8),
                addr: u64_at(d, o + 16),
                offset: u64_at(d, o + 24),
                size: u64_at(d, o + 32),
                link: u32_at(d, o + 40),
                info: u32_at(d, o + 44),
                entsize: u64_at(d, o + 56),
            })
        })
        .collect()
}
