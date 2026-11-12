//! The code ranges an image's unwind table (`.eh_frame`) describes.
//!
//! Every function a compiler emits for Linux carries a frame description
//! entry (FDE) in `.eh_frame`, giving the range of addresses it covers; hand
//! written assembly with CFI directives does too. Bytes of an executable
//! section that no FDE covers are, in practice, data placed among the code,
//! such as the constant tables OpenSSL's assembly keeps in `.text`. The code
//! rewriter uses this to tell the two apart.
//!
//! Only what that needs is decoded: each CIE's augmentation (for the
//! encoding of its FDEs' addresses) and each FDE's start and length. Anything
//! unexpected makes the whole table unusable (`None`), and the caller falls
//! back to treating every executable byte as code.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// `DW_EH_PE_omit`: no value.
const PE_OMIT: u8 = 0xff;

/// A cursor over the table's bytes, where `pos` is an offset in it.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let b = self.data.get(self.pos..self.pos + N)?.try_into().ok()?;
        self.pos += N;
        Some(b)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            v |= i64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1 << shift;
                }
                return Some(v);
            }
            if shift >= 64 {
                return None;
            }
        }
    }

    /// A pointer in encoding `enc`, at link address `vaddr` for the start of
    /// the table. `pcrel` applies only to addresses, not to lengths.
    fn pointer(&mut self, enc: u8, vaddr: u64, apply: bool) -> Option<u64> {
        let at = vaddr.wrapping_add(self.pos as u64);
        let raw = match enc & 0x0f {
            0x00 => u64::from_le_bytes(self.bytes::<8>()?),
            0x01 => self.uleb()?,
            0x02 => u64::from(u16::from_le_bytes(self.bytes::<2>()?)),
            0x03 => u64::from(u32::from_le_bytes(self.bytes::<4>()?)),
            0x04 => u64::from_le_bytes(self.bytes::<8>()?),
            0x09 => self.sleb()? as u64,
            0x0a => i16::from_le_bytes(self.bytes::<2>()?) as i64 as u64,
            0x0b => i32::from_le_bytes(self.bytes::<4>()?) as i64 as u64,
            0x0c => u64::from_le_bytes(self.bytes::<8>()?),
            _ => return None,
        };
        if !apply {
            return Some(raw);
        }
        match enc & 0x70 {
            0x00 => Some(raw),
            0x10 => Some(at.wrapping_add(raw)), // pcrel
            _ => None,                          // textrel, datarel, funcrel, aligned
        }
    }
}

/// From `.eh_frame_hdr` (its bytes, at link address `vaddr`): the address
/// of `.eh_frame`, and that of the last frame description entry its search
/// table names, if it has a table. `None` for a header this cannot read.
pub fn eh_frame_from_header(hdr: &[u8], vaddr: u64) -> Option<(u64, Option<u64>)> {
    let mut r = Reader { data: hdr, pos: 0 };
    if r.u8()? != 1 {
        return None;
    }
    let (ptr_enc, count_enc, table_enc) = (r.u8()?, r.u8()?, r.u8()?);
    // `DW_EH_PE_datarel` here is relative to the header's start.
    let value = |r: &mut Reader<'_>, enc: u8| -> Option<u64> {
        if enc & 0x70 == 0x30 {
            Some(vaddr.wrapping_add(r.pointer(enc & 0x0f, vaddr, false)?))
        } else {
            r.pointer(enc, vaddr, true)
        }
    };
    let eh_frame = value(&mut r, ptr_enc)?;
    if count_enc == PE_OMIT || table_enc == PE_OMIT {
        return Some((eh_frame, None));
    }
    let count = r.pointer(count_enc & 0x0f, vaddr, false)?;
    let mut last = None;
    for _ in 0..count {
        let _start = value(&mut r, table_enc)?;
        let fde = value(&mut r, table_enc)?;
        last = Some(last.map_or(fde, |l: u64| l.max(fde)));
    }
    Some((eh_frame, last))
}

/// The FDE address encoding a CIE at `pos` declares (its `R` augmentation),
/// or absolute 8-byte pointers when it declares none.
fn cie_encoding(data: &[u8], pos: usize, end: usize, vaddr: u64) -> Option<u8> {
    let mut r = Reader { data: &data[..end], pos };
    let version = r.u8()?;
    let mut aug = Vec::new();
    loop {
        match r.u8()? {
            0 => break,
            c => aug.push(c),
        }
    }
    if aug.starts_with(b"eh") {
        r.bytes::<8>()?;
    }
    r.uleb()?; // code alignment
    r.sleb()?; // data alignment
    if version == 1 {
        r.u8()?; // return address register
    } else {
        r.uleb()?;
    }
    let mut enc = 0x00;
    if aug.first() == Some(&b'z') {
        r.uleb()?; // augmentation data length
        for &c in &aug[1..] {
            match c {
                b'R' => enc = r.u8()?,
                b'L' => {
                    r.u8()?;
                }
                b'P' => {
                    let penc = r.u8()?;
                    r.pointer(penc, vaddr, false)?;
                }
                b'S' | b'B' | b'G' => {}
                _ => return None,
            }
        }
    } else if !aug.is_empty() && !aug.starts_with(b"eh") {
        return None;
    }
    Some(enc)
}

/// The `(start, length)` link-address ranges the FDEs of the `.eh_frame`
/// section `data`, linked at `vaddr`, cover, or `None` if it cannot be read.
pub fn code_ranges(data: &[u8], vaddr: u64) -> Option<Vec<(u64, u64)>> {
    let mut encodings: BTreeMap<usize, u8> = BTreeMap::new();
    let mut ranges = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        if len == 0 {
            break; // terminator
        }
        if len == 0xffff_ffff {
            return None; // the 64-bit format, which nothing emits for arm64
        }
        let body = pos + 4;
        let end = body.checked_add(len).filter(|&e| e <= data.len())?;
        let id = u32::from_le_bytes(data.get(body..body + 4)?.try_into().ok()?) as usize;
        if id == 0 {
            encodings.insert(pos, cie_encoding(data, body + 4, end, vaddr)?);
        } else {
            let cie = body.checked_sub(id)?;
            let enc = match encodings.get(&cie) {
                Some(&e) => e,
                None => {
                    // A CIE after its FDEs: read it where it is.
                    let clen = u32::from_le_bytes(data.get(cie..cie + 4)?.try_into().ok()?);
                    let cend = (cie + 4).checked_add(clen as usize)?;
                    let e = cie_encoding(data, cie + 8, cend.min(data.len()), vaddr)?;
                    encodings.insert(cie, e);
                    e
                }
            };
            if enc == PE_OMIT {
                return None;
            }
            let mut r = Reader { data: &data[..end], pos: body + 4 };
            let start = r.pointer(enc, vaddr, true)?;
            let size = r.pointer(enc & 0x0f, vaddr, false)?;
            if size != 0 {
                ranges.push((start, size));
            }
        }
        pos = end;
    }
    ranges.sort_unstable();
    Some(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A CIE with augmentation "zR" (pcrel sdata4 addresses) and two FDEs,
    /// as GCC emits them, then the terminator.
    fn table() -> Vec<u8> {
        let mut t = Vec::new();
        // CIE: id 0, version 1, "zR", code align 4, data align -8, return
        // register 30, augmentation length 1, encoding 0x1b (pcrel sdata4),
        // then `def_cfa sp, 0` and padding.
        let cie = [0u8, 0, 0, 0, 1, b'z', b'R', 0, 4, 0x78, 30, 1, 0x1b, 0x0c, 31, 0];
        t.extend((cie.len() as u32).to_le_bytes());
        t.extend(cie);
        for (target, size) in [(0x1000i64, 0x40u32), (0x2000, 0x10)] {
            let pos = t.len();
            // CIE pointer: back from this field to the CIE at 0.
            let mut fde = Vec::from(((pos + 4) as u32).to_le_bytes());
            // pc_begin is pcrel from its own address; the section is at 0x8000.
            let field = 0x8000 + pos as i64 + 8;
            fde.extend(((target - field) as i32).to_le_bytes());
            fde.extend(size.to_le_bytes());
            fde.extend([0, 0, 0, 0]); // augmentation length 0, padding
            t.extend((fde.len() as u32).to_le_bytes());
            t.extend(fde);
        }
        t.extend([0, 0, 0, 0]);
        t
    }

    #[test]
    fn fdes_give_their_ranges() {
        assert_eq!(code_ranges(&table(), 0x8000), Some(vec![(0x1000, 0x40), (0x2000, 0x10)]));
    }

    #[test]
    fn a_truncated_table_is_unusable() {
        let t = table();
        assert_eq!(code_ranges(&t[..t.len() - 9], 0x8000), None);
    }

    #[test]
    fn leb128() {
        let mut r = Reader { data: &[0xe5, 0x8e, 0x26, 0x7f], pos: 0 };
        assert_eq!(r.uleb(), Some(624_485));
        assert_eq!(r.sleb(), Some(-1));
    }
}
