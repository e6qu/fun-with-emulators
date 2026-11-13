//! The entries of a layer archive, with what the host's `tar` cannot give
//! an unprivileged user: each entry's owner and its whole mode (set-ID
//! bits included), for `--pull` to keep as fwe keeps them.
//!
//! The host's `tar` turns the layer, however compressed, into a plain
//! archive (`tar -cf - @layer`), whose headers are read here: ustar, with
//! pax extended headers and GNU long names.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    /// A hard link, a device, a FIFO.
    Other,
}

/// One entry of a layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Relative to the root, with no `./` before it or `/` after.
    pub path: String,
    pub kind: Kind,
    /// Permission bits, set-ID and sticky bits included.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// The entries of the archive at `layer`.
pub fn read(layer: &Path) -> Result<Vec<Entry>, String> {
    let mut child = Command::new("tar")
        .args(["-cf", "-", "--format", "pax"])
        .arg(format!("@{}", layer.display()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("tar: {e}"))?;
    let mut out = std::io::BufReader::with_capacity(1 << 20, child.stdout.take().unwrap());
    let entries = parse(&mut out);
    // The rest unread (on an error), so the child does not wait to write.
    let _ = std::io::copy(&mut out, &mut std::io::sink());
    let r = child.wait_with_output().map_err(|e| format!("tar: {e}"))?;
    if !r.status.success() {
        return Err(format!("reading a layer: {}", String::from_utf8_lossy(&r.stderr).trim()));
    }
    entries
}

/// The entries of a plain tar archive read from `input`.
pub fn parse(input: &mut impl Read) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    // What a pax header or a GNU long name says of the next entry.
    let (mut path, mut uid, mut gid) = (None, None, None);
    let mut block = [0u8; 512];
    loop {
        if !read_block(input, &mut block)? || block.iter().all(|&b| b == 0) {
            return Ok(entries);
        }
        let size = number(&block[124..136])?;
        let kind = block[156];
        match kind {
            b'x' | b'L' => {
                let data = read_data(input, size)?;
                if kind == b'L' {
                    path = Some(String::from_utf8_lossy(trim_nul(&data)).into_owned());
                } else {
                    for (k, v) in pax_records(&data)? {
                        match k.as_str() {
                            "path" => path = Some(v),
                            "uid" => uid = v.parse().ok(),
                            "gid" => gid = v.parse().ok(),
                            _ => {}
                        }
                    }
                }
                continue;
            }
            // Global pax headers and GNU long link names: nothing this keeps.
            b'g' | b'K' => {
                read_data(input, size)?;
                continue;
            }
            _ => {}
        }
        let name = path.take().unwrap_or_else(|| {
            let name = String::from_utf8_lossy(trim_nul(&block[0..100])).into_owned();
            let prefix = trim_nul(&block[345..500]);
            if &block[257..262] == b"ustar" && !prefix.is_empty() {
                format!("{}/{name}", String::from_utf8_lossy(prefix))
            } else {
                name
            }
        });
        let entry = Entry {
            path: name.trim_start_matches("./").trim_end_matches('/').to_string(),
            kind: match kind {
                b'0' | 0 | b'7' => Kind::File,
                b'5' => Kind::Dir,
                b'2' => Kind::Symlink,
                _ => Kind::Other,
            },
            mode: number(&block[100..108])? as u32 & 0o7777,
            uid: uid.take().unwrap_or(number(&block[108..116])? as u32),
            gid: gid.take().unwrap_or(number(&block[116..124])? as u32),
        };
        // A hard link's size is 0: its data is its target's.
        if matches!(entry.kind, Kind::File) {
            skip(input, size)?;
        }
        if !entry.path.is_empty() && entry.path != "." {
            entries.push(entry);
        }
    }
}

/// Read a whole block; `false` at the end of the input.
fn read_block(input: &mut impl Read, block: &mut [u8; 512]) -> Result<bool, String> {
    let mut got = 0;
    while got < 512 {
        match input.read(&mut block[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err("a layer ends inside a header".to_string()),
            Ok(n) => got += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(true)
}

/// An entry's data, `size` bytes and the padding to a whole block.
fn read_data(input: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    if size > 1 << 20 {
        return Err("a layer has a header record too large".to_string());
    }
    let mut data = vec![0u8; size.next_multiple_of(512) as usize];
    input.read_exact(&mut data).map_err(|e| e.to_string())?;
    data.truncate(size as usize);
    Ok(data)
}

/// Skip `size` bytes of data and the padding.
fn skip(input: &mut impl Read, size: u64) -> Result<(), String> {
    let n = size.next_multiple_of(512);
    let copied =
        std::io::copy(&mut input.take(n), &mut std::io::sink()).map_err(|e| e.to_string())?;
    if copied != n {
        return Err("a layer ends inside an entry".to_string());
    }
    Ok(())
}

fn trim_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// A header's number field: octal digits, or base-256 with the top bit set.
fn number(field: &[u8]) -> Result<u64, String> {
    if field[0] & 0x80 != 0 {
        return Ok(field[1..]
            .iter()
            .fold(u64::from(field[0] & 0x7f), |n, &b| n << 8 | u64::from(b)));
    }
    let digits = trim_nul(field);
    let text = String::from_utf8_lossy(digits);
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| format!("a layer has a bad number field {text:?}"))
}

/// A pax header's `length key=value\n` records.
fn pax_records(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let space = data[at..].iter().position(|&c| c == b' ').ok_or("a bad pax record")?;
        let len: usize = std::str::from_utf8(&data[at..at + space])
            .ok()
            .and_then(|n| n.parse().ok())
            .filter(|&n| n > space + 1 && at + n <= data.len())
            .ok_or("a bad pax record length")?;
        let record = &data[at + space + 1..at + len - 1];
        if let Some(eq) = record.iter().position(|&c| c == b'=') {
            out.push((
                String::from_utf8_lossy(&record[..eq]).into_owned(),
                String::from_utf8_lossy(&record[eq + 1..]).into_owned(),
            ));
        }
        at += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header block for `name`.
    fn header(name: &str, kind: u8, mode: u32, uid: u32, gid: u32, size: usize) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[..name.len()].copy_from_slice(name.as_bytes());
        let mut field = |at: usize, len: usize, v: u64| {
            let s = format!("{v:0w$o}", w = len - 1);
            b[at..at + len - 1].copy_from_slice(s.as_bytes());
        };
        field(100, 8, u64::from(mode));
        field(108, 8, u64::from(uid));
        field(116, 8, u64::from(gid));
        field(124, 12, size as u64);
        b[156] = kind;
        b[257..263].copy_from_slice(b"ustar\0");
        b
    }

    #[test]
    fn headers_give_owners_modes_and_long_names() {
        let mut a = Vec::new();
        a.extend(header("./usr/", b'5', 0o755, 0, 0, 0));
        a.extend(header("./usr/bin/su", b'0', 0o4755, 0, 0, 3));
        a.extend(*b"abc");
        a.resize(a.len().next_multiple_of(512), 0);
        // A pax header naming the next entry and its owner.
        let long = format!("var/{}", "x".repeat(150));
        // A record's length counts its own digits.
        let rec = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut n = body.len() + 1;
            while n != body.len() + n.to_string().len() {
                n = body.len() + n.to_string().len();
            }
            format!("{n}{body}")
        };
        let pax = format!("{}{}", rec("path", &long), rec("uid", "100"));
        a.extend(header("pax", b'x', 0o644, 0, 0, pax.len()));
        a.extend(pax.as_bytes());
        a.resize(a.len().next_multiple_of(512), 0);
        a.extend(header("short", b'0', 0o640, 0, 42, 0));
        a.extend(header("etc/link", b'2', 0o777, 0, 0, 0));
        a.extend([0u8; 1024]);
        let entries = parse(&mut a.as_slice()).unwrap();
        let e = |path: &str, kind, mode, uid, gid| Entry {
            path: path.to_string(),
            kind,
            mode,
            uid,
            gid,
        };
        assert_eq!(
            entries,
            [
                e("usr", Kind::Dir, 0o755, 0, 0),
                e("usr/bin/su", Kind::File, 0o4755, 0, 0),
                e(&long, Kind::File, 0o640, 100, 42),
                e("etc/link", Kind::Symlink, 0o777, 0, 0),
            ]
        );
    }

    #[test]
    fn number_fields_read_both_ways() {
        assert_eq!(number(b"0000755\0").unwrap(), 0o755);
        assert_eq!(number(b"  644 \0").unwrap(), 0o644);
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 0, 1, 0]).unwrap(), 256);
        assert!(number(b"9\0").is_err());
    }
}
