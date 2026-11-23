//! A tmpfs's options as Linux reads them ([`parse`]): what a filesystem of
//! fwe's store a tmpfs is made with ([`crate::filestore`]) and remounted
//! to.

use fwe_abi::errno;

/// What a tmpfs's options (`mount`'s data, `fsconfig`'s parameters) ask
/// for, of what fwe acts on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// `size=` (or `nr_blocks=`), in bytes.
    pub size: Option<u64>,
    /// `nr_inodes=`: 0 is no limit.
    pub inodes: Option<u64>,
    /// `mode=`, of the root.
    pub mode: Option<u32>,
    /// `uid=` and `gid=`, of the root, as the mounter's namespace has
    /// them.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Tmpfs options `data` (comma-separated), as Linux's `shmem_parse_one`
/// reads them: a value it refuses is `EINVAL`; an option fwe does not act
/// on is taken as given.
pub fn parse(data: &[u8]) -> Result<Options, i32> {
    let mut o = Options::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        let text = || value.and_then(|v| std::str::from_utf8(v).ok()).ok_or(errno::EINVAL);
        match key {
            b"size" => {
                let s = text()?;
                o.size = Some(match s.strip_suffix('%') {
                    Some(p) => memory_bytes() / 100 * memparse(p)?,
                    None => memparse(s)?,
                });
            }
            b"nr_blocks" => {
                o.size = Some(memparse(text()?)?.checked_mul(4096).ok_or(errno::EINVAL)?)
            }
            b"nr_inodes" => o.inodes = Some(memparse(text()?)?),
            b"mode" => {
                o.mode = Some(u32::from_str_radix(text()?, 8).map_err(|_| errno::EINVAL)? & 0o7777)
            }
            b"uid" => o.uid = Some(number(text()?)?),
            b"gid" => o.gid = Some(number(text()?)?),
            _ => {}
        }
    }
    Ok(o)
}

/// A number as the kernel's `kstrtouint` with base 0 reads it: decimal,
/// `0x` hexadecimal or `0` octal.
fn number(s: &str) -> Result<u32, i32> {
    let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8)
    } else {
        s.parse()
    };
    n.map_err(|_| errno::EINVAL)
}

/// A size as the kernel's `memparse` reads it: a number (decimal, `0x`
/// hexadecimal or `0` octal) and a `K`, `M`, `G`, `T`, `P` or `E` suffix
/// (either case), and nothing after.
fn memparse(s: &str) -> Result<u64, i32> {
    let (num, shift) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 10),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 20),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 30),
        Some(b't' | b'T') => (&s[..s.len() - 1], 40),
        Some(b'p' | b'P') => (&s[..s.len() - 1], 50),
        Some(b'e' | b'E') => (&s[..s.len() - 1], 60),
        _ => (s, 0),
    };
    let n = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else if num.len() > 1 && num.starts_with('0') {
        u64::from_str_radix(&num[1..], 8)
    } else {
        num.parse()
    };
    let n = n.map_err(|_| errno::EINVAL)?;
    n.checked_mul(1 << shift).ok_or(errno::EINVAL)
}

/// The size a tmpfs has when its options give none: half the memory, as
/// Linux's `shmem_default_max_blocks`.
pub fn default_size() -> u64 {
    memory_bytes() / 2
}

/// The inodes a tmpfs has when its options give no number: one for each
/// two pages of memory, as Linux's `shmem_default_max_inodes`.
pub fn default_inodes() -> u64 {
    memory_bytes() / 4096 / 2
}

/// The host's memory, in bytes.
fn memory_bytes() -> u64 {
    // SAFETY: plain host calls.
    let (pages, page) =
        unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    (pages.max(0) as u64).saturating_mul(page.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_size(data: &[u8]) -> Option<u64> {
        parse(data).ok()?.size
    }

    #[test]
    fn sizes_parse_as_linux_reads_them() {
        assert_eq!(parse_size(b"mode=755,size=32M"), Some(32 << 20));
        assert_eq!(parse_size(b"size=4k"), Some(4096));
        assert_eq!(parse_size(b"size=2G,nr_inodes=10"), Some(2 << 30));
        assert_eq!(parse_size(b"size=100"), Some(100));
        assert_eq!(parse_size(b"mode=755"), None);
        assert!(parse_size(b"size=50%").is_some_and(|n| n > 0));
    }

    /// `nr_inodes=`, `mode=`, `uid=` and `gid=` read as Linux reads them;
    /// a value it refuses is `EINVAL`, an option fwe does not act on is
    /// taken.
    #[test]
    fn options_parse_as_linux_reads_them() {
        let o = parse(b"nr_inodes=1k,mode=01777,uid=1000,gid=0x10,huge=never").unwrap();
        let want = Options {
            size: None,
            inodes: Some(1024),
            mode: Some(0o1777),
            uid: Some(1000),
            gid: Some(16),
        };
        assert_eq!(o, want);
        assert_eq!(parse(b"nr_blocks=2").unwrap().size, Some(8192));
        assert_eq!(parse(b"mode=17777").unwrap().mode, Some(0o7777));
        for bad in [&b"size=lots"[..], b"nr_inodes=1%", b"uid=-1", b"gid=", b"mode=9", b"nr_inodes"]
        {
            assert_eq!(parse(bad), Err(errno::EINVAL), "{}", String::from_utf8_lossy(bad));
        }
    }
}
