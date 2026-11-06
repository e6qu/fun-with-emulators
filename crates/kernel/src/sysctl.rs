//! The sysctls of a network namespace (`/proc/sys/net/...`) that container
//! runtimes set: each namespace of fwe's keeps its own values in its record
//! ([`crate::ns::Net`]), which `/proc/sys` shows and a write there changes,
//! with Linux's checks. The initial namespace's are Linux's defaults and
//! cannot be changed (they would be the host's).

use crate::fdmarks::{self, Mark};
use fwe_abi::errno;

/// A sysctl fwe keeps: its path under `/proc/sys`, its default, and how a
/// value written to it is checked and kept.
struct Sysctl {
    path: &'static [u8],
    default: &'static str,
    kind: Kind,
}

#[derive(Clone, Copy)]
enum Kind {
    /// One integer, in a range.
    Int(i64, i64),
    /// Two integers, the first not above the second
    /// (`net.ipv4.ping_group_range`).
    Range,
}

const SYSCTLS: &[Sysctl] = &[
    Sysctl { path: b"net/ipv4/ping_group_range", default: "1\t0", kind: Kind::Range },
    Sysctl {
        path: b"net/ipv4/ip_unprivileged_port_start",
        default: "1024",
        kind: Kind::Int(0, 65536),
    },
    Sysctl { path: b"net/ipv4/ip_forward", default: "0", kind: Kind::Int(0, 1) },
    Sysctl { path: b"net/core/somaxconn", default: "4096", kind: Kind::Int(0, i32::MAX as i64) },
];

fn index(path: &[u8]) -> Option<usize> {
    let rel = path.strip_prefix(b"/proc/sys/")?;
    SYSCTLS.iter().position(|s| s.path == rel)
}

/// The value of sysctl `i` in the process's network namespace.
fn value(i: usize) -> String {
    let name = String::from_utf8_lossy(SYSCTLS[i].path).into_owned();
    crate::netns::current()
        .and_then(|n| n.get().sysctls.get(&name).cloned())
        .unwrap_or_else(|| SYSCTLS[i].default.to_string())
}

/// What `/proc/sys` shows at `path` (a sysctl fwe keeps), if it is one.
pub fn read(path: &[u8]) -> Option<Vec<u8>> {
    index(path).map(|i| format!("{}\n", value(i)).into_bytes())
}

/// The entries of `/proc/sys` directory `dir` that are sysctls fwe keeps
/// or directories of them.
pub fn children(dir: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let Some(rel) = dir.strip_prefix(b"/proc/sys") else { return Vec::new() };
    let rel = rel.strip_prefix(b"/").unwrap_or(rel);
    let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
    for s in SYSCTLS {
        let rest = if rel.is_empty() {
            Some(s.path)
        } else {
            s.path.strip_prefix(rel).and_then(|r| r.strip_prefix(b"/"))
        };
        let Some(rest) = rest else { continue };
        let (name, is_dir) = match rest.iter().position(|&b| b == b'/') {
            Some(i) => (&rest[..i], true),
            None => (rest, false),
        };
        if !out.iter().any(|(n, _)| n == name) {
            out.push((name.to_vec(), is_dir));
        }
    }
    out
}

/// Whether `path` is a directory of sysctls fwe keeps.
pub fn is_dir(path: &[u8]) -> bool {
    path.strip_prefix(b"/proc/sys/").is_some_and(|rel| {
        SYSCTLS.iter().any(|s| s.path.strip_prefix(rel).is_some_and(|r| r.first() == Some(&b'/')))
    })
}

/// Opening sysctl `path` to write, by a caller that has `CAP_NET_ADMIN`
/// (`admin`): the mark the descriptor carries, or the error.
pub fn open_for_write(path: &[u8], admin: bool) -> Option<Result<Mark, i32>> {
    let i = index(path)?;
    Some(if crate::netns::current().is_none() || !admin {
        // The initial namespace's are the host's.
        Err(errno::EACCES)
    } else {
        Ok(Mark::Sysctl(i as u8))
    })
}

/// A `write` of `len` bytes at guest `buf` to `fd`: for a sysctl opened
/// for writing, what the write does (`Some` result).
pub fn try_write(fd: i32, buf: u64, len: u64) -> Option<i64> {
    let Some(Mark::Sysctl(i)) = fdmarks::marked(fd) else { return None };
    let s = SYSCTLS.get(i as usize)?;
    let data = match crate::uaccess::read_bytes(buf, len.min(256) as usize) {
        Ok(d) => d,
        Err(e) => return Some(fwe_abi::err(e)),
    };
    let text = String::from_utf8_lossy(&data);
    let words: Vec<i64> = match text.split_whitespace().map(str::parse::<i64>).collect() {
        Ok(w) => w,
        Err(_) => return Some(fwe_abi::err(errno::EINVAL)),
    };
    let kept = match (s.kind, &words[..]) {
        (Kind::Int(lo, hi), [v]) if (lo..=hi).contains(v) => v.to_string(),
        (Kind::Range, [a, b]) if a <= b && *a >= 0 && *b <= i64::from(u32::MAX >> 1) => {
            format!("{a}\t{b}")
        }
        _ => return Some(fwe_abi::err(errno::EINVAL)),
    };
    let Some(net) = crate::netns::current() else { return Some(fwe_abi::err(errno::EACCES)) };
    let name = String::from_utf8_lossy(s.path).into_owned();
    let r = net.update(|n| {
        n.sysctls.insert(name.clone(), kept.clone());
        Ok(())
    });
    Some(match r {
        Ok(()) => len as i64,
        Err(e) => fwe_abi::err(e),
    })
}

/// The lowest port a caller without `CAP_NET_BIND_SERVICE` may bind in the
/// process's network namespace.
pub fn unprivileged_port_start() -> u16 {
    index(b"/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .and_then(|i| value(i).trim().parse().ok())
        .unwrap_or(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctls_and_their_directories() {
        assert_eq!(read(b"/proc/sys/net/ipv4/ping_group_range").unwrap(), b"1\t0\n");
        assert!(read(b"/proc/sys/net/ipv4/nope").is_none());
        assert!(is_dir(b"/proc/sys/net") && is_dir(b"/proc/sys/net/ipv4"));
        assert!(!is_dir(b"/proc/sys/net/ipv4/ip_forward"));
        let net: Vec<_> = children(b"/proc/sys/net").into_iter().map(|(n, _)| n).collect();
        assert_eq!(net, [b"ipv4".to_vec(), b"core".to_vec()]);
        assert!(children(b"/proc/sys").contains(&(b"net".to_vec(), true)));
        assert_eq!(unprivileged_port_start(), 1024);
    }
}
