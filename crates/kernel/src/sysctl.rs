//! The sysctls fwe keeps per namespace, as Linux does: a network
//! namespace's (`/proc/sys/net/...`, which container runtimes set) and an
//! IPC namespace's (`kernel.shmmax`, `kernel.msgmni` and the like, the
//! System V IPC limits, and `fs.mqueue.*`, the message queues'). Each namespace of fwe's keeps its own values in
//! its record ([`crate::ns::Net`], [`crate::sysvipc::Ipc`]), which
//! `/proc/sys` shows and a write there changes, with Linux's checks. The
//! initial network namespace's are Linux's defaults and cannot be changed
//! (they would be the host's); the initial IPC namespace is fwe's own, so
//! root may change its limits.

use crate::fdmarks::{self, Mark};
use fwe_abi::errno;
use fwe_abi::mqueue as mq;

/// A sysctl fwe keeps: its path under `/proc/sys`, its default, and how a
/// value written to it is checked and kept.
struct Sysctl {
    path: &'static [u8],
    default: &'static str,
    kind: Kind,
    space: Space,
}

/// Which namespace a sysctl is of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Space {
    Net,
    Ipc,
}

#[derive(Clone, Copy)]
enum Kind {
    /// One integer, in a range.
    Int(i64, i64),
    /// Two integers, the first not above the second
    /// (`net.ipv4.ping_group_range`).
    Range,
    /// One unsigned 64-bit integer (`kernel.shmmax`).
    U64,
    /// Integers, as many as given, each in a range (`kernel.sem`: four).
    Ints(usize, i64, i64),
}

const INT_MAX: i64 = i32::MAX as i64;
/// `IPCMNI`: the most objects of a kind a namespace may have.
const IPCMNI: i64 = 32768;

const SYSCTLS: &[Sysctl] = &[
    Sysctl {
        path: b"net/ipv4/ping_group_range",
        default: "1\t0",
        kind: Kind::Range,
        space: Space::Net,
    },
    Sysctl {
        path: b"net/ipv4/ip_unprivileged_port_start",
        default: "1024",
        kind: Kind::Int(0, 65535),
        space: Space::Net,
    },
    Sysctl { path: b"net/ipv4/ip_forward", default: "0", kind: Kind::Int(0, 1), space: Space::Net },
    Sysctl {
        path: b"net/core/somaxconn",
        default: "4096",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Net,
    },
    Sysctl {
        path: b"kernel/shmmax",
        default: "18446744073692774399",
        kind: Kind::U64,
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/shmall",
        default: "18446744073692774399",
        kind: Kind::U64,
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/shmmni",
        default: "4096",
        kind: Kind::Int(0, IPCMNI),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/sem",
        default: "32000\t1024000000\t500\t32000",
        kind: Kind::Ints(4, 0, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/msgmax",
        default: "8192",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/msgmnb",
        default: "16384",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/msgmni",
        default: "32000",
        kind: Kind::Int(0, IPCMNI),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"fs/mqueue/queues_max",
        default: "256",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"fs/mqueue/msg_max",
        default: "10",
        kind: Kind::Int(mq::MIN_MSGMAX, mq::HARD_MSGMAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"fs/mqueue/msgsize_max",
        default: "8192",
        kind: Kind::Int(mq::MIN_MSGSIZEMAX, mq::HARD_MSGSIZEMAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"fs/mqueue/msg_default",
        default: "10",
        kind: Kind::Int(mq::MIN_MSGMAX, mq::HARD_MSGMAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"fs/mqueue/msgsize_default",
        default: "8192",
        kind: Kind::Int(mq::MIN_MSGSIZEMAX, mq::HARD_MSGSIZEMAX),
        space: Space::Ipc,
    },
];

fn index(path: &[u8]) -> Option<usize> {
    let rel = path.strip_prefix(b"/proc/sys/")?;
    SYSCTLS.iter().position(|s| s.path == rel)
}

/// The value of sysctl `i` in the process's namespace of its kind.
fn value(i: usize) -> String {
    let name = String::from_utf8_lossy(SYSCTLS[i].path).into_owned();
    let set = match SYSCTLS[i].space {
        Space::Net => crate::netns::current().and_then(|n| n.get().sysctls.get(&name).cloned()),
        Space::Ipc => crate::sysvipc::current().and_then(|r| r.get().sysctls.get(&name).cloned()),
    };
    set.unwrap_or_else(|| SYSCTLS[i].default.to_string())
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

/// Opening sysctl `path` to write, by a caller with `creds`: the mark the
/// descriptor carries, or the error. A network one takes `CAP_NET_ADMIN`
/// in a namespace of fwe's (the initial one's are the host's); an IPC one,
/// root's access to the file (`CAP_DAC_OVERRIDE`).
pub fn open_for_write(path: &[u8], creds: &crate::creds::Creds) -> Option<Result<Mark, i32>> {
    let i = index(path)?;
    let allowed = match SYSCTLS[i].space {
        Space::Net => crate::netns::current().is_some() && creds.has(crate::caps::CAP_NET_ADMIN),
        Space::Ipc => creds.has(crate::caps::CAP_DAC_OVERRIDE),
    };
    Some(if allowed { Ok(Mark::Sysctl(i as u8)) } else { Err(errno::EACCES) })
}

/// A write of `len` bytes, `data` the first of them, to `fd`: for a
/// sysctl opened for writing, what the write does (`Some` result; see
/// [`crate::specialwrite`]).
pub fn try_write(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    let Some(Mark::Sysctl(_)) = fdmarks::marked(fd) else { return None };
    write_value(fd, &data[..data.len().min(256)], len)
}

/// Keep `data`, written to sysctl descriptor `fd` (`len` bytes in all).
fn write_value(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    let Some(Mark::Sysctl(i)) = fdmarks::marked(fd) else { return None };
    let s = SYSCTLS.get(i as usize)?;
    let text = String::from_utf8_lossy(data);
    let kept = if let Kind::U64 = s.kind {
        match text.trim().parse::<u64>() {
            Ok(v) => v.to_string(),
            Err(_) => return Some(fwe_abi::err(errno::EINVAL)),
        }
    } else {
        let words: Vec<i64> = match text.split_whitespace().map(str::parse::<i64>).collect() {
            Ok(w) => w,
            Err(_) => return Some(fwe_abi::err(errno::EINVAL)),
        };
        match (s.kind, &words[..]) {
            (Kind::Int(lo, hi), [v]) if (lo..=hi).contains(v) => v.to_string(),
            (Kind::Range, [a, b]) if a <= b && *a >= 0 && *b <= i64::from(u32::MAX >> 1) => {
                format!("{a}\t{b}")
            }
            (Kind::Ints(n, lo, hi), w)
                if w.len() == n && w.iter().all(|v| (lo..=hi).contains(v)) =>
            {
                w.iter().map(i64::to_string).collect::<Vec<_>>().join("\t")
            }
            _ => return Some(fwe_abi::err(errno::EINVAL)),
        }
    };
    let name = String::from_utf8_lossy(s.path).into_owned();
    let r = match s.space {
        Space::Net => {
            let Some(net) = crate::netns::current() else {
                return Some(fwe_abi::err(errno::EACCES));
            };
            net.update(|n| {
                n.sysctls.insert(name.clone(), kept.clone());
                Ok(())
            })
        }
        Space::Ipc => {
            let Some(ipc) = crate::sysvipc::current() else {
                return Some(fwe_abi::err(errno::ENOMEM));
            };
            ipc.update(|t| {
                t.sysctls.insert(name.clone(), kept.clone());
                Ok(())
            })
        }
    };
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
