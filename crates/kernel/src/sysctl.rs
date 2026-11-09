//! The sysctls fwe keeps per namespace, as Linux does: a network
//! namespace's (`/proc/sys/net/...`, which container runtimes set) and an
//! IPC namespace's (`kernel.shmmax`, `kernel.msgmni` and the like, the
//! System V IPC limits, and `fs.mqueue.*`, the message queues'). Each
//! namespace of fwe's keeps its own values in its record
//! ([`crate::ns::Net`], [`crate::sysvipc::Ipc`]), which
//! `/proc/sys` shows and a write there changes, with Linux's checks. The
//! initial network namespace's start at Linux's defaults and are kept with
//! the sysctls of no namespace: fwe consults them only for its own
//! namespaces, so changing them changes nothing on the host. The initial
//! IPC namespace is fwe's own, so root may change its limits.

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
    /// The rest: fwe's own, every process's ([`Globals`]).
    Global,
}

/// The sysctls of no namespace set from their defaults, by name: a record
/// every fwe process sees (`fs.inotify.*`, `kernel.keys.*`,
/// `vm.drop_caches`).
#[derive(Clone, Debug, Default)]
pub struct Globals(pub std::collections::BTreeMap<String, String>);

impl crate::shared::Data for Globals {
    fn encode(&self, e: &mut crate::snapshot::Enc) {
        e.u64(self.0.len() as u64);
        for (k, v) in &self.0 {
            e.bytes(k.as_bytes());
            e.bytes(v.as_bytes());
        }
    }
    fn decode(d: &mut crate::snapshot::Dec) -> Self {
        let n = d.count(16);
        Globals(
            (0..n)
                .map(|_| {
                    let (k, v) = (d.bytes(), d.bytes());
                    (
                        String::from_utf8_lossy(&k).into_owned(),
                        String::from_utf8_lossy(&v).into_owned(),
                    )
                })
                .collect(),
        )
    }
}

fn globals() -> Option<&'static crate::shared::Record<Globals>> {
    static G: std::sync::OnceLock<Option<crate::shared::Record<Globals>>> =
        std::sync::OnceLock::new();
    G.get_or_init(|| crate::shared::Record::named("sysctl", 0, Globals::default).ok()).as_ref()
}

/// The value of the sysctl at `path` (under `/proc/sys`, `fs/inotify/...`)
/// as a number, if it is one fwe keeps.
pub fn number(path: &[u8]) -> Option<i64> {
    text(path)?.trim().parse().ok()
}

/// The value of the sysctl at `path` (under `/proc/sys`), if it is one fwe
/// keeps.
pub fn text(path: &[u8]) -> Option<String> {
    let i = SYSCTLS.iter().position(|s| s.path == path)?;
    Some(value(i))
}

#[derive(Clone, Copy)]
enum Kind {
    /// One integer, in a range.
    Int(i64, i64),
    /// Two integers, a range (`net.ipv4.ping_group_range`).
    Range,
    /// One unsigned 64-bit integer (`kernel.shmmax`).
    U64,
    /// Integers, as many as given, each in a range (`kernel.sem`: four).
    Ints(usize, i64, i64),
    /// A line of text, up to the length given (with its NUL), the rest of
    /// a longer one dropped (`kernel.core_pattern`).
    Text(usize),
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
    // An interface's tag, for userspace: the loopback's, and what a new
    // interface takes (`default`), or every one is set to (`all`).
    Sysctl {
        path: b"net/ipv4/conf/all/tag",
        default: "0",
        kind: Kind::Int(0, u32::MAX as i64),
        space: Space::Net,
    },
    Sysctl {
        path: b"net/ipv4/conf/default/tag",
        default: "0",
        kind: Kind::Int(0, u32::MAX as i64),
        space: Space::Net,
    },
    Sysctl {
        path: b"net/ipv4/conf/lo/tag",
        default: "0",
        kind: Kind::Int(0, u32::MAX as i64),
        space: Space::Net,
    },
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
        path: b"fs/lease-break-time",
        default: "45",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/pipe-max-size",
        default: "1048576",
        kind: Kind::Int(4096, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/gc_delay",
        default: "300",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/maxbytes",
        default: "20000",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/maxkeys",
        default: "200",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/persistent_keyring_expiry",
        default: "259200",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/root_maxbytes",
        default: "25000000",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/keys/root_maxkeys",
        default: "1000000",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/inotify/max_queued_events",
        default: "16384",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/inotify/max_user_instances",
        default: "128",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/inotify/max_user_watches",
        default: "8192",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    // Pids are below it (fwe's namespaces number below it; the host's
    // own pids are the host's).
    Sysctl {
        path: b"kernel/pid_max",
        default: "4194304",
        kind: Kind::Int(301, 4_194_304),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/printk",
        default: "4\t4\t1\t7",
        kind: Kind::Ints(4, 0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/core_pattern",
        default: "core",
        kind: Kind::Text(128),
        space: Space::Global,
    },
    Sysctl {
        path: b"kernel/core_uses_pid",
        default: "0",
        kind: Kind::Int(0, 1),
        space: Space::Global,
    },
    Sysctl { path: b"vm/drop_caches", default: "0", kind: Kind::Int(1, 4), space: Space::Global },
    // Pipe buffer pages a user may hold before new pipes get the least
    // (soft) or none (hard, 0: no limit): Linux's defaults. A privileged
    // process (every root one) is not held to them.
    Sysctl {
        path: b"fs/pipe-user-pages-soft",
        default: "16384",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/pipe-user-pages-hard",
        default: "0",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    // The most descriptors a process may have: its `RLIMIT_NOFILE` and a
    // copy of a shared descriptor table are bounded by it.
    Sysctl {
        path: b"fs/nr_open",
        default: "1048576",
        kind: Kind::Int(64, 2_147_483_584),
        space: Space::Global,
    },
    Sysctl {
        path: b"vm/max_map_count",
        default: "65530",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
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
        Space::Net => match crate::netns::current() {
            Some(n) => n.get().sysctls.get(&name).cloned(),
            // The initial namespace's, kept with those of no namespace.
            None => globals().and_then(|r| r.get().0.get(&name).cloned()),
        },
        Space::Ipc => crate::sysvipc::current().and_then(|r| r.get().sysctls.get(&name).cloned()),
        Space::Global => globals().and_then(|r| r.get().0.get(&name).cloned()),
    };
    set.unwrap_or_else(|| SYSCTLS[i].default.to_string())
}

/// Set the sysctl of no namespace at `path` (under `/proc/sys`) to
/// `value`, as the kernel itself does (`syslog` setting the console's
/// level).
pub fn set_global(path: &[u8], value: String) -> Result<(), i32> {
    let s = SYSCTLS.iter().find(|s| s.path == path && s.space == Space::Global);
    let name = String::from_utf8_lossy(s.ok_or(errno::EINVAL)?.path).into_owned();
    globals().ok_or(errno::ENOMEM)?.update(|t| {
        t.0.insert(name, value);
        Ok(())
    })
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
        Space::Net => creds.has(crate::caps::CAP_NET_ADMIN),
        Space::Ipc | Space::Global => creds.has(crate::caps::CAP_DAC_OVERRIDE),
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
    let kept = if let Kind::Text(max) = s.kind {
        // The first line, as much of it as fits.
        let line = text.split('\n').next().unwrap_or("");
        let mut end = line.len().min(max - 1);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line[..end].to_string()
    } else if let Kind::U64 = s.kind {
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
            // A range of valid ids; a backwards one is taken as none
            // (`1 0`), as Linux takes it.
            (Kind::Range, [a, b])
                if *a >= 0 && *b >= 0 && *a.max(b) <= i64::from(u32::MAX >> 1) =>
            {
                if a <= b {
                    format!("{a}\t{b}")
                } else {
                    "1\t0".to_string()
                }
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
        Space::Net if crate::netns::current().is_some() => {
            let net = crate::netns::current()?;
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
        // The initial network namespace's, with those of no namespace.
        Space::Global | Space::Net => {
            let Some(r) = globals() else {
                return Some(fwe_abi::err(errno::ENOMEM));
            };
            r.update(|t| {
                t.0.insert(name.clone(), kept.clone());
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
