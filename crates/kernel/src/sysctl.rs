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
    /// A user namespace's limits (`user.max_*`): the initial one's with
    /// the rest, another's in a record inside its own ([`user_limit`]).
    User,
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

/// Whether `fs.protected_symlinks` and `fs.protected_hardlinks` are on,
/// read again only when a sysctl has changed (the walk asks at each link).
pub fn protected_links() -> (bool, bool) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// The record's generation the values are of (`u64::MAX`: none yet),
    /// and the values (bit 0: symlinks, bit 1: hardlinks).
    static SEEN: AtomicU64 = AtomicU64::new(u64::MAX);
    static BITS: AtomicU64 = AtomicU64::new(0);
    let Some(r) = globals() else { return (false, false) };
    let now = r.generation();
    if SEEN.load(Ordering::Acquire) != now {
        let on = |p: &[u8]| number(p).is_some_and(|n| n != 0);
        let bits =
            u64::from(on(b"fs/protected_symlinks")) | u64::from(on(b"fs/protected_hardlinks")) << 1;
        BITS.store(bits, Ordering::Release);
        SEEN.store(now, Ordering::Release);
    }
    let bits = BITS.load(Ordering::Acquire);
    (bits & 1 != 0, bits & 2 != 0)
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
/// Yama's `ptrace_scope`, whose writes are Yama's to check.
const YAMA_SCOPE: &[u8] = b"kernel/yama/ptrace_scope";
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
    // The most connections `listen` queues.
    Sysctl {
        path: b"net/core/somaxconn",
        default: "4096",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Net,
    },
    // The largest socket buffers `SO_RCVBUF` and `SO_SNDBUF` give.
    Sysctl {
        path: b"net/core/rmem_max",
        default: "212992",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Net,
    },
    Sysctl {
        path: b"net/core/wmem_max",
        default: "212992",
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
    // The id the next object of a kind gets (-1: any), for checkpoint and
    // restore, used once ([`crate::sysvipc::Ipc::create`]).
    Sysctl {
        path: b"kernel/msg_next_id",
        default: "-1",
        kind: Kind::Int(-1, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/sem_next_id",
        default: "-1",
        kind: Kind::Int(-1, INT_MAX),
        space: Space::Ipc,
    },
    Sysctl {
        path: b"kernel/shm_next_id",
        default: "-1",
        kind: Kind::Int(-1, INT_MAX),
        space: Space::Ipc,
    },
    // The most AIO events all contexts may hold.
    Sysctl {
        path: b"fs/aio-max-nr",
        default: "65536",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/lease-break-time",
        default: "45",
        kind: Kind::Int(0, INT_MAX),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/protected_hardlinks",
        default: "0",
        kind: Kind::Int(0, 1),
        space: Space::Global,
    },
    // Whether a process that raised privilege, or changed its credentials,
    // stays dumpable: 0 no, 1 yes, 2 for root only (`PR_GET_DUMPABLE` 2).
    Sysctl { path: b"fs/suid_dumpable", default: "0", kind: Kind::Int(0, 2), space: Space::Global },
    // Yama: who may attach to a process (`ptrace`, `/proc/<pid>/mem`,
    // `process_vm_readv`): 0 any process of the same ids, 1 only its
    // ancestors and the one it names, 2 only with `CAP_SYS_PTRACE`, 3 none.
    // Setting it takes `CAP_SYS_PTRACE`, and 3 cannot be undone.
    Sysctl {
        path: b"kernel/yama/ptrace_scope",
        default: "1",
        kind: Kind::Int(0, 3),
        space: Space::Global,
    },
    Sysctl {
        path: b"fs/protected_symlinks",
        default: "0",
        kind: Kind::Int(0, 1),
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
    // Kept, with no effect: the page cache is the host's, which only the
    // host's root may drop.
    Sysctl { path: b"vm/drop_caches", default: "0", kind: Kind::Int(1, 4), space: Space::Global },
    // Pipe buffer pages a user may hold before new pipes get the least
    // (soft) or none (hard, 0: no limit), at Linux's defaults. Kept, not
    // enforced: a pipe is a host pipe, whose buffer the host sizes.
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
    // The most namespaces of each kind the user namespace and those below
    // it may hold, which [`crate::ns::may_make`] holds new ones to: half
    // of `kernel.threads-max` in the initial one, as on Linux, and no
    // limit of its own in another until set.
    Sysctl {
        path: b"user/max_cgroup_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_ipc_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_mnt_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_net_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_pid_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_time_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_user_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
    },
    Sysctl {
        path: b"user/max_uts_namespaces",
        default: "127414",
        kind: Kind::Int(0, INT_MAX),
        space: Space::User,
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
        Space::User => match crate::userns::chain().first() {
            Some(u) => {
                return limits_of(u.dir()).map_or_else(
                    || INT_MAX.to_string(),
                    |r| r.get().0.get(&name).cloned().unwrap_or_else(|| INT_MAX.to_string()),
                );
            }
            None => globals().and_then(|r| r.get().0.get(&name).cloned()),
        },
    };
    set.unwrap_or_else(|| SYSCTLS[i].default.to_string())
}

/// The limits set in the user namespace whose record is at `dir`: a
/// record inside it, which lives as long as it does (kept open, one per
/// namespace, for the process's life).
fn limits_of(dir: &[u8]) -> Option<std::sync::Arc<crate::shared::Record<Globals>>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    type Open = Mutex<Option<HashMap<Vec<u8>, Arc<crate::shared::Record<Globals>>>>>;
    static OPEN: Open = Mutex::new(None);
    let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    let open = open.get_or_insert_with(HashMap::new);
    if let Some(r) = open.get(dir) {
        return Some(r.clone());
    }
    let r = Arc::new(crate::shared::Record::at([dir, b"/limits"].concat(), Globals::default).ok()?);
    open.insert(dir.to_vec(), r.clone());
    Some(r)
}

/// The limit `name` (`user/max_net_namespaces`) of the user namespace
/// whose record is at `dir` (`None`: the initial one).
pub fn user_limit(dir: Option<&[u8]>, name: &str) -> i64 {
    let set = match dir {
        Some(d) => {
            limits_of(d).and_then(|r| r.get().0.get(name).cloned()).unwrap_or(INT_MAX.to_string())
        }
        None => globals()
            .and_then(|r| r.get().0.get(name).cloned())
            .or_else(|| {
                SYSCTLS.iter().find(|s| s.path == name.as_bytes()).map(|s| s.default.into())
            })
            .unwrap_or_default(),
    };
    set.trim().parse().unwrap_or(INT_MAX)
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
/// in the user namespace owning the network namespace; an IPC one, root's
/// access to the file (`CAP_DAC_OVERRIDE`) in the user namespace owning
/// the IPC namespace; any other, root's access in the initial user
/// namespace: a user namespace has no say over the whole system's.
pub fn open_for_write(path: &[u8], creds: &crate::creds::Creds) -> Option<Result<Mark, i32>> {
    use crate::caps::{CAP_DAC_OVERRIDE, CAP_NET_ADMIN};
    let i = index(path)?;
    if SYSCTLS[i].path == YAMA_SCOPE && !creds.has(crate::caps::CAP_SYS_PTRACE) {
        return Some(Err(errno::EPERM));
    }
    let allowed = match SYSCTLS[i].space {
        Space::Net => creds.has_in(&crate::netns::owner(), CAP_NET_ADMIN),
        Space::Ipc => creds.has_in(&crate::sysvipc::owner(), CAP_DAC_OVERRIDE),
        Space::Global => creds.has(CAP_DAC_OVERRIDE),
        // `CAP_SYS_RESOURCE` in the caller's own user namespace, whose
        // limits these are, as Linux checks it.
        Space::User => creds.has_own(crate::caps::CAP_SYS_RESOURCE),
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
            // Yama's scope 3 is for good.
            (Kind::Int(..), [v])
                if s.path == YAMA_SCOPE && *v != 3 && number(YAMA_SCOPE) == Some(3) =>
            {
                return Some(fwe_abi::err(errno::EINVAL));
            }
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
        Space::User if !crate::userns::chain().is_empty() => {
            let dir = crate::userns::chain()[0].dir().to_vec();
            let Some(r) = limits_of(&dir) else {
                return Some(fwe_abi::err(errno::ENOMEM));
            };
            r.update(|t| {
                t.0.insert(name.clone(), kept.clone());
                Ok(())
            })
        }
        // The initial network namespace's, with those of no namespace.
        Space::Global | Space::Net | Space::User => {
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

/// The most connections a `listen` in the process's network namespace
/// queues (`net.core.somaxconn`).
pub fn somaxconn() -> i32 {
    number(b"net/core/somaxconn").map_or(4096, |n| n.clamp(0, INT_MAX) as i32)
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
        assert_eq!(read(b"/proc/sys/net/core/rmem_max").unwrap(), b"212992\n");
        assert_eq!(read(b"/proc/sys/user/max_user_namespaces").unwrap(), b"127414\n");
        assert!(is_dir(b"/proc/sys/user"));
        let user: Vec<_> = children(b"/proc/sys/user").into_iter().map(|(n, _)| n).collect();
        assert_eq!(user.len(), 8);
        assert_eq!(somaxconn(), 4096);
    }
}
