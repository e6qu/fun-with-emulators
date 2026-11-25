//! Synthetic `/proc` and `/sys` entries.
//!
//! The guest's root filesystem has no real `/proc` or `/sys`, so a small set
//! of the files programs read at startup are generated here. The filesystem
//! layer consults [`lookup`] before touching the host rootfs.

use crate::syscalls::RELEASE;

/// Per-process information the synthetic files draw on.
#[derive(Clone, Default)]
pub struct ProcInfo {
    /// Absolute guest path of the running program (`/proc/self/exe`).
    pub exe: Vec<u8>,
    /// `argv` joined by NUL with a trailing NUL (`/proc/self/cmdline`).
    pub cmdline: Vec<u8>,
    /// Online CPU count.
    pub ncpu: u32,
    /// Host name.
    pub hostname: Vec<u8>,
    /// fwe's descriptor of the running program when it has no path (a
    /// memfd it was executed from), which `/proc/self/exe` opens.
    pub exe_fd: Option<i32>,
    /// The auxiliary vector the program started with, as words
    /// (`/proc/self/auxv`).
    pub auxv: Vec<u8>,
}

/// A synthetic entry for a `/proc` or `/sys` path.
pub enum Entry {
    /// A regular file with this content.
    File(Vec<u8>),
    /// A symlink to this target.
    Symlink(Vec<u8>),
    /// `/proc/self/fd/N`: a link to what open descriptor `fd` refers to.
    /// `target` is a guest path, or a name such as `pipe:[ino]` for
    /// something without one; opening it reopens the file, or duplicates
    /// the descriptor when there is no path.
    Fd { fd: i32, target: Vec<u8> },
    /// A synthetic directory (its entries come from [`children`]).
    Dir,
    /// A namespace's file bound to a path (an nsfs mount): opening it
    /// gives a descriptor of the namespace.
    Ns(crate::nsfd::NsRef),
    /// A path under `/proc` or `/sys` that is not there to the caller: the
    /// errno its lookup fails with (`ENOENT`; `ESRCH` in the descriptor
    /// directories of a process that has ended, [`crate::fs::ProcPin`]).
    Missing(i32),
}

/// `hidepid=` of a `proc` mount: another's `/proc/<pid>` is open to all
/// (`off`); its directory listed but nothing in it reached (`EPERM`) by
/// one who cannot trace it (`noaccess`); or not there at all to such a
/// reader (`ENOENT`), whom `ptraceable` names as Linux's own check does
/// and `invisible` likewise.
pub const HIDEPID_OFF: u8 = 0;
pub const HIDEPID_NO_ACCESS: u8 = 1;
pub const HIDEPID_INVISIBLE: u8 = 2;
pub const HIDEPID_NOT_PTRACEABLE: u8 = 4;

/// The `hidepid=` value `v` names (a number or a name), if Linux takes it.
pub fn hidepid(v: &[u8]) -> Option<u8> {
    Some(match v {
        b"0" | b"off" => HIDEPID_OFF,
        b"1" | b"noaccess" => HIDEPID_NO_ACCESS,
        b"2" | b"invisible" => HIDEPID_INVISIBLE,
        b"4" | b"ptraceable" => HIDEPID_NOT_PTRACEABLE,
        _ => return None,
    })
}

/// What a `proc` mount's options hide: `hidepid=`, the group `gid=`
/// exempts from it (an initial-namespace id), and `subset=pid` (only the
/// processes' directories, `self` and `thread-self`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hiding {
    pub hidepid: u8,
    pub gid: Option<u32>,
    pub pids_only: bool,
}

impl Hiding {
    /// What options `options` (as the mount keeps them) hide.
    pub fn of(options: &[u8]) -> Hiding {
        let mut h = Hiding::default();
        for o in options.split(|&b| b == b',') {
            if let Some(v) = o.strip_prefix(b"hidepid=") {
                h.hidepid = hidepid(v).unwrap_or(HIDEPID_OFF);
            } else if let Some(v) = o.strip_prefix(b"gid=") {
                h.gid = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok());
            } else if let Some(v) = o.strip_prefix(b"subset=") {
                h.pids_only = v == b"pid";
            }
        }
        h
    }

    /// Whether it hides anything.
    pub fn any(&self) -> bool {
        self.hidepid != HIDEPID_OFF || self.pids_only
    }

    /// What it refuses of `fs_path` (a path in the mount, `/123/status`),
    /// `traceable` telling whether the reader can trace the process a
    /// number names (its own always): `ENOENT` for what it hides, `EPERM`
    /// for what `noaccess` keeps out of; `None` for the rest.
    pub fn refuses(&self, fs_path: &[u8], traceable: impl FnOnce(i32) -> bool) -> Option<i32> {
        let rel = fs_path.strip_prefix(b"/").unwrap_or(fs_path);
        let (first, rest) = match rel.iter().position(|&b| b == b'/') {
            Some(i) => (&rel[..i], &rel[i + 1..]),
            None => (rel, &b""[..]),
        };
        if first.is_empty() {
            return None;
        }
        let pid = std::str::from_utf8(first).ok().and_then(|s| s.parse::<i32>().ok());
        let Some(pid) = pid.filter(|_| first.iter().all(u8::is_ascii_digit)) else {
            let own = matches!(first, b"self" | b"thread-self");
            return (self.pids_only && !own).then_some(fwe_abi::errno::ENOENT);
        };
        if self.hidepid == HIDEPID_OFF || traceable(pid) {
            return None;
        }
        if self.hidepid >= HIDEPID_INVISIBLE {
            return Some(fwe_abi::errno::ENOENT);
        }
        (!rest.is_empty()).then_some(fwe_abi::errno::EPERM)
    }
}

/// Linux `d_type` values used in directory listings.
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// One listed entry: `(name, d_type)`.
type Child = (&'static [u8], u8);
/// One synthetic directory: `(path, entries)`.
type DirDef = (&'static [u8], &'static [Child]);

/// The kernel configuration fwe presents: what it implements, in the
/// options' terms (an option not listed is not set; the ones programs ask
/// about by name are said to be not set), for the programs and test suites
/// that read `/proc/config.gz` to tell what the kernel has. The calls of
/// an option not set fail as on a kernel built without it (`ENOSYS`).
const CONFIG: &str = "\
# Linux/arm64 Kernel Configuration, as fwe implements it
CONFIG_ARM64=y
CONFIG_64BIT=y
CONFIG_MMU=y
CONFIG_ARM64_4K_PAGES=y
CONFIG_ARM64_VA_BITS_48=y
CONFIG_PGTABLE_LEVELS=4
CONFIG_SMP=y
CONFIG_HZ_250=y
CONFIG_HZ=250
CONFIG_HIGH_RES_TIMERS=y
CONFIG_POSIX_TIMERS=y
CONFIG_SYSCTL=y
CONFIG_PROC_SYSCTL=y
CONFIG_FILE_LOCKING=y
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_FHANDLE=y
CONFIG_KCMP=y
CONFIG_CROSS_MEMORY_ATTACH=y
CONFIG_CACHESTAT_SYSCALL=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
CONFIG_MULTIUSER=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_AIO=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FSNOTIFY=y
CONFIG_SHMEM=y
CONFIG_TMPFS=y
CONFIG_TMPFS_XATTR=y
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_BLOCK=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_LOOP_MIN_COUNT=8
CONFIG_MEMFD_CREATE=y
CONFIG_UNIX98_PTYS=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_SYSVIPC=y
CONFIG_CHECKPOINT_RESTORE=y
CONFIG_BSD_PROCESS_ACCT=y
CONFIG_BSD_PROCESS_ACCT_V3=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_PIDS=y
CONFIG_CPUSETS=y
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_BLK_CGROUP=y
CONFIG_MEMCG=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_MISC=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_YAMA=y
CONFIG_LSM=\"capability,landlock,yama\"
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_OVERLAY_FS=y
CONFIG_NET=y
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_KEYS=y
CONFIG_PERSISTENT_KEYRINGS=y
CONFIG_BIG_KEYS=y
CONFIG_ENCRYPTED_KEYS=y
CONFIG_USER_DECRYPTED_DATA=y
CONFIG_KEY_DH_OPERATIONS=y
CONFIG_DNS_RESOLVER=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS8_PRIVATE_KEY_PARSER=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_CRYPTO_DH=y
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_HMAC=y
# CONFIG_MODULES is not set
# CONFIG_IO_URING is not set
# CONFIG_PERF_EVENTS is not set
# CONFIG_FANOTIFY is not set
# CONFIG_USERFAULTFD is not set
# CONFIG_TIME_NS is not set
# CONFIG_RSEQ is not set
# CONFIG_NUMA is not set
# CONFIG_SECRETMEM is not set
";

/// [`CONFIG`], gzipped as `/proc/config.gz` is (in stored blocks: the
/// format, not the size, is what readers need).
fn config_gz() -> Vec<u8> {
    gzip_stored(CONFIG.as_bytes())
}

/// `data` as a gzip stream of stored (uncompressed) deflate blocks.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    // Magic, deflate, no flags, no time, no extra flags, Unix.
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        let len = chunk.len() as u16;
        out.push(last as u8);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// The CRC-32 gzip ends with (IEEE 802.3, reflected).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// The synthetic directory tree: each directory and the entries it lists.
const DIRS: &[DirDef] = &[
    (
        b"/proc",
        &[
            (b"self", DT_DIR),
            (b"version", DT_REG),
            (b"cpuinfo", DT_REG),
            (b"meminfo", DT_REG),
            (b"stat", DT_REG),
            (b"uptime", DT_REG),
            (b"loadavg", DT_REG),
            (b"filesystems", DT_REG),
            (b"sys", DT_DIR),
            (b"mounts", DT_LNK),
            (b"cmdline", DT_REG),
            (b"config.gz", DT_REG),
            (b"sysvipc", DT_DIR),
            (b"partitions", DT_REG),
            (b"keys", DT_REG),
            (b"key-users", DT_REG),
            (b"net", DT_LNK),
        ],
    ),
    (
        b"/proc/self",
        &[
            (b"stat", DT_REG),
            (b"status", DT_REG),
            (b"comm", DT_REG),
            (b"task", DT_DIR),
            (b"cwd", DT_LNK),
            (b"root", DT_LNK),
            (b"exe", DT_LNK),
            (b"cmdline", DT_REG),
            (b"fd", DT_DIR),
            (b"fdinfo", DT_DIR),
            (b"ns", DT_DIR),
            (b"mountinfo", DT_REG),
            (b"mounts", DT_REG),
            (b"uid_map", DT_REG),
            (b"gid_map", DT_REG),
            (b"setgroups", DT_REG),
            (b"cgroup", DT_REG),
            (b"oom_score_adj", DT_REG),
            (b"oom_adj", DT_REG),
            (b"oom_score", DT_REG),
            (b"coredump_filter", DT_REG),
            (b"mem", DT_REG),
            (b"pagemap", DT_REG),
            (b"timerslack_ns", DT_REG),
            (b"maps", DT_REG),
            (b"smaps", DT_REG),
            (b"personality", DT_REG),
            (b"auxv", DT_REG),
            (b"environ", DT_REG),
            (b"limits", DT_REG),
            (b"statm", DT_REG),
            (b"io", DT_REG),
            (b"net", DT_DIR),
        ],
    ),
    (
        b"/proc/self/net",
        &[
            (b"dev", DT_REG),
            (b"if_inet6", DT_REG),
            (b"route", DT_REG),
            (b"snmp", DT_REG),
            (b"tcp", DT_REG),
            (b"tcp6", DT_REG),
            (b"udp", DT_REG),
            (b"udp6", DT_REG),
            (b"unix", DT_REG),
        ],
    ),
    (
        b"/proc/self/ns",
        &[
            (b"cgroup", DT_LNK),
            (b"ipc", DT_LNK),
            (b"mnt", DT_LNK),
            (b"net", DT_LNK),
            (b"pid", DT_LNK),
            (b"pid_for_children", DT_LNK),
            (b"user", DT_LNK),
            (b"uts", DT_LNK),
        ],
    ),
    // Listed from the open descriptors (see `Fs::synth_children`).
    (b"/proc/self/fd", &[]),
    (b"/proc/sys", &[(b"kernel", DT_DIR), (b"vm", DT_DIR), (b"fs", DT_DIR)]),
    (b"/proc/sysvipc", &[(b"shm", DT_REG), (b"sem", DT_REG), (b"msg", DT_REG)]),
    // With the sysctls fwe keeps there ([`crate::sysctl::children`]).
    (b"/proc/sys/fs", &[(b"file-max", DT_REG)]),
    (
        b"/proc/sys/kernel",
        &[
            (b"ostype", DT_REG),
            (b"osrelease", DT_REG),
            (b"version", DT_REG),
            (b"hostname", DT_REG),
            (b"cap_last_cap", DT_REG),
            (b"ngroups_max", DT_REG),
            (b"overflowuid", DT_REG),
            (b"overflowgid", DT_REG),
            (b"threads-max", DT_REG),
            (b"domainname", DT_REG),
            (b"tainted", DT_REG),
            (b"random", DT_DIR),
        ],
    ),
    (
        b"/proc/sys/kernel/random",
        &[
            (b"entropy_avail", DT_REG),
            (b"poolsize", DT_REG),
            (b"uuid", DT_REG),
            (b"boot_id", DT_REG),
        ],
    ),
    (b"/proc/sys/vm", &[(b"overcommit_memory", DT_REG), (b"mmap_min_addr", DT_REG)]),
    (
        b"/sys",
        &[
            (b"devices", DT_DIR),
            (b"fs", DT_DIR),
            (b"block", DT_DIR),
            (b"dev", DT_DIR),
            (b"kernel", DT_DIR),
        ],
    ),
    (b"/sys/kernel", &[(b"security", DT_DIR)]),
    // securityfs: the security modules, Linux's capabilities and Landlock.
    (b"/sys/kernel/security", &[(b"lsm", DT_REG)]),
    // Where the cgroup hierarchy is mounted.
    (b"/sys/fs", &[(b"cgroup", DT_DIR)]),
    (b"/sys/fs/cgroup", &[]),
    (b"/sys/devices", &[(b"system", DT_DIR), (b"virtual", DT_DIR)]),
    (b"/sys/devices/system", &[(b"cpu", DT_DIR)]),
];

/// The entries of a synthetic directory `path`, including `.` and `..`, or
/// `None` if `path` is not a synthetic directory.
pub fn children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    let mut out = vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)];
    // The loop devices' directories, and the CPUs'.
    if let Some(entries) =
        crate::loopdev::sys_children(path).or_else(|| crate::syscpu::children(path))
    {
        out.extend(entries);
        return Some(out);
    }
    let listed = DIRS.iter().find(|(p, _)| *p == path).map(|d| d.1);
    if listed.is_none() && !crate::sysctl::is_dir(path) {
        return None;
    }
    out.extend(listed.unwrap_or_default().iter().map(|(n, t)| (n.to_vec(), *t)));
    // The network namespace's sysctls.
    for (name, dir) in crate::sysctl::children(path) {
        if !out.iter().any(|(n, _)| *n == name) {
            out.push((name, if dir { DT_DIR } else { DT_REG }));
        }
    }
    Some(out)
}

fn is_dir(path: &[u8]) -> bool {
    DIRS.iter().any(|(p, _)| *p == path)
        || crate::sysctl::is_dir(path)
        || matches!(crate::syscpu::lookup(path), Some(Entry::Dir))
}

/// Look up `path` (an absolute, normalized guest path). Returns `None` if the
/// path is not under `/proc` or `/sys` (the caller then uses the host rootfs).
pub fn lookup(path: &[u8], info: &ProcInfo) -> Option<Entry> {
    let under_proc = path == b"/proc" || path.starts_with(b"/proc/");
    let under_sys = path == b"/sys" || path.starts_with(b"/sys/");
    if !under_proc && !under_sys {
        return None;
    }
    Some(match path {
        b"/proc/self/exe" if info.exe_fd.is_some() => {
            Entry::Fd { fd: info.exe_fd.unwrap(), target: info.exe.clone() }
        }
        b"/proc/self/exe" if !info.exe.is_empty() => Entry::Symlink(info.exe.clone()),
        b"/proc/self/cmdline" => Entry::File(info.cmdline.clone()),
        // The process's own memory, as it holds the strings now.
        b"/proc/self/environ" => Entry::File(match crate::prmm::env_moved() {
            // Where `PR_SET_MM` put it.
            Some((start, end)) => {
                let mut b = vec![0u8; end.saturating_sub(start).min(4 << 20) as usize];
                if crate::uaccess::read_into(start, &mut b).is_err() {
                    b.clear();
                }
                b
            }
            None => crate::procpid::environ(&info.auxv, &info.cmdline, |addr, buf| {
                crate::uaccess::read_into(addr, buf).is_ok()
            }),
        }),
        b"/proc/self/statm" => Entry::File(crate::procpid::statm(crate::host::pid())),
        b"/proc/self/io" => Entry::File(crate::procpid::io(crate::host::pid())),
        b"/proc/self/limits" => Entry::File(crate::procpid::limits(
            &(0..fwe_abi::resource::RLIM_NLIMITS)
                .map(|r| crate::syscalls::own_limit(r).unwrap_or((u64::MAX, u64::MAX)))
                .collect::<Vec<_>>(),
        )),
        b"/proc/net" => Entry::Symlink(b"self/net".to_vec()),
        b"/proc/self/auxv" => Entry::File(info.auxv.clone()),
        b"/proc/self/personality" => Entry::File(
            format!(
                "{:08x}\n",
                crate::syscalls::PERSONALITY.load(std::sync::atomic::Ordering::SeqCst)
            )
            .into_bytes(),
        ),
        p if crate::sysctl::read(p).is_some() => Entry::File(crate::sysctl::read(p).unwrap()),
        // The initial user namespace's: every id is itself.
        b"/proc/self/uid_map" | b"/proc/self/gid_map" => {
            Entry::File(b"         0          0 4294967295\n".to_vec())
        }
        b"/proc/self/setgroups" => Entry::File(b"allow\n".to_vec()),
        b"/proc/cpuinfo" => Entry::File(cpuinfo(info.ncpu, &info.auxv)),
        // What `mount` takes, and the rootfs's own.
        b"/proc/filesystems" => Entry::File(
            b"nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tcgroup2\nnodev\tdevpts\n\
              nodev\tmqueue\nnodev\toverlay\n\text4\n"
                .to_vec(),
        ),
        b"/proc/meminfo" => Entry::File(meminfo()),
        // The keys the reader can view, which the open gives
        // ([`crate::keys::proc_keys`]); each user's keys and quotas.
        b"/proc/keys" => Entry::File(Vec::new()),
        b"/proc/key-users" => Entry::File(crate::keys::proc_key_users()),
        b"/proc/stat" => Entry::File(stat(info.ncpu)),
        // The kernel, as `uname` gives it (no compiler built fwe's).
        b"/proc/version" => Entry::File(
            format!("Linux version {RELEASE} (fwe@fwe) (fwe) #1 SMP PREEMPT\n").into_bytes(),
        ),
        b"/proc/uptime" => Entry::File(format!("{:.2} 0.00\n", crate::host::uptime()).into_bytes()),
        b"/proc/loadavg" => {
            let [one, five, fifteen] = crate::host::load_averages();
            Entry::File(format!("{one:.2} {five:.2} {fifteen:.2} 1/1 1\n").into_bytes())
        }
        b"/proc/sys/kernel/ostype" => Entry::File(b"Linux\n".to_vec()),
        b"/proc/sys/kernel/osrelease" => Entry::File(line(RELEASE.as_bytes())),
        b"/proc/sys/kernel/version" => Entry::File(b"#1 SMP PREEMPT\n".to_vec()),
        b"/proc/sys/kernel/hostname" => Entry::File(line(&info.hostname)),
        b"/proc/sys/kernel/cap_last_cap" => {
            Entry::File(format!("{}\n", crate::caps::CAP_LAST_CAP).into_bytes())
        }
        b"/proc/sys/kernel/ngroups_max" => Entry::File(b"65536\n".to_vec()),
        b"/proc/sys/kernel/overflowuid" | b"/proc/sys/kernel/overflowgid" => {
            Entry::File(b"65534\n".to_vec())
        }
        b"/proc/sys/kernel/threads-max" => Entry::File(b"254828\n".to_vec()),
        // Nothing has tainted fwe's kernel.
        b"/proc/sys/kernel/tainted" => Entry::File(b"0\n".to_vec()),
        // Linux's pool is full from boot.
        b"/proc/sys/kernel/random/entropy_avail" => Entry::File(b"256\n".to_vec()),
        b"/proc/sys/kernel/random/poolsize" => Entry::File(b"256\n".to_vec()),
        // A new random UUID each read; one for as long as the host runs.
        b"/proc/sys/kernel/random/uuid" => Entry::File(uuid_line(random_128())),
        b"/proc/sys/kernel/random/boot_id" => Entry::File(uuid_line(boot_id())),
        // The kernel was given no command line.
        b"/proc/cmdline" => Entry::File(b"\n".to_vec()),
        b"/proc/config.gz" => Entry::File(config_gz()),
        b"/proc/sys/fs/file-max" => Entry::File(b"9223372036854775807\n".to_vec()),
        b"/proc/sys/vm/overcommit_memory" => Entry::File(b"0\n".to_vec()),
        b"/proc/sys/vm/mmap_min_addr" => {
            Entry::File(format!("{}\n", crate::mm::MMAP_MIN_ADDR).into_bytes())
        }
        // No newline, as Linux writes it.
        b"/sys/kernel/security/lsm" => Entry::File(b"capability,landlock,yama".to_vec()),
        // The CPUs, their topology and caches.
        p if let Some(e) = crate::syscpu::lookup(p) => e,
        b"/proc/partitions" => Entry::File(crate::loopdev::partitions()),
        p if let Some(e) = crate::loopdev::sys_lookup(p) => e,
        p if is_dir(p) => Entry::Dir,
        _ => Entry::Missing(fwe_abi::errno::ENOENT),
    })
}

/// 128 random bits.
fn random_128() -> u128 {
    let mut b = [0u8; 16];
    // SAFETY: `b` is a valid buffer of its length (at most 256 bytes).
    unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) };
    u128::from_ne_bytes(b)
}

/// The host's boot, as 128 bits: the same for every read until it
/// restarts.
fn boot_id() -> u128 {
    let boot = crate::host::boot_time().to_le_bytes();
    let a = crate::shared::hash(&[&boot[..], b"boot"].concat());
    let b = crate::shared::hash(&[&boot[..], b"id"].concat());
    u128::from(a) << 64 | u128::from(b)
}

/// `bits` as a version 4 UUID's text, with a newline.
fn uuid_line(bits: u128) -> Vec<u8> {
    let mut b = bits.to_be_bytes();
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}\n", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]).into_bytes()
}

fn line(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.push(b'\n');
    v
}

/// The names Linux gives the `AT_HWCAP` bits, then the `AT_HWCAP2` ones,
/// in bit order (`arch/arm64/kernel/cpuinfo.c`).
const HWCAP_NAMES: [&str; 32] = [
    "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp",
    "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4",
    "asimddp", "sha512", "sve", "asimdfhm", "dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb",
    "paca", "pacg",
];
const HWCAP2_NAMES: [&str; 45] = [
    "dcpodp",
    "sve2",
    "sveaes",
    "svepmull",
    "svebitperm",
    "svesha3",
    "svesm4",
    "flagm2",
    "frint",
    "svei8mm",
    "svef32mm",
    "svef64mm",
    "svebf16",
    "i8mm",
    "bf16",
    "dgh",
    "rng",
    "bti",
    "mte",
    "ecv",
    "afp",
    "rpres",
    "mte3",
    "sme",
    "smei16i64",
    "smef64f64",
    "smei8i32",
    "smef16f32",
    "smeb16f32",
    "smef32f32",
    "smefa64",
    "wfxt",
    "ebf16",
    "sveebf16",
    "cssc",
    "rprfm",
    "sve2p1",
    "sme2",
    "sme2p1",
    "smei16i32",
    "smebi32i32",
    "smeb16b16",
    "smef16f16",
    "mops",
    "hbc",
];

/// The value of entry `key` of auxiliary vector `auxv` (words), if it is
/// there.
pub(crate) fn auxv_value(auxv: &[u8], key: u64) -> Option<u64> {
    auxv.as_chunks::<16>().0.iter().find_map(|e| {
        let k = u64::from_ne_bytes(e[..8].try_into().ok()?);
        (k == key).then(|| u64::from_ne_bytes(e[8..].try_into().unwrap_or([0; 8])))
    })
}

/// `/proc/cpuinfo` as Linux writes it on arm64: for each of `ncpu` CPUs,
/// its BogoMIPS, the features of the hwcaps the program was given in
/// `auxv`, and the host's identity of the core.
fn cpuinfo(ncpu: u32, auxv: &[u8]) -> Vec<u8> {
    let hwcap = auxv_value(auxv, fwe_abi::auxv::AT_HWCAP).unwrap_or(0);
    let hwcap2 = auxv_value(auxv, fwe_abi::auxv::AT_HWCAP2).unwrap_or(0);
    let features: Vec<&str> = HWCAP_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| hwcap & (1 << i) != 0)
        .chain(HWCAP2_NAMES.iter().enumerate().filter(|(i, _)| hwcap2 & (1 << i) != 0))
        .map(|(_, n)| *n)
        .collect();
    let id = crate::host::cpu_identity();
    let mut out = Vec::new();
    for i in 0..ncpu.max(1) {
        let part = if i < id.efficiency_cores { id.parts.0 } else { id.parts.1 };
        out.extend_from_slice(
            format!(
                "processor\t: {i}\nBogoMIPS\t: {:.2}\nFeatures\t: {}\nCPU implementer\t: {:#x}\n\
                 CPU architecture: 8\nCPU variant\t: {:#x}\nCPU part\t: {part:#05x}\n\
                 CPU revision\t: {}\n\n",
                id.bogomips,
                features.join(" "),
                id.implementer,
                id.variant,
                id.revision
            )
            .as_bytes(),
        );
    }
    out
}

/// `/proc/meminfo`: the host's memory ([`crate::host::memory`]), in kB.
fn meminfo() -> Vec<u8> {
    let m = crate::host::memory();
    let kb = |b: u64| b / 1024;
    let lines = [
        ("MemTotal", kb(m.total)),
        ("MemFree", kb(m.free)),
        ("MemAvailable", kb(m.available)),
        ("Buffers", 0),
        ("Cached", kb(m.cached)),
        ("SwapCached", 0),
        ("Active", kb(m.active)),
        ("Inactive", kb(m.inactive)),
        ("Unevictable", kb(m.wired)),
        ("Mlocked", 0),
        ("SwapTotal", kb(m.swap_total)),
        ("SwapFree", kb(m.swap_free)),
        ("Dirty", 0),
        ("Writeback", 0),
        ("Shmem", 0),
        ("HugePages_Total", 0),
        ("HugePages_Free", 0),
        ("HugePages_Rsvd", 0),
        ("HugePages_Surp", 0),
    ];
    let mut out = String::new();
    for (name, v) in lines {
        let unit = if name.starts_with("HugePages") { "" } else { " kB" };
        out.push_str(&format!("{:<16}{v:>8}{unit}\n", format!("{name}:")));
    }
    // The huge page pool: empty (`vm.nr_hugepages`).
    out.push_str("Hugepagesize:       2048 kB\nHugetlb:               0 kB\n");
    out.into_bytes()
}

/// `/proc/stat`: the host's CPU times (in `USER_HZ` ticks), each of the
/// first `ncpu` CPUs', and when it booted.
fn stat(ncpu: u32) -> Vec<u8> {
    let mut cpus = crate::host::cpu_times();
    cpus.resize(ncpu.max(1) as usize, [0; 4]);
    let line = |name: &str, t: [u64; 4]| {
        format!("{name} {} {} {} {} 0 0 0 0 0 0\n", t[0], t[1], t[2], t[3])
    };
    let total =
        cpus.iter().fold([0; 4], |a, t| [a[0] + t[0], a[1] + t[1], a[2] + t[2], a[3] + t[3]]);
    let mut out = line("cpu ", total).into_bytes();
    for (i, t) in cpus.iter().enumerate() {
        out.extend_from_slice(line(&format!("cpu{i}"), *t).as_bytes());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    let btime = (now - crate::host::uptime()).max(0.0) as u64;
    out.extend_from_slice(
        format!("intr 0\nctxt 0\nbtime {btime}\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n")
            .as_bytes(),
    );
    out
}

/// The online CPUs.
pub fn ncpu_hint() -> u32 {
    // SAFETY: plain host call.
    (unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }).max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ProcInfo {
        ProcInfo {
            exe: b"/bin/prog".to_vec(),
            cmdline: b"prog\0arg\0".to_vec(),
            ncpu: 4,
            hostname: b"fwe".to_vec(),
            exe_fd: None,
            auxv: vec![6, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0],
        }
    }

    /// The configuration names what fwe has: each cgroup controller it
    /// offers, and the calls whose options programs look for.
    #[test]
    fn config_names_what_fwe_has() {
        let set = |o: &str| CONFIG.contains(&format!("\nCONFIG_{o}=y\n"));
        for c in crate::cgroupfs::CONTROLLERS {
            let option = match *c {
                "cpuset" => "CPUSETS",
                "cpu" => "CGROUP_SCHED",
                "io" => "BLK_CGROUP",
                "memory" => "MEMCG",
                "hugetlb" => "CGROUP_HUGETLB",
                "pids" => "CGROUP_PIDS",
                "rdma" => "CGROUP_RDMA",
                "misc" => "CGROUP_MISC",
                other => panic!("no option for controller {other}"),
            };
            assert!(set(option), "{option}");
        }
        for o in [
            "POSIX_MQUEUE",
            "FHANDLE",
            "MEMBARRIER",
            "CROSS_MEMORY_ATTACH",
            "KCMP",
            "SYSCTL",
            "FILE_LOCKING",
            "CHECKPOINT_RESTORE",
        ] {
            assert!(set(o), "{o}");
        }
        assert!(CONFIG.contains("\n# CONFIG_TIME_NS is not set\n"));
    }

    /// `/proc/config.gz` is a gzip stream of the configuration: framed as
    /// gzip, the configuration in its stored blocks, the right CRC.
    #[test]
    fn config_is_gzipped() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let gz = config_gz();
        assert_eq!(&gz[..3], &[0x1f, 0x8b, 8]);
        let body = &gz[10..gz.len() - 8];
        assert_eq!(body[0], 1);
        let len = u16::from_le_bytes([body[1], body[2]]) as usize;
        assert_eq!(&body[5..5 + len], CONFIG.as_bytes());
        assert!(CONFIG.contains("\n# CONFIG_MODULES is not set\n"));
        let tail = &gz[gz.len() - 8..];
        assert_eq!(u32::from_le_bytes(tail[..4].try_into().unwrap()), crc32(CONFIG.as_bytes()));
        assert_eq!(u32::from_le_bytes(tail[4..].try_into().unwrap()), CONFIG.len() as u32);
        let big = gzip_stored(&vec![7u8; 70_000]);
        assert_eq!(big[10], 0);
        assert_eq!(big.len(), 10 + 5 + 65_535 + 5 + (70_000 - 65_535) + 8);
    }

    #[test]
    fn known_files_and_symlink() {
        let info = info();
        assert!(
            matches!(lookup(b"/proc/self/exe", &info), Some(Entry::Symlink(t)) if t == b"/bin/prog")
        );
        assert!(
            matches!(lookup(b"/proc/self/cmdline", &info), Some(Entry::File(c)) if c == b"prog\0arg\0")
        );
        assert!(
            matches!(lookup(b"/proc/self/auxv", &info), Some(Entry::File(a)) if a == info.auxv)
        );
        assert!(
            matches!(lookup(b"/proc/sys/kernel/ostype", &info), Some(Entry::File(c)) if c == b"Linux\n")
        );
        assert!(
            matches!(lookup(b"/sys/devices/system/cpu/online", &info), Some(Entry::File(c)) if *c == format!("0-{}\n", ncpu_hint() - 1).into_bytes())
        );
    }

    /// `/proc/sys/kernel/random` is a directory; `uuid` differs at each
    /// read, `boot_id` does not.
    #[test]
    fn random_directory() {
        let info = info();
        assert!(matches!(lookup(b"/proc/sys/kernel/random", &info), Some(Entry::Dir)));
        let names: Vec<_> =
            children(b"/proc/sys/kernel/random").unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&b"boot_id".to_vec()) && names.contains(&b"uuid".to_vec()));
        let read = |p: &[u8]| match lookup(p, &info) {
            Some(Entry::File(c)) => c,
            _ => panic!(),
        };
        let u = read(b"/proc/sys/kernel/random/uuid");
        assert_eq!(u.len(), 37);
        assert_eq!(u[14], b'4');
        assert_ne!(u, read(b"/proc/sys/kernel/random/uuid"));
        assert_eq!(
            read(b"/proc/sys/kernel/random/boot_id"),
            read(b"/proc/sys/kernel/random/boot_id")
        );
        let fs: Vec<_> = children(b"/proc/sys/fs").unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(fs.contains(&b"pipe-max-size".to_vec()) && fs.contains(&b"file-max".to_vec()));
    }

    /// `/proc/cpuinfo` names the features of the hwcaps given and nothing
    /// Linux does not write; `/proc/meminfo` reports the host's memory.
    #[test]
    fn cpuinfo_and_meminfo() {
        let mut auxv = Vec::new();
        for (k, v) in [(fwe_abi::auxv::AT_HWCAP, 0b11 | 1 << 8), (fwe_abi::auxv::AT_HWCAP2, 1)] {
            auxv.extend_from_slice(&k.to_ne_bytes());
            auxv.extend_from_slice(&(v as u64).to_ne_bytes());
        }
        let text = String::from_utf8(cpuinfo(2, &auxv)).unwrap();
        assert_eq!(text.matches("processor\t:").count(), 2);
        assert!(text.contains("Features\t: fp asimd atomics dcpodp\n"), "{text}");
        assert!(text.contains("CPU implementer\t: 0x61\n"));
        assert!(!text.contains("BHID"));
        let mem = String::from_utf8(meminfo()).unwrap();
        let total: u64 =
            mem.lines().next().unwrap()[9..].trim().trim_end_matches(" kB").parse().unwrap();
        #[cfg(target_os = "macos")]
        assert_eq!(total, crate::host::sysctl_u64(c"hw.memsize").unwrap() / 1024);
        let _ = total;
        assert!(mem.contains("\nMemAvailable:   "));
    }

    #[test]
    fn unknown_proc_path_is_missing_and_others_fall_through() {
        let info = info();
        assert!(matches!(lookup(b"/proc/does/not/exist", &info), Some(Entry::Missing(_))));
        assert!(lookup(b"/etc/passwd", &info).is_none());
        assert!(lookup(b"/home", &info).is_none());
    }

    /// `hidepid=` and `subset=pid` as Linux's `proc` has them: another's
    /// directory hidden (`invisible`, `ptraceable`) or kept out of
    /// (`noaccess`) for a reader that cannot trace it; with `subset=pid`
    /// only the processes' directories and the reader's own links.
    #[test]
    fn hidepid_and_subset_hide_as_linux() {
        assert_eq!(hidepid(b"invisible"), Some(HIDEPID_INVISIBLE));
        assert_eq!(hidepid(b"3"), None);
        let none = Hiding::of(b"rw");
        assert!(!none.any());
        assert_eq!(none.refuses(b"/42/status", |_| false), None);
        let invisible = Hiding::of(b"hidepid=invisible,gid=10");
        assert_eq!(invisible.gid, Some(10));
        assert_eq!(invisible.refuses(b"/42", |_| false), Some(fwe_abi::errno::ENOENT));
        assert_eq!(invisible.refuses(b"/42/status", |_| true), None);
        assert_eq!(invisible.refuses(b"/meminfo", |_| false), None);
        let noaccess = Hiding::of(b"hidepid=1");
        assert_eq!(noaccess.refuses(b"/42", |_| false), None);
        assert_eq!(noaccess.refuses(b"/42/status", |_| false), Some(fwe_abi::errno::EPERM));
        let pids = Hiding::of(b"subset=pid");
        assert!(pids.any());
        assert_eq!(pids.refuses(b"/meminfo", |_| false), Some(fwe_abi::errno::ENOENT));
        assert_eq!(pids.refuses(b"/sys/kernel", |_| false), Some(fwe_abi::errno::ENOENT));
        assert_eq!(pids.refuses(b"/self/status", |_| false), None);
        assert_eq!(pids.refuses(b"/42/status", |_| false), None);
        assert_eq!(pids.refuses(b"/", |_| false), None);
    }
}
