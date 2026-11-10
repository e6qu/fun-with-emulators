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
    /// A path under `/proc` or `/sys` that is not provided (maps to ENOENT).
    Missing,
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
/// options' terms (an option not listed is not set), for the programs and
/// test suites that read `/proc/config.gz` to tell what the kernel has.
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
CONFIG_SHMEM=y
CONFIG_TMPFS=y
CONFIG_BLOCK=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_LOOP_MIN_COUNT=8
CONFIG_MEMFD_CREATE=y
CONFIG_UNIX98_PTYS=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_DEVICE=y
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
    (
        b"/proc/sys/fs",
        &[
            (b"nr_open", DT_REG),
            (b"file-max", DT_REG),
            (b"pipe-max-size", DT_REG),
            (b"lease-break-time", DT_REG),
        ],
    ),
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
        ],
    ),
    (b"/proc/sys/vm", &[(b"overcommit_memory", DT_REG), (b"mmap_min_addr", DT_REG)]),
    (b"/sys", &[(b"devices", DT_DIR), (b"fs", DT_DIR), (b"block", DT_DIR), (b"dev", DT_DIR)]),
    // Where the cgroup hierarchy is mounted.
    (b"/sys/fs", &[(b"cgroup", DT_DIR)]),
    (b"/sys/fs/cgroup", &[]),
    (b"/sys/devices", &[(b"system", DT_DIR), (b"virtual", DT_DIR)]),
    (b"/sys/devices/system", &[(b"cpu", DT_DIR)]),
    (b"/sys/devices/system/cpu", &[(b"online", DT_REG), (b"possible", DT_REG)]),
];

/// The entries of a synthetic directory `path`, including `.` and `..`, or
/// `None` if `path` is not a synthetic directory.
pub fn children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    let mut out = vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)];
    // The loop devices' directories.
    if let Some(entries) = crate::loopdev::sys_children(path) {
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
    DIRS.iter().any(|(p, _)| *p == path) || crate::sysctl::is_dir(path)
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
        b"/proc/cpuinfo" => Entry::File(cpuinfo(info.ncpu)),
        // What `mount` takes, and the rootfs's own.
        b"/proc/filesystems" => Entry::File(
            b"nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tcgroup2\nnodev\tdevpts\n\
              nodev\tmqueue\nnodev\toverlay\n\text4\n"
                .to_vec(),
        ),
        b"/proc/meminfo" => Entry::File(meminfo()),
        // The keys the reader may view, which the open gives
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
        b"/proc/sys/fs/lease-break-time" => Entry::File(b"45\n".to_vec()),
        // Linux's pool is full from boot.
        b"/proc/sys/kernel/random/entropy_avail" => Entry::File(b"256\n".to_vec()),
        b"/proc/sys/kernel/random/poolsize" => Entry::File(b"256\n".to_vec()),
        // The kernel was given no command line.
        b"/proc/cmdline" => Entry::File(b"\n".to_vec()),
        b"/proc/config.gz" => Entry::File(config_gz()),
        b"/proc/sys/fs/file-max" => Entry::File(b"9223372036854775807\n".to_vec()),
        b"/proc/sys/fs/pipe-max-size" => Entry::File(b"1048576\n".to_vec()),
        b"/proc/sys/vm/overcommit_memory" => Entry::File(b"0\n".to_vec()),
        b"/proc/sys/vm/mmap_min_addr" => Entry::File(b"65536\n".to_vec()),
        b"/sys/devices/system/cpu/online" | b"/sys/devices/system/cpu/possible" => {
            Entry::File(cpu_range(info.ncpu))
        }
        b"/proc/partitions" => Entry::File(crate::loopdev::partitions()),
        p if let Some(e) = crate::loopdev::sys_lookup(p) => e,
        p if is_dir(p) => Entry::Dir,
        _ => Entry::Missing,
    })
}

fn line(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.push(b'\n');
    v
}

fn cpuinfo(ncpu: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..ncpu.max(1) {
        out.extend_from_slice(
            format!(
                "processor\t: {i}\nBHID\t: 0x0\nCPU implementer\t: 0x61\n\
                 CPU architecture: 8\nFeatures\t: fp asimd\n\n"
            )
            .as_bytes(),
        );
    }
    out
}

/// The memory reported to the guest, in kB: plausible fixed values (programs
/// mostly read the total and what is available). `sysinfo` reports the same.
pub(crate) const MEM_TOTAL_KB: u64 = 8_388_608;
pub(crate) const MEM_FREE_KB: u64 = 4_194_304;
const MEM_AVAILABLE_KB: u64 = 6_291_456;
const MEM_CACHED_KB: u64 = 1_048_576;

fn meminfo() -> Vec<u8> {
    format!(
        "MemTotal:       {MEM_TOTAL_KB:8} kB\nMemFree:        {MEM_FREE_KB:8} kB\n\
         MemAvailable:   {MEM_AVAILABLE_KB:8} kB\nBuffers:               0 kB\n\
         Cached:         {MEM_CACHED_KB:8} kB\nSwapTotal:             0 kB\n\
         SwapFree:              0 kB\n"
    )
    .into_bytes()
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

fn cpu_range(ncpu: u32) -> Vec<u8> {
    let n = ncpu.max(1);
    if n == 1 { b"0\n".to_vec() } else { format!("0-{}\n", n - 1).into_bytes() }
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
            matches!(lookup(b"/sys/devices/system/cpu/online", &info), Some(Entry::File(c)) if c == b"0-3\n")
        );
    }

    #[test]
    fn unknown_proc_path_is_missing_and_others_fall_through() {
        let info = info();
        assert!(matches!(lookup(b"/proc/does/not/exist", &info), Some(Entry::Missing)));
        assert!(lookup(b"/etc/passwd", &info).is_none());
        assert!(lookup(b"/home", &info).is_none());
    }
}
