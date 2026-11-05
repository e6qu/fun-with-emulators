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

/// The synthetic directory tree: each directory and the entries it lists.
const DIRS: &[DirDef] = &[
    (
        b"/proc",
        &[
            (b"self", DT_DIR),
            (b"cpuinfo", DT_REG),
            (b"meminfo", DT_REG),
            (b"stat", DT_REG),
            (b"uptime", DT_REG),
            (b"loadavg", DT_REG),
            (b"sys", DT_DIR),
            (b"mounts", DT_LNK),
        ],
    ),
    (
        b"/proc/self",
        &[
            (b"exe", DT_LNK),
            (b"cmdline", DT_REG),
            (b"fd", DT_DIR),
            (b"ns", DT_DIR),
            (b"mountinfo", DT_REG),
            (b"mounts", DT_REG),
            (b"uid_map", DT_REG),
            (b"gid_map", DT_REG),
            (b"setgroups", DT_REG),
            (b"cgroup", DT_REG),
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
    (b"/proc/sys/fs", &[(b"nr_open", DT_REG), (b"file-max", DT_REG), (b"pipe-max-size", DT_REG)]),
    (
        b"/proc/sys/kernel",
        &[
            (b"ostype", DT_REG),
            (b"osrelease", DT_REG),
            (b"version", DT_REG),
            (b"hostname", DT_REG),
            (b"pid_max", DT_REG),
            (b"cap_last_cap", DT_REG),
            (b"ngroups_max", DT_REG),
            (b"overflowuid", DT_REG),
            (b"overflowgid", DT_REG),
            (b"threads-max", DT_REG),
            (b"domainname", DT_REG),
        ],
    ),
    (b"/proc/sys/vm", &[(b"overcommit_memory", DT_REG), (b"mmap_min_addr", DT_REG)]),
    (b"/sys", &[(b"devices", DT_DIR), (b"fs", DT_DIR)]),
    // Where the cgroup hierarchy is mounted.
    (b"/sys/fs", &[(b"cgroup", DT_DIR)]),
    (b"/sys/fs/cgroup", &[]),
    (b"/sys/devices", &[(b"system", DT_DIR)]),
    (b"/sys/devices/system", &[(b"cpu", DT_DIR)]),
    (b"/sys/devices/system/cpu", &[(b"online", DT_REG), (b"possible", DT_REG)]),
];

/// The entries of a synthetic directory `path`, including `.` and `..`, or
/// `None` if `path` is not a synthetic directory.
pub fn children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    let entries = DIRS.iter().find(|(p, _)| *p == path)?.1;
    let mut out = vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)];
    out.extend(entries.iter().map(|(n, t)| (n.to_vec(), *t)));
    Some(out)
}

fn is_dir(path: &[u8]) -> bool {
    DIRS.iter().any(|(p, _)| *p == path)
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
        // The initial user namespace's: every id is itself.
        b"/proc/self/uid_map" | b"/proc/self/gid_map" => {
            Entry::File(b"         0          0 4294967295\n".to_vec())
        }
        b"/proc/self/setgroups" => Entry::File(b"allow\n".to_vec()),
        b"/proc/cpuinfo" => Entry::File(cpuinfo(info.ncpu)),
        b"/proc/meminfo" => Entry::File(meminfo()),
        b"/proc/stat" => Entry::File(stat(info.ncpu)),
        b"/proc/uptime" => Entry::File(format!("{:.2} 0.00\n", crate::host::uptime()).into_bytes()),
        b"/proc/loadavg" => {
            let [one, five, fifteen] = crate::host::load_averages();
            Entry::File(format!("{one:.2} {five:.2} {fifteen:.2} 1/1 1\n").into_bytes())
        }
        b"/proc/sys/kernel/ostype" => Entry::File(b"Linux\n".to_vec()),
        b"/proc/sys/kernel/osrelease" => Entry::File(line(RELEASE.as_bytes())),
        b"/proc/sys/kernel/version" => Entry::File(b"#1 SMP PREEMPT\n".to_vec()),
        b"/proc/sys/kernel/hostname" => Entry::File(line(&info.hostname)),
        b"/proc/sys/kernel/pid_max" => Entry::File(b"4194304\n".to_vec()),
        b"/proc/sys/kernel/cap_last_cap" => {
            Entry::File(format!("{}\n", crate::caps::CAP_LAST_CAP).into_bytes())
        }
        b"/proc/sys/kernel/ngroups_max" => Entry::File(b"65536\n".to_vec()),
        b"/proc/sys/kernel/overflowuid" | b"/proc/sys/kernel/overflowgid" => {
            Entry::File(b"65534\n".to_vec())
        }
        b"/proc/sys/kernel/threads-max" => Entry::File(b"254828\n".to_vec()),
        b"/proc/sys/fs/nr_open" => Entry::File(b"1048576\n".to_vec()),
        b"/proc/sys/fs/file-max" => Entry::File(b"9223372036854775807\n".to_vec()),
        b"/proc/sys/fs/pipe-max-size" => Entry::File(b"1048576\n".to_vec()),
        b"/proc/sys/vm/overcommit_memory" => Entry::File(b"0\n".to_vec()),
        b"/proc/sys/vm/mmap_min_addr" => Entry::File(b"65536\n".to_vec()),
        b"/sys/devices/system/cpu/online" | b"/sys/devices/system/cpu/possible" => {
            Entry::File(cpu_range(info.ncpu))
        }
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

fn stat(ncpu: u32) -> Vec<u8> {
    let mut out = b"cpu  0 0 0 0 0 0 0 0 0 0\n".to_vec();
    for i in 0..ncpu.max(1) {
        out.extend_from_slice(format!("cpu{i} 0 0 0 0 0 0 0 0 0 0\n").as_bytes());
    }
    out.extend_from_slice(b"btime 1700000000\nprocesses 1\n");
    out
}

fn cpu_range(ncpu: u32) -> Vec<u8> {
    let n = ncpu.max(1);
    if n == 1 { b"0\n".to_vec() } else { format!("0-{}\n", n - 1).into_bytes() }
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
        }
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
