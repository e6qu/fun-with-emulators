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
}

/// A synthetic entry for a `/proc` or `/sys` path.
pub enum Entry {
    /// A regular file with this content.
    File(Vec<u8>),
    /// A symlink to this target.
    Symlink(Vec<u8>),
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
        ],
    ),
    (b"/proc/self", &[(b"exe", DT_LNK), (b"cmdline", DT_REG)]),
    (b"/proc/sys", &[(b"kernel", DT_DIR), (b"vm", DT_DIR)]),
    (
        b"/proc/sys/kernel",
        &[
            (b"ostype", DT_REG),
            (b"osrelease", DT_REG),
            (b"version", DT_REG),
            (b"hostname", DT_REG),
            (b"pid_max", DT_REG),
        ],
    ),
    (b"/proc/sys/vm", &[(b"overcommit_memory", DT_REG), (b"mmap_min_addr", DT_REG)]),
    (b"/sys", &[(b"devices", DT_DIR)]),
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
        b"/proc/self/exe" if !info.exe.is_empty() => Entry::Symlink(info.exe.clone()),
        b"/proc/self/cmdline" => Entry::File(info.cmdline.clone()),
        b"/proc/cpuinfo" => Entry::File(cpuinfo(info.ncpu)),
        b"/proc/meminfo" => Entry::File(meminfo()),
        b"/proc/stat" => Entry::File(stat(info.ncpu)),
        b"/proc/uptime" => Entry::File(b"0.00 0.00\n".to_vec()),
        b"/proc/loadavg" => Entry::File(b"0.00 0.00 0.00 1/1 1\n".to_vec()),
        b"/proc/sys/kernel/ostype" => Entry::File(b"Linux\n".to_vec()),
        b"/proc/sys/kernel/osrelease" => Entry::File(line(RELEASE.as_bytes())),
        b"/proc/sys/kernel/version" => Entry::File(b"#1 SMP PREEMPT\n".to_vec()),
        b"/proc/sys/kernel/hostname" => Entry::File(line(&info.hostname)),
        b"/proc/sys/kernel/pid_max" => Entry::File(b"4194304\n".to_vec()),
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

fn meminfo() -> Vec<u8> {
    // Plausible fixed values; programs mostly parse MemTotal/MemAvailable.
    b"MemTotal:        8388608 kB\nMemFree:         4194304 kB\n\
      MemAvailable:    6291456 kB\nBuffers:               0 kB\n\
      Cached:          1048576 kB\nSwapTotal:             0 kB\n\
      SwapFree:              0 kB\n"
        .to_vec()
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
