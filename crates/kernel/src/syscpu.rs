//! `/sys/devices/system/cpu`: the CPUs, their topology and their caches,
//! as Linux lays them out on a machine its device tree describes (Apple's
//! are such), from the host's kinds of core ([`crate::host::core_kinds`]).
//!
//! The CPUs are numbered as `/proc/cpuinfo` numbers them, the efficiency
//! cores first. A cluster is the cores that share an L2 (`cluster_id`
//! its index, `core_id` the core's in it), all in one package. Each CPU
//! has its L1 data and instruction caches and its cluster's L2
//! (`cache/index0` to `index2`); what the host does not tell (the
//! associativity, the frequencies) is left out, as Linux leaves out what
//! its firmware does not describe. `cpu_capacity` is 1024 for each, as on
//! a machine whose firmware gives no relative capacities.

use crate::host::CoreKind;
use crate::procfs::{DT_DIR, DT_REG, Entry};
use std::sync::OnceLock;

/// The directory itself.
const DIR: &[u8] = b"/sys/devices/system/cpu";
/// The highest CPU number the kernel could have (`NR_CPUS` - 1), as an
/// arm64 distribution's kernel is built.
const KERNEL_MAX: u32 = 511;

/// One CPU: its kind and its cluster (the CPUs `first..=last`, number
/// `cluster`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cpu {
    kind: usize,
    cluster: u32,
    first: u32,
    last: u32,
}

/// The host's CPUs as the tree shows them.
struct Layout {
    kinds: Vec<CoreKind>,
    line: u64,
    cpus: Vec<Cpu>,
}

impl Layout {
    fn of(kinds: Vec<CoreKind>, line: u64) -> Layout {
        let mut cpus = Vec::new();
        let mut cluster = 0;
        for (kind, k) in kinds.iter().enumerate() {
            let per = if k.per_l2 == 0 { k.cpus } else { k.per_l2.min(k.cpus) }.max(1);
            let start = cpus.len() as u32;
            for i in 0..k.cpus {
                let first = start + i / per * per;
                let last = (first + per).min(start + k.cpus) - 1;
                cpus.push(Cpu { kind, cluster: cluster + i / per, first, last });
            }
            cluster += k.cpus.div_ceil(per);
        }
        Layout { kinds, line, cpus }
    }

    fn n(&self) -> u32 {
        self.cpus.len() as u32
    }
}

fn layout() -> &'static Layout {
    static LAYOUT: OnceLock<Layout> = OnceLock::new();
    LAYOUT.get_or_init(|| {
        let (kinds, line) = crate::host::core_kinds(crate::procfs::ncpu_hint());
        Layout::of(kinds, line)
    })
}

/// CPUs `first..=last` of `n` as Linux prints a mask (`%*pb`): hex digits
/// as many as `n` takes, in groups of eight from the right, comma-separated.
fn mask(first: u32, last: u32, n: u32) -> Vec<u8> {
    let digits = n.div_ceil(4).max(1);
    let mut out = Vec::new();
    for d in (0..digits).rev() {
        let nibble =
            (0..4).filter(|b| (first..=last).contains(&(d * 4 + b))).fold(0, |v, b| v | 1 << b);
        out.push(b"0123456789abcdef"[nibble as usize]);
        if d % 8 == 0 && d != 0 {
            out.push(b',');
        }
    }
    out.push(b'\n');
    out
}

/// CPUs `first..=last` as Linux prints a list (`%*pbl`).
fn list(first: u32, last: u32) -> Vec<u8> {
    if first == last { format!("{first}\n") } else { format!("{first}-{last}\n") }.into_bytes()
}

/// A cache's size as Linux prints it.
fn size(bytes: u64) -> Vec<u8> {
    format!("{}K\n", bytes / 1024).into_bytes()
}

/// CPU `cpu`'s caches: (level, type, size, shared by `first..=last`).
fn caches(l: &Layout, cpu: u32) -> Vec<(u32, &'static str, u64, u32, u32)> {
    let c = l.cpus[cpu as usize];
    let k = &l.kinds[c.kind];
    [
        (1, "Data", k.l1d, cpu, cpu),
        (1, "Instruction", k.l1i, cpu, cpu),
        (2, "Unified", k.l2, c.first, c.last),
    ]
    .into_iter()
    .filter(|&(_, _, bytes, _, _)| bytes > 0)
    .collect()
}

/// `cpu<n>`'s number and the rest of the path, if `rest` starts with one.
fn cpu_of<'a>(l: &Layout, rest: &'a [u8]) -> Option<(u32, &'a [u8])> {
    let rest = rest.strip_prefix(b"/cpu")?;
    let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
    let (num, sub) = rest.split_at(end);
    if num.is_empty() || !num.iter().all(u8::is_ascii_digit) || (num.len() > 1 && num[0] == b'0') {
        return None;
    }
    let n: u32 = std::str::from_utf8(num).ok()?.parse().ok()?;
    (n < l.n()).then_some((n, sub))
}

const TOPOLOGY: &[&[u8]] = &[
    b"cluster_cpus",
    b"cluster_cpus_list",
    b"cluster_id",
    b"core_cpus",
    b"core_cpus_list",
    b"core_id",
    b"core_siblings",
    b"core_siblings_list",
    b"package_cpus",
    b"package_cpus_list",
    b"physical_package_id",
    b"thread_siblings",
    b"thread_siblings_list",
];

const CACHE: &[&[u8]] =
    &[b"coherency_line_size", b"level", b"shared_cpu_list", b"shared_cpu_map", b"size", b"type"];

/// What the tree holds at `path`, if `path` is in it.
pub fn lookup(path: &[u8]) -> Option<Entry> {
    let rest = path.strip_prefix(DIR)?;
    if !rest.is_empty() && !rest.starts_with(b"/") {
        return None;
    }
    let l = layout();
    let n = l.n();
    let file = |b: Vec<u8>| Some(Entry::File(b));
    match rest {
        b"" => return Some(Entry::Dir),
        b"/online" | b"/possible" | b"/present" => return file(list(0, n - 1)),
        b"/offline" | b"/isolated" => return file(b"\n".to_vec()),
        b"/kernel_max" => return file(format!("{KERNEL_MAX}\n").into_bytes()),
        _ => {}
    }
    let Some((cpu, sub)) = cpu_of(l, rest) else {
        return Some(Entry::Missing(fwe_abi::errno::ENOENT));
    };
    let c = l.cpus[cpu as usize];
    let entry = match sub {
        b"" | b"/topology" | b"/cache" => Entry::Dir,
        b"/online" => Entry::File(b"1\n".to_vec()),
        b"/cpu_capacity" => Entry::File(b"1024\n".to_vec()),
        b"/topology/cluster_cpus" | b"/topology/core_siblings" => {
            Entry::File(mask(c.first, c.last, n))
        }
        b"/topology/cluster_cpus_list" | b"/topology/core_siblings_list" => {
            Entry::File(list(c.first, c.last))
        }
        b"/topology/package_cpus" => Entry::File(mask(0, n - 1, n)),
        b"/topology/package_cpus_list" => Entry::File(list(0, n - 1)),
        b"/topology/core_cpus" | b"/topology/thread_siblings" => Entry::File(mask(cpu, cpu, n)),
        b"/topology/core_cpus_list" | b"/topology/thread_siblings_list" => {
            Entry::File(list(cpu, cpu))
        }
        b"/topology/cluster_id" => Entry::File(format!("{}\n", c.cluster).into_bytes()),
        b"/topology/core_id" => Entry::File(format!("{}\n", cpu - c.first).into_bytes()),
        b"/topology/physical_package_id" => Entry::File(b"0\n".to_vec()),
        _ => match cache_entry(l, cpu, sub) {
            Some(e) => e,
            None => Entry::Missing(fwe_abi::errno::ENOENT),
        },
    };
    Some(entry)
}

/// `cache/index<i>` of CPU `cpu`, or a file in it (`sub`).
fn cache_entry(l: &Layout, cpu: u32, sub: &[u8]) -> Option<Entry> {
    let rest = sub.strip_prefix(b"/cache/index")?;
    let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
    let (num, file) = rest.split_at(end);
    let i: usize = std::str::from_utf8(num).ok().filter(|n| n.len() == 1)?.parse().ok()?;
    let &(level, kind, bytes, first, last) = caches(l, cpu).get(i)?;
    let n = l.n();
    Some(match file {
        b"" => Entry::Dir,
        b"/coherency_line_size" => Entry::File(format!("{}\n", l.line).into_bytes()),
        b"/level" => Entry::File(format!("{level}\n").into_bytes()),
        b"/shared_cpu_list" => Entry::File(list(first, last)),
        b"/shared_cpu_map" => Entry::File(mask(first, last, n)),
        b"/size" => Entry::File(size(bytes)),
        b"/type" => Entry::File(format!("{kind}\n").into_bytes()),
        _ => return None,
    })
}

/// The entries of the tree's directory `path` (`.` and `..` aside), if
/// `path` is one of them.
pub fn children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    let rest = path.strip_prefix(DIR)?;
    let l = layout();
    let files = |names: &[&[u8]]| names.iter().map(|n| (n.to_vec(), DT_REG)).collect::<Vec<_>>();
    if rest.is_empty() {
        let mut out =
            files(&[b"isolated", b"kernel_max", b"offline", b"online", b"possible", b"present"]);
        out.extend((0..l.n()).map(|i| (format!("cpu{i}").into_bytes(), DT_DIR)));
        return Some(out);
    }
    let (cpu, sub) = cpu_of(l, rest)?;
    match sub {
        b"" => {
            let mut out = files(&[b"cpu_capacity", b"online"]);
            out.extend([(b"cache".to_vec(), DT_DIR), (b"topology".to_vec(), DT_DIR)]);
            Some(out)
        }
        b"/topology" => Some(files(TOPOLOGY)),
        b"/cache" => {
            let n = caches(l, cpu).len();
            Some((0..n).map(|i| (format!("index{i}").into_bytes(), DT_DIR)).collect())
        }
        _ => matches!(cache_entry(l, cpu, sub), Some(Entry::Dir)).then(|| files(CACHE)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Mac with 4 efficiency cores sharing an L2 and 8 performance
    /// cores in two clusters of 4.
    fn mac() -> Layout {
        let e = CoreKind { cpus: 4, l1i: 128 << 10, l1d: 64 << 10, l2: 4 << 20, per_l2: 4 };
        let p = CoreKind { cpus: 8, l1i: 192 << 10, l1d: 128 << 10, l2: 16 << 20, per_l2: 4 };
        Layout::of(vec![e, p], 128)
    }

    #[test]
    fn clusters_are_the_cores_sharing_an_l2() {
        let l = mac();
        assert_eq!(l.n(), 12);
        assert_eq!(l.cpus[0], Cpu { kind: 0, cluster: 0, first: 0, last: 3 });
        assert_eq!(l.cpus[5], Cpu { kind: 1, cluster: 1, first: 4, last: 7 });
        assert_eq!(l.cpus[11], Cpu { kind: 1, cluster: 2, first: 8, last: 11 });
        let c = caches(&l, 9);
        assert_eq!(c[0], (1, "Data", 128 << 10, 9, 9));
        assert_eq!(c[2], (2, "Unified", 16 << 20, 8, 11));
    }

    /// As Linux prints them (an arm64 machine of 4 CPUs: `f`, `0-3`).
    #[test]
    fn masks_and_lists_print_as_linux_does() {
        assert_eq!(mask(0, 3, 4), b"f\n");
        assert_eq!(mask(1, 1, 4), b"2\n");
        assert_eq!(mask(0, 0, 12), b"001\n");
        assert_eq!(mask(8, 11, 12), b"f00\n");
        assert_eq!(mask(32, 32, 40), b"01,00000000\n");
        assert_eq!(list(0, 3), b"0-3\n");
        assert_eq!(list(5, 5), b"5\n");
        assert_eq!(size(16 << 20), b"16384K\n");
    }
}
