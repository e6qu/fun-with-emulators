//! Device nodes: `mknod` of a character or block device, which the host
//! lets only its own root make.
//!
//! A device node is an empty file marked with the host file flag
//! `UF_OPAQUE` (which means nothing for a file, and `stat` reports at no
//! cost) and its Linux type and numbers in an extended attribute. `stat`
//! reports it as the device; opening it opens the host device the numbers
//! name (`/dev/null` for 1:3, and the like), or fails with `ENXIO` for one
//! the host has no counterpart of. Every device access, `mknod` included,
//! is first put to the device programs of the process's cgroup
//! ([`crate::cgroupfs::check_device`]).

use crate::bpf::{BPF_DEVCG_DEV_BLOCK, BPF_DEVCG_DEV_CHAR};
use fwe_abi::errno;

/// The extended attribute holding a node's type (`b` or `c`) and numbers.
#[cfg(target_os = "macos")]
const ATTR: &std::ffi::CStr = c"org.fwe.dev";

/// `S_IFCHR` and `S_IFBLK`.
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;

/// Linux's device numbers, from a `dev_t`.
pub fn major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

pub fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// A Linux `dev_t`.
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    (ma & 0xfff) << 8 | (ma & !0xfff) << 32 | (mi & 0xff) | (mi & !0xff) << 12
}

/// A device node fwe made: its type (`S_IFCHR` or `S_IFBLK`) and numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: u32,
    pub major: u32,
    pub minor: u32,
}

impl Node {
    /// The type as a device program sees it.
    pub fn bpf_type(self) -> u32 {
        if self.kind == S_IFBLK { BPF_DEVCG_DEV_BLOCK } else { BPF_DEVCG_DEV_CHAR }
    }
}

/// Whether the host `stat` says the file may be one of fwe's nodes.
pub fn marked(st: &libc::stat) -> bool {
    #[cfg(target_os = "macos")]
    {
        st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_flags & libc::UF_OPAQUE != 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = st;
        false
    }
}

/// The node at `name` in directory `dir`, if it is one of fwe's.
pub fn node_at(dir: i32, name: &std::ffi::CStr) -> Option<Node> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; 12];
        // SAFETY: a NUL-terminated name and a valid buffer.
        let fd = unsafe {
            libc::openat(dir, name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: as above; the descriptor is closed after.
        let n =
            unsafe { libc::fgetxattr(fd, ATTR.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), 0, 0) };
        // SAFETY: closing the descriptor just opened.
        unsafe { libc::close(fd) };
        decode(&buf, n)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (dir, name);
        None
    }
}

/// The node `fd` is open on, if it is one of fwe's.
pub fn node_of(fd: i32) -> Option<Node> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; 12];
        // SAFETY: a valid buffer.
        let n =
            unsafe { libc::fgetxattr(fd, ATTR.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), 0, 0) };
        decode(&buf, n)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        None
    }
}

#[cfg(target_os = "macos")]
fn decode(buf: &[u8; 12], n: isize) -> Option<Node> {
    if n != 12 {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
    Some(Node { kind: w(0), major: w(4), minor: w(8) })
}

/// Make node `node` with permissions `perm` (less the umask) at `name` in
/// directory `dir` (`EEXIST` if something is there). It is made whole
/// under a temporary name and linked into place, so no process opens it
/// half-made.
pub fn make(dir: i32, name: &std::ffi::CStr, node: Node, perm: u32) -> Result<(), i32> {
    make_node(dir, name, node, perm, false)
}

/// [`make`] with exactly the permissions `perm`, whatever the umask: one
/// of fwe's own nodes.
pub fn make_exact(dir: i32, name: &std::ffi::CStr, node: Node, perm: u32) -> Result<(), i32> {
    make_node(dir, name, node, perm, true)
}

fn make_node(
    dir: i32,
    name: &std::ffi::CStr,
    node: Node,
    perm: u32,
    exact: bool,
) -> Result<(), i32> {
    #[cfg(target_os = "macos")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let pid = crate::host::pid();
        let tmp = std::ffi::CString::new(format!(
            ".fwe-node-{pid}-{}",
            N.fetch_add(1, Ordering::Relaxed)
        ))
        .map_err(|_| errno::EINVAL)?;
        // SAFETY: a NUL-terminated name; the file is fwe's to make.
        let fd = unsafe {
            libc::openat(
                dir,
                tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                perm as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&node.kind.to_le_bytes());
        buf[4..8].copy_from_slice(&node.major.to_le_bytes());
        buf[8..12].copy_from_slice(&node.minor.to_le_bytes());
        // SAFETY: valid buffers; plain host calls on the new file, then
        // linking it to its name (which fails if the name is taken).
        let ok = unsafe {
            libc::fsetxattr(fd, ATTR.as_ptr(), buf.as_ptr().cast(), buf.len(), 0, 0) == 0
                && libc::fchflags(fd, libc::UF_OPAQUE) == 0
                && (!exact || libc::fchmod(fd, perm as libc::mode_t) == 0)
                && libc::linkat(dir, tmp.as_ptr(), dir, name.as_ptr(), 0) == 0
        };
        let e = crate::host::errno_to_linux(crate::host::last_errno());
        // SAFETY: closing the descriptor just made, and removing the
        // temporary name (the node keeps its own).
        unsafe {
            libc::close(fd);
            libc::unlinkat(dir, tmp.as_ptr(), 0);
        }
        if !ok {
            return Err(e);
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (dir, name, node, perm, exact);
        Err(errno::EPERM)
    }
}

/// The host device a Linux character device's numbers name, if the host
/// has one.
pub fn host_device(node: Node) -> Option<&'static std::ffi::CStr> {
    if node.kind != S_IFCHR {
        return None;
    }
    Some(match (node.major, node.minor) {
        (1, 3) => c"/dev/null",
        (1, 5) => c"/dev/zero",
        // No /dev/full on the host: it reads as zeros (writes fail with
        // ENOSPC, see `full`).
        (1, 7) => c"/dev/zero",
        (1, 8) => c"/dev/random",
        (1, 9) => c"/dev/urandom",
        (5, 0) => c"/dev/tty",
        _ => return None,
    })
}

/// Whether the node is `/dev/full`, whose writes fail with `ENOSPC`.
pub fn full(node: Node) -> bool {
    node.kind == S_IFCHR && node.major == 1 && node.minor == 7
}

/// The Linux numbers of a host device file (one of the standard nodes a
/// rootfs's `/dev` or a bind mount shows), for the device programs.
#[allow(clippy::unnecessary_cast)] // libc::stat field types differ by host
pub fn linux_numbers_of_host(st: &libc::stat) -> Option<Node> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<(u64, Node)>> = OnceLock::new();
    let kind = st.st_mode as u32 & libc::S_IFMT as u32;
    if kind != libc::S_IFCHR as u32 {
        return None;
    }
    let table = TABLE.get_or_init(|| {
        let mut t = Vec::new();
        for (path, major, minor) in [
            (c"/dev/null", 1, 3),
            (c"/dev/zero", 1, 5),
            (c"/dev/random", 1, 8),
            (c"/dev/urandom", 1, 9),
            (c"/dev/tty", 5, 0),
        ] {
            // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
            let mut s: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a NUL-terminated path and a valid out-parameter.
            if unsafe { libc::stat(path.as_ptr(), &mut s) } == 0 {
                t.push((s.st_rdev as u64, Node { kind: S_IFCHR, major, minor }));
            }
        }
        t
    });
    table.iter().find(|(rdev, _)| *rdev == st.st_rdev as u64).map(|(_, n)| *n)
}

/// `ENXIO`, for a node the host has nothing behind.
pub const NO_DEVICE: i32 = errno::ENXIO;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers_round_trip() {
        for (ma, mi) in [(1, 3), (136, 2), (4095, 255), (4096, 1 << 19)] {
            let d = makedev(ma, mi);
            assert_eq!((major(d), minor(d)), (ma, mi));
        }
        assert_eq!(makedev(1, 3), 0x103);
    }
}
