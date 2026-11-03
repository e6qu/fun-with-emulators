//! Pseudo-terminal allocation.
//!
//! Linux allocates a pty by opening `/dev/ptmx` (yielding a master), reading
//! the slave number with the `TIOCGPTN` ioctl, unlocking it with `TIOCSPTLCK`,
//! and opening `/dev/pts/<n>`. macOS has neither `/dev/ptmx` nor those ioctls;
//! it uses `posix_openpt`/`grantpt`/`unlockpt`/`ptsname`. Those four are also
//! available on Linux, so this module uses them uniformly and presents the
//! Linux interface to the guest:
//!
//! - opening `/dev/ptmx` calls [`open_master`], which allocates the pty and
//!   remembers a guest-facing slave number;
//! - `TIOCGPTN` returns that number, `TIOCSPTLCK` is accepted (the slave is
//!   already unlocked);
//! - opening `/dev/pts/<n>` calls [`open_slave`], mapping the number to the
//!   host slave device (`/dev/pts/<n>` on Linux, `/dev/ttys<nnn>` on macOS).

use crate::host::last_error;
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Mutex;

struct Ptys {
    /// Master fd → (guest slave number, host slave path).
    masters: HashMap<i32, (u32, Vec<u8>)>,
    /// Guest slave number → host slave path.
    slaves: HashMap<u32, Vec<u8>>,
    next: u32,
}

static PTYS: Mutex<Option<Ptys>> = Mutex::new(None);

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = PTYS.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

fn with<R>(f: impl FnOnce(&mut Ptys) -> R) -> R {
    let mut g = PTYS.lock().unwrap_or_else(|e| e.into_inner());
    let p =
        g.get_or_insert_with(|| Ptys { masters: HashMap::new(), slaves: HashMap::new(), next: 0 });
    f(p)
}

/// Write the registry into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    with(|p| {
        crate::snapshot::fd_map(e, &p.masters, |e, (n, path)| {
            e.u32(*n);
            e.bytes(path);
        });
        let mut slaves: Vec<_> = p.slaves.iter().collect();
        slaves.sort();
        e.u64(slaves.len() as u64);
        for (n, path) in slaves {
            e.u32(*n);
            e.bytes(path);
        }
        e.u32(p.next);
    })
}

/// Rebuild the registry in a fork child.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let masters = crate::snapshot::read_fd_map(d, |d| (d.u32(), d.bytes()));
    let n = d.count(12);
    let slaves = (0..n).map(|_| (d.u32(), d.bytes())).collect();
    let next = d.u32();
    with(|p| *p = Ptys { masters, slaves, next });
}

fn apply_open_flags(fd: i32, linux_flags: u64) {
    use fwe_abi::fcntl;
    // SAFETY: plain host calls on a fresh descriptor.
    unsafe {
        if linux_flags & fcntl::O_CLOEXEC != 0 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        if linux_flags & fcntl::O_NONBLOCK != 0 {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

/// Open `/dev/ptmx`: allocate a pty master. `linux_flags` are the guest's open
/// flags (only `O_CLOEXEC`/`O_NONBLOCK` are meaningful for the master).
pub fn open_master(linux_flags: u64) -> i64 {
    // SAFETY: plain host calls to allocate and unlock a pty.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if m < 0 {
            return last_error();
        }
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            let e = last_error();
            libc::close(m);
            return e;
        }
        let name = libc::ptsname(m);
        if name.is_null() {
            libc::close(m);
            return err(errno::EIO);
        }
        let path = CStr::from_ptr(name).to_bytes().to_vec();
        apply_open_flags(m, linux_flags);
        with(|p| {
            let n = p.next;
            p.next += 1;
            p.masters.insert(m, (n, path.clone()));
            p.slaves.insert(n, path);
        });
        m as i64
    }
}

/// Open `/dev/pts/<n>`: the slave for a previously allocated master.
/// `host_flags` are already translated to host open flags.
pub fn open_slave(n: u32, host_flags: i32) -> i64 {
    let path = match with(|p| p.slaves.get(&n).cloned()) {
        Some(p) => p,
        None => return err(errno::ENOENT),
    };
    let mut c = path;
    c.push(0);
    // SAFETY: `c` is a NUL-terminated host path.
    let fd = unsafe { libc::open(c.as_ptr() as *const libc::c_char, host_flags) };
    if fd < 0 { last_error() } else { fd as i64 }
}

/// The guest slave number for a master fd (`TIOCGPTN`), if it is one of ours.
pub fn ptsnum(master_fd: i32) -> Option<u32> {
    with(|p| p.masters.get(&master_fd).map(|(n, _)| *n))
}

/// Release a master fd if it is one of ours (`close`). Returns `Some(0)` then,
/// `None` for any other descriptor.
pub fn try_close(fd: i32) -> Option<i64> {
    let entry = with(|p| p.masters.remove(&fd));
    let (n, _) = entry?;
    with(|p| p.slaves.remove(&n));
    // SAFETY: `fd` is a master we allocated.
    unsafe { libc::close(fd) };
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_slave_loopback() {
        let m = open_master(0);
        if m < 0 {
            eprintln!("skipping: pty unavailable ({m})");
            return;
        }
        let n = ptsnum(m as i32).expect("master should have a slave number");
        let s = open_slave(n, libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open_slave: {s}");

        // Data written to the master appears on the slave. A trailing newline
        // flushes the default canonical line discipline.
        // SAFETY: valid fds and buffers.
        unsafe {
            assert_eq!(libc::write(m as i32, b"hi\n".as_ptr() as *const _, 3), 3);
            let mut buf = [0u8; 8];
            let got = libc::read(s as i32, buf.as_mut_ptr() as *mut _, 8);
            assert_eq!(got, 3, "slave read: {got}");
            assert_eq!(&buf[..3], b"hi\n");
            libc::close(s as i32);
        }
        assert_eq!(try_close(m as i32), Some(0));
        // A second close is no longer ours.
        assert_eq!(try_close(m as i32), None);
    }

    #[test]
    fn unknown_slave_is_enoent() {
        assert_eq!(open_slave(999_999, libc::O_RDWR), err(errno::ENOENT));
    }
}
