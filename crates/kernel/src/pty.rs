//! Pseudo-terminal allocation.
//!
//! Linux allocates a pty by opening `/dev/ptmx` (yielding a master), reading
//! the slave number with the `TIOCGPTN` ioctl, unlocking it with `TIOCSPTLCK`,
//! and opening `/dev/pts/<n>`. macOS's `/dev/ptmx` takes none of those
//! ioctls; it uses `posix_openpt`/`grantpt`/`unlockpt`/`ptsname`. Those four are also
//! available on Linux, so this module uses them uniformly and presents the
//! Linux interface to the guest:
//!
//! - opening `/dev/ptmx` calls [`open_master`], which allocates the pty and
//!   remembers a guest-facing slave number;
//! - `TIOCGPTN` returns that number, `TIOCSPTLCK` is accepted (the slave is
//!   already unlocked);
//! - opening `/dev/pts/<n>` calls [`open_slave`], mapping the number to the
//!   host slave device (`/dev/pts/<n>` on Linux, `/dev/ttys<nnn>` on macOS).
//!
//! What the slave writes outlives it, as on Linux. When the last holder of
//! a slave closes it, Linux keeps what the master has not read yet: the
//! master reads it, then `EIO` (a hang-up), and `poll` reports `POLLHUP`.
//! macOS throws it away and reads 0. So the process that opens a master
//! holds the slave too, out of the guest's reach ([`Master::keep`]), and
//! the host never hangs it up: fwe tells the hang-up itself. (A Linux
//! host keeps the output and tells the hang-up as the guest expects: there
//! fwe holds nothing.) A slave a
//! guest has opened ([`opened`], kept where every fwe process sees it)
//! that no guest process holds any more is hung up ([`hung_up`]). A master's
//! `read` with nothing to read looks between short slices of its wait
//! ([`before_read`]), and so do `poll`, `select` and `epoll` waits that
//! watch one.

use crate::host::last_error;
use fwe_abi::{err, errno};
use std::collections::HashMap;
use std::ffi::CStr;

/// A master this process opened.
#[derive(Clone)]
struct Master {
    /// The guest's number for its slave.
    n: u32,
    /// The host slave's path.
    path: Vec<u8>,
    /// The slave, held open by fwe (in the reserved range: no guest
    /// process's descriptor), so what it wrote is kept until read.
    keep: i32,
    /// The master's and the slave's host device numbers.
    rdev: u64,
    slave: u64,
}

struct Ptys {
    /// Master fd → its master.
    masters: HashMap<i32, Master>,
    /// Guest slave number → host slave path.
    slaves: HashMap<u32, Vec<u8>>,
    next: u32,
}

impl crate::kept::Table for Ptys {
    fn is_empty(&self) -> bool {
        self.masters.is_empty() && self.slaves.is_empty()
    }
}

static PTYS: crate::kept::Kept<Option<Ptys>> = crate::kept::Kept::new(None);

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = PTYS.lock();
    f()
}

fn with<R>(f: impl FnOnce(&mut Ptys) -> R) -> R {
    let mut g = PTYS.lock();
    let p =
        g.get_or_insert_with(|| Ptys { masters: HashMap::new(), slaves: HashMap::new(), next: 0 });
    f(p)
}

/// Write the registry into a fork snapshot or an exec state (`exec`:
/// fwe's holds of the slaves survive the host `execve` that re-executes
/// fwe).
pub(crate) fn save(e: &mut crate::snapshot::Enc, exec: bool) {
    with(|p| {
        if exec {
            for m in p.masters.values().filter(|m| m.keep >= 0) {
                // SAFETY: plain host call on fwe's own descriptor.
                unsafe { libc::fcntl(m.keep, libc::F_SETFD, 0) };
            }
        }
        crate::snapshot::fd_map(e, &p.masters, |e, m| {
            e.u32(m.n);
            e.bytes(&m.path);
            e.u32(m.keep as u32);
            e.u64(m.rdev);
            e.u64(m.slave);
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

/// Rebuild the registry in a fork child, or in the program an exec
/// started.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    let masters = crate::snapshot::read_fd_map(d, |d| Master {
        n: d.u32(),
        path: d.bytes(),
        keep: d.u32() as i32,
        rdev: d.u64(),
        slave: d.u64(),
    });
    let n = d.count(12);
    let slaves = (0..n).map(|_| (d.u32(), d.bytes())).collect();
    let next = d.u32();
    for m in masters.values().filter(|m| m.keep >= 0) {
        // SAFETY: plain host call on fwe's own descriptor.
        unsafe { libc::fcntl(m.keep, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
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
        let keep = match hold_slave(&path) {
            Ok(k) => k,
            Err(e) => {
                libc::close(m);
                return err(e);
            }
        };
        let (rdev, slave) = (rdev_of(m), rdev_of(keep));
        // A new pty on that device: no guest has opened its slave yet.
        if let Some(r) = opened()
            && r.get().0.contains(&slave)
        {
            let _ = r.update(|o| {
                o.0.remove(&slave);
                Ok(())
            });
        }
        apply_open_flags(m, linux_flags);
        with(|p| {
            let n = p.next;
            p.next += 1;
            p.masters.insert(m, Master { n, path: path.clone(), keep, rdev, slave });
            p.slaves.insert(n, path);
        });
        m as i64
    }
}

/// The slave at `path`, opened for fwe to hold ([`Master::keep`]): read
/// only, without waiting, in the reserved range. None on a Linux host (-1).
fn hold_slave(path: &[u8]) -> Result<i32, i32> {
    if !cfg!(target_os = "macos") {
        return Ok(-1);
    }
    let c = std::ffi::CString::new(path).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated host path.
    let fd = unsafe {
        libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    crate::fdtable::reserve(fd)
}

/// The host device number `fd` is open on (0 if `fstat` fails).
fn rdev_of(fd: i32) -> u64 {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } == 0 { st.st_rdev as u64 } else { 0 }
}

/// The host slave devices a guest has opened since their master was made,
/// as every fwe process sees them: Linux hangs up only a slave that was
/// opened once.
#[derive(Clone, Default)]
pub struct Opened(std::collections::BTreeSet<u64>);

impl crate::shared::Data for Opened {
    fn encode(&self, e: &mut crate::snapshot::Enc) {
        e.u64(self.0.len() as u64);
        for &d in &self.0 {
            e.u64(d);
        }
    }

    fn decode(d: &mut crate::snapshot::Dec) -> Self {
        let n = d.count(8);
        Opened((0..n).map(|_| d.u64()).collect())
    }
}

/// [`Opened`]'s record.
fn opened() -> Option<&'static crate::shared::Record<Opened>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<Opened>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| crate::shared::Record::named("ptys-opened", 0, Opened::default).ok()).as_ref()
}

/// The master `fd` is open on, if it is one this process opened (or
/// inherited) and whose hang-up fwe tells (none on a Linux host): by its
/// number, or by its device (a duplicate, which the slave fwe holds would
/// otherwise leave waiting for ever).
fn master(fd: i32) -> Option<Master> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let g = PTYS.if_used()?;
    let p = g.as_ref()?;
    if p.masters.is_empty() {
        return None;
    }
    if let Some(m) = p.masters.get(&fd) {
        return Some(m.clone());
    }
    let rdev = rdev_of(fd);
    p.masters.values().find(|m| rdev != 0 && m.rdev == rdev).cloned()
}

/// Whether `fd` is a master whose hang-up fwe tells ([`hung_up`]).
pub fn is_master(fd: i32) -> bool {
    master(fd).is_some()
}

/// Whether a guest process holds the slave at `path`: a descriptor of any
/// fwe process open on it, fwe's own ([`Master::keep`]) aside.
fn held(path: &[u8]) -> bool {
    crate::procstore::pids().into_iter().any(|pid| {
        crate::procpid::fds(pid)
            .iter()
            .any(|(_, t)| matches!(t, crate::procpid::FdTarget::Path(p) if p == path))
    })
}

/// Whether master `fd` is hung up: a guest opened its slave once, and no
/// guest process holds it now (what the slave wrote may still be waiting).
pub fn hung_up(fd: i32) -> bool {
    master(fd).is_some_and(|m| gone(&m))
}

fn gone(m: &Master) -> bool {
    opened().is_some_and(|r| r.get().0.contains(&m.slave)) && !held(&m.path)
}

/// Whether master `fd` has something to read.
fn readable(fd: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: one valid entry, no wait.
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & libc::POLLIN != 0 }
}

/// Before the host reads master `fd`: `EIO` once it is hung up with
/// nothing left to read, as Linux's; a read that would wait waits here, in
/// slices it looks between, until there is something to read or the
/// slave hangs up (a signal ends the wait, `EINTR`, as it would the host's
/// read). `None` for any other descriptor, and once the host's read can
/// go on.
pub fn before_read(fd: i32) -> Option<i64> {
    let m = master(fd)?;
    loop {
        if readable(fd) {
            return None;
        }
        if gone(&m) {
            return Some(err(errno::EIO));
        }
        // SAFETY: plain host call.
        if unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0 {
            return None;
        }
        let mut set = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }];
        let slice = i64::from(crate::fifo::SLICE_MS) * 1_000_000;
        if let Err(e) = crate::thread::wait_ready_ns(&mut set, slice) {
            return Some(err(e));
        }
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
    if fd < 0 {
        return last_error();
    }
    // Opened by a guest: from now on, its last holder's going hangs it up.
    let dev = rdev_of(fd);
    if let Some(r) = opened()
        && !r.get().0.contains(&dev)
    {
        let _ = r.update(|o| {
            o.0.insert(dev);
            Ok(())
        });
    }
    fd as i64
}

/// The guest slave number for a master fd (`TIOCGPTN`), if it is one of ours.
pub fn ptsnum(master_fd: i32) -> Option<u32> {
    with(|p| p.masters.get(&master_fd).map(|m| m.n))
}

/// Release a master fd if it is one of ours (`close`). Returns `Some(0)` then,
/// `None` for any other descriptor.
///
/// The slave's number stays mapped: another process may still hold the
/// master (a fork child closing its copy, as apt's does before opening the
/// slave by name), and on Linux the slave can be opened as long as any
/// reference to the master is. Guest numbers are never reused, and once the
/// last master is closed the host itself refuses to open its slave.
///
/// fwe's hold of the slave goes with it (a duplicate of the master the
/// guest keeps then has the host's ways: what its slave wrote goes with the
/// slave's last holder).
pub fn try_close(fd: i32) -> Option<i64> {
    let m = PTYS.if_used()?.as_mut()?.masters.remove(&fd)?;
    // SAFETY: `fd` is a master we allocated, `m.keep` fwe's hold of its
    // slave.
    unsafe {
        if m.keep >= 0 {
            libc::close(m.keep);
        }
        libc::close(fd);
    }
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

    /// A slave can be opened by number after the guest closes a master that
    /// is still open elsewhere: a fork child closing its copy of the
    /// parent's master, as apt's does before it opens the slave.
    #[test]
    fn slave_opens_after_a_shared_master_is_closed() {
        let m = open_master(0);
        if m < 0 {
            eprintln!("skipping: pty unavailable ({m})");
            return;
        }
        let n = ptsnum(m as i32).unwrap();
        // SAFETY: duplicating the master: the copy another process keeps.
        let other = unsafe { libc::dup(m as i32) };
        assert_eq!(try_close(m as i32), Some(0));
        let s = open_slave(n, libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open_slave after close: {s}");
        // SAFETY: closing the descriptors made here.
        unsafe {
            libc::close(s as i32);
            libc::close(other);
        }
    }

    /// A master's read as the guest's goes: [`before_read`], then the
    /// host's.
    fn read_master(m: i32, buf: &mut [u8]) -> i64 {
        before_read(m).unwrap_or_else(|| {
            // SAFETY: a valid descriptor and buffer.
            crate::host::ret(unsafe { libc::read(m, buf.as_mut_ptr().cast(), buf.len()) } as i64)
        })
    }

    /// What a slave wrote outlives it: the master reads it, then `EIO`;
    /// a master whose slave no guest has opened is not hung up.
    #[test]
    fn master_reads_what_a_closed_slave_left_then_eio() {
        let m = open_master(0);
        if m < 0 {
            eprintln!("skipping: pty unavailable ({m})");
            return;
        }
        let m = m as i32;
        assert!(!hung_up(m), "no slave opened yet");
        let n = ptsnum(m).unwrap();
        let s = open_slave(n, libc::O_RDWR | libc::O_NOCTTY) as i32;
        assert!(s >= 0, "open_slave: {s}");
        // SAFETY: valid descriptors and buffers.
        unsafe {
            assert_eq!(libc::write(s, b"hi\n".as_ptr().cast(), 3), 3);
            libc::close(s);
        }
        let mut buf = [0u8; 8];
        let got = read_master(m, &mut buf);
        assert_eq!(&buf[..got.max(0) as usize], b"hi\r\n", "read: {got}");
        assert_eq!(read_master(m, &mut buf), err(errno::EIO));
        assert_eq!(try_close(m), Some(0));
    }

    #[test]
    fn unknown_slave_is_enoent() {
        assert_eq!(open_slave(999_999, libc::O_RDWR), err(errno::ENOENT));
    }
}
