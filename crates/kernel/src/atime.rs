//! Access times as a mount's flags have them: `noatime` (never updated),
//! `nodiratime` (never for a directory) and `strictatime` (on every
//! read). The host updates a file's access time by its own rule, so a read
//! of a file opened through such a mount has its access time noted before
//! and, where the host left another, set after as Linux would have left
//! it, by the host's `setattrlist` of the access time alone, which leaves
//! the change time as a read leaves it. A mount with none of them is `relatime`, Linux's
//! default, which is left to the host.

use crate::mounts::ms;
use fwe_abi::nr;

/// What a read needs restored or set, noted before it.
pub struct Before {
    fd: i32,
    atime: libc::timespec,
    /// Leave the access time as it was (else: set it to now).
    keep: bool,
}

/// The descriptor call `n` (with `a`) reads, if it reads one.
fn read_fd(n: u64, a: &[u64; 6]) -> Option<i32> {
    Some(match n {
        nr::READ | nr::READV | nr::PREAD64 | nr::PREADV | nr::PREADV2 | nr::GETDENTS64 => a[0],
        nr::SENDFILE => a[1],
        nr::SPLICE | nr::COPY_FILE_RANGE => a[0],
        _ => return None,
    } as i32)
}

/// Whether any descriptor was opened with `O_NOATIME` (until then a read
/// looks no further).
static NOATIME_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The descriptors opened with `O_NOATIME`: reading through one leaves the
/// access time, as Linux's does.
pub(crate) static NOATIME_FDS: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

fn noatime_fd(fd: i32) -> bool {
    NOATIME_FDS.lock().unwrap_or_else(|e| e.into_inner()).contains(&fd)
}

/// `fd` was opened with `O_NOATIME`.
pub fn opened_noatime(fd: i32) {
    NOATIME_FDS.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
    NOATIME_ANY.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    if NOATIME_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        if noatime_fd(fd) {
            note(fd, "closing");
        }
        NOATIME_FDS.lock().unwrap_or_else(|e| e.into_inner()).retain(|&f| f != fd);
    }
}

/// Before call `n`: what its read of a file of a `noatime`, `nodiratime`
/// or `strictatime` mount needs afterwards.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn before(n: u64, a: &[u64; 6]) -> Option<Before> {
    let fd = read_fd(n, a)?;
    // Opened with `O_NOATIME`: as a `noatime` mount's file.
    let own = NOATIME_ANY.load(std::sync::atomic::Ordering::Relaxed) && noatime_fd(fd);
    if !own && !crate::fdmarks::atime_files() {
        return None;
    }
    let flags = if own { ms::NOATIME } else { crate::fdmarks::origin(fd)?.flags };
    if flags & (ms::NOATIME | ms::NODIRATIME | ms::STRICTATIME) == 0 {
        return None;
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let keep = flags & ms::NOATIME != 0 || (dir && flags & ms::NODIRATIME != 0) || {
        // Else `strictatime`, or `relatime` (with `nodiratime`, for a
        // file): updated only when it is not after the last change, or a
        // day old.
        let (at, mt, ct) = (st.st_atime, st.st_mtime, st.st_ctime);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        flags & ms::STRICTATIME == 0 && at > mt && at > ct && now - at < 86_400
    };
    let atime = libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec };
    note(fd, if keep { "before a read that keeps it" } else { "before a read that sets it" });
    Some(Before { fd, atime, keep })
}

/// After the call noted `b` returned `r`: the access time as the mount has
/// it.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn after(b: Option<Before>, r: i64) {
    let Some(b) = b else { return };
    if r < 0 {
        return;
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(b.fd, &mut st) } != 0 {
        return;
    }
    let now = (st.st_atime, st.st_atime_nsec);
    note(b.fd, "after the read");
    let atime = if b.keep {
        if now == (b.atime.tv_sec, b.atime.tv_nsec) {
            return;
        }
        b.atime
    } else {
        // Updated: the host did, if it moved it on.
        if now > (b.atime.tv_sec, b.atime.tv_nsec) {
            return;
        }
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a valid out-parameter.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
        now
    };
    set_access_time(b.fd, atime);
    note(b.fd, &format!("set back to {}.{:09} after the host's read", atime.tv_sec, atime.tv_nsec));
}

/// Note, in the trace file (`--strace-file`), the access, change and
/// modification times of the file open as `fd`, at `when`: what a guest
/// that finds an access time it did not expect can be traced by.
fn note(fd: i32, when: &str) {
    if crate::trace::file().is_none() {
        return;
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return;
    }
    crate::trace::note_to_file(&format!(
        "access time of fd {fd} (inode {}) {when}: atime {}.{:09} mtime {}.{:09} ctime {}.{:09}",
        st.st_ino,
        st.st_atime,
        st.st_atime_nsec,
        st.st_mtime,
        st.st_mtime_nsec,
        st.st_ctime,
        st.st_ctime_nsec
    ));
}

/// Give the file open as `fd` the access time `t`, its change time left
/// as it is, as a read leaves it on Linux: the host's `setattrlist` of the
/// access time alone moves no change time (`futimens` would).
#[cfg(target_os = "macos")]
fn set_access_time(fd: i32, t: libc::timespec) {
    // SAFETY: zeroed bytes are a valid `attrlist`.
    let mut list: libc::attrlist = unsafe { std::mem::zeroed() };
    list.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    list.commonattr = libc::ATTR_CMN_ACCTIME;
    // SAFETY: a valid attribute list and a buffer of the one timespec it
    // names; the descriptor is the guest's.
    unsafe {
        libc::fsetattrlist(
            fd,
            std::ptr::from_mut(&mut list).cast(),
            std::ptr::from_ref(&t).cast_mut().cast(),
            std::mem::size_of::<libc::timespec>(),
            0,
        )
    };
}

#[cfg(not(target_os = "macos"))]
fn set_access_time(fd: i32, t: libc::timespec) {
    let times = [t, libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }];
    // SAFETY: a valid times array; the descriptor is the guest's.
    unsafe { libc::futimens(fd, times.as_ptr()) };
}
