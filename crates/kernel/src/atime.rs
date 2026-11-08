//! Access times as a mount's flags have them: `noatime` (never updated),
//! `nodiratime` (never for a directory) and `strictatime` (on every
//! read). The host updates a file's access time by its own rule, so a read
//! of a file opened through such a mount has its access time noted before
//! and set after, as Linux would have left it. A mount with none of them
//! is `relatime`, Linux's default, which is left to the host.

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

/// Before call `n`: what its read of a file of a `noatime`, `nodiratime`
/// or `strictatime` mount needs afterwards.
pub fn before(n: u64, a: &[u64; 6]) -> Option<Before> {
    let fd = read_fd(n, a)?;
    if !crate::fdmarks::any_marks() {
        return None;
    }
    let flags = crate::fdmarks::origin(fd)?.flags;
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
    Some(Before { fd, atime, keep })
}

/// After the call noted `b` returned `r`: the access time as the mount has
/// it.
pub fn after(b: Option<Before>, r: i64) {
    let Some(b) = b else { return };
    if r < 0 {
        return;
    }
    let atime =
        if b.keep { b.atime } else { libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW } };
    let times = [atime, libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }];
    // SAFETY: a valid times array; the descriptor is the guest's.
    unsafe { libc::futimens(b.fd, times.as_ptr()) };
}
