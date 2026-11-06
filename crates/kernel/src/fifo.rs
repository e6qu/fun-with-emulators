//! Named FIFOs, as Linux has them, where macOS differs.
//!
//! On Linux, once the last writer of a FIFO closes, its reader is readable
//! (`read` returns end-of-file) and `poll` and `epoll` report `POLLHUP` —
//! once a writer has been there: a reader that never had one is not hung
//! up. macOS's `read` returns end-of-file too, but neither `kqueue` nor
//! `poll` reports anything, so a reader that waits with them never learns
//! it. `select` does: the host's FIFO is a pair of sockets, and `select`
//! asks the reading one, which is readable once its writers have gone (and
//! not before one has been there), as Linux's is. fwe waits that watch a
//! FIFO's read end look with it between short slices ([`probe`]). It reads
//! nothing, so another reader of the FIFO (a process may hold one only to
//! keep it open) loses no data to the look.
//!
//! Anonymous pipes need none of this: the host reports their writer's end.

/// What a probe found: the writers have gone, data is waiting, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    HungUp,
    Data,
    Nothing,
}

/// Whether `fd` is the read end of a named FIFO (one the host would not
/// report the writers' end of).
pub fn is_reader(fd: i32) -> bool {
    if cfg!(target_os = "linux") {
        // The host is Linux: it reports a FIFO's writers going itself.
        return false;
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return false;
    }
    // SAFETY: plain host call.
    let access = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
    access != libc::O_WRONLY && crate::fs::host_path_of(fd).is_some()
}

/// Look at FIFO reader `fd` without blocking, and without reading.
pub fn probe(fd: i32) -> Probe {
    if fd < 0 {
        return Probe::Nothing;
    }
    if !readable(fd) {
        return Probe::Nothing;
    }
    let mut waiting: libc::c_int = 0;
    // SAFETY: a valid out-parameter.
    if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut waiting) } == 0 && waiting > 0 {
        return Probe::Data;
    }
    // Readable with nothing to read: end-of-file, the writers gone.
    Probe::HungUp
}

/// Whether `select` finds `fd` readable now.
fn readable(fd: i32) -> bool {
    // A set of the bits up to `fd`, however high: the host's `select`
    // takes any number of descriptors in its unlimited form.
    let mut set = vec![0u32; fd as usize / 32 + 1];
    set[fd as usize / 32] |= 1 << (fd % 32);
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    // SAFETY: `set` spans `fd + 1` bits; `tv` is a zero timeout.
    let n = unsafe {
        select_any(
            fd + 1,
            set.as_mut_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    n > 0 && set[fd as usize / 32] & (1 << (fd % 32)) != 0
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `select` without the `FD_SETSIZE` bound (`_DARWIN_UNLIMITED_SELECT`).
    #[link_name = "select$DARWIN_EXTSN"]
    fn select_any(
        n: libc::c_int,
        r: *mut libc::fd_set,
        w: *mut libc::fd_set,
        e: *mut libc::fd_set,
        t: *mut libc::timeval,
    ) -> libc::c_int;
}

#[cfg(not(target_os = "macos"))]
use libc::select as select_any;

/// How long a wait that watches FIFO readers sleeps between probes.
pub const SLICE_MS: i32 = 20;

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The host's `select` says what Linux's `poll` would: nothing before a
    /// writer has been there or while one is, data once written, end of
    /// file once the writers have gone; and the look takes nothing.
    #[test]
    fn probe_sees_writers_go() {
        let dir = std::env::temp_dir().join(format!("fwe-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = CString::new(dir.join("f").to_str().unwrap()).unwrap();
        // SAFETY: plain host calls on a FIFO of this test's own.
        unsafe {
            assert_eq!(libc::mkfifo(path.as_ptr(), 0o600), 0);
            let r = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
            assert!(r >= 0);
            assert_eq!(probe(r), Probe::Nothing, "no writer yet");
            let w = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
            assert!(w >= 0);
            assert_eq!(probe(r), Probe::Nothing, "a writer, nothing written");
            assert_eq!(libc::write(w, b"ab".as_ptr().cast(), 2), 2);
            assert_eq!(probe(r), Probe::Data);
            libc::close(w);
            assert_eq!(probe(r), Probe::Data, "gone, data left");
            let mut b = [0u8; 4];
            assert_eq!(libc::read(r, b.as_mut_ptr().cast(), 4), 2, "the look took nothing");
            assert_eq!(probe(r), Probe::HungUp);
            libc::close(r);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
