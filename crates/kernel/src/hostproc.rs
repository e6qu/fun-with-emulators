//! Processes fwe starts for itself, and the sockets it talks to them over:
//! a spawn that hands the new process only the descriptors named, and a
//! stream socket's reads and writes that pass a descriptor alongside
//! (`SCM_RIGHTS`).

use crate::ids::HostPid;
use std::os::fd::{FromRawFd, OwnedFd};

/// Start program `path` with `argv` (NUL-terminated pointers, ending in
/// null) and this process's environment, as a process of fwe's own: in a
/// process group of its own, every signal unblocked and at its default,
/// holding only the descriptors `moved` puts in place (each `(from, to)`)
/// and those `kept` names (the rest close as it starts). Its pid, or the
/// spawn's error.
#[cfg(not(target_os = "macos"))]
pub fn spawn(
    _path: &std::ffi::CStr,
    _argv: &[*const libc::c_char],
    _moved: &[(i32, i32)],
    _kept: &[i32],
) -> Result<HostPid, i32> {
    Err(fwe_abi::errno::ENOSYS)
}

/// As above, on macOS (whose spawn can close every descriptor not named).
#[cfg(target_os = "macos")]
pub fn spawn(
    path: &std::ffi::CStr,
    argv: &[*const libc::c_char],
    moved: &[(i32, i32)],
    kept: &[i32],
) -> Result<HostPid, i32> {
    assert!(argv.last().is_some_and(|p| p.is_null()), "argv ends in null");
    assert!(
        kept.iter().all(|k| moved.iter().all(|m| m.1 != *k)),
        "a kept descriptor is moved over"
    );
    unsafe extern "C" {
        fn posix_spawn_file_actions_addinherit_np(
            fa: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
        static environ: *const *const libc::c_char;
    }
    // The actions run in order in the new process, so a source that is
    // another's target would be overwritten before it is read: each source
    // goes first to a number of its own above every one named, which only
    // the new process has, then to its target. (macOS's actions name no
    // descriptor at or above OPEN_MAX, 10240, where fwe's reserved range is:
    // the sources are not fwe's own, which are not passed this way.)
    let top = moved.iter().flat_map(|&(f, t)| [f, t]).chain(kept.iter().copied()).max();
    let scratch = top.map_or(0, |t| t + 1);
    let mut pid = 0;
    // SAFETY: spawn attributes and file actions initialized, used and
    // destroyed here; the argument array and the environment live across
    // the call.
    let rc = unsafe {
        let mut fa: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        libc::posix_spawn_file_actions_init(&mut fa);
        let mut added = 0;
        for (i, &(from, _)) in moved.iter().enumerate() {
            added |= libc::posix_spawn_file_actions_adddup2(&mut fa, from, scratch + i as i32);
        }
        for (i, &(_, to)) in moved.iter().enumerate() {
            added |= libc::posix_spawn_file_actions_adddup2(&mut fa, scratch + i as i32, to);
            added |= libc::posix_spawn_file_actions_addclose(&mut fa, scratch + i as i32);
        }
        for &fd in kept {
            added |= posix_spawn_file_actions_addinherit_np(&mut fa, fd);
        }
        if added != 0 {
            libc::posix_spawn_file_actions_destroy(&mut fa);
            return Err(fwe_abi::errno::EBADF);
        }
        let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
        libc::posix_spawnattr_init(&mut attr);
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::posix_spawnattr_setsigmask(&mut attr, &none);
        libc::posix_spawnattr_setsigdefault(&mut attr, &all);
        libc::posix_spawnattr_setpgroup(&mut attr, 0);
        let flags = libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short);
        let rc = libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            &fa,
            &attr,
            argv.as_ptr() as *const *mut libc::c_char,
            environ as *const *mut libc::c_char,
        );
        libc::posix_spawn_file_actions_destroy(&mut fa);
        libc::posix_spawnattr_destroy(&mut attr);
        rc
    };
    if rc != 0 {
        return Err(rc);
    }
    HostPid::new(pid).ok_or(fwe_abi::errno::ECHILD)
}

/// A control message buffer for one descriptor, aligned as `cmsghdr`s are.
type Control = [u64; 4];

/// Send all of `bytes` on stream socket `sock`, with descriptor `fd` (if
/// any) passed alongside the first of them.
pub fn send_with_fd(sock: i32, bytes: &[u8], fd: Option<i32>) -> std::io::Result<()> {
    let mut sent = 0;
    if let Some(fd) = fd {
        let mut control: Control = [0; 4];
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
        assert!(space <= size_of::<Control>());
        let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut _, iov_len: bytes.len() };
        // SAFETY: an all-zero msghdr is valid; it points at this frame's
        // buffers, which live across the call; the control message is
        // written within its buffer, which is large enough.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
            libc::CMSG_DATA(c).cast::<i32>().write_unaligned(fd);
            libc::sendmsg(sock, &msg, 0)
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        sent = n as usize;
    }
    while sent < bytes.len() {
        // SAFETY: the rest of `bytes`, read during the call.
        let n = unsafe { libc::write(sock, bytes[sent..].as_ptr().cast(), bytes.len() - sent) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        sent += n as usize;
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes from stream socket `sock`, and the
/// descriptor passed with them, if one was: moved into fwe's reserved range,
/// close-on-exec ([`crate::fdtable::reserve`]).
pub fn recv_with_fd(sock: i32, buf: &mut [u8]) -> std::io::Result<Option<OwnedFd>> {
    let mut got = 0;
    let mut passed = None;
    while got < buf.len() {
        let mut control: Control = [0; 4];
        let mut iov =
            libc::iovec { iov_base: buf[got..].as_mut_ptr().cast(), iov_len: buf.len() - got };
        // SAFETY: an all-zero msghdr is valid; it points at this frame's
        // buffers, which live across the call.
        let (n, msg) = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = size_of::<Control>() as _;
            (libc::recvmsg(sock, &mut msg, 0), msg)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        // SAFETY: the control messages the host wrote into `control`.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let fd = libc::CMSG_DATA(c).cast::<i32>().read_unaligned();
                    let high =
                        crate::fdtable::reserve(fd).map_err(std::io::Error::from_raw_os_error)?;
                    passed = Some(OwnedFd::from_raw_fd(high));
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        got += n as usize;
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// A pipe: its read end, and its write end at a number of its own above
    /// `at`.
    #[cfg(target_os = "macos")]
    fn pipe_above(at: i32) -> (std::fs::File, OwnedFd) {
        let mut ends = [0; 2];
        // SAFETY: plain host call into this frame's array.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: plain host calls on the descriptors just made, owned here.
        unsafe {
            let high = libc::fcntl(ends[1], libc::F_DUPFD_CLOEXEC, at);
            libc::close(ends[1]);
            (std::fs::File::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(high))
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn descriptors_moved_low_land_there() {
        use std::io::Read;
        let (mut p, pw) = pipe_above(300);
        let (mut q, qw) = pipe_above(300);
        let (mut r, rw) = pipe_above(300);
        let script = c"echo three >&3; echo four >&4; echo zero >&0";
        let argv = [c"/bin/sh".as_ptr(), c"-c".as_ptr(), script.as_ptr(), std::ptr::null()];
        let moved = [(pw.as_raw_fd(), 3), (qw.as_raw_fd(), 4), (rw.as_raw_fd(), 0)];
        let pid = spawn(c"/bin/sh", &argv, &moved, &[2]).unwrap();
        let mut status = 0;
        // SAFETY: plain host call on the child just started.
        assert_eq!(unsafe { libc::waitpid(pid.get(), &mut status, 0) }, pid.get());
        drop((pw, qw, rw));
        let mut got = [String::new(), String::new(), String::new()];
        p.read_to_string(&mut got[0]).unwrap();
        q.read_to_string(&mut got[1]).unwrap();
        r.read_to_string(&mut got[2]).unwrap();
        assert_eq!(got, ["three\n", "four\n", "zero\n"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn descriptors_swapped_in_a_spawn_each_land_where_named() {
        use std::io::Read;
        let (mut p, pw) = pipe_above(300);
        let (mut q, qw) = pipe_above(300);
        let (a, b) = (pw.as_raw_fd(), qw.as_raw_fd());
        // The child's `a` is `q`'s write end and its `b` is `p`'s: each
        // source is the other's target.
        let script = std::ffi::CString::new(format!("echo p >&{b}; echo q >&{a}")).unwrap();
        let argv = [c"/bin/sh".as_ptr(), c"-c".as_ptr(), script.as_ptr(), std::ptr::null()];
        let pid = spawn(c"/bin/sh", &argv, &[(a, b), (b, a)], &[]).unwrap();
        let mut status = 0;
        // SAFETY: plain host call on the child just started.
        assert_eq!(unsafe { libc::waitpid(pid.get(), &mut status, 0) }, pid.get());
        drop((pw, qw));
        let (mut got_p, mut got_q) = (String::new(), String::new());
        p.read_to_string(&mut got_p).unwrap();
        q.read_to_string(&mut got_q).unwrap();
        assert_eq!((got_p.as_str(), got_q.as_str()), ("p\n", "q\n"));
    }

    #[test]
    fn a_descriptor_passes_with_the_bytes() {
        let mut ends = [0; 2];
        // SAFETY: plain host call into this frame's array.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, ends.as_mut_ptr()) };
        assert_eq!(r, 0);
        // SAFETY: the descriptors just made, owned here.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        let file = std::fs::File::open("/dev/null").unwrap();
        send_with_fd(a.as_raw_fd(), b"head and body", Some(file.as_raw_fd())).unwrap();
        let mut buf = [0u8; 13];
        let got = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap().expect("a descriptor");
        assert_eq!(&buf, b"head and body");
        assert!(!crate::fdtable::guest_visible(got.as_raw_fd()));
        send_with_fd(a.as_raw_fd(), b"no descriptor", None).unwrap();
        assert!(recv_with_fd(b.as_raw_fd(), &mut buf).unwrap().is_none());
        drop(a);
        assert!(recv_with_fd(b.as_raw_fd(), &mut buf).is_err());
    }
}
