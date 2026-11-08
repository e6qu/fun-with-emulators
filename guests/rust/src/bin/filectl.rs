//! `fcntl` on open files: open-file-description locks conflicting between
//! two opens of one file and shared by a duplicate; `F_CREATED_QUERY`; an
//! owned pipe's `F_SETSIG` signal standing for `SIGIO`, with the
//! descriptor; and a lease another process's open breaks, the open waiting
//! until the lease is let go. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const O_RDONLY: i32 = 0;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_ASYNC: i32 = 0o20000;
const F_DUPFD: i32 = 0;
const F_SETFL: i32 = 4;
const F_SETOWN: i32 = 8;
const F_SETSIG: i32 = 10;
const F_SETLEASE: i32 = 1024;
const F_GETLEASE: i32 = 1025;
const F_CREATED_QUERY: i32 = 1028;
const F_OFD_SETLK: i32 = 37;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const SIGUSR1: i32 = 10;
const SIGIO: i32 = 29;
const EAGAIN: i32 = 11;

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn getpid() -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn sigtimedwait(set: *const u64, info: *mut [u8; 128], timeout: *const Timespec) -> i32;
    fn sigprocmask(how: i32, set: *const u64, old: *mut u64) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn lock(fd: i32, kind: i16) -> i32 {
    let fl = Flock { l_type: kind, l_whence: 0, l_start: 0, l_len: 10, l_pid: 0 };
    // SAFETY: a valid flock.
    unsafe { fcntl(fd, F_OFD_SETLK, &fl) }
}

/// Wait up to five seconds for one of `sigs`: the signal and its
/// `si_fd`.
fn wait_for(sigs: &[i32]) -> (i32, i32) {
    let set: u64 = sigs.iter().fold(0, |s, &n| s | 1 << (n - 1));
    let mut info = [0u8; 128];
    let t = Timespec { sec: 5, nsec: 0 };
    // SAFETY: a valid set, siginfo buffer and timeout.
    let sig = unsafe { sigtimedwait(&set, &mut info, &t) };
    (sig, i32::from_ne_bytes(info[24..28].try_into().unwrap()))
}

fn main() {
    // SAFETY: plain calls into the C library throughout.
    unsafe {
        let path = CString::new(format!("/tmp/fwe-filectl-{}", getpid())).unwrap();
        // Made by this open, then not by the next.
        let a = open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
        let made = fcntl(a, F_CREATED_QUERY, 0);
        let b = open(path.as_ptr(), O_RDWR);
        println!("created: {made}, then {}", fcntl(b, F_CREATED_QUERY, 0));

        // Two opens of the file conflict; a duplicate shares the lock.
        let first = lock(a, F_WRLCK);
        let second = lock(b, F_WRLCK) == -1 && errno() == EAGAIN;
        let dup = fcntl(a, F_DUPFD, 0);
        let released = lock(dup, F_UNLCK);
        println!("ofd: locked {first}, other open refused {second}, released through a duplicate {released}, then {}", lock(b, F_WRLCK));
        close(dup);
        close(a);
        close(b);

        // An owned pipe's chosen signal, with the descriptor, for SIGIO.
        let blocked: u64 = (1 << (SIGUSR1 - 1)) | (1 << (SIGIO - 1));
        sigprocmask(0, &blocked, std::ptr::null_mut());
        let mut p = [0i32; 2];
        pipe(p.as_mut_ptr());
        fcntl(p[0], F_SETOWN, getpid());
        fcntl(p[0], F_SETSIG, SIGUSR1);
        fcntl(p[0], F_SETFL, O_ASYNC);
        write(p[1], b"x".as_ptr(), 1);
        let (sig, fd) = wait_for(&[SIGUSR1, SIGIO]);
        println!("io signal: {}, for the descriptor {}", if sig == SIGUSR1 { "the chosen one" } else { "SIGIO" }, fd == p[0]);
        close(p[0]);
        close(p[1]);

        // A lease another process's open breaks: the holder hears, lets it
        // go, and the open goes on.
        let fd = open(path.as_ptr(), O_RDONLY);
        let leased = fcntl(fd, F_SETLEASE, F_WRLCK as i32);
        let pid = fork();
        if pid == 0 {
            let other = open(path.as_ptr(), O_RDONLY);
            _exit((other >= 0) as i32);
        }
        let mut status = 0;
        let (sig, _) = wait_for(&[SIGIO]);
        let breaking = fcntl(fd, F_GETLEASE);
        let downgraded = fcntl(fd, F_SETLEASE, F_RDLCK as i32);
        waitpid(pid, &mut status, 0);
        println!(
            "lease: set {leased}, broken {}, to {}, downgraded {downgraded}, the other open done {}",
            sig == SIGIO,
            if breaking == F_RDLCK as i32 { "read" } else { "other" },
            (status >> 8) & 0xff == 1
        );
        fcntl(fd, F_SETLEASE, F_UNLCK as i32);
        close(fd);
        std::fs::remove_file(path.to_str().unwrap()).unwrap();
    }
}
