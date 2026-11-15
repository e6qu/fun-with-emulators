//! File-system rules a Linux program relies on, one scenario per argument,
//! each printing what it observed. Runs as (virtual) root in a root
//! filesystem with `/tmp`.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

use std::ffi::{CString, c_char};

const O_RDONLY: i32 = 0;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const R_OK: i32 = 4;
const W_OK: i32 = 2;
const X_OK: i32 = 1;
const AT_FDCWD: i32 = -100;
const AT_EACCESS: i32 = 0x200;
const SYS_FACCESSAT2: i64 = 439;

unsafe extern "C" {
    fn open(p: *const c_char, f: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn mkdir(p: *const c_char, m: u32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, st: *mut i32, o: i32) -> i32;
    fn setuid(u: u32) -> i32;
    fn setgid(g: u32) -> i32;
    fn setresuid(r: u32, e: u32, s: u32) -> i32;
    fn setgroups(n: usize, g: *const u32) -> i32;
    fn access(p: *const c_char, m: i32) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// `r`, a C library result: "ok", or the name of the error.
fn res(r: i64) -> String {
    if r >= 0 { "ok".into() } else { name(errno()) }
}

fn name(e: i32) -> String {
    match e {
        1 => "EPERM".into(),
        2 => "ENOENT".into(),
        13 => "EACCES".into(),
        30 => "EROFS".into(),
        e => format!("errno {e}"),
    }
}

/// Make file `p` with mode `mode`.
fn make(p: &str, mode: u32) {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c(p).as_ptr(), O_CREAT | O_RDWR, mode) };
    assert!(fd >= 0, "make {p}: {}", errno());
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
}

/// Run `f` in a child process, waiting for it.
fn in_child(f: impl FnOnce()) {
    // SAFETY: plain fork; the child runs `f` and exits.
    let pid = unsafe { fork() };
    if pid == 0 {
        f();
        // SAFETY: ends the child.
        unsafe { _exit(0) };
    }
    let mut st = 0;
    // SAFETY: waits for the child just made.
    unsafe { waitpid(pid, &mut st, 0) };
}

fn faccessat2(p: &str, mode: i32, flags: i32) -> String {
    // SAFETY: a NUL-terminated path.
    res(unsafe { syscall(SYS_FACCESSAT2, AT_FDCWD, c(p).as_ptr(), mode, flags) })
}

/// `access` agrees with `open` for a user that is not root; the real ids
/// are checked unless `AT_EACCESS` asks for the effective ones; root
/// searches a directory of no execute bit but runs no file of none.
fn access_scenario() {
    make("/tmp/a", 0o640);
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/d").as_ptr(), 0o700);
        mkdir(c("/tmp/nox").as_ptr(), 0o600);
    }
    make("/tmp/d/g", 0o644);
    // SAFETY: NUL-terminated paths.
    let (dir_x, file_x) =
        unsafe { (access(c("/tmp/nox").as_ptr(), X_OK), access(c("/tmp/a").as_ptr(), X_OK)) };
    println!("root X_OK dir: {} file: {}", res(dir_x.into()), res(file_x.into()));
    in_child(|| {
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(1000);
            setuid(1000);
        }
        // SAFETY: NUL-terminated paths.
        let (r, o, w, s) = unsafe {
            (
                access(c("/tmp/a").as_ptr(), R_OK),
                open(c("/tmp/a").as_ptr(), O_RDONLY),
                access(c("/tmp/a").as_ptr(), W_OK),
                access(c("/tmp/d/g").as_ptr(), 0),
            )
        };
        println!("user R_OK: {} open: {}", res(r.into()), res(o.into()));
        println!("user W_OK: {} beyond a closed dir: {}", res(w.into()), res(s.into()));
    });
    in_child(|| {
        // Real user 1000, effective root.
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(1000);
            setresuid(1000, 0, 0);
        }
        println!(
            "real: {} effective: {}",
            faccessat2("/tmp/a", R_OK, 0),
            faccessat2("/tmp/a", R_OK, AT_EACCESS)
        );
    });
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    match scenario.as_str() {
        "access" => access_scenario(),
        s => panic!("unknown scenario {s}"),
    }
}
