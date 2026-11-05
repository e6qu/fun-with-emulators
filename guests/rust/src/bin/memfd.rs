//! Anonymous files as container runtimes use them: crun copies itself into a
//! sealed memfd and re-executes that copy, then checks through
//! `/proc/self/exe` that it runs sealed. One scenario per argument, each
//! printing what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::CString;

const MFD_CLOEXEC: u32 = 1;
const MFD_ALLOW_SEALING: u32 = 2;
const F_GETFL: i32 = 3;
const F_ADD_SEALS: i32 = 1033;
const F_GET_SEALS: i32 = 1034;
const F_SEAL_SEAL: i32 = 1;
const F_SEAL_SHRINK: i32 = 2;
const F_SEAL_GROW: i32 = 4;
const F_SEAL_WRITE: i32 = 8;
const O_RDONLY: i32 = 0;
const O_RDWR: i32 = 2;
const O_ACCMODE: i32 = 3;
const O_CLOEXEC: i32 = 0o2000000;
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 1;
const AT_EMPTY_PATH: i64 = 0x1000;
const SYS_EXECVEAT: i64 = 281;
const EPERM: i32 = 1;
const EINVAL: i32 = 22;
const ALL: i32 = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

unsafe extern "C" {
    fn memfd_create(name: *const std::ffi::c_char, flags: u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn pread(fd: i32, buf: *mut u8, len: usize, off: i64) -> isize;
    fn ftruncate(fd: i32, len: i64) -> i32;
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn execve(
        path: *const std::ffi::c_char,
        argv: *const *const std::ffi::c_char,
        envp: *const *const std::ffi::c_char,
    ) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's errno location for this thread.
    unsafe { *__errno_location() }
}

fn name(e: i32) -> &'static str {
    match e {
        EPERM => "EPERM",
        EINVAL => "EINVAL",
        _ => "?",
    }
}

fn link(path: &str) -> String {
    std::fs::read_link(path).map(|p| p.display().to_string()).unwrap_or_else(|e| e.to_string())
}

/// A sealable memfd holding this program, sealed as crun seals its copy.
fn sealed_copy_of_self() -> i32 {
    let me = std::fs::read("/proc/self/exe").unwrap();
    // SAFETY: a NUL-terminated name.
    let fd = unsafe { memfd_create(c"self".as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
    assert!(fd >= 0, "memfd_create: {}", errno());
    let mut at = 0;
    while at < me.len() {
        // SAFETY: a valid buffer.
        let n = unsafe { write(fd, me[at..].as_ptr(), me.len() - at) };
        assert!(n > 0);
        at += n as usize;
    }
    // SAFETY: plain call.
    assert_eq!(unsafe { fcntl(fd, F_ADD_SEALS, ALL) }, 0, "sealing: {}", errno());
    fd
}

fn c_strings(v: &[&str]) -> (Vec<CString>, Vec<*const std::ffi::c_char>) {
    let owned: Vec<CString> = v.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut ptrs: Vec<*const std::ffi::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    (owned, ptrs)
}

/// Run this program again from a sealed memfd, by descriptor or by its
/// `/proc/self/fd` path, as `child <how>`.
fn exec_copy(how: &str) -> ! {
    let fd = sealed_copy_of_self();
    let (_a, argv) = c_strings(&["copy", "child", how]);
    let (_e, envp) = c_strings(&[]);
    if how == "by-path" {
        let path = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
        // SAFETY: valid arrays of C strings.
        unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    } else {
        // SAFETY: valid arrays of C strings; an empty path with AT_EMPTY_PATH.
        unsafe {
            syscall(
                SYS_EXECVEAT,
                fd as i64,
                c"".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                AT_EMPTY_PATH,
            )
        };
    }
    panic!("exec of the copy failed: {}", errno());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        // A memfd: its name in /proc/self/fd, seals refused until sealing
        // is allowed, then each seal holding.
        Some("seals") => {
            // SAFETY: a NUL-terminated name.
            let plain = unsafe { memfd_create(c"plain".as_ptr(), 0) };
            println!("link: {}", link(&format!("/proc/self/fd/{plain}")));
            // SAFETY: plain calls.
            unsafe {
                println!("seals: {}", fcntl(plain, F_GET_SEALS));
                let r = fcntl(plain, F_ADD_SEALS, F_SEAL_WRITE);
                println!("sealing it: {r} {}", name(errno()));
                println!("not a memfd: {} {}", fcntl(0, F_GET_SEALS), name(errno()));
            }
            // SAFETY: a NUL-terminated name.
            let fd = unsafe { memfd_create(c"data".as_ptr(), MFD_ALLOW_SEALING) };
            // SAFETY: valid buffers and plain calls throughout.
            unsafe {
                write(fd, b"hello".as_ptr(), 5);
                println!("sealable: {}", fcntl(fd, F_GET_SEALS));
                fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW);
                println!("shrink: {} {}", ftruncate(fd, 2), name(errno()));
                println!("grow: {} {}", ftruncate(fd, 9), name(errno()));
                println!("same size: {}", ftruncate(fd, 5));
                // A writable shared mapping is refused once writing is sealed.
                fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE);
                println!("write: {} {}", write(fd, b"x".as_ptr(), 1), name(errno()));
                let m = mmap(std::ptr::null_mut(), 5, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                println!("writable mapping: {} {}", m as isize, name(errno()));
                let m = mmap(std::ptr::null_mut(), 5, PROT_READ, MAP_SHARED, fd, 0);
                println!("read-only mapping: {}", std::slice::from_raw_parts(m, 5) == b"hello");
                println!("still open for writing: {}", fcntl(fd, F_GETFL) & O_ACCMODE == O_RDWR);
                fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL);
                println!("seals now: {}", fcntl(fd, F_GET_SEALS));
                println!("more: {} {}", fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK), name(errno()));
                // Reopened through /proc, it is the same file.
                let p = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
                let again = open(p.as_ptr(), O_RDONLY | O_CLOEXEC);
                let mut buf = [0u8; 5];
                pread(again, buf.as_mut_ptr(), 5, 0);
                println!("reopened: {} seals {}", buf == *b"hello", fcntl(again, F_GET_SEALS));
                close(again);
            }
        }
        Some("exec") => exec_copy("by-descriptor"),
        Some("exec-path") => exec_copy("by-path"),
        // From a process with another thread, which fwe runs as a fresh
        // process of its own.
        Some("exec-threaded") => {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            std::thread::spawn(move || {
                let _ = rx.recv();
            });
            let _keep = tx;
            exec_copy("from-a-thread")
        }
        // The copy: run from the memfd, which /proc/self/exe opens.
        Some("child") => {
            println!("running {} as {}", args[2], args[0]);
            println!("exe: {}", link("/proc/self/exe"));
            // SAFETY: a NUL-terminated path; plain calls.
            unsafe {
                let fd = open(c"/proc/self/exe".as_ptr(), O_RDONLY | O_CLOEXEC);
                println!("exe sealed: {}", fcntl(fd, F_GET_SEALS) == ALL);
            }
        }
        other => panic!("unknown scenario {other:?}"),
    }
}
