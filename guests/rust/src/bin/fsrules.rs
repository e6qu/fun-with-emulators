//! File-system rules a Linux program relies on, one scenario per argument,
//! each printing what it observed. Runs as (virtual) root in a root
//! filesystem with `/tmp`.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

use std::ffi::{CString, c_char};

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const O_NONBLOCK: i32 = 0o4000;
const O_DIRECTORY: i32 = 0o40000;
const O_PATH: i32 = 0o10000000;
const O_TMPFILE: i32 = 0o20200000;
const R_OK: i32 = 4;
const W_OK: i32 = 2;
const X_OK: i32 = 1;
const AT_FDCWD: i32 = -100;
const AT_EACCESS: i32 = 0x200;
const AT_EMPTY_PATH: i32 = 0x1000;
const SYS_FACCESSAT2: i64 = 439;
const SYS_STATX: i64 = 291;
const SYS_NAME_TO_HANDLE_AT: i64 = 264;
const SYS_OPEN_BY_HANDLE_AT: i64 = 265;
const SYS_CAPSET: i64 = 91;

unsafe extern "C" {
    fn open(p: *const c_char, f: i32, ...) -> i32;
    fn openat(d: i32, p: *const c_char, f: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn mkdir(p: *const c_char, m: u32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, st: *mut i32, o: i32) -> i32;
    fn setuid(u: u32) -> i32;
    fn setgid(g: u32) -> i32;
    fn setresuid(r: u32, e: u32, s: u32) -> i32;
    fn setgroups(n: usize, g: *const u32) -> i32;
    fn access(p: *const c_char, m: i32) -> i32;
    fn stat(p: *const c_char, st: *mut u8) -> i32;
    fn fstat(fd: i32, st: *mut u8) -> i32;
    fn chown(p: *const c_char, u: u32, g: u32) -> i32;
    fn chmod(p: *const c_char, m: u32) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn mknod(p: *const c_char, m: u32, d: u64) -> i32;
    fn chdir(p: *const c_char) -> i32;
    fn read(fd: i32, b: *mut u8, n: usize) -> isize;
    fn write(fd: i32, b: *const u8, n: usize) -> isize;
    fn mount(
        s: *const c_char,
        t: *const c_char,
        f: *const c_char,
        fl: u64,
        d: *const c_char,
    ) -> i32;
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
    let n = match e {
        1 => "EPERM",
        2 => "ENOENT",
        9 => "EBADF",
        11 => "EAGAIN",
        13 => "EACCES",
        17 => "EEXIST",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        28 => "ENOSPC",
        30 => "EROFS",
        40 => "ELOOP",
        95 => "EOPNOTSUPP",
        116 => "ESTALE",
        e => return format!("errno {e}"),
    };
    n.into()
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

/// `stat` of `p`: (uid, gid, mode).
fn stat_of(p: &str) -> (u32, u32, u32) {
    let mut st = [0u64; 16];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
    let r = unsafe { stat(c(p).as_ptr(), st.as_mut_ptr().cast()) };
    assert_eq!(r, 0, "stat {p}: {}", errno());
    let word = |i: usize| (st[i / 2] >> (32 * (i % 2))) as u32;
    // arm64's `struct stat`: dev, ino, then mode, nlink, uid, gid words.
    (word(6), word(7), word(4))
}

/// The inode flags of `p` (`FS_IOC_GETFLAGS`), or with `set` given, set
/// them.
fn inode_flags(p: &str, set: Option<u32>) -> u32 {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c(p).as_ptr(), O_RDONLY) };
    let mut v = set.unwrap_or(0);
    let req: u64 = if set.is_some() { 0x4008_6602 } else { 0x8008_6601 };
    // SAFETY: the flags word for the request.
    let r = unsafe { ioctl(fd, req, &mut v) };
    assert_eq!(r, 0, "inode flags of {p}: {}", errno());
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
    v
}

/// The `statx` attributes of `p`.
fn statx_attributes(p: &str) -> u64 {
    let mut buf = [0u64; 32];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct statx`.
    let r = unsafe { syscall(SYS_STATX, AT_FDCWD, c(p).as_ptr(), 0, 0xfff, buf.as_mut_ptr()) };
    assert_eq!(r, 0, "statx {p}: {}", errno());
    buf[1]
}

/// A file given another owner is not no-dump, and clearing its inode
/// flags (`chattr -d`) keeps its owner; the guest's own no-dump is
/// reported as set.
fn nodump_scenario() {
    const FS_NODUMP_FL: u32 = 0x40;
    const STATX_ATTR_NODUMP: u64 = 0x40;
    make("/tmp/owned", 0o644);
    // SAFETY: a NUL-terminated path.
    unsafe { chown(c("/tmp/owned").as_ptr(), 1000, 100) };
    let nodump = |p: &str| {
        (inode_flags(p, None) & FS_NODUMP_FL != 0, statx_attributes(p) & STATX_ATTR_NODUMP != 0)
    };
    println!("owned no-dump: {:?}", nodump("/tmp/owned"));
    inode_flags("/tmp/owned", Some(0));
    let (uid, gid, _) = stat_of("/tmp/owned");
    println!("after clearing: {uid}:{gid}");
    inode_flags("/tmp/owned", Some(FS_NODUMP_FL));
    let (uid, gid, _) = stat_of("/tmp/owned");
    println!("set: {:?} owner {uid}:{gid}", nodump("/tmp/owned"));
}

/// A device node made outside `/dev` opens as the device, also to read by
/// an absolute path and from the working directory.
fn devnode_scenario() {
    // SAFETY: NUL-terminated paths.
    let r = unsafe { mknod(c("/tmp/zero").as_ptr(), 0o20666, (1 << 8) | 5) };
    println!("mknod: {}", res(r.into()));
    for p in ["/tmp/zero", "zero"] {
        // SAFETY: NUL-terminated paths.
        unsafe { chdir(c("/tmp").as_ptr()) };
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c(p).as_ptr(), O_RDONLY) };
        let mut buf = [1u8; 4];
        // SAFETY: a buffer of 4 bytes.
        let n = unsafe { read(fd, buf.as_mut_ptr(), 4) };
        println!("{p}: {n} {buf:?}");
        // SAFETY: the descriptor just opened.
        unsafe { close(fd) };
    }
}

/// A file handle of `p`: its 8-byte head and bytes.
fn handle_of(p: &str) -> [u8; 136] {
    let mut h = [0u8; 136];
    h[..4].copy_from_slice(&128u32.to_ne_bytes());
    let mut mnt = 0i32;
    // SAFETY: a NUL-terminated path, a handle buffer of 128 bytes past its
    // head, and an `int` for the mount id.
    let r = unsafe {
        syscall(SYS_NAME_TO_HANDLE_AT, AT_FDCWD, c(p).as_ptr(), h.as_mut_ptr(), &mut mnt, 0)
    };
    assert_eq!(r, 0, "name_to_handle_at {p}: {}", errno());
    h
}

/// `open_by_handle_at` of handle `h` from directory `dir` with `flags`.
fn open_handle(dir: &str, h: &[u8; 136], flags: i32) -> i64 {
    // SAFETY: a NUL-terminated path.
    let mfd = unsafe { open(c(dir).as_ptr(), O_RDONLY | O_DIRECTORY) };
    // SAFETY: a handle as `name_to_handle_at` wrote it.
    let fd = unsafe { syscall(SYS_OPEN_BY_HANDLE_AT, mfd, h.as_ptr(), flags) };
    let e = errno();
    // SAFETY: the descriptor just opened.
    unsafe { close(mfd) };
    if fd < 0 {
        // SAFETY: musl's thread-local errno, as the call left it.
        unsafe { *__errno_location() = e };
    }
    fd
}

/// What reading the descriptor `fd` gives: its bytes, or the error.
fn read_all(fd: i64) -> String {
    let mut buf = [0u8; 64];
    // SAFETY: a buffer of 64 bytes.
    let n = unsafe { read(fd as i32, buf.as_mut_ptr(), 64) };
    if n < 0 {
        return name(errno());
    }
    String::from_utf8_lossy(&buf[..n as usize]).into_owned()
}

/// `open_by_handle_at` opens as `openat` does, in the caller's view: a
/// file read through its handle; `O_PATH` opens it for nothing but naming
/// it; a read-only mount refuses writing; a caller without
/// `CAP_DAC_OVERRIDE` is held to the file's mode; a handle forged for a
/// host file outside the root (inode `outside`) is stale; and a caller
/// without `CAP_DAC_READ_SEARCH` may open none.
fn handles_scenario(outside: u64) {
    const MS_RDONLY: u64 = 1;
    const MS_REMOUNT: u64 = 32;
    const MS_BIND: u64 = 4096;
    make("/tmp/h", 0o644);
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/h").as_ptr(), O_RDWR) };
    // SAFETY: five bytes.
    unsafe {
        write(fd, b"hello".as_ptr(), 5);
        close(fd);
        mkdir(c("/tmp/ro").as_ptr(), 0o755);
    }
    make("/tmp/ro/f", 0o644);
    make("/tmp/locked", 0o444);
    // SAFETY: NUL-terminated paths and no data.
    unsafe {
        let ro = c("/tmp/ro");
        mount(ro.as_ptr(), ro.as_ptr(), std::ptr::null(), MS_BIND, std::ptr::null());
        mount(
            std::ptr::null(),
            ro.as_ptr(),
            std::ptr::null(),
            MS_REMOUNT | MS_BIND | MS_RDONLY,
            std::ptr::null(),
        );
    }
    let h = handle_of("/tmp/h");
    println!("read: {}", read_all(open_handle("/tmp", &h, O_RDONLY)));
    println!("O_PATH read: {}", read_all(open_handle("/tmp", &h, O_PATH)));
    let f = handle_of("/tmp/ro/f");
    println!(
        "read-only mount: write {} read {}",
        res(open_handle("/tmp/ro", &f, O_RDWR)),
        res(open_handle("/tmp/ro", &f, O_RDONLY))
    );
    let mut forged = h;
    forged[16..24].copy_from_slice(&outside.to_ne_bytes());
    println!("outside the root: {}", res(open_handle("/tmp", &forged, O_RDONLY)));
    let locked = handle_of("/tmp/locked");
    in_child(|| {
        // Only `CAP_DAC_READ_SEARCH` (2) left.
        let head = [0x2008_0522u32, 0];
        let data = [4u32, 4, 0, 0, 0, 0];
        // SAFETY: a capability header and two data words.
        unsafe { syscall(SYS_CAPSET, head.as_ptr(), data.as_ptr()) };
        println!(
            "without CAP_DAC_OVERRIDE: write {} read {}",
            res(open_handle("/tmp", &locked, O_WRONLY)),
            res(open_handle("/tmp", &locked, O_RDONLY))
        );
    });
    in_child(|| {
        // SAFETY: a plain id change, which drops the capabilities.
        unsafe { setuid(1000) };
        println!("without CAP_DAC_READ_SEARCH: {}", res(open_handle("/tmp", &h, O_RDONLY)));
    });
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    match scenario.as_str() {
        "handles" => handles_scenario(std::env::args().nth(2).unwrap().parse().unwrap()),
        "devnode" => devnode_scenario(),
        "access" => access_scenario(),
        "nodump" => nodump_scenario(),
        s => panic!("unknown scenario {s}"),
    }
}
