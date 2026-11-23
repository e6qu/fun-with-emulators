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
const O_TMPFILE: i32 = 0o20040000;
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
const SYS_FILE_GETATTR: i64 = 468;
const SYS_FILE_SETATTR: i64 = 469;

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
    fn fchmod(fd: i32, m: u32) -> i32;
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
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn getpid() -> i32;
    fn usleep(us: u32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn ftruncate(fd: i32, len: i64) -> i32;
    fn getpagesize() -> i32;
    fn fallocate(fd: i32, mode: i32, off: i64, len: i64) -> i32;
    fn mmap(a: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn sleep(s: u32) -> u32;
    fn opendir(p: *const c_char) -> *mut u8;
    fn readdir(d: *mut u8) -> *const u8;
    fn telldir(d: *mut u8) -> i64;
    fn seekdir(d: *mut u8, pos: i64);
    fn unlink(p: *const c_char) -> i32;
    fn rename(a: *const c_char, b: *const c_char) -> i32;
    fn symlink(t: *const c_char, p: *const c_char) -> i32;
    fn mkfifo(p: *const c_char, m: u32) -> i32;
    fn lstat(p: *const c_char, st: *mut u8) -> i32;
    fn truncate(p: *const c_char, len: i64) -> i32;
    fn utimensat(d: i32, p: *const c_char, t: *const [i64; 4], f: i32) -> i32;
    fn getxattr(p: *const c_char, n: *const c_char, v: *mut u8, s: usize) -> isize;
    fn posix_fadvise(fd: i32, off: i64, len: i64, advice: i32) -> i32;
    fn unshare(f: i32) -> i32;
    fn socket(d: i32, t: i32, p: i32) -> i32;
    #[link_name = "bind"]
    fn bind_socket(fd: i32, a: *const u8, l: u32) -> i32;
    fn connect(fd: i32, a: *const u8, l: u32) -> i32;
    fn listen(fd: i32, n: i32) -> i32;
    fn umask(m: u32) -> u32;
    fn sendto(fd: i32, b: *const u8, n: usize, f: i32, a: *const u8, l: u32) -> isize;
    fn sendmsg(fd: i32, m: *const MsgHdr, f: i32) -> isize;
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
        18 => "EXDEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        28 => "ENOSPC",
        30 => "EROFS",
        40 => "ELOOP",
        26 => "ETXTBSY",
        61 => "ENODATA",
        98 => "EADDRINUSE",
        111 => "ECONNREFUSED",
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
    let (dir_x, file_x) = unsafe {
        (
            res(access(c("/tmp/nox").as_ptr(), X_OK).into()),
            res(access(c("/tmp/a").as_ptr(), X_OK).into()),
        )
    };
    println!("root X_OK dir: {dir_x} file: {file_x}");
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
                res(access(c("/tmp/a").as_ptr(), R_OK).into()),
                res(open(c("/tmp/a").as_ptr(), O_RDONLY).into()),
                res(access(c("/tmp/a").as_ptr(), W_OK).into()),
                res(access(c("/tmp/d/g").as_ptr(), 0).into()),
            )
        };
        println!("user R_OK: {r} open: {o}");
        println!("user W_OK: {w} beyond a closed dir: {s}");
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
    // A link's own handle opens as `O_NOFOLLOW` opens it; a descriptor of
    // another file system (`/dev/null`) holds no file the handle names.
    // SAFETY: NUL-terminated paths.
    unsafe { symlink(c("h").as_ptr(), c("/tmp/hl").as_ptr()) };
    let link = handle_of("/tmp/hl");
    // SAFETY: a NUL-terminated path; a handle as `name_to_handle_at` wrote it.
    let other = unsafe {
        let null = open(c("/dev/null").as_ptr(), O_RDONLY);
        let r = res(syscall(SYS_OPEN_BY_HANDLE_AT, null, h.as_ptr(), O_RDONLY));
        close(null);
        r
    };
    println!("link: {} other file system: {other}", res(open_handle("/tmp", &link, O_RDWR)));
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

/// Bind `from` at `to`, then, with `flags`, remount it.
fn bind(from: &str, to: &str, flags: Option<u64>) -> String {
    const MS_REMOUNT: u64 = 32;
    const MS_BIND: u64 = 4096;
    let (from, to) = (c(from), c(to));
    let none = std::ptr::null();
    // SAFETY: NUL-terminated paths and no data.
    let mut r = unsafe { mount(from.as_ptr(), to.as_ptr(), none, MS_BIND, none) };
    if let Some(f) = flags
        && r == 0
    {
        // SAFETY: as above.
        r = unsafe { mount(none, to.as_ptr(), none, MS_REMOUNT | MS_BIND | f, none) };
    }
    res(r.into())
}

/// A bind mount of a read-only mount is read-only, until a remount makes
/// it writable; a Unix socket's node cannot be made on a read-only mount;
/// a read-only `/proc/sys` takes no write to a sysctl.
fn read_only_mounts_scenario() {
    const MS_RDONLY: u64 = 1;
    const CLONE_NEWNS: i32 = 0x20000;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS) };
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/src").as_ptr(), 0o755);
        mkdir(c("/tmp/copy").as_ptr(), 0o755);
    }
    println!("ro: {}", bind("/tmp/src", "/tmp/src", Some(MS_RDONLY)));
    println!("copy: {}", bind("/tmp/src", "/tmp/copy", None));
    let create = |p: &str| {
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c(p).as_ptr(), O_CREAT | O_WRONLY, 0o644) };
        if fd >= 0 {
            // SAFETY: the descriptor just opened.
            unsafe { close(fd) };
        }
        res(fd.into())
    };
    println!("create in the copy: {}", create("/tmp/copy/f"));
    let rw = bind("/tmp/copy", "/tmp/copy", Some(0));
    println!("remount rw: {rw} create: {}", create("/tmp/copy/f"));
    // SAFETY: a plain call.
    let s = unsafe { socket(1, 1, 0) };
    let mut addr = [0u8; 110];
    addr[0] = 1;
    addr[2..2 + 13].copy_from_slice(b"/tmp/src/sock");
    // SAFETY: a socket address of its length.
    let r = unsafe { bind_socket(s, addr.as_ptr(), 110) };
    println!("socket bind: {}", res(r.into()));
    println!("ro /proc/sys: {}", bind("/proc/sys", "/proc/sys", Some(MS_RDONLY)));
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/proc/sys/fs/protected_symlinks").as_ptr(), O_WRONLY) };
    println!("sysctl write: {}", res(fd.into()));
    println!("sysctl W_OK: {}", faccessat2("/proc/sys/fs/protected_symlinks", W_OK, 0));
}

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

/// A write lock of the first ten bytes of `fd`, set (`F_SETLK`).
fn lock(fd: i32) -> i32 {
    const F_SETLK: i32 = 6;
    let fl = Flock { l_type: 1, l_whence: 0, l_start: 0, l_len: 10, l_pid: 0 };
    // SAFETY: a valid `struct flock`.
    unsafe { fcntl(fd, F_SETLK, &fl) }
}

/// Whether another process finds the first ten bytes of `p` locked.
fn locked(p: &str) -> bool {
    // SAFETY: plain fork; the child tries the lock and exits with what it
    // found.
    let pid = unsafe { fork() };
    if pid == 0 {
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c(p).as_ptr(), O_RDWR) };
        // SAFETY: ends the child.
        unsafe { _exit(i32::from(lock(fd) != 0)) };
    }
    let mut st = 0;
    // SAFETY: waits for the child just made.
    unsafe { waitpid(pid, &mut st, 0) };
    st != 0
}

/// fwe's own work on a file never drops the record locks the process
/// holds on it, as a close of a descriptor of it would: `truncate`,
/// `utimensat`, `stat`, `access`, `chmod`, `chown`, attributes, inode
/// flags by path, `fadvise` of a write-only descriptor, another open to
/// read; also for a file of another owner at a path longer than the
/// host's limit.
fn locks_scenario() {
    const POSIX_FADV_DONTNEED: i32 = 4;
    // A path past macOS's 1024 bytes.
    let mut deep = String::from("/tmp");
    for _ in 0..20 {
        deep.push_str("/directory-with-a-name-of-many-bytes-to-make-a-long-path-of");
        // SAFETY: a NUL-terminated path.
        unsafe { mkdir(c(&deep).as_ptr(), 0o755) };
    }
    for p in ["/tmp/l".to_string(), format!("{deep}/l")] {
        make(&p, 0o644);
        // SAFETY: a NUL-terminated path.
        unsafe { chown(c(&p).as_ptr(), 1000, 1000) };
        // SAFETY: as above.
        let fd = unsafe { open(c(&p).as_ptr(), O_RDWR) };
        println!("lock: {}", res(lock(fd).into()));
        let cp = c(&p);
        let st = [0u8; 128];
        let buf = [0u8; 8];
        let attr = [0u8; 24];
        let ops: [(&str, &dyn Fn() -> i64); 9] = [
            // SAFETY: (each) a NUL-terminated path, valid buffers.
            ("truncate", &|| unsafe { truncate(cp.as_ptr(), 20) }.into()),
            ("utimensat", &|| {
                unsafe { utimensat(AT_FDCWD, cp.as_ptr(), std::ptr::null(), 0) }.into()
            }),
            ("stat", &|| unsafe { stat(cp.as_ptr(), st.as_ptr().cast_mut()) }.into()),
            ("access", &|| unsafe { access(cp.as_ptr(), R_OK) }.into()),
            ("chmod", &|| unsafe { chmod(cp.as_ptr(), 0o640) }.into()),
            ("chown", &|| unsafe { chown(cp.as_ptr(), 1001, 1001) }.into()),
            ("getxattr", &|| {
                unsafe {
                    getxattr(cp.as_ptr(), c"user.x".as_ptr(), buf.as_ptr().cast_mut(), 8) as i64
                }
                .max(0)
            }),
            ("file_getattr", &|| unsafe {
                syscall(SYS_FILE_GETATTR, AT_FDCWD, cp.as_ptr(), attr.as_ptr().cast_mut(), 24, 0)
            }),
            ("open", &|| unsafe { open(cp.as_ptr(), O_RDONLY) }.into()),
        ];
        let mut out = Vec::new();
        for (name, op) in ops {
            let r = op();
            out.push(format!("{name} {} {}", res(r), if locked(&p) { "held" } else { "LOST" }));
        }
        // SAFETY: a NUL-terminated path; a descriptor kept open.
        let w = unsafe { open(cp.as_ptr(), O_WRONLY) };
        // SAFETY: plain call on the descriptor.
        let r = unsafe { posix_fadvise(w, 0, 0, POSIX_FADV_DONTNEED) };
        out.push(format!("fadvise {r} {}", if locked(&p) { "held" } else { "LOST" }));
        // The guest's own close of one of them lets the locks go, as Linux's.
        // SAFETY: a descriptor opened above.
        unsafe { close(w) };
        out.push(format!("close {}", if locked(&p) { "held" } else { "released" }));
        println!("{}", out.join(", "));
    }
}

/// Set the inode flags of `p` (`FS_IOC_SETFLAGS` through a descriptor
/// opened to read): "ok" or the error.
fn try_set_flags(p: &str, flags: u32) -> String {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c(p).as_ptr(), O_RDONLY) };
    let mut v = flags;
    // SAFETY: the flags word for the request.
    let r = unsafe { ioctl(fd, 0x4008_6602, &mut v) };
    let out = res(r.into());
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
    out
}

/// `file_setattr` of `p` with the no-dump flag: "ok" or the error.
fn try_file_setattr(dir: i32, p: &str, flags: i32) -> String {
    let mut attr = [0u8; 24];
    attr[..8].copy_from_slice(&0x80u64.to_ne_bytes());
    // SAFETY: a NUL-terminated path and a `struct file_attr`.
    res(unsafe { syscall(SYS_FILE_SETATTR, dir, c(p).as_ptr(), attr.as_ptr(), 24, flags) })
}

/// Inode flags change through a writable mount only (`EROFS` otherwise),
/// and an overlay's lower file is copied up to take them, the lower layer
/// left alone.
fn chattr_scenario() {
    const FS_NODUMP_FL: u32 = 0x40;
    const MS_RDONLY: u64 = 1;
    const CLONE_NEWNS: i32 = 0x20000;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS) };
    for d in ["/tmp/lower", "/tmp/upper", "/tmp/work", "/tmp/merged", "/tmp/ro"] {
        // SAFETY: a NUL-terminated path.
        unsafe { mkdir(c(d).as_ptr(), 0o755) };
    }
    make("/tmp/lower/f", 0o644);
    make("/tmp/lower/g", 0o644);
    make("/tmp/ro/f", 0o644);
    let data = c("lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work");
    // SAFETY: NUL-terminated strings.
    let r = unsafe {
        mount(
            c("overlay").as_ptr(),
            c("/tmp/merged").as_ptr(),
            c("overlay").as_ptr(),
            0,
            data.as_ptr(),
        )
    };
    println!("overlay: {}", res(r.into()));
    println!("ioctl: {}", try_set_flags("/tmp/merged/f", FS_NODUMP_FL));
    println!("file_setattr: {}", try_file_setattr(AT_FDCWD, "/tmp/merged/g", 0));
    println!(
        "merged: {} {} lower: {} {}",
        inode_flags("/tmp/merged/f", None),
        inode_flags("/tmp/merged/g", None),
        inode_flags("/tmp/lower/f", None),
        inode_flags("/tmp/lower/g", None)
    );
    println!("ro: {}", bind("/tmp/ro", "/tmp/ro", Some(MS_RDONLY)));
    println!("ioctl on ro: {}", try_set_flags("/tmp/ro/f", FS_NODUMP_FL));
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/ro/f").as_ptr(), O_RDONLY) };
    println!("file_setattr on ro: {}", try_file_setattr(fd, "", AT_EMPTY_PATH));
}

/// `F_GETLK` names the holder of a lock by its pid in the caller's pid
/// namespace.
fn getlk_scenario() {
    const F_GETLK: i32 = 5;
    const CLONE_NEWPID: i32 = 0x2000_0000;
    make("/tmp/k", 0o644);
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWPID) };
    in_child(|| {
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c("/tmp/k").as_ptr(), O_RDWR) };
        lock(fd);
        // SAFETY: a plain call.
        let me = unsafe { getpid() };
        in_child(|| {
            // SAFETY: a NUL-terminated path.
            let fd = unsafe { open(c("/tmp/k").as_ptr(), O_RDWR) };
            let mut fl = Flock { l_type: 1, l_whence: 0, l_start: 0, l_len: 10, l_pid: 0 };
            // SAFETY: a valid `struct flock`.
            unsafe { fcntl(fd, F_GETLK, &mut fl) };
            println!("holder {me}: type {} pid {}", fl.l_type, fl.l_pid);
        });
    });
}

/// `fchownat` and `fchmodat2` with `AT_EMPTY_PATH` on an `O_PATH`
/// descriptor of a link or a FIFO act on that link or FIFO.
fn opath_scenario() {
    const O_NOFOLLOW: i32 = 0o100000;
    const SYS_FCHOWNAT: i64 = 54;
    const SYS_FCHMODAT2: i64 = 452;
    make("/tmp/target", 0o644);
    // SAFETY: NUL-terminated paths.
    unsafe {
        symlink(c("/tmp/target").as_ptr(), c("/tmp/link").as_ptr());
        mkfifo(c("/tmp/fifo").as_ptr(), 0o644);
    }
    let empty = c("");
    for p in ["/tmp/link", "/tmp/fifo"] {
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c(p).as_ptr(), O_PATH | O_NOFOLLOW) };
        // SAFETY: an empty path with `AT_EMPTY_PATH`.
        let (own, mode) = unsafe {
            (
                res(syscall(SYS_FCHOWNAT, fd, empty.as_ptr(), 1000, 1000, AT_EMPTY_PATH)),
                res(syscall(SYS_FCHMODAT2, fd, empty.as_ptr(), 0o600, AT_EMPTY_PATH)),
            )
        };
        let mut st = [0u64; 16];
        // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
        unsafe { lstat(c(p).as_ptr(), st.as_mut_ptr().cast()) };
        let word = |i: usize| (st[i / 2] >> (32 * (i % 2))) as u32;
        println!(
            "{p}: chown {} chmod {} -> {}:{} {:o}",
            own,
            mode,
            word(6),
            word(7),
            word(4) & 0o7777
        );
    }
    let (uid, _, _) = stat_of("/tmp/target");
    println!("target: {uid}");
}

/// A Unix socket address of path `p`.
fn unix_addr(p: &str) -> [u8; 110] {
    let mut addr = [0u8; 110];
    addr[0] = 1;
    addr[2..2 + p.len()].copy_from_slice(p.as_bytes());
    addr
}

/// musl's `struct msghdr` on a 64-bit target (each 32-bit length padded).
#[repr(C)]
struct MsgHdr {
    name: *const u8,
    namelen: usize,
    iov: *const [usize; 2],
    iovlen: usize,
    control: *const u8,
    controllen: usize,
    flags: i32,
}

/// A memfd sent to a process of the host's (the test, at socket `path`),
/// as a program hands an X server the memory it draws in: the host maps
/// what the guest wrote, and says what it read there.
fn host_peer_scenario(path: &str) {
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    const SYS_MEMFD_CREATE: i64 = 279;
    // SAFETY: plain calls on this program's own descriptors and buffers.
    unsafe {
        let s = socket(AF_UNIX, SOCK_STREAM, 0);
        let addr = unix_addr(path);
        assert_eq!(connect(s, addr.as_ptr(), 110), 0, "connect: {}", errno());
        let m = syscall(SYS_MEMFD_CREATE, c("drawn").as_ptr(), 0) as i32;
        let text = b"drawn by the guest";
        write(m, text.as_ptr(), text.len());
        // One byte, with the memfd: a control message of one descriptor
        // (`SOL_SOCKET`, `SCM_RIGHTS`).
        let byte = [b'x'];
        let iov = [byte.as_ptr() as usize, 1];
        let mut ctl = [0u8; 24];
        ctl[0..8].copy_from_slice(&20u64.to_ne_bytes());
        ctl[8..12].copy_from_slice(&1i32.to_ne_bytes());
        ctl[12..16].copy_from_slice(&1i32.to_ne_bytes());
        ctl[16..20].copy_from_slice(&m.to_ne_bytes());
        let msg = MsgHdr {
            name: std::ptr::null(),
            namelen: 0,
            iov: &iov,
            iovlen: 1,
            control: ctl.as_ptr(),
            controllen: ctl.len(),
            flags: 0,
        };
        println!("sent: {}", res(sendmsg(s, &msg, 0) as i64));
        let mut buf = [0u8; 64];
        let n = read(s, buf.as_mut_ptr(), buf.len());
        println!("the host read: {}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
    }
}

/// Connecting or sending to a Unix socket's node needs write permission
/// on it, by the caller's ids against its owner and mode, as `open`
/// checks; making one needs write permission on its directory.
fn unix_permissions_scenario() {
    const SOCK_STREAM: i32 = 1;
    const SOCK_DGRAM: i32 = 2;
    // SAFETY: plain calls; socket addresses of their length.
    let (s, d) = unsafe {
        umask(0o022);
        let s = socket(1, SOCK_STREAM, 0);
        bind_socket(s, unix_addr("/tmp/s").as_ptr(), 110);
        listen(s, 4);
        let d = socket(1, SOCK_DGRAM, 0);
        bind_socket(d, unix_addr("/tmp/d").as_ptr(), 110);
        mkdir(c("/tmp/closed").as_ptr(), 0o755);
        (s, d)
    };
    let try_all = || {
        in_child(|| {
            // SAFETY: plain id changes.
            unsafe {
                setgroups(0, std::ptr::null());
                setgid(1000);
                setuid(1000);
            }
            // SAFETY: plain calls; socket addresses of their length.
            let (conn, sent, made) = unsafe {
                let c = socket(1, SOCK_STREAM, 0);
                let conn = res(connect(c, unix_addr("/tmp/s").as_ptr(), 110).into());
                let u = socket(1, SOCK_DGRAM, 0);
                let sent = sendto(u, b"x".as_ptr(), 1, 0, unix_addr("/tmp/d").as_ptr(), 110);
                let sent = res(sent as i64);
                let b = socket(1, SOCK_DGRAM, 0);
                let made = res(bind_socket(b, unix_addr("/tmp/closed/b").as_ptr(), 110).into());
                (conn, sent, made)
            };
            println!("connect {conn} sendto {sent} bind {made}");
        });
    };
    try_all();
    // SAFETY: NUL-terminated paths.
    unsafe {
        chmod(c("/tmp/s").as_ptr(), 0o777);
        chmod(c("/tmp/d").as_ptr(), 0o777);
        chmod(c("/tmp/closed").as_ptr(), 0o777);
    }
    try_all();
    let _ = (s, d);
}

/// A socket is its maker's, every bit allowed: its maker may `fchmod` it,
/// as conmon does before binding its attach socket, and the node bound
/// for it takes that mode, less the umask.
fn socket_mode_scenario() {
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/open").as_ptr(), 0o777);
        chmod(c("/tmp/open").as_ptr(), 0o777);
    }
    in_child(|| {
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(1000);
            setuid(1000);
        }
        let fstat_of = |fd: i32| {
            let mut st = [0u64; 16];
            // SAFETY: a buffer as big as a `struct stat`.
            assert_eq!(unsafe { fstat(fd, st.as_mut_ptr().cast()) }, 0);
            let word = |i: usize| (st[i / 2] >> (32 * (i % 2))) as u32;
            format!("{:o} {}", word(4) & 0o7777, word(6))
        };
        // SAFETY: plain calls; a socket address of its length.
        unsafe {
            umask(0o022);
            let s = socket(1, 1, 0);
            let fresh = fstat_of(s);
            let changed = res(fchmod(s, 0o700).into());
            let after = fstat_of(s);
            let bound = res(bind_socket(s, unix_addr("/tmp/open/sm").as_ptr(), 110).into());
            if bound != "ok" {
                println!("made {fresh} fchmod {changed} now {after} bind {bound}");
                return;
            }
            let (uid, _, mode) = stat_of("/tmp/open/sm");
            println!(
                "made {fresh} fchmod {changed} now {after} bind {bound} node {:o} {uid}",
                mode & 0o7777
            );
        }
    });
}

/// In an overlay's sticky directory, as in any, a user may remove or
/// rename only its own files (or the directory's owner, or root).
fn overlay_sticky_scenario() {
    const CLONE_NEWNS: i32 = 0x20000;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS) };
    for d in ["/tmp/lower", "/tmp/lower/t", "/tmp/upper", "/tmp/work", "/tmp/m"] {
        // SAFETY: a NUL-terminated path.
        unsafe { mkdir(c(d).as_ptr(), 0o755) };
    }
    make("/tmp/lower/t/root", 0o666);
    make("/tmp/lower/t/user", 0o666);
    // SAFETY: NUL-terminated paths.
    unsafe {
        chmod(c("/tmp/lower/t").as_ptr(), 0o1777);
        chown(c("/tmp/lower/t/user").as_ptr(), 1000, 1000);
    }
    let data = c("lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work");
    // SAFETY: NUL-terminated strings.
    let r = unsafe {
        mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, data.as_ptr())
    };
    println!("overlay: {}", res(r.into()));
    in_child(|| {
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(1000);
            setuid(1000);
        }
        // SAFETY: NUL-terminated paths.
        let (unlinked, renamed, own) = unsafe {
            (
                res(unlink(c("/tmp/m/t/root").as_ptr()).into()),
                res(rename(c("/tmp/m/t/root").as_ptr(), c("/tmp/m/t/mine").as_ptr()).into()),
                res(unlink(c("/tmp/m/t/user").as_ptr()).into()),
            )
        };
        println!("unlink another's: {unlinked} rename it: {renamed} unlink own: {own}");
    });
}

/// A trailing slash names a directory in every path call.
fn trailing_slash_scenario() {
    make("/tmp/f", 0o644);
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/d").as_ptr(), 0o755);
        symlink(c("/tmp/d").as_ptr(), c("/tmp/l").as_ptr());
    }
    let mut st = [0u64; 16];
    // SAFETY: (each) NUL-terminated paths and a buffer as big as a `struct
    // stat`.
    let out = unsafe {
        [
            ("stat file/", res(stat(c("/tmp/f/").as_ptr(), st.as_mut_ptr().cast()).into())),
            ("lstat link/", res(lstat(c("/tmp/l/").as_ptr(), st.as_mut_ptr().cast()).into())),
            ("chmod file/", res(chmod(c("/tmp/f/").as_ptr(), 0o600).into())),
            ("unlink file/", res(unlink(c("/tmp/f/").as_ptr()).into())),
            ("rename file/", res(rename(c("/tmp/f/").as_ptr(), c("/tmp/g").as_ptr()).into())),
            ("mkfifo new/", res(mkfifo(c("/tmp/new/").as_ptr(), 0o644).into())),
            ("mkdir new/", res(mkdir(c("/tmp/new/").as_ptr(), 0o755).into())),
        ]
    };
    for (what, r) in out {
        println!("{what}: {r}");
    }
    let word = |i: usize| (st[i / 2] >> (32 * (i % 2))) as u32;
    println!("link/ is a directory: {}", word(4) & 0o170000 == 0o40000);
}

/// `telldir` and `seekdir` (the C library's, from `d_off`) return to the
/// same place in a directory's listing.
fn telldir_scenario() {
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/dd").as_ptr(), 0o755) };
    for i in 0..40 {
        make(&format!("/tmp/dd/file-with-a-longer-name-{i:02}"), 0o644);
    }
    // SAFETY: a NUL-terminated path; the stream is the C library's.
    let d = unsafe { opendir(c("/tmp/dd").as_ptr()) };
    let next = || {
        // SAFETY: the stream above; an entry's name at its offset 19.
        unsafe {
            let e = readdir(d);
            std::ffi::CStr::from_ptr(e.add(19).cast()).to_string_lossy().into_owned()
        }
    };
    for _ in 0..25 {
        next();
    }
    // SAFETY: the stream above.
    let pos = unsafe { telldir(d) };
    let after = next();
    next();
    // SAFETY: the stream above, a position it gave.
    unsafe { seekdir(d, pos) };
    println!("back to the same entry: {}", next() == after);
}

/// The access and change times of `p`, in seconds.
fn times_of(p: &str) -> (i64, i64) {
    let mut st = [0i64; 16];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
    unsafe { stat(c(p).as_ptr(), st.as_mut_ptr().cast()) };
    // arm64's `struct stat`: st_atime at byte 72, st_ctime at 104.
    (st[9], st[13])
}

/// A read through a `strictatime` mount sets the access time and leaves
/// the change time, as a read does on Linux.
fn atime_scenario() {
    const MS_STRICTATIME: u64 = 1 << 24;
    const CLONE_NEWNS: i32 = 0x20000;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS) };
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/s").as_ptr(), 0o755) };
    make("/tmp/s/f", 0o644);
    let old = [1_000_000i64, 0, 1_000_000, 0];
    // SAFETY: a NUL-terminated path and two timespecs.
    unsafe { utimensat(AT_FDCWD, c("/tmp/s/f").as_ptr(), &old, 0) };
    println!("strictatime: {}", bind("/tmp/s", "/tmp/s", Some(MS_STRICTATIME)));
    let (_, ctime) = times_of("/tmp/s/f");
    // SAFETY: plain calls; a buffer of one byte.
    unsafe {
        sleep(2);
        let fd = open(c("/tmp/s/f").as_ptr(), O_RDONLY);
        let mut b = [0u8; 1];
        read(fd, b.as_mut_ptr(), 1);
        close(fd);
    }
    let (atime, after) = times_of("/tmp/s/f");
    println!("access time set: {} change time kept: {}", atime > 1_000_000, after == ctime);
}

/// A set-ID file changed by a user without `CAP_FSETID` loses its set-ID
/// bits whatever the change: a write through a duplicate of the
/// descriptor, `ftruncate`, `truncate`, `fallocate`, `copy_file_range` into
/// it, a shared writable mapping of it.
fn setid_scenario() {
    const SYS_COPY_FILE_RANGE: i64 = 285;
    let names = ["dup", "ftruncate", "truncate", "fallocate", "copy_file_range", "mmap"];
    for n in names {
        let p = format!("/tmp/{n}");
        make(&p, 0o644);
        // SAFETY: a NUL-terminated path.
        unsafe {
            chown(c(&p).as_ptr(), 1000, 1000);
            chmod(c(&p).as_ptr(), 0o6775);
        }
    }
    make("/tmp/src", 0o644);
    // SAFETY: a NUL-terminated path; a byte written to the descriptor.
    unsafe {
        let fd = open(c("/tmp/src").as_ptr(), O_WRONLY);
        write(fd, b"x".as_ptr(), 1);
        close(fd);
    }
    in_child(|| {
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(1000);
            setuid(1000);
        }
        for n in names {
            let p = format!("/tmp/{n}");
            // SAFETY: plain calls on a NUL-terminated path and descriptors
            // of it, valid buffers.
            unsafe {
                let fd = open(c(&p).as_ptr(), O_RDWR);
                match n {
                    "dup" => {
                        let d = dup(fd);
                        write(d, b"x".as_ptr(), 1);
                    }
                    "ftruncate" => {
                        ftruncate(fd, 100);
                    }
                    "truncate" => {
                        truncate(c(&p).as_ptr(), 100);
                    }
                    "fallocate" => {
                        fallocate(fd, 0, 0, 100);
                    }
                    "copy_file_range" => {
                        let src = open(c("/tmp/src").as_ptr(), O_RDONLY);
                        let mut off = 0i64;
                        syscall(
                            SYS_COPY_FILE_RANGE,
                            src,
                            &mut off,
                            fd,
                            std::ptr::null::<i64>(),
                            1,
                            0,
                        );
                    }
                    _ => {
                        ftruncate(fd, 4096);
                        mmap(std::ptr::null_mut(), 4096, 3, 1, fd, 0);
                    }
                }
            }
            println!("{n}: {:o}", stat_of(&p).2 & 0o7777);
        }
    });
}

/// The link count of the file open as `fd`.
fn nlink_of(fd: i32) -> u32 {
    let mut st = [0u64; 16];
    // SAFETY: a buffer as big as a `struct stat`.
    unsafe { fstat(fd, st.as_mut_ptr().cast()) };
    (st[2] >> 32) as u32
}

/// An `O_TMPFILE` file has no link until one is given it, through any
/// duplicate of its descriptor; a fork child's close leaves it to its
/// maker; one the process still holds as it ends leaves nothing behind.
fn tmpfile_scenario() {
    const SYS_LINKAT: i64 = 37;
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/t").as_ptr(), 0o755);
        mkdir(c("/tmp/left").as_ptr(), 0o755);
    }
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/t").as_ptr(), O_TMPFILE | O_RDWR, 0o600) };
    println!("links: {}", nlink_of(fd));
    // SAFETY: plain calls on the descriptor.
    let d = unsafe {
        let d = dup(fd);
        close(fd);
        d
    };
    in_child(|| {
        // SAFETY: the child's copy of the descriptor.
        unsafe { close(d) };
    });
    let empty = c("");
    // SAFETY: NUL-terminated paths.
    let r = unsafe {
        syscall(SYS_LINKAT, d, empty.as_ptr(), AT_FDCWD, c("/tmp/t/named").as_ptr(), AT_EMPTY_PATH)
    };
    println!("linked through a duplicate: {} links: {}", res(r), nlink_of(d));
    in_child(|| {
        // SAFETY: a NUL-terminated path; left open as the child ends.
        unsafe { open(c("/tmp/left").as_ptr(), O_TMPFILE | O_RDWR, 0o600) };
    });
}

/// A tmpfs's size holds for `copy_file_range`, `pwritev` and `splice`
/// into it as for `write`, and a remount gives it a new one.
fn tmpfs_size_scenario() {
    const SYS_COPY_FILE_RANGE: i64 = 285;
    const SYS_PWRITEV: i64 = 70;
    const SYS_SPLICE: i64 = 76;
    const CLONE_NEWNS: i32 = 0x20000;
    const MS_REMOUNT: u64 = 32;
    // SAFETY: plain calls; NUL-terminated strings.
    unsafe {
        unshare(CLONE_NEWNS);
        mkdir(c("/tmp/m").as_ptr(), 0o755);
        let t = c("tmpfs");
        mount(t.as_ptr(), c("/tmp/m").as_ptr(), t.as_ptr(), 0, c("size=32k").as_ptr());
    }
    let big = vec![7u8; 100_000];
    make("/tmp/src", 0o644);
    // SAFETY: NUL-terminated paths, buffers of their lengths.
    let (copied, written, spliced) = unsafe {
        let src = open(c("/tmp/src").as_ptr(), O_RDWR);
        write(src, big.as_ptr(), big.len());
        let a = open(c("/tmp/m/a").as_ptr(), O_CREAT | O_RDWR, 0o644);
        let mut off = 0i64;
        let copied =
            syscall(SYS_COPY_FILE_RANGE, src, &mut off, a, std::ptr::null::<i64>(), 100_000, 0);
        let b = open(c("/tmp/m/b").as_ptr(), O_CREAT | O_RDWR, 0o644);
        let iov = [big.as_ptr() as usize, 65_536];
        let written = res(syscall(SYS_PWRITEV, b, iov.as_ptr(), 1, 0));
        let mut p = [0i32; 2];
        pipe(p.as_mut_ptr());
        write(p[1], big.as_ptr(), 60_000);
        let s = open(c("/tmp/m/s").as_ptr(), O_CREAT | O_RDWR, 0o644);
        let spliced = res(syscall(
            SYS_SPLICE,
            p[0],
            std::ptr::null::<i64>(),
            s,
            std::ptr::null::<i64>(),
            60_000,
            0,
        ));
        (copied, written, spliced)
    };
    println!("copy_file_range cut short: {}", (0..100_000).contains(&copied));
    println!("pwritev past the size: {written} splice: {spliced}");
    // SAFETY: NUL-terminated strings.
    let r = unsafe {
        mount(
            std::ptr::null(),
            c("/tmp/m").as_ptr(),
            std::ptr::null(),
            MS_REMOUNT,
            c("size=1m").as_ptr(),
        )
    };
    // SAFETY: a NUL-terminated path, a buffer of its length.
    let n = unsafe {
        let d = open(c("/tmp/m/d").as_ptr(), O_CREAT | O_RDWR, 0o644);
        write(d, big.as_ptr(), 65_536)
    };
    println!("remount: {} then a write of 64k: {n}", res(r.into()));
}

/// `/proc/self/mountinfo` gives the root filesystem the device numbers
/// `stat` reports for its files.
fn mountinfo_scenario() {
    let mut st = [0u64; 16];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
    unsafe { stat(c("/tmp").as_ptr(), st.as_mut_ptr().cast()) };
    let dev = st[0];
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let root = info.lines().find(|l| l.split(' ').nth(4) == Some("/")).unwrap();
    let numbers = root.split(' ').nth(2).unwrap();
    println!("root's numbers match stat: {}", numbers == format!("{major}:{minor}"));
}

/// Open FIFO `name` from `dir` (`AT_FDCWD` for a path) to read on a thread
/// of its own, while this thread opens `path` to write: neither open holds
/// the other up.
fn meet_at_fifo(dir: i32, name: &'static str, path: &str) -> String {
    let reader = std::thread::spawn(move || {
        // SAFETY: a NUL-terminated path; waits for a writer.
        let fd = unsafe { openat(dir, c(name).as_ptr(), O_RDONLY) };
        let mut b = [0u8; 2];
        // SAFETY: a buffer of two bytes.
        let n = unsafe { read(fd, b.as_mut_ptr(), 2) };
        String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
    });
    // The reader waiting, a call of this thread's that takes fwe's lock
    // goes on (were the lock held, it would wait for a writer that never
    // came).
    // SAFETY: plain calls; a NUL-terminated path.
    unsafe {
        usleep(200_000);
        mkdir(c(&format!("{path}.made")).as_ptr(), 0o755);
    }
    // SAFETY: a NUL-terminated path; waits for the reader.
    let w = unsafe { open(c(path).as_ptr(), O_WRONLY) };
    // SAFETY: two bytes.
    unsafe {
        write(w, b"ok".as_ptr(), 2);
        close(w);
    }
    reader.join().unwrap()
}

/// FIFO opens that wait for the other end hold up no other thread of the
/// process: a FIFO another user owns, one opened from a directory
/// descriptor, one in an overlay.
fn fifo_scenario() {
    const CLONE_NEWNS: i32 = 0x20000;
    // SAFETY: plain calls; NUL-terminated strings.
    unsafe {
        unshare(CLONE_NEWNS);
        for d in ["/tmp/lower", "/tmp/upper", "/tmp/work", "/tmp/m"] {
            mkdir(c(d).as_ptr(), 0o755);
        }
        mkfifo(c("/tmp/owned").as_ptr(), 0o666);
        chown(c("/tmp/owned").as_ptr(), 1000, 1000);
        mkfifo(c("/tmp/plain").as_ptr(), 0o666);
        mkfifo(c("/tmp/lower/f").as_ptr(), 0o666);
        let data = c("lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work");
        mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, data.as_ptr());
    }
    println!("another's: {}", meet_at_fifo(AT_FDCWD, "/tmp/owned", "/tmp/owned"));
    // SAFETY: a NUL-terminated path.
    let tmp = unsafe { open(c("/tmp").as_ptr(), O_RDONLY | O_DIRECTORY) };
    println!("from a directory: {}", meet_at_fifo(tmp, "plain", "/tmp/plain"));
    println!("in an overlay: {}", meet_at_fifo(AT_FDCWD, "/tmp/m/f", "/tmp/m/f"));
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    match scenario.as_str() {
        "fifo" => fifo_scenario(),
        "mountinfo" => mountinfo_scenario(),
        "tmpfs" => tmpfs_size_scenario(),
        "tmpfile" => tmpfile_scenario(),
        "setid" => setid_scenario(),
        "atime" => atime_scenario(),
        "telldir" => telldir_scenario(),
        "slash" => trailing_slash_scenario(),
        "ovlsticky" => overlay_sticky_scenario(),
        "unixperm" => unix_permissions_scenario(),
        "sockmode" => socket_mode_scenario(),
        "opath" => opath_scenario(),
        "getlk" => getlk_scenario(),
        "chattr" => chattr_scenario(),
        "locks" => locks_scenario(),
        "romounts" => read_only_mounts_scenario(),
        "handles" => handles_scenario(std::env::args().nth(2).unwrap().parse().unwrap()),
        "devnode" => devnode_scenario(),
        "access" => access_scenario(),
        "nodump" => nodump_scenario(),
        "linkrules" => link_rules_scenario(),
        "stickyxattr" => sticky_xattr_scenario(),
        "noatimeflag" => noatime_flag_scenario(),
        "tmpfsopts" => tmpfs_options_scenario(),
        "procopts" => proc_options_scenario(),
        "store" => store_scenario(),
        "host-peer" => host_peer_scenario(&std::env::args().nth(2).unwrap()),
        // A program run from a tmpfs ([`store_scenario`]): its exit code.
        "exit" => std::process::exit(7),
        s => panic!("unknown scenario {s}"),
    }
}

unsafe extern "C" {
    fn setxattr(p: *const c_char, n: *const c_char, v: *const u8, s: usize, f: i32) -> i32;
    fn linkat(od: i32, op: *const c_char, nd: i32, np: *const c_char, f: i32) -> i32;
    fn statfs(p: *const c_char, buf: *mut u8) -> i32;
}

const SYS_OPENAT2: i64 = 437;
const CLONE_NEWNS_FLAG: i32 = 0x20000;

/// Write `v` to the sysctl at `p`.
fn sysctl(p: &str, v: &str) {
    // SAFETY: a NUL-terminated path; a buffer of `v`'s length.
    unsafe {
        let fd = open(c(p).as_ptr(), O_WRONLY);
        assert!(fd >= 0, "{p}: {}", errno());
        write(fd, v.as_ptr(), v.len());
        close(fd);
    }
}

/// Run `f` in a child of user and group `id`, no supplementary groups.
fn as_user(id: u32, f: impl FnOnce()) {
    in_child(|| {
        // SAFETY: plain id changes.
        unsafe {
            setgroups(0, std::ptr::null());
            setgid(id);
            setuid(id);
        }
        f();
    });
}

/// `open(p, flags)`, closed again: "ok" or the error.
fn try_open(p: &str, flags: i32) -> String {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c(p).as_ptr(), flags) };
    let out = res(fd.into());
    if fd >= 0 {
        // SAFETY: the descriptor just opened.
        unsafe { close(fd) };
    }
    out
}

/// `openat2(AT_FDCWD, p, {flags, 0, resolve})`, closed again.
fn try_openat2(p: &str, flags: u64, resolve: u64) -> String {
    let how = [flags, 0, resolve];
    // SAFETY: a NUL-terminated path and a `struct open_how`.
    let fd = unsafe { syscall(SYS_OPENAT2, AT_FDCWD, c(p).as_ptr(), how.as_ptr(), 24) };
    let out = res(fd);
    if fd >= 0 {
        // SAFETY: the descriptor just opened.
        unsafe { close(fd as i32) };
    }
    out
}

/// Mount a new `kind` filesystem at `at` with `flags` and options `data`.
fn mount_new(kind: &str, at: &str, flags: u64, data: &str) -> String {
    // SAFETY: NUL-terminated strings.
    res(unsafe {
        mount(c(kind).as_ptr(), c(at).as_ptr(), c(kind).as_ptr(), flags, c(data).as_ptr())
    }
    .into())
}

/// `fs.protected_symlinks` refuses a trailing link in a sticky directory
/// anyone may write to, to one who neither owns it nor the directory, and
/// passes a link the path goes through, to `open` and `openat2` alike; a
/// `nosymfollow` mount's links are followed by neither; `linkat` of a
/// descriptor's file (`AT_EMPTY_PATH`) stays within its mount and is held
/// to `fs.protected_hardlinks`, as a path's is.
fn link_rules_scenario() {
    const RESOLVE_NO_MAGICLINKS: u64 = 2;
    const MS_NOSYMFOLLOW: u64 = 256;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS_FLAG) };
    sysctl("/proc/sys/fs/protected_symlinks", "1");
    sysctl("/proc/sys/fs/protected_hardlinks", "1");
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/s").as_ptr(), 0o777);
        chmod(c("/tmp/s").as_ptr(), 0o1777);
        mkdir(c("/tmp/d").as_ptr(), 0o755);
    }
    make("/tmp/d/f", 0o644);
    make("/tmp/t", 0o644);
    as_user(1000, || {
        // SAFETY: NUL-terminated paths.
        unsafe {
            symlink(c("/tmp/t").as_ptr(), c("/tmp/s/l").as_ptr());
            symlink(c("/tmp/d").as_ptr(), c("/tmp/s/dl").as_ptr());
        }
    });
    as_user(2000, || {
        println!(
            "trailing: open {} openat2 {}",
            try_open("/tmp/s/l", O_RDONLY),
            try_openat2("/tmp/s/l", 0, RESOLVE_NO_MAGICLINKS)
        );
        println!(
            "passed through: open {} openat2 {}",
            try_open("/tmp/s/dl/f", O_RDONLY),
            try_openat2("/tmp/s/dl/f", 0, RESOLVE_NO_MAGICLINKS)
        );
    });
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/nf").as_ptr(), 0o755) };
    println!("nosymfollow: {}", mount_new("tmpfs", "/tmp/nf", MS_NOSYMFOLLOW, ""));
    // SAFETY: NUL-terminated paths.
    unsafe { symlink(c("/tmp/t").as_ptr(), c("/tmp/nf/l").as_ptr()) };
    println!(
        "followed there: open {} openat2 {}, the link itself: {}",
        try_open("/tmp/nf/l", O_RDONLY),
        try_openat2("/tmp/nf/l", 0, RESOLVE_NO_MAGICLINKS),
        try_openat2("/tmp/nf/l", (O_PATH | 0o100000) as u64, RESOLVE_NO_MAGICLINKS)
    );
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/other").as_ptr(), 0o755) };
    println!("other: {}", mount_new("tmpfs", "/tmp/other", 0, ""));
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/t").as_ptr(), O_RDONLY) };
    let link_fd = |fd: i32, to: &str| {
        // SAFETY: an empty path and a NUL-terminated one.
        res(unsafe { linkat(fd, c("").as_ptr(), AT_FDCWD, c(to).as_ptr(), AT_EMPTY_PATH) }.into())
    };
    println!(
        "AT_EMPTY_PATH: across mounts {} within {}",
        link_fd(fd, "/tmp/other/x"),
        link_fd(fd, "/tmp/x")
    );
    make("/tmp/theirs", 0o600);
    // SAFETY: a NUL-terminated path.
    unsafe { chown(c("/tmp/theirs").as_ptr(), 1000, 1000) };
    in_child(|| {
        // Only `CAP_DAC_READ_SEARCH` (2) left: it may read the file, and
        // name it by its descriptor, but neither owns it nor may write it.
        let head = [0x2008_0522u32, 0];
        let data = [4u32, 4, 0, 0, 0, 0];
        // SAFETY: a capability header and two data words.
        unsafe { syscall(SYS_CAPSET, head.as_ptr(), data.as_ptr()) };
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { open(c("/tmp/theirs").as_ptr(), O_RDONLY) };
        // SAFETY: NUL-terminated paths.
        let by_path = unsafe {
            linkat(AT_FDCWD, c("/tmp/theirs").as_ptr(), AT_FDCWD, c("/tmp/y").as_ptr(), 0)
        };
        println!(
            "protected_hardlinks: by descriptor {} by path {}",
            link_fd(fd, "/tmp/z"),
            res(by_path.into())
        );
    });
}

/// A sticky directory's `user.` attributes are its owner's to change
/// (`EPERM` to another, whatever its mode allows), and root's.
fn sticky_xattr_scenario() {
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/st").as_ptr(), 0o777);
        chmod(c("/tmp/st").as_ptr(), 0o1777);
        mkdir(c("/tmp/mine").as_ptr(), 0o777);
        chmod(c("/tmp/mine").as_ptr(), 0o1777);
        chown(c("/tmp/mine").as_ptr(), 1000, 1000);
        mkdir(c("/tmp/plain").as_ptr(), 0o777);
        chmod(c("/tmp/plain").as_ptr(), 0o777);
    }
    let set = |p: &str| {
        // SAFETY: NUL-terminated strings and a value of one byte.
        res(unsafe { setxattr(c(p).as_ptr(), c("user.x").as_ptr(), b"1".as_ptr(), 1, 0) }.into())
    };
    as_user(1000, || {
        let mut v = [0u8; 4];
        // SAFETY: NUL-terminated strings and a buffer of 4 bytes.
        let got =
            res(
                unsafe { getxattr(c("/tmp/st").as_ptr(), c("user.y").as_ptr(), v.as_mut_ptr(), 4) }
                    as i64,
            );
        println!(
            "another's sticky: set {} get {}; own sticky: {}; not sticky: {}",
            set("/tmp/st"),
            got,
            set("/tmp/mine"),
            set("/tmp/plain")
        );
    });
    println!("root: {}", set("/tmp/st"));
}

/// The no-access-time flag (`chattr +A`) is kept: read back through both
/// requests, and a read of the file leaves its access time where a read
/// of another sets it.
fn noatime_flag_scenario() {
    const MS_STRICTATIME: u64 = 1 << 24;
    const FS_NOATIME_FL: u32 = 0x80;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS_FLAG) };
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/s").as_ptr(), 0o755) };
    make("/tmp/s/a", 0o644);
    make("/tmp/s/b", 0o644);
    println!("strictatime: {}", bind("/tmp/s", "/tmp/s", Some(MS_STRICTATIME)));
    let old = [1_000_000i64, 0, 1_000_000, 0];
    // SAFETY: NUL-terminated paths and two timespecs.
    unsafe {
        utimensat(AT_FDCWD, c("/tmp/s/a").as_ptr(), &old, 0);
        utimensat(AT_FDCWD, c("/tmp/s/b").as_ptr(), &old, 0);
    }
    inode_flags("/tmp/s/a", Some(FS_NOATIME_FL));
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/s/a").as_ptr(), O_RDONLY) };
    let mut fsx = [0u8; 28];
    // SAFETY: a `struct fsxattr`.
    let r = unsafe { ioctl(fd, 0x801c_581f, fsx.as_mut_ptr()) };
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
    println!(
        "flags: {:#x} xflags: {} {:#x}",
        inode_flags("/tmp/s/a", None),
        res(r.into()),
        u32::from_ne_bytes(fsx[..4].try_into().unwrap())
    );
    for p in ["/tmp/s/a", "/tmp/s/b"] {
        // SAFETY: plain calls; a buffer of one byte.
        unsafe {
            let fd = open(c(p).as_ptr(), O_RDONLY);
            let mut b = [0u8; 1];
            read(fd, b.as_mut_ptr(), 1);
            close(fd);
        }
    }
    println!(
        "flagged kept: {} other set: {}",
        times_of("/tmp/s/a").0 == 1_000_000,
        times_of("/tmp/s/b").0 > 1_000_000
    );
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/s/a").as_ptr(), O_RDONLY) };
    let clear = [0u8; 28];
    // SAFETY: a `struct fsxattr`.
    let r = unsafe { ioctl(fd, 0x401c_5820, clear.as_ptr()) };
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
    println!("cleared: {} flags: {:#x}", res(r.into()), inode_flags("/tmp/s/a", None));
}

/// A tmpfs's `uid=`, `gid=` and `mode=` make its root's owner and mode,
/// and `nr_inodes=` holds its root and the names in it (`ENOSPC` past it,
/// which `statfs` counts); a value Linux refuses is `EINVAL`.
fn tmpfs_options_scenario() {
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS_FLAG) };
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/m").as_ptr(), 0o755) };
    println!(
        "mount: {}",
        mount_new("tmpfs", "/tmp/m", 0, "nr_inodes=3,uid=1000,gid=100,mode=0750")
    );
    let mut st = [0u32; 32];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
    unsafe { stat(c("/tmp/m").as_ptr(), st.as_mut_ptr().cast()) };
    // arm64's `struct stat`: st_mode at word 4, st_uid 6, st_gid 7.
    println!("root: {:o} {}:{}", st[4] & 0o7777, st[6], st[7]);
    // SAFETY: NUL-terminated paths.
    let (a, b) = unsafe {
        let a = open(c("/tmp/m/a").as_ptr(), O_CREAT | O_RDWR, 0o644);
        (a, mkdir(c("/tmp/m/b").as_ptr(), 0o755))
    };
    // SAFETY: NUL-terminated paths.
    let full = unsafe { mkdir(c("/tmp/m/c").as_ptr(), 0o755) };
    println!(
        "file: {} dir: {} past the inodes: {}",
        res(a.into()),
        res(b.into()),
        res(full.into())
    );
    let mut fs = [0u64; 15];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct statfs`.
    unsafe { statfs(c("/tmp/m").as_ptr(), fs.as_mut_ptr().cast()) };
    println!("statfs: files {} free {}", fs[5], fs[6]);
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(c("/tmp/n").as_ptr(), 0o755) };
    println!(
        "bad size: {} bad uid: {}",
        mount_new("tmpfs", "/tmp/n", 0, "size=lots"),
        mount_new("tmpfs", "/tmp/n", 0, "uid=-1")
    );
}

unsafe extern "C" {
    fn execv(p: *const c_char, argv: *const *const c_char) -> i32;
    fn getpeername(fd: i32, a: *mut u8, l: *mut u32) -> i32;
    fn readlink(p: *const c_char, b: *mut u8, n: usize) -> isize;
    fn accept(fd: i32, a: *mut u8, l: *mut u32) -> i32;
}

/// arm64's `struct stat` of `p` (not following a link), as words.
fn stat_words(p: &str) -> [u64; 16] {
    let mut st = [0u64; 16];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
    unsafe { lstat(c(p).as_ptr(), st.as_mut_ptr().cast()) };
    st
}

/// What `/proc/self/fd/<fd>` reads.
fn fd_link(fd: i32) -> String {
    let mut b = [0u8; 256];
    // SAFETY: a NUL-terminated path; a buffer of its length.
    let n = unsafe { readlink(c(&format!("/proc/self/fd/{fd}")).as_ptr(), b.as_mut_ptr(), 256) };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

/// A tmpfs (a filesystem of fwe's store, in memory) does what a Linux
/// tmpfs does by path: a socket bound there is connected to and named; a
/// FIFO made there passes data between processes and its descriptor shows
/// the file; a program copied there runs (not while open to write); a
/// file's handle opens it until it is gone; `/proc/self/fd` follows a
/// file renamed and removed; a directory lists in the order its names
/// were made; mode, size, times, attributes and the filesystem's type by
/// path.
fn store_scenario() {
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    // SAFETY: a plain call; NUL-terminated paths.
    unsafe {
        unshare(CLONE_NEWNS_FLAG);
        mkdir(c("/tmp/s").as_ptr(), 0o755);
    }
    println!("mount: {}", mount_new("tmpfs", "/tmp/s", 0, "size=64m"));

    // A socket.
    let (addr, len) = (unix_addr("/tmp/s/sock"), 110);
    // SAFETY: plain socket calls on an address of its length.
    let (bound, again, connected, peer) = unsafe {
        let srv = socket(AF_UNIX, SOCK_STREAM, 0);
        let bound = bind_socket(srv, addr.as_ptr(), len);
        listen(srv, 1);
        let other = socket(AF_UNIX, SOCK_STREAM, 0);
        let again = bind_socket(other, addr.as_ptr(), len);
        let cl = socket(AF_UNIX, SOCK_STREAM, 0);
        let connected = connect(cl, addr.as_ptr(), len);
        let mut pa = [0u8; 110];
        let mut pl = 110u32;
        getpeername(cl, pa.as_mut_ptr(), &mut pl);
        let a = accept(srv, std::ptr::null_mut(), std::ptr::null_mut());
        write(cl, b"x".as_ptr(), 1);
        let mut x = [0u8; 1];
        read(a, x.as_mut_ptr(), 1);
        let end = pa[2..].iter().position(|&b| b == 0).map_or(pl as usize, |e| e + 2);
        (bound, again, connected, String::from_utf8_lossy(&pa[2..end]).into_owned())
    };
    let kind = stat_words("/tmp/s/sock")[2] as u32 & 0o170000;
    println!(
        "socket: bind {} again {} connect {} peer {peer} a socket {}",
        res(bound.into()),
        res(again.into()),
        res(connected.into()),
        kind == 0o140000
    );
    make("/tmp/s/plain", 0o644);
    let (pa, pl) = (unix_addr("/tmp/s/plain"), 110);
    // SAFETY: as above.
    let refused = res(unsafe { connect(socket(AF_UNIX, SOCK_STREAM, 0), pa.as_ptr(), pl) }.into());
    // SAFETY: a NUL-terminated path.
    unsafe { unlink(c("/tmp/s/sock").as_ptr()) };
    // SAFETY: as above.
    let gone = unsafe { connect(socket(AF_UNIX, SOCK_STREAM, 0), addr.as_ptr(), len) };
    println!("not a socket: {refused} unlinked: {}", res(gone.into()));

    // A FIFO.
    // SAFETY: a NUL-terminated path.
    unsafe { mkfifo(c("/tmp/s/fifo").as_ptr(), 0o600) };
    // SAFETY: fork; the child writes and leaves.
    let pid = unsafe { fork() };
    if pid == 0 {
        // SAFETY: a NUL-terminated path; two bytes.
        unsafe {
            let w = open(c("/tmp/s/fifo").as_ptr(), O_WRONLY);
            write(w, b"hi".as_ptr(), 2);
            _exit(0);
        }
    }
    // SAFETY: a NUL-terminated path.
    let r = unsafe { open(c("/tmp/s/fifo").as_ptr(), O_RDONLY) };
    let got = read_all(r.into());
    let mut st = [0u64; 16];
    // SAFETY: a buffer as big as a `struct stat`.
    unsafe { fstat(r, st.as_mut_ptr().cast()) };
    let same = st[1] == stat_words("/tmp/s/fifo")[1] && st[2] as u32 & 0o170000 == 0o10000;
    // SAFETY: the child above.
    unsafe { waitpid(pid, std::ptr::null_mut(), 0) };
    println!("fifo: read {got} the file's status {same}");

    // A program.
    let prog = std::fs::read("/fsrules").unwrap();
    std::fs::write("/tmp/s/prog", &prog).unwrap();
    // SAFETY: a NUL-terminated path.
    unsafe { chmod(c("/tmp/s/prog").as_ptr(), 0o755) };
    let run = || {
        // SAFETY: fork; the child runs the program.
        let pid = unsafe { fork() };
        if pid == 0 {
            let (p, a) = (c("/tmp/s/prog"), c("exit"));
            let argv = [p.as_ptr(), a.as_ptr(), std::ptr::null()];
            // SAFETY: a NUL-terminated path and argument vector.
            unsafe {
                execv(p.as_ptr(), argv.as_ptr());
                _exit(100 + errno());
            }
        }
        let mut status = 0;
        // SAFETY: the child above.
        unsafe { waitpid(pid, &mut status, 0) };
        (status >> 8) & 0xff
    };
    let ran = run();
    // SAFETY: a NUL-terminated path.
    let writer = unsafe { open(c("/tmp/s/prog").as_ptr(), O_WRONLY) };
    let busy = run();
    // SAFETY: the descriptor just opened.
    unsafe { close(writer) };
    println!("exec: exit {ran}, while open to write {}", name(busy - 100));

    // A handle.
    std::fs::write("/tmp/s/h", b"held").unwrap();
    let h = handle_of("/tmp/s/h");
    let first = read_all(open_handle("/tmp/s", &h, O_RDONLY));
    // SAFETY: NUL-terminated paths.
    unsafe { rename(c("/tmp/s/h").as_ptr(), c("/tmp/s/h2").as_ptr()) };
    let moved = read_all(open_handle("/tmp/s", &h, O_RDONLY));
    // SAFETY: a NUL-terminated path.
    unsafe { unlink(c("/tmp/s/h2").as_ptr()) };
    println!(
        "handle: {first}, renamed {moved}, removed {}",
        res(open_handle("/tmp/s", &h, O_RDONLY))
    );

    // `/proc/self/fd`.
    make("/tmp/s/a", 0o644);
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c("/tmp/s/a").as_ptr(), O_RDONLY) };
    let opened = fd_link(fd);
    // SAFETY: NUL-terminated paths.
    unsafe { rename(c("/tmp/s/a").as_ptr(), c("/tmp/s/b").as_ptr()) };
    let renamed = fd_link(fd);
    // SAFETY: a NUL-terminated path.
    unsafe { unlink(c("/tmp/s/b").as_ptr()) };
    println!("fd link: {opened}, {renamed}, {}", fd_link(fd));

    // A listing.
    // SAFETY: NUL-terminated paths.
    unsafe { mkdir(c("/tmp/s/d").as_ptr(), 0o755) };
    for n in ["z", "a", "m"] {
        make(&format!("/tmp/s/d/{n}"), 0o644);
    }
    println!("listing: {}", names_in("/tmp/s/d").join(" "));

    // Attributes by path.
    std::fs::write("/tmp/s/f", b"0123456789abcdef").unwrap();
    let times = [1000i64, 0, 2000, 0];
    // SAFETY: NUL-terminated paths and values of their lengths.
    let (m, t, u, x) = unsafe {
        (
            chmod(c("/tmp/s/f").as_ptr(), 0o640),
            truncate(c("/tmp/s/f").as_ptr(), 10),
            utimensat(AT_FDCWD, c("/tmp/s/f").as_ptr(), &times, 0),
            setxattr(c("/tmp/s/f").as_ptr(), c("user.k").as_ptr(), b"v".as_ptr(), 1, 0),
        )
    };
    let st = stat_words("/tmp/s/f");
    let mut v = [0u8; 8];
    // SAFETY: NUL-terminated names; a buffer of its length.
    let n = unsafe { getxattr(c("/tmp/s/f").as_ptr(), c("user.k").as_ptr(), v.as_mut_ptr(), 8) };
    let mut fs = [0u64; 15];
    // SAFETY: a NUL-terminated path and a buffer as big as a `struct statfs`.
    unsafe { statfs(c("/tmp/s/f").as_ptr(), fs.as_mut_ptr().cast()) };
    println!(
        "by path: {} {} {} {}; mode {:o} size {} atime {} mtime {} attribute {} tmpfs {}",
        res(m.into()),
        res(t.into()),
        res(u.into()),
        res(x.into()),
        st[2] as u32 & 0o7777,
        st[6],
        st[9],
        st[11],
        String::from_utf8_lossy(&v[..n.max(0) as usize]),
        fs[0] == 0x0102_1994
    );

    // A mount on a directory of the store named by a descriptor's link,
    // as a container runtime mounts inside a root it holds open.
    // SAFETY: NUL-terminated paths.
    let dir = unsafe {
        mkdir(c("/tmp/s/pts").as_ptr(), 0o755);
        open(c("/tmp/s/pts").as_ptr(), O_PATH | O_DIRECTORY)
    };
    let on = mount_new("tmpfs", &format!("/proc/self/fd/{dir}"), 0, "");
    let other = stat_words("/tmp/s/pts")[0] != stat_words("/tmp/s")[0];
    println!("mount by descriptor: {on}, another filesystem {other}");

    // The pages of a file in memory are the page cache's, dirty: three
    // written, of the five its size spans.
    const SYS_CACHESTAT: i64 = 451;
    // SAFETY: a NUL-terminated path; buffers of the sizes given.
    let (cache, dirty, half) = unsafe {
        let fd = open(c("/tmp/s/cached").as_ptr(), 0o102, 0o644);
        let size = getpagesize() as usize;
        let page = vec![7u8; size];
        for _ in 0..3 {
            write(fd, page.as_ptr(), page.len());
        }
        ftruncate(fd, 5 * size as i64);
        let mut cs = [0u64; 5];
        let all = [0u64, 0];
        syscall(SYS_CACHESTAT, fd as i64, all.as_ptr(), cs.as_mut_ptr(), 0);
        let (cache, dirty) = (cs[0], cs[1]);
        let range = [size as u64, size as u64];
        syscall(SYS_CACHESTAT, fd as i64, range.as_ptr(), cs.as_mut_ptr(), 0);
        close(fd);
        (cache, dirty, cs[0])
    };
    println!("cachestat: cached {cache} dirty {dirty}, of one page {half}");
    // A read at the end of a file touches its access time too, as tmpfs's
    // does (`relatime`: the access time is not past the change).
    let old = [1000i64, 0, 1000, 0];
    // SAFETY: a NUL-terminated path; buffers of the sizes given.
    let (n, atime) = unsafe {
        let fd = open(c("/tmp/s/at-end").as_ptr(), 0o102, 0o644);
        write(fd, b"x".as_ptr(), 1);
        utimensat(AT_FDCWD, c("/tmp/s/at-end").as_ptr(), &old, 0);
        let mut b = [0u8; 8];
        let n = read(fd, b.as_mut_ptr(), b.len());
        close(fd);
        (n, times_of("/tmp/s/at-end").0)
    };
    println!("read at the end: {n} bytes, access time touched {}", atime > 1000);
    // A name longer than 255 bytes is refused, by the lookup.
    let long = format!("/tmp/s/{}", "n".repeat(256));
    // SAFETY: NUL-terminated paths.
    let (r, e) = unsafe { (rename(c("/tmp/s/at-end").as_ptr(), c(&long).as_ptr()), errno()) };
    println!("rename to a 256-byte name: {r} errno {e}");
    // Both times omitted: nothing done, on an immutable file and on a
    // path that names nothing alike.
    const FS_IMMUTABLE_FL: u32 = 0x10;
    let omit = [0i64, (1 << 30) - 2, 0, (1 << 30) - 2];
    let set = try_set_flags("/tmp/s/cached", FS_IMMUTABLE_FL);
    // SAFETY: NUL-terminated paths; the times array.
    let (immutable, missing) = unsafe {
        (
            utimensat(AT_FDCWD, c("/tmp/s/cached").as_ptr(), &omit, 0),
            utimensat(AT_FDCWD, c("/tmp/s/none/x").as_ptr(), &omit, 0),
        )
    };
    let unset = try_set_flags("/tmp/s/cached", 0);
    println!("times omitted: immutable ({set}) {immutable}, missing {missing} ({unset})");
}

/// The names in directory `p`.
fn names_in(p: &str) -> Vec<String> {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(c(p).as_ptr(), O_RDONLY | O_DIRECTORY) };
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: a buffer of its length.
        let n = unsafe { syscall(61, fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let mut at = 0;
        while at < n as usize {
            let len = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
            // SAFETY: a NUL-terminated name within the entry.
            let name = unsafe { std::ffi::CStr::from_ptr(buf[at + 19..].as_ptr().cast()) };
            out.push(name.to_string_lossy().into_owned());
            at += len;
        }
    }
    // SAFETY: the descriptor just opened.
    unsafe { close(fd) };
    out
}

/// A `proc` mount's `hidepid=invisible` hides another user's process from
/// one who may not trace it (root sees it); `noaccess`, after a remount,
/// lists it and keeps the reader out of it (`EPERM`); `subset=pid` shows
/// only the processes; a value Linux refuses is `EINVAL`.
fn proc_options_scenario() {
    const MS_REMOUNT: u64 = 32;
    // SAFETY: a plain call.
    unsafe { unshare(CLONE_NEWNS_FLAG) };
    let mut ready = [0i32; 2];
    let mut hold = [0i32; 2];
    // SAFETY: two pipes.
    unsafe {
        pipe(ready.as_mut_ptr());
        pipe(hold.as_mut_ptr());
    }
    // SAFETY: plain fork; the child changes user, says so and waits.
    let other = unsafe { fork() };
    if other == 0 {
        // SAFETY: plain calls on the pipes above; a byte buffer.
        unsafe {
            setuid(1000);
            write(ready[1], b"1".as_ptr(), 1);
            let mut b = [0u8; 1];
            close(hold[1]);
            read(hold[0], b.as_mut_ptr(), 1);
            _exit(0);
        }
    }
    let mut b = [0u8; 1];
    // SAFETY: the pipe above; a byte buffer.
    unsafe { read(ready[0], b.as_mut_ptr(), 1) };
    // SAFETY: NUL-terminated paths.
    unsafe {
        mkdir(c("/tmp/p").as_ptr(), 0o755);
        mkdir(c("/tmp/q").as_ptr(), 0o755);
    }
    println!("hidepid=invisible: {}", mount_new("proc", "/tmp/p", 0, "hidepid=invisible"));
    let pid = other.to_string();
    let theirs = format!("/tmp/p/{pid}/status");
    let seen = |label: &str| {
        let mut st = [0u64; 16];
        // SAFETY: a NUL-terminated path and a buffer as big as a `struct stat`.
        let r = unsafe { stat(c(&format!("/tmp/p/{pid}")).as_ptr(), st.as_mut_ptr().cast()) };
        println!(
            "{label}: stat {} listed {} status {}",
            res(r.into()),
            names_in("/tmp/p").contains(&pid),
            try_open(&theirs, O_RDONLY)
        );
    };
    seen("root");
    as_user(2000, || {
        seen("another user");
        println!("own: {}", try_open("/tmp/p/self/status", O_RDONLY));
    });
    // SAFETY: NUL-terminated strings.
    let r = unsafe {
        mount(
            std::ptr::null(),
            c("/tmp/p").as_ptr(),
            std::ptr::null(),
            MS_REMOUNT,
            c("hidepid=noaccess").as_ptr(),
        )
    };
    println!("remount noaccess: {}", res(r.into()));
    as_user(2000, || seen("another user"));
    println!("subset=pid: {}", mount_new("proc", "/tmp/q", 0, "subset=pid"));
    let names = names_in("/tmp/q");
    println!(
        "meminfo: {} self: {} listed meminfo {} pid {}",
        try_open("/tmp/q/meminfo", O_RDONLY),
        try_open("/tmp/q/self/status", O_RDONLY),
        names.iter().any(|n| n == "meminfo"),
        names.contains(&pid)
    );
    println!("hidepid=3: {}", mount_new("proc", "/tmp/q", 0, "hidepid=3"));
    // SAFETY: the pipe the child waits on; then the child itself.
    unsafe {
        close(hold[1]);
        let mut st = 0;
        waitpid(other, &mut st, 0);
    }
}
