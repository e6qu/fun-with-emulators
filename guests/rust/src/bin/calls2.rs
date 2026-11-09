//! Newer calls: `openat2`'s resolve rules; `epoll_pwait2`'s timeout;
//! `mseal`'s sealed mapping; `futex_waitv` woken on one of its futexes;
//! and `remap_file_pages` showing another page of the file. It prints what
//! it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

const O_RDONLY: u64 = 0;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_DIRECTORY: i32 = 0o200000;
const RESOLVE_NO_SYMLINKS: u64 = 4;
const RESOLVE_BENEATH: u64 = 8;
const RESOLVE_IN_ROOT: u64 = 0x10;
const EXDEV: i32 = 18;
const ELOOP: i32 = 40;
const EPERM: i32 = 1;
const PROT_READ: i32 = 1;
const PROT_RW: i32 = 3;
const MAP_PRIVATE_ANON: i32 = 0x02 | 0x20;
const MAP_SHARED: i32 = 1;
const EPOLLIN: u32 = 1;
const FUTEX_WAKE_PRIVATE: i32 = 1 | 128;
const SYS_FUTEX: i64 = 98;
const SYS_OPENAT2: i64 = 437;
const SYS_EPOLL_PWAIT2: i64 = 441;
const SYS_FUTEX_WAITV: i64 = 449;
const SYS_MSEAL: i64 = 462;
const SYS_REMAP_FILE_PAGES: i64 = 234;
const AT_FDCWD: i64 = -100;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
struct Waitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn pipe(fds: *mut i32) -> i32;
    fn symlink(target: *const c_char, path: *const c_char) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, ev: *mut EpollEvent) -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn getpagesize() -> i32;
    fn getpid() -> i32;
    fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// `openat2` of `path` from `dir` with `resolve`: the descriptor, or the
/// errno negated.
fn openat2(dir: i32, path: &str, resolve: u64) -> i64 {
    let how: [u64; 3] = [O_RDONLY, 0, resolve];
    let p = c(path);
    // SAFETY: a valid path and `struct open_how`.
    let r = unsafe { syscall(SYS_OPENAT2, i64::from(dir), p.as_ptr(), how.as_ptr(), 24i64) };
    if r < 0 { -i64::from(errno()) } else { r }
}

static WORDS: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

fn main() {
    // SAFETY: plain calls into the C library throughout.
    unsafe {
        let page = getpagesize() as usize;

        // openat2's resolve rules, from a directory of the guest's own.
        let dir = format!("/tmp/fwe-calls2-{}", getpid());
        std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
        std::fs::write(format!("{dir}/sub/file"), b"x").unwrap();
        std::fs::write(format!("{dir}/file"), b"x").unwrap();
        symlink(c("sub/file").as_ptr(), c(&format!("{dir}/link")).as_ptr());
        let d = open(c(&dir).as_ptr(), O_DIRECTORY);
        let plain = openat2(d, "link", 0);
        let in_root = openat2(d, "/sub/file", RESOLVE_IN_ROOT);
        println!(
            "openat2: plain {}, beneath ../ {}, no symlinks {}, in root {}",
            plain >= 0,
            openat2(d, "../x", RESOLVE_BENEATH) == -i64::from(EXDEV),
            openat2(d, "link", RESOLVE_NO_SYMLINKS) == -i64::from(ELOOP),
            in_root >= 0
        );
        for fd in [plain, in_root] {
            close(fd as i32);
        }
        let _ = openat2(AT_FDCWD as i32, "/", 0);
        close(d);
        std::fs::remove_dir_all(&dir).unwrap();

        // epoll_pwait2: a timeout in nanoseconds, then a ready pipe.
        let ep = epoll_create1(0);
        let mut p = [0i32; 2];
        pipe(p.as_mut_ptr());
        let mut ev = EpollEvent { events: EPOLLIN, data: 7 };
        epoll_ctl(ep, 1, p[0], &mut ev);
        let mut out = EpollEvent { events: 0, data: 0 };
        let t = Timespec { sec: 0, nsec: 50_000_000 };
        let mut before = Timespec { sec: 0, nsec: 0 };
        let mut after = Timespec { sec: 0, nsec: 0 };
        clock_gettime(1, &mut before);
        let none = syscall(SYS_EPOLL_PWAIT2, i64::from(ep), &mut out as *mut EpollEvent, 1i64, &t, 0i64, 8i64);
        clock_gettime(1, &mut after);
        let waited = (after.sec - before.sec) * 1_000_000_000 + (after.nsec - before.nsec);
        write(p[1], b"x".as_ptr(), 1);
        let one = syscall(SYS_EPOLL_PWAIT2, i64::from(ep), &mut out as *mut EpollEvent, 1i64, &t, 0i64, 8i64);
        println!(
            "epoll_pwait2: none {none} after the timeout {}, then {one} with {}",
            waited >= 45_000_000,
            out.data
        );

        // mseal: the sealed mapping stays as it is.
        let m = mmap(std::ptr::null_mut(), 2 * page, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
        let sealed = syscall(SYS_MSEAL, m, (2 * page) as i64, 0i64);
        let unmapped = munmap(m, 2 * page) == -1 && errno() == EPERM;
        let protected = mprotect(m, page, PROT_READ) == -1 && errno() == EPERM;
        println!("mseal: {sealed}, munmap refused {unmapped}, mprotect refused {protected}");

        // futex_waitv: woken on the second of two futexes.
        let waker = std::thread::spawn(|| {
            for _ in 0..500 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                let woke = syscall(SYS_FUTEX, WORDS[1].as_ptr(), i64::from(FUTEX_WAKE_PRIVATE), 1i64);
                if woke > 0 {
                    return;
                }
            }
        });
        let waiters: Vec<Waitv> = WORDS
            .iter()
            .map(|w| Waitv { val: 0, uaddr: w.as_ptr() as u64, flags: 2 | 128, reserved: 0 })
            .collect();
        let mut deadline = Timespec { sec: 0, nsec: 0 };
        clock_gettime(1, &mut deadline);
        deadline.sec += 10;
        let which = syscall(SYS_FUTEX_WAITV, waiters.as_ptr(), 2i64, 0i64, &deadline, 1i64);
        waker.join().unwrap();
        WORDS[0].store(0, Ordering::SeqCst);
        println!("futex_waitv: woken on {which}");

        // remap_file_pages: the first page of a mapping shows the file's
        // fourth.
        let path = format!("/tmp/fwe-calls2-file-{}", getpid());
        let fd = open(c(&path).as_ptr(), O_RDWR | O_CREAT, 0o600);
        for i in 0..4u8 {
            write(fd, vec![i; page].as_ptr(), page);
        }
        let m = mmap(std::ptr::null_mut(), 4 * page, PROT_RW, MAP_SHARED, fd, 0) as *mut u8;
        let before = *m;
        let r = syscall(SYS_REMAP_FILE_PAGES, m, page as i64, 0i64, 3i64, 0i64);
        println!("remap_file_pages: {r}, first page showed {before}, now {}", *m);
        munmap(m.cast(), 4 * page);
        close(fd);
        std::fs::remove_file(&path).unwrap();
    }
}
