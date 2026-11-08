//! System calls a program makes of the kernel's own: moving data through
//! pipes (`splice` from a file's offset, `tee`, `vmsplice`), the
//! personality, a scheduling policy set and read back (and a fork child
//! that inherits it), the clock, which may be read but not set, a pipe's
//! filesystem, and a `statx` request Linux refuses. It prints what it
//! observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates; the calls musl lacks are made with
//! `syscall`.
use std::ffi::{CString, c_char};

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const SPLICE_F_NONBLOCK: u32 = 2;
const EAGAIN: i32 = 11;
const EPERM: i32 = 1;
const EINVAL: i32 = 22;

const SYS_SPLICE: i64 = 76;
const SYS_TEE: i64 = 77;
const SYS_VMSPLICE: i64 = 75;
const SYS_PERSONALITY: i64 = 92;
const SYS_SCHED_SETATTR: i64 = 274;
const SYS_SCHED_GETATTR: i64 = 275;
const SYS_SCHED_GETSCHEDULER: i64 = 120;
const SYS_CLOCK_SETTIME: i64 = 112;
const SYS_CLOCK_GETTIME: i64 = 113;
const SYS_STATX: i64 = 291;

const SCHED_RR: u32 = 2;
const UNAME26: u64 = 0x2_0000;

#[repr(C)]
#[derive(Default)]
struct SchedAttr {
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
}

#[repr(C)]
struct Utsname {
    fields: [[u8; 65]; 6],
}

unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn lseek(fd: i32, off: i64, whence: i32) -> i64;
    fn pipe(fds: *mut i32) -> i32;
    fn unlink(path: *const c_char) -> i32;
    fn getpid() -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn uname(u: *mut Utsname) -> i32;
    fn fstatfs(fd: i32, buf: *mut i64) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

/// `-errno` of a failed call, else its result.
fn res(r: i64) -> i64 {
    if r < 0 { -(errno() as i64) } else { r }
}

fn main() {
    // SAFETY: plain calls into the C library throughout; every buffer is a
    // live local of the length passed.
    unsafe {
        let path = CString::new(format!("/tmp/fwe-calls-{}", getpid())).unwrap();
        let file = open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
        write(file, b"0123456789".as_ptr(), 10);
        let (mut a, mut b) = ([0i32; 2], [0i32; 2]);
        pipe(a.as_mut_ptr());
        pipe(b.as_mut_ptr());

        // From the file's offset 2 into a pipe: the offset moves, the
        // file's own position does not.
        let mut off: i64 = 2;
        let n = syscall(SYS_SPLICE, file, &mut off as *mut i64, a[1], 0usize, 5usize, 0u32);
        println!("splice: {n}, offset {off}, position {}", lseek(file, 0, 1));
        // Copied into a second pipe and left in the first.
        let t = syscall(SYS_TEE, a[0], b[1], 3usize, 0u32);
        let mut buf = [0u8; 16];
        let (x, y) = (read(a[0], buf.as_mut_ptr(), 5), read(b[0], buf[5..].as_mut_ptr(), 3));
        println!("tee: {t}; first pipe {}, second {}", String::from_utf8_lossy(&buf[..x as usize]), String::from_utf8_lossy(&buf[5..5 + y as usize]));
        // From memory into a pipe; an empty pipe, asked not to wait.
        let data = *b"vmsplice";
        let iov = [data.as_ptr() as usize, data.len()];
        let v = syscall(SYS_VMSPLICE, a[1], iov.as_ptr(), 1usize, 0u32);
        let got = read(a[0], buf.as_mut_ptr(), 16);
        println!("vmsplice: {v}, read {}", String::from_utf8_lossy(&buf[..got as usize]));
        let e = res(syscall(SYS_SPLICE, a[0], 0usize, file, 0usize, 1usize, SPLICE_F_NONBLOCK));
        println!("splice from an empty pipe: {}", e == -(EAGAIN as i64));
        println!("splice between files: {}", res(syscall(SYS_SPLICE, file, 0usize, file, 0usize, 1usize, 0u32)) == -(EINVAL as i64));

        // The personality: set, read back, and seen by uname.
        let old = syscall(SYS_PERSONALITY, UNAME26);
        let now = syscall(SYS_PERSONALITY, 0xffff_ffffu64);
        let mut u: Utsname = std::mem::zeroed();
        uname(&mut u);
        let release = &u.fields[2];
        println!("personality: was {old}, now {now:#x}, release 2.6: {}", release.starts_with(b"2.6."));
        syscall(SYS_PERSONALITY, 0u64);

        // A round-robin policy at priority 10, read back, and inherited.
        let mut attr = SchedAttr { size: 48, policy: SCHED_RR, priority: 10, ..Default::default() };
        let r = syscall(SYS_SCHED_SETATTR, 0, &attr as *const SchedAttr, 0u32);
        attr = SchedAttr::default();
        let g = syscall(SYS_SCHED_GETATTR, 0, &mut attr as *mut SchedAttr, 48u32, 0u32);
        println!("sched: set {r}, get {g}, policy {}, priority {}", attr.policy, attr.priority);
        let pid = fork();
        if pid == 0 {
            _exit(syscall(SYS_SCHED_GETSCHEDULER, 0) as i32);
        }
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        println!("child's policy: {}", (status >> 8) & 0xff);

        // The clock is read, not set.
        let mut ts = [0i64; 2];
        let read_ok = syscall(SYS_CLOCK_GETTIME, 0, ts.as_mut_ptr());
        let set = res(syscall(SYS_CLOCK_SETTIME, 0, ts.as_ptr()));
        println!("clock: read {read_ok}, set refused {}", set == -(EPERM as i64));

        // A pipe's filesystem is pipefs; `statx` refuses a reserved mask
        // bit.
        let mut sf = [0i64; 15];
        let r = fstatfs(a[0], sf.as_mut_ptr());
        let mut sx = [0u8; 256];
        let bad = res(syscall(SYS_STATX, -100i64, c"/".as_ptr(), 0, 0x8000_0000u32, sx.as_mut_ptr()));
        println!("pipe's filesystem: {r}, pipefs {}; statx reserved bit refused {}", sf[0] == 0x5049_5045, bad == -(EINVAL as i64));

        for fd in [a[0], a[1], b[0], b[1], file] {
            close(fd);
        }
        unlink(path.as_ptr());
    }
}
