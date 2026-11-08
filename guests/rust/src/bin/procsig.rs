//! Signals between processes and how processes end: a real-time signal
//! queued to another process with its value; `rt_sigqueueinfo` to pid -1
//! refused; a signal the host lacks (`SIGSTKFLT`) and a fault signal sent
//! to a child the moment it is forked; core dumps, of a fault and of a
//! sent signal; a child whose end is told with `SIGUSR2`; a child sharing
//! the memory (`CLONE_VM`); the hard CPU limit; and the timer slack a child
//! inherits. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

const SIGILL: i32 = 4;
const SIGABRT: i32 = 6;
const SIGKILL: i32 = 9;
const SIGUSR2: i32 = 12;
const SIGFPE: i32 = 8;
const SIGSTKFLT: i32 = 16;
const SIGXCPU: i32 = 24;
const SIGRT1: i32 = 35;
const SI_QUEUE: i32 = -1;
const ESRCH: i32 = 3;
const RLIMIT_CPU: i32 = 0;
const RLIMIT_CORE: i32 = 4;
const CLONE_VM: i32 = 0x100;
const SIGCHLD: i32 = 17;
const WALL: i32 = 0x4000_0000;
const PR_SET_TIMERSLACK: i32 = 29;
const PR_GET_TIMERSLACK: i32 = 30;
const PROT_RW: i32 = 3;
const MAP_SHARED_ANON: i32 = 0x01 | 0x20;
const SYS_RT_SIGQUEUEINFO: i64 = 138;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn fork() -> i32;
    fn getpid() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn raise(sig: i32) -> i32;
    fn pause() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn sigtimedwait(set: *const u64, info: *mut [u8; 128], timeout: *const Timespec) -> i32;
    fn sigprocmask(how: i32, set: *const u64, old: *mut u64) -> i32;
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn setrlimit(res: i32, lim: *const Rlimit) -> i32;
    fn prctl(op: i32, ...) -> i32;
    fn clone(f: extern "C" fn(*mut c_void) -> i32, stack: *mut c_void, flags: i32, arg: *mut c_void) -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn chdir(path: *const c_char) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn set(sigs: &[i32]) -> u64 {
    sigs.iter().fold(0, |s, &n| s | 1 << (n - 1))
}

/// How a child ended: its signal and whether it dumped core, or its exit
/// status as a negative number.
fn ended(status: i32) -> (i32, bool) {
    if status & 0x7f == 0 { (-((status >> 8) & 0xff), false) } else { (status & 0x7f, status & 0x80 != 0) }
}

static SHARED: AtomicI32 = AtomicI32::new(0);
static XCPU: AtomicI32 = AtomicI32::new(0);

extern "C" fn in_shared_memory(_: *mut c_void) -> i32 {
    SHARED.store(7, Ordering::SeqCst);
    0
}

fn main() {
    // SAFETY: plain calls into the C library throughout.
    unsafe {
        let mut status = 0;
        let none = Rlimit { cur: 0, max: u64::MAX };
        setrlimit(RLIMIT_CORE, &none);

        // A queued signal for pid -1 names no process.
        let info = [0u8; 128];
        let r = syscall(SYS_RT_SIGQUEUEINFO, -1i64, 10i64, info.as_ptr());
        println!("queued to -1: {}", r == -1 && errno() == ESRCH);

        // A real-time signal, with its value, to another process.
        let rt = set(&[SIGRT1]);
        sigprocmask(0, &rt, std::ptr::null_mut());
        let pid = fork();
        if pid == 0 {
            let mut got = [0u8; 128];
            let t = Timespec { sec: 10, nsec: 0 };
            let sig = sigtimedwait(&rt, &mut got, &t);
            let code = i32::from_ne_bytes(got[8..12].try_into().unwrap());
            let value = i32::from_ne_bytes(got[24..28].try_into().unwrap());
            _exit((sig == SIGRT1 && code == SI_QUEUE && value == 42) as i32);
        }
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&SIGRT1.to_ne_bytes());
        info[8..12].copy_from_slice(&SI_QUEUE.to_ne_bytes());
        info[24..28].copy_from_slice(&42i32.to_ne_bytes());
        let sent = syscall(SYS_RT_SIGQUEUEINFO, i64::from(pid), i64::from(SIGRT1), info.as_ptr());
        waitpid(pid, &mut status, 0);
        println!("real-time to another: sent {sent}, taken with its value {}", ended(status) == (-1, false));
        sigprocmask(1, &rt, std::ptr::null_mut());

        // Signals sent the moment a child is forked: one the host lacks,
        // and fault signals (not SIGSEGV or SIGBUS, which Rust's runtime
        // catches).
        for sig in [SIGSTKFLT, SIGFPE, SIGILL] {
            let pid = fork();
            if pid == 0 {
                pause();
                _exit(0);
            }
            kill(pid, sig);
            waitpid(pid, &mut status, 0);
            println!("signal {sig} at once: {:?}", ended(status));
        }

        // Core dumps, in a directory of the guest's own.
        let dir = format!("/tmp/fwe-procsig-{}", getpid());
        std::fs::create_dir(&dir).unwrap();
        let cdir = CString::new(dir.clone()).unwrap();
        chdir(cdir.as_ptr());
        let some = Rlimit { cur: 1 << 20, max: u64::MAX };
        setrlimit(RLIMIT_CORE, &some);
        for (what, how) in [("a fault", 0), ("SIGABRT", 1)] {
            let pid = fork();
            if pid == 0 {
                if how == 0 {
                    std::ptr::write_volatile(8 as *mut i32, 1);
                }
                raise(SIGABRT);
                _exit(0);
            }
            waitpid(pid, &mut status, 0);
            let core = std::fs::read(format!("{dir}/core")).unwrap_or_default();
            let elf_core = core.starts_with(b"\x7fELF") && core.get(16) == Some(&4);
            println!("core of {what}: {:?}, an ELF core {elf_core}", ended(status));
            let _ = std::fs::remove_file(format!("{dir}/core"));
        }
        setrlimit(RLIMIT_CORE, &none);
        chdir(c"/".as_ptr());
        std::fs::remove_dir(&dir).unwrap();

        // A child whose end is told with SIGUSR2, not SIGCHLD.
        let usr2 = set(&[SIGUSR2, SIGCHLD]);
        sigprocmask(0, &usr2, std::ptr::null_mut());
        let pid = syscall(220, i64::from(SIGUSR2), 0i64, 0i64, 0i64, 0i64) as i32;
        if pid == 0 {
            _exit(0);
        }
        let mut got = [0u8; 128];
        let t = Timespec { sec: 10, nsec: 0 };
        let sig = sigtimedwait(&usr2, &mut got, &t);
        let reaped = waitpid(pid, &mut status, WALL) == pid;
        println!("end told with: {}, reaped {reaped}", if sig == SIGUSR2 { "SIGUSR2" } else { "other" });
        sigprocmask(1, &usr2, std::ptr::null_mut());

        // A child that shares the memory.
        let stack = vec![0u8; 64 << 10];
        let top = stack.as_ptr().add(stack.len()) as *mut c_void;
        let pid = clone(in_shared_memory, top, CLONE_VM | SIGCHLD, std::ptr::null_mut());
        if pid > 0 {
            waitpid(pid, &mut status, 0);
            println!("memory shared: {}", SHARED.load(Ordering::SeqCst) == 7);
        } else {
            println!("memory shared: refused");
        }

        // The hard CPU limit: SIGXCPU at the soft one, then SIGKILL.
        let seen = mmap(std::ptr::null_mut(), 4096, PROT_RW, MAP_SHARED_ANON, -1, 0) as *mut i32;
        let pid = fork();
        if pid == 0 {
            extern "C" fn on_xcpu(_: i32) {
                XCPU.fetch_add(1, Ordering::SeqCst);
            }
            signal(SIGXCPU, on_xcpu);
            setrlimit(RLIMIT_CPU, &Rlimit { cur: 1, max: 2 });
            loop {
                std::ptr::write_volatile(seen, XCPU.load(Ordering::SeqCst));
            }
        }
        waitpid(pid, &mut status, 0);
        println!("cpu limit: SIGXCPU {}, then {:?}", *seen > 0, ended(status) == (SIGKILL, false));

        // The timer slack, which a child takes from its parent.
        prctl(PR_SET_TIMERSLACK, 70_000u64);
        let shown = std::fs::read_to_string("/proc/self/timerslack_ns").unwrap();
        let pid = fork();
        if pid == 0 {
            let inherited = prctl(PR_GET_TIMERSLACK);
            prctl(PR_SET_TIMERSLACK, 0u64);
            _exit((inherited == 70_000 && prctl(PR_GET_TIMERSLACK) == 70_000) as i32);
        }
        waitpid(pid, &mut status, 0);
        println!(
            "timer slack: {}, shown {}, the child's {}",
            prctl(PR_GET_TIMERSLACK),
            shown.trim(),
            ended(status) == (-1, false)
        );
    }
}
