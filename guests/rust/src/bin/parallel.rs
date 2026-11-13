//! Threads making system calls at once, while others change what those
//! calls read: reader threads ask for their parent, working directory and
//! a pipe's status and block and unblock a signal, over and over, while
//! one thread changes directory back and forth, another forks children
//! that ask for their parent and exit, and the main thread signals the
//! process. Every answer must be one the process could give at that
//! moment, and every thread must finish. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;
const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SA_RESTART: u64 = 0x1000_0000;
const READERS: usize = 6;
const ROUNDS: usize = 20_000;
const FORKS: usize = 40;

#[repr(C)]
struct KernelSigaction {
    handler: extern "C" fn(c_int),
    flags: u64,
    restorer: usize,
    mask: u64,
}

unsafe extern "C" {
    fn getppid() -> c_int;
    fn getpid() -> c_int;
    fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char;
    fn chdir(path: *const c_char) -> c_int;
    fn mkdir(path: *const c_char, mode: u32) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn fstat(fd: c_int, st: *mut [u8; 128]) -> c_int;
    fn sigprocmask(how: c_int, set: *const u64, old: *mut u64) -> c_int;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn usleep(us: u32) -> c_int;
    fn _exit(code: c_int) -> !;
    fn syscall(nr: i64, ...) -> i64;
}

static BAD: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_: c_int) {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn cwd() -> Vec<u8> {
    let mut buf = [0u8; 512];
    // SAFETY: a buffer of its length.
    if unsafe { getcwd(buf.as_mut_ptr().cast(), buf.len()) }.is_null() {
        return Vec::new();
    }
    buf[..buf.iter().position(|&b| b == 0).unwrap_or(0)].to_vec()
}

fn main() {
    let base = std::env::args().nth(1).expect("a directory to work in");
    let (a, b) = (format!("{base}/a\0"), format!("{base}/b\0"));
    // Each directory as `getcwd` names it (the path given may run through
    // a symbolic link).
    let mut dirs = [Vec::new(), Vec::new()];
    for (d, path) in dirs.iter_mut().zip([&b, &a]) {
        // SAFETY: NUL-terminated paths.
        unsafe {
            mkdir(path.as_ptr().cast(), 0o755);
            chdir(path.as_ptr().cast());
        }
        *d = cwd();
    }
    let action = KernelSigaction { handler: on_usr1, flags: SA_RESTART, restorer: 0, mask: 0 };
    // SAFETY: a valid action (arm64 needs no restorer: the kernel's
    // trampoline returns from the handler).
    unsafe { syscall(134, SIGUSR1 as i64, &action as *const KernelSigaction, 0usize, 8usize) };
    // SAFETY: getppid cannot fail.
    let parent = unsafe { getppid() };

    std::thread::scope(|s| {
        let mut readers = Vec::new();
        for _ in 0..READERS {
            let dirs = &dirs;
            readers.push(s.spawn(move || {
                let mut fds = [0; 2];
                // SAFETY: a 2-element array.
                unsafe { pipe(fds.as_mut_ptr()) };
                let mut st = [0u8; 128];
                let usr2 = 1u64 << (SIGUSR2 - 1);
                for _ in 0..ROUNDS {
                    // SAFETY: plain calls with valid buffers.
                    let ok = unsafe {
                        getppid() == parent
                            && fstat(fds[0], &mut st) == 0
                            && sigprocmask(SIG_BLOCK, &usr2, std::ptr::null_mut()) == 0
                            && sigprocmask(SIG_UNBLOCK, &usr2, std::ptr::null_mut()) == 0
                    };
                    let here = cwd();
                    if !ok || !dirs.contains(&here) {
                        BAD.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // SAFETY: closing the pipe made above.
                unsafe {
                    close(fds[0]);
                    close(fds[1]);
                }
            }));
        }
        s.spawn(|| {
            let mut i = 0;
            while !DONE.load(Ordering::Relaxed) {
                let to = if i % 2 == 0 { &b } else { &a };
                // SAFETY: a NUL-terminated path.
                if unsafe { chdir(to.as_ptr().cast()) } != 0 {
                    BAD.fetch_add(1, Ordering::Relaxed);
                }
                i += 1;
            }
        });
        let forker = s.spawn(|| {
            let mut ok = 0;
            for _ in 0..FORKS {
                // SAFETY: the child makes plain calls and exits.
                let me = unsafe { getpid() };
                let pid = unsafe { fork() };
                if pid == 0 {
                    // SAFETY: as above.
                    unsafe { _exit(if getppid() == me { 0 } else { 1 }) };
                }
                let mut status = -1;
                // SAFETY: a valid status pointer.
                unsafe { waitpid(pid, &mut status, 0) };
                if status == 0 {
                    ok += 1;
                }
            }
            ok
        });
        for _ in 0..100 {
            // SAFETY: plain calls.
            unsafe {
                kill(getpid(), SIGUSR1);
                usleep(200);
            }
        }
        let forks = forker.join().unwrap();
        println!("forks: {forks} of {FORKS} saw their parent");
        for r in readers {
            r.join().unwrap();
        }
        // The directory changer stops once the readers are done.
        DONE.store(true, Ordering::Relaxed);
    });
    println!("readers: {} wrong answers", BAD.load(Ordering::Relaxed));
    println!("signals handled: {}", HANDLED.load(Ordering::Relaxed) > 0);
}
