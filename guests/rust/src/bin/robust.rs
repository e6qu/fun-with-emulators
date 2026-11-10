//! Robust mutexes held by a child that ends with `_exit` (a waiter
//! blocked on it wakes), or is killed by a signal, and by a thread that
//! ends with the raw `exit` call (a waiter blocked on it wakes), each
//! locked next with `EOWNERDEAD`, made consistent and locked again. musl
//! leaves these to the kernel's walk of the robust list, which it keeps
//! for process-shared mutexes only. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{c_int, c_long, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

const PTHREAD_MUTEX_ROBUST: c_int = 1;
const PTHREAD_PROCESS_SHARED: c_int = 1;
const EOWNERDEAD: c_int = 130;
const SYS_EXIT: c_long = 93;
const SIGTERM: c_int = 15;
const PROT_RW: c_int = 3;
const MAP_SHARED_ANON: c_int = 0x01 | 0x20;

/// Room for musl's `pthread_mutex_t` (40 bytes) and its attributes.
#[repr(C, align(8))]
struct Mutex([u8; 48]);
#[repr(C, align(8))]
struct Attr([u8; 8]);

unsafe extern "C" {
    fn pthread_mutexattr_init(a: *mut Attr) -> c_int;
    fn pthread_mutexattr_setrobust(a: *mut Attr, robust: c_int) -> c_int;
    fn pthread_mutexattr_setpshared(a: *mut Attr, shared: c_int) -> c_int;
    fn pthread_mutex_init(m: *mut Mutex, a: *const Attr) -> c_int;
    fn pthread_mutex_lock(m: *mut Mutex) -> c_int;
    fn pthread_mutex_unlock(m: *mut Mutex) -> c_int;
    fn pthread_mutex_consistent(m: *mut Mutex) -> c_int;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void;
    fn fork() -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn read(fd: c_int, buf: *mut u8, n: usize) -> isize;
    fn write(fd: c_int, buf: *const u8, n: usize) -> isize;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn getpid() -> c_int;
    fn usleep(us: u32) -> c_int;
    fn _exit(code: c_int) -> !;
    fn syscall(nr: c_long, ...) -> c_long;
    fn pthread_create(
        t: *mut usize,
        attr: *const c_void,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
}

/// The thread [`lock_and_exit`] holds its mutex.
static LOCKED: AtomicBool = AtomicBool::new(false);

/// A thread that locks the mutex at `m`, says so, and ends with the raw
/// `exit` call (so it is never joined: musl's join waits for its own
/// `pthread_exit`).
extern "C" fn lock_and_exit(m: *mut c_void) -> *mut c_void {
    // SAFETY: the mutex `main` made; ending only this thread.
    unsafe {
        pthread_mutex_lock(m.cast());
        LOCKED.store(true, Ordering::SeqCst);
        usleep(50_000);
        syscall(SYS_EXIT, 0 as c_long);
    }
    std::ptr::null_mut()
}

/// A robust, process-shared mutex in shared memory.
fn robust_mutex() -> *mut Mutex {
    // SAFETY: a fresh shared mapping holds the mutex; the attribute calls
    // get valid pointers.
    unsafe {
        let m = mmap(std::ptr::null_mut(), 4096, PROT_RW, MAP_SHARED_ANON, -1, 0).cast::<Mutex>();
        let mut a = Attr([0; 8]);
        pthread_mutexattr_init(&mut a);
        pthread_mutexattr_setrobust(&mut a, PTHREAD_MUTEX_ROBUST);
        pthread_mutexattr_setpshared(&mut a, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(m, &a);
        m
    }
}

/// Lock `m`, expecting its owner dead: whether the lock said so, and
/// whether it could be made consistent, unlocked and locked again.
fn recover(m: *mut Mutex) -> (bool, bool) {
    // SAFETY: a mutex `robust_mutex` made.
    unsafe {
        let dead = pthread_mutex_lock(m) == EOWNERDEAD;
        let ok = pthread_mutex_consistent(m) == 0
            && pthread_mutex_unlock(m) == 0
            && pthread_mutex_lock(m) == 0
            && pthread_mutex_unlock(m) == 0;
        (dead, ok)
    }
}

/// A child that locks `m`, says so, and ends by `end` while holding it.
fn child_holding(m: *mut Mutex, end: fn()) -> c_int {
    let mut fds = [0 as c_int; 2];
    // SAFETY: a valid out-array; plain calls.
    unsafe {
        pipe(fds.as_mut_ptr());
        let c = fork();
        if c == 0 {
            pthread_mutex_lock(m);
            write(fds[1], b"x".as_ptr(), 1);
            usleep(50_000);
            end();
            _exit(1);
        }
        let mut b = [0u8; 1];
        read(fds[0], b.as_mut_ptr(), 1);
        c
    }
}

fn main() {
    // A process-shared mutex whose holder exits; this process is waiting
    // for it by then.
    let m = robust_mutex();
    // SAFETY: ending the child.
    let c = child_holding(m, || unsafe { _exit(0) });
    let (dead, ok) = recover(m);
    // SAFETY: reaping the child.
    unsafe { waitpid(c, &mut 0, 0) };
    println!("exited holder: owner dead {dead}, recovered {ok}");

    // One whose holder a signal kills.
    let m = robust_mutex();
    // SAFETY: the child signals itself.
    let c = child_holding(m, || unsafe {
        kill(getpid(), SIGTERM);
    });
    let mut st = 0;
    // SAFETY: reaping the child.
    unsafe { waitpid(c, &mut st, 0) };
    let (dead, ok) = recover(m);
    println!("killed holder: signal {}, owner dead {dead}, recovered {ok}", st & 0x7f);

    // A thread's, the thread ending without the C library's help.
    let m = robust_mutex();
    let mut t = 0usize;
    // SAFETY: a valid out-pointer; the thread gets the mutex.
    let started = unsafe { pthread_create(&mut t, std::ptr::null(), lock_and_exit, m.cast()) == 0 };
    while started && !LOCKED.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    let (dead, ok) = recover(m);
    println!("thread holder: started {started}, owner dead {dead}, recovered {ok}");
}
