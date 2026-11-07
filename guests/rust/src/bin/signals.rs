//! Signals and processes as shells, build tools and runtimes use them: one
//! scenario per argument, each printing what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGKILL: i32 = 9;
const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
const SIGTRAP: i32 = 5;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGPIPE: i32 = 13;
const SIGALRM: i32 = 14;
const SIGTERM: i32 = 15;
const SIGCHLD: i32 = 17;
const SIGCONT: i32 = 18;
const SIGTSTP: i32 = 20;
/// A real-time signal musl does not reserve for itself.
const SIGRT: i32 = 40;

const SA_SIGINFO: i32 = 4;
const SA_RESTART: i32 = 0x1000_0000;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const P_PID: i32 = 1;
const WEXITED: i32 = 4;
const WUNTRACED: i32 = 2;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const SYS_GETTID: i64 = 178;
const SYS_TGKILL: i64 = 131;

#[repr(C)]
#[derive(Clone, Copy)]
struct SigSet([u64; 16]);

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: SigSet,
    flags: i32,
    restorer: usize,
}

#[repr(C)]
struct SigInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    pid: i32,
    uid: u32,
    status: i32,
    _rest: [u8; 100],
}

#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i64,
}

#[repr(C)]
struct Itimerval {
    interval: Timeval,
    value: Timeval,
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
struct Rusage {
    utime: Timeval,
    stime: Timeval,
    maxrss: i64,
    _rest: [i64; 13],
}

unsafe extern "C" {
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn sigprocmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32;
    fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32;
    fn sigsuspend(set: *const SigSet) -> i32;
    fn sigpending(set: *mut SigSet) -> i32;
    fn sigtimedwait(set: *const SigSet, info: *mut SigInfo, timeout: *const Timespec) -> i32;
    fn fork() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
    fn getppid() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn wait4(pid: i32, status: *mut i32, options: i32, usage: *mut Rusage) -> i32;
    fn waitid(idtype: i32, id: u32, info: *mut SigInfo, options: i32) -> i32;
    fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn pause() -> i32;
    fn setitimer(which: i32, new: *const Itimerval, old: *mut Itimerval) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn raise(sig: i32) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
    fn signalfd(fd: i32, mask: *const SigSet, flags: i32) -> i32;
    fn ppoll(fds: *mut u8, n: u64, timeout: *const Timespec, mask: *const SigSet) -> i32;
    fn _exit(code: i32) -> !;
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, event: *mut u8) -> i32;
    fn epoll_wait(ep: i32, events: *mut u8, max: i32, timeout: i32) -> i32;
    fn timerfd_create(clock: i32, flags: i32) -> i32;
    fn timerfd_settime(fd: i32, flags: i32, new: *const [Timespec; 2], old: *mut u8) -> i32;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's errno location for this thread.
    unsafe { *__errno_location() }
}

fn set(sigs: &[i32]) -> SigSet {
    let mut s = SigSet([0; 16]);
    for &sig in sigs {
        s.0[0] |= 1 << (sig - 1);
    }
    s
}

static HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_SIG: AtomicI32 = AtomicI32::new(0);
static LAST_PID: AtomicI32 = AtomicI32::new(0);
static LAST_STATUS: AtomicI32 = AtomicI32::new(0);
static LAST_TID: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(sig: i32, info: *mut SigInfo, _ctx: *mut u8) {
    LAST_SIG.store(sig, Ordering::SeqCst);
    // SAFETY: SA_SIGINFO handlers get a valid siginfo.
    let (pid, status) = unsafe { ((*info).pid, (*info).status) };
    LAST_PID.store(pid, Ordering::SeqCst);
    LAST_STATUS.store(status, Ordering::SeqCst);
    // SAFETY: plain system call.
    LAST_TID.store(unsafe { syscall(SYS_GETTID) } as i32, Ordering::SeqCst);
    HITS.fetch_add(1, Ordering::SeqCst);
}

fn catch(sig: i32, flags: i32) {
    let act = SigAction {
        handler: record as *const () as usize,
        mask: SigSet([0; 16]),
        flags: flags | SA_SIGINFO,
        restorer: 0,
    };
    // SAFETY: a valid sigaction.
    assert_eq!(unsafe { sigaction(sig, &act, std::ptr::null_mut()) }, 0);
}

fn block(sigs: &[i32]) {
    // SAFETY: a valid signal set.
    unsafe { sigprocmask(SIG_BLOCK, &set(sigs), std::ptr::null_mut()) };
}

fn suspend_until_hit() {
    let empty = set(&[]);
    while HITS.load(Ordering::SeqCst) == 0 {
        // SAFETY: a valid signal set.
        unsafe { sigsuspend(&empty) };
    }
}

fn child(f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: the child only runs `f` and exits.
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork failed: {}", errno());
    if pid == 0 {
        let code = f();
        // SAFETY: ending the child.
        unsafe { _exit(code) }
    }
    pid
}

fn wait_status(pid: i32) -> i32 {
    let mut status = 0;
    // SAFETY: a valid out-parameter.
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    status
}

fn describe(status: i32) -> String {
    if status & 0x7f == 0 {
        format!("exited {}", (status >> 8) & 0xff)
    } else {
        format!("killed by {}", status & 0x7f)
    }
}

fn gettid() -> i32 {
    // SAFETY: plain system call.
    unsafe { syscall(SYS_GETTID) as i32 }
}

fn tgkill(tid: i32, sig: i32) -> i64 {
    // SAFETY: plain system call.
    unsafe { syscall(SYS_TGKILL, getpid() as i64, tid as i64, sig as i64) }
}

/// A thread that blocks in `read` on a pipe nobody writes, and reports how
/// the read ended. Returns its tid and the reporting channel.
fn blocked_reader() -> (i32, std::sync::mpsc::Receiver<String>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut fds = [0; 2];
        // SAFETY: a 2-element array.
        unsafe { pipe(fds.as_mut_ptr()) };
        tid_tx.send(gettid()).unwrap();
        let mut b = 0u8;
        // SAFETY: a 1-byte buffer.
        let r = unsafe { read(fds[0], &mut b, 1) };
        let e = errno();
        tx.send(if r < 0 && e == EINTR { "EINTR".into() } else { format!("read {r} errno {e}") })
            .unwrap();
    });
    let tid = tid_rx.recv().unwrap();
    (tid, rx)
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    match scenario.as_str() {
        // The parent kills a child that waits forever.
        "kill-child" => {
            let pid = child(|| {
                loop {
                    // SAFETY: plain call.
                    unsafe { pause() };
                }
            });
            std::thread::sleep(Duration::from_millis(50));
            // SAFETY: plain call.
            assert_eq!(unsafe { kill(pid, SIGTERM) }, 0);
            println!("{}", describe(wait_status(pid)));
        }
        // A child signals its parent, which learns the sender.
        // A flood of signals while the process makes system calls, which
        // fwe runs inside a host signal handler: each is taken, and none
        // nests the handlers until the signal stack runs out.
        "storm" => {
            catch(SIGUSR1, SA_RESTART);
            catch(SIGUSR2, SA_RESTART);
            let me = std::process::id() as i32;
            // Several senders at once.
            let senders: Vec<i32> = (0..6)
                .map(|_| {
                    child(move || {
                        for i in 0..20_000 {
                            // SAFETY: plain calls.
                            unsafe { kill(me, if i % 2 == 0 { SIGUSR1 } else { SIGUSR2 }) };
                        }
                        0
                    })
                })
                .collect();
            let mut status = 0;
            let mut calls = 0u64;
            let mut left = senders.len();
            while left > 0 {
                // A call with a path, failing: faccessat(AT_FDCWD, ..).
                // SAFETY: plain calls with valid arguments.
                unsafe { syscall(48, -100i64, c"/no/such/file".as_ptr(), 0i64, 0i64) };
                calls += 1;
                // SAFETY: a valid out-parameter.
                if unsafe { waitpid(-1, &mut status, 1) } > 0 {
                    left -= 1;
                }
            }
            println!("survived: {} calls: {}", HITS.load(Ordering::SeqCst) > 0, calls > 0);
        }
        "notify-parent" => {
            // The child may signal before the parent's `fork` returns, while
            // musl's `fork` blocks every signal: the sender is kept either
            // way. If it arrives before the wait, the wait returns at once.
            catch(SIGUSR1, 0);
            let pid = child(|| {
                // SAFETY: plain calls.
                unsafe { kill(getppid(), SIGUSR1) };
                0
            });
            suspend_until_hit();
            println!("SIGUSR1 from child: {}", LAST_PID.load(Ordering::SeqCst) == pid);
            println!("{}", describe(wait_status(pid)));
        }
        // A signal kept pending while blocked keeps its sender, as on
        // Linux (macOS forgets the sender of a signal it holds blocked):
        // the child has signalled and exited before the parent unblocks.
        "notify-parent-blocked" => {
            catch(SIGUSR1, 0);
            block(&[SIGUSR1]);
            let pid = child(|| {
                // SAFETY: plain calls.
                unsafe { kill(getppid(), SIGUSR1) };
                0
            });
            let status = wait_status(pid);
            suspend_until_hit();
            println!("SIGUSR1 from child: {}", LAST_PID.load(Ordering::SeqCst) == pid);
            println!("{}", describe(status));
        }
        // The same taken with sigtimedwait, whose siginfo names the sender.
        "sigwait-from-child" => {
            block(&[SIGUSR2]);
            let pid = child(|| {
                // SAFETY: plain calls.
                unsafe { kill(getppid(), SIGUSR2) };
                0
            });
            let status = wait_status(pid);
            // SAFETY: zeroed bytes are a valid siginfo.
            let mut info: SigInfo = unsafe { std::mem::zeroed() };
            let ts = Timespec { sec: 5, nsec: 0 };
            // SAFETY: valid set, info and timeout.
            let r = unsafe { sigtimedwait(&set(&[SIGUSR2]), &mut info, &ts) };
            println!("took {r} from child: {}", info.pid == pid);
            println!("{}", describe(status));
        }
        // A signal sent with tgkill to a thread that blocks it waits for
        // that thread, even while another thread accepts it.
        "tgkill-blocked" => {
            catch(SIGUSR1, 0);
            let (tid_tx, tid_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
            std::thread::spawn(move || {
                // SAFETY: a valid signal set.
                unsafe { pthread_sigmask(SIG_BLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
                tid_tx.send(gettid()).unwrap();
                go_rx.recv().unwrap();
                // SAFETY: a valid signal set.
                unsafe { pthread_sigmask(SIG_UNBLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let worker = tid_rx.recv().unwrap();
            assert_eq!(tgkill(worker, SIGUSR1), 0);
            // The main thread accepts it, and must not take it meanwhile.
            std::thread::sleep(Duration::from_millis(200));
            let early = HITS.load(Ordering::SeqCst);
            go_tx.send(()).unwrap();
            while HITS.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            println!(
                "held for the blocking thread: {}, then handled on it: {}",
                early == 0,
                LAST_TID.load(Ordering::SeqCst) == worker
            );
        }
        // A signal whose default action ends the process stays pending
        // while every thread blocks it.
        "default-blocked" => {
            block(&[SIGUSR1]);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                // Inherits the blocked mask.
                ready_tx.send(()).unwrap();
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            ready_rx.recv().unwrap();
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGUSR1) };
            std::thread::sleep(Duration::from_millis(200));
            let mut pending = SigSet([0; 16]);
            // SAFETY: a valid out-parameter.
            unsafe { sigpending(&mut pending) };
            println!("still running, pending: {}", pending.0[0] & 1 << (SIGUSR1 - 1) != 0);
        }
        // SIGTSTP's default action stops the process, and the parent's
        // waitpid reports that signal.
        "stop-tstp" => {
            let pid = child(|| {
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            // SAFETY: plain calls.
            unsafe { kill(pid, SIGTSTP) };
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            assert_eq!(unsafe { waitpid(pid, &mut status, WUNTRACED) }, pid);
            let stopped = status & 0xff == 0x7f;
            println!("stopped: {stopped}, by {}", (status >> 8) & 0xff);
            // SAFETY: plain calls.
            unsafe {
                kill(pid, SIGCONT);
                kill(pid, SIGKILL);
            }
            println!("{}", describe(wait_status(pid)));
        }
        // SIGCHLD reaches a handler, with the exit status.
        // `sigchld-late`: the child has exited, and its SIGCHLD waited
        // blocked, before the parent waits for it.
        "sigchld" | "sigchld-late" => {
            catch(SIGCHLD, 0);
            block(&[SIGCHLD]);
            let pid = child(|| 3);
            if scenario == "sigchld-late" {
                std::thread::sleep(Duration::from_millis(300));
            }
            suspend_until_hit();
            println!(
                "SIGCHLD from child: {}, status {}",
                LAST_PID.load(Ordering::SeqCst) == pid,
                LAST_STATUS.load(Ordering::SeqCst)
            );
            println!("{}", describe(wait_status(pid)));
        }
        // A timer interrupts a blocking read; SA_RESTART decides whether the
        // read resumes or fails with EINTR.
        "restart" | "no-restart" => {
            catch(SIGALRM, if scenario == "restart" { SA_RESTART } else { 0 });
            let mut fds = [0; 2];
            // SAFETY: a 2-element array.
            unsafe { pipe(fds.as_mut_ptr()) };
            let writer = fds[1];
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                // SAFETY: a 1-byte buffer.
                unsafe { write(writer, b"x".as_ptr(), 1) };
            });
            let timer = Itimerval {
                interval: Timeval { sec: 0, usec: 0 },
                value: Timeval { sec: 0, usec: 50_000 },
            };
            // SAFETY: a valid itimerval.
            unsafe { setitimer(0, &timer, std::ptr::null_mut()) };
            let mut b = 0u8;
            // SAFETY: a 1-byte buffer.
            let r = unsafe { read(fds[0], &mut b, 1) };
            let what = if r < 0 { format!("errno {}", errno()) } else { format!("{r} byte") };
            println!("read: {what}, handler ran {} time(s)", HITS.load(Ordering::SeqCst));
        }
        // A timer signal interrupts a loop that makes no system calls; the
        // handler runs and the loop sees its flag.
        "busy-alarm" => {
            catch(SIGALRM, 0);
            let timer = Itimerval {
                interval: Timeval { sec: 0, usec: 0 },
                value: Timeval { sec: 0, usec: 50_000 },
            };
            // SAFETY: a valid itimerval.
            unsafe { setitimer(0, &timer, std::ptr::null_mut()) };
            let start = std::time::Instant::now();
            let mut spins = 0u64;
            while HITS.load(Ordering::SeqCst) == 0 && spins < 20_000_000_000 {
                spins += 1;
                std::hint::spin_loop();
            }
            let _ = start;
            println!("busy loop interrupted: {}", HITS.load(Ordering::SeqCst) == 1);
        }
        // pause() returns once a handler has run.
        "pause" => {
            catch(SIGALRM, 0);
            let timer = Itimerval {
                interval: Timeval { sec: 0, usec: 0 },
                value: Timeval { sec: 0, usec: 30_000 },
            };
            // SAFETY: a valid itimerval.
            unsafe { setitimer(0, &timer, std::ptr::null_mut()) };
            // SAFETY: plain call.
            let r = unsafe { pause() };
            println!(
                "pause: {r} errno {}, handler ran: {}",
                errno(),
                HITS.load(Ordering::SeqCst) == 1
            );
        }
        // A process-wide signal goes to the thread that does not block it.
        "thread-mask" => {
            catch(SIGUSR1, 0);
            // The main thread blocks it; threads spawned now inherit that.
            // SAFETY: a valid signal set.
            unsafe { pthread_sigmask(SIG_BLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
            let (tid_tx, tid_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                // SAFETY: a valid signal set.
                unsafe { pthread_sigmask(SIG_UNBLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
                tid_tx.send(gettid()).unwrap();
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let worker = tid_rx.recv().unwrap();
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGUSR1) };
            while HITS.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            println!(
                "handled on the unblocked thread: {}",
                LAST_TID.load(Ordering::SeqCst) == worker
            );
        }
        // A process signal sent while every thread blocks it goes to the
        // first thread to unblock it, even though the host parks it on
        // another thread (macOS picks the main one, which blocks it for
        // good).
        "parked" => {
            catch(SIGUSR1, 0);
            // SAFETY: a valid signal set.
            unsafe { pthread_sigmask(SIG_BLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
            let (tid_tx, tid_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                go_rx.recv().unwrap();
                // SAFETY: a valid signal set.
                unsafe { pthread_sigmask(SIG_UNBLOCK, &set(&[SIGUSR1]), std::ptr::null_mut()) };
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let worker = tid_rx.recv().unwrap();
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGUSR1) };
            go_tx.send(()).unwrap();
            while HITS.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            println!(
                "parked signal handled on the unblocked thread: {}",
                LAST_TID.load(Ordering::SeqCst) == worker
            );
        }
        // tgkill interrupts one thread's blocking call: a relayed signal and
        // a real-time one (which the host does not have).
        "tgkill" => {
            for sig in [SIGUSR2, SIGRT] {
                catch(sig, 0);
                let (tid, rx) = blocked_reader();
                // Resend until the read is interrupted: a signal that lands
                // before the thread reaches `read` only runs the handler.
                let mut outcome = String::from("stuck");
                for _ in 0..50 {
                    assert_eq!(tgkill(tid, sig), 0);
                    if let Ok(o) = rx.recv_timeout(Duration::from_millis(100)) {
                        outcome = o;
                        break;
                    }
                }
                println!(
                    "signal {sig}: reader {outcome}, handled on it: {}",
                    LAST_TID.load(Ordering::SeqCst) == tid
                );
            }
        }
        // A real-time signal sent to the process itself.
        "rt-self" => {
            catch(SIGRT, 0);
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGRT) };
            println!(
                "handled: {}, signal {}",
                HITS.load(Ordering::SeqCst),
                LAST_SIG.load(Ordering::SeqCst)
            );
        }
        // Writing to a pipe with no reader kills the writer by default.
        "sigpipe" => {
            let act = SigAction { handler: SIG_DFL, mask: SigSet([0; 16]), flags: 0, restorer: 0 };
            // SAFETY: a valid sigaction (the Rust runtime ignores SIGPIPE).
            unsafe { sigaction(SIGPIPE, &act, std::ptr::null_mut()) };
            let mut fds = [0; 2];
            // SAFETY: plain calls on a fresh pipe.
            unsafe {
                pipe(fds.as_mut_ptr());
                close(fds[0]);
                write(fds[1], b"x".as_ptr(), 1);
            }
            println!("still alive");
        }
        // Dispositions inherited as ignored stay ignored.
        "inherited" => {
            for sig in [SIGHUP, SIGINT] {
                let mut old =
                    SigAction { handler: 99, mask: SigSet([0; 16]), flags: 0, restorer: 0 };
                // SAFETY: querying into a valid sigaction.
                unsafe { sigaction(sig, std::ptr::null(), &mut old) };
                let what = match old.handler {
                    SIG_IGN => "ignored",
                    SIG_DFL => "default",
                    _ => "other",
                };
                println!("signal {sig}: {what}");
            }
        }
        // sigtimedwait takes a blocked pending signal, then times out.
        "sigtimedwait" => {
            block(&[SIGUSR2]);
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGUSR2) };
            let mut info: SigInfo = unsafe { std::mem::zeroed() };
            let ts = Timespec { sec: 1, nsec: 0 };
            // SAFETY: valid set, info and timeout.
            let r = unsafe { sigtimedwait(&set(&[SIGUSR2]), &mut info, &ts) };
            // SAFETY: plain call.
            println!("took {r}, code {}", info.code);
            let ts = Timespec { sec: 0, nsec: 50_000_000 };
            // SAFETY: as above.
            let r = unsafe { sigtimedwait(&set(&[SIGUSR2]), &mut info, &ts) };
            println!(
                "then {r} errno {}",
                if errno() == EAGAIN { "EAGAIN".into() } else { errno().to_string() }
            );
        }
        // std::process::Command spawns with posix_spawn (a vfork-style clone).
        "spawn" => {
            let exe = std::env::current_exe().unwrap();
            let out = std::process::Command::new(exe).arg("spawned").output().unwrap();
            print!("child said: {}", String::from_utf8_lossy(&out.stdout));
            println!("child {}", out.status);
        }
        // The same with the child sharing this process's stdio.
        "spawn-status" => {
            let exe = std::env::current_exe().unwrap();
            let status = std::process::Command::new(exe).arg("spawned").status().unwrap();
            println!("child {status}");
        }
        "exec-self" => {
            unsafe extern "C" {
                fn execve(p: *const u8, a: *const *const u8, e: *const *const u8) -> i32;
            }
            let exe = std::env::current_exe().unwrap();
            let mut path = exe.into_os_string().into_encoded_bytes();
            path.push(0);
            let argv = [path.as_ptr(), b"spawned\0".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            // SAFETY: valid NUL-terminated arrays.
            unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            println!("execve failed: {}", errno());
        }
        "vfork-exec" => {
            unsafe extern "C" {
                fn vfork() -> i32;
                fn execve(p: *const u8, a: *const *const u8, e: *const *const u8) -> i32;
            }
            let exe = std::env::current_exe().unwrap();
            let mut path = exe.into_os_string().into_encoded_bytes();
            path.push(0);
            let argv = [path.as_ptr(), b"spawned\0".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            // SAFETY: the child only execs or exits.
            let pid = unsafe { vfork() };
            if pid == 0 {
                // SAFETY: valid NUL-terminated arrays.
                unsafe {
                    execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                    _exit(127)
                }
            }
            println!("{}", describe(wait_status(pid)));
        }
        "spawned" => println!("hello from the spawned child"),
        // Code written into writable and executable memory, as a JIT
        // compiler does: run, rewritten in place and run again, one piece
        // making a system call itself. Then the cache type register, which
        // code that flushes the caches reads.
        "jit" => {
            // SAFETY: a fresh anonymous mapping, PROT_READ | WRITE | EXEC.
            let code = unsafe { mmap(std::ptr::null_mut(), 16384, 7, 0x22, -1, 0) };
            assert!(!code.is_null() && code as isize != -1, "mmap failed");
            let run = |words: &[u32]| -> u64 {
                // SAFETY: writing instructions into the mapping, then making
                // them visible to instruction fetch as Linux requires.
                unsafe {
                    let w = code.cast::<u32>();
                    for (i, &word) in words.iter().enumerate() {
                        w.add(i).write_volatile(word);
                    }
                    for i in 0..words.len() {
                        let at = w.add(i);
                        std::arch::asm!("dc cvau, {0}", "dsb ish", "ic ivau, {0}", in(reg) at);
                    }
                    std::arch::asm!("dsb ish", "isb");
                    let f: extern "C" fn() -> u64 = std::mem::transmute(code);
                    f()
                }
            };
            let ret = 0xd65f_03c0; // ret
            let first = run(&[0x5280_0540, ret]); // mov w0, #42
            let second = run(&[0x5280_00e0, ret]); // mov w0, #7
            // mov x8, #172 (getpid); svc #0
            let pid = run(&[0xd280_1588, 0xd400_0001, ret]);
            // SAFETY: plain call.
            let mine = unsafe { getpid() } as u64;
            let ctr: u64;
            // SAFETY: reading the cache type register.
            unsafe { std::arch::asm!("mrs {}, ctr_el0", out(reg) ctr) };
            println!("jit: {first} {second}, getpid matches: {}", pid == mine);
            println!("ctr_el0 has cache lines: {}", ctr & 0xf != 0 && (ctr >> 16) & 0xf != 0);
        }
        // fork from a process with another thread running.
        "threaded-fork" => {
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let s = stop.clone();
            let t = std::thread::spawn(move || {
                let mut n = 0u64;
                while !s.load(Ordering::Relaxed) {
                    n = n.wrapping_add(1);
                    std::thread::sleep(Duration::from_millis(1));
                }
                n
            });
            std::thread::sleep(Duration::from_millis(20));
            let pid = child(|| {
                println!("child of a threaded parent");
                5
            });
            println!("{}", describe(wait_status(pid)));
            stop.store(true, Ordering::Relaxed);
            t.join().unwrap();
        }
        // A fork child gets the parent's memory as it was at the fork, and
        // neither side sees the other's later writes, except to shared
        // memory: in the executable's image, the heap and a MAP_SHARED
        // mapping.
        "fork-cow" => {
            static IMAGE: AtomicU8 = AtomicU8::new(b'p');
            let mut heap = vec![b'p'; 1 << 20];
            // SAFETY: a fresh shared anonymous mapping.
            let shared = unsafe { mmap(std::ptr::null_mut(), 1 << 16, 3, 0x21, -1, 0) };
            assert!(!shared.is_null() && shared as isize != -1);
            // SAFETY: the mapping is 64 KiB.
            unsafe { *shared = b'p' };
            let (mut down, mut up) = ([0i32; 2], [0i32; 2]);
            // SAFETY: valid two-element arrays.
            unsafe { assert!(pipe(down.as_mut_ptr()) == 0 && pipe(up.as_mut_ptr()) == 0) };
            let byte = |fd: i32| {
                let mut b = 0u8;
                // SAFETY: one byte into a local.
                unsafe { read(fd, &mut b, 1) };
            };
            let send = |fd: i32| {
                // SAFETY: one byte from a constant.
                unsafe { write(fd, b"x".as_ptr(), 1) };
            };
            let last = heap.len() - 1;
            let pid = {
                let heap = heap.as_mut_ptr();
                child(move || {
                    // SAFETY: the heap buffer and the mapping are the
                    // child's copy (and the shared mapping) after the fork.
                    unsafe {
                        let saw = [IMAGE.load(Ordering::Relaxed), *heap, *heap.add(last), *shared];
                        byte(down[0]);
                        let unchanged = IMAGE.load(Ordering::Relaxed) == b'p' && *heap == b'p';
                        IMAGE.store(b'c', Ordering::Relaxed);
                        *heap = b'c';
                        *shared = b'c';
                        println!("child sees the fork-time memory: {}", saw == [b'p'; 4]);
                        println!("parent's later writes unseen: {unchanged}");
                    }
                    send(up[1]);
                    0
                })
            };
            IMAGE.store(b'P', Ordering::Relaxed);
            heap[0] = b'P';
            send(down[1]);
            byte(up[0]);
            let status = wait_status(pid);
            let mine = IMAGE.load(Ordering::Relaxed) == b'P' && heap[0] == b'P';
            println!("child's writes unseen: {mine}");
            // SAFETY: the mapping is still there.
            println!("shared memory shared: {}", unsafe { *shared } == b'c');
            println!("{}", describe(status));
        }
        // A fork child reading a pipe until its end: the end comes once
        // the parent closes its write end, as no one else holds one.
        "fork-pipe" => {
            let mut p = [0i32; 2];
            // SAFETY: a valid two-element array.
            unsafe { assert!(pipe(p.as_mut_ptr()) == 0) };
            let pid = child(move || {
                // SAFETY: the child's own descriptors and a local buffer.
                unsafe {
                    close(p[1]);
                    let (mut got, mut b) = (0, [0u8; 16]);
                    loop {
                        let n = read(p[0], b.as_mut_ptr(), b.len());
                        if n <= 0 {
                            break;
                        }
                        got += n;
                    }
                    println!("child read {got} bytes, then the end");
                }
                0
            });
            // SAFETY: the parent's own descriptors.
            unsafe {
                close(p[0]);
                write(p[1], b"hello".as_ptr(), 5);
                close(p[1]);
            }
            println!("{}", describe(wait_status(pid)));
        }
        // A fork while another thread writes sees one instant of the
        // process: the thread bumps a counter in the executable's image and
        // then one on the heap, so any instant has them equal or the first
        // one ahead by one, wherever in memory each lives.
        "fork-snapshot" => {
            static FIRST: AtomicU64 = AtomicU64::new(0);
            let second = std::sync::Arc::new(AtomicU64::new(0));
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let (s, st) = (second.clone(), stop.clone());
            let t = std::thread::spawn(move || {
                let mut n = 0u64;
                while !st.load(Ordering::Relaxed) {
                    n += 1;
                    FIRST.store(n, Ordering::SeqCst);
                    s.store(n, Ordering::SeqCst);
                }
            });
            std::thread::sleep(Duration::from_millis(10));
            let mut consistent = 0;
            for _ in 0..8 {
                let second = second.clone();
                let pid = child(move || {
                    let (a, b) = (FIRST.load(Ordering::SeqCst), second.load(Ordering::SeqCst));
                    (a != b && a != b + 1) as i32
                });
                if wait_status(pid) == 0 {
                    consistent += 1;
                }
            }
            stop.store(true, Ordering::Relaxed);
            t.join().unwrap();
            println!("consistent snapshots: {consistent} of 8");
        }
        // A fork child can use the epoll and timerfd descriptors it
        // inherited (kqueues on macOS, which a child does not inherit).
        "fork-epoll" => {
            let mut p = [0i32; 2];
            // SAFETY: a valid two-element array.
            assert_eq!(unsafe { pipe(p.as_mut_ptr()) }, 0);
            // SAFETY: plain calls; the event is an arm64 epoll_event, with
            // its data word at offset 8.
            let ep = unsafe { epoll_create1(0) };
            let mut ev = [0u8; 16];
            ev[0] = 1; // EPOLLIN
            ev[8..].copy_from_slice(&42u64.to_ne_bytes());
            assert_eq!(unsafe { epoll_ctl(ep, 1, p[0], ev.as_mut_ptr()) }, 0);
            // A one-shot timer 50 ms out.
            // SAFETY: plain calls with a valid itimerspec.
            let tfd = unsafe { timerfd_create(1, 0) };
            let spec = [Timespec { sec: 0, nsec: 0 }, Timespec { sec: 0, nsec: 50_000_000 }];
            assert_eq!(unsafe { timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) }, 0);
            let pid = child(move || {
                let mut got = [0u8; 16];
                // SAFETY: room for one event.
                let n = unsafe { epoll_wait(ep, got.as_mut_ptr(), 1, 5000) };
                let data = u64::from_ne_bytes(got[8..].try_into().unwrap());
                println!("child's epoll: {n} event(s), data {data}");
                let mut count = 0u64;
                // SAFETY: an 8-byte read into a local.
                let r = unsafe { read(tfd, (&mut count as *mut u64).cast(), 8) };
                println!("child's timer fired: {}", r == 8 && count >= 1);
                0
            });
            // SAFETY: one byte from a constant.
            unsafe { write(p[1], b"x".as_ptr(), 1) };
            println!("{}", describe(wait_status(pid)));
        }
        // A one-shot timer that expired before the fork, unread, is read in
        // the child; one the parent read is not, in the child either.
        "fork-timerfd" => {
            let spec = [Timespec { sec: 0, nsec: 0 }, Timespec { sec: 0, nsec: 1_000_000 }];
            // SAFETY: plain calls with a valid itimerspec; 2048 is
            // TFD_NONBLOCK.
            let unread = unsafe { timerfd_create(1, 2048) };
            let read_ = unsafe { timerfd_create(1, 2048) };
            assert_eq!(unsafe { timerfd_settime(unread, 0, &spec, std::ptr::null_mut()) }, 0);
            assert_eq!(unsafe { timerfd_settime(read_, 0, &spec, std::ptr::null_mut()) }, 0);
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut count = 0u64;
            // SAFETY: an 8-byte read into a local.
            let r = unsafe { read(read_, (&mut count as *mut u64).cast(), 8) };
            println!("parent read its expiration: {}", r == 8 && count == 1);
            let pid = child(move || {
                let mut count = 0u64;
                // SAFETY: 8-byte reads into a local.
                let r = unsafe { read(unread, (&mut count as *mut u64).cast(), 8) };
                println!("child reads the unread expiration: {}", r == 8 && count == 1);
                let r = unsafe { read(read_, (&mut count as *mut u64).cast(), 8) };
                println!("child finds the read one empty: {}", r < 0 && errno() == 11);
                0
            });
            println!("{}", describe(wait_status(pid)));
        }
        // clone3 in its fork form: no flags, SIGCHLD as the exit signal.
        "clone3-fork" => {
            let mut args = [0u64; 11];
            args[4] = SIGCHLD as u64;
            // SAFETY: a valid struct clone_args; the child only prints and exits.
            let pid = unsafe { syscall(435, args.as_ptr(), 88usize) } as i32;
            assert!(pid >= 0, "clone3 failed: {}", errno());
            if pid == 0 {
                println!("clone3 child");
                // SAFETY: ending the child.
                unsafe { _exit(3) }
            }
            println!("{}", describe(wait_status(pid)));
        }
        // execveat: a path relative to a directory descriptor, the open file
        // itself (AT_EMPTY_PATH), and a symbolic link refused under
        // AT_SYMLINK_NOFOLLOW.
        "execveat" => {
            const AT_FDCWD: i64 = -100;
            const AT_SYMLINK_NOFOLLOW: i64 = 0x100;
            const AT_EMPTY_PATH: i64 = 0x1000;
            unsafe extern "C" {
                fn open(path: *const u8, flags: i32, ...) -> i32;
            }
            let exe = std::env::current_exe().unwrap();
            let cstr = |p: &std::path::Path| {
                let mut v = p.as_os_str().as_encoded_bytes().to_vec();
                v.push(0);
                v
            };
            let dir = cstr(exe.parent().unwrap());
            let base = cstr(std::path::Path::new(exe.file_name().unwrap()));
            let whole = cstr(&exe);
            // SAFETY: NUL-terminated paths; O_RDONLY (with O_DIRECTORY).
            let (dfd, efd) = unsafe { (open(dir.as_ptr(), 0o200000), open(whole.as_ptr(), 0)) };
            assert!(dfd >= 0 && efd >= 0);
            let argv = [whole.as_ptr(), b"spawned\0".as_ptr(), std::ptr::null()];
            let envp: [*const u8; 1] = [std::ptr::null()];
            let execveat = |fd: i64, path: *const u8, flags: i64| {
                // SAFETY: valid NUL-terminated strings and arrays.
                unsafe { syscall(281, fd, path, argv.as_ptr(), envp.as_ptr(), flags) }
            };
            for (label, fd, path, flags) in [
                ("relative to a directory", dfd as i64, base.as_ptr(), 0),
                ("the open file itself", efd as i64, b"\0".as_ptr(), AT_EMPTY_PATH),
            ] {
                let pid = child(|| {
                    execveat(fd, path, flags);
                    127
                });
                println!("{label}: {}", describe(wait_status(pid)));
            }
            let link = std::env::temp_dir().join(format!("fwe-execveat-{}", std::process::id()));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&exe, &link).unwrap();
            let r = execveat(AT_FDCWD, cstr(&link).as_ptr(), AT_SYMLINK_NOFOLLOW);
            println!("symlink with AT_SYMLINK_NOFOLLOW: {r}, errno {}", errno());
            let _ = std::fs::remove_file(&link);
            println!(
                "unknown flag: {}, errno {}",
                execveat(dfd as i64, base.as_ptr(), 0x1),
                errno()
            );
        }
        // execve keeps the credentials (the saved IDs becoming the effective
        // ones), the descriptor limit and the umask, whether the program is
        // replaced in place or, with another thread alive, fwe re-executes
        // itself ("threaded").
        "exec-keeps-ids" => {
            unsafe extern "C" {
                fn setgroups(n: usize, list: *const u32) -> i32;
                fn setresgid(r: u32, e: u32, s: u32) -> i32;
                fn setresuid(r: u32, e: u32, s: u32) -> i32;
                fn setrlimit(res: i32, lim: *const [u64; 2]) -> i32;
                fn umask(mask: u32) -> u32;
                fn execve(p: *const u8, a: *const *const u8, e: *const *const u8) -> i32;
            }
            // SAFETY: plain calls with valid arguments.
            unsafe {
                assert_eq!(setgroups(1, [7u32].as_ptr()), 0);
                assert_eq!(setresgid(20, 21, 22), 0);
                assert_eq!(setresuid(10, 11, 12), 0);
                assert_eq!(setrlimit(7, &[300, 400]), 0); // RLIMIT_NOFILE
                umask(0o027);
            }
            if std::env::args().nth(2).as_deref() == Some("threaded") {
                std::thread::spawn(|| {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                });
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut path = std::env::current_exe().unwrap().into_os_string().into_encoded_bytes();
            path.push(0);
            let argv = [path.as_ptr(), b"report-ids\0".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            // SAFETY: valid NUL-terminated arrays.
            unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            println!("execve failed: {}", errno());
        }
        "report-ids" => {
            unsafe extern "C" {
                fn getresuid(r: *mut u32, e: *mut u32, s: *mut u32) -> i32;
                fn getresgid(r: *mut u32, e: *mut u32, s: *mut u32) -> i32;
                fn getgroups(n: i32, list: *mut u32) -> i32;
                fn getrlimit(res: i32, lim: *mut [u64; 2]) -> i32;
                fn umask(mask: u32) -> u32;
            }
            let (mut u, mut g, mut groups, mut lim) = ([0u32; 3], [0u32; 3], [0u32; 8], [0u64; 2]);
            // SAFETY: valid out-parameters.
            let (n, mask) = unsafe {
                getresuid(&mut u[0], &mut u[1], &mut u[2]);
                getresgid(&mut g[0], &mut g[1], &mut g[2]);
                getrlimit(7, &mut lim);
                (getgroups(8, groups.as_mut_ptr()), umask(0))
            };
            println!(
                "uids {u:?} gids {g:?} groups {:?} nofile {lim:?} umask {mask:o}",
                &groups[..n.max(0) as usize]
            );
        }
        // waitid reports exits and kills as siginfo.
        "waitid" => {
            let pid = child(|| 6);
            let mut info: SigInfo = unsafe { std::mem::zeroed() };
            // SAFETY: a valid out-parameter.
            assert_eq!(unsafe { waitid(P_PID, pid as u32, &mut info, WEXITED) }, 0);
            println!(
                "exited: {}, status {}, pid matches: {}",
                info.code == CLD_EXITED,
                info.status,
                info.pid == pid
            );
            let pid = child(|| {
                loop {
                    // SAFETY: plain call.
                    unsafe { pause() };
                }
            });
            // SAFETY: plain call.
            unsafe { kill(pid, SIGKILL) };
            // SAFETY: a valid out-parameter.
            assert_eq!(unsafe { waitid(P_PID, pid as u32, &mut info, WEXITED) }, 0);
            println!("killed: {}, signal {}", info.code == CLD_KILLED, info.status);
        }
        // Resource usage comes back in Linux units (maxrss in KiB).
        "rusage" => {
            let pid = child(|| {
                let mut x = 0u64;
                for i in 0..20_000_000u64 {
                    x = x.wrapping_mul(31).wrapping_add(i);
                }
                (x & 1) as i32
            });
            let mut usage: Rusage = unsafe { std::mem::zeroed() };
            let mut status = 0;
            // SAFETY: valid out-parameters.
            assert_eq!(unsafe { wait4(pid, &mut status, 0, &mut usage) }, pid);
            let cpu = usage.utime.sec * 1_000_000 + usage.utime.usec;
            println!("child used cpu: {}", cpu > 0);
            let plausible = |kib: i64| (1_000..10_000_000).contains(&kib);
            println!("child maxrss plausible: {}", plausible(usage.maxrss));
            // SAFETY: a valid out-parameter.
            unsafe { getrusage(0, &mut usage) };
            println!("own maxrss plausible: {}", plausible(usage.maxrss));
        }
        // The fault signals sent rather than raised by an instruction reach
        // their handlers, and an ignored one is ignored.
        "raise-faults" => {
            for sig in [SIGSEGV, SIGFPE, SIGTRAP] {
                HITS.store(0, Ordering::SeqCst);
                catch(sig, 0);
                // SAFETY: plain call.
                unsafe { raise(sig) };
                println!("signal {sig}: handled {}", HITS.load(Ordering::SeqCst));
            }
            // SAFETY: plain calls.
            unsafe {
                signal(SIGTRAP, SIG_IGN);
                raise(SIGTRAP);
            }
            println!("ignored SIGTRAP: still running");
        }
        // A real-time signal sent to the process wakes a thread waiting for
        // it in sigtimedwait.
        "rt-to-waiter" => {
            block(&[SIGRT]);
            let t = std::thread::spawn(|| {
                // SAFETY: a valid set; no info, no timeout.
                unsafe { sigtimedwait(&set(&[SIGRT]), std::ptr::null_mut(), std::ptr::null()) }
            });
            std::thread::sleep(Duration::from_millis(100));
            // SAFETY: plain calls.
            unsafe { kill(getpid(), SIGRT) };
            println!("waiter took {}", t.join().unwrap());
        }
        // A signal for a signalfd that the host hands to a thread waiting on
        // a futex (here the main thread, joining the reader) still reaches
        // the reader.
        "signalfd-join" => {
            block(&[SIGUSR1]);
            // SAFETY: a valid set.
            let fd = unsafe { signalfd(-1, &set(&[SIGUSR1]), 0) };
            let reader = std::thread::spawn(move || {
                let mut b = [0u8; 128];
                // SAFETY: a 128-byte buffer.
                let r = unsafe { read(fd, b.as_mut_ptr(), 128) };
                (r, b[0])
            });
            let pid = child(|| {
                std::thread::sleep(Duration::from_millis(100));
                // SAFETY: plain calls.
                unsafe { kill(getppid(), SIGUSR1) };
                0
            });
            let (r, sig) = reader.join().unwrap();
            println!("reader got {r} bytes for signal {sig}");
            wait_status(pid);
        }
        // ppoll's mask applies while it waits: the blocked signal wakes it.
        "ppoll-mask" => {
            catch(SIGUSR1, 0);
            block(&[SIGUSR1]);
            let pid = child(|| {
                std::thread::sleep(Duration::from_millis(100));
                // SAFETY: plain calls.
                unsafe { kill(getppid(), SIGUSR1) };
                0
            });
            // SAFETY: no descriptors, no timeout, an empty mask.
            let r = unsafe { ppoll(std::ptr::null_mut(), 0, std::ptr::null(), &set(&[])) };
            println!("ppoll {r} errno {}, handled {}", errno(), HITS.load(Ordering::SeqCst));
            wait_status(pid);
        }
        other => {
            eprintln!("unknown scenario {other:?}");
            std::process::exit(2);
        }
    }
}
