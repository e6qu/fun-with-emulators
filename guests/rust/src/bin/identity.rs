//! Processes, identities and resources, one check per subcommand: what a
//! guest can do to a host process fwe did not start, signals between
//! processes and their senders' ids, and the limits and controls applied
//! to processes and memory. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char, c_void};

const SYS_PROCESS_VM_READV: i64 = 270;
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;
const SIGUSR1: i32 = 10;
const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;
const SIGTSTP: i32 = 20;
const CLONE_NEWPID: i32 = 0x2000_0000;
const SIGRT1: i32 = 35;
const SIGRT2: i32 = 36;
const SIGCHLD: i32 = 17;
const SI_QUEUE: i32 = -1;
const SI_USER: i32 = 0;
const SYS_RT_SIGQUEUEINFO: i64 = 138;
const P_PID: i32 = 1;
const WEXITED: i32 = 4;
const O_RDONLY: i32 = 0;
const SIG_BLOCK: i32 = 0;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn kill(pid: i32, sig: i32) -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn fork() -> i32;
    fn getpid() -> i32;
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn setuid(uid: u32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut c_void, len: usize) -> isize;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn sigprocmask(how: i32, set: *const u64, old: *mut u64) -> i32;
    fn sigtimedwait(set: *const u64, info: *mut [u8; 128], timeout: *const Timespec) -> i32;
    fn _exit(code: i32) -> !;
    fn unshare(flags: i32) -> i32;
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn write(fd: i32, buf: *const c_void, len: usize) -> isize;
    fn usleep(us: u32) -> i32;
    fn waitid(idtype: i32, id: u32, info: *mut [u8; 128], options: i32) -> i32;
    fn __errno_location() -> *mut i32;
}

fn sigset(sig: i32) -> u64 {
    1 << (sig - 1)
}

/// Wait up to `ms` milliseconds for blocked signal `sig`, with what it
/// carries.
fn wait_for(sig: i32, ms: i64) -> Option<[u8; 128]> {
    let set = sigset(sig);
    let mut info = [0u8; 128];
    let t = Timespec { sec: ms / 1000, nsec: ms % 1000 * 1_000_000 };
    // SAFETY: a valid set, buffer and timeout.
    (unsafe { sigtimedwait(&set, &mut info, &t) } == sig).then_some(info)
}

/// Fork a child that waits for pipe `go` to close, runs `f`, and exits
/// with what it returns.
fn child(go: [i32; 2], f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: plain calls into the C library.
    unsafe {
        let pid = fork();
        if pid == 0 {
            close(go[1]);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            _exit(f());
        }
        pid
    }
}

/// A child's exit status.
fn reap(pid: i32) -> i32 {
    let mut status = 0;
    // SAFETY: plain call into the C library.
    unsafe { waitpid(pid, &mut status, 0) };
    (status >> 8) & 0xff
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

/// A call's result as Linux's errno name, or `ok`.
fn outcome(r: i64) -> String {
    if r >= 0 {
        return "ok".into();
    }
    match errno() {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        11 => "EAGAIN",
        13 => "EACCES",
        22 => "EINVAL",
        e => return format!("errno {e}"),
    }
    .into()
}

/// A host process fwe did not start (`pid`, which the test started):
/// what reaches it. Asking it for a descriptor or its memory needs an fwe
/// process to answer, and a signal the host lacks needs fwe's mailbox:
/// each is refused, and the process lives on.
fn host_process(pid: i32) {
    // SAFETY: plain calls into the C library and the kernel.
    unsafe {
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(pid), 0i64);
        println!("pidfd_open: {}", outcome(fd));
        println!("pidfd_getfd: {}", outcome(syscall(SYS_PIDFD_GETFD, fd, 0i64, 0i64)));
        let mut buf = [0u8; 8];
        let local = [buf.as_mut_ptr() as u64, 8];
        let remote = [0x1_0000u64, 8];
        let r = syscall(SYS_PROCESS_VM_READV, i64::from(pid), local.as_ptr(), 1i64, remote.as_ptr(), 1i64, 0i64);
        println!("process_vm_readv: {}", outcome(r));
        let path = CString::new(format!("/proc/{pid}/mem")).unwrap();
        let mem = open(path.as_ptr(), O_RDONLY);
        println!("/proc/<pid>/mem: {}", outcome(i64::from(mem)));
        if mem >= 0 {
            close(mem);
        }
        println!("kill real-time: {}", outcome(i64::from(kill(pid, SIGRT1))));
        let r = syscall(SYS_PIDFD_SEND_SIGNAL, fd, i64::from(SIGRT1), 0i64, 0i64);
        println!("pidfd_send_signal real-time: {}", outcome(r));
        close(fd as i32);
    }
}

static HANDLED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn count(_: i32) {
    HANDLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// A pid namespace's init takes only the signals it has a handler for:
/// `SIGTERM` and `SIGTSTP` with their default actions are dropped, from
/// itself, a child in its namespace and its parent outside it; `SIGUSR1`,
/// which it handles, arrives; `SIGKILL` from outside ends it.
fn init_signals() {
    // SAFETY: plain calls into the C library.
    unsafe {
        if unshare(CLONE_NEWPID) != 0 {
            println!("unshare: errno {}", errno());
            return;
        }
        let (mut ready, mut go) = ([0i32; 2], [0i32; 2]);
        pipe(ready.as_mut_ptr());
        pipe(go.as_mut_ptr());
        let init = fork();
        if init == 0 {
            close(ready[0]);
            close(go[1]);
            signal(SIGUSR1, count);
            let own = kill(1, SIGTERM);
            let stop = kill(1, SIGTSTP);
            let c = fork();
            if c == 0 {
                _exit(i32::from(kill(1, SIGTERM) == 0 && kill(1, SIGUSR1) == 0));
            }
            let ok = reap(c);
            usleep(200_000);
            println!(
                "init {}: own SIGTERM {own}, SIGTSTP {stop}, child's sent {}",
                getpid(),
                ok == 1
            );
            write(ready[1], b"r".as_ptr().cast(), 1);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            usleep(200_000);
            println!("init lives, handled SIGUSR1 {}", HANDLED.load(std::sync::atomic::Ordering::SeqCst));
            write(ready[1], b"r".as_ptr().cast(), 1);
            loop {
                usleep(1_000_000);
            }
        }
        close(ready[1]);
        close(go[0]);
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        println!("parent's SIGTERM: {}", kill(init, SIGTERM));
        close(go[1]);
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        kill(init, SIGKILL);
        let mut status = 0;
        waitpid(init, &mut status, 0);
        println!("init killed by {}", status & 0x7f);
    }
}

/// `si_pid` and `si_uid` of a `siginfo`.
fn sender(info: &[u8; 128]) -> (i32, u32) {
    (
        i32::from_ne_bytes(info[16..20].try_into().unwrap()),
        u32::from_ne_bytes(info[20..24].try_into().unwrap()),
    )
}

/// A `siginfo` for `rt_sigqueueinfo`: `sig` with `code`, naming `pid` and
/// `uid` as its sender.
fn queued_info(sig: i32, code: i32, pid: i32, uid: u32) -> [u8; 128] {
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&sig.to_ne_bytes());
    info[8..12].copy_from_slice(&code.to_ne_bytes());
    info[16..20].copy_from_slice(&pid.to_ne_bytes());
    info[20..24].copy_from_slice(&uid.to_ne_bytes());
    info
}

/// The sender's ids each signal carries: its pid and its guest user
/// (not the host's), as `kill` from a process of uid 1000 to another
/// gives them, with a host signal and with one the host lacks;
/// `rt_sigqueueinfo` delivers the caller's own, to itself and to another;
/// a child's `SIGCHLD` and `waitid` name the child's user.
fn sender_ids() {
    // SAFETY: plain calls into the C library and the kernel.
    unsafe {
        let all = sigset(SIGUSR1) | sigset(SIGRT1) | sigset(SIGRT2) | sigset(SIGCHLD);
        sigprocmask(SIG_BLOCK, &all, std::ptr::null_mut());
        let me = getpid();
        kill(me, SIGUSR1);
        let own = wait_for(SIGUSR1, 1000).map(|i| sender(&i));
        println!("own kill: {}", own == Some((me, 0)));
        let info = queued_info(SIGRT1, SI_QUEUE, 4242, 77);
        syscall(SYS_RT_SIGQUEUEINFO, i64::from(me), i64::from(SIGRT1), info.as_ptr());
        println!("own sigqueueinfo: {:?}", wait_for(SIGRT1, 1000).map(|i| sender(&i)));
        let (mut ready, mut report) = ([0i32; 2], [0i32; 2]);
        pipe(ready.as_mut_ptr());
        pipe(report.as_mut_ptr());
        let receiver = fork();
        if receiver == 0 {
            setuid(1000);
            write(ready[1], b"r".as_ptr().cast(), 1);
            let mut line = String::new();
            for sig in [SIGUSR1, SIGRT1, SIGRT2] {
                let got = wait_for(sig, 5000).map(|i| sender(&i));
                line.push_str(&format!("{got:?} "));
            }
            write(report[1], line.as_ptr().cast(), line.len());
            _exit(0);
        }
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let from = fork();
        if from == 0 {
            setuid(1000);
            kill(receiver, SIGUSR1);
            kill(receiver, SIGRT1);
            let info = queued_info(SIGRT2, SI_QUEUE, getpid(), 1000);
            syscall(SYS_RT_SIGQUEUEINFO, i64::from(receiver), i64::from(SIGRT2), info.as_ptr());
            let info = queued_info(SIGRT2, SI_USER, getpid(), 1000);
            let r = syscall(SYS_RT_SIGQUEUEINFO, i64::from(receiver), i64::from(SIGRT2), info.as_ptr());
            _exit(i32::from(r == -1 && errno() == 1));
        }
        let refused = reap(from);
        reap(receiver);
        // SIGCHLD of the sender, the receiver: drained.
        while wait_for(SIGCHLD, 0).is_some() {}
        let mut buf = [0u8; 256];
        let n = read(report[0], buf.as_mut_ptr().cast(), buf.len());
        let text = String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned();
        let want = format!("Some(({from}, 1000)) ").repeat(3);
        println!("from uid 1000: {}, si_code 0 to another refused {}", text == want, refused == 1);
        if text != want {
            println!("  got {text}, wanted {want}");
        }
        let c = fork();
        if c == 0 {
            setuid(1000);
            _exit(3);
        }
        let chld = wait_for(SIGCHLD, 5000).map(|i| sender(&i));
        let mut info = [0u8; 128];
        waitid(P_PID, c as u32, &mut info, WEXITED);
        println!("child's SIGCHLD: {}, waitid: {}", chld == Some((c, 1000)), sender(&info) == (c, 1000));
    }
}

/// `kill(0)` and `kill(-pgid)` from a process of uid 1000, in a group
/// with root's processes and one of uid 1000: each member it may signal
/// takes the signal, the others do not, and a group of root's only gives
/// `EPERM`.
fn group_kill() {
    // SAFETY: plain calls into the C library.
    unsafe {
        let usr1 = sigset(SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, std::ptr::null_mut());
        setpgid(0, 0);
        let mut go = [0i32; 2];
        pipe(go.as_mut_ptr());
        let got = || i32::from(wait_for(SIGUSR1, 1500).is_some());
        let root = child(go, got);
        let user = child(go, || {
            setuid(1000);
            got()
        });
        let other = child(go, got);
        setpgid(other, other);
        let sender = child(go, || {
            setuid(1000);
            let own = kill(0, SIGUSR1) == 0;
            let r = kill(-other, SIGUSR1);
            let refused = r == -1 && errno() == 1;
            i32::from(own) | i32::from(refused) << 1 | i32::from(wait_for(SIGUSR1, 1500).is_some()) << 2
        });
        close(go[1]);
        let s = reap(sender);
        println!(
            "own group: sent {}, sender took it {}, uid 1000 took it {}, root took it {}, parent took it {}",
            s & 1 != 0,
            s & 4 != 0,
            reap(user) == 1,
            reap(root) == 1,
            wait_for(SIGUSR1, 0).is_some()
        );
        println!("root's group: EPERM {}, its member took it {}", s & 2 != 0, reap(other) == 1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    match arg(1) {
        "host-process" => host_process(arg(2).parse().unwrap()),
        "group-kill" => group_kill(),
        "init-signals" => init_signals(),
        "sender-ids" => sender_ids(),
        other => {
            eprintln!("unknown check {other:?}");
            std::process::exit(2);
        }
    }
}
