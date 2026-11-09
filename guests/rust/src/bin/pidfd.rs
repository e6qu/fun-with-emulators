//! Process descriptors: `pidfd_open` of itself and of a child, `poll`
//! and `epoll` for a child's end, `waitid(P_PIDFD)` blocking and not,
//! `pidfd_send_signal` with a value, `PIDFD_GET_INFO` before and after the
//! reap, `clone3` with `CLONE_PIDFD`, a descriptor a fork child inherits,
//! one of a thread (`PIDFD_THREAD`), `pidfd_getfd` of a child's file,
//! `setns` and `PIDFD_GET_UTS_NAMESPACE` into a child's namespace, and the
//! errors Linux gives. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

const SYS_IOCTL: i64 = 29;
const SYS_WAITID: i64 = 95;
const SYS_SETNS: i64 = 268;
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_CLONE3: i64 = 435;
const SYS_PIDFD_GETFD: i64 = 438;
const PIDFD_NONBLOCK: i64 = 0o4000;
const PIDFD_THREAD: i64 = 0o200;
const P_PIDFD: i64 = 3;
const WEXITED: i64 = 4;
const WNOHANG: i64 = 1;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_NEWUTS: i64 = 0x0400_0000;
const SIGCHLD: u64 = 17;
const SIGUSR1: i32 = 10;
const SI_QUEUE: i32 = -1;
const F_GETFD: i32 = 1;
const F_GETFL: i32 = 3;
const O_NONBLOCK: i32 = 0o4000;
const O_RDONLY: i32 = 0;
const O_CREAT: i32 = 0o100;
const O_WRONLY: i32 = 1;
const O_TRUNC: i32 = 0o1000;
const EAGAIN: i32 = 11;
const ESRCH: i32 = 3;
const EINVAL: i32 = 22;
const EBADF: i32 = 9;
const POLLIN: i16 = 1;
const EPOLL_CTL_ADD: i32 = 1;
const EPOLLIN: u32 = 1;
const SA_SIGINFO: u64 = 4;
/// `_IOWR(0xFF, 11, struct pidfd_info)` with the 72-byte structure.
const PIDFD_GET_INFO: u64 = 0xc048_ff0b;
/// `_IO(0xFF, 10)`.
const PIDFD_GET_UTS_NAMESPACE: u64 = 0xff0a;
const PIDFD_INFO_PID: u64 = 1;
const PIDFD_INFO_EXIT: u64 = 8;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

#[repr(C)]
struct SigAction {
    handler: extern "C" fn(i32, *const u8, *mut c_void),
    mask: [u64; 16],
    flags: u64,
    restorer: usize,
}

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn fork() -> i32;
    fn getpid() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut c_void, len: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, len: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn unlink(path: *const c_char) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, ev: *mut EpollEvent) -> i32;
    fn epoll_wait(ep: i32, evs: *mut EpollEvent, n: i32, timeout: i32) -> i32;
    fn readlink(path: *const c_char, buf: *mut c_char, len: usize) -> isize;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn pause() -> i32;
    fn unshare(flags: i32) -> i32;
    fn sethostname(name: *const c_char, len: usize) -> i32;
    fn gethostname(name: *mut c_char, len: usize) -> i32;
    fn usleep(us: u32) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

/// Whether `fd` is readable now, or within `ms` milliseconds.
fn readable(fd: i32, ms: i32) -> bool {
    let mut p = PollFd { fd, events: POLLIN, revents: 0 };
    // SAFETY: one valid pollfd.
    unsafe { poll(&mut p, 1, ms) == 1 && p.revents & POLLIN != 0 }
}

/// `waitid(P_PIDFD, fd, ...)`: its result (0, or -errno) and `si_status`.
fn waitid_pidfd(fd: i32, options: i64) -> (i64, i32) {
    let mut info = [0i32; 32];
    // SAFETY: a 128-byte siginfo_t.
    let r = unsafe { syscall(SYS_WAITID, P_PIDFD, i64::from(fd), info.as_mut_ptr(), options, 0i64) };
    (if r < 0 { -i64::from(errno()) } else { r }, info[6])
}

/// `PIDFD_GET_INFO` asking for `mask`: its result (0 or -errno), the mask
/// given back, the pid and the exit code.
fn info(fd: i32, mask: u64) -> (i64, u64, u32, i32) {
    let mut b = [0u8; 72];
    b[..8].copy_from_slice(&mask.to_ne_bytes());
    // SAFETY: a 72-byte struct pidfd_info.
    let r = unsafe { syscall(SYS_IOCTL, i64::from(fd), PIDFD_GET_INFO, b.as_mut_ptr()) };
    let r = if r < 0 { -i64::from(errno()) } else { r };
    let w = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
    (r, u64::from_ne_bytes(b[..8].try_into().unwrap()), w(16), w(60) as i32)
}

fn link(fd: i32) -> String {
    let p = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let mut buf = [0u8; 256];
    // SAFETY: a NUL-terminated path and a buffer of its length.
    let n = unsafe { readlink(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned()
}

static VALUE: AtomicU64 = AtomicU64::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_: i32, info: *const u8, _: *mut c_void) {
    // SAFETY: the kernel's siginfo_t: si_code at 8, si_value at 24.
    unsafe {
        CODE.store(*(info.add(8) as *const i32), Ordering::SeqCst);
        VALUE.store(*(info.add(24) as *const u64), Ordering::SeqCst);
    }
}

/// A child that waits for a byte on `go`, then ends with `code`.
fn waiting_child(code: i32) -> (i32, i32) {
    let mut go = [0i32; 2];
    // SAFETY: plain calls; the child only reads and exits.
    unsafe {
        pipe(go.as_mut_ptr());
        let pid = fork();
        if pid == 0 {
            close(go[1]);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            _exit(code);
        }
        close(go[0]);
        (pid, go[1])
    }
}

fn main() {
    // SAFETY: plain calls into the C library and the kernel throughout.
    unsafe {
        // Its own: close-on-exec, what /proc shows, and the errors.
        let me = syscall(SYS_PIDFD_OPEN, i64::from(getpid()), 0i64) as i32;
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{me}")).unwrap_or_default();
        println!(
            "self: cloexec {}, link {}, fdinfo pid {}",
            fcntl(me, F_GETFD) & 1 == 1,
            link(me),
            fdinfo.contains(&format!("Pid:\t{}\n", getpid()))
        );
        close(me);
        let bad = |pid: i64, flags: i64| {
            let r = syscall(SYS_PIDFD_OPEN, pid, flags);
            if r < 0 { errno() } else { 0 }
        };
        println!(
            "errors: -1 {}, flags {}, none {}",
            bad(-1, 0) == EINVAL,
            bad(i64::from(getpid()), 1) == EINVAL,
            bad(4_000_000, 0) == ESRCH
        );

        // A child: not ended yet, then sent a signal with a value, then
        // ended and reaped.
        let (pid, go) = waiting_child(7);
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(pid), PIDFD_NONBLOCK) as i32;
        let nonblock = fcntl(fd, F_GETFL) & O_NONBLOCK != 0;
        let early = readable(fd, 0);
        let (w, _) = waitid_pidfd(fd, WEXITED);
        let (r, mask, shown, _) = info(fd, PIDFD_INFO_EXIT);
        println!(
            "child: nonblock {nonblock}, ended early {early}, waitid {}, info {r} pid {} exit asked {}",
            if w == -i64::from(EAGAIN) { "EAGAIN" } else { "?" },
            shown == pid as u32 && mask & PIDFD_INFO_PID != 0,
            mask & PIDFD_INFO_EXIT != 0
        );
        write(go, b"g".as_ptr().cast(), 1);
        let came = readable(fd, 5000);
        let (w, st) = loop {
            let r = waitid_pidfd(fd, WEXITED);
            if r.0 != -i64::from(EAGAIN) {
                break r;
            }
            usleep(10_000);
        };
        let (r, mask, _, code) = info(fd, PIDFD_INFO_EXIT);
        let (r2, _, _, _) = info(fd, 0);
        let sent = syscall(SYS_PIDFD_SEND_SIGNAL, i64::from(fd), 10i64, 0i64, 0i64);
        println!(
            "ended: readable {came}, waitid {w} status {st}, info {r} exit {} code {:#x}, without exit {}, signal {}",
            mask & PIDFD_INFO_EXIT != 0,
            code,
            if r2 == -i64::from(ESRCH) { "ESRCH" } else { "?" },
            if sent < 0 && errno() == ESRCH { "ESRCH" } else { "?" }
        );
        close(fd);
        close(go);

        // A signal with its value, through the descriptor.
        let act = SigAction { handler: on_usr1, mask: [0; 16], flags: SA_SIGINFO, restorer: 0 };
        sigaction(SIGUSR1, &act, std::ptr::null_mut());
        let mut ready = [0i32; 2];
        pipe(ready.as_mut_ptr());
        let pid = fork();
        if pid == 0 {
            close(ready[0]);
            write(ready[1], b"r".as_ptr().cast(), 1);
            for _ in 0..500 {
                if VALUE.load(Ordering::SeqCst) != 0 {
                    break;
                }
                usleep(10_000);
            }
            let ok = VALUE.load(Ordering::SeqCst) == 0x51 && CODE.load(Ordering::SeqCst) == SI_QUEUE;
            _exit(if ok { 3 } else { 4 });
        }
        close(ready[1]);
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(pid), 0i64) as i32;
        let mut si = [0u8; 128];
        si[0..4].copy_from_slice(&SIGUSR1.to_ne_bytes());
        si[8..12].copy_from_slice(&SI_QUEUE.to_ne_bytes());
        si[24..32].copy_from_slice(&0x51u64.to_ne_bytes());
        let sent = syscall(SYS_PIDFD_SEND_SIGNAL, i64::from(fd), 10i64, si.as_ptr(), 0i64);
        let mismatched = syscall(SYS_PIDFD_SEND_SIGNAL, i64::from(fd), 12i64, si.as_ptr(), 0i64);
        let mismatched = if mismatched < 0 { errno() } else { 0 };
        let (w, st) = waitid_pidfd(fd, WEXITED);
        println!(
            "signal: sent {sent}, another number {}, child saw the value {}",
            if mismatched == EINVAL { "EINVAL" } else { "?" },
            w == 0 && st == 3
        );
        close(fd);
        close(ready[0]);

        // clone3 with CLONE_PIDFD, and epoll for its end.
        let mut pidfd: i32 = -1;
        let args = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: SIGCHLD,
            ..CloneArgs::default()
        };
        let pid = syscall(SYS_CLONE3, &args as *const CloneArgs, std::mem::size_of::<CloneArgs>());
        if pid == 0 {
            usleep(50_000);
            _exit(5);
        }
        let ep = epoll_create1(0);
        let mut ev = EpollEvent { events: EPOLLIN, data: 9 };
        epoll_ctl(ep, EPOLL_CTL_ADD, pidfd, &mut ev);
        let mut out = [EpollEvent { events: 0, data: 0 }];
        let n = epoll_wait(ep, out.as_mut_ptr(), 1, 5000);
        let (w, st) = waitid_pidfd(pidfd, WEXITED);
        println!(
            "clone3: pidfd {}, cloexec {}, epoll {n} data {}, waitid {w} status {st}",
            pidfd >= 0,
            fcntl(pidfd, F_GETFD) & 1 == 1,
            out[0].data
        );
        close(ep);
        close(pidfd);

        // A descriptor a fork child inherits: it sees its sibling end.
        let (sibling, go) = waiting_child(0);
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(sibling), 0i64) as i32;
        let watcher = fork();
        if watcher == 0 {
            let before = readable(fd, 0);
            let after = readable(fd, 5000);
            _exit(if !before && after { 0 } else { 1 });
        }
        usleep(50_000);
        write(go, b"g".as_ptr().cast(), 1);
        let mut status = 0;
        libc_waitpid(watcher, &mut status);
        let (w, _) = waitid_pidfd(fd, WEXITED);
        println!("inherited: the fork child saw its sibling end {}, reaped {w}", status == 0);
        close(fd);
        close(go);

        // A thread's descriptor: readable once the thread has ended.
        let (tx, rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            tx.send(gettid()).unwrap();
            stop_rx.recv().unwrap();
        });
        let tid = rx.recv().unwrap();
        let plain = syscall(SYS_PIDFD_OPEN, i64::from(tid), 0i64);
        let plain = if plain < 0 { errno() } else { 0 };
        let tfd = syscall(SYS_PIDFD_OPEN, i64::from(tid), PIDFD_THREAD) as i32;
        let alive = readable(tfd, 0);
        stop_tx.send(()).unwrap();
        t.join().unwrap();
        println!(
            "thread: without PIDFD_THREAD {}, ended while running {alive}, ended after {}",
            if plain == EINVAL { "EINVAL" } else { "?" },
            readable(tfd, 5000)
        );
        close(tfd);

        // A child's file, taken with pidfd_getfd.
        let path = CString::new("/tmp/fwe-pidfd-getfd").unwrap();
        let mut report = [0i32; 2];
        pipe(report.as_mut_ptr());
        let (child, go) = {
            let mut go = [0i32; 2];
            pipe(go.as_mut_ptr());
            let pid = fork();
            if pid == 0 {
                close(go[1]);
                let f = open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o600);
                write(f, b"from the child".as_ptr().cast(), 14);
                write(report[1], (&f as *const i32).cast(), 4);
                let mut b = 0u8;
                read(go[0], (&mut b as *mut u8).cast(), 1);
                _exit(0);
            }
            close(go[0]);
            (pid, go[1])
        };
        let mut theirs = -1i32;
        read(report[0], (&mut theirs as *mut i32).cast(), 4);
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(child), 0i64) as i32;
        let got = syscall(SYS_PIDFD_GETFD, i64::from(fd), i64::from(theirs), 0i64) as i32;
        let cloexec = got >= 0 && fcntl(got, F_GETFD) & 1 == 1;
        // The same open file: a write through it goes after the child's.
        write(got, b", and the parent".as_ptr().cast(), 16);
        let missing = syscall(SYS_PIDFD_GETFD, i64::from(fd), 900i64, 0i64);
        let missing = if missing < 0 { errno() } else { 0 };
        let flags = syscall(SYS_PIDFD_GETFD, i64::from(fd), i64::from(theirs), 1i64);
        let flags = if flags < 0 { errno() } else { 0 };
        let not_pidfd = syscall(SYS_PIDFD_GETFD, i64::from(report[0]), i64::from(theirs), 0i64);
        let not_pidfd = if not_pidfd < 0 { errno() } else { 0 };
        write(go, b"g".as_ptr().cast(), 1);
        waitid_pidfd(fd, WEXITED);
        let r = open(path.as_ptr(), O_RDONLY);
        let mut buf = [0u8; 64];
        let n = read(r, buf.as_mut_ptr().cast(), buf.len());
        println!(
            "getfd: got {}, cloexec {cloexec}, file {:?}, not open {}, flags {}, not a pidfd {}",
            got >= 0,
            String::from_utf8_lossy(&buf[..n.max(0) as usize]),
            if missing == EBADF { "EBADF" } else { "?" },
            if flags == EINVAL { "EINVAL" } else { "?" },
            if not_pidfd == EBADF { "EBADF" } else { "?" }
        );
        close(r);
        close(got);
        close(fd);
        close(go);
        close(report[0]);
        close(report[1]);
        unlink(path.as_ptr());

        // A child's UTS namespace, joined with setns and opened with
        // PIDFD_GET_UTS_NAMESPACE.
        let mut ready = [0i32; 2];
        pipe(ready.as_mut_ptr());
        let (child, go) = {
            let mut go = [0i32; 2];
            pipe(go.as_mut_ptr());
            let pid = fork();
            if pid == 0 {
                close(go[1]);
                unshare(CLONE_NEWUTS as i32);
                sethostname(b"inner".as_ptr().cast(), 5);
                write(ready[1], b"r".as_ptr().cast(), 1);
                let mut b = 0u8;
                read(go[0], (&mut b as *mut u8).cast(), 1);
                _exit(0);
            }
            close(go[0]);
            (pid, go[1])
        };
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let fd = syscall(SYS_PIDFD_OPEN, i64::from(child), 0i64) as i32;
        let ns = syscall(SYS_IOCTL, i64::from(fd), PIDFD_GET_UTS_NAMESPACE, 0i64) as i32;
        let ns_link = if ns >= 0 { link(ns) } else { String::new() };
        let joiner = fork();
        if joiner == 0 {
            let r = syscall(SYS_SETNS, i64::from(fd), CLONE_NEWUTS);
            let mut name = [0 as c_char; 64];
            gethostname(name.as_mut_ptr(), name.len());
            let inner = CStr::from_ptr(name.as_ptr()).to_bytes() == b"inner";
            _exit(if r == 0 && inner { 0 } else { 1 });
        }
        let mut status = 0;
        libc_waitpid(joiner, &mut status);
        write(go, b"g".as_ptr().cast(), 1);
        waitid_pidfd(fd, WEXITED);
        println!(
            "namespaces: uts descriptor {}, setns joined it {}",
            ns_link.starts_with("uts:["),
            status == 0
        );
        close(ns);
        close(fd);
        close(go);
        close(ready[0]);
        close(ready[1]);

        // A regular file is no process descriptor.
        let not = syscall(SYS_PIDFD_SEND_SIGNAL, 0i64, 0i64, 0i64, 0i64);
        let not = if not < 0 { errno() } else { 0 };
        let nohang = waitid_pidfd(0, WEXITED | WNOHANG).0;
        println!(
            "not a pidfd: signal {}, waitid {}",
            if not == EBADF { "EBADF" } else { "?" },
            if nohang == -i64::from(EBADF) { "EBADF" } else { "?" }
        );
    }
}

fn gettid() -> i32 {
    // SAFETY: plain system call.
    unsafe { syscall(178) as i32 }
}

fn libc_waitpid(pid: i32, status: &mut i32) {
    unsafe extern "C" {
        fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    }
    // SAFETY: a valid out-parameter.
    unsafe { waitpid(pid, status, 0) };
}
