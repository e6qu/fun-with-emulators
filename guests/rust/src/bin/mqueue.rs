//! POSIX message queues: messages taken by priority, the status line a
//! queue's descriptor reads as (and its file in the mqueue filesystem,
//! which lists it), a queue that outlives its name while it is
//! open, and notifications another process's message sets off (a signal,
//! standard or real-time, carrying the registered value and the sender, and a notification thread
//! the C library runs). It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char, c_void};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_NONBLOCK: i32 = 0o4000;
const EAGAIN: i32 = 11;
const ENOENT: i32 = 2;
const EINTR: i32 = 4;
const SIGUSR1: i32 = 10;
/// A real-time signal (`SIGRTMIN` + 8).
const SIGRT: i32 = 40;
const F_GETFD: i32 = 1;
const FD_CLOEXEC: i32 = 1;
const SA_SIGINFO: u64 = 4;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_THREAD: i32 = 2;
const SI_MESGQ: i32 = -3;

#[repr(C)]
#[derive(Default)]
struct MqAttr {
    flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    reserved: [i64; 4],
}

#[repr(C)]
struct SigEvent {
    value: u64,
    signo: i32,
    notify: i32,
    function: Option<extern "C" fn(u64)>,
    attributes: *const c_void,
    pad: [u64; 4],
}

#[repr(C)]
struct SigAction {
    handler: extern "C" fn(i32, *const u8, *mut c_void),
    mask: [u64; 16],
    flags: u64,
    restorer: usize,
}

unsafe extern "C" {
    fn mq_open(name: *const c_char, flags: i32, ...) -> i32;
    fn mq_close(q: i32) -> i32;
    fn mq_unlink(name: *const c_char) -> i32;
    fn mq_send(q: i32, msg: *const u8, len: usize, prio: u32) -> i32;
    fn mq_receive(q: i32, msg: *mut u8, len: usize, prio: *mut u32) -> isize;
    fn mq_getattr(q: i32, attr: *mut MqAttr) -> i32;
    fn mq_notify(q: i32, ev: *const SigEvent) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn pread(fd: i32, buf: *mut u8, len: usize, off: i64) -> isize;
    fn getpid() -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn usleep(us: u32) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

/// What the notification signal's handler saw: its code, sender and value.
static CODE: AtomicI32 = AtomicI32::new(0);
static SENDER: AtomicI32 = AtomicI32::new(0);
static VALUE: AtomicU64 = AtomicU64::new(0);
/// What the notification thread was given.
static THREAD_VALUE: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_signal(_: i32, info: *const u8, _: *mut c_void) {
    // SAFETY: the kernel's `siginfo_t`: `si_code` at 8, `si_pid` at 16,
    // `si_value` at 24.
    unsafe {
        CODE.store(*(info.add(8) as *const i32), Ordering::SeqCst);
        SENDER.store(*(info.add(16) as *const i32), Ordering::SeqCst);
        VALUE.store(*(info.add(24) as *const u64), Ordering::SeqCst);
    }
}

extern "C" fn on_thread(value: u64) {
    THREAD_VALUE.store(value, Ordering::SeqCst);
}

/// Fork a child that sends `msg` to queue `q` and ends: its pid, once it
/// has ended.
fn send_from_child(q: i32, msg: &[u8]) -> i32 {
    // SAFETY: plain calls into the C library; the child only sends and
    // exits.
    unsafe {
        let pid = fork();
        if pid == 0 {
            _exit(if mq_send(q, msg.as_ptr(), msg.len(), 0) == 0 { 0 } else { 1 });
        }
        let mut status = 0;
        while waitpid(pid, &mut status, 0) == -1 && errno() == EINTR {}
        pid
    }
}

/// Wait (up to five seconds) for `done`.
fn wait_until(done: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if done() {
            return true;
        }
        // SAFETY: plain call.
        unsafe { usleep(10_000) };
    }
    false
}

fn main() {
    // SAFETY: plain calls into the C library throughout; every buffer is a
    // live local of the length passed.
    unsafe {
        let name = CString::new(format!("/fwe-mq-{}", getpid())).unwrap();
        mq_unlink(name.as_ptr());
        let attr = MqAttr { maxmsg: 4, msgsize: 32, ..Default::default() };
        let q = mq_open(name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0o640, &attr);
        let mut got = MqAttr::default();
        mq_getattr(q, &mut got);
        // The descriptor's file is the queue's: its mode and owner.
        let file = std::mem::ManuallyDrop::new(<std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(q));
        let mode = std::os::unix::fs::PermissionsExt::mode(&file.metadata().unwrap().permissions());
        let cloexec = fcntl(q, F_GETFD) & FD_CLOEXEC != 0;
        println!(
            "open: {}, maxmsg {}, msgsize {}, mode {mode:o}, close-on-exec {cloexec}",
            q >= 0,
            got.maxmsg,
            got.msgsize
        );

        // Taken highest priority first, oldest first within one.
        for (m, p) in [(&b"low"[..], 1), (b"high", 9), (b"low2", 1), (b"mid", 5)] {
            mq_send(q, m.as_ptr(), m.len(), p);
        }
        let mut buf = [0u8; 64];
        let n = read(q, buf.as_mut_ptr(), buf.len());
        println!("status: {}", String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim_end());
        // The mqueue filesystem lists the queue, its file read as the same.
        let file = format!("/dev/mqueue/fwe-mq-{}", getpid());
        let listed = std::fs::read_dir("/dev/mqueue")
            .map(|d| d.flatten().any(|e| e.path().to_str() == Some(&file)))
            .unwrap_or(false);
        let same = std::fs::read(&file).ok().as_deref() == Some(&buf[..n.max(0) as usize]);
        println!("listed: {listed}, file the same: {same}");
        let mut order = Vec::new();
        for _ in 0..4 {
            let mut prio = 0;
            let n = mq_receive(q, buf.as_mut_ptr(), buf.len(), &mut prio);
            order.push(format!("{}/{prio}", String::from_utf8_lossy(&buf[..n as usize])));
        }
        println!("received: {}", order.join(" "));

        // An empty queue, asked not to wait.
        let nb = mq_open(name.as_ptr(), O_RDWR | O_NONBLOCK);
        let r = mq_receive(nb, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut());
        println!("empty: {}", r == -1 && errno() == EAGAIN);
        mq_close(nb);

        // A signal another process's message sets off, with the value
        // registered and the sender.
        let act = SigAction { handler: on_signal, mask: [0; 16], flags: SA_SIGINFO, restorer: 0 };
        sigaction(SIGUSR1, &act, std::ptr::null_mut());
        let ev = SigEvent {
            value: 0x5eed,
            signo: SIGUSR1,
            notify: SIGEV_SIGNAL,
            function: None,
            attributes: std::ptr::null(),
            pad: [0; 4],
        };
        let registered = mq_notify(q, &ev);
        let n = pread(q, buf.as_mut_ptr(), buf.len(), 0);
        let line = String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned();
        let shows = line.contains("NOTIFY:0     SIGNO:10") && line.contains(&format!("NOTIFY_PID:{}", getpid()));
        let child = send_from_child(q, b"ping");
        let came = wait_until(|| VALUE.load(Ordering::SeqCst) != 0);
        println!(
            "signal: registered {registered}, shown {shows}, came {came}, mesgq {}, from the sender {}, value {:#x}",
            CODE.load(Ordering::SeqCst) == SI_MESGQ,
            SENDER.load(Ordering::SeqCst) == child,
            VALUE.load(Ordering::SeqCst)
        );
        mq_receive(q, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut());

        // The same with a real-time signal, which the host lacks.
        CODE.store(0, Ordering::SeqCst);
        VALUE.store(0, Ordering::SeqCst);
        sigaction(SIGRT, &act, std::ptr::null_mut());
        let ev = SigEvent { value: 0x7e47, signo: SIGRT, ..ev };
        let registered = mq_notify(q, &ev);
        let child = send_from_child(q, b"ping");
        let came = wait_until(|| VALUE.load(Ordering::SeqCst) != 0);
        println!(
            "real-time signal: registered {registered}, came {came}, mesgq {}, from the sender {}, value {:#x}",
            CODE.load(Ordering::SeqCst) == SI_MESGQ,
            SENDER.load(Ordering::SeqCst) == child,
            VALUE.load(Ordering::SeqCst)
        );
        mq_receive(q, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut());

        // A notification thread, run for another process's message.
        let ev = SigEvent {
            value: 0x7ead,
            signo: 0,
            notify: SIGEV_THREAD,
            function: Some(on_thread),
            attributes: std::ptr::null(),
            pad: [0; 4],
        };
        let registered = mq_notify(q, &ev);
        send_from_child(q, b"pong");
        let came = wait_until(|| THREAD_VALUE.load(Ordering::SeqCst) != 0);
        println!(
            "thread: registered {registered}, came {came}, value {:#x}",
            THREAD_VALUE.load(Ordering::SeqCst)
        );
        mq_receive(q, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut());

        // The name goes; the queue lives while it is open.
        mq_unlink(name.as_ptr());
        let gone = mq_open(name.as_ptr(), O_RDWR) == -1 && errno() == ENOENT;
        let sent = mq_send(q, b"kept".as_ptr(), 4, 0);
        let n = mq_receive(q, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut());
        println!(
            "unlinked: name gone {gone}, still sends {sent}, receives {}",
            String::from_utf8_lossy(&buf[..n.max(0) as usize])
        );
        mq_close(q);
        let again = mq_open(name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0o600, std::ptr::null::<MqAttr>());
        mq_getattr(again, &mut got);
        println!("made again: {}, empty {}", again >= 0, got.curmsgs == 0);
        mq_close(again);
        mq_unlink(name.as_ptr());
    }
}
