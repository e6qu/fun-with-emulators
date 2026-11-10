//! What debuggers ask of ptrace beyond its basics, as strace and gdb ask
//! it: a child seized (`PTRACE_SEIZE`) goes on running; interrupted
//! (`PTRACE_INTERRUPT`) it stops with `PTRACE_EVENT_STOP`; at a system
//! call's entry and exit `PTRACE_GET_SYSCALL_INFO` describes the call; its
//! signal mask is read and set (`PTRACE_GETSIGMASK`, `PTRACE_SETSIGMASK`);
//! a stop signal stops it in a group-stop, reported as an event stop, in
//! which `PTRACE_LISTEN` leaves it until `SIGCONT`; and its memory is read
//! and written through `/proc/<pid>/mem`. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicU64, Ordering};

const SYS_PTRACE: c_long = 117;
const SYS_GETPID: c_long = 172;
const SYS_GETPPID: c_long = 173;
const SYS_RT_SIGPROCMASK: c_long = 135;
const PTRACE_CONT: c_long = 7;
const PTRACE_SYSCALL: c_long = 24;
const PTRACE_SEIZE: c_long = 0x4206;
const PTRACE_INTERRUPT: c_long = 0x4207;
const PTRACE_LISTEN: c_long = 0x4208;
const PTRACE_GETSIGMASK: c_long = 0x420a;
const PTRACE_SETSIGMASK: c_long = 0x420b;
const PTRACE_GET_SYSCALL_INFO: c_long = 0x420e;
const PTRACE_O_TRACESYSGOOD: u64 = 1;
const PTRACE_EVENT_STOP: i32 = 128;
const SIGKILL: c_int = 9;
const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;
const SIGTRAP: i32 = 5;
const SIGCONT: c_int = 18;
const SIGSTOP: c_int = 19;
const WALL: c_int = 0x4000_0000;
const WNOHANG: c_int = 1;
const O_RDWR: c_int = 2;
/// `AUDIT_ARCH_AARCH64`.
const ARCH: u32 = 0xc000_00b7;

unsafe extern "C" {
    fn fork() -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn syscall(n: c_long, ...) -> c_long;
    fn usleep(us: u32) -> c_int;
    fn open(path: *const u8, flags: c_int, ...) -> c_int;
    fn pread(fd: c_int, buf: *mut u8, n: usize, off: i64) -> isize;
    fn pwrite(fd: c_int, buf: *const u8, n: usize, off: i64) -> isize;
    fn close(fd: c_int) -> c_int;
}

/// A word the parent reads and writes in the child through its `mem`.
static WORD: AtomicU64 = AtomicU64::new(0x5eed_f00d_cafe_d00d);

fn ptrace(req: c_long, pid: c_int, addr: u64, data: u64) -> c_long {
    // SAFETY: the raw call; pointer arguments are this program's own.
    unsafe { syscall(SYS_PTRACE, req, pid as c_long, addr, data) }
}

/// The next wait status of `pid` (`None`: nothing to report yet, with
/// `WNOHANG` in `flags`).
fn wait(pid: c_int, flags: c_int) -> Option<c_int> {
    let mut st = 0;
    // SAFETY: a valid out-parameter.
    let r = unsafe { waitpid(pid, &mut st, WALL | flags) };
    (r == pid).then_some(st)
}

fn stopsig(st: c_int) -> i32 {
    if st & 0xff == 0x7f { (st >> 8) & 0xff } else { -1 }
}

fn event(st: c_int) -> i32 {
    st >> 16
}

/// `struct ptrace_syscall_info`, as much as is read here.
#[repr(C)]
#[derive(Default)]
struct SyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    pc: u64,
    sp: u64,
    /// `entry.nr` or `exit.rval`, then the arguments or `exit.is_error`.
    words: [u64; 7],
}

fn syscall_info(pid: c_int) -> (i64, SyscallInfo) {
    let mut i = SyscallInfo::default();
    let n = ptrace(
        PTRACE_GET_SYSCALL_INFO,
        pid,
        std::mem::size_of::<SyscallInfo>() as u64,
        &mut i as *mut SyscallInfo as u64,
    );
    (n as i64, i)
}

fn main() {
    // SAFETY: plain calls; the child ends by SIGKILL.
    let child = unsafe { fork() };
    if child == 0 {
        // SIGUSR1 blocked, for the tracer to see; then system calls,
        // over and over.
        let set = 1u64 << (SIGUSR1 - 1);
        // SAFETY: a valid set, no old one asked for.
        unsafe { syscall(SYS_RT_SIGPROCMASK, 0 as c_long, &set as *const u64, 0usize, 8usize) };
        loop {
            // SAFETY: a plain call.
            unsafe { syscall(SYS_GETPPID) };
            std::hint::black_box(WORD.load(Ordering::Relaxed));
        }
    }

    // Seized, it goes on: nothing to report.
    let seized = ptrace(PTRACE_SEIZE, child, 0, PTRACE_O_TRACESYSGOOD);
    // SAFETY: a plain call.
    unsafe { usleep(50_000) };
    println!("seize: {seized}, running {}", wait(child, WNOHANG).is_none());

    // Interrupted, it stops: an event stop with SIGTRAP.
    let r = ptrace(PTRACE_INTERRUPT, child, 0, 0);
    let st = wait(child, 0).unwrap_or(0);
    println!(
        "interrupt: {r}, stopped {}, event stop {}",
        stopsig(st) == SIGTRAP,
        event(st) == PTRACE_EVENT_STOP
    );

    // Its signal mask, read and set.
    let mut mask = 0u64;
    let got = ptrace(PTRACE_GETSIGMASK, child, 8, &mut mask as *mut u64 as u64);
    let blocked = mask & 1 << (SIGUSR1 - 1) != 0;
    let more = mask | 1 << (SIGUSR2 - 1);
    let set = ptrace(PTRACE_SETSIGMASK, child, 8, &more as *const u64 as u64);
    let mut again = 0u64;
    ptrace(PTRACE_GETSIGMASK, child, 8, &mut again as *mut u64 as u64);
    println!("sigmask: get {got}, SIGUSR1 blocked {blocked}, set {set}, now {}", again == more);

    // Its memory through /proc/<pid>/mem.
    let path = format!("/proc/{child}/mem\0");
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(path.as_ptr(), O_RDWR) };
    let at = WORD.as_ptr() as i64;
    let mut b = [0u8; 8];
    // SAFETY: a buffer of its length.
    let n = unsafe { pread(fd, b.as_mut_ptr(), 8, at) };
    let read_ok = n == 8 && u64::from_ne_bytes(b) == 0x5eed_f00d_cafe_d00d;
    let new = 0x0123_4567_89ab_cdefu64.to_ne_bytes();
    // SAFETY: as above.
    let w = unsafe { pwrite(fd, new.as_ptr(), 8, at) };
    let mut back = [0u8; 8];
    // SAFETY: as above.
    unsafe { pread(fd, back.as_mut_ptr(), 8, at) };
    // SAFETY: its own descriptor.
    unsafe { close(fd) };
    println!("mem: read {read_ok}, write {}", w == 8 && back == new);

    // Its system calls: a stop at getppid's entry, then at its exit.
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    let st = wait(child, 0).unwrap_or(0);
    let (n, entry) = syscall_info(child);
    let entry_ok = stopsig(st) == SIGTRAP | 0x80 && entry.op == 1 && entry.arch == ARCH;
    let nr = entry.words[0];
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    let st = wait(child, 0).unwrap_or(0);
    let (_, exit) = syscall_info(child);
    // SAFETY: a plain call.
    let me = unsafe { syscall(SYS_GETPID) } as u64;
    let exit_ok = stopsig(st) == SIGTRAP | 0x80 && exit.op == 2 && exit.words[0] == me && exit.words[1] == 0;
    println!("syscall info: size {}, entry {entry_ok}, number {nr}, exit {exit_ok}", n > 0);

    // A stop signal: its delivery stop, then, passed on, a group-stop the
    // tracer sees as an event stop; listened to, it stays stopped until
    // SIGCONT, which it reports with SIGTRAP.
    // SAFETY: a plain call.
    unsafe { kill(child, SIGSTOP) };
    ptrace(PTRACE_CONT, child, 0, 0);
    let st = wait(child, 0).unwrap_or(0);
    let delivery = stopsig(st) == SIGSTOP && event(st) == 0;
    ptrace(PTRACE_CONT, child, 0, SIGSTOP as u64);
    let st = wait(child, 0).unwrap_or(0);
    let group = stopsig(st) == SIGSTOP && event(st) == PTRACE_EVENT_STOP;
    let listen = ptrace(PTRACE_LISTEN, child, 0, 0);
    // SAFETY: a plain call.
    unsafe { usleep(50_000) };
    let quiet = wait(child, WNOHANG).is_none();
    // SAFETY: a plain call.
    unsafe { kill(child, SIGCONT) };
    let st = wait(child, 0).unwrap_or(0);
    let continued = stopsig(st) == SIGTRAP && event(st) == PTRACE_EVENT_STOP;
    println!(
        "group stop: delivery {delivery}, event {group}, listen {listen}, stays {quiet}, continued {continued}"
    );

    // SAFETY: plain calls.
    unsafe { kill(child, SIGKILL) };
    let st = wait(child, 0).unwrap_or(0);
    println!("killed: {}", st & 0x7f == SIGKILL);
}
