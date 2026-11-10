//! ptrace: a child traced (`PTRACE_TRACEME`) stops for a signal; its
//! memory is read and written (`PEEKDATA`, `POKEDATA`, the write seen in
//! its exit status) and its registers read (`GETREGSET`); its system calls
//! stop at entry and exit (`PTRACE_SYSCALL`, `PTRACE_O_TRACESYSGOOD`), the
//! number and result in its registers; a fork it makes is followed
//! (`PTRACE_O_TRACEFORK`, the new child stopping first, exit events for
//! both); `waitid` reports a stop (`CLD_TRAPPED`); it runs to its end one
//! instruction at a time (`PTRACE_SINGLESTEP`); and a breakpoint planted
//! in its code stops it there. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicU64, Ordering};

const SYS_PTRACE: c_long = 117;
const SYS_WRITE: c_long = 64;
const SIGSTOP: c_int = 19;
const SIGTRAP: i32 = 5;
const SIGCHLD: i32 = 17;
const PTRACE_TRACEME: c_long = 0;
const PTRACE_PEEKDATA: c_long = 2;
const PTRACE_POKEDATA: c_long = 5;
const PTRACE_POKETEXT: c_long = 4;
const PTRACE_PEEKTEXT: c_long = 1;
const PTRACE_CONT: c_long = 7;
const PTRACE_SINGLESTEP: c_long = 9;
const PTRACE_SYSCALL: c_long = 24;
const PTRACE_SETOPTIONS: c_long = 0x4200;
const PTRACE_GETEVENTMSG: c_long = 0x4201;
const PTRACE_GETREGSET: c_long = 0x4204;
const PTRACE_O_TRACESYSGOOD: c_long = 1;
const PTRACE_O_TRACEFORK: c_long = 2;
const PTRACE_O_TRACEEXIT: c_long = 0x40;
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_EXIT: i32 = 6;
const NT_PRSTATUS: c_long = 1;
const WALL: c_int = 0x4000_0000;
const P_PID: c_int = 1;
const WSTOPPED: c_int = 2;
const CLD_TRAPPED: i32 = 4;

unsafe extern "C" {
    fn fork() -> c_int;
    fn getpid() -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn waitid(idtype: c_int, id: c_int, info: *mut [i32; 32], options: c_int) -> c_int;
    fn syscall(n: c_long, ...) -> c_long;
    fn _exit(code: c_int) -> !;
}

static SECRET: AtomicU64 = AtomicU64::new(0x1122_3344_5566_7788);

#[inline(never)]
fn work(n: i32) -> i32 {
    std::hint::black_box(n) * 2 + 1
}

fn ptrace(req: c_long, pid: c_int, addr: u64, data: u64) -> c_long {
    // SAFETY: the raw call; pointer arguments are this program's own.
    unsafe { syscall(SYS_PTRACE, req, pid as c_long, addr, data) }
}

fn wait(pid: c_int) -> c_int {
    let mut st = 0;
    // SAFETY: a valid out-parameter.
    unsafe { waitpid(pid, &mut st, WALL) };
    st
}

fn stopsig(st: c_int) -> i32 {
    if st & 0xff == 0x7f { (st >> 8) & 0xff } else { -1 }
}

fn exit_code(st: c_int) -> i32 {
    if st & 0x7f == 0 { (st >> 8) & 0xff } else { -1 }
}

/// A child that is traced and stopped (by SIGSTOP), then runs `then`.
fn traced_child(then: impl FnOnce() -> i32) -> c_int {
    // SAFETY: plain calls; the child ends with `_exit`.
    unsafe {
        let pid = fork();
        if pid == 0 {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            kill(getpid(), SIGSTOP);
            _exit(then());
        }
        pid
    }
}

/// The general registers (x0-x30, sp, pc, pstate) and their size.
fn regs(pid: c_int) -> ([u64; 34], u64) {
    let mut r = [0u64; 34];
    let mut iov = [r.as_mut_ptr() as u64, std::mem::size_of_val(&r) as u64];
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as u64, iov.as_mut_ptr() as u64);
    (r, iov[1])
}

fn main() {
    // A signal stop; memory read and written; registers.
    let c = traced_child(|| if SECRET.load(Ordering::SeqCst) == 42 { 7 } else { 3 });
    println!("stop: signal {}", stopsig(wait(c)));
    let mut word = 0u64;
    ptrace(PTRACE_PEEKDATA, c, SECRET.as_ptr() as u64, &mut word as *mut u64 as u64);
    println!("peek: {}", word == 0x1122_3344_5566_7788);
    let (r, size) = regs(c);
    let text = main as *const () as u64;
    println!("regs: {size} bytes, pc near the code {}", r[32].abs_diff(text) < 1 << 24);
    ptrace(PTRACE_POKEDATA, c, SECRET.as_ptr() as u64, 42);
    ptrace(PTRACE_CONT, c, 0, 0);
    println!("poke: exit {}", exit_code(wait(c)));

    // System-call stops: a write's entry and exit.
    let c = traced_child(|| {
        // SAFETY: a write to no descriptor, which fails.
        unsafe { syscall(SYS_WRITE, -1 as c_long, b"x".as_ptr(), 1 as c_long) };
        0
    });
    wait(c);
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESYSGOOD as u64);
    let (mut entry, mut result) = (false, 0i64);
    loop {
        ptrace(PTRACE_SYSCALL, c, 0, 0);
        let st = wait(c);
        if stopsig(st) != (SIGTRAP | 0x80) {
            break;
        }
        let (r, _) = regs(c);
        if r[8] == SYS_WRITE as u64 {
            if entry {
                result = r[0] as i64;
            }
            entry = true;
        }
    }
    println!("syscalls: write stopped at entry {entry}, its result {result}");

    // A fork followed, with exit events.
    let c = traced_child(|| {
        // SAFETY: plain calls; the grandchild ends with `_exit`.
        unsafe {
            let g = fork();
            if g == 0 {
                _exit(3);
            }
            let mut st = 0;
            waitpid(g, &mut st, 0);
        }
        4
    });
    wait(c);
    ptrace(PTRACE_SETOPTIONS, c, 0, (PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXIT) as u64);
    ptrace(PTRACE_CONT, c, 0, 0);
    let (mut forks, mut new_stopped, mut exit_events, mut exits, mut live) = (0, 0, 0, 0, 1);
    while live > 0 {
        let mut st = 0;
        // SAFETY: a valid out-parameter.
        let w = unsafe { waitpid(-1, &mut st, WALL) };
        if w < 0 {
            break;
        }
        if st & 0x7f == 0 {
            exits += 1;
            live -= 1;
            continue;
        }
        match st >> 16 {
            PTRACE_EVENT_FORK => {
                let mut msg = 0u64;
                ptrace(PTRACE_GETEVENTMSG, w, 0, &mut msg as *mut u64 as u64);
                forks += i32::from(msg > 0);
                live += 1;
            }
            PTRACE_EVENT_EXIT => exit_events += 1,
            _ if w != c && stopsig(st) == SIGSTOP => new_stopped += 1,
            _ => {}
        }
        ptrace(PTRACE_CONT, w, 0, 0);
    }
    println!(
        "fork: events {forks}, new child stopped {new_stopped}, exit events {exit_events}, exits {exits}"
    );

    // waitid of a stop.
    let c = traced_child(|| 0);
    let mut info = [0i32; 32];
    // SAFETY: a valid out-parameter.
    unsafe { waitid(P_PID, c, &mut info, WSTOPPED) };
    println!(
        "waitid: signal {}, trapped {}, status {}",
        info[0] == SIGCHLD,
        info[2] == CLD_TRAPPED,
        info[6]
    );
    ptrace(PTRACE_CONT, c, 0, 0);
    wait(c);

    // One instruction at a time, to the end.
    let c = traced_child(|| work(10));
    wait(c);
    let mut steps = 0;
    let st = loop {
        ptrace(PTRACE_SINGLESTEP, c, 0, 0);
        let st = wait(c);
        if stopsig(st) != SIGTRAP || steps > 100_000 {
            break st;
        }
        steps += 1;
    };
    println!("step: exit {}, stepped {}", exit_code(st), steps > 10);

    // A breakpoint.
    let c = traced_child(|| work(10));
    wait(c);
    let at = work as *const () as u64;
    let mut orig = 0u64;
    ptrace(PTRACE_PEEKTEXT, c, at, &mut orig as *mut u64 as u64);
    let brk = (orig & !0xffff_ffff) | 0xd420_0000;
    ptrace(PTRACE_POKETEXT, c, at, brk);
    ptrace(PTRACE_CONT, c, 0, 0);
    let sig = stopsig(wait(c));
    let (r, _) = regs(c);
    ptrace(PTRACE_POKETEXT, c, at, orig);
    ptrace(PTRACE_CONT, c, 0, 0);
    println!(
        "breakpoint: signal {sig}, at work {}, argument {}, exit {}",
        r[32] == at,
        r[0],
        exit_code(wait(c))
    );
}
