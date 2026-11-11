//! ptrace: a child traced (`PTRACE_TRACEME`) stops for a signal; its
//! memory is read and written (`PEEKDATA`, `POKEDATA`, the write seen in
//! its exit status) and its registers and thread pointer read
//! (`GETREGSET`); its system calls
//! stop at entry and exit (`PTRACE_SYSCALL`, `PTRACE_O_TRACESYSGOOD`), the
//! number and result in its registers; a fork it makes is followed
//! (`PTRACE_O_TRACEFORK`, the new child stopping first, exit events for
//! both); a thread it starts is followed (`PTRACE_O_TRACECLONE`, the
//! thread stopping first under its own id, its end reported); `waitid`
//! reports a stop (`CLD_TRAPPED`); it runs to its end one
//! instruction at a time (`PTRACE_SINGLESTEP`); and a breakpoint planted
//! in its code stops it there; and a thread of a running process that is
//! not traced is listed in `/proc/<pid>/task`, reached by `tgkill`, and
//! attached to on its own (`PTRACE_ATTACH` of its tid), stopping while its
//! process goes on, and its process's and its own robust futex lists read
//! (`get_robust_list`). It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicU64, Ordering};

const SYS_PTRACE: c_long = 117;
const SYS_WRITE: c_long = 64;
const SYS_GETTID: c_long = 178;
const SYS_TGKILL: c_long = 131;
const SYS_SET_ROBUST_LIST: c_long = 99;
const SYS_GET_ROBUST_LIST: c_long = 100;
const PTRACE_ATTACH: c_long = 16;
const PTRACE_DETACH: c_long = 17;
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
const PTRACE_O_TRACECLONE: c_long = 8;
const PTRACE_O_TRACEEXIT: c_long = 0x40;
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXIT: i32 = 6;
const NT_PRSTATUS: c_long = 1;
const NT_ARM_TLS: c_long = 0x401;
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
    fn pipe(fds: *mut c_int) -> c_int;
    fn read(fd: c_int, buf: *mut u8, n: usize) -> isize;
    fn write(fd: c_int, buf: *const u8, n: usize) -> isize;
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
    let mut tp = 0u64;
    let mut iov = [&mut tp as *mut u64 as u64, 8];
    ptrace(PTRACE_GETREGSET, c, NT_ARM_TLS as u64, iov.as_mut_ptr() as u64);
    println!("thread pointer: set {}", tp != 0 && iov[1] == 8);
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
    // (The new child's first stop may come before its parent's event, as
    // on Linux; the child ends last, having waited for it.)
    let (mut forks, mut new_stopped, mut exit_events, mut exits) = (0, 0, 0, 0);
    loop {
        let mut st = 0;
        // SAFETY: a valid out-parameter.
        let w = unsafe { waitpid(-1, &mut st, WALL) };
        if w < 0 {
            break;
        }
        if st & 0x7f == 0 {
            exits += 1;
            if w == c {
                break;
            }
            continue;
        }
        match st >> 16 {
            PTRACE_EVENT_FORK => {
                let mut msg = 0u64;
                ptrace(PTRACE_GETEVENTMSG, w, 0, &mut msg as *mut u64 as u64);
                forks += i32::from(msg > 0);
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

    // A thread followed.
    let c = traced_child(|| std::thread::spawn(|| 5).join().unwrap_or(0));
    wait(c);
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACECLONE as u64);
    ptrace(PTRACE_CONT, c, 0, 0);
    // (The new thread's first stop may come before its creator's event,
    // as on Linux: any stop or end but the process's is the thread's.)
    let (mut clones, mut thread_stopped, mut thread_ends, mut code) = (0, 0, 0, -1);
    loop {
        let mut st = 0;
        // SAFETY: a valid out-parameter.
        let w = unsafe { waitpid(-1, &mut st, WALL) };
        if w < 0 {
            break;
        }
        if st & 0x7f == 0 {
            if w == c {
                code = exit_code(st);
                break;
            }
            thread_ends += 1;
            continue;
        }
        if st >> 16 == PTRACE_EVENT_CLONE {
            let mut msg = 0u64;
            ptrace(PTRACE_GETEVENTMSG, w, 0, &mut msg as *mut u64 as u64);
            clones += i32::from(msg > 0);
        } else if w != c && stopsig(st) == SIGSTOP {
            thread_stopped += 1;
        }
        ptrace(PTRACE_CONT, w, 0, 0);
    }
    println!(
        "thread: events {clones}, new thread stopped {thread_stopped}, its end {thread_ends}, exit {code}"
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

    // A thread of a running process attached to on its own.
    static MAIN_HEAD: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    static THREAD_HEAD: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    // An empty robust list: its head pointing at itself.
    fn set_robust(head: &'static [AtomicU64; 3]) -> u64 {
        let at = head.as_ptr() as u64;
        head[0].store(at, Ordering::SeqCst);
        // SAFETY: the head lives for the whole program.
        unsafe { syscall(SYS_SET_ROBUST_LIST, at as c_long, 24 as c_long) };
        at
    }
    fn get_robust(pid: c_int) -> (u64, u64) {
        let (mut head, mut len) = (0u64, 0u64);
        // SAFETY: valid out-pointers.
        let r = unsafe {
            syscall(SYS_GET_ROBUST_LIST, pid as c_long, &mut head as *mut u64 as c_long, &mut len as *mut u64 as c_long)
        };
        if r == 0 { (head, len) } else { (0, 0) }
    }
    let mut fds = [0 as c_int; 2];
    // SAFETY: a valid out-array; plain calls; the child ends by SIGKILL.
    let c = unsafe {
        pipe(fds.as_mut_ptr());
        let c = fork();
        if c == 0 {
            let w = fds[1];
            set_robust(&MAIN_HEAD);
            std::thread::spawn(move || {
                set_robust(&THREAD_HEAD);
                let tid = syscall(SYS_GETTID) as i32;
                write(w, tid.to_ne_bytes().as_ptr(), 4);
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            });
            loop {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        c
    };
    let mut b = [0u8; 4];
    // SAFETY: a valid buffer.
    unsafe { read(fds[0], b.as_mut_ptr(), 4) };
    let tid = i32::from_ne_bytes(b);
    let listed = std::fs::read_dir(format!("/proc/{c}/task"))
        .map(|d| d.filter_map(Result::ok).any(|e| e.file_name().to_str() == Some(&tid.to_string())))
        .unwrap_or(false);
    // SAFETY: the raw call, signal 0 only checks the thread.
    let reached = unsafe { syscall(SYS_TGKILL, c as c_long, tid as c_long, 0 as c_long) } == 0;
    let attached = ptrace(PTRACE_ATTACH, tid, 0, 0) == 0;
    let sig = stopsig(wait(tid));
    let (r, _) = regs(tid);
    let detached = ptrace(PTRACE_DETACH, tid, 0, 0) == 0;
    let process_list = get_robust(c) == (MAIN_HEAD.as_ptr() as u64, 24);
    let thread_list = get_robust(tid) == (THREAD_HEAD.as_ptr() as u64, 24);
    // SAFETY: plain calls on the child.
    unsafe {
        kill(c, 9);
        waitpid(c, &mut 0, 0);
    }
    println!(
        "attach: listed {listed}, tgkill {reached}, attached {attached}, signal {sig}, pc {}, detached {detached}",
        r[32] != 0
    );
    println!("robust lists: process {process_list}, thread {thread_list}");

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
