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
const CLONE_NEWUSER: i32 = 0x1000_0000;
const PRIO_PROCESS: i32 = 0;
const PRIO_USER: i32 = 2;
const O_WRONLY: i32 = 1;
const SIGRT1: i32 = 35;
const SIGRT2: i32 = 36;
const SIGCHLD: i32 = 17;
const SI_QUEUE: i32 = -1;
const SI_USER: i32 = 0;
const SYS_RT_SIGQUEUEINFO: i64 = 138;
const P_PID: i32 = 1;
const RLIMIT_SIGPENDING: i32 = 11;
const RLIMIT_MEMLOCK: i32 = 8;
const PROT_RW: i32 = 3;
const MAP_PRIVATE_ANON: i32 = 0x02 | 0x20;
const MAP_LOCKED: i32 = 0x2000;
const MCL_FUTURE: i32 = 2;
const SYS_MMAP: i64 = 222;
const SYS_SCHED_SETAFFINITY: i64 = 122;
const SYS_SCHED_GETAFFINITY: i64 = 123;
const SYS_GETCPU: i64 = 168;
const SYS_PRLIMIT64: i64 = 261;
const RLIMIT_NOFILE: i32 = 7;
const RLIMIT_NPROC: i32 = 6;
const RLIMIT_MSGQUEUE: i32 = 12;
const RLIMIT_STACK: i32 = 3;
const MAP_SHARED: i32 = 0x01;
const MAP_SHARED_ANON: i32 = 0x01 | 0x20;
const MAP_PRIVATE: i32 = 0x02;
const MADV_NORMAL: i32 = 0;
const MADV_DONTNEED: i32 = 4;
const MADV_REMOVE: i32 = 9;
const MADV_DONTFORK: i32 = 10;
const MADV_DOFORK: i32 = 11;
const MADV_DONTNEED_LOCKED: i32 = 24;
const MADV_GUARD_INSTALL: i32 = 102;
const MADV_GUARD_REMOVE: i32 = 103;
const SYS_TIMER_CREATE: i64 = 107;
const SYS_TIMER_DELETE: i64 = 111;
const CLOCK_MONOTONIC: i64 = 1;

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}
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
    fn setrlimit(res: i32, lim: *const Rlimit) -> i32;
    fn getpriority(which: i32, who: u32) -> i32;
    fn setpriority(which: i32, who: u32, prio: i32) -> i32;
    fn gettid() -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn mlock(addr: *const c_void, len: usize) -> i32;
    fn mlockall(flags: i32) -> i32;
    fn munlockall() -> i32;
    fn dup(fd: i32) -> i32;
    fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
    fn pause() -> i32;
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn memfd_create(name: *const c_char, flags: u32) -> i32;
    fn ftruncate(fd: i32, len: i64) -> i32;
    fn pread(fd: i32, buf: *mut c_void, len: usize, off: i64) -> isize;
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

/// `rt_sigqueueinfo(pid, sig)` with `value`, as `sigqueue` sends it: 0 or
/// the errno.
fn sigqueue(pid: i32, sig: i32, value: i32) -> i32 {
    // SAFETY: plain calls into the C library and the kernel.
    unsafe {
        let mut info = queued_info(sig, SI_QUEUE, getpid(), 0);
        info[24..28].copy_from_slice(&value.to_ne_bytes());
        if syscall(SYS_RT_SIGQUEUEINFO, i64::from(pid), i64::from(sig), info.as_ptr()) == 0 { 0 } else { errno() }
    }
}

/// The values of the queued `sig` taken, in order, waiting up to `ms`
/// for each.
fn take_all(sig: i32, ms: i64) -> Vec<i32> {
    std::iter::from_fn(|| wait_for(sig, ms)).map(|i| i32::from_ne_bytes(i[24..28].try_into().unwrap())).collect()
}

/// `RLIMIT_SIGPENDING` counts each signal queued: past it, `sigqueue`
/// and `timer_create` fail with `EAGAIN`, while `kill` merges its signal
/// into the one pending; to another process, what waits for room is kept
/// for it, never lost.
fn sigpending_limit() {
    // SAFETY: plain calls into the C library and the kernel.
    unsafe {
        let rt = sigset(SIGRT1);
        sigprocmask(SIG_BLOCK, &rt, std::ptr::null_mut());
        let ten = Rlimit { cur: 10, max: 10 };
        setrlimit(RLIMIT_SIGPENDING, &ten);
        let me = getpid();
        let mut sent = 0;
        let refused = loop {
            match sigqueue(me, SIGRT1, sent) {
                0 if sent < 100 => sent += 1,
                e => break e,
            }
        };
        let mut timer = 0i32;
        let t = syscall(SYS_TIMER_CREATE, CLOCK_MONOTONIC, 0i64, &mut timer as *mut i32);
        let timer_refused = t == -1 && errno() == 11;
        let killed = kill(me, SIGRT1);
        let taken = take_all(SIGRT1, 0);
        let in_order = taken.iter().copied().eq(0..sent);
        println!(
            "own: queued {sent}, then {}, timer refused {timer_refused}, kill {killed}, taken {} in order {in_order}",
            if refused == 11 { "EAGAIN" } else { "?" },
            taken.len()
        );
        let t = syscall(SYS_TIMER_CREATE, CLOCK_MONOTONIC, 0i64, &mut timer as *mut i32);
        println!("timer once there is room: {}", t == 0);
        syscall(SYS_TIMER_DELETE, i64::from(timer));

        let (mut ready, mut go) = ([0i32; 2], [0i32; 2]);
        pipe(ready.as_mut_ptr());
        pipe(go.as_mut_ptr());
        let child = fork();
        if child == 0 {
            close(go[1]);
            let five = Rlimit { cur: 5, max: 5 };
            setrlimit(RLIMIT_SIGPENDING, &five);
            write(ready[1], b"r".as_ptr().cast(), 1);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            let got = take_all(SIGRT1, 500);
            let in_order = got.iter().copied().eq(0..got.len() as i32);
            _exit(if in_order { got.len() as i32 } else { 255 });
        }
        close(go[0]);
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let mut sent = 0;
        let refused = loop {
            match sigqueue(child, SIGRT1, sent) {
                0 if sent < 200 => sent += 1,
                e => break e,
            }
        };
        close(go[1]);
        let got = reap(child);
        println!(
            "another: then {}, past its limit {}, all taken in order {}",
            if refused == 11 { "EAGAIN" } else { "?" },
            sent >= 5,
            got == sent
        );
    }
}

/// An anonymous mapping of `len` bytes with `flags` added: `ok` or the
/// errno's name.
fn map_anon(len: usize, flags: i32) -> String {
    // The system call itself: musl turns its EPERM into ENOMEM.
    // SAFETY: a fresh mapping, left mapped.
    let r = unsafe { syscall(SYS_MMAP, 0i64, len, PROT_RW, MAP_PRIVATE_ANON | flags, -1i64, 0i64) };
    outcome(r)
}

/// Use `n` frames of 64 KiB of the stack.
#[inline(never)]
fn deep(n: u32) -> u8 {
    let mut frame = [0u8; 64 << 10];
    frame[n as usize % frame.len()] = n as u8;
    std::hint::black_box(&mut frame);
    if n == 0 { frame[0] } else { deep(n - 1).wrapping_add(frame[n as usize % frame.len()]) }
}

/// A program run under `RLIMIT_STACK` of `limit_mib` MiB that uses
/// `use_mib` MiB of its main thread's stack: how it ends.
fn stack_run(limit_mib: u64, use_mib: u32) -> String {
    in_child(|| {
        let mib = 1 << 20;
        // SAFETY: plain calls into the C library.
        unsafe {
            setrlimit(RLIMIT_STACK, &Rlimit { cur: limit_mib * mib, max: limit_mib * mib });
            let me = CString::new("/proc/self/exe").unwrap();
            let n = CString::new(use_mib.to_string()).unwrap();
            let args = [c"identity".as_ptr(), c"deep".as_ptr(), n.as_ptr(), std::ptr::null()];
            execv(me.as_ptr(), args.as_ptr());
        }
        1
    })
}

/// `RLIMIT_STACK` sizes the main thread's stack of the program `execve`
/// runs: past the 8 MiB fwe's stack once had, and no further.
fn stack_limit() {
    println!(
        "limit 32 MiB, 20 MiB used: {}; limit 1 MiB, 4 MiB used: {}",
        stack_run(32, 20),
        if stack_run(1, 4).starts_with("killed") { "killed" } else { "not killed" }
    );
}

/// `RLIMIT_NPROC` counts a user's tasks, threads included, at `fork`: as
/// a user no other process has, the least limit that lets this process
/// fork is passed once it runs two more threads.
fn nproc_threads() {
    // SAFETY: plain calls into the C library.
    unsafe {
        let child = fork();
        if child == 0 {
            setuid(43210);
            let hard = limit_of(0, RLIMIT_NPROC).1;
            let forks = |n: u64| {
                setrlimit(RLIMIT_NPROC, &Rlimit { cur: n, max: hard });
                let pid = fork();
                if pid == 0 {
                    _exit(0);
                }
                if pid > 0 {
                    reap(pid);
                }
                pid > 0
            };
            let Some(least) = (1..200).find(|&n| forks(n)) else {
                println!("no limit lets it fork");
                _exit(1);
            };
            setrlimit(RLIMIT_NPROC, &Rlimit { cur: least + 10, max: hard });
            let mut stop = [0i32; 2];
            pipe(stop.as_mut_ptr());
            let threads: Vec<_> = (0..2)
                .map(|_| {
                    let r = stop[0];
                    std::thread::spawn(move || {
                        let mut b = 0u8;
                        read(r, (&mut b as *mut u8).cast(), 1);
                    })
                })
                .collect();
            usleep(100_000);
            let refused = !forks(least);
            let again = forks(least + 2);
            close(stop[1]);
            for t in threads {
                let _ = t.join();
            }
            println!("two more threads: fork at the least limit refused {refused}, two more allowed {again}");
            _exit(0);
        }
        reap(child);
    }
}

/// `prlimit(pid, res)`: its soft and hard limit.
fn limit_of(pid: i32, res: i32) -> (u64, u64) {
    let mut old = Rlimit { cur: 0, max: 0 };
    // SAFETY: a valid out-parameter.
    unsafe { syscall(SYS_PRLIMIT64, i64::from(pid), i64::from(res), 0i64, &mut old as *mut Rlimit) };
    (old.cur, old.max)
}

/// `prlimit` of another process: it reads that process's limits, not the
/// caller's, and a limit set takes effect in it at once, without its
/// asking for its limits (its descriptors stop at the new limit).
fn prlimit_other() {
    // SAFETY: plain calls into the C library and the kernel.
    unsafe {
        let (mut ready, mut go) = ([0i32; 2], [0i32; 2]);
        pipe(ready.as_mut_ptr());
        pipe(go.as_mut_ptr());
        let child = fork();
        if child == 0 {
            close(go[1]);
            write(ready[1], b"r".as_ptr().cast(), 1);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            let mut highest = 0;
            for _ in 0..2000 {
                match dup(0) {
                    -1 => break,
                    fd => highest = fd,
                }
            }
            _exit(highest);
        }
        close(go[0]);
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let new = Rlimit { cur: 64, max: 64 };
        let set = syscall(SYS_PRLIMIT64, i64::from(child), i64::from(RLIMIT_NOFILE), &new as *const Rlimit, 0i64);
        let own = Rlimit { cur: 128, max: limit_of(0, RLIMIT_NOFILE).1 };
        setrlimit(RLIMIT_NOFILE, &own);
        println!(
            "set {set}: it reads {:?}, the caller's own {:?}",
            limit_of(child, RLIMIT_NOFILE),
            limit_of(0, RLIMIT_NOFILE).0
        );
        close(go[1]);
        println!("its highest descriptor {}", reap(child));
        // One that set its own limit, then ran a program: what it carried.
        let child = fork();
        if child == 0 {
            setrlimit(RLIMIT_MSGQUEUE, &Rlimit { cur: 4321, max: 4321 });
            let me = CString::new("/proc/self/exe").unwrap();
            let args = [c"identity".as_ptr(), c"pause".as_ptr(), std::ptr::null()];
            execv(me.as_ptr(), args.as_ptr());
            _exit(1);
        }
        let mut seen = (0, 0);
        for _ in 0..100 {
            usleep(20_000);
            seen = limit_of(child, RLIMIT_MSGQUEUE);
            if seen == (4321, 4321) {
                break;
            }
        }
        kill(child, SIGKILL);
        reap(child);
        println!("after its execve: {seen:?}");
    }
}

/// `sched_getaffinity(pid)`'s first word (0 on failure).
fn affinity_of(pid: i32) -> u64 {
    let mut mask = [0u64; 16];
    // SAFETY: a buffer of the size given.
    let r = unsafe { syscall(SYS_SCHED_GETAFFINITY, i64::from(pid), 128i64, mask.as_mut_ptr()) };
    if r > 0 { mask[0] } else { 0 }
}

/// `sched_setaffinity(pid)` to the CPUs of `word`.
fn set_affinity(pid: i32, word: u64) -> i64 {
    let mask = [word, 0, 0, 0, 0, 0, 0, 0];
    // SAFETY: a buffer of the size given.
    unsafe { syscall(SYS_SCHED_SETAFFINITY, i64::from(pid), 64i64, mask.as_ptr()) }
}

/// The CPU `getcpu` reports.
fn cpu() -> u32 {
    let mut c = u32::MAX;
    // SAFETY: an out-parameter; no node or cache asked for.
    unsafe { syscall(SYS_GETCPU, &mut c as *mut u32, 0i64, 0i64) };
    c
}

/// CPU affinity is kept per process: set on another process, it is what
/// that process and others read; a fork child inherits it; `getcpu`
/// reports a CPU of it.
fn affinity() {
    // SAFETY: plain calls into the C library.
    unsafe {
        let all = affinity_of(0);
        let (mut ready, mut go, mut report) = ([0i32; 2], [0i32; 2], [0i32; 2]);
        pipe(ready.as_mut_ptr());
        pipe(go.as_mut_ptr());
        pipe(report.as_mut_ptr());
        let child = fork();
        if child == 0 {
            close(go[1]);
            write(ready[1], b"r".as_ptr().cast(), 1);
            let mut b = 0u8;
            read(go[0], (&mut b as *mut u8).cast(), 1);
            let line = format!("child reads its own {:#x}, getcpu {}\n", affinity_of(0), cpu());
            write(report[1], line.as_ptr().cast(), line.len());
            _exit(0);
        }
        close(go[0]);
        let mut b = 0u8;
        read(ready[0], (&mut b as *mut u8).cast(), 1);
        let set = set_affinity(child, 0b10);
        println!("set another's {set}: it reads {:#x}, own unchanged {}", affinity_of(child), affinity_of(0) == all);
        close(go[1]);
        reap(child);
        let mut buf = [0u8; 128];
        let n = read(report[0], buf.as_mut_ptr().cast(), buf.len());
        print!("{}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
        set_affinity(0, 0b100);
        let inherited = in_child(|| affinity_of(0) as i32);
        println!("own {:#x}, getcpu {}, a fork child's {inherited}", affinity_of(0), cpu());
    }
}

/// A child that runs `f` and exits with what it returns: how it ended,
/// its exit status or `killed by <signal>`.
fn in_child(f: impl FnOnce() -> i32) -> String {
    // SAFETY: plain calls into the C library.
    unsafe {
        let pid = fork();
        if pid == 0 {
            _exit(f());
        }
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        if status & 0x7f != 0 { format!("killed by {}", status & 0x7f) } else { format!("exit {}", (status >> 8) & 0xff) }
    }
}

/// `madvise`'s controls of what a fork child gets and what memory holds:
/// `MADV_DONTFORK` (the child has nothing there) and `MADV_DOFORK`;
/// guard pages (an access is a `SIGSEGV`, whatever `mprotect` says, until
/// removed, then reading zero); `MADV_REMOVE` (a shared mapping's file
/// reads zero; private memory refused); `MADV_DONTNEED_LOCKED`.
fn madvise_controls() {
    // SAFETY: plain calls into the C library on mappings made here.
    unsafe {
        let k = 16 << 10;
        let anon = |len: usize, flags: i32| {
            mmap(std::ptr::null_mut(), len, PROT_RW, flags, -1, 0) as *mut u8
        };
        let p = anon(k, MAP_PRIVATE_ANON);
        *p = 7;
        let dont = madvise(p.cast(), k, MADV_DONTFORK);
        let without = in_child(|| i32::from(madvise(p.cast(), k, MADV_NORMAL) == -1 && errno() == 12));
        madvise(p.cast(), k, MADV_DOFORK);
        let with = in_child(|| i32::from(*p));
        println!("dontfork {dont}: child has it unmapped {without}; dofork: child reads {with}");

        let g = anon(3 * k, MAP_PRIVATE_ANON);
        std::ptr::write_bytes(g, 1, 3 * k);
        let installed = madvise(g.add(k).cast(), k, MADV_GUARD_INSTALL);
        let touch = || in_child(|| i32::from(std::ptr::read_volatile(g.add(k))));
        let first = touch();
        let neighbours = *g + *g.add(2 * k);
        mprotect(g.cast(), 3 * k, PROT_RW);
        let after_mprotect = touch();
        let removed = madvise(g.add(k).cast(), k, MADV_GUARD_REMOVE);
        println!(
            "guard {installed}: access {first}, neighbours {neighbours}, after mprotect {after_mprotect}; removed {removed}: reads {}",
            *g.add(k)
        );
        let l = anon(k, MAP_PRIVATE_ANON);
        mlock(l.cast(), k);
        let guard_locked = madvise(l.cast(), k, MADV_GUARD_INSTALL);
        let guard_locked = if guard_locked == -1 && errno() == 22 { "EINVAL".to_string() } else { guard_locked.to_string() };
        *l = 3;
        let dontneed = madvise(l.cast(), k, MADV_DONTNEED);
        let dontneed = if dontneed == -1 && errno() == 22 { "EINVAL".to_string() } else { dontneed.to_string() };
        let locked = madvise(l.cast(), k, MADV_DONTNEED_LOCKED);
        println!("locked: guard {guard_locked}, dontneed {dontneed}, dontneed_locked {locked} reads {}", *l);

        let errno_of = |r: i32| if r == 0 { "0".to_string() } else { match errno() { 13 => "EACCES".into(), 22 => "EINVAL".into(), e => format!("errno {e}") } };
        let private = anon(k, MAP_PRIVATE_ANON);
        let private_anon = errno_of(madvise(private.cast(), k, MADV_REMOVE));
        let shared = anon(k, MAP_SHARED_ANON);
        *shared = 5;
        let shared_anon = errno_of(madvise(shared.cast(), k, MADV_REMOVE));
        let shared_reads = *shared;
        let name = CString::new("remove").unwrap();
        let fd = memfd_create(name.as_ptr(), 0);
        ftruncate(fd, k as i64);
        let file_private = mmap(std::ptr::null_mut(), k, PROT_RW, MAP_PRIVATE, fd, 0);
        let private_file = errno_of(madvise(file_private, k, MADV_REMOVE));
        let file = mmap(std::ptr::null_mut(), k, PROT_RW, MAP_SHARED, fd, 0) as *mut u8;
        *file = 9;
        let shared_file = errno_of(madvise(file.cast(), k, MADV_REMOVE));
        let mut b = 1u8;
        pread(fd, (&mut b as *mut u8).cast(), 1, 0);
        println!(
            "remove: private anonymous {private_anon}, shared anonymous {shared_anon} reads {shared_reads}, \
             private file {private_file}, shared file {shared_file} file reads {b}"
        );
    }
}

/// `RLIMIT_MEMLOCK` for a process without `CAP_IPC_LOCK` (uid 1000): a
/// `MAP_LOCKED` mapping is refused with a limit of 0 (`EPERM`) and past
/// the limit (`EAGAIN`), as is any mapping after `mlockall(MCL_FUTURE)`;
/// `mlock` within it works.
fn memlock() {
    // SAFETY: plain calls into the C library.
    unsafe {
        let child = fork();
        if child == 0 {
            setuid(1000);
            let k = 16 << 10;
            let hard = 8 << 20;
            setrlimit(RLIMIT_MEMLOCK, &Rlimit { cur: 0, max: hard });
            println!("limit 0: MAP_LOCKED {}", map_anon(k, MAP_LOCKED));
            setrlimit(RLIMIT_MEMLOCK, &Rlimit { cur: 4 * k as u64, max: hard });
            println!(
                "limit 64 KiB: MAP_LOCKED 32 KiB {}, then 48 KiB {}",
                map_anon(2 * k, MAP_LOCKED),
                map_anon(3 * k, MAP_LOCKED)
            );
            let f = mlockall(MCL_FUTURE);
            println!(
                "mlockall(MCL_FUTURE) {f}: 48 KiB {}, 16 KiB {}",
                map_anon(3 * k, 0),
                map_anon(k, 0)
            );
            munlockall();
            let p = mmap(std::ptr::null_mut(), 3 * k, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
            println!("unlocked: 48 KiB mapped {}, mlock of 16 KiB {}", p as isize != -1, mlock(p, k));
            munmap(p, 3 * k);
            _exit(0);
        }
        reap(child);
    }
}

/// Nice values: the process's (its main thread's) and another thread's
/// own, a thread starting with its creator's; the host process given the
/// process's as far as the host lets (the test reads it while this waits
/// on its input); and `PRIO_USER` naming a user as the caller's user
/// namespace numbers it.
fn priorities() {
    // SAFETY: plain calls into the C library.
    unsafe {
        let start = getpriority(PRIO_PROCESS, 0);
        let raised = setpriority(PRIO_PROCESS, 0, 5);
        let at5 = getpriority(PRIO_PROCESS, 0);
        let lowered = setpriority(PRIO_PROCESS, 0, 2);
        println!(
            "process: start {start}, set 5 {raised} reads {at5}, lowered to 2 {lowered} reads {}",
            getpriority(PRIO_PROCESS, 0)
        );
        let main = getpid() as u32;
        let thread = std::thread::spawn(move || {
            let tid = gettid() as u32;
            let first = getpriority(PRIO_PROCESS, tid);
            let set = setpriority(PRIO_PROCESS, tid, 9);
            (first, set, getpriority(PRIO_PROCESS, 0), getpriority(PRIO_PROCESS, main))
        })
        .join()
        .unwrap();
        println!(
            "thread: starts {}, set 9 {}, reads {}, main thread's {}",
            thread.0, thread.1, thread.2, thread.3
        );
        println!("main thread: {}", getpriority(PRIO_PROCESS, 0));
        println!("pid {}", getpid());
        let mut b = 0u8;
        read(0, (&mut b as *mut u8).cast(), 1);
        let mut report = [0i32; 2];
        pipe(report.as_mut_ptr());
        let child = fork();
        if child == 0 {
            setuid(1000);
            unshare(CLONE_NEWUSER);
            let map = CString::new("/proc/self/uid_map").unwrap();
            let fd = open(map.as_ptr(), O_WRONLY);
            write(fd, b"500 1000 1".as_ptr().cast(), 10);
            close(fd);
            let mapped = getpriority(PRIO_USER, 500);
            let mapped = if mapped == -1 { format!("errno {}", errno()) } else { mapped.to_string() };
            let unmapped = getpriority(PRIO_USER, 1000);
            let unmapped = if unmapped == -1 && errno() == 3 { "ESRCH".to_string() } else { unmapped.to_string() };
            let line = format!("user namespace: user 500 (1000 outside) {mapped}, user 1000 {unmapped}\n");
            write(report[1], line.as_ptr().cast(), line.len());
            _exit(0);
        }
        reap(child);
        let mut buf = [0u8; 256];
        let n = read(report[0], buf.as_mut_ptr().cast(), buf.len());
        print!("{}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
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
        "sigpending" => sigpending_limit(),
        "priorities" => priorities(),
        "memlock" => memlock(),
        "madvise" => madvise_controls(),
        "affinity" => affinity(),
        "prlimit-other" => prlimit_other(),
        "nproc-threads" => nproc_threads(),
        "stack-limit" => stack_limit(),
        "deep" => std::process::exit(i32::from(deep(arg(2).parse::<u32>().unwrap() * 16) == 255)),
        // SAFETY: waiting for a signal.
        "pause" => loop {
            unsafe { pause() };
        },
        other => {
            eprintln!("unknown check {other:?}");
            std::process::exit(2);
        }
    }
}
