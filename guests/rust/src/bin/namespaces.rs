//! Namespaces and mounts as container runtimes use them, one scenario per
//! argument (a thread's own included), each printing what it observed. Runs as (virtual) root, in a
//! root filesystem that has `/mnt`, `/newroot` (with `etc/marker` and
//! `proc`) and `/tmp`.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

const O_DIRECTORY: i32 = 0o40000;
const CLONE_FS: i32 = 0x0000_0200;
const CLONE_PARENT: i32 = 0x0000_8000;
const CLONE_NEWNS: i32 = 0x0002_0000;
const CLONE_NEWUTS: i32 = 0x0400_0000;
const CLONE_NEWPID: i32 = 0x2000_0000;
const CLONE_NEWIPC: i32 = 0x0800_0000;
const CLONE_NEWNET: i32 = 0x4000_0000;
const CLONE_NEWUSER: i32 = 0x1000_0000;
const MS_RDONLY: u64 = 1;
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;
const MS_REMOUNT: u64 = 32;
const MNT_DETACH: i32 = 2;
const SIGKILL: i32 = 9;
const SIGSTOP: i32 = 19;
const SIGCONT: i32 = 18;
const WNOHANG: i32 = 1;
const WUNTRACED: i32 = 2;
const WCONTINUED: i32 = 8;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;
const SIGCHLD: u64 = 17;
const SYS_CLONE: i64 = 220;
const SYS_PIVOT_ROOT: i64 = 41;
const EROFS: i32 = 30;

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
    fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn mkdirat(dirfd: i32, path: *const std::ffi::c_char, mode: u32) -> i32;
    fn setns(fd: i32, nstype: i32) -> i32;
    fn umask(mask: u32) -> u32;
    fn sethostname(name: *const u8, len: usize) -> i32;
    fn uname(u: *mut Utsname) -> i32;
    fn fork() -> i32;
    fn getuid() -> u32;
    fn getgid() -> u32;
    fn setuid(uid: u32) -> i32;
    fn getpid() -> i32;
    fn getppid() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn pause() -> i32;
    fn _exit(code: i32) -> !;
    fn mount(
        src: *const std::ffi::c_char,
        target: *const std::ffi::c_char,
        fstype: *const std::ffi::c_char,
        flags: u64,
        data: *const u8,
    ) -> i32;
    fn umount2(target: *const std::ffi::c_char, flags: i32) -> i32;
    fn chroot(path: *const std::ffi::c_char) -> i32;
    fn chdir(path: *const std::ffi::c_char) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn pipe(fds: *mut i32) -> i32;
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn __errno_location() -> *mut i32;
    fn prctl(option: i32, ...) -> i32;
    fn sigaction(sig: i32, act: *const Sigaction, old: *mut Sigaction) -> i32;
    fn poll(fds: *mut [i32; 2], n: u64, timeout: i32) -> i32;
    fn usleep(us: u32) -> i32;
}

/// musl's `struct sigaction`.
#[repr(C)]
struct Sigaction {
    handler: extern "C" fn(i32, *const u8, *const u8),
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

const PR_SET_CHILD_SUBREAPER: i32 = 36;
const PR_GET_CHILD_SUBREAPER: i32 = 37;
const SA_SIGINFO: i32 = 4;
const ECHILD: i32 = 10;

/// The `si_pid` and `si_code` of the last `SIGCHLD`.
static CHLD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static CHLD_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn on_chld(_sig: i32, info: *const u8, _ctx: *const u8) {
    // SAFETY: a `siginfo_t`, whose `si_code` is at offset 8 and `si_pid`
    // at 16.
    let (code, pid) = unsafe { (info.add(8).cast::<i32>().read(), info.add(16).cast::<i32>().read()) };
    CHLD_CODE.store(code, std::sync::atomic::Ordering::SeqCst);
    CHLD_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a `SIGCHLD` from `pid` with `si_code` `code` arrives, waiting a
/// while for it.
fn sigchld_coded(pid: i32, code: i32) -> bool {
    for _ in 0..200 {
        if CHLD_PID.load(std::sync::atomic::Ordering::SeqCst) == pid
            && CHLD_CODE.load(std::sync::atomic::Ordering::SeqCst) == code
        {
            return true;
        }
        // SAFETY: plain call.
        unsafe { usleep(10_000) };
    }
    false
}

/// Note each `SIGCHLD`'s sender in [`CHLD_PID`].
fn catch_sigchld() {
    let act = Sigaction { handler: on_chld, mask: [0; 16], flags: SA_SIGINFO, restorer: 0 };
    // SAFETY: a valid action.
    unsafe { sigaction(SIGCHLD as i32, &act, std::ptr::null_mut()) };
}

/// Whether a `SIGCHLD` from `pid` arrives, waiting a while for it.
fn sigchld_from(pid: i32) -> bool {
    for _ in 0..200 {
        if CHLD_PID.load(std::sync::atomic::Ordering::SeqCst) == pid {
            return true;
        }
        // SAFETY: plain call.
        unsafe { usleep(10_000) };
    }
    false
}

fn read_i32(fd: i32) -> i32 {
    let mut b = [0u8; 4];
    // Again when a signal (a child's SIGCHLD) interrupts it.
    // SAFETY: a valid buffer.
    while unsafe { read(fd, b.as_mut_ptr(), 4) } < 0 && errno() == 4 {}
    i32::from_ne_bytes(b)
}

fn write_i32(fd: i32, v: i32) {
    // SAFETY: a valid buffer.
    unsafe { write(fd, v.to_ne_bytes().as_ptr(), 4) };
}

/// Block until `fd` reaches its end (every writer closed it).
fn drain(fd: i32) {
    let mut b = 0u8;
    // SAFETY: a valid buffer.
    while unsafe { read(fd, &mut b, 1) } > 0 {}
}

/// Make a child that makes a grandchild and exits, leaving the grandchild
/// an orphan: the grandchild waits for its parent to end, reports its
/// parent to `report`, then runs `then`. Returns the child's pid, and the
/// grandchild's (read from `report` once the child is reaped).
fn orphan(report: [i32; 2], then: fn() -> i32) -> (i32, i32) {
    let mut hold = [0i32; 2];
    // SAFETY: plain calls; the children exit.
    unsafe {
        pipe(hold.as_mut_ptr());
        let child = fork();
        if child == 0 {
            close(hold[0]);
            let mut sub = -1;
            prctl(PR_GET_CHILD_SUBREAPER, &mut sub as *mut i32);
            let parent = getpid();
            let g = fork();
            if g == 0 {
                close(hold[1]);
                drain(hold[0]);
                // Its descriptors close before it is gone: wait for the
                // adoption, as on Linux.
                for _ in 0..500 {
                    if getppid() != parent {
                        break;
                    }
                    usleep(10_000);
                }
                write_i32(report[1], getppid());
                _exit(then());
            }
            write_i32(report[1], sub);
            write_i32(report[1], g);
            _exit(0);
        }
        close(hold[0]);
        close(hold[1]);
        let mut status = 0;
        waitpid(child, &mut status, 0);
        println!("child exited {}", (status >> 8) & 0xff);
        let sub = read_i32(report[0]);
        println!("child is not a subreaper: {}", sub == 0);
        (child, read_i32(report[0]))
    }
}

/// A pid namespace's init with a child of its own, which holds the write
/// end of the pipe whose read end is returned (with the init's pid) and
/// waits to be killed; the init then waits too (`stay`), or exits 3.
fn init_with_member(stay: bool) -> (i32, i32) {
    let (mut hold, mut ready, mut up) = ([0i32; 2], [0i32; 2], [0i32; 2]);
    // SAFETY: plain calls; the children exit.
    unsafe {
        pipe(hold.as_mut_ptr());
        pipe(ready.as_mut_ptr());
        pipe(up.as_mut_ptr());
        let init = clone_child(CLONE_NEWPID, || {
            // Plain calls, in the unsafe block around.
            {
                if fork() == 0 {
                    close(hold[0]);
                    write(ready[1], b"x".as_ptr(), 1);
                    pause();
                    _exit(0);
                }
                let mut b = 0u8;
                read(ready[0], &mut b, 1);
                write(up[1], b"x".as_ptr(), 1);
                if stay {
                    pause();
                }
            }
            3
        });
        for fd in [hold[1], ready[0], ready[1], up[1]] {
            close(fd);
        }
        let mut b = 0u8;
        read(up[0], &mut b, 1);
        close(up[0]);
        (init, hold[0])
    }
}

/// Whether the processes holding the write end of the pipe `fd` reads
/// have all ended within `ms` milliseconds; `fd` is closed.
fn ended_now(fd: i32, ms: i32) -> bool {
    let mut pfd = [fd, 1]; // POLLIN
    let mut b = 0u8;
    // SAFETY: plain calls with valid arguments.
    unsafe {
        let r = poll(&mut pfd, 1, ms) == 1 && read(fd, &mut b, 1) == 0;
        close(fd);
        r
    }
}

/// Wait for a signal to end the process.
fn wait_forever() -> i32 {
    // SAFETY: plain call.
    unsafe { pause() };
    0
}

/// How a wait status ended: "exited N" or "killed by N".
fn ended(status: i32) -> String {
    if status & 0x7f == 0 {
        format!("exited {}", (status >> 8) & 0xff)
    } else {
        format!("killed by {}", status & 0x7f)
    }
}

/// The `PPid` line of `/proc/<pid>/status`.
fn proc_ppid(pid: i32) -> i32 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("PPid:\t").and_then(|v| v.trim().parse().ok()))
        .unwrap_or(-1)
}

fn errno() -> i32 {
    // SAFETY: musl's errno location for this thread.
    unsafe { *__errno_location() }
}

fn node() -> String {
    // SAFETY: zeroed bytes are a valid `Utsname`, which uname fills.
    let mut u: Utsname = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { uname(&mut u) };
    let end = u.nodename.iter().position(|&b| b == 0).unwrap_or(65);
    String::from_utf8_lossy(&u.nodename[..end]).into_owned()
}

/// Run `f` in a child and return its exit status.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: plain calls; the child runs `f` and exits.
    unsafe {
        let pid = fork();
        if pid == 0 {
            _exit(f());
        }
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        (status >> 8) & 0xff
    }
}

/// `clone(flags | SIGCHLD)` as a fork: the child runs `f`.
fn clone_child(flags: i32, f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: a fork-like clone with no new stack; the child runs `f`.
    unsafe {
        let pid = syscall(SYS_CLONE, flags as u64 | SIGCHLD, 0u64, 0u64, 0u64, 0u64) as i32;
        if pid == 0 {
            _exit(f());
        }
        pid
    }
}

/// Bring the loopback interface up, as a runtime does in a new network
/// namespace (`SIOCSIFFLAGS` with `IFF_UP`).
fn set_lo_up() -> bool {
    const SIOCSIFFLAGS: u64 = 0x8914;
    let mut ifr = [0u8; 40];
    ifr[..2].copy_from_slice(b"lo");
    ifr[16] = 1 | 8; // IFF_UP | IFF_LOOPBACK
    // SAFETY: a socket for the request, and a valid ifreq.
    unsafe {
        let s = socket(2, 2, 0);
        let r = ioctl(s, SIOCSIFFLAGS, ifr.as_mut_ptr());
        close(s);
        r == 0
    }
}

fn mounted(point: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|m| m.lines().any(|l| l.split(' ').nth(4) == Some(point)))
        .unwrap_or(false)
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        // A new UTS namespace: its own host name, which the parent's does
        // not see.
        Some("uts") => {
            let before = node();
            let code = in_child(|| {
                // SAFETY: plain calls with a valid buffer.
                unsafe {
                    if unshare(CLONE_NEWUTS) != 0 {
                        return 1;
                    }
                    sethostname(b"box".as_ptr(), 3);
                }
                println!("inside: {}", node());
                println!(
                    "proc: {}",
                    std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim()
                );
                0
            });
            println!("child exited {code}, outside unchanged: {}", node() == before);
            // SAFETY: a valid buffer.
            println!(
                "outside sethostname: {} errno {}",
                unsafe { sethostname(b"x".as_ptr(), 1) },
                errno()
            );
        }
        // A new pid namespace: the child is its init (pid 1, parent 0), its
        // own children are numbered from there, and the parent sees the
        // child by a pid of its own.
        Some("pid") => {
            let pid = clone_child(CLONE_NEWPID, || {
                // SAFETY: plain calls.
                unsafe {
                    println!("child: pid {} ppid {}", getpid(), getppid());
                    let mut ready = [0i32; 2];
                    pipe(ready.as_mut_ptr());
                    let grandchild = fork();
                    if grandchild == 0 {
                        println!("grandchild: pid {} ppid {}", getpid(), getppid());
                        write(ready[1], b"x".as_ptr(), 1);
                        pause();
                        _exit(0);
                    }
                    let mut b = 0u8;
                    read(ready[0], &mut b, 1);
                    println!("forked {grandchild}");
                    println!("kill: {}", kill(grandchild, SIGKILL));
                    let mut status = 0;
                    let w = waitpid(grandchild, &mut status, 0);
                    println!("reaped {w}, killed by {}", status & 0x7f);
                    println!("no such pid: {} errno {}", kill(77, 0), errno());
                }
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                7
            });
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            let w = unsafe { waitpid(pid, &mut status, 0) };
            println!(
                "parent: child {} reaped as itself, exited {}",
                w == pid && pid > 1,
                (status >> 8) & 0xff
            );
        }
        // A mount in a new mount namespace is that namespace's only.
        Some("mount") => {
            let code = in_child(|| {
                // SAFETY: plain calls with NUL-terminated strings.
                unsafe {
                    unshare(CLONE_NEWNS);
                    mount(
                        c"none".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        MS_REC | MS_PRIVATE,
                        std::ptr::null(),
                    );
                    let r = mount(
                        c"tmpfs".as_ptr(),
                        c"/mnt".as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        b"mode=755\0".as_ptr(),
                    );
                    println!("mount tmpfs: {r}");
                }
                std::fs::write("/mnt/file", b"in tmpfs").unwrap();
                println!(
                    "inside: {} {}",
                    std::fs::read_to_string("/mnt/file").unwrap(),
                    mounted("/mnt")
                );
                // A read-only bind of it.
                // SAFETY: as above.
                unsafe {
                    std::fs::create_dir_all("/tmp/ro").unwrap();
                    mount(
                        c"/mnt".as_ptr(),
                        c"/tmp/ro".as_ptr(),
                        std::ptr::null(),
                        MS_BIND,
                        std::ptr::null(),
                    );
                    mount(
                        std::ptr::null(),
                        c"/tmp/ro".as_ptr(),
                        std::ptr::null(),
                        MS_REMOUNT | MS_BIND | MS_RDONLY,
                        std::ptr::null(),
                    );
                }
                println!("through the bind: {}", std::fs::read_to_string("/tmp/ro/file").unwrap());
                let e = std::fs::write("/tmp/ro/other", b"x").unwrap_err().raw_os_error();
                println!("write there: EROFS {}", e == Some(EROFS));
                // SAFETY: as above.
                println!("umount: {}", unsafe { umount2(c"/tmp/ro".as_ptr(), 0) });
                0
            });
            println!(
                "child exited {code}, outside: {} {}",
                std::path::Path::new("/mnt/file").exists(),
                mounted("/mnt")
            );
        }
        // A container's root, as crun makes it: a bind mount of the new
        // root onto itself, `pivot_root(".", ".")`, and the old root
        // unmounted from on top of it.
        Some("pivot") => {
            let code = in_child(|| {
                // SAFETY: plain calls with NUL-terminated strings.
                unsafe {
                    unshare(CLONE_NEWNS);
                    mount(
                        c"none".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        MS_REC | MS_PRIVATE,
                        std::ptr::null(),
                    );
                    mount(
                        c"/newroot".as_ptr(),
                        c"/newroot".as_ptr(),
                        std::ptr::null(),
                        MS_BIND | MS_REC,
                        std::ptr::null(),
                    );
                    mount(
                        c"proc".as_ptr(),
                        c"/newroot/proc".as_ptr(),
                        c"proc".as_ptr(),
                        0,
                        std::ptr::null(),
                    );
                    chdir(c"/newroot".as_ptr());
                    println!("pivot: {}", syscall(SYS_PIVOT_ROOT, c".".as_ptr(), c".".as_ptr()));
                    println!("umount old root: {}", umount2(c".".as_ptr(), MNT_DETACH));
                    chdir(c"/".as_ptr());
                }
                println!("marker: {}", std::fs::read_to_string("/etc/marker").unwrap().trim());
                println!("old root gone: {}", !std::path::Path::new("/newroot").exists());
                println!("proc: {}", std::fs::read_link("/proc/self/exe").is_ok());
                let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
                println!(
                    "mounts: {}",
                    info.lines()
                        .map(|l| l.split(' ').nth(4).unwrap())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                0
            });
            println!("child exited {code}");
        }
        // `chroot`, and the namespaces a clone makes for its child.
        Some("chroot") => {
            let code = in_child(|| {
                // SAFETY: NUL-terminated strings.
                unsafe {
                    println!("chroot: {}", chroot(c"/newroot".as_ptr()));
                    chdir(c"/".as_ptr());
                }
                println!("marker: {}", std::fs::read_to_string("/etc/marker").unwrap().trim());
                println!(
                    "cannot leave: {}",
                    std::fs::read_to_string("/../../etc/marker").unwrap().trim()
                );
                0
            });
            println!("child exited {code}");
            let pid = clone_child(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET, || {
                let ns = |k: &str| {
                    std::fs::read_link(format!("/proc/self/ns/{k}")).unwrap().display().to_string()
                };
                println!(
                    "new namespaces: {}",
                    ["mnt", "uts", "ipc", "net"]
                        .iter()
                        .map(|k| ns(k))
                        .all(|l| !l.contains("40265318"))
                );
                0
            });
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            unsafe { waitpid(pid, &mut status, 0) };
            let ns = |k: &str| {
                std::fs::read_link(format!("/proc/self/ns/{k}")).unwrap().display().to_string()
            };
            println!("own: {} {}", ns("uts"), ns("pid"));
        }
        // A network namespace: a loopback interface, down until brought up,
        // and ports of its own.
        Some("net") => {
            use std::io::{Read, Write};
            let code = in_child(|| {
                // SAFETY: plain call.
                unsafe { unshare(CLONE_NEWNET) };
                let down = std::net::TcpListener::bind("127.0.0.1:18080").map(|_| ()).unwrap_err();
                println!("lo down: {:?}", down.raw_os_error() == Some(99));
                println!("lo up: {}", set_lo_up());
                let listener = std::net::TcpListener::bind("127.0.0.1:18080").unwrap();
                println!("bound: {}", listener.local_addr().unwrap());
                let mut client = std::net::TcpStream::connect("127.0.0.1:18080").unwrap();
                println!("client's peer: {}", client.peer_addr().unwrap());
                let (mut conn, _) = listener.accept().unwrap();
                client.write_all(b"ping").unwrap();
                let mut buf = [0u8; 4];
                conn.read_exact(&mut buf).unwrap();
                println!("served: {}", String::from_utf8_lossy(&buf));
                let again = std::net::TcpListener::bind("0.0.0.0:18080").map(|_| ()).unwrap_err();
                println!("taken: {}", again.raw_os_error() == Some(98));
                let far = std::net::TcpStream::connect("10.1.2.3:80").map(|_| ()).unwrap_err();
                println!("elsewhere: {}", far.raw_os_error() == Some(101));
                let refused =
                    std::net::TcpStream::connect("127.0.0.1:18081").map(|_| ()).unwrap_err();
                println!("nobody there: {}", refused.raw_os_error() == Some(111));
                std::io::stdout().flush().unwrap();
                0
            });
            println!("child exited {code}");
        }
        // A thread's own root, mounts and network namespace, as Docker
        // makes them on one of its threads while the others carry on; and
        // a working directory and umask the threads share.
        Some("threads") => {
            use std::os::fd::AsRawFd;
            let own = std::thread::spawn(|| {
                // SAFETY: plain calls with NUL-terminated strings.
                unsafe {
                    let u = unshare(CLONE_FS | CLONE_NEWNS);
                    let p = mount(
                        c"none".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        MS_REC | MS_PRIVATE,
                        std::ptr::null(),
                    );
                    let m = mount(
                        c"tmpfs".as_ptr(),
                        c"/mnt".as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        std::ptr::null(),
                    );
                    let mnt = mounted("/mnt");
                    let c = chroot(c"/newroot".as_ptr());
                    chdir(c"/".as_ptr());
                    let marker = std::fs::read_to_string("/etc/marker").unwrap_or_default();
                    format!(
                        "thread: unshare {u} private {p} tmpfs {m} {mnt} chroot {c} marker {}",
                        marker.trim()
                    )
                }
            });
            println!("{}", own.join().unwrap());
            println!(
                "others: root kept {}, /mnt not mounted {}",
                std::path::Path::new("/newroot/etc/marker").exists(),
                !mounted("/mnt")
            );
            // Shared: what a thread sets, the others have.
            std::thread::spawn(|| {
                // SAFETY: plain calls.
                unsafe {
                    umask(0o077);
                    chdir(c"/tmp".as_ptr());
                }
            })
            .join()
            .unwrap();
            // SAFETY: plain call.
            let was = unsafe { umask(0o022) };
            let cwd = std::env::current_dir().unwrap();
            println!("shared: umask {was:o} cwd {}", cwd.display());
            // SAFETY: a NUL-terminated path.
            unsafe { chdir(c"/".as_ptr()) };
            // A thread's own network namespace, then back in the process's.
            let (to_main, from_thread) = std::sync::mpsc::channel();
            let (to_thread, from_main) = std::sync::mpsc::channel::<()>();
            let net = std::thread::spawn(move || {
                let orig = std::fs::File::open("/proc/self/ns/net").unwrap();
                // SAFETY: plain calls.
                unsafe { unshare(CLONE_NEWNET) };
                set_lo_up();
                let inside = std::net::TcpListener::bind("127.0.0.1:18090");
                to_main.send(inside.is_ok()).unwrap();
                from_main.recv().unwrap();
                // SAFETY: a namespace descriptor.
                let back = unsafe { setns(orig.as_raw_fd(), CLONE_NEWNET) };
                let again = std::net::TcpListener::bind("127.0.0.1:18090").map(|_| ()).unwrap_err();
                format!("back: {back}, port taken {}", again.raw_os_error() == Some(98))
            });
            let inside = from_thread.recv().unwrap();
            let outside = std::net::TcpListener::bind("127.0.0.1:18090");
            println!("net: thread bound {inside}, process too {}", outside.is_ok());
            to_thread.send(()).unwrap();
            println!("{}", net.join().unwrap());
            // A mount namespace is not joined while the root is shared.
            let mnt = std::fs::File::open("/proc/self/ns/mnt").unwrap();
            let (hold, wait) = std::sync::mpsc::channel::<()>();
            let other = std::thread::spawn(move || wait.recv());
            // SAFETY: a namespace descriptor.
            let r = unsafe { setns(mnt.as_raw_fd(), CLONE_NEWNS) };
            println!("setns mnt with threads: {r} errno {}", errno());
            drop(hold);
            let _ = other.join();
        }
        // A network namespace kept by a bind mount of its file, as Docker
        // and `ip netns` keep one: made on a thread, bound by its
        // `/proc/<pid>/task/<tid>/ns/net`, joined through the file by the
        // process and by a child, and gone from the path once unmounted.
        Some("nsbind") => {
            use std::os::fd::AsRawFd;
            std::fs::write("/tmp/netns", b"").unwrap();
            let made = std::thread::spawn(|| {
                let orig = std::fs::File::open("/proc/self/ns/net").unwrap();
                // SAFETY: plain calls with NUL-terminated strings.
                unsafe {
                    unshare(CLONE_NEWNET);
                    set_lo_up();
                    let tid = syscall(178);
                    let src = std::ffi::CString::new(format!(
                        "/proc/{}/task/{tid}/ns/net",
                        getpid()
                    ))
                    .unwrap();
                    let link = std::fs::read_link(src.to_str().unwrap()).unwrap();
                    let m = mount(
                        src.as_ptr(),
                        c"/tmp/netns".as_ptr(),
                        std::ptr::null(),
                        MS_BIND,
                        std::ptr::null(),
                    );
                    let back = setns(orig.as_raw_fd(), CLONE_NEWNET);
                    (m, back, link)
                }
            });
            let (m, back, link) = made.join().unwrap();
            println!("bind: {m}, back {back}");
            let ino = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata("/tmp/netns").unwrap().ino()
            };
            let id = link.to_string_lossy().trim_start_matches("net:[").trim_end_matches(']').to_string();
            println!("inode is the namespace's: {}", ino.to_string() == id);
            println!(
                "mountinfo: {}",
                std::fs::read_to_string("/proc/self/mountinfo")
                    .unwrap()
                    .lines()
                    .any(|l| l.contains(" /tmp/netns ") && l.contains(" - nsfs nsfs "))
            );
            // Through a directory's link too, as `/var/run` leads to `/run`.
            std::os::unix::fs::symlink("/tmp", "/tmp/via").unwrap();
            let ns = std::fs::File::open("/tmp/via/netns").unwrap();
            // SAFETY: a namespace descriptor.
            let joined = unsafe { setns(ns.as_raw_fd(), CLONE_NEWNET) };
            let held = std::net::TcpListener::bind("127.0.0.1:18091");
            println!("joined: {joined}, bound {}", held.is_ok());
            let code = in_child(|| {
                let ns = std::fs::File::open("/tmp/netns").unwrap();
                // SAFETY: a namespace descriptor.
                let r = unsafe { setns(ns.as_raw_fd(), CLONE_NEWNET) };
                let taken = std::net::TcpListener::bind("127.0.0.1:18091").map(|_| ()).unwrap_err();
                println!("child joined: {r}, port taken {}", taken.raw_os_error() == Some(98));
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                0
            });
            println!("child exited {code}");
            // SAFETY: a NUL-terminated path.
            let u = unsafe { umount2(c"/tmp/netns".as_ptr(), MNT_DETACH) };
            let plain = std::fs::File::open("/tmp/netns").unwrap();
            // SAFETY: a descriptor of a plain file.
            let r = unsafe { setns(plain.as_raw_fd(), CLONE_NEWNET) };
            println!("umount: {u}, a plain file again: {r} errno {}", errno());
        }
        // A directory of a bind mount of an overlay, opened, reaches what
        // is mounted below the bind (runc makes `dev/pts` in the tmpfs it
        // put on a container's `dev` this way), not the overlay's own.
        Some("ovlbind") => {
            use std::os::fd::AsRawFd;
            for d in ["/tmp/lower/dev", "/tmp/upper", "/tmp/work", "/tmp/o", "/tmp/b"] {
                std::fs::create_dir_all(d).unwrap();
            }
            let code = in_child(|| {
                // SAFETY: plain calls with NUL-terminated strings.
                unsafe {
                    unshare(CLONE_NEWNS);
                    let o = mount(
                        c"overlay".as_ptr(),
                        c"/tmp/o".as_ptr(),
                        c"overlay".as_ptr(),
                        0,
                        c"lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work".as_ptr().cast(),
                    );
                    let b = mount(
                        c"/tmp/o".as_ptr(),
                        c"/tmp/b".as_ptr(),
                        c"bind".as_ptr(),
                        MS_BIND | MS_REC,
                        std::ptr::null(),
                    );
                    let t = mount(
                        c"tmpfs".as_ptr(),
                        c"/tmp/b/dev".as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        std::ptr::null(),
                    );
                    println!("mounts: {o} {b} {t}");
                }
                let root = std::fs::File::open("/tmp/b").unwrap();
                let dev = std::ffi::CString::new("dev").unwrap();
                let pts = std::ffi::CString::new("pts").unwrap();
                // SAFETY: a directory descriptor and NUL-terminated names.
                let made = unsafe {
                    let d = openat(root.as_raw_fd(), dev.as_ptr(), O_DIRECTORY);
                    mkdirat(d, pts.as_ptr(), 0o755)
                };
                println!(
                    "mkdir: {made}, in the tmpfs {}, not the overlay's {}",
                    std::path::Path::new("/tmp/b/dev/pts").is_dir(),
                    !std::path::Path::new("/tmp/o/dev/pts").exists()
                );
                0
            });
            println!("child exited {code}");
        }
        Some("net-outside") => {
            // The port a namespace holds is not the host's: the parent binds
            // it while a child in its own namespace has it.
            // SAFETY: plain calls; the child waits until killed.
            unsafe {
                let mut ready = [0i32; 2];
                pipe(ready.as_mut_ptr());
                let pid = fork();
                if pid == 0 {
                    unshare(CLONE_NEWNET);
                    set_lo_up();
                    let l = std::net::TcpListener::bind("127.0.0.1:18082").unwrap();
                    println!("inside: {}", l.local_addr().unwrap());
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    write(ready[1], b"x".as_ptr(), 1);
                    pause();
                    _exit(0);
                }
                // Once the child holds its port.
                let mut b = 0u8;
                read(ready[0], &mut b, 1);
                let outside = std::net::TcpListener::bind("127.0.0.1:18082");
                println!("outside too: {}", outside.is_ok());
                kill(pid, SIGKILL);
                let mut status = 0;
                waitpid(pid, &mut status, 0);
            }
        }
        // A user namespace: unmapped until its map is written, by itself
        // (its own id only, setgroups denied first) or by its parent.
        Some("user") => {
            let code = in_child(|| {
                // SAFETY: plain calls.
                unsafe {
                    unshare(CLONE_NEWUSER);
                    println!("unmapped: {} {}", getuid(), getgid());
                }
                let caps = std::fs::read_to_string("/proc/self/status").unwrap();
                println!("{}", caps.lines().find(|l| l.starts_with("CapEff")).unwrap());
                let w = |p: &str, s: &str| {
                    std::fs::write(p, s).map_err(|e| e.raw_os_error().unwrap_or(0))
                };
                println!("gid_map before setgroups: {:?}", w("/proc/self/gid_map", "0 0 1"));
                println!("setgroups: {:?}", w("/proc/self/setgroups", "deny"));
                println!("uid_map, more than one's own: {:?}", w("/proc/self/uid_map", "0 0 2"));
                println!("uid_map: {:?}", w("/proc/self/uid_map", "0 0 1"));
                println!("gid_map: {:?}", w("/proc/self/gid_map", "0 0 1"));
                println!("again: {:?}", w("/proc/self/uid_map", "0 0 1"));
                // SAFETY: plain calls.
                unsafe {
                    println!("mapped: {} {}", getuid(), getgid());
                    println!("setuid to an unmapped id: {} errno {}", setuid(7), errno());
                }
                println!(
                    "map: {}",
                    std::fs::read_to_string("/proc/self/uid_map").unwrap().trim_end()
                );
                0
            });
            println!("child exited {code}");
            // The parent writes a child's map, with ranges.
            let mut ready = [0i32; 2];
            let mut go = [0i32; 2];
            // SAFETY: plain calls with valid arrays.
            unsafe {
                pipe(ready.as_mut_ptr());
                pipe(go.as_mut_ptr());
            }
            let pid = clone_child(CLONE_NEWUSER, || {
                let mut b = 0u8;
                // SAFETY: plain calls on the pipes.
                unsafe {
                    write(ready[1], b"x".as_ptr(), 1);
                    read(go[0], &mut b, 1);
                    println!(
                        "in child: uid {}, setuid(5) {}, uid {}",
                        getuid(),
                        setuid(5),
                        getuid()
                    );
                }
                0
            });
            let mut b = 0u8;
            // SAFETY: plain calls on the pipes.
            unsafe { read(ready[0], &mut b, 1) };
            let map = std::fs::write(format!("/proc/{pid}/uid_map"), "0 0 1\n1 100000 1000\n");
            println!("parent wrote the map: {}", map.is_ok());
            // SAFETY: plain calls.
            unsafe {
                write(go[1], b"x".as_ptr(), 1);
                let mut status = 0;
                waitpid(pid, &mut status, 0);
            }
        }
        // A child subreaper adopts the orphans below it: it is their
        // parent, is sent SIGCHLD when one ends, and reaps it.
        // Children made with CLONE_PARENT are the creator's parent's: it
        // is told when each ends and reaps it, though it is no subreaper
        // and they are not its children on the host; as runc makes a
        // container's init, in new namespaces, two levels down.
        Some("fosters") => {
            catch_sigchld();
            // SAFETY: plain calls with valid buffers; the children end.
            unsafe {
                let mut report = [0i32; 2];
                pipe(report.as_mut_ptr());
                let first = fork();
                if first == 0 {
                    let second = syscall(SYS_CLONE, CLONE_PARENT as i64 | SIGCHLD as i64, 0, 0, 0, 0);
                    if second == 0 {
                        unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET);
                        let init =
                            syscall(SYS_CLONE, CLONE_PARENT as i64 | SIGCHLD as i64, 0, 0, 0, 0);
                        if init == 0 {
                            usleep(300_000);
                            _exit(7);
                        }
                        // Its pid: in the parent's pid namespace still.
                        write_i32(report[1], getpid());
                        write_i32(report[1], init as i32);
                        _exit(0);
                    }
                    usleep(50_000);
                    _exit(0);
                }
                let second = read_i32(report[0]);
                let init = read_i32(report[0]);
                let mut reaped = Vec::new();
                loop {
                    let mut st = 0;
                    let w = waitpid(-1, &mut st, 0);
                    if w < 0 {
                        println!("then: ECHILD {}", errno() == ECHILD);
                        break;
                    }
                    reaped.push((w, (st >> 8) & 0xff));
                }
                let has = |p: i32, code: i32| reaped.contains(&(p, code));
                println!(
                    "reaped: {} children, first {}, second {}, init exited {}",
                    reaped.len(),
                    has(first, 0),
                    has(second, 0),
                    reaped.iter().find(|r| r.0 == init).map_or(-1, |r| r.1)
                );
                println!("init's SIGCHLD: {}", sigchld_coded(init, 1));
            }
        }
        Some("subreaper") => {
            catch_sigchld();
            // SAFETY: plain calls with valid out-parameters.
            unsafe {
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                let mut on = 0;
                prctl(PR_GET_CHILD_SUBREAPER, &mut on as *mut i32);
                println!("subreaper: {on}");
                let mut report = [0i32; 2];
                pipe(report.as_mut_ptr());
                let (child, g) = orphan(report, || 7);
                let parent = read_i32(report[0]);
                // On a mismatch, what it saw instead (its old parent, still
                // there after the orphan's wait, or another).
                let seen = if parent == getpid() {
                    "true".to_string()
                } else {
                    format!("false: saw {parent}, its old parent was {child}, this is {}", getpid())
                };
                println!("orphan's parent is the subreaper: {seen}");
                let mut status = 0;
                let w = waitpid(-1, &mut status, 0);
                println!("reaped the orphan: {}, {}", w == g, ended(status));
                println!("SIGCHLD from the orphan: {}", sigchld_from(g));
                println!("then: {} errno {}", waitpid(-1, &mut status, 0), errno() == ECHILD);
            }
        }
        // A process that becomes a subreaper does not adopt the orphans
        // that had their adopter already, as on Linux an orphan is adopted
        // when its parent ends.
        Some("subreaper-late") => {
            // SAFETY: plain calls with valid out-parameters.
            unsafe {
                let mut report = [0i32; 2];
                pipe(report.as_mut_ptr());
                let (_, g) = orphan(report, wait_forever);
                println!("orphan's parent is another: {}", read_i32(report[0]) != getpid());
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                println!("and stays so: {}", proc_ppid(g) != getpid());
                let mut status = 0;
                let w = waitpid(-1, &mut status, WNOHANG);
                println!("nothing to wait for: {}", w == -1 && errno() == ECHILD);
                kill(g, SIGKILL);
            }
        }
        // An orphan a subreaper below adopted goes on to a process that
        // became a subreaper later, once the one below ends, as on Linux.
        Some("subreaper-handover") => {
            // SAFETY: plain calls with valid out-parameters; children exit.
            unsafe {
                let (mut report, mut go) = ([0i32; 2], [0i32; 2]);
                pipe(report.as_mut_ptr());
                pipe(go.as_mut_ptr());
                let b = fork();
                if b == 0 {
                    prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                    let d = fork();
                    if d == 0 {
                        let c = fork();
                        if c == 0 {
                            pause();
                            _exit(0);
                        }
                        write_i32(report[1], c);
                        _exit(0);
                    }
                    waitpid(d, std::ptr::null_mut(), 0);
                    read_i32(go[0]);
                    _exit(0);
                }
                let c = read_i32(report[0]);
                for _ in 0..500 {
                    if proc_ppid(c) == b {
                        break;
                    }
                    usleep(10_000);
                }
                println!("adopted below: {}", proc_ppid(c) == b);
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                write_i32(go[1], 1);
                let mut status = 0;
                waitpid(b, &mut status, 0);
                println!("handed up: {}", proc_ppid(c) == getpid());
                kill(c, SIGKILL);
                let w = waitpid(c, &mut status, 0);
                println!("reaped: {}, {}", w == c, ended(status));
            }
        }
        // An adopted orphan that stops and continues is reported to the
        // subreaper's `wait` and with `SIGCHLD`, as a child is.
        Some("subreaper-stop") => {
            catch_sigchld();
            // SAFETY: plain calls with valid out-parameters.
            unsafe {
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                let mut report = [0i32; 2];
                pipe(report.as_mut_ptr());
                let (_, g) = orphan(report, wait_forever);
                read_i32(report[0]);
                let mut status = 0;
                println!("nothing yet: {}", waitpid(g, &mut status, WNOHANG | WUNTRACED) == 0);
                kill(g, SIGSTOP);
                let w = waitpid(g, &mut status, WUNTRACED);
                println!("stopped: {}, by {}", w == g && status & 0xff == 0x7f, (status >> 8) & 0xff);
                println!("SIGCHLD for the stop: {}", sigchld_coded(g, CLD_STOPPED));
                println!("reported once: {}", waitpid(g, &mut status, WNOHANG | WUNTRACED) == 0);
                kill(g, SIGCONT);
                let w = waitpid(g, &mut status, WCONTINUED);
                println!("continued: {}", w == g && status == 0xffff);
                println!("SIGCHLD for the continue: {}", sigchld_coded(g, CLD_CONTINUED));
                kill(g, SIGKILL);
                let w = waitpid(g, &mut status, 0);
                println!("reaped: {}, {}", w == g, ended(status));
            }
        }
        // An adopted orphan killed outright is reaped as killed.
        Some("subreaper-kill") => {
            // SAFETY: plain calls with valid out-parameters.
            unsafe {
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                let mut report = [0i32; 2];
                pipe(report.as_mut_ptr());
                let (_, g) = orphan(report, wait_forever);
                read_i32(report[0]);
                println!("proc shows the subreaper: {}", proc_ppid(g) == getpid());
                let mut status = 0;
                println!("not ended yet: {}", waitpid(g, &mut status, 1) == 0);
                kill(g, SIGKILL);
                let w = waitpid(g, &mut status, 0);
                if w != g {
                    eprintln!("waitpid({g}) returned {w}, errno {}", errno());
                }
                println!("reaped the orphan: {}, {}", w == g, ended(status));
            }
        }
        // A child killed outright while its parent lives, a zombie of that
        // parent; when the parent ends, the subreaper is sent SIGCHLD for it
        // and reaps it.
        Some("subreaper-zombie") => {
            catch_sigchld();
            // SAFETY: plain calls with valid out-parameters.
            unsafe {
                prctl(PR_SET_CHILD_SUBREAPER, 1u64);
                let (mut report, mut go) = ([0i32; 2], [0i32; 2]);
                pipe(report.as_mut_ptr());
                pipe(go.as_mut_ptr());
                let p = fork();
                if p == 0 {
                    let x = fork();
                    if x == 0 {
                        pause();
                        _exit(0);
                    }
                    write_i32(report[1], x);
                    // Until the subreaper has killed it.
                    read_i32(go[0]);
                    _exit(0);
                }
                let x = read_i32(report[0]);
                kill(x, SIGKILL);
                // Its parent lives on a moment, then ends without waiting.
                usleep(100_000);
                write_i32(go[1], 1);
                let mut status = 0;
                waitpid(p, &mut status, 0);
                println!("SIGCHLD for the killed orphan: {}", sigchld_from(x));
                let w = waitpid(-1, &mut status, 0);
                println!("reaped it: {}, {}", w == x, ended(status));
            }
        }
        // A pid namespace's init cannot be killed from inside it, by
        // itself or by a child.
        Some("init-unkillable") => {
            let init = clone_child(CLONE_NEWPID, || {
                // Plain calls, in the unsafe block around.
                {
                    // SAFETY: plain calls.
                    unsafe {
                        println!("init kills itself: {}", kill(1, SIGKILL));
                        if fork() == 0 {
                            println!("child kills init: {}", kill(1, SIGKILL));
                            _exit(0);
                        }
                        let mut status = 0;
                        waitpid(-1, &mut status, 0);
                    }
                }
                println!("init lives");
                4
            });
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            unsafe { waitpid(init, &mut status, 0) };
            println!("init {}", ended(status));
        }
        // A pid namespace's init adopts the orphans in it.
        Some("pid-orphan") => {
            let init = clone_child(CLONE_NEWPID, || {
                // SAFETY: plain calls with valid out-parameters.
                unsafe {
                    let mut report = [0i32; 2];
                    pipe(report.as_mut_ptr());
                    let (_, g) = orphan(report, || 5);
                    println!("orphan's parent: {}", read_i32(report[0]));
                    let mut status = 0;
                    let w = waitpid(-1, &mut status, 0);
                    println!("init reaped the orphan: {}, {}", w == g, ended(status));
                }
                0
            });
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            unsafe { waitpid(init, &mut status, 0) };
            println!("init {}", ended(status));
        }
        // When a pid namespace's init ends, or is killed, every other
        // process in it is killed, before the init's parent can reap it.
        Some("init-death") => {
            for kill_it in [false, true] {
                let (init, hold) = init_with_member(kill_it);
                if kill_it {
                    // SAFETY: plain call.
                    unsafe { kill(init, SIGKILL) };
                }
                let mut status = 0;
                // SAFETY: a valid out-parameter.
                unsafe { waitpid(init, &mut status, 0) };
                println!("init {}: the rest ended first: {}", ended(status), ended_now(hold, 0));
            }
        }
        // An init killed from outside fwe (the test sends it `SIGKILL`
        // once it finds its pid in `/tmp/init-pid`) takes its namespace
        // with it, without its parent reaping it.
        Some("init-killed") => {
            let (init, hold) = init_with_member(true);
            std::fs::write("/tmp/init-pid", init.to_string()).unwrap();
            println!("the rest ended unreaped: {}", ended_now(hold, 10_000));
            let mut status = 0;
            // SAFETY: a valid out-parameter.
            unsafe { waitpid(init, &mut status, 0) };
            println!("init {}", ended(status));
        }
        other => panic!("unknown scenario {other:?}"),
    }
}
