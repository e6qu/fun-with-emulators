//! Namespaces and mounts as container runtimes use them, one scenario per
//! argument, each printing what it observed. Runs as (virtual) root, in a
//! root filesystem that has `/mnt`, `/newroot` (with `etc/marker` and
//! `proc`) and `/tmp`.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

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
        Some("net-outside") => {
            // The port a namespace holds is not the host's: the parent binds
            // it while a child in its own namespace has it.
            // SAFETY: plain calls; the child waits until killed.
            unsafe {
                let pid = fork();
                if pid == 0 {
                    unshare(CLONE_NEWNET);
                    set_lo_up();
                    let l = std::net::TcpListener::bind("127.0.0.1:18082").unwrap();
                    println!("inside: {}", l.local_addr().unwrap());
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    pause();
                    _exit(0);
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
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
        other => panic!("unknown scenario {other:?}"),
    }
}
