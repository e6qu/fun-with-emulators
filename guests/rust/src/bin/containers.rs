//! What container tools ask of the kernel beyond namespaces, one scenario
//! per argument, each printing what it observed. Runs as (virtual) root in
//! a root filesystem with `/tmp` and `/etc`.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

use std::ffi::CString;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENODATA: i32 = 61;
const EOPNOTSUPP: i32 = 95;
const XATTR_CREATE: i32 = 1;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const SOCK_SEQPACKET: i32 = 5;
const MSG_TRUNC: i32 = 0x20;
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0o100;
const O_DIRECTORY: i32 = 0o40000;
const EPOLLIN: u32 = 1;
const EPOLLHUP: u32 = 0x10;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLL_CTL_ADD: i32 = 1;
const CLONE_NEWNET: i32 = 0x4000_0000;

#[repr(C)]
struct SockaddrUn {
    family: u16,
    path: [u8; 108],
}

#[repr(C)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

#[repr(C)]
struct Msghdr {
    name: *mut u8,
    namelen: u32,
    iov: *mut Iovec,
    iovlen: usize,
    control: *mut u8,
    controllen: usize,
    flags: i32,
}

unsafe extern "C" {
    fn setxattr(p: *const std::ffi::c_char, n: *const std::ffi::c_char, v: *const u8, s: usize, f: i32) -> i32;
    fn lsetxattr(p: *const std::ffi::c_char, n: *const std::ffi::c_char, v: *const u8, s: usize, f: i32) -> i32;
    fn getxattr(p: *const std::ffi::c_char, n: *const std::ffi::c_char, v: *mut u8, s: usize) -> isize;
    fn listxattr(p: *const std::ffi::c_char, l: *mut u8, s: usize) -> isize;
    fn removexattr(p: *const std::ffi::c_char, n: *const std::ffi::c_char) -> i32;
    fn symlink(t: *const std::ffi::c_char, p: *const std::ffi::c_char) -> i32;
    fn mkdir(p: *const std::ffi::c_char, m: u32) -> i32;
    fn chmod(p: *const std::ffi::c_char, m: u32) -> i32;
    fn fchmod(fd: i32, m: u32) -> i32;
    fn open(p: *const std::ffi::c_char, f: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, b: *mut u8, n: usize) -> isize;
    fn write(fd: i32, b: *const u8, n: usize) -> isize;
    fn fork() -> i32;
    fn waitpid(pid: i32, st: *mut i32, o: i32) -> i32;
    fn setuid(u: u32) -> i32;
    fn umask(m: u32) -> u32;
    fn chdir(p: *const std::ffi::c_char) -> i32;
    fn readlink(p: *const std::ffi::c_char, b: *mut u8, n: usize) -> isize;
    fn unshare(f: i32) -> i32;
    fn socket(d: i32, t: i32, p: i32) -> i32;
    fn bind(fd: i32, a: *const SockaddrUn, l: u32) -> i32;
    fn listen(fd: i32, n: i32) -> i32;
    fn connect(fd: i32, a: *const SockaddrUn, l: u32) -> i32;
    fn accept(fd: i32, a: *mut u8, l: *mut u32) -> i32;
    fn send(fd: i32, b: *const u8, n: usize, f: i32) -> isize;
    fn recvmsg(fd: i32, m: *mut Msghdr, f: i32) -> isize;
    fn epoll_create1(f: i32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, ev: *mut EpollEvent) -> i32;
    fn epoll_wait(ep: i32, ev: *mut EpollEvent, n: i32, t: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's errno location for this thread.
    unsafe { *__errno_location() }
}

fn name(e: i32) -> &'static str {
    match e {
        EPERM => "EPERM",
        ENOENT => "ENOENT",
        EACCES => "EACCES",
        EEXIST => "EEXIST",
        ENODATA => "ENODATA",
        EOPNOTSUPP => "EOPNOTSUPP",
        _ => "?",
    }
}

/// `r` as the scenario prints it: `ok`, or the errno's name.
fn res(r: i64) -> &'static str {
    if r >= 0 { "ok" } else { name(errno()) }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mode(p: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{:o}", std::fs::symlink_metadata(p).unwrap().mode() & 0o7777)
}

fn unix_addr(path: &str) -> (SockaddrUn, u32) {
    let mut a = SockaddrUn { family: AF_UNIX as u16, path: [0; 108] };
    a.path[..path.len()].copy_from_slice(path.as_bytes());
    (a, (2 + path.len() + 1) as u32)
}

/// One message from `fd` into a buffer of `cap` bytes: what it held, and
/// whether it was cut short.
fn recv_one(fd: i32, cap: usize) -> (isize, String, bool) {
    let mut buf = vec![0u8; cap];
    let mut iov = Iovec { base: buf.as_mut_ptr(), len: cap };
    let mut m = Msghdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: std::ptr::null_mut(),
        controllen: 0,
        flags: 0,
    };
    // SAFETY: a valid message header and buffer.
    let n = unsafe { recvmsg(fd, &mut m, 0) };
    let text = String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned();
    (n, text, m.flags & MSG_TRUNC != 0)
}

fn main() {
    // SAFETY: the scenarios' calls take valid strings and buffers.
    unsafe {
        match std::env::args().nth(1).as_deref() {
            // Extended attributes by namespace, as container images carry
            // them (file capabilities, overlay markers).
            Some("xattr") => {
                std::fs::write("/tmp/f", b"x").unwrap();
                let f = c("/tmp/f");
                let set = |n: &str, v: &str, fl: i32| {
                    res(setxattr(f.as_ptr(), c(n).as_ptr(), v.as_ptr(), v.len(), fl) as i64)
                };
                println!("user: {}", set("user.a", "1", 0));
                println!("trusted: {}", set("trusted.overlay.opaque", "y", XATTR_CREATE));
                println!("again, create: {}", set("trusted.overlay.opaque", "y", XATTR_CREATE));
                println!("acl: {}", set("system.posix_acl_access", "", 0));
                println!("no namespace: {}", set("foo", "1", 0));
                let mut buf = [0u8; 64];
                let n = getxattr(f.as_ptr(), c("trusted.overlay.opaque").as_ptr(), buf.as_mut_ptr(), 64);
                println!("get: {}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
                let size = getxattr(f.as_ptr(), c("user.a").as_ptr(), std::ptr::null_mut(), 0);
                println!("size: {size}");
                let n = getxattr(f.as_ptr(), c("user.none").as_ptr(), buf.as_mut_ptr(), 64);
                println!("missing: {}", res(n as i64));
                let n = listxattr(f.as_ptr(), buf.as_mut_ptr(), 64);
                let mut names: Vec<String> = buf[..n.max(0) as usize]
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                names.sort();
                println!("list: {}", names.join(" "));
                println!("remove: {}", res(removexattr(f.as_ptr(), c("user.a").as_ptr()) as i64));
                symlink(c("/tmp/f").as_ptr(), c("/tmp/l").as_ptr());
                let l = c("/tmp/l");
                let r = lsetxattr(l.as_ptr(), c("user.b").as_ptr(), b"1".as_ptr(), 1, 0);
                println!("user on a link: {}", res(r as i64));
                let r = lsetxattr(l.as_ptr(), c("trusted.b").as_ptr(), b"1".as_ptr(), 1, 0);
                println!("trusted on a link: {}", res(r as i64));
            }
            // Root passes permission bits; a mode denying the owner is what
            // `stat` shows; a process without the capabilities is refused.
            Some("modes") => {
                mkdir(c("/tmp/ro").as_ptr(), 0o555);
                println!("dir: {}", mode("/tmp/ro"));
                let fd = open(c("/tmp/ro/f").as_ptr(), O_WRONLY | O_CREAT, 0o644);
                println!("root makes a file in it: {}", res(fd as i64));
                close(fd);
                chmod(c("/tmp/ro/f").as_ptr(), 0);
                println!("file: {}", mode("/tmp/ro/f"));
                let fd = open(c("/tmp/ro/f").as_ptr(), O_WRONLY);
                println!("root writes it: {}", res(fd as i64));
                close(fd);
                if fork() == 0 {
                    // A user of its own: no capabilities.
                    setuid(1000);
                    let fd = open(c("/tmp/ro/f").as_ptr(), O_RDONLY);
                    println!("user reads it: {}", res(fd as i64));
                    let fd = open(c("/tmp/ro/g").as_ptr(), O_WRONLY | O_CREAT, 0o644);
                    println!("user makes a file: {}", res(fd as i64));
                    _exit(0);
                }
                waitpid(-1, std::ptr::null_mut(), 0);
                chmod(c("/tmp/ro").as_ptr(), 0o755);
                println!("dir after chmod: {}", mode("/tmp/ro"));
            }
            // A listening SOCK_SEQPACKET socket: messages keep their
            // boundaries, a long one is cut (MSG_TRUNC), and the peer's
            // close is end-of-file that epoll reports.
            Some("seqpacket") => {
                let (addr, len) = unix_addr("/tmp/sp");
                let l = socket(AF_UNIX, SOCK_SEQPACKET, 0);
                println!("bind: {}", res(bind(l, &addr, len) as i64));
                listen(l, 1);
                if fork() == 0 {
                    let s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
                    connect(s, &addr, len);
                    for m in ["one", "two", "hello world"] {
                        send(s, m.as_ptr(), m.len(), 0);
                    }
                    let mut b = 0u8;
                    // Until the parent has read them all.
                    read(s, &mut b, 1);
                    _exit(0);
                }
                let conn = accept(l, std::ptr::null_mut(), std::ptr::null_mut());
                for cap in [64, 64, 5] {
                    let (n, text, cut) = recv_one(conn, cap);
                    println!("got {n} {text:?} cut {cut}");
                }
                let ep = epoll_create1(0);
                let mut ev = EpollEvent { events: EPOLLIN | EPOLLRDHUP, data: 7 };
                epoll_ctl(ep, EPOLL_CTL_ADD, conn, &mut ev);
                let mut out = EpollEvent { events: 0, data: 0 };
                println!("nothing yet: {}", epoll_wait(ep, &mut out, 1, 100));
                send(conn, b"x".as_ptr(), 1, 0);
                waitpid(-1, std::ptr::null_mut(), 0);
                let n = epoll_wait(ep, &mut out, 1, 5000);
                println!(
                    "peer gone: {n} in {} hup {}",
                    out.events & EPOLLIN != 0,
                    out.events & (EPOLLHUP | EPOLLRDHUP) != 0
                );
                let (n, _, _) = recv_one(conn, 64);
                println!("end of file: {n}");
            }
            // The process's links in /proc lead out of it mid-path.
            Some("proc-links") => {
                let d = open(c("/tmp").as_ptr(), O_RDONLY | O_DIRECTORY);
                let p = format!("/proc/self/fd/{d}/through-fd");
                let fd = open(c(&p).as_ptr(), O_WRONLY | O_CREAT, 0o644);
                println!("made through the fd: {}", res(fd as i64));
                println!("there: {}", std::path::Path::new("/tmp/through-fd").exists());
                chdir(c("/etc").as_ptr());
                println!(
                    "through cwd: {}",
                    std::fs::read_to_string("/proc/self/cwd/marker").unwrap().trim()
                );
                println!(
                    "through root: {}",
                    std::fs::read_to_string("/proc/self/root/etc/marker").unwrap().trim()
                );
                let mut buf = [0u8; 64];
                let n = readlink(c("/proc/self/cwd").as_ptr(), buf.as_mut_ptr(), 64);
                println!("cwd: {}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
            }
            // A network namespace's own sysctls; the initial one's are fixed.
            Some("sysctl") => {
                let path = "/proc/sys/net/ipv4/ping_group_range";
                let show = || std::fs::read_to_string(path).unwrap().replace('\t', " ");
                print!("initial: {}", show());
                println!(
                    "initial write: {}",
                    std::fs::write(path, "0 0").map_or_else(|e| e.to_string(), |_| "ok".into())
                );
                if fork() == 0 {
                    unshare(CLONE_NEWNET);
                    print!("new: {}", show());
                    std::fs::write(path, "0 2147483647").unwrap();
                    print!("set: {}", show());
                    let bad = std::fs::write(path, "5 1").map_or_else(|e| e.to_string(), |_| "ok".into());
                    println!("backwards: {bad}");
                    _exit(0);
                }
                waitpid(-1, std::ptr::null_mut(), 0);
                print!("initial after: {}", show());
                let listed: Vec<String> = std::fs::read_dir("/proc/sys/net/ipv4")
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .filter(|n| n == "ping_group_range")
                    .collect();
                println!("listed: {listed:?}");
            }
            // A socket's mode is its node's, less the umask; a path too long
            // for the host under the root still binds and connects.
            Some("sockets") => {
                umask(0o022);
                let (a, len) = unix_addr("/tmp/plain");
                bind(socket(AF_UNIX, SOCK_STREAM, 0), &a, len);
                println!("plain: {}", mode("/tmp/plain"));
                let s = socket(AF_UNIX, SOCK_STREAM, 0);
                fchmod(s, 0o660);
                let (a, len) = unix_addr("/tmp/chmodded");
                bind(s, &a, len);
                println!("fchmod 660: {}", mode("/tmp/chmodded"));
                let long = format!("/tmp/{}", "d".repeat(60));
                mkdir(c(&long).as_ptr(), 0o755);
                let path = format!("{long}/{}", "s".repeat(30));
                let (a, len) = unix_addr(&path);
                let l = socket(AF_UNIX, SOCK_STREAM, 0);
                println!("long bind: {}", res(bind(l, &a, len) as i64));
                listen(l, 1);
                let s = socket(AF_UNIX, SOCK_STREAM, 0);
                println!("long connect: {}", res(connect(s, &a, len) as i64));
                let (a, len) = unix_addr(&format!("{long}/missing"));
                let s = socket(AF_UNIX, SOCK_STREAM, 0);
                println!("missing: {}", res(connect(s, &a, len) as i64));
            }
            other => panic!("unknown scenario {other:?}"),
        }
    }
}
