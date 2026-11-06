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
const EFAULT: i32 = 14;
const EXDEV: i32 = 18;
const EINVAL: i32 = 22;
const EROFS: i32 = 30;
const ENOTEMPTY: i32 = 39;
const ESTALE: i32 = 116;
const MSG_PEEK: i32 = 2;
const MSG_DONTWAIT: i32 = 0x40;
const O_NONBLOCK: i32 = 0o4000;
const F_SETFL: i32 = 4;
const SOL_SOCKET: i32 = 1;
const SO_TYPE: i32 = 3;
const SCM_RIGHTS: i32 = 1;
const XATTR_CREATE: i32 = 1;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const SOCK_SEQPACKET: i32 = 5;
const MSG_TRUNC: i32 = 0x20;
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0o100;
const O_DIRECTORY: i32 = 0o40000;
const O_PATH: i32 = 0o10000000;
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
    fn socketpair(d: i32, t: i32, p: i32, sv: *mut i32) -> i32;
    fn recv(fd: i32, b: *mut u8, n: usize, f: i32) -> isize;
    fn sendmsg(fd: i32, m: *const Msghdr, f: i32) -> isize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn getsockopt(fd: i32, l: i32, o: i32, v: *mut i32, len: *mut u32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, ev: *mut EpollEvent) -> i32;
    fn epoll_wait(ep: i32, ev: *mut EpollEvent, n: i32, t: i32) -> i32;
    fn mount(s: *const std::ffi::c_char, t: *const std::ffi::c_char, f: *const std::ffi::c_char, fl: u64, d: *const u8) -> i32;
    fn umount2(t: *const std::ffi::c_char, f: i32) -> i32;
    fn statfs(p: *const std::ffi::c_char, b: *mut u64) -> i32;
    fn rmdir(p: *const std::ffi::c_char) -> i32;
    fn alarm(s: u32) -> u32;
    fn openat(d: i32, p: *const std::ffi::c_char, f: i32, ...) -> i32;
    fn pread(fd: i32, b: *mut u8, n: usize, off: i64) -> isize;
    fn lseek(fd: i32, off: i64, wh: i32) -> i64;
    fn mknod(p: *const std::ffi::c_char, m: u32, d: u64) -> i32;
    fn syscall(n: i64, ...) -> i64;
    fn pipe(fds: *mut i32) -> i32;
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
        EFAULT => "EFAULT",
        EXDEV => "EXDEV",
        ENOTEMPTY => "ENOTEMPTY",
        EROFS => "EROFS",
        EINVAL => "EINVAL",
        ESTALE => "ESTALE",
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

/// The sorted names in directory `p`.
fn names(p: &str) -> String {
    let mut v: Vec<String> = std::fs::read_dir(p)
        .map(|d| d.map(|e| e.unwrap().file_name().into_string().unwrap()).collect())
        .unwrap_or_default();
    v.sort();
    v.join(" ")
}

/// What an `std::fs` call came to.
fn io<T>(r: std::io::Result<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => name(e.raw_os_error().unwrap_or(0)),
    }
}

fn text(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| format!("<{}>", name(e.raw_os_error().unwrap_or(0))))
}

/// The names `getdents64` gives for `fd`, `size` bytes at a time, until
/// there are `max` or more.
fn dents(fd: i32, size: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; size];
    while out.len() < max {
        // SAFETY: a valid buffer of `size` bytes.
        let n = unsafe { syscall(61, fd, buf.as_mut_ptr(), size) };
        if n <= 0 {
            break;
        }
        let mut i = 0usize;
        while i < n as usize {
            let reclen = u16::from_ne_bytes([buf[i + 16], buf[i + 17]]) as usize;
            let name = &buf[i + 19..i + reclen];
            let end = name.iter().position(|&b| b == 0).unwrap();
            out.push(String::from_utf8_lossy(&name[..end]).into_owned());
            i += reclen;
        }
    }
    out
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
            // Messages bigger than a host socket's default buffers, sent
            // and taken without blocking, looked at first; a bad buffer;
            // and a SOCK_SEQPACKET socket passed to another holder of it
            // with SCM_RIGHTS keeps its message boundaries.
            Some("seqpacket-more") => {
                let mut sv = [0i32; 2];
                socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv.as_mut_ptr());
                fcntl(sv[0], F_SETFL, O_NONBLOCK);
                let big: Vec<u8> = (0..20000u32).map(|i| (i % 251) as u8 + 1).collect();
                println!("non-blocking send: {}", send(sv[0], big.as_ptr(), big.len(), 0));
                let mut buf = vec![0u8; 50000];
                let n = recv(sv[1], buf.as_mut_ptr(), buf.len(), MSG_PEEK);
                println!("peek: {n} same {}", buf[..n.max(0) as usize] == big[..]);
                let n = recv(sv[1], buf.as_mut_ptr(), buf.len(), MSG_DONTWAIT);
                println!("take: {n} same {}", buf[..n.max(0) as usize] == big[..]);
                println!("nothing left: {}", recv(sv[1], buf.as_mut_ptr(), 10, MSG_DONTWAIT));
                send(sv[0], b"x".as_ptr(), 1, 0);
                let r = read(sv[1], 8 as *mut u8, 2);
                println!("bad buffer: {} {}", r, name(errno()));
                // Pass one end of a second pair over the first.
                let mut pair = [0i32; 2];
                socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair.as_mut_ptr());
                let mut control = [0u8; 24];
                control[..8].copy_from_slice(&20u64.to_ne_bytes());
                control[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
                control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
                control[16..20].copy_from_slice(&pair[1].to_ne_bytes());
                let mut byte = *b"f";
                let mut iov = Iovec { base: byte.as_mut_ptr(), len: 1 };
                let m = Msghdr {
                    name: std::ptr::null_mut(),
                    namelen: 0,
                    iov: &mut iov,
                    iovlen: 1,
                    control: control.as_mut_ptr(),
                    controllen: 24,
                    flags: 0,
                };
                println!("passed: {}", sendmsg(sv[0], &m, 0));
                let mut cbuf = [0u8; 64];
                let mut b = 0u8;
                let mut iov = Iovec { base: &mut b, len: 1 };
                let mut m = Msghdr {
                    name: std::ptr::null_mut(),
                    namelen: 0,
                    iov: &mut iov,
                    iovlen: 1,
                    control: cbuf.as_mut_ptr(),
                    controllen: 64,
                    flags: 0,
                };
                recvmsg(sv[1], &mut m, 0);
                let got = i32::from_ne_bytes(cbuf[16..20].try_into().unwrap());
                close(pair[1]);
                for msg in ["m1", "m22"] {
                    send(pair[0], msg.as_ptr(), msg.len(), 0);
                }
                let mut ty = 0;
                let mut len = 4u32;
                getsockopt(got, SOL_SOCKET, SO_TYPE, &mut ty, &mut len);
                println!("received socket type: {ty}");
                for _ in 0..2 {
                    let (n, text, _) = recv_one(got, 64);
                    println!("through it: {n} {text:?}");
                }
            }
            // An overlay: layers merged, changes copied up, removals
            // covered by whiteouts, the lower layers untouched.
            Some("overlay") => {
                use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
                for d in ["l1/d", "l1/sub", "l2/d", "l2/deep", "u", "w", "m", "ro"] {
                    std::fs::create_dir_all(format!("/tmp/{d}")).unwrap();
                }
                for (f, text) in [
                    ("l1/a", "lower1"),
                    ("l2/a", "lower2"),
                    ("l1/d/x", "x"),
                    ("l1/d/y", "y"),
                    ("l2/d/z", "z"),
                    ("l1/gone", "g"),
                    ("l1/sub/f", "f"),
                    ("l2/deep/e", "e"),
                ] {
                    std::fs::write(format!("/tmp/{f}"), text).unwrap();
                }
                let opts = b"lowerdir=/tmp/l1:/tmp/l2,upperdir=/tmp/u,workdir=/tmp/w\0";
                let r = mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, opts.as_ptr());
                println!("mount: {}", res(r as i64));
                println!("a: {}", text("/tmp/m/a"));
                println!("d: {}", names("/tmp/m/d"));
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().append(true).open("/tmp/m/a").unwrap();
                f.write_all(b"+").unwrap();
                drop(f);
                println!("a written: {} lower: {} upper: {}", text("/tmp/m/a"), text("/tmp/l1/a"), text("/tmp/u/a"));
                println!("unlink: {}", io(std::fs::remove_file("/tmp/m/gone")));
                let w = std::fs::symlink_metadata("/tmp/u/gone").unwrap();
                println!(
                    "gone: {} lower: {} whiteout: {} {}",
                    io(std::fs::metadata("/tmp/m/gone")),
                    text("/tmp/l1/gone"),
                    w.file_type().is_char_device(),
                    w.rdev()
                );
                println!("rename a lower dir: {}", io(std::fs::rename("/tmp/m/d", "/tmp/m/e")));
                println!("rename a file: {}", io(std::fs::rename("/tmp/m/d/x", "/tmp/m/d/x2")));
                println!("d: {} lower: {}", names("/tmp/m/d"), names("/tmp/l1/d"));
                println!("rmdir full: {}", name(if rmdir(c("/tmp/m/sub").as_ptr()) == 0 { 0 } else { errno() }));
                std::fs::remove_file("/tmp/m/sub/f").unwrap();
                println!("rmdir: {}", res(rmdir(c("/tmp/m/sub").as_ptr()) as i64));
                println!("made again: {} holds: [{}]", io(std::fs::create_dir("/tmp/m/sub")), names("/tmp/m/sub"));
                let mut buf = [0u8; 8];
                let n = getxattr(c("/tmp/u/sub").as_ptr(), c("trusted.overlay.opaque").as_ptr(), buf.as_mut_ptr(), 8);
                println!("opaque in upper: {}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
                let n = getxattr(c("/tmp/m/sub").as_ptr(), c("trusted.overlay.opaque").as_ptr(), buf.as_mut_ptr(), 8);
                println!("opaque through the overlay: {}", res(n as i64));
                // A file opened in a lower layer, then changed through it.
                let fd = open(c("/tmp/m/deep/e").as_ptr(), O_RDONLY);
                println!("fchmod: {}", res(fchmod(fd, 0o600) as i64));
                close(fd);
                let mode = |p: &str| std::fs::metadata(p).map(|m| format!("{:o}", m.permissions().mode() & 0o777)).unwrap_or_default();
                println!("e: {} lower: {} upper: {}", mode("/tmp/m/deep/e"), mode("/tmp/l2/deep/e"), mode("/tmp/u/deep/e"));
                let mut sf = [0u64; 15];
                statfs(c("/tmp/m").as_ptr(), sf.as_mut_ptr());
                println!("f_type: {:#x}", sf[0]);
                let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
                println!("mountinfo: {}", info.lines().any(|l| l.contains(" /tmp/m ") && l.contains(" - overlay ")));
                let fs = std::fs::read_to_string("/proc/filesystems").unwrap();
                println!("filesystems: {}", fs.lines().any(|l| l == "nodev\toverlay"));
                println!("root: {}", names("/tmp/m"));
                println!("upper: {}", names("/tmp/u"));
                println!("umount: {}", res(umount2(c("/tmp/m").as_ptr(), 0) as i64));
                // Lower layers only: read-only.
                let opts = b"lowerdir=/tmp/u:/tmp/l1\0";
                let r = mount(c("overlay").as_ptr(), c("/tmp/ro").as_ptr(), c("overlay").as_ptr(), 0, opts.as_ptr());
                println!("read-only mount: {} a: {}", res(r as i64), text("/tmp/ro/a"));
                println!("write: {}", io(std::fs::write("/tmp/ro/new", "x")));
                let bad = b"lowerdir=/tmp/l1,metacopy=on\0";
                let r = mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, bad.as_ptr());
                println!("metacopy: {}", res(r as i64));
            }
            // Processes sharing a SOCK_SEQPACKET socket take whole
            // messages, however they come in; and a child forked while a
            // thread waits in a receive on the socket receives from it too.
            Some("seqpacket-shared") => {
                const LEN: usize = 100_000;
                const COUNT: usize = 40;
                let mut sv = [0i32; 2];
                socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv.as_mut_ptr());
                let mut counts = [0i32; 2];
                pipe(counts.as_mut_ptr());
                for _ in 0..2 {
                    if fork() == 0 {
                        close(sv[0]);
                        let (mut whole, mut torn) = (0i32, 0i32);
                        let mut buf = vec![0u8; LEN + 16];
                        loop {
                            let n = read(sv[1], buf.as_mut_ptr(), buf.len());
                            if n <= 0 {
                                break;
                            }
                            let n = n as usize;
                            if n == LEN && buf[..n].iter().all(|&b| b == buf[0]) {
                                whole += 1;
                            } else {
                                torn += 1;
                            }
                        }
                        write(counts[1], [whole, torn].as_ptr().cast(), 8);
                        _exit(0);
                    }
                }
                close(sv[1]);
                close(counts[1]);
                for i in 0..COUNT {
                    let msg = vec![i as u8; LEN];
                    write(sv[0], msg.as_ptr(), LEN);
                }
                close(sv[0]);
                let (mut whole, mut torn) = (0, 0);
                for _ in 0..2 {
                    let mut c = [0i32; 2];
                    read(counts[0], c.as_mut_ptr().cast(), 8);
                    whole += c[0];
                    torn += c[1];
                    waitpid(-1, std::ptr::null_mut(), 0);
                }
                println!("whole: {whole} torn: {torn}");
                // A thread waits in a receive; a fork then.
                let mut sv = [0i32; 2];
                socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv.as_mut_ptr());
                let r = sv[1];
                let waiting = std::thread::spawn(move || {
                    let mut b = [0u8; 16];
                    read(r, b.as_mut_ptr(), 16)
                });
                std::thread::sleep(std::time::Duration::from_millis(200));
                let child = fork();
                if child == 0 {
                    alarm(10);
                    let mut b = [0u8; 16];
                    let n = read(r, b.as_mut_ptr(), 16);
                    _exit(if n == 5 { 0 } else { 1 });
                }
                write(sv[0], b"first".as_ptr(), 5);
                write(sv[0], b"other".as_ptr(), 5);
                let mut status = 0;
                waitpid(child, &mut status, 0);
                println!("thread got: {}", waiting.join().unwrap());
                println!("child got one: {}", status == 0);
            }
            // What an overlay must not do: write a layer through a layer's
            // own directory, a descriptor that outlived its mount, or a
            // name it does not show; lose track of a moved directory or a
            // listing's place; show what a whiteout hid.
            Some("overlay-edges") => {
                for d in ["l1/d", "l1/e", "l1/lst", "l1/h", "u", "w", "m", "ro/up", "ro/work", "rm"] {
                    std::fs::create_dir_all(format!("/tmp/{d}")).unwrap();
                }
                std::fs::write("/tmp/l1/a", "lower").unwrap();
                std::fs::write("/tmp/l1/h/secret", "s").unwrap();
                for i in 1..=6 {
                    std::fs::write(format!("/tmp/l1/lst/e{i}"), "").unwrap();
                }
                let opts = b"lowerdir=/tmp/l1,upperdir=/tmp/u,workdir=/tmp/w\0";
                let mnt = || mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, opts.as_ptr());
                println!("mount: {}", res(mnt() as i64));
                // A layer's directory, opened as itself.
                let fd = open(c("/tmp/l1/d").as_ptr(), O_RDONLY | O_DIRECTORY);
                close(openat(fd, c("own").as_ptr(), O_WRONLY | O_CREAT, 0o644));
                close(fd);
                println!("layer's own: {} not upper: {}", std::path::Path::new("/tmp/l1/d/own").exists(), !std::path::Path::new("/tmp/u/d/own").exists());
                // O_PATH makes nothing.
                let r = open(c("/tmp/m/zz").as_ptr(), O_PATH | O_CREAT, 0o644);
                println!("O_PATH|O_CREAT: {} then: {}", res(r as i64), res(open(c("/tmp/m/d/zz").as_ptr(), O_RDONLY) as i64));
                // A directory moved, then one made in its place.
                std::fs::create_dir("/tmp/m/n").unwrap();
                let fd = open(c("/tmp/m/n").as_ptr(), O_RDONLY | O_DIRECTORY);
                std::fs::rename("/tmp/m/n", "/tmp/m/n2").unwrap();
                std::fs::create_dir("/tmp/m/n").unwrap();
                close(openat(fd, c("f").as_ptr(), O_WRONLY | O_CREAT, 0o644));
                close(fd);
                println!("moved dir: {}", std::path::Path::new("/tmp/m/n2/f").exists() && !std::path::Path::new("/tmp/m/n/f").exists());
                // A lower file renamed over, then changed through its own
                // descriptor.
                let fd = open(c("/tmp/m/a").as_ptr(), O_RDONLY);
                std::fs::write("/tmp/m/b", "upper-b").unwrap();
                std::fs::rename("/tmp/m/b", "/tmp/m/a").unwrap();
                let r = fchmod(fd, 0o600);
                let mut buf = [0u8; 16];
                let n = pread(fd, buf.as_mut_ptr(), 16, 0);
                close(fd);
                println!("renamed over: {} still reads: {}", res(r as i64), String::from_utf8_lossy(&buf[..n.max(0) as usize]));
                // A listing read on across its directory's copy-up, then
                // sought.
                let fd = open(c("/tmp/m/lst").as_ptr(), O_RDONLY | O_DIRECTORY);
                let mut seen = dents(fd, 64, 3);
                fchmod(fd, 0o755);
                seen.extend(dents(fd, 4096, 100));
                let mut sorted = seen.clone();
                sorted.sort();
                sorted.dedup();
                println!("listing across copy-up: {} entries, {} distinct", seen.len(), sorted.len());
                lseek(fd, 0, 0);
                lseek(fd, 3, 0);
                let after = dents(fd, 4096, 1);
                println!("seek to 3: {}", after.first().is_some_and(|n| n != "." && n != ".."));
                close(fd);
                // RENAME_EXCHANGE of a directory onto a name a whiteout hid.
                std::fs::remove_file("/tmp/m/h/secret").unwrap();
                std::fs::remove_dir("/tmp/m/h").unwrap();
                std::fs::write("/tmp/m/h", "file").unwrap();
                std::fs::create_dir("/tmp/m/k").unwrap();
                let r = syscall(276, -100i64, c("/tmp/m/k").as_ptr(), -100i64, c("/tmp/m/h").as_ptr(), 2u32);
                println!("exchange: {} h holds: [{}]", res(r), names("/tmp/m/h"));
                // A whiteout of one's own.
                println!("mknod 0:0: {}", res(mknod(c("/tmp/m/wh").as_ptr(), 0o20000 | 0o644, 0) as i64));
                // A descriptor that outlives its mount.
                let fd = open(c("/tmp/m/e").as_ptr(), O_RDONLY | O_DIRECTORY);
                umount2(c("/tmp/m").as_ptr(), 2);
                close(openat(fd, c("late").as_ptr(), O_WRONLY | O_CREAT, 0o644));
                close(fd);
                println!("after unmount: upper {} lower {}", std::path::Path::new("/tmp/u/e/late").exists(), std::path::Path::new("/tmp/l1/e/late").exists());
                // An upper layer in a read-only mount.
                mount(c("/tmp/ro").as_ptr(), c("/tmp/rm").as_ptr(), std::ptr::null(), 4096, std::ptr::null());
                mount(std::ptr::null(), c("/tmp/rm").as_ptr(), std::ptr::null(), 4096 | 32 | 1, std::ptr::null());
                let opts = b"lowerdir=/tmp/l1,upperdir=/tmp/rm/up,workdir=/tmp/rm/work\0";
                let r = mount(c("overlay").as_ptr(), c("/tmp/m").as_ptr(), c("overlay").as_ptr(), 0, opts.as_ptr());
                println!("read-only upper: {}", res(r as i64));
            }
            other => panic!("unknown scenario {other:?}"),
        }
    }
}
