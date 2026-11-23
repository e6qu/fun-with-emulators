//! Namespace descriptors: `/proc/self/ns/uts` opened (it stats as nsfs
//! shows a namespace, reads and seeks fail, `poll` finds it ready and
//! `epoll` refuses it, as nsfs has no wait), the `NS_GET_*` requests, and
//! `setns` back into the namespace a descriptor names after `unshare` left
//! it. Then `setns` into its own user namespace (refused, its
//! capabilities kept), and into pid namespaces: its own active one (even
//! with a new one for its children), and from a child in a new one, the
//! namespace above (refused) and its own. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const CLONE_NEWUTS: i32 = 0x0400_0000;
const NS_GET_NSTYPE: u64 = 0xb703;
const NS_GET_PARENT: u64 = 0xb702;
const CLONE_NEWPID: i32 = 0x2000_0000;
const CLONE_NEWUSER: i32 = 0x1000_0000;
const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const ESPIPE: i32 = 29;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const EPOLL_CTL_ADD: i32 = 1;
/// `SYS_capget`, `SYS_capset` on arm64, and `_LINUX_CAPABILITY_VERSION_3`.
const SYS_CAPGET: i64 = 90;
const SYS_CAPSET: i64 = 91;
const CAP_V3: u32 = 0x2008_0522;
const CAP_SYS_ADMIN: u32 = 21;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut u64) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn unshare(flags: i32) -> i32;
    fn setns(fd: i32, nstype: i32) -> i32;
    fn sethostname(name: *const u8, len: usize) -> i32;
    fn gethostname(name: *mut u8, len: usize) -> i32;
    fn fstat(fd: i32, st: *mut u64) -> i32;
    fn __errno_location() -> *mut i32;
    fn syscall(nr: i64, ...) -> i64;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn getpid() -> i32;
    fn _exit(code: i32) -> !;
}

/// The caller's capabilities: effective, permitted, inheritable (low
/// words).
fn caps() -> [u32; 6] {
    let hdr = [CAP_V3, 0];
    let mut data = [0u32; 6];
    // SAFETY: a header and two `__user_cap_data_struct`s, live locals.
    unsafe { syscall(SYS_CAPGET, hdr.as_ptr(), data.as_mut_ptr()) };
    data
}

fn set_caps(data: &[u32; 6]) -> i64 {
    let hdr = [CAP_V3, 0];
    // SAFETY: as in `caps`.
    unsafe { syscall(SYS_CAPSET, hdr.as_ptr(), data.as_ptr()) }
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn hostname() -> String {
    let mut b = [0u8; 65];
    // SAFETY: a buffer of its length.
    unsafe { gethostname(b.as_mut_ptr(), b.len()) };
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(0)]).into_owned()
}

fn main() {
    // SAFETY: plain calls into the C library throughout; every buffer is a
    // live local of the length passed.
    unsafe {
        let path = CString::new("/proc/self/ns/uts").unwrap();
        let fd = open(path.as_ptr(), 0);
        let link = std::fs::read_link("/proc/self/ns/uts").unwrap();
        let link = link.to_string_lossy();
        // `struct stat`: the inode at 8.
        let mut st = [0u64; 16];
        fstat(fd, st.as_mut_ptr());
        let ino_matches = link == format!("uts:[{}]", st[1]);
        let mut b = [0u8; 8];
        let r = read(fd, b.as_mut_ptr(), b.len());
        println!("open: {}, inode is the link's {ino_matches}, read refused {}", fd >= 0, r == -1 && errno() == EINVAL);
        let seek = lseek(fd, 0, 0) == -1 && errno() == ESPIPE;
        let mut p = PollFd { fd, events: POLLIN | POLLOUT, revents: 0 };
        let polled = poll(&mut p, 1, -1);
        let ep = epoll_create1(0);
        let mut ev = [POLLIN as u64, 0];
        let watched = epoll_ctl(ep, EPOLL_CTL_ADD, fd, ev.as_mut_ptr());
        println!(
            "seek refused {seek}, poll {polled} revents {:#x}, epoll refused {}",
            p.revents,
            watched == -1 && errno() == EPERM
        );
        close(ep);
        let ty = ioctl(fd, NS_GET_NSTYPE);
        let parent = ioctl(fd, NS_GET_PARENT);
        println!("nstype {:#x}, parent of a UTS namespace refused {}", ty, parent == -1 && errno() == EINVAL);

        let before = hostname();
        unshare(CLONE_NEWUTS);
        sethostname(b"fwe-nsfd".as_ptr(), 8);
        let inside = hostname();
        let r = setns(fd, CLONE_NEWUTS);
        println!("setns: {r}, own name {}, back {}", inside == "fwe-nsfd", hostname() == before);
        let wrong = setns(fd, 0x0800_0000);
        println!("wrong type refused {}", wrong == -1 && errno() == EINVAL);
        close(fd);

        // Its own user namespace: refused before the capability is asked
        // for, and the capabilities stay as they were.
        let user = CString::new("/proc/self/ns/user").unwrap();
        let ufd = open(user.as_ptr(), 0);
        let r = setns(ufd, CLONE_NEWUSER);
        let e = errno();
        println!("own user namespace: {r} errno {e}");
        let full = caps();
        let mut less = full;
        less[0] &= !(1 << CAP_SYS_ADMIN);
        set_caps(&less);
        let r = setns(ufd, CLONE_NEWUSER);
        let e = errno();
        let kept = caps()[0] & (1 << CAP_SYS_ADMIN) == 0;
        println!("without CAP_SYS_ADMIN: {r} errno {e}, capabilities kept {kept}");
        set_caps(&full);
        close(ufd);

        // Pid namespaces: the caller's own active one, after a new one is
        // made for its children; from a child in that one, the one above
        // is refused and its own taken.
        let pid = CString::new("/proc/self/ns/pid").unwrap();
        let above = open(pid.as_ptr(), 0);
        let r = unshare(CLONE_NEWPID);
        let own = setns(above, CLONE_NEWPID);
        println!("unshare pid {r}, setns into its own active one {own}");
        unshare(CLONE_NEWPID);
        let child = fork();
        if child == 0 {
            let r = setns(above, CLONE_NEWPID);
            let refused = r == -1 && errno() == EINVAL;
            let mine = open(pid.as_ptr(), 0);
            let r = setns(mine, CLONE_NEWPID);
            _exit(if getpid() == 1 && refused && r == 0 { 0 } else { 1 });
        }
        let mut status = 0;
        waitpid(child, &mut status, 0);
        println!("child: the namespace above refused, its own joined {}", status == 0);
    }
}
