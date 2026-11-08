//! Namespace descriptors: `/proc/self/ns/uts` opened (it stats as nsfs
//! shows a namespace, and reads fail), the `NS_GET_*` requests, and
//! `setns` back into the namespace a descriptor names after `unshare` left
//! it. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const CLONE_NEWUTS: i32 = 0x0400_0000;
const NS_GET_NSTYPE: u64 = 0xb703;
const NS_GET_PARENT: u64 = 0xb702;
const EINVAL: i32 = 22;

unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn unshare(flags: i32) -> i32;
    fn setns(fd: i32, nstype: i32) -> i32;
    fn sethostname(name: *const u8, len: usize) -> i32;
    fn gethostname(name: *mut u8, len: usize) -> i32;
    fn fstat(fd: i32, st: *mut u64) -> i32;
    fn __errno_location() -> *mut i32;
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
    }
}
