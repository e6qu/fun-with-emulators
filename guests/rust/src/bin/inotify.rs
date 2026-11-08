//! inotify: a watched directory hears of what another process does in it
//! (a file made, written, closed, renamed with one cookie for both ends,
//! and removed), `poll` sees the events waiting, the descriptor's fdinfo
//! lists the watch, and a removed watch says so. It prints what it
//! observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const IN_NONBLOCK: i32 = 0o4000;
const IN_ALL_EVENTS: u32 = 0xfff;
const EAGAIN: i32 = 11;
const POLLIN: i16 = 1;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, path: *const c_char, mask: u32) -> i32;
    fn inotify_rm_watch(fd: i32, wd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn getpid() -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn syscall(n: i64, ...) -> i64;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

/// The events as `kind name` words.
fn described(got: &[(u32, u32, String)]) -> String {
    got.iter()
        .map(|(m, _, n)| {
            let kind = match m & 0xfff {
                0x100 => "create",
                0x20 => "open",
                0x2 => "modify",
                0x8 => "close_write",
                0x40 => "moved_from",
                0x80 => "moved_to",
                0x200 => "delete",
                _ => "other",
            };
            format!("{kind} {n}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The events waiting on `fd`: (mask, cookie, name).
fn events(fd: i32) -> Vec<(u32, u32, String)> {
    let mut buf = [0u8; 4096];
    // SAFETY: a buffer of its length.
    let n = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 16 <= n.max(0) as usize {
        let word = |o: usize| u32::from_ne_bytes(buf[at + o..at + o + 4].try_into().unwrap());
        let (mask, cookie, len) = (word(4), word(8), word(12) as usize);
        let name = &buf[at + 16..at + 16 + len];
        let name = String::from_utf8_lossy(&name[..name.iter().position(|&b| b == 0).unwrap_or(len)]);
        out.push((mask, cookie, name.into_owned()));
        at += 16 + len;
    }
    out
}

fn main() {
    // SAFETY: plain calls into the C library throughout.
    unsafe {
        let dir = format!("/tmp/fwe-inotify-{}", getpid());
        std::fs::create_dir(&dir).unwrap();
        let fd = inotify_init1(IN_NONBLOCK);
        let wd = inotify_add_watch(fd, CString::new(dir.clone()).unwrap().as_ptr(), IN_ALL_EVENTS);
        let empty = read(fd, [0u8; 64].as_mut_ptr(), 64) == -1 && errno() == EAGAIN;
        println!("watch: {}, nothing yet {empty}", wd > 0);

        // Another process acts in the directory.
        let pid = fork();
        if pid == 0 {
            std::fs::write(format!("{dir}/a"), b"x").unwrap();
            std::fs::rename(format!("{dir}/a"), format!("{dir}/b")).unwrap();
            std::fs::remove_file(format!("{dir}/b")).unwrap();
            _exit(0);
        }
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        let mut p = PollFd { fd, events: POLLIN, revents: 0 };
        let ready = poll(&mut p, 1, 1000) == 1 && p.revents & POLLIN != 0;
        let got = events(fd);
        let cookies: Vec<u32> = got.iter().filter(|(m, _, _)| m & 0xc0 != 0).map(|(_, c, _)| *c).collect();
        let paired = cookies.len() == 2 && cookies[0] == cookies[1] && cookies[0] != 0;
        println!("ready {ready}: {}", described(&got));
        println!("move cookies paired {paired}");

        // A writer that ends without closing: its close comes as it ends.
        let pid = fork();
        if pid == 0 {
            let f = CString::new(format!("{dir}/c")).unwrap();
            let fd = open(f.as_ptr(), 0o101, 0o644);
            write(fd, b"x".as_ptr(), 1);
            _exit(0);
        }
        waitpid(pid, &mut status, 0);
        println!("exit closes: {}", described(&events(fd)));

        // An exchange: each moves where the other was, and nothing goes.
        std::fs::write(format!("{dir}/d"), b"y").unwrap();
        events(fd);
        let (c, d) = (CString::new(format!("{dir}/c")).unwrap(), CString::new(format!("{dir}/d")).unwrap());
        const RENAME_EXCHANGE: u32 = 2;
        syscall(276, -100i64, c.as_ptr(), -100i64, d.as_ptr(), RENAME_EXCHANGE);
        println!("exchange: {}", described(&events(fd)));
        std::fs::remove_file(format!("{dir}/c")).unwrap();
        std::fs::remove_file(format!("{dir}/d")).unwrap();
        events(fd);

        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap_or_default();
        println!("fdinfo lists the watch {}", info.contains(&format!("inotify wd:{wd} ")) && info.contains("mask:fff"));
        let r = inotify_rm_watch(fd, wd);
        let after = events(fd);
        println!("removed {r}: ignored {}", after.len() == 1 && after[0].0 == 0x8000);
        std::fs::remove_dir(&dir).unwrap();
    }
}
