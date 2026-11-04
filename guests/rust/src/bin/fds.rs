//! The guest's descriptor table: fwe's own descriptors stay out of reach of
//! a guest that closes everything, and `/proc/self/fd` lists what is open.
use std::os::fd::AsRawFd;

const SIGUSR1: i32 = 10;
const SIG_BLOCK: i32 = 0;
const RLIMIT_NOFILE: i32 = 7;
const EBADF: i32 = 9;
const EPERM: i32 = 1;
const SYS_CLOSE_RANGE: i64 = 436;

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

unsafe extern "C" {
    fn eventfd(initval: u32, flags: i32) -> i32;
    fn signalfd(fd: i32, mask: *const [u64; 16], flags: i32) -> i32;
    fn sigprocmask(how: i32, set: *const [u64; 16], old: *mut [u64; 16]) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
    fn getrlimit(res: i32, lim: *mut Rlimit) -> i32;
    fn setrlimit(res: i32, lim: *const Rlimit) -> i32;
    fn close(fd: i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn syscall(n: i64, ...) -> i64;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's errno location for this thread.
    unsafe { *__errno_location() }
}

fn nofile() -> Rlimit {
    let mut lim = Rlimit { cur: 0, max: 0 };
    // SAFETY: a valid out-parameter.
    unsafe { getrlimit(RLIMIT_NOFILE, &mut lim) };
    lim
}

fn main() {
    let exe = std::env::current_exe().unwrap();
    match std::env::args().nth(1).as_deref() {
        // Close every descriptor from 3 to the limit, as daemons and spawn
        // helpers do, keeping only an eventfd and a signalfd: paths still
        // resolve, and both descriptors still work.
        Some("close-all") => {
            let mut mask = [0u64; 16];
            mask[0] = 1 << (SIGUSR1 - 1);
            // SAFETY: valid sets; plain calls.
            let (efd, sfd) = unsafe {
                sigprocmask(SIG_BLOCK, &mask, std::ptr::null_mut());
                (eventfd(0, 0), signalfd(-1, &mask, 0))
            };
            let lim = nofile();
            println!("soft limit {}", lim.cur);
            for fd in 3..lim.cur as i32 {
                if fd != efd && fd != sfd {
                    // SAFETY: closing descriptors this process may hold.
                    unsafe { close(fd) };
                }
            }
            println!("read own binary: {}", std::fs::read(&exe).is_ok());
            let mut v = 3u64.to_ne_bytes();
            // SAFETY: 8-byte buffers.
            let n = unsafe {
                write(efd, v.as_ptr(), 8);
                read(efd, v.as_mut_ptr(), 8)
            };
            println!("eventfd: {n} bytes, value {}", u64::from_ne_bytes(v));
            let mut info = [0u8; 128];
            // SAFETY: plain calls; a 128-byte buffer.
            let n = unsafe {
                kill(getpid(), SIGUSR1);
                read(sfd, info.as_mut_ptr(), 128)
            };
            println!("signalfd: {n} bytes, signal {}", info[0]);
        }
        // close_range over everything from 3 up.
        Some("close-range") => {
            let file = std::fs::File::open(&exe).unwrap();
            let fd = file.as_raw_fd();
            // SAFETY: plain system call.
            let r = unsafe { syscall(SYS_CLOSE_RANGE, 3i64, u32::MAX as i64, 0i64) };
            // SAFETY: F_GETFD only queries the descriptor.
            let gone = unsafe { fcntl(fd, 1) } < 0 && errno() == EBADF;
            std::mem::forget(file);
            println!("close_range {r}, file closed: {gone}");
            println!("read own binary: {}", std::fs::read(&exe).is_ok());
        }
        // /proc/self/fd lists the open descriptors and links each to what
        // it refers to.
        Some("proc-fd") => {
            let file = std::fs::File::open(&exe).unwrap();
            let mut p = [0; 2];
            // SAFETY: a 2-element array.
            unsafe { pipe(p.as_mut_ptr()) };
            let mut listed: Vec<i32> = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
                .collect();
            listed.sort();
            let fd = file.as_raw_fd();
            let expect = [0, 1, 2, fd, p[0], p[1]];
            println!("lists the open ones: {}", expect.iter().all(|f| listed.contains(f)));
            // Exactly what fcntl says is open (inherited descriptors
            // included), plus the listing's own directory descriptor, which
            // is closed again by now.
            let open: Vec<i32> = (0..nofile().max as i32)
                // SAFETY: F_GETFD only queries the descriptor.
                .filter(|&f| unsafe { fcntl(f, 1) } >= 0)
                .collect();
            let extra: Vec<&i32> = listed.iter().filter(|f| !open.contains(f)).collect();
            println!(
                "and nothing else: {}",
                open.iter().all(|f| listed.contains(f)) && extra.len() == 1
            );
            let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
            println!("file link is its path: {}", link == exe);
            let link = std::fs::read_link(format!("/proc/self/fd/{}", p[0])).unwrap();
            println!("pipe link: {}", link.to_str().unwrap().starts_with("pipe:["));
            // Opening the entry gives a working descriptor for the same pipe.
            let reopened = std::fs::File::open(format!("/proc/self/fd/{}", p[0])).unwrap();
            // SAFETY: a 1-byte buffer.
            unsafe { write(p[1], b"z".as_ptr(), 1) };
            let mut b = 0u8;
            // SAFETY: a 1-byte buffer.
            let n = unsafe { read(reopened.as_raw_fd(), &mut b, 1) };
            println!("reopened pipe reads: {n} {}", b as char);
        }
        // The limit is virtual and bounds what the guest can name.
        Some("limits") => {
            let lim = nofile();
            println!("hard limit above soft: {}", lim.max >= lim.cur);
            // SAFETY: plain calls.
            let (r, e) = unsafe { (dup2(1, lim.max as i32), errno()) };
            println!("dup2 at the hard limit: {r} {}", if e == EBADF { "EBADF" } else { "?" });
            // SAFETY: plain call.
            let r = unsafe { dup2(1, lim.max as i32 - 1) };
            println!("dup2 just below it: {}", r == lim.max as i32 - 1);
            let above = Rlimit { cur: lim.max + 1, max: lim.max + 1 };
            // SAFETY: a valid in-parameter.
            let (r, e) = unsafe { (setrlimit(RLIMIT_NOFILE, &above), errno()) };
            println!("raising past it: {r} {}", if e == EPERM { "EPERM" } else { "?" });
            let lower = Rlimit { cur: 256, max: lim.max };
            // SAFETY: a valid in-parameter.
            unsafe { setrlimit(RLIMIT_NOFILE, &lower) };
            println!("soft limit now {}", nofile().cur);
        }
        other => {
            eprintln!("unknown scenario {other:?}");
            std::process::exit(2);
        }
    }
}
