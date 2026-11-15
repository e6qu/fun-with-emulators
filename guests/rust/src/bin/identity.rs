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
const SIGRT1: i32 = 35;
const O_RDONLY: i32 = 0;

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn kill(pid: i32, sig: i32) -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn __errno_location() -> *mut i32;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    match arg(1) {
        "host-process" => host_process(arg(2).parse().unwrap()),
        other => {
            eprintln!("unknown check {other:?}");
            std::process::exit(2);
        }
    }
}
