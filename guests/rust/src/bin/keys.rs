//! Keys and keyrings: a key added to the session keyring reads back and is
//! described; a fork child shares the session and what it adds there; a
//! key a helper never instantiated is negative; a revoked key says so;
//! `/proc/keys` lists the caller's keys; across `execve` the session keyring
//! stays and the process keyring goes. It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const SYS_ADD_KEY: i64 = 217;
const SYS_REQUEST_KEY: i64 = 218;
const SYS_KEYCTL: i64 = 219;

const KEY_SPEC_PROCESS_KEYRING: i64 = -2;
const KEY_SPEC_SESSION_KEYRING: i64 = -3;

const KEYCTL_GET_KEYRING_ID: i64 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: i64 = 1;
const KEYCTL_REVOKE: i64 = 3;
const KEYCTL_DESCRIBE: i64 = 6;
const KEYCTL_SEARCH: i64 = 10;
const KEYCTL_READ: i64 = 11;

const ENOKEY: i32 = 126;
const EKEYREVOKED: i32 = 128;

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn getuid() -> u32;
    fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// `add_key("user", desc, payload, len, ring)`.
fn add_user_key(desc: &str, payload: &[u8], ring: i64) -> i64 {
    let d = c(desc);
    // SAFETY: valid strings and a payload of its length.
    unsafe { syscall(SYS_ADD_KEY, c"user".as_ptr(), d.as_ptr(), payload.as_ptr(), payload.len(), ring) }
}

/// `KEYCTL_READ` of `key` into a fresh buffer.
fn read_key(key: i64) -> Result<Vec<u8>, i32> {
    let mut buf = [0u8; 256];
    // SAFETY: a buffer of its length.
    let n = unsafe { syscall(SYS_KEYCTL, KEYCTL_READ, key, buf.as_mut_ptr(), buf.len()) };
    if n < 0 { Err(errno()) } else { Ok(buf[..(n as usize).min(buf.len())].to_vec()) }
}

/// `KEYCTL_SEARCH` of the session keyring for user key `desc`.
fn search(desc: &str) -> i64 {
    let d = c(desc);
    // SAFETY: valid strings.
    unsafe { syscall(SYS_KEYCTL, KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, c"user".as_ptr(), d.as_ptr(), 0) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // SAFETY: plain calls into the C library and the kernel throughout.
    unsafe {
        if args.get(1).map(String::as_str) == Some("after-exec") {
            // The session keyring stayed, the process keyring went.
            let session_key = search("held") > 0;
            let process = syscall(SYS_KEYCTL, KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0);
            println!("after exec: session key {session_key}, process keyring gone {}", process == -1 && errno() == ENOKEY);
            return;
        }

        // A session of its own, and a key in it.
        let ses = syscall(SYS_KEYCTL, KEYCTL_JOIN_SESSION_KEYRING, 0);
        let key = add_user_key("held", b"secret", KEY_SPEC_SESSION_KEYRING);
        let read = read_key(key).map(|r| r == b"secret").unwrap_or(false);
        let mut buf = [0u8; 128];
        let n = syscall(SYS_KEYCTL, KEYCTL_DESCRIBE, key, buf.as_mut_ptr(), buf.len());
        let described = String::from_utf8_lossy(&buf[..(n.max(1) - 1) as usize]).into_owned();
        let expected = format!("user;{};", getuid());
        println!(
            "session {}, key read {read}, described {}",
            ses > 0,
            described.starts_with(&expected) && described.ends_with(";held")
        );

        // A fork child finds it, and adds one the parent then finds.
        let pid = fork();
        if pid == 0 {
            let found = search("held") == key;
            let added = add_user_key("from-child", b"c", KEY_SPEC_SESSION_KEYRING) > 0;
            _exit(if found && added { 0 } else { 1 });
        }
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        println!("child shares the session {}, its key here {}", status == 0, search("from-child") > 0);

        // A key no helper instantiates: negative.
        let r = syscall(SYS_REQUEST_KEY, c"user".as_ptr(), c"wanted".as_ptr(), c"info".as_ptr(), KEY_SPEC_PROCESS_KEYRING);
        let refused = r == -1 && errno() == ENOKEY;
        let mut id = [0i32; 1];
        syscall(SYS_KEYCTL, KEYCTL_READ, KEY_SPEC_PROCESS_KEYRING, id.as_mut_ptr(), 4usize);
        let negative = read_key(id[0] as i64) == Err(ENOKEY);
        println!("request refused {refused}, negative key {negative}");

        // Revoked.
        let doomed = add_user_key("doomed", b"d", KEY_SPEC_SESSION_KEYRING);
        syscall(SYS_KEYCTL, KEYCTL_REVOKE, doomed);
        println!("revoked {}", read_key(doomed) == Err(EKEYREVOKED));

        // /proc/keys lists the session's key.
        let listed = std::fs::read_to_string("/proc/keys")
            .map(|t| t.lines().any(|l| l.starts_with(&format!("{key:08x} ")) && l.contains(" user ") && l.ends_with("held: 6")))
            .unwrap_or(false);
        println!("listed {listed}");

        // Across execve.
        let exe = c(&std::env::current_exe().unwrap().to_string_lossy());
        let arg = c("after-exec");
        let argv = [exe.as_ptr(), arg.as_ptr(), std::ptr::null()];
        execv(exe.as_ptr(), argv.as_ptr());
        println!("exec failed: {}", errno());
    }
}
