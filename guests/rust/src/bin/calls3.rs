//! More calls: native AIO (a write and a read of a file, a poll of a pipe
//! that waits, a completion signalled on an eventfd); process accounting
//! (a child's record); dnotify (two watches signalling one real-time
//! signal, each carrying its descriptor); real-time signals queued, each
//! with its value; `file_setattr` and `file_getattr`; the security modules
//! listed; `sync` and `syncfs`; a trailing slash on a file; and a message
//! queue's id chosen by `kernel.msg_next_id`; and a child's memory read
//! and written by its parent (`process_vm_readv`, `process_vm_writev`);
//! and a Landlock domain that lets a child read under one directory only.
//! It prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char, c_void};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

const SYS_IO_SETUP: i64 = 0;
const SYS_IO_DESTROY: i64 = 1;
const SYS_IO_SUBMIT: i64 = 2;
const SYS_IO_GETEVENTS: i64 = 4;
const SYS_SYNC: i64 = 81;
const SYS_ACCT: i64 = 89;
const SYS_UNSHARE: i64 = 97;
const CLONE_NEWPID: i64 = 0x2000_0000;
const SYS_SYNCFS: i64 = 267;
const SYS_LSM_LIST_MODULES: i64 = 461;
const SYS_FILE_GETATTR: i64 = 468;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_RT_SIGQUEUEINFO: i64 = 138;
const SYS_EVENTFD2: i64 = 19;
const SYS_PROCESS_VM_READV: i64 = 270;
const SYS_PROCESS_VM_WRITEV: i64 = 271;
const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
const SYS_LANDLOCK_ADD_RULE: i64 = 445;
const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
const SYS_PRCTL: i64 = 167;
const O_PATH: i32 = 0o10000000;

const O_RDONLY: i32 = 0;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const F_SETSIG: i32 = 10;
const F_NOTIFY: i32 = 1026;
const DN_ATTRIB: u64 = 0x20;
const DN_MULTISHOT: u64 = 0x8000_0000;
const SA_SIGINFO: i32 = 4;
const SIG_BLOCK: i32 = 0;
const POLLIN: u64 = 1;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const FS_XFLAG_NODUMP: u64 = 0x80;
const AT_FDCWD: i64 = -100;
const ENOTDIR: i32 = 20;

#[repr(C)]
#[derive(Default)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: u32,
    opcode: u16,
    reqprio: i16,
    fd: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct IoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

/// musl's `struct sigaction`.
#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

#[repr(C)]
struct SigInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    words: [u64; 14],
}

unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn pipe(fds: *mut i32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn getpid() -> i32;
    fn chmod(path: *const c_char, mode: u32) -> i32;
    fn mkdir(path: *const c_char, mode: u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn sigprocmask(how: i32, set: *const u64, old: *mut u64) -> i32;
    fn sigtimedwait(set: *const u64, info: *mut SigInfo, ts: *const Timespec) -> i32;
    fn msgget(key: i32, flags: i32) -> i32;
    fn msgctl(id: i32, cmd: i32, buf: *mut c_void) -> i32;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// A word a child sets, which its parent reads and writes.
static WORD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The descriptors dnotify's signal was taken with, in order.
static SEEN: [AtomicI32; 4] = [const { AtomicI32::new(-1) }; 4];
static SEEN_N: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_dnotify(_: i32, info: *mut SigInfo, _: *mut c_void) {
    // SAFETY: the kernel's siginfo; `si_fd` follows `si_band`.
    let fd = unsafe { (*info).words[1] as i32 };
    let i = SEEN_N.fetch_add(1, Ordering::SeqCst);
    if i < SEEN.len() {
        SEEN[i].store(fd, Ordering::SeqCst);
    }
}

fn main() {
    let dir = format!("/tmp/fwe-calls3-{}", unsafe { getpid() });
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: plain calls into the C library and the kernel throughout,
    // with buffers that outlive them.
    unsafe {
        // AIO: a write then a read of a file, a poll of a pipe completed
        // once written, its completion counted on an eventfd.
        let mut ctx = 0u64;
        let setup = syscall(SYS_IO_SETUP, 8i64, &mut ctx as *mut u64);
        let f = open(c(&format!("{dir}/aio")).as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
        let data = *b"asynchronous";
        let mut back = [0u8; 12];
        let mut w = Iocb { data: 1, opcode: 1, fd: f as u32, ..Default::default() };
        (w.buf, w.nbytes) = (data.as_ptr() as u64, data.len() as u64);
        let mut r = Iocb { data: 2, opcode: 0, fd: f as u32, ..Default::default() };
        (r.buf, r.nbytes) = (back.as_mut_ptr() as u64, back.len() as u64);
        let first = [&mut w as *mut Iocb];
        let submitted_w = syscall(SYS_IO_SUBMIT, ctx, 1i64, first.as_ptr());
        let second = [&mut r as *mut Iocb];
        let submitted_r = syscall(SYS_IO_SUBMIT, ctx, 1i64, second.as_ptr());
        let mut ev = [IoEvent::default(); 4];
        let got = syscall(SYS_IO_GETEVENTS, ctx, 2i64, 4i64, ev.as_mut_ptr(), 0i64);
        println!(
            "aio: setup {setup}, submitted {submitted_w} {submitted_r}, events {got}, wrote {} read {}, same {}",
            ev[0].res,
            ev[1].res,
            back == data
        );
        let mut p = [0i32; 2];
        pipe(p.as_mut_ptr());
        let efd = syscall(SYS_EVENTFD2, 0i64, 0i64) as i32;
        let mut poll = Iocb { data: 3, opcode: 5, fd: p[0] as u32, buf: POLLIN, ..Default::default() };
        (poll.flags, poll.resfd) = (1, efd as u32);
        let list = [&mut poll as *mut Iocb];
        syscall(SYS_IO_SUBMIT, ctx, 1i64, list.as_ptr());
        let zero = Timespec { sec: 0, nsec: 0 };
        let before = syscall(SYS_IO_GETEVENTS, ctx, 1i64, 1i64, ev.as_mut_ptr(), &zero as *const Timespec);
        write(p[1], b"x".as_ptr(), 1);
        let after = syscall(SYS_IO_GETEVENTS, ctx, 1i64, 1i64, ev.as_mut_ptr(), 0i64);
        let mut count = 0u64;
        read(efd, (&mut count as *mut u64).cast(), 8);
        println!(
            "aio poll: before {before}, after {after} with data {} res {}, eventfd {count}",
            ev[0].data,
            ev[0].res & 1
        );
        let destroyed = syscall(SYS_IO_DESTROY, ctx);
        let again = syscall(SYS_IO_DESTROY, ctx) == -1;
        println!("aio destroy: {destroyed}, again refused {again}");
        for fd in [f, p[0], p[1], efd] {
            close(fd);
        }

        // Process accounting: a child's record, its name and exit code, in
        // a pid namespace of its own (accounting is a namespace's).
        let helper = fork();
        if helper == 0 {
            syscall(SYS_UNSHARE, CLONE_NEWPID);
            let init = fork();
            if init == 0 {
                let file = format!("{dir}/acct");
                close(open(c(&file).as_ptr(), O_RDWR | O_CREAT, 0o600));
                let on = syscall(SYS_ACCT, c(&file).as_ptr());
                let child = fork();
                if child == 0 {
                    _exit(3);
                }
                waitpid(child, &mut 0, 0);
                let off = syscall(SYS_ACCT, 0i64);
                let rec = std::fs::read(&file).unwrap_or_default();
                let found = rec.chunks_exact(64).find(|r| {
                    u32::from_le_bytes(r[16..20].try_into().unwrap()) == child as u32
                });
                let (version, exit, forked) = found.map_or((0, 0, false), |r| {
                    (r[1], u32::from_le_bytes(r[4..8].try_into().unwrap()), r[0] & 1 != 0)
                });
                println!(
                    "acct: on {on}, off {off}, record {}, version {version}, exit status {exit:#x}, forked {forked}",
                    found.is_some()
                );
                _exit(0);
            }
            waitpid(init, &mut 0, 0);
            _exit(0);
        }
        waitpid(helper, &mut 0, 0);

        // dnotify: a directory and one in it both watched, one signal.
        let sig = 35;
        let act = SigAction {
            handler: on_dnotify as *const () as usize,
            mask: [0; 16],
            flags: SA_SIGINFO,
            restorer: 0,
        };
        sigaction(sig, &act, std::ptr::null_mut());
        let sub = format!("{dir}/sub");
        mkdir(c(&sub).as_ptr(), 0o700);
        let parent = open(c(&dir).as_ptr(), O_RDONLY);
        let inner = open(c(&sub).as_ptr(), O_RDONLY);
        for fd in [parent, inner] {
            fcntl(fd, F_SETSIG, sig);
            fcntl(fd, F_NOTIFY, DN_ATTRIB | DN_MULTISHOT);
        }
        chmod(c(&sub).as_ptr(), 0o755);
        let n = SEEN_N.load(Ordering::SeqCst);
        let seen: Vec<i32> = SEEN[..n.min(4)].iter().map(|s| s.load(Ordering::SeqCst)).collect();
        println!(
            "dnotify: {n} signals, parent's {}, inner's {}",
            seen.contains(&parent),
            seen.contains(&inner)
        );
        close(parent);
        close(inner);

        // Real-time signals queued, each with its own value.
        let rt = 40;
        let set = 1u64 << (rt - 1);
        sigprocmask(SIG_BLOCK, &set, std::ptr::null_mut());
        for v in 1..=3u64 {
            let mut info = SigInfo { signo: rt, errno: 0, code: -1, _pad: 0, words: [0; 14] };
            info.words[0] = u64::from(getpid() as u32);
            info.words[1] = v;
            syscall(SYS_RT_SIGQUEUEINFO, i64::from(getpid()), i64::from(rt), &info as *const SigInfo);
        }
        let mut values = Vec::new();
        let mut info = SigInfo { signo: 0, errno: 0, code: 0, _pad: 0, words: [0; 14] };
        while sigtimedwait(&set, &mut info, &zero) == rt {
            values.push(info.words[1]);
        }
        println!("real-time queue: {values:?}");

        // File attributes: no-dump set, then read back.
        let path = format!("{dir}/attr");
        close(open(c(&path).as_ptr(), O_RDWR | O_CREAT, 0o600));
        let mut attr = [0u64; 3];
        attr[0] = FS_XFLAG_NODUMP;
        let p = c(&path);
        let set_r = syscall(SYS_FILE_SETATTR, AT_FDCWD, p.as_ptr(), attr.as_ptr(), 24i64, 0i64);
        let mut back = [0u64; 3];
        let get_r = syscall(SYS_FILE_GETATTR, AT_FDCWD, p.as_ptr(), back.as_mut_ptr(), 24i64, 0i64);
        println!("file attributes: set {set_r}, get {get_r}, no-dump {}", back[0] & FS_XFLAG_NODUMP != 0);

        // The security modules: capabilities alone.
        let mut ids = [0u64; 4];
        let mut size = 32u32;
        let n = syscall(SYS_LSM_LIST_MODULES, ids.as_mut_ptr(), &mut size as *mut u32, 0i64);
        println!("lsm: {n} modules, ids {} {}, size {size}", ids[0], ids[1]);

        // sync and syncfs; a file named with a trailing slash.
        let d = open(c(&dir).as_ptr(), O_RDONLY);
        println!(
            "sync: {}, syncfs {}, file/ {}",
            syscall(SYS_SYNC),
            syscall(SYS_SYNCFS, i64::from(d)),
            if open(c(&format!("{path}/")).as_ptr(), O_RDONLY) < 0 && errno() == ENOTDIR {
                "ENOTDIR"
            } else {
                "opened"
            }
        );
        close(d);

        // A message queue's id, as kernel.msg_next_id asks.
        std::fs::write("/proc/sys/kernel/msg_next_id", "4242").ok();
        let q = msgget(0x5eed, IPC_CREAT | 0o600);
        let next = std::fs::read_to_string("/proc/sys/kernel/msg_next_id").unwrap_or_default();
        println!("msg_next_id: id {}, then {}", q == 4242, next.trim());
        msgctl(q, IPC_RMID, std::ptr::null_mut());

        // A child's memory, read and written by its parent.
        let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
        pipe(up.as_mut_ptr());
        pipe(down.as_mut_ptr());
        let child = fork();
        if child == 0 {
            WORD.store(0x1234, Ordering::SeqCst);
            write(up[1], b"x".as_ptr(), 1);
            let mut b = 0u8;
            read(down[0], &mut b, 1);
            _exit((WORD.load(Ordering::SeqCst) & 0xff) as i32);
        }
        let mut b = 0u8;
        read(up[0], &mut b, 1);
        let at = WORD.as_ptr() as u64;
        let mut got = 0u64;
        let local = [(&mut got as *mut u64 as u64), 8u64];
        let remote = [at, 8u64];
        let read_n = syscall(SYS_PROCESS_VM_READV, i64::from(child), local.as_ptr(), 1i64, remote.as_ptr(), 1i64, 0i64);
        let new = 0x99u64;
        let local = [(&new as *const u64 as u64), 8u64];
        let wrote_n = syscall(SYS_PROCESS_VM_WRITEV, i64::from(child), local.as_ptr(), 1i64, remote.as_ptr(), 1i64, 0i64);
        write(down[1], b"x".as_ptr(), 1);
        let mut st = 0;
        waitpid(child, &mut st, 0);
        println!(
            "process_vm: read {read_n} bytes {got:#x}, wrote {wrote_n}, child saw {:#x}",
            (st >> 8) & 0xff
        );

        // Landlock: reading allowed under one directory only, in a child.
        let inside = format!("{dir}/inside");
        mkdir(c(&inside).as_ptr(), 0o700);
        std::fs::write(format!("{inside}/file"), b"in").unwrap();
        std::fs::write(format!("{dir}/outside"), b"out").unwrap();
        let abi = syscall(SYS_LANDLOCK_CREATE_RULESET, 0i64, 0i64, 1i64);
        let child = fork();
        if child == 0 {
            const READ_FILE: u64 = 1 << 2;
            let attr = [READ_FILE];
            let rs = syscall(SYS_LANDLOCK_CREATE_RULESET, attr.as_ptr(), 8i64, 0i64);
            let parent = open(c(&inside).as_ptr(), O_PATH);
            let rule: [u8; 12] = {
                let mut r = [0u8; 12];
                r[..8].copy_from_slice(&READ_FILE.to_ne_bytes());
                r[8..].copy_from_slice(&parent.to_ne_bytes());
                r
            };
            syscall(SYS_LANDLOCK_ADD_RULE, rs, 1i64, rule.as_ptr(), 0i64);
            syscall(SYS_PRCTL, 38i64, 1i64, 0i64, 0i64, 0i64);
            let restricted = syscall(SYS_LANDLOCK_RESTRICT_SELF, rs, 0i64) == 0;
            let ok = open(c(&format!("{inside}/file")).as_ptr(), O_RDONLY) >= 0;
            let denied = open(c(&format!("{dir}/outside")).as_ptr(), O_RDONLY) < 0 && errno() == 13;
            _exit(i32::from(restricted) | i32::from(ok) << 1 | i32::from(denied) << 2);
        }
        let mut st = 0;
        waitpid(child, &mut st, 0);
        let bits = (st >> 8) & 0xff;
        println!(
            "landlock: abi {abi}, restricted {}, inside read {}, outside EACCES {}",
            bits & 1 != 0,
            bits & 2 != 0,
            bits & 4 != 0
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
