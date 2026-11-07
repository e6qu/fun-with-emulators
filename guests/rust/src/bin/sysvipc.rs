//! System V IPC between processes and threads: a shared memory segment a
//! child writes and its parent reads, a semaphore a child posts while its
//! parent waits on it (and another posted with `SEM_UNDO`, undone as the
//! child ends), messages both ways, and a semaphore posted by another
//! thread of a process that waits on it. One scenario per argument, each
//! printing what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const GETVAL: i32 = 12;
const GETPID: i32 = 11;
const SEM_UNDO: i16 = 0x1000;

#[repr(C)]
struct Sembuf {
    num: u16,
    op: i16,
    flg: i16,
}

#[repr(C)]
struct Msg {
    mtype: i64,
    text: [u8; 32],
}

unsafe extern "C" {
    fn shmget(key: i32, size: usize, flags: i32) -> i32;
    fn shmat(id: i32, addr: *const u8, flags: i32) -> *mut u8;
    fn shmdt(addr: *const u8) -> i32;
    fn shmctl(id: i32, cmd: i32, buf: *mut u8) -> i32;
    fn semget(key: i32, n: i32, flags: i32) -> i32;
    fn semop(id: i32, ops: *mut Sembuf, n: usize) -> i32;
    fn semctl(id: i32, num: i32, cmd: i32, ...) -> i32;
    fn msgget(key: i32, flags: i32) -> i32;
    fn msgsnd(id: i32, msg: *const Msg, size: usize, flags: i32) -> i32;
    fn msgrcv(id: i32, msg: *mut Msg, size: usize, mtype: i64, flags: i32) -> isize;
    fn msgctl(id: i32, cmd: i32, buf: *mut u8) -> i32;
    fn fork() -> i32;
    fn getpid() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn usleep(us: u32) -> i32;
    fn _exit(code: i32) -> !;
}

fn op(id: i32, delta: i16, flg: i16) -> i32 {
    let mut b = Sembuf { num: 0, op: delta, flg };
    // SAFETY: one valid operation.
    unsafe { semop(id, &mut b, 1) }
}

fn wait(pid: i32) -> i32 {
    let mut status = 0;
    // SAFETY: a valid out-parameter.
    unsafe { waitpid(pid, &mut status, 0) };
    status
}

fn processes() {
    // Shared memory: the child writes, the parent reads; attached once in
    // the parent afterwards.
    // SAFETY: plain calls with valid arguments; the segment is 8 KiB.
    unsafe {
        let shm = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0o600);
        let p = shmat(shm, std::ptr::null(), 0);
        let child = fork();
        if child == 0 {
            std::ptr::copy_nonoverlapping(b"written by the child\0".as_ptr(), p, 21);
            shmdt(p);
            _exit(0);
        }
        wait(child);
        let text = std::ffi::CStr::from_ptr(p.cast()).to_string_lossy().into_owned();
        let mut ds = [0u8; 112];
        shmctl(shm, IPC_STAT, ds.as_mut_ptr());
        let nattch = u64::from_ne_bytes(ds[88..96].try_into().unwrap());
        println!("shm: {text}, attached {nattch}");
        shmdt(p);
        shmctl(shm, IPC_RMID, std::ptr::null_mut());
    }

    // A semaphore the parent waits on and a child posts.
    // SAFETY: plain calls with valid arguments.
    unsafe {
        let sem = semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600);
        let child = fork();
        if child == 0 {
            usleep(100_000);
            op(sem, 1, 0);
            _exit(0);
        }
        let r = op(sem, -1, 0);
        wait(child);
        // The last to complete an operation on it is this process, whose
        // wait completed after the post.
        println!(
            "sem: waited for the child's post: {}, last by this process: {}",
            r == 0,
            semctl(sem, 0, GETPID) == getpid()
        );
        // Posted with SEM_UNDO by a child that ends: undone.
        let child = fork();
        if child == 0 {
            op(sem, 1, SEM_UNDO);
            _exit(0);
        }
        wait(child);
        println!("sem: after the child's undo: {}", semctl(sem, 0, GETVAL));
        semctl(sem, 0, IPC_RMID);
    }

    // Messages: a child waits for one of type 2 and answers with type 3.
    // SAFETY: plain calls with valid arguments.
    unsafe {
        let q = msgget(IPC_PRIVATE, IPC_CREAT | 0o600);
        let child = fork();
        if child == 0 {
            let mut m = Msg { mtype: 0, text: [0; 32] };
            let n = msgrcv(q, &mut m, 32, 2, 0);
            let mut reply = Msg { mtype: 3, text: [0; 32] };
            let answer = format!("got {}", String::from_utf8_lossy(&m.text[..n.max(0) as usize]));
            reply.text[..answer.len()].copy_from_slice(answer.as_bytes());
            msgsnd(q, &reply, answer.len(), 0);
            _exit(0);
        }
        let mut ping = Msg { mtype: 2, text: [0; 32] };
        ping.text[..4].copy_from_slice(b"ping");
        msgsnd(q, &ping, 4, 0);
        let mut m = Msg { mtype: 0, text: [0; 32] };
        let n = msgrcv(q, &mut m, 32, 3, 0);
        wait(child);
        println!("msg: {} (type {})", String::from_utf8_lossy(&m.text[..n.max(0) as usize]), m.mtype);
        // One more, left on the queue: its count, then gone with the queue.
        msgsnd(q, &ping, 4, 0);
        let mut ds = [0u8; 120];
        msgctl(q, IPC_STAT, ds.as_mut_ptr());
        let qnum = u64::from_ne_bytes(ds[80..88].try_into().unwrap());
        println!("msg: left on the queue: {qnum}");
        msgctl(q, IPC_RMID, std::ptr::null_mut());
    }
}

fn threads() {
    // A semaphore another thread posts while the main thread waits: the
    // wait must not hold anything the post needs.
    // SAFETY: plain calls with valid arguments.
    let sem = unsafe { semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600) };
    let poster = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        op(sem, 1, 0)
    });
    let r = op(sem, -1, 0);
    println!("thread: waited for the other thread's post: {}", r == 0 && poster.join().unwrap() == 0);
    // SAFETY: removing the set.
    unsafe { semctl(sem, 0, IPC_RMID) };
}

fn main() {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "processes" => processes(),
            "threads" => threads(),
            other => panic!("unknown scenario {other}"),
        }
    }
}
