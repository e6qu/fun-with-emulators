//! Who sent a signal whose `siginfo` the host emptied.
//!
//! macOS empties the `siginfo` of a signal it leaves pending while blocked.
//! fwe never blocks a signal the guest catches for the guest's sake, but its
//! own handlers run with every signal blocked, so a signal that arrives
//! while one runs (a child's `SIGUSR1` and then its `SIGCHLD`, say) is
//! taken after it with no sender. Linux keeps the sender.
//!
//! So an fwe process that sends another a signal first leaves a note of
//! itself in the target's mailbox, a small file beside its process record
//! ([`crate::procreg`]): a few slots per host signal (several processes
//! may send one at once, which the host merges), each with the sender's pid
//! and user, when it was written, and for a signal that carries more than
//! its sender (one a message queue raises, `SI_MESGQ`) its Linux `si_code`
//! and value. A handler given a signal with no
//! sender takes the note for it, if a recent one is there ([`take`]); one
//! given a sender takes that sender's note ([`take_from`]), so a later
//! signal from elsewhere (the terminal, the host) is not taken for it. Both
//! are
//! async-signal-safe: `pread` and `pwrite` on the process's own mailbox,
//! which the first sender makes, kept open in fwe's reserved descriptor
//! range once a handler first reads it (opening it by its path takes a
//! number below the range for that moment only). A note whose signal could
//! not be sent is taken back.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

/// The directory of the process records, made once as the process starts
/// (the handlers read it without allocating).
static DIR: OnceLock<Vec<u8>> = OnceLock::new();

/// A slot: sender pid (`i32`), sender uid (`u32`), monotonic nanoseconds
/// when written (`u64`), Linux `si_code` (`i32`, 0 for `SI_USER`), four
/// bytes unused, and the value (`u64`).
const SLOT: usize = 32;

/// A sender's note, as a handler takes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Note {
    pub pid: i32,
    pub uid: u32,
    /// The thread it is for (0: the process).
    pub tid: i32,
    /// Linux's `si_code`: `SI_USER` (0) for a plain `kill`.
    pub code: i32,
    pub value: u64,
}
/// Host signals are numbered below this.
const SIGNALS: usize = 32;
/// Slots for each signal: notes of senders whose signals the host may
/// have merged, taken one at a time.
const PER_SIGNAL: usize = 8;
/// A note older than this is not taken for a signal that came with no
/// sender (one whose sender has ended, or the host did not name): a signal
/// is held by fwe's handlers only for a moment, though a loaded machine
/// delivers it late.
const FRESH_NS: u64 = 10_000_000_000;
/// A note older than this is not taken for a signal from the process that
/// left it: the sender names it, so only a slow delivery (a loaded machine,
/// the VM's stand-in) separates them.
const SENDER_FRESH_NS: u64 = 60_000_000_000;

/// This process's own mailbox, open (-1: not yet), and the pid it is of.
static OWN: AtomicI32 = AtomicI32::new(-1);
static OWN_PID: AtomicI32 = AtomicI32::new(0);

/// Learn where the mailboxes are. Called as the process starts, before any
/// handler may need it.
pub fn init() {
    if DIR.get().is_none()
        && let Some(d) = crate::procreg::records_dir()
    {
        let _ = DIR.set(d);
    }
    open_own();
}

/// Open this process's own mailbox, if it is not open yet for this pid (a
/// fork child has its parent's open): where its handlers read notes.
pub fn open_own() {
    let me = crate::host::pid();
    if OWN_PID.load(Ordering::SeqCst) == me {
        return;
    }
    let mut buf = [0u8; 512];
    let Some(path) = mailbox(me, &mut buf) else { return };
    // Not made here: the first sender makes it, and the first note read
    // keeps it open ([`own_mailbox`]). Most processes are sent nothing,
    // and making a file costs more than the rest of a fork child's start.
    // SAFETY: a NUL-terminated path; the descriptor is moved out of the
    // guest's range and kept for the process's life.
    let fd = unsafe { libc::open(path, libc::O_RDWR | libc::O_CLOEXEC) };
    let fd = if fd >= 0 { crate::fdtable::reserve(fd).unwrap_or(-1) } else { -1 };
    let old = OWN.swap(fd, Ordering::SeqCst);
    OWN_PID.store(me, Ordering::SeqCst);
    if old >= 0 {
        // The parent's, inherited.
        // SAFETY: fwe's own descriptor, no longer used.
        unsafe { libc::close(old) };
    }
}

/// `<dir>/<pid>.sig`, NUL-terminated, in `buf`. Async-signal-safe.
fn mailbox(pid: i32, buf: &mut [u8; 512]) -> Option<*const libc::c_char> {
    record_file(pid, b".sig", buf)
}

/// The path of process `pid`'s file beside its record with suffix `suffix`
/// (`.sig`, its mailbox; `.end`, how it ended), NUL-terminated in `buf`.
/// Async-signal-safe: it allocates nothing.
pub fn record_file(pid: i32, suffix: &[u8], buf: &mut [u8; 512]) -> Option<*const libc::c_char> {
    let dir = DIR.get()?;
    let mut digits = [0u8; 12];
    let mut n = pid.unsigned_abs();
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let need = dir.len() + 1 + len + suffix.len() + 1;
    if pid <= 0 || need > buf.len() {
        return None;
    }
    buf[..dir.len()].copy_from_slice(dir);
    let mut at = dir.len();
    buf[at] = b'/';
    at += 1;
    for i in (0..len).rev() {
        buf[at] = digits[i];
        at += 1;
    }
    buf[at..at + suffix.len()].copy_from_slice(suffix);
    buf[at + suffix.len()] = 0;
    Some(buf.as_ptr().cast())
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid out-parameter; async-signal-safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Where the slots of host signal `sig` start.
fn offset(sig: libc::c_int) -> Option<libc::off_t> {
    (1..SIGNALS as libc::c_int)
        .contains(&sig)
        .then(|| (sig as usize * PER_SIGNAL * SLOT) as libc::off_t)
}

/// The pid and time of slot `i` of `slots`.
fn slot_of(slots: &[u8], i: usize) -> (i32, u64) {
    let s = &slots[i * SLOT..(i + 1) * SLOT];
    (
        i32::from_ne_bytes(s[0..4].try_into().unwrap()),
        u64::from_ne_bytes(s[8..16].try_into().unwrap()),
    )
}

/// The signal [`note`] was for could not be sent: take the note back, if
/// it is still this process's.
pub fn unnote(target: i32, sig: libc::c_int) {
    let Some(off) = offset(sig) else { return };
    let mut buf = [0u8; 512];
    let Some(path) = mailbox(target, &mut buf) else { return };
    let mut slots = [0u8; PER_SIGNAL * SLOT];
    // SAFETY: a NUL-terminated path; buffers of their lengths.
    unsafe {
        let fd = libc::open(path, libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            return;
        }
        crate::shared::lock_exclusive(fd);
        let me = libc::getpid();
        let n = libc::pread(fd, slots.as_mut_ptr().cast(), slots.len(), off).max(0) as usize;
        // This process's latest note there.
        let mine = (0..n / SLOT)
            .filter(|&i| slot_of(&slots, i).0 == me)
            .max_by_key(|&i| slot_of(&slots, i).1);
        if let Some(i) = mine {
            libc::pwrite(fd, [0u8; SLOT].as_ptr().cast(), SLOT, off + (i * SLOT) as libc::off_t);
        }
        libc::flock(fd, libc::LOCK_UN);
        libc::close(fd);
    }
}

/// This process is about to send host signal `sig` to host process
/// `target`: leave a note of itself there.
pub fn note(target: i32, sig: libc::c_int) {
    note_with(target, sig, 0, 0);
}

/// As [`note`], for a signal the target is to take with Linux `si_code`
/// `code` and value `value` (a message queue's notification).
pub fn note_with(target: i32, sig: libc::c_int, code: i32, value: u64) {
    let Some(off) = offset(sig) else { return };
    let mut buf = [0u8; 512];
    let Some(path) = mailbox(target, &mut buf) else { return };
    let mut slot = [0u8; SLOT];
    // SAFETY: plain host calls.
    let (me, uid) = unsafe { (libc::getpid(), libc::getuid()) };
    slot[0..4].copy_from_slice(&me.to_ne_bytes());
    slot[4..8].copy_from_slice(&uid.to_ne_bytes());
    slot[8..16].copy_from_slice(&now_ns().to_ne_bytes());
    slot[16..20].copy_from_slice(&code.to_ne_bytes());
    slot[24..32].copy_from_slice(&value.to_ne_bytes());
    // A free slot of the signal's, or the oldest note's, under the
    // mailbox's lock (other senders write there too).
    let mut slots = [0u8; PER_SIGNAL * SLOT];
    // SAFETY: a NUL-terminated path; buffers of their lengths.
    unsafe {
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd >= 0 {
            crate::shared::lock_exclusive(fd);
            let n = libc::pread(fd, slots.as_mut_ptr().cast(), slots.len(), off).max(0) as usize;
            let len = slots.len();
            slots[n.min(len)..].fill(0);
            let at = (0..PER_SIGNAL)
                .find(|&i| slot_of(&slots, i).0 == 0)
                .or_else(|| (0..PER_SIGNAL).min_by_key(|&i| slot_of(&slots, i).1))
                .unwrap_or(0);
            libc::pwrite(fd, slot.as_ptr().cast(), SLOT, off + (at * SLOT) as libc::off_t);
            libc::flock(fd, libc::LOCK_UN);
            libc::close(fd);
        }
    }
}

/// This process's mailbox for a handler to read: the descriptor kept open
/// for it while it is still the file at the mailbox's path, and whether it
/// was opened here instead (to be closed by the caller). A fork child
/// before it opened its own (it may be sent a signal at once) reads it by
/// its path; so does a process whose file was replaced: one that started
/// with the pid of a process whose records were left behind opens that
/// one's mailbox, which goes when those records are cleared, and senders
/// then write a new one. Async-signal-safe; the caller keeps errno.
fn own_mailbox() -> Option<(i32, bool)> {
    let me = crate::host::pid();
    let mut buf = [0u8; 512];
    let path = mailbox(me, &mut buf)?;
    let own = OWN.load(Ordering::SeqCst);
    if OWN_PID.load(Ordering::SeqCst) == me && own >= 0 {
        // SAFETY: stat buffers of their size; a NUL-terminated path.
        let same = unsafe {
            let (mut a, mut b): (libc::stat, libc::stat) = (std::mem::zeroed(), std::mem::zeroed());
            libc::fstat(own, &mut a) == 0
                && libc::stat(path, &mut b) == 0
                && (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
        };
        if same {
            return Some((own, false));
        }
    }
    // SAFETY: a NUL-terminated path; async-signal-safe.
    let fd = unsafe { libc::open(path, libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // Kept for the next note, out of the guest's range, if none is kept:
    // the mailbox a sender made after this process started.
    if OWN_PID.load(Ordering::SeqCst) == me && own < 0 {
        // SAFETY: plain host calls on the descriptor just opened;
        // async-signal-safe.
        let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, crate::fdtable::guest_max()) };
        if high >= 0 {
            // SAFETY: the descriptor opened above, now copied.
            unsafe { libc::close(fd) };
            if OWN.compare_exchange(-1, high, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return Some((high, false));
            }
            return Some((high, true));
        }
    }
    Some((fd, true))
}

/// Read, and with `clear_if` (clearing only a note of that sender, or with
/// 0 any), clear this process's note for host signal `sig`.
/// Async-signal-safe.
fn read_note(sig: libc::c_int, clear_if: Option<i32>) -> Option<(Note, u64)> {
    let off = offset(sig)?;
    let saved = crate::host::last_errno();
    let Some((fd, opened)) = own_mailbox() else {
        crate::host::set_errno(saved);
        return None;
    };
    let opened = opened.then_some(fd);
    let mut slots = [0u8; PER_SIGNAL * SLOT];
    let mut slot = [0u8; SLOT];
    // SAFETY: fwe's own descriptor of the mailbox; buffers of their
    // lengths.
    let got = unsafe {
        let n = libc::pread(fd, slots.as_mut_ptr().cast(), slots.len(), off).max(0) as usize;
        let now = now_ns();
        // The note of the sender named, or (none named) the oldest recent
        // one: the signal the host merged others into came first.
        let pick = (0..n / SLOT)
            .filter(|&i| {
                let (pid, when) = slot_of(&slots, i);
                pid != 0
                    && match clear_if {
                        Some(c) if c != 0 => pid == c,
                        _ => now.saturating_sub(when) < FRESH_NS,
                    }
            })
            .min_by_key(|&i| slot_of(&slots, i).1);
        if let Some(i) = pick {
            slot.copy_from_slice(&slots[i * SLOT..(i + 1) * SLOT]);
            if clear_if.is_some() {
                let zero = [0u8; SLOT];
                libc::pwrite(fd, zero.as_ptr().cast(), SLOT, off + (i * SLOT) as libc::off_t);
            }
        }
        pick.is_some()
    };
    if let Some(fd) = opened {
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
    }
    crate::host::set_errno(saved);
    let word = |at: usize| slot[at..at + 4].try_into().unwrap();
    got.then(|| {
        let note = Note {
            pid: i32::from_ne_bytes(word(0)),
            uid: u32::from_ne_bytes(word(4)),
            tid: 0,
            code: i32::from_ne_bytes(word(16)),
            value: u64::from_ne_bytes(slot[24..32].try_into().unwrap()),
        };
        (note, u64::from_ne_bytes(slot[8..16].try_into().unwrap()))
    })
}

/// The queue of signals the host has no equivalent of (Linux's real-time
/// signals, `SIGSTKFLT`, `SIGPWR`), after the host signals' slots: each
/// entry is the Linux signal (0: free), the sender's pid and uid, the
/// `si_code` and the value. A sender queues one under the mailbox's lock
/// ([`queue`]), then wakes the target with [`crate::host::WAKE_SIGNAL`],
/// whose handler takes them all ([`drain`]).
const QUEUE_AT: usize = SIGNALS * PER_SIGNAL * SLOT;
/// Entries in the queue: as many signals as may wait for a process.
const QUEUE_LEN: usize = 64;
const ENTRY: usize = 32;

/// Queue Linux signal `sig`, which the host lacks, for host process
/// `target`, sent with `code` and `value` (and this process as sender):
/// a standard one already queued is not queued again, as Linux keeps one;
/// a full queue refuses a real-time one (`EAGAIN`). The caller wakes the
/// target.
pub fn queue(target: i32, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    put(target, 0, sig, code, value)
}

/// [`queue`] for thread `tid` of host process `target`.
pub fn queue_thread(target: i32, tid: i32, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    put(target, tid, sig, code, value)
}

/// What a queue entry holds in place of a signal for a request of a
/// descriptor ([`request_fd`]): above every signal number.
const FD_REQUEST: u64 = 0x1_0000;

/// Ask host process `target` (woken by the caller) for its descriptor
/// `fd`, to be sent to this process's reply socket `token`
/// ([`fd_reply_socket`]).
pub fn request_fd(target: i32, fd: i32, token: u64) -> Result<(), i32> {
    put(target, 0, FD_REQUEST, fd, token)
}

/// What a queue entry holds for a request to copy this process's memory
/// ([`request_mem`]).
const MEM_REQUEST: u64 = 0x1_0001;

/// What a queue entry holds for the note that the receiver has a foster
/// child ([`foster`]).
const FOSTER_NOTE: u64 = 0x1_0002;

/// Tell host process `target` (woken by the caller) that it has a child
/// made with `CLONE_PARENT` ([`crate::reaper::foster_started`]).
pub fn foster(target: i32) -> Result<(), i32> {
    put(target, 0, FOSTER_NOTE, 0, 0)
}

/// Ask process `target` to copy between its memory and the request file
/// of reply socket `token` ([`answer_mem`]).
pub fn request_mem(target: i32, token: u64) -> Result<(), i32> {
    put(target, 0, MEM_REQUEST, 0, token)
}

/// A memory request's file: its reply socket's path with `m` after it.
fn mem_path(pid: i32, token: u64, buf: &mut [u8; SUN_PATH + 1]) -> Option<usize> {
    let mut sock = [0u8; SUN_PATH];
    let len = reply_path(pid, token, &mut sock)?;
    buf[..len].copy_from_slice(&sock[..len]);
    buf[len] = b'm';
    buf[len + 1] = 0;
    Some(len + 1)
}

/// The path of process `pid`'s memory request `token`.
pub fn mem_request_path(pid: i32, token: u64) -> Option<Vec<u8>> {
    let mut buf = [0u8; SUN_PATH + 1];
    let len = mem_path(pid, token, &mut buf)?;
    Some(buf[..len].to_vec())
}

/// A memory request's file: a header (the operation, 0 to read this
/// process's memory and 1 to write it; the count of ranges; the result,
/// written by the answer), the ranges (address and length), then the
/// data. The answer's result is the bytes copied, `-EFAULT` if none could
/// be, or [`MEM_RETRY`] when the translation of guest addresses was being
/// changed.
pub const MEM_HEADER: usize = 16;
pub const MEM_RETRY: i64 = i64::MIN;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_vm_read_overwrite(task: u32, addr: u64, size: u64, data: u64, out: *mut u64) -> i32;
    fn mach_vm_write(task: u32, addr: u64, data: usize, count: u32) -> i32;
    /// This task's port (`mach_task_self()` is a macro over it).
    static mach_task_self_: u32;
}

/// In the wake handler: carry out process `caller`'s memory request
/// `token` on this process's memory, through the host's copies of its own
/// task, which report an address with nothing behind it rather than fault,
/// and tell the caller on its reply socket. Async-signal-safe.
fn answer_mem(caller: i32, token: u64) {
    let mut path = [0u8; SUN_PATH + 1];
    let Some(_) = mem_path(caller, token, &mut path) else { return };
    let saved = crate::host::last_errno();
    // SAFETY: a NUL-terminated path; buffers on the stack of their stated
    // lengths; the host copies check the addresses they are given.
    unsafe {
        let fd = libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd >= 0 {
            let mut h = [0u8; MEM_HEADER];
            let ok = libc::pread(fd, h.as_mut_ptr().cast(), MEM_HEADER, 0) == MEM_HEADER as isize;
            let write = u32::from_ne_bytes(h[..4].try_into().unwrap()) == 1;
            let count = u32::from_ne_bytes(h[4..8].try_into().unwrap()) as usize;
            let data_at = MEM_HEADER + count * 16;
            let mut done: i64 = 0;
            let mut failed = !ok;
            'ranges: for i in 0..count.min(1024) {
                if failed {
                    break;
                }
                let mut r = [0u8; 16];
                if libc::pread(fd, r.as_mut_ptr().cast(), 16, (MEM_HEADER + i * 16) as libc::off_t)
                    != 16
                {
                    failed = true;
                    break;
                }
                let base = u64::from_ne_bytes(r[..8].try_into().unwrap());
                let len = u64::from_ne_bytes(r[8..].try_into().unwrap());
                let mut off = 0u64;
                while off < len {
                    let Some((host, room)) = crate::uaccess::try_run(base + off) else {
                        done = MEM_RETRY;
                        break 'ranges;
                    };
                    let n = (len - off).min(room).min(4096);
                    let mut buf = [0u8; 4096];
                    let at = (data_at as u64 + done as u64) as libc::off_t;
                    #[cfg(target_os = "macos")]
                    let copied = if write {
                        libc::pread(fd, buf.as_mut_ptr().cast(), n as usize, at) == n as isize
                            && mach_vm_write(mach_task_self_, host, buf.as_ptr() as usize, n as u32)
                                == 0
                    } else {
                        let mut out = 0u64;
                        mach_vm_read_overwrite(
                            mach_task_self_,
                            host,
                            n,
                            buf.as_mut_ptr() as u64,
                            &mut out,
                        ) == 0
                            && out == n
                            && libc::pwrite(fd, buf.as_ptr().cast(), n as usize, at) == n as isize
                    };
                    #[cfg(not(target_os = "macos"))]
                    let copied = {
                        let _ = (host, at, write, &mut buf);
                        false
                    };
                    if !copied {
                        failed = true;
                        break 'ranges;
                    }
                    done += n as i64;
                    off += n;
                }
            }
            let result = if done == MEM_RETRY || done > 0 || !failed {
                done
            } else {
                -i64::from(fwe_abi::errno::EFAULT)
            };
            libc::pwrite(fd, result.to_ne_bytes().as_ptr().cast(), 8, 8);
            libc::close(fd);
        }
    }
    crate::host::set_errno(saved);
    // The answer itself is in the file: the caller is only woken.
    answer_fd(caller, -1, token);
}

fn put(target: i32, tid: i32, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    let mut buf = [0u8; 512];
    let path = mailbox(target, &mut buf).ok_or(fwe_abi::errno::ESRCH)?;
    // SAFETY: plain host calls.
    let (me, uid) = unsafe { (libc::getpid(), libc::getuid()) };
    // SAFETY: a NUL-terminated path; buffers of their stated lengths; the
    // descriptor is closed below.
    unsafe {
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd < 0 {
            return Err(fwe_abi::errno::ESRCH);
        }
        crate::shared::lock_exclusive(fd);
        let mut q = [0u8; QUEUE_LEN * ENTRY];
        let n = libc::pread(fd, q.as_mut_ptr().cast(), q.len(), QUEUE_AT as libc::off_t);
        if n < q.len() as isize {
            // Short of the queue: what is missing is free.
            q[n.max(0) as usize..].fill(0);
        }
        let sig_at = |i: usize| i32::from_ne_bytes(q[i * ENTRY..i * ENTRY + 4].try_into().unwrap());
        let r = if sig < fwe_abi::signal::SIGRTMIN
            && tid == 0
            && (0..QUEUE_LEN).any(|i| sig_at(i) == sig as i32)
        {
            Ok(())
        } else if let Some(i) = (0..QUEUE_LEN).find(|&i| sig_at(i) == 0) {
            let mut e = [0u8; ENTRY];
            e[0..4].copy_from_slice(&(sig as i32).to_ne_bytes());
            e[4..8].copy_from_slice(&me.to_ne_bytes());
            e[8..12].copy_from_slice(&uid.to_ne_bytes());
            e[12..16].copy_from_slice(&code.to_ne_bytes());
            e[16..24].copy_from_slice(&value.to_ne_bytes());
            e[24..28].copy_from_slice(&tid.to_ne_bytes());
            let at = (QUEUE_AT + i * ENTRY) as libc::off_t;
            if libc::pwrite(fd, e.as_ptr().cast(), ENTRY, at) == ENTRY as isize {
                Ok(())
            } else {
                Err(fwe_abi::errno::EAGAIN)
            }
        } else {
            Err(fwe_abi::errno::EAGAIN)
        };
        libc::flock(fd, libc::LOCK_UN);
        libc::close(fd);
        r
    }
}

/// In the wake signal's handler: take every queued signal for this
/// process, each with its sender's note, in the order queued.
/// Async-signal-safe.
pub fn drain(mut post: impl FnMut(u64, Note)) {
    let saved = crate::host::last_errno();
    let Some((fd, opened)) = own_mailbox() else {
        crate::host::set_errno(saved);
        return;
    };
    let mut q = [0u8; QUEUE_LEN * ENTRY];
    // SAFETY: fwe's descriptor of the mailbox; a buffer of its length.
    let n = unsafe {
        crate::shared::lock_exclusive(fd);
        let n = libc::pread(fd, q.as_mut_ptr().cast(), q.len(), QUEUE_AT as libc::off_t);
        if n > 0 {
            let zero = [0u8; QUEUE_LEN * ENTRY];
            libc::pwrite(fd, zero.as_ptr().cast(), n as usize, QUEUE_AT as libc::off_t);
        }
        libc::flock(fd, libc::LOCK_UN);
        if opened {
            libc::close(fd);
        }
        n
    };
    crate::host::set_errno(saved);
    for e in q[..n.max(0) as usize].as_chunks::<ENTRY>().0.iter() {
        let word = |at: usize| e[at..at + 4].try_into().unwrap();
        let sig = i32::from_ne_bytes(word(0));
        if sig as u64 == FOSTER_NOTE {
            crate::reaper::fostered();
        } else if sig as u64 == MEM_REQUEST {
            answer_mem(
                i32::from_ne_bytes(word(4)),
                u64::from_ne_bytes(e[16..24].try_into().unwrap()),
            );
        } else if sig as u64 == FD_REQUEST {
            answer_fd(
                i32::from_ne_bytes(word(4)),
                i32::from_ne_bytes(word(12)),
                u64::from_ne_bytes(e[16..24].try_into().unwrap()),
            );
        } else if sig > 0 {
            post(
                sig as u64,
                Note {
                    pid: i32::from_ne_bytes(word(4)),
                    uid: u32::from_ne_bytes(word(8)),
                    code: i32::from_ne_bytes(word(12)),
                    value: u64::from_ne_bytes(e[16..24].try_into().unwrap()),
                    tid: i32::from_ne_bytes(word(24)),
                },
            );
        }
    }
}

/// In the host handler, for host signal `sig` that came with no sender: the
/// sender (host pid, host uid) a recent note names, and what it carries,
/// the note taken. Async-signal-safe.
pub fn take(sig: libc::c_int) -> Option<Note> {
    let (note, when) = read_note(sig, Some(0))?;
    (now_ns().saturating_sub(when) < FRESH_NS).then_some(note)
}

/// In the host handler, for host signal `sig` that came from `sender`: its
/// note, spent, if it left a recent one. Async-signal-safe.
pub fn take_from(sig: libc::c_int, sender: i32) -> Option<Note> {
    if sender <= 0 {
        return None;
    }
    let (note, when) = read_note(sig, Some(sender))?;
    (note.pid == sender && now_ns().saturating_sub(when) < SENDER_FRESH_NS).then_some(note)
}

/// A socket a descriptor another process sends is received on.
pub struct Reply {
    pub sock: i32,
    pub token: u64,
    /// Its path, removed with it.
    pub path: Vec<u8>,
}

impl Drop for Reply {
    fn drop(&mut self) {
        // SAFETY: the socket made for this reply, and its path.
        unsafe {
            libc::close(self.sock);
            if let Ok(c) = std::ffi::CString::new(self.path.clone()) {
                libc::unlink(c.as_ptr());
            }
        }
    }
}

/// Write `n` in decimal into `buf` at `*at`. Async-signal-safe.
fn put_decimal(mut n: u64, buf: &mut [u8], at: &mut usize) -> Option<()> {
    let mut d = [0u8; 20];
    let mut len = 0;
    loop {
        d[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if *at + len > buf.len() {
        return None;
    }
    for i in (0..len).rev() {
        buf[*at] = d[i];
        *at += 1;
    }
    Some(())
}

fn put_bytes(b: &[u8], buf: &mut [u8], at: &mut usize) -> Option<()> {
    buf.get_mut(*at..*at + b.len())?.copy_from_slice(b);
    *at += b.len();
    Some(())
}

/// The longest path a host `AF_UNIX` address holds, its NUL included.
const SUN_PATH: usize = 104;

/// The path of process `pid`'s reply socket `token`, NUL-terminated, in
/// `buf`: `<records>/<pid>.fd<token>`, or where that is too long for a
/// socket's address, `/tmp/fwe-<uid>-fd/<pid>.fd<token>` (a directory only
/// the user may use, [`fd_reply_socket`]). Its length. Async-signal-safe.
fn reply_path(pid: i32, token: u64, buf: &mut [u8; SUN_PATH]) -> Option<usize> {
    let dir = DIR.get()?;
    let name = |buf: &mut [u8; SUN_PATH], at: &mut usize| {
        put_bytes(b"/", buf, at)?;
        put_decimal(u64::from(pid.unsigned_abs()), buf, at)?;
        put_bytes(b".fd", buf, at)?;
        put_decimal(token, buf, at)?;
        (*at < SUN_PATH).then(|| buf[*at] = 0)
    };
    let mut at = 0;
    if put_bytes(dir, buf, &mut at).and_then(|()| name(buf, &mut at)).is_some() {
        return Some(at);
    }
    at = 0;
    put_bytes(b"/tmp/fwe-", buf, &mut at)?;
    // SAFETY: getuid cannot fail.
    put_decimal(u64::from(unsafe { libc::getuid() }), buf, &mut at)?;
    put_bytes(b"-fd", buf, &mut at)?;
    name(buf, &mut at)?;
    Some(at)
}

/// A new reply socket, bound where [`reply_path`] says, out of the
/// guest's descriptor range.
pub fn fd_reply_socket() -> Option<Reply> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let token = NEXT.fetch_add(1, Ordering::Relaxed);
    let me = crate::host::pid();
    let mut buf = [0u8; SUN_PATH];
    let len = reply_path(me, token, &mut buf)?;
    let path = buf[..len].to_vec();
    if !path.starts_with(DIR.get()?) {
        // The short directory: made only the user's, or refused if it is
        // anything else.
        let slash = path.iter().rposition(|&b| b == b'/')?;
        let d = std::ffi::CString::new(&path[..slash]).ok()?;
        // SAFETY: a NUL-terminated path; zeroed bytes are a valid `stat`.
        unsafe {
            libc::mkdir(d.as_ptr(), 0o700);
            let mut st: libc::stat = std::mem::zeroed();
            if libc::lstat(d.as_ptr(), &mut st) != 0
                || st.st_mode & libc::S_IFMT != libc::S_IFDIR
                || st.st_uid != libc::getuid()
                || st.st_mode & 0o077 != 0
            {
                return None;
            }
        }
    }
    // SAFETY: plain host call.
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    let sock = crate::fdtable::reserve(sock).ok()?;
    let reply = Reply { sock, token, path };
    // SAFETY: a valid address of the length given.
    let bound = crate::net::at_unix_path(&reply.path, |a, l| unsafe { libc::bind(sock, a, l) });
    (bound == Ok(0)).then_some(reply)
}

/// In the wake handler: send this process's descriptor `fd` to process
/// `caller`'s reply socket `token`, as `SCM_RIGHTS`, beside the host
/// errno (0) of the answer; a descriptor the guest has no such number of
/// is answered with `EBADF`. Async-signal-safe.
fn answer_fd(caller: i32, fd: i32, token: u64) {
    let mut path = [0u8; SUN_PATH];
    let Some(len) = reply_path(caller, token, &mut path) else { return };
    let saved = crate::host::last_errno();
    // SAFETY: zeroed bytes are a valid `sockaddr_un`, `msghdr` and control
    // buffer; plain host calls on a socket made and closed here, and on
    // the guest's descriptor `fd`, only sent.
    unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0);
        let mut a: libc::sockaddr_un = std::mem::zeroed();
        a.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (o, &b) in a.sun_path.iter_mut().zip(&path[..len]) {
            *o = b as libc::c_char;
        }
        let alen = (2 + len + 1) as libc::socklen_t;
        #[cfg(not(target_os = "linux"))]
        {
            a.sun_len = alen as u8;
        }
        if s >= 0 && libc::connect(s, (&a as *const libc::sockaddr_un).cast(), alen) == 0 {
            let valid =
                fd >= 0 && fd < crate::fdtable::guest_max() && libc::fcntl(fd, libc::F_GETFD) >= 0;
            let mut answer: i32 = if valid { 0 } else { libc::EBADF };
            let mut iov = libc::iovec { iov_base: (&mut answer as *mut i32).cast(), iov_len: 4 };
            let mut ctl = [0u64; 4];
            let mut m: libc::msghdr = std::mem::zeroed();
            m.msg_iov = &mut iov;
            m.msg_iovlen = 1;
            if valid {
                let c = ctl.as_mut_ptr().cast::<libc::cmsghdr>();
                (*c).cmsg_len = libc::CMSG_LEN(4) as _;
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                *(libc::CMSG_DATA(c) as *mut i32) = fd;
                m.msg_control = ctl.as_mut_ptr().cast();
                m.msg_controllen = libc::CMSG_SPACE(4) as _;
            }
            if libc::sendmsg(s, &m, 0) < 0 && valid {
                // One the host passes on no socket (a kqueue): its error.
                let mut refused = crate::host::last_errno();
                let mut again =
                    libc::iovec { iov_base: (&mut refused as *mut i32).cast(), iov_len: 4 };
                m.msg_iov = &mut again;
                m.msg_control = std::ptr::null_mut();
                m.msg_controllen = 0;
                libc::sendmsg(s, &m, 0);
            }
        }
        if s >= 0 {
            libc::close(s);
        }
    }
    crate::host::set_errno(saved);
}

/// What arrived on reply socket `sock`: the host errno of the answer (0
/// for none) and the descriptor sent (-1 for none).
pub fn receive_fd(sock: i32) -> (i32, i32) {
    let mut answer: i32 = 0;
    let mut ctl = [0u64; 4];
    // SAFETY: zeroed bytes are a valid `msghdr`; buffers of their stated
    // lengths; the control data read as the host wrote it.
    unsafe {
        let mut iov = libc::iovec { iov_base: (&mut answer as *mut i32).cast(), iov_len: 4 };
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_iov = &mut iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl.as_mut_ptr().cast();
        m.msg_controllen = std::mem::size_of_val(&ctl) as _;
        if libc::recvmsg(sock, &mut m, libc::MSG_DONTWAIT) < 4 {
            return (libc::EAGAIN, -1);
        }
        let c = libc::CMSG_FIRSTHDR(&m);
        let fd = if !c.is_null()
            && (*c).cmsg_level == libc::SOL_SOCKET
            && (*c).cmsg_type == libc::SCM_RIGHTS
        {
            *(libc::CMSG_DATA(c) as *const i32)
        } else {
            -1
        };
        (answer, fd)
    }
}

/// Host process `pid`'s mailbox goes with its record.
pub fn remove(pid: i32) {
    let mut buf = [0u8; 512];
    if let Some(path) = mailbox(pid, &mut buf) {
        // SAFETY: a NUL-terminated path.
        unsafe { libc::unlink(path) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that use this process's own mailbox, one at a time.
    static OWN_BOX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Signals the host lacks queue in a process's mailbox and are taken
    /// in order, a standard one once, each with its sender and value.
    #[test]
    fn queued_signals_are_taken_in_order() {
        let _one = OWN_BOX.lock().unwrap_or_else(|e| e.into_inner());
        init();
        let me = crate::host::pid();
        if DIR.get().is_none() {
            return;
        }
        drain(|_, _| {});
        queue(me, 34, -1, 7).unwrap();
        queue(me, 16, 0, 0).unwrap();
        queue(me, 16, 0, 0).unwrap();
        queue(me, 34, -1, 8).unwrap();
        let mut got = Vec::new();
        drain(|sig, n| got.push((sig, n.code, n.value, n.pid)));
        assert_eq!(got, [(34, -1, 7, me), (16, 0, 0, me), (34, -1, 8, me)]);
        let mut again = 0;
        drain(|_, _| again += 1);
        assert_eq!(again, 0);
    }

    /// A mailbox replaced under a process that has it open (the records
    /// of an earlier process with its pid cleared after it started) still
    /// brings it its senders' notes.
    #[test]
    fn a_replaced_mailbox_is_read_by_its_path() {
        let _one = OWN_BOX.lock().unwrap_or_else(|e| e.into_inner());
        init();
        let me = crate::host::pid();
        if DIR.get().is_none() {
            return;
        }
        // A signal no other test notes.
        let sig = libc::SIGXFSZ;
        let mut buf = [0u8; 512];
        let path = mailbox(me, &mut buf).unwrap();
        // SAFETY: a NUL-terminated path.
        unsafe { libc::unlink(path) };
        note(me, sig);
        assert_eq!(take(sig).map(|n| n.pid), Some(me));
        assert!(take(sig).is_none());
    }

    #[test]
    fn mailbox_path_is_made_without_allocating() {
        init();
        let Some(dir) = DIR.get() else { return };
        let mut buf = [0u8; 512];
        let p = mailbox(4021, &mut buf).unwrap();
        // SAFETY: NUL-terminated by `mailbox`.
        let s = unsafe { std::ffi::CStr::from_ptr(p) };
        assert_eq!(s.to_bytes(), [&dir[..], b"/4021.sig"].concat());
        assert!(mailbox(0, &mut buf).is_none());
    }
}
