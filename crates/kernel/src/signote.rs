//! Who sent a signal whose `siginfo` the host emptied.
//!
//! macOS empties the `siginfo` of a signal it leaves pending while blocked.
//! fwe never blocks a signal the guest catches for the guest's sake, but its
//! own handlers run with every signal blocked, so a signal that arrives
//! while one runs (a child's `SIGUSR1` and then its `SIGCHLD`, say) is
//! taken after it with no sender. Linux keeps the sender.
//!
//! So an fwe process that sends another a signal first leaves a note of
//! itself in the target's mailbox, in the memory every fwe process maps
//! ([`crate::procstore::mailbox`], given to the target by its first
//! sender): a few slots per host signal (several processes can send one at
//! once, which the host merges), each with the sender's pid and user (its
//! guest real uid, an initial-namespace id, [`crate::creds::real_uid`]), when
//! it was written, and for a signal that carries more than its sender (one
//! a message queue raises, `SI_MESGQ`) its Linux `si_code` and value. A
//! handler given a signal with no sender takes the note for it, if a
//! recent one is there ([`take`]); one given a sender takes that sender's
//! note ([`take_from`]), so a later signal from elsewhere (the terminal,
//! the host) is not taken for it. A note whose signal could not be sent is
//! taken back.
//!
//! Every slot is claimed and taken with a compare-and-swap of its first
//! word, which holds a generation (bumped by each change, so a slot taken
//! and filled again meanwhile is never taken for the one seen) and the
//! sender, or a mark while a sender fills it: no lock, so a handler reads
//! and takes notes whatever its thread was doing.

use crate::ids::{HostPid, Tid};
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::{self, SeqCst};

/// The directory of the process records, made once as the process starts
/// (the handlers read it without allocating).
static DIR: OnceLock<Vec<u8>> = OnceLock::new();

/// A slot's words: its state (generation above, sender or [`BUSY`] or 0
/// below), the sender's uid and Linux `si_code`, when it was written
/// (monotonic nanoseconds), and the value.
const SLOT: usize = 4;

/// A slot's sender while one fills it in.
const BUSY: u64 = 0xffff_ffff;

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
/// Slots for each signal: notes of senders whose signals the host might
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

/// Learn where the process records are (reply sockets are made beside
/// them). Called as the process starts, before any handler needs it.
pub fn init() {
    if DIR.get().is_none()
        && let Some(d) = crate::procreg::records_dir()
    {
        let _ = DIR.set(d);
    }
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid out-parameter; async-signal-safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The words of host signal `sig`'s slots in mailbox `mb`.
fn slots(mb: &[crate::procstore::Word], sig: libc::c_int) -> Option<&[crate::procstore::Word]> {
    let s = usize::try_from(sig).ok().filter(|s| (1..SIGNALS).contains(s))?;
    let at = NOTES_AT + s * PER_SIGNAL * SLOT;
    mb.get(at..at + PER_SIGNAL * SLOT)
}

/// The mailbox's words: a ticket counter, the notes, then the queue.
const NOTES_AT: usize = 1;

/// Claim the slot whose state word is `w`, seen as `seen`: its next
/// generation, marked [`BUSY`] until filled in.
fn claim(w: &crate::procstore::Word, seen: u64) -> Option<u64> {
    let generation = (seen >> 32).wrapping_add(1) & 0xffff_ffff;
    w.compare_exchange(seen, generation << 32 | BUSY, SeqCst, SeqCst).ok().map(|_| generation)
}

/// The signal [`note`] was for could not be sent: take the note back, if
/// it is still this process's.
pub fn unnote(target: HostPid, sig: libc::c_int) {
    let Some(mb) = crate::procstore::mailbox(target) else { return };
    let Some(slots) = slots(mb, sig) else { return };
    let me = crate::host::pid().get() as u64;
    // This process's latest note there.
    let mine = slots
        .chunks(SLOT)
        .map(|s| (s, s[0].load(SeqCst), s[2].load(SeqCst)))
        .filter(|&(_, state, _)| state & 0xffff_ffff == me)
        .max_by_key(|&(_, _, when)| when);
    if let Some((s, state, _)) = mine {
        let _ = s[0].compare_exchange(state, state & !0xffff_ffff, SeqCst, SeqCst);
    }
}

/// Whether an fwe process sent host process `target` a `SIGKILL`: a note
/// of one is there, recent (it is never taken: the signal ends the
/// process before a handler could).
pub fn kill_noted(target: HostPid) -> bool {
    let Some(mb) = crate::procstore::mailbox(target) else { return false };
    let Some(slots) = slots(mb, libc::SIGKILL) else { return false };
    let now = now_ns();
    slots.chunks(SLOT).any(|s| {
        let pid = s[0].load(SeqCst) & 0xffff_ffff;
        pid != 0 && pid != BUSY && now.saturating_sub(s[2].load(SeqCst)) < FRESH_NS
    })
}

/// This process is about to send host signal `sig` to host process
/// `target`: leave a note of itself there.
pub fn note(target: HostPid, sig: libc::c_int) {
    note_with(target, sig, 0, 0, crate::creds::real_uid());
}

/// As [`note`], for a signal the target is to take with Linux `si_code`
/// `code` and value `value` (a message queue's notification), from user
/// `uid` (an initial-namespace id).
pub fn note_with(target: HostPid, sig: libc::c_int, code: i32, value: u64, uid: u32) {
    let Some(mb) = crate::procstore::mailbox_or_make(target) else { return };
    let Some(slots) = slots(mb, sig) else { return };
    let me = crate::host::pid().get() as u64;
    // A free slot of the signal's, or the oldest note's.
    for _ in 0..64 {
        let state = |s: &[crate::procstore::Word]| s[0].load(SeqCst);
        let pick = slots.chunks(SLOT).find(|s| state(s) & 0xffff_ffff == 0).or_else(|| {
            slots
                .chunks(SLOT)
                .filter(|s| state(s) & 0xffff_ffff != BUSY)
                .min_by_key(|s| s[2].load(SeqCst))
        });
        let Some(s) = pick else {
            std::thread::yield_now();
            continue;
        };
        let seen = state(s);
        let Some(generation) = claim(&s[0], seen) else { continue };
        s[1].store(u64::from(uid) | (code as u32 as u64) << 32, SeqCst);
        s[2].store(now_ns(), SeqCst);
        s[3].store(value, SeqCst);
        s[0].store(generation << 32 | me, SeqCst);
        return;
    }
}

/// Read, and with `clear_if` (clearing only a note of that sender, or with
/// 0 any), clear this process's note for host signal `sig`.
/// Async-signal-safe.
fn read_note(sig: libc::c_int, clear_if: Option<i32>) -> Option<(Note, u64)> {
    // (A fork child's handler can run before it knows its own pid.)
    let mb = crate::procstore::mailbox(crate::host::pid_now())?;
    let slots = slots(mb, sig)?;
    let now = now_ns();
    for _ in 0..64 {
        // The note of the sender named, or (none named) the oldest recent
        // one: the signal the host merged others into came first.
        let pick = slots
            .chunks(SLOT)
            .map(|s| (s, s[0].load(SeqCst)))
            .filter(|&(s, state)| {
                let pid = state & 0xffff_ffff;
                pid != 0
                    && pid != BUSY
                    && match clear_if {
                        Some(c) if c != 0 => pid == c as u64,
                        _ => now.saturating_sub(s[2].load(SeqCst)) < FRESH_NS,
                    }
            })
            .min_by_key(|&(s, _)| s[2].load(SeqCst));
        let (s, state) = pick?;
        let (ids, when, value) = (s[1].load(SeqCst), s[2].load(SeqCst), s[3].load(SeqCst));
        // Taken (or, not to be taken, still as read): else read again.
        let kept = if clear_if.is_some() {
            s[0].compare_exchange(state, state & !0xffff_ffff, SeqCst, SeqCst).is_ok()
        } else {
            s[0].load(SeqCst) == state
        };
        if kept {
            let note = Note {
                pid: (state & 0xffff_ffff) as i32,
                uid: ids as u32,
                tid: 0,
                code: (ids >> 32) as i32,
                value,
            };
            return Some((note, when));
        }
    }
    None
}

/// The queue of signals the host has no equivalent of (Linux's real-time
/// signals, `SIGSTKFLT`, `SIGPWR`), after the host signals' slots: each
/// entry's words are its state (the ticket it was queued with above, the
/// Linux signal or 0 or [`BUSY`] below), the sender's pid and uid, the
/// `si_code` and thread, and the value. A sender queues one ([`queue`]),
/// then wakes the target with [`crate::host::WAKE_SIGNAL`], whose handler
/// takes them all, in the order of their tickets ([`drain`]).
const QUEUE_AT: usize = NOTES_AT + SIGNALS * PER_SIGNAL * SLOT;
/// Entries in the queue: as many signals as can wait for a process.
const QUEUE_LEN: usize = 64;
const ENTRY: usize = 4;

/// Queue Linux signal `sig`, which the host lacks, for host process
/// `target`, sent with `code` and `value` (and this process as sender):
/// a standard one already queued is not queued again, as Linux keeps one;
/// a full queue refuses a real-time one (`EAGAIN`). The caller wakes the
/// target.
pub fn queue(target: HostPid, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    put(target, 0, sig, code, value)
}

/// [`queue`] with the sender the signal names: host pid `pid` and user
/// `uid` (an initial-namespace id), as `rt_sigqueueinfo`'s caller gives
/// them, or a message queue's sender.
pub fn queue_from(
    target: HostPid,
    sig: u64,
    code: i32,
    value: u64,
    (pid, uid): (i32, u32),
) -> Result<(), i32> {
    put_from(target, 0, sig, code, value, (pid as u32, uid))
}

/// [`queue`] for thread `tid` of host process `target`.
pub fn queue_thread(target: HostPid, tid: Tid, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    put(target, tid.get(), sig, code, value)
}

/// [`queue_thread`] with the sender the signal names, as [`queue_from`].
pub fn queue_thread_from(
    target: HostPid,
    tid: Tid,
    sig: u64,
    code: i32,
    value: u64,
    (pid, uid): (i32, u32),
) -> Result<(), i32> {
    put_from(target, tid.get(), sig, code, value, (pid as u32, uid))
}

/// The mailbox's count of the `SIGCONT`s sent to its process
/// ([`continuing`]), after the queue: also the word a process in a stop of
/// fwe's sleeps on ([`park_word`]).
const CONTINUED_AT: usize = QUEUE_AT + QUEUE_LEN * ENTRY;
/// The process's job-control stop, as its parent's `wait` sees it: the
/// number of its stops so far times 256, plus the signal of the one it is
/// in (none while it runs) ([`job_stopped`], [`job_continued`]).
const STOP_AT: usize = CONTINUED_AT + 1;
/// The latest of those stops a `wait` reported.
const STOP_SEEN_AT: usize = CONTINUED_AT + 2;
/// How many times it came back from a stop; and the latest of those a
/// `wait` reported.
const CONT_AT: usize = CONTINUED_AT + 3;
const CONT_SEEN_AT: usize = CONTINUED_AT + 4;
const _: () = assert!(CONT_SEEN_AT < crate::procstore::MAILBOX_WORDS - 1);

/// How many times host process `pid` has been continued ([`continuing`]): 0
/// while it has no mailbox. Async-signal-safe once the store is mapped.
pub fn continued(pid: HostPid) -> u64 {
    crate::procstore::mailbox(pid).and_then(|mb| mb.get(CONTINUED_AT)).map_or(0, |w| w.load(SeqCst))
}

/// Host process `pid` is sent `SIGCONT`: a stop signal sent to it before,
/// still queued or pending, is not taken, as Linux discards a pending stop
/// signal as `SIGCONT` is sent (`prepare_signal`), and a stop of fwe's it
/// is in ends ([`park_word`]). Its mailbox is made if it has none (the
/// sender's).
pub fn continuing(pid: HostPid) {
    count_continue(crate::procstore::mailbox_or_make(pid));
}

/// [`continuing`] of this process, from its own handler of the host's
/// `SIGCONT`: async-signal-safe (with no mailbox, nothing was queued for
/// it, and nothing is counted).
pub fn continuing_own() {
    count_continue(crate::procstore::mailbox(crate::host::pid_now()));
}

fn count_continue(mb: Option<&'static [AtomicU64]>) {
    if let Some(w) = mb.and_then(|mb| mb.get(CONTINUED_AT)) {
        w.fetch_add(1, SeqCst);
        crate::shared::wake_word(w);
    }
}

/// The word this process sleeps on in a stop of fwe's, which every
/// continue changes and wakes ([`continuing`]); its mailbox made if it has
/// none.
pub fn park_word() -> &'static AtomicU64 {
    let mb = crate::procstore::mailbox_or_make(crate::host::pid_now());
    mb.and_then(|mb| mb.get(CONTINUED_AT)).expect("a mailbox has its words")
}

/// This process is new (a fork child, or a program fwe starts, not one an
/// `execve` ran): what an earlier process of its number left of its stops
/// in a mailbox it might share is not its. Async-signal-safe.
pub fn job_reset() {
    let Some(mb) = crate::procstore::mailbox(crate::host::pid_now()) else { return };
    for i in [STOP_AT, STOP_SEEN_AT, CONT_AT, CONT_SEEN_AT] {
        if let Some(w) = mb.get(i) {
            w.store(0, SeqCst);
        }
    }
}

/// This process enters a job-control stop of fwe's, of signal `sig`.
pub fn job_stopped(sig: u64) {
    if let Some(w) =
        crate::procstore::mailbox_or_make(crate::host::pid_now()).and_then(|mb| mb.get(STOP_AT))
    {
        let seq = w.load(SeqCst) >> 8;
        w.store((seq + 1) << 8 | (sig & 0xff), SeqCst);
    }
}

/// This process comes back from its job-control stop.
pub fn job_continued() {
    let Some(mb) = crate::procstore::mailbox(crate::host::pid_now()) else { return };
    if let (Some(stop), Some(cont)) = (mb.get(STOP_AT), mb.get(CONT_AT)) {
        stop.fetch_and(!0xff, SeqCst);
        cont.fetch_add(1, SeqCst);
    }
}

/// The signal of the job-control stop of fwe's host process `pid` is in,
/// if any. Async-signal-safe.
pub fn job_stop_of(pid: HostPid) -> Option<u64> {
    let w = crate::procstore::mailbox(pid)?.get(STOP_AT)?.load(SeqCst);
    (w & 0xff != 0).then_some(w & 0xff)
}

/// What a `wait` of host process `pid`'s parent reports of its
/// job-control stops: the stop it is in, if `stopped` and none reported it
/// yet, as `(CLD_STOPPED, signal)`; else, if `continued`, its coming back
/// from one since none reported, as `(CLD_CONTINUED, SIGCONT)`. Taken
/// (reported once), unless `peek`.
pub fn take_job_change(
    pid: HostPid,
    stopped: bool,
    continued: bool,
    peek: bool,
) -> Option<(i32, i32)> {
    let mb = crate::procstore::mailbox(pid)?;
    let (stop, stop_seen) = (mb.get(STOP_AT)?, mb.get(STOP_SEEN_AT)?);
    let (cont, cont_seen) = (mb.get(CONT_AT)?, mb.get(CONT_SEEN_AT)?);
    // Claimed by one `wait` alone, however many look at once.
    let claim = |word: &AtomicU64, from: u64, to: u64| {
        peek || word.compare_exchange(from, to, SeqCst, SeqCst).is_ok()
    };
    let now = stop.load(SeqCst);
    if stopped && now & 0xff != 0 {
        let seen = stop_seen.load(SeqCst);
        if now >> 8 > seen && claim(stop_seen, seen, now >> 8) {
            return Some((fwe_abi::wait::CLD_STOPPED, (now & 0xff) as i32));
        }
    }
    if continued && now & 0xff == 0 {
        let (n, seen) = (cont.load(SeqCst), cont_seen.load(SeqCst));
        if n > seen && claim(cont_seen, seen, n) {
            return Some((fwe_abi::wait::CLD_CONTINUED, fwe_abi::signal::SIGCONT as i32));
        }
    }
    None
}

/// What a queue entry holds in place of a signal for a request of a
/// descriptor ([`request_fd`]): above every signal number.
const FD_REQUEST: u64 = 0x1_0000;

/// Ask host process `target` (woken by the caller) for its descriptor
/// `fd`, to be sent to this process's reply socket `token`
/// ([`fd_reply_socket`]).
pub fn request_fd(target: HostPid, fd: i32, token: u64) -> Result<(), i32> {
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
pub fn foster(target: HostPid) -> Result<(), i32> {
    put(target, 0, FOSTER_NOTE, 0, 0)
}

/// What a queue entry holds for the note that another process left the
/// receiver resource limits ([`limits_set`]).
const LIMITS_NOTE: u64 = 0x1_0003;

/// Tell host process `target` (woken by the caller) that limits were left
/// in its record for it ([`crate::procreg::limits_left`]).
pub fn limits_set(target: HostPid) -> Result<(), i32> {
    put(target, 0, LIMITS_NOTE, 0, 0)
}

/// Ask process `target` to copy between its memory and the request object
/// of reply socket `token` ([`answer_mem`]).
pub fn request_mem(target: HostPid, token: u64) -> Result<(), i32> {
    put(target, 0, MEM_REQUEST, 0, token)
}

/// The length of a memory request object's name, its NUL included.
pub const MEM_NAME: usize = 21;

/// The name of process `pid`'s memory request `token`: a host shared
/// memory object (memory, not a file), named `/fwe` and a hash of the
/// user, the process and the token, within the host's 31 bytes;
/// NUL-terminated. Async-signal-safe.
pub fn mem_name(pid: i32, token: u64) -> [u8; MEM_NAME] {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut key = [0u8; 4 + 4 + 8 + 3];
    key[..3].copy_from_slice(b"mem");
    key[3..7].copy_from_slice(&uid.to_ne_bytes());
    key[7..11].copy_from_slice(&pid.to_ne_bytes());
    key[11..19].copy_from_slice(&token.to_ne_bytes());
    let h = crate::shared::hash(&key);
    let mut name = [0u8; MEM_NAME];
    name[..4].copy_from_slice(b"/fwe");
    for i in 0..16 {
        name[4 + i] = b"0123456789abcdef"[(h >> (60 - 4 * i) & 0xf) as usize];
    }
    name
}

/// A memory request's object: a header (the operation, 0 to read this
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
    let name = mem_name(caller, token);
    let saved = crate::host::last_errno();
    // SAFETY: a NUL-terminated name; the object mapped whole for the
    // duration, every access within its size; the host copies check the
    // addresses they are given.
    unsafe {
        let fd = libc::shm_open(name.as_ptr().cast(), libc::O_RDWR, 0 as libc::c_uint);
        if fd >= 0 {
            let mut st: libc::stat = std::mem::zeroed();
            let size = if libc::fstat(fd, &mut st) == 0 { st.st_size as usize } else { 0 };
            let map = if size >= MEM_HEADER {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            } else {
                libc::MAP_FAILED
            };
            libc::close(fd);
            if map != libc::MAP_FAILED {
                let m = std::slice::from_raw_parts_mut(map.cast::<u8>(), size);
                let word =
                    |m: &[u8], at: usize| u64::from_ne_bytes(m[at..at + 8].try_into().unwrap());
                let write = u32::from_ne_bytes(m[..4].try_into().unwrap()) == 1;
                let count = u32::from_ne_bytes(m[4..8].try_into().unwrap()) as usize;
                let data_at = MEM_HEADER + count.min(1024) * 16;
                let mut done: i64 = 0;
                let mut failed = data_at > size;
                'ranges: for i in 0..count.min(1024) {
                    if failed {
                        break;
                    }
                    let base = word(m, MEM_HEADER + i * 16);
                    let len = word(m, MEM_HEADER + i * 16 + 8);
                    let mut off = 0u64;
                    while off < len {
                        let Some((host, room)) = crate::uaccess::try_run(base + off) else {
                            done = MEM_RETRY;
                            break 'ranges;
                        };
                        let n = (len - off).min(room).min(4096);
                        let at = data_at + done as usize;
                        if at + n as usize > size {
                            failed = true;
                            break 'ranges;
                        }
                        let buf = m[at..].as_mut_ptr();
                        #[cfg(target_os = "macos")]
                        let copied = if write {
                            mach_vm_write(mach_task_self_, host, buf as usize, n as u32) == 0
                        } else {
                            let mut out = 0u64;
                            mach_vm_read_overwrite(mach_task_self_, host, n, buf as u64, &mut out)
                                == 0
                                && out == n
                        };
                        #[cfg(not(target_os = "macos"))]
                        let copied = {
                            let _ = (host, write, buf);
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
                m[8..16].copy_from_slice(&result.to_ne_bytes());
                libc::munmap(map, size);
            }
        }
    }
    crate::host::set_errno(saved);
    // The answer itself is in the object: the caller is only woken.
    answer_fd(caller, -1, token);
}

fn put(target: HostPid, tid: i32, sig: u64, code: i32, value: u64) -> Result<(), i32> {
    let me = (crate::host::pid().get() as u32, crate::creds::real_uid());
    put_from(target, tid, sig, code, value, me)
}

/// [`put`] naming host pid `me` and user `uid` as the sender.
fn put_from(
    target: HostPid,
    tid: i32,
    sig: u64,
    code: i32,
    value: u64,
    (me, uid): (u32, u32),
) -> Result<(), i32> {
    let mb = crate::procstore::mailbox_or_make(target).ok_or(fwe_abi::errno::ESRCH)?;
    let q = mb.get(QUEUE_AT..QUEUE_AT + QUEUE_LEN * ENTRY).ok_or(fwe_abi::errno::ESRCH)?;
    // A stop signal is dated by the target's continuations in place of a
    // value (it carries none): one sent before the next is not taken.
    let stop = crate::signal::discarded_by_continue(sig, code);
    let value = if stop { mb.get(CONTINUED_AT).map_or(0, |w| w.load(SeqCst)) } else { value };
    let sig_of = |e: &[crate::procstore::Word]| e[0].load(SeqCst) & 0xffff_ffff;
    // A standard signal already queued for the process is not queued
    // again, as Linux keeps one (a stop signal that is to be taken).
    if sig < fwe_abi::signal::SIGRTMIN
        && tid == 0
        && q.chunks(ENTRY).any(|e| {
            sig_of(e) == sig
                && (e[2].load(SeqCst) >> 32) as i32 == 0
                && (!stop || e[3].load(SeqCst) >= value)
        })
    {
        return Ok(());
    }
    for _ in 0..4 {
        for e in q.chunks(ENTRY) {
            let seen = e[0].load(SeqCst);
            if seen & 0xffff_ffff != 0 {
                continue;
            }
            let ticket = mb[0].fetch_add(1, SeqCst) & 0xffff_ffff;
            if e[0].compare_exchange(seen, ticket << 32 | BUSY, SeqCst, SeqCst).is_err() {
                continue;
            }
            e[1].store(u64::from(me) | u64::from(uid) << 32, SeqCst);
            e[2].store(code as u32 as u64 | (tid as u32 as u64) << 32, SeqCst);
            e[3].store(value, SeqCst);
            e[0].store(ticket << 32 | sig, SeqCst);
            return Ok(());
        }
    }
    Err(fwe_abi::errno::EAGAIN)
}

/// In the wake signal's handler: take every queued signal for this
/// process, each with its sender's note, in the order queued. One the
/// process has no room for under `RLIMIT_SIGPENDING`
/// ([`crate::thread::admits`]) stays queued, with those of its number
/// after it, until it has. Async-signal-safe (it allocates nothing).
pub fn drain(mut post: impl FnMut(u64, Note)) {
    let Some(mb) = crate::procstore::mailbox(crate::host::pid_now()) else { return };
    let Some(q) = mb.get(QUEUE_AT..QUEUE_AT + QUEUE_LEN * ENTRY) else { return };
    // In ticket order.
    let mut queued = [(0u64, 0usize); QUEUE_LEN];
    let mut n = 0;
    for (i, e) in q.chunks(ENTRY).enumerate() {
        let state = e[0].load(SeqCst);
        let sig = state & 0xffff_ffff;
        if sig != 0 && sig != BUSY {
            queued[n] = (state >> 32, i);
            n += 1;
        }
    }
    let queued = &mut queued[..n];
    queued.sort_unstable_by_key(|t| t.0);
    let mut taken = [(0u64, 0u64, 0u64, 0u64, 0u64); QUEUE_LEN];
    let (mut n, mut admitted, mut held) = (0, 0u64, 0u64);
    for &(_, i) in queued.iter() {
        let e = &q[i * ENTRY..(i + 1) * ENTRY];
        let state = e[0].load(SeqCst);
        let sig = state & 0xffff_ffff;
        if sig == 0 || sig == BUSY {
            continue;
        }
        let (a, b, c) = (e[1].load(SeqCst), e[2].load(SeqCst), e[3].load(SeqCst));
        if sig <= fwe_abi::signal::NSIG {
            let bit = 1u64 << (sig - 1);
            if held & bit != 0 || !crate::thread::admits(sig, b as u32 as i32, admitted) {
                held |= bit;
                continue;
            }
        }
        if e[0].compare_exchange(state, state & !0xffff_ffff, SeqCst, SeqCst).is_ok() {
            taken[n] = (state >> 32, sig, a, b, c);
            n += 1;
            if (fwe_abi::signal::SIGRTMIN..=fwe_abi::signal::NSIG).contains(&sig) {
                admitted += 1;
            }
        }
    }
    let taken = &taken[..n];
    for &(_, sig, ids, code_tid, value) in taken.iter() {
        let pid = ids as u32 as i32;
        if sig == FOSTER_NOTE {
            crate::reaper::fostered();
        } else if sig == LIMITS_NOTE {
            crate::procreg::limits_left();
        } else if sig == MEM_REQUEST {
            answer_mem(pid, value);
        } else if sig == FD_REQUEST {
            answer_fd(pid, code_tid as u32 as i32, value);
        } else if crate::signal::discarded_by_continue(sig, code_tid as u32 as i32)
            && value < continued(crate::host::pid_now())
        {
            // A stop signal sent before the process was last continued:
            // gone, as on Linux.
        } else if crate::signal::discarded_by_continue(sig, code_tid as u32 as i32) {
            // Pending as of its sending ([`put_from`]); the value only
            // dated it, a stop signal carries none.
            crate::signal::stop_sent_at(value);
            post(
                sig,
                Note {
                    pid,
                    uid: (ids >> 32) as u32,
                    code: code_tid as u32 as i32,
                    value: 0,
                    tid: (code_tid >> 32) as i32,
                },
            );
        } else {
            post(
                sig,
                Note {
                    pid,
                    uid: (ids >> 32) as u32,
                    code: code_tid as u32 as i32,
                    value,
                    tid: (code_tid >> 32) as i32,
                },
            );
        }
    }
}

/// In the host handler, for host signal `sig` that came with no sender: the
/// sender (host pid, guest uid) a recent note names, and what it carries,
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
/// the user can use, [`fd_reply_socket`]). Its length. Async-signal-safe.
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
    let len = reply_path(me.get(), token, &mut buf)?;
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
                fd >= 0 && crate::fdtable::guest_visible(fd) && libc::fcntl(fd, libc::F_GETFD) >= 0;
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
                let mut refused = crate::host::last_errno().raw();
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

/// What arrived on reply socket `sock`: the host errno of the answer (none
/// if it is 0) and the descriptor sent (-1 for none).
pub fn receive_fd(sock: i32) -> (Option<crate::host::HostErrno>, i32) {
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
            return (Some(crate::host::HostErrno::new(libc::EAGAIN)), -1);
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
        ((answer != 0).then_some(crate::host::HostErrno::new(answer)), fd)
    }
}

/// Host process `pid`'s mailbox goes with its record.
pub fn remove(pid: HostPid) {
    crate::procstore::forget_mailbox(pid);
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
        let me = me.get();
        assert_eq!(got, [(34, -1, 7, me), (16, 0, 0, me), (34, -1, 8, me)]);
        let mut again = 0;
        drain(|_, _| again += 1);
        assert_eq!(again, 0);
    }

    /// A note left for this process is taken once, by a handler that
    /// names no sender, and one for another sender is left.
    #[test]
    fn notes_are_taken_once() {
        let _one = OWN_BOX.lock().unwrap_or_else(|e| e.into_inner());
        init();
        let me = crate::host::pid();
        // A signal no other test notes.
        let sig = libc::SIGXFSZ;
        note(me, sig);
        assert_eq!(take(sig).map(|n| n.pid), Some(me.get()));
        assert!(take(sig).is_none());
        note_with(me, sig, -3, 9, 0);
        assert!(take_from(sig, me.get() + 1).is_none());
        assert_eq!(take_from(sig, me.get()).map(|n| (n.code, n.value)), Some((-3, 9)));
    }
}
