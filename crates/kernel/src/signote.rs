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
//! ([`crate::procreg`]): one slot per host signal, with the sender's pid
//! and user, when it was written, and for a signal that carries more than
//! its sender (one a message queue raises, `SI_MESGQ`) its Linux `si_code`
//! and value. A handler given a signal with no
//! sender takes the note for it, if a recent one is there ([`take`]); one
//! given a sender takes that sender's note ([`take_from`]), so a later
//! signal from elsewhere (the terminal, the host) is not taken for it. Both
//! are
//! async-signal-safe: `pread` and `pwrite` on the process's own mailbox,
//! which it opened as it started (and a fork child as it starts), in fwe's
//! reserved descriptor range, so a handler takes no number the guest's
//! next descriptor would. A note whose signal could not be sent is taken
//! back.

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
    /// Linux's `si_code`: `SI_USER` (0) for a plain `kill`.
    pub code: i32,
    pub value: u64,
}
/// Host signals are numbered below this.
const SIGNALS: usize = 32;
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
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    if OWN_PID.load(Ordering::SeqCst) == me {
        return;
    }
    let mut buf = [0u8; 512];
    let Some(path) = mailbox(me, &mut buf) else { return };
    // SAFETY: a NUL-terminated path; the descriptor is moved out of the
    // guest's range and kept for the process's life.
    let fd = unsafe { libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600) };
    let Ok(fd) = crate::fdtable::reserve(fd) else { return };
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
    let need = dir.len() + 1 + len + 4 + 1;
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
    buf[at..at + 4].copy_from_slice(b".sig");
    buf[at + 4] = 0;
    Some(buf.as_ptr().cast())
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid out-parameter; async-signal-safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn offset(sig: libc::c_int) -> Option<libc::off_t> {
    (1..SIGNALS as libc::c_int).contains(&sig).then(|| sig as libc::off_t * SLOT as libc::off_t)
}

/// The signal [`note`] was for could not be sent: take the note back, if
/// it is still this process's.
pub fn unnote(target: i32, sig: libc::c_int) {
    let Some(off) = offset(sig) else { return };
    let mut buf = [0u8; 512];
    let Some(path) = mailbox(target, &mut buf) else { return };
    let mut slot = [0u8; SLOT];
    // SAFETY: a NUL-terminated path; buffers of `SLOT` bytes.
    unsafe {
        let fd = libc::open(path, libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            return;
        }
        let me = libc::getpid();
        if libc::pread(fd, slot.as_mut_ptr().cast(), SLOT, off) == SLOT as isize
            && i32::from_ne_bytes(slot[0..4].try_into().unwrap()) == me
        {
            libc::pwrite(fd, [0u8; SLOT].as_ptr().cast(), SLOT, off);
        }
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
    // SAFETY: a NUL-terminated path; a buffer of `SLOT` bytes.
    unsafe {
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd >= 0 {
            libc::pwrite(fd, slot.as_ptr().cast(), SLOT, off);
            libc::close(fd);
        }
    }
}

/// Read, and with `clear_if` (clearing only a note of that sender, or with
/// 0 any), clear this process's note for host signal `sig`.
/// Async-signal-safe.
fn read_note(sig: libc::c_int, clear_if: Option<i32>) -> Option<(Note, u64)> {
    let off = offset(sig)?;
    // SAFETY: getpid cannot fail.
    if OWN_PID.load(Ordering::SeqCst) != unsafe { libc::getpid() } {
        // Not open for this process yet (a fork child before it starts).
        return None;
    }
    let fd = OWN.load(Ordering::SeqCst);
    let saved = crate::host::last_errno();
    let mut slot = [0u8; SLOT];
    // SAFETY: fwe's own descriptor of the mailbox; a buffer of `SLOT`
    // bytes.
    let got = unsafe {
        let n = libc::pread(fd, slot.as_mut_ptr().cast(), SLOT, off);
        let pid = i32::from_ne_bytes(slot[0..4].try_into().unwrap());
        if n == SLOT as isize && pid != 0 && clear_if.is_none_or(|c| c == 0 || c == pid) {
            let zero = [0u8; SLOT];
            libc::pwrite(fd, zero.as_ptr().cast(), SLOT, off);
        }
        n == SLOT as isize && pid != 0
    };
    crate::host::set_errno(saved);
    let word = |at: usize| slot[at..at + 4].try_into().unwrap();
    got.then(|| {
        let note = Note {
            pid: i32::from_ne_bytes(word(0)),
            uid: u32::from_ne_bytes(word(4)),
            code: i32::from_ne_bytes(word(16)),
            value: u64::from_ne_bytes(slot[24..32].try_into().unwrap()),
        };
        (note, u64::from_ne_bytes(slot[8..16].try_into().unwrap()))
    })
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

    #[test]
    fn mailbox_path_is_made_without_allocating() {
        let _ = DIR.set(b"/x/v5-procs".to_vec());
        let mut buf = [0u8; 512];
        let p = mailbox(4021, &mut buf).unwrap();
        // SAFETY: NUL-terminated by `mailbox`.
        let s = unsafe { std::ffi::CStr::from_ptr(p) };
        if DIR.get().unwrap() == b"/x/v5-procs" {
            assert_eq!(s.to_bytes(), b"/x/v5-procs/4021.sig");
        }
        assert!(mailbox(0, &mut buf).is_none());
    }
}
