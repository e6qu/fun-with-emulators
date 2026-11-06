//! The end of a named FIFO's writers, which macOS does not report.
//!
//! On Linux, once the last writer of a FIFO closes, its reader is readable
//! (`read` returns end-of-file) and `poll` and `epoll` report `POLLHUP`.
//! macOS's `read` returns end-of-file too, but neither `kqueue` nor `poll`
//! reports anything, so a reader that waits with them never learns it.
//! fwe probes such a reader itself: with nothing buffered, a read that does
//! not block returns 0 once the writers have gone, or fails with `EAGAIN`
//! while one remains. A byte that arrives between the look and the probe
//! is taken by it; it is kept ([`take`]) and given to the next read before
//! anything else, so the guest loses nothing. Anonymous pipes need none of
//! this: the host reports their writer's end.

use std::collections::HashMap;
use std::sync::Mutex;

/// What a probe found: the writers have gone, data is waiting, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    HungUp,
    Data,
    Nothing,
}

/// Bytes a probe took, by descriptor, with the identity of the FIFO.
/// A descriptor's kept bytes, with the identity (device, inode) of its FIFO.
type Kept = HashMap<i32, ((u64, u64), Vec<u8>)>;

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

fn kept<R>(f: impl FnOnce(&mut Kept) -> R) -> R {
    let mut g = KEPT.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn stat(fd: i32) -> Option<libc::stat> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

/// Whether `fd` is the read end of a named FIFO (one the host would not
/// report the writers' end of).
pub fn is_reader(fd: i32) -> bool {
    let Some(st) = stat(fd) else { return false };
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return false;
    }
    // SAFETY: plain host call.
    let access = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
    access != libc::O_WRONLY && crate::fs::host_path_of(fd).is_some()
}

/// Look at FIFO reader `fd` without blocking.
pub fn probe(fd: i32) -> Probe {
    let Some(st) = stat(fd) else { return Probe::Nothing };
    let id = identity(&st);
    if kept(|k| k.get(&fd).is_some_and(|(i, b)| *i == id && !b.is_empty())) {
        return Probe::Data;
    }
    let mut waiting: libc::c_int = 0;
    // SAFETY: a valid out-parameter.
    if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut waiting) } == 0 && waiting > 0 {
        return Probe::Data;
    }
    // SAFETY: plain host calls on the descriptor; the flags are put back.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags & libc::O_NONBLOCK == 0 {
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let mut b = 0u8;
    // SAFETY: a one-byte buffer.
    let n = unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) };
    let errno = crate::host::last_errno();
    if flags & libc::O_NONBLOCK == 0 {
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    }
    match n {
        0 => Probe::HungUp,
        1 => {
            kept(|k| {
                let e = k.entry(fd).or_insert((id, Vec::new()));
                if e.0 != id {
                    *e = (id, Vec::new());
                }
                e.1.push(b);
            });
            Probe::Data
        }
        _ if errno == libc::EAGAIN => Probe::Nothing,
        _ => Probe::Nothing,
    }
}

/// Whether a probe kept bytes of `fd` for its next read.
pub fn has_kept(fd: i32) -> bool {
    let Some(st) = stat(fd) else { return false };
    let id = identity(&st);
    kept(|k| k.get(&fd).is_some_and(|(i, b)| *i == id && !b.is_empty()))
}

/// A read of up to `len` bytes into guest `buf` from `fd`: the bytes a
/// probe took first, if it took any (`None` otherwise).
pub fn take(fd: i32, buf: u64, len: u64) -> Option<i64> {
    if KEPT.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_none_or(HashMap::is_empty) {
        return None;
    }
    let id = identity(&stat(fd)?);
    let bytes = kept(|k| {
        let (i, b) = k.get_mut(&fd)?;
        if *i != id {
            k.remove(&fd);
            return None;
        }
        let n = (len as usize).min(b.len());
        let out: Vec<u8> = b.drain(..n).collect();
        if b.is_empty() {
            k.remove(&fd);
        }
        Some(out)
    })?;
    if bytes.is_empty() && len > 0 {
        return None;
    }
    Some(match crate::uaccess::write_from(buf, &bytes) {
        Ok(()) => bytes.len() as i64,
        Err(e) => fwe_abi::err(e),
    })
}

/// `fd` was closed: what a probe kept of it goes.
pub fn closed(fd: i32) {
    if KEPT.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_none_or(HashMap::is_empty) {
        return;
    }
    kept(|k| k.remove(&fd));
}

/// How long a wait that watches FIFO readers sleeps between probes.
pub const SLICE_MS: i32 = 20;
