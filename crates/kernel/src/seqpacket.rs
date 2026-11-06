//! `SOCK_SEQPACKET` Unix sockets, which macOS lacks: each is a Unix stream
//! socket (a socketpair's end, or one made with `socket`, to bind, listen,
//! connect and accept with), marked ([`crate::fdmarks::Mark::SeqPacket`]),
//! whose messages are framed on the stream: a 4-byte length, then the
//! message. A send writes a whole frame or none (its descriptors passed
//! with the first byte); a receive takes one, cut to the buffer
//! (`MSG_TRUNC`), the rest of it dropped, as Linux keeps message
//! boundaries. Everything else is the stream's own: a peer that has gone
//! reads end-of-file, a send to it fails with `EPIPE`, and `poll` and
//! `epoll` see both.
//!
//! - The socket's buffers are made big enough for two of the largest
//!   messages, and their size, which any process can read back, marks it,
//!   so one received with `SCM_RIGHTS` is known for what it is ([`adopt`]).
//! - A message is sent, or taken, under the socket's lock for that
//!   direction: a mutex for the threads of a process, and between
//!   processes that share the socket a byte-range lock on a file of fwe's
//!   ([`Exclusive`]), so that no two interleave or split a frame.

use crate::fdmarks::{self, Mark};
use crate::host::{self, last_error};
use fwe_abi::{err, errno};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The length a frame starts with.
const HEADER: usize = 4;

/// The largest message, as Linux's default socket buffer bounds one.
const MAX: usize = 212_992;

/// The size of a seqpacket socket's buffers: room for two whole frames,
/// and an odd number no one else asks for, which marks the socket.
const BUFFER: i32 = 2 * (HEADER + MAX) as i32 + 1;

/// Whether `fd` is a `SOCK_SEQPACKET` socket of fwe's.
pub fn is(fd: i32) -> bool {
    fdmarks::any_marks() && fdmarks::marked(fd) == Some(Mark::SeqPacket)
}

fn sockopt(fd: i32, opt: i32) -> i32 {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid out-parameters.
    unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, opt, (&mut v as *mut libc::c_int).cast(), &mut len)
    };
    v
}

fn set_sockopt(fd: i32, opt: i32, v: i32) {
    // SAFETY: a valid in-parameter.
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&v as *const i32).cast(), 4);
    }
}

/// Make stream socket `fd` a `SOCK_SEQPACKET` one: mark it and size its
/// buffers.
pub fn make(fd: i32) {
    set_sockopt(fd, libc::SO_SNDBUF, BUFFER);
    set_sockopt(fd, libc::SO_RCVBUF, BUFFER);
    fdmarks::mark(fd, Mark::SeqPacket);
}

/// A descriptor received with `SCM_RIGHTS`: if it is a `SOCK_SEQPACKET`
/// socket of fwe's (its buffers say so), mark it here too.
pub fn adopt(fd: i32) {
    if sockopt(fd, libc::SO_TYPE) == libc::SOCK_STREAM && sockopt(fd, libc::SO_RCVBUF) == BUFFER {
        fdmarks::mark(fd, Mark::SeqPacket);
    }
}

/// Each socket's lock (by inode), which a thread holds while it takes a
/// whole message, or sends one.
static LOCKS: Mutex<BTreeMap<u64, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// Run a host `fork` (see [`crate::fork_locked`]) with the table of locks
/// held; in the child, the sockets' locks are new: one a thread of the
/// parent held (blocked in a receive, say) has no holder there.
pub(crate) fn hold(fork: impl FnOnce() -> libc::pid_t) -> libc::pid_t {
    let mut locks = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    let pid = fork();
    if pid == 0 {
        locks.clear();
    }
    pid
}

/// Which way a lock is for.
#[derive(Clone, Copy)]
enum Way {
    Receive = 0,
    Send = 1,
}

/// The file whose bytes stand for the sockets' locks between processes:
/// `v<format>-seqpacket.lock` in fwe's private directory, open for the
/// life of the process.
fn lock_file() -> Option<i32> {
    // Opened once, under a lock: a second descriptor of the file, closed,
    // would drop every byte-range lock this process holds on it.
    static FD: Mutex<i32> = Mutex::new(-1);
    let mut fd = FD.lock().unwrap_or_else(|e| e.into_inner());
    if *fd >= 0 {
        return Some(*fd);
    }
    let mut path = crate::fs::shm::user_dir().ok()?;
    path.extend_from_slice(format!("/v{}-seqpacket.lock", crate::shared::FORMAT).as_bytes());
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: a NUL-terminated path in fwe's private directory.
    let raw =
        unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600) };
    // No lock is held on the file yet, so `reserve` closing `raw` loses none.
    *fd = crate::fdtable::reserve(raw).ok()?;
    Some(*fd)
}

/// A socket's lock for one way held between processes: a write lock on
/// one byte of [`lock_file`] (byte-range locks are a process's, so the
/// threads of one take the mutex first). Released when dropped.
struct Exclusive {
    file: i32,
    at: i64,
}

impl Exclusive {
    /// Take the lock of socket `fd` for `way`, waiting for it unless
    /// `nonblock`: `EAGAIN` if another process holds it and `nonblock`,
    /// `EINTR` if a signal came first. `None` where fwe has no lock file
    /// (the threads' mutex is then all).
    fn take(fd: i32, way: Way, nonblock: bool) -> Result<Option<Exclusive>, i32> {
        let Some(file) = lock_file() else { return Ok(None) };
        // A byte for each way of each socket (its inode, kept within the
        // offsets a file has; two that meet only wait for each other).
        let at = ((inode(fd) % (1 << 40)) * 2 + way as u64) as i64;
        let mut fl = lock_range(at, libc::F_WRLCK);
        let cmd = if nonblock { libc::F_SETLK } else { libc::F_SETLKW };
        // SAFETY: a valid lock description on fwe's own file.
        if unsafe { libc::fcntl(file, cmd, &mut fl) } == 0 {
            return Ok(Some(Exclusive { file, at }));
        }
        match host::last_errno() {
            libc::EAGAIN | libc::EACCES => Err(errno::EAGAIN),
            libc::EINTR => Err(errno::EINTR),
            _ => Ok(None),
        }
    }
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        let mut fl = lock_range(self.at, libc::F_UNLCK);
        // SAFETY: a valid lock description on fwe's own file.
        unsafe { libc::fcntl(self.file, libc::F_SETLK, &mut fl) };
    }
}

fn lock_range(at: i64, kind: impl Into<i32>) -> libc::flock {
    // SAFETY: zeroed bytes are a valid `flock`, filled in below.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = kind.into() as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = at as _;
    fl.l_len = 1;
    fl
}

/// The inode number of socket `fd`, which names it to every process.
#[allow(clippy::unnecessary_cast)] // `ino_t` differs by host
fn inode(fd: i32) -> u64 {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) };
    st.st_ino as u64
}

fn lock_of(fd: i32) -> Arc<Mutex<()>> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) };
    let mut locks = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    // Those of sockets no thread is using go.
    locks.retain(|_, l| Arc::strong_count(l) > 1);
    locks.entry(st.st_ino as u64).or_default().clone()
}

fn nonblocking(fd: i32, host_flags: i32) -> bool {
    // SAFETY: plain host call.
    host_flags & libc::MSG_DONTWAIT != 0
        || unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0
}

/// Wait until `fd` is ready for `events`; `Err` when a signal came first.
fn wait(fd: i32, events: i16) -> Result<(), ()> {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: one valid pollfd.
    if unsafe { libc::poll(&mut p, 1, -1) } < 0 { Err(()) } else { Ok(()) }
}

/// Whether the peer of `fd` has room for `need` more bytes now: what
/// `POLLOUT` says with the low-water mark at `need`.
fn has_room(fd: i32, need: usize) -> bool {
    let old = sockopt(fd, libc::SO_SNDLOWAT);
    set_sockopt(fd, libc::SO_SNDLOWAT, need as i32);
    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    // SAFETY: one valid pollfd; no wait.
    unsafe { libc::poll(&mut p, 1, 0) };
    set_sockopt(fd, libc::SO_SNDLOWAT, old.max(1));
    p.revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
}

/// Send one message, the bytes of `iov` (host buffers, checked), with the
/// host control data `control` (its descriptors), as Linux's `sendmsg` on a
/// `SOCK_SEQPACKET` socket: whole, or not at all. Returns the message's
/// length, or a raw Linux error.
pub fn send(
    fd: i32,
    iov: &[libc::iovec],
    control: (*mut libc::c_void, usize),
    host_flags: i32,
) -> i64 {
    let len: usize = iov.iter().map(|v| v.iov_len).sum();
    if len > MAX {
        return err(errno::EMSGSIZE);
    }
    let nonblock = nonblocking(fd, host_flags);
    let lock = lock_of(fd);
    let _held = if nonblock {
        match lock.try_lock() {
            Ok(g) => g,
            Err(_) => return err(errno::EAGAIN),
        }
    } else {
        lock.lock().unwrap_or_else(|e| e.into_inner())
    };
    let _between = match Exclusive::take(fd, Way::Send, nonblock) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let total = HEADER + len;
    if nonblock && !has_room(fd, total) {
        return err(errno::EAGAIN);
    }
    let header = (len as u32).to_le_bytes();
    let mut frame = vec![libc::iovec { iov_base: header.as_ptr() as *mut _, iov_len: HEADER }];
    frame.extend_from_slice(iov);
    // SAFETY: zeroed bytes are a valid `msghdr`, filled in below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = frame.as_mut_ptr();
    msg.msg_iovlen = frame.len() as _;
    msg.msg_control = control.0;
    msg.msg_controllen = control.1 as _;
    // SAFETY: the message references the header and the caller's buffers.
    let mut sent = unsafe { libc::sendmsg(fd, &msg, host_flags) };
    if sent < 0 {
        return last_error();
    }
    // A frame is never left half sent: the rest goes, waiting for room
    // (only a blocking send gets here with any of it left).
    while (sent as usize) < total {
        let mut skip = sent as usize;
        let rest: Vec<libc::iovec> = frame
            .iter()
            .filter_map(|v| {
                if skip >= v.iov_len {
                    skip -= v.iov_len;
                    return None;
                }
                let part = libc::iovec {
                    // SAFETY: within the buffer.
                    iov_base: unsafe { v.iov_base.cast::<u8>().add(skip) }.cast(),
                    iov_len: v.iov_len - skip,
                };
                skip = 0;
                Some(part)
            })
            .collect();
        // SAFETY: the rest of the same buffers.
        let r = unsafe { libc::writev(fd, rest.as_ptr(), rest.len() as i32) };
        if r < 0 {
            match host::last_errno() {
                libc::EINTR => continue,
                libc::EAGAIN => {
                    let _ = wait(fd, libc::POLLOUT);
                    continue;
                }
                _ => return last_error(),
            }
        }
        sent += r;
    }
    len as i64
}

/// Read `buf.len()` bytes from `fd`, or with `peek` look at them, the host
/// control data that comes with the first into `control`. `committed`
/// says a frame is begun, so neither an interruption nor a lull ends the
/// read. Returns how many bytes there were (fewer at end-of-file), the
/// control length and flags, or the host errno.
fn read_exact(
    fd: i32,
    buf: &mut [u8],
    control: (*mut libc::c_void, usize),
    peek: bool,
    committed: bool,
) -> Result<(usize, usize, i32), i32> {
    let mut got = 0;
    let (mut clen, mut cflags) = (0, 0);
    while got < buf.len() {
        // A peek sees what is there from the start each time.
        let at = if peek { 0 } else { got };
        let mut v = libc::iovec {
            // SAFETY: within `buf`.
            iov_base: unsafe { buf.as_mut_ptr().add(at) }.cast(),
            iov_len: buf.len() - at,
        };
        // SAFETY: zeroed bytes are a valid `msghdr`, filled in below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut v;
        msg.msg_iovlen = 1;
        if got == 0 && !control.0.is_null() {
            msg.msg_control = control.0;
            msg.msg_controllen = control.1 as _;
        }
        let flags = libc::MSG_WAITALL | if peek { libc::MSG_PEEK } else { 0 };
        // SAFETY: a valid message header and buffers.
        let r = unsafe { libc::recvmsg(fd, &mut msg, flags) };
        if r < 0 {
            let e = host::last_errno();
            let begun = got > 0 || committed;
            if begun && e == libc::EINTR {
                continue;
            }
            if begun && e == libc::EAGAIN {
                // The rest of a frame begun is on its way.
                let _ = wait(fd, libc::POLLIN);
                continue;
            }
            return Err(e);
        }
        if got == 0 && msg.msg_controllen != 0 {
            (clen, cflags) = (msg.msg_controllen as usize, msg.msg_flags);
        }
        if r == 0 {
            break;
        }
        if !peek {
            got += r as usize;
            continue;
        }
        got = r as usize;
        if got < buf.len() && wait(fd, libc::POLLIN).is_err() && !committed {
            // Not all of it is there yet, and a signal came first.
            return Err(libc::EINTR);
        }
    }
    Ok((got, clen, cflags))
}

/// What [`recv`] took: the bytes given (or the message's length, with
/// `MSG_TRUNC`), and the control length and host message flags for the
/// guest's `msghdr`.
pub struct Received {
    pub result: i64,
    pub controllen: usize,
    pub flags: i32,
}

/// Take one message into `iov` (host buffers, checked), its descriptors
/// into host control buffer `control`, as Linux's `recvmsg` on a
/// `SOCK_SEQPACKET` socket. `linux_flags` are the guest's (`MSG_PEEK`,
/// `MSG_TRUNC`, `MSG_DONTWAIT`).
pub fn recv(
    fd: i32,
    iov: &[libc::iovec],
    control: (*mut libc::c_void, usize),
    linux_flags: u64,
    host_flags: i32,
) -> Received {
    use fwe_abi::socket::{MSG_PEEK, MSG_TRUNC};
    let fail = |e: i64| Received { result: e, controllen: 0, flags: 0 };
    let eof = || Received { result: 0, controllen: 0, flags: 0 };
    let as_err = |e: i32| fail(err(host::errno_to_linux(e)));
    let peek = linux_flags & MSG_PEEK != 0;
    let nonblock = nonblocking(fd, host_flags);
    let lock = lock_of(fd);
    let _held = if nonblock {
        match lock.try_lock() {
            Ok(g) => g,
            Err(_) => return fail(err(errno::EAGAIN)),
        }
    } else {
        lock.lock().unwrap_or_else(|e| e.into_inner())
    };
    let _between = match Exclusive::take(fd, Way::Receive, nonblock) {
        Ok(x) => x,
        Err(e) => return fail(err(e)),
    };
    let mut header = [0u8; HEADER];
    if nonblock {
        // Only a whole frame is a message to take now.
        // SAFETY: a valid buffer.
        let n = unsafe {
            libc::recv(fd, header.as_mut_ptr().cast(), HEADER, libc::MSG_PEEK | libc::MSG_DONTWAIT)
        };
        if n < 0 {
            return fail(last_error());
        }
        if n == 0 {
            return eof();
        }
        let mut ready: libc::c_int = 0;
        // SAFETY: a valid out-parameter.
        unsafe { libc::ioctl(fd, libc::FIONREAD, &mut ready) };
        let len = u32::from_le_bytes(header) as usize;
        if len <= MAX && ((n as usize) < HEADER || (ready as usize) < HEADER + len) {
            return fail(err(errno::EAGAIN));
        }
    }
    // The frame's length (and the descriptors sent with it).
    let (len, controllen, cflags) = match read_exact(fd, &mut header, control, peek, false) {
        Ok((n, ..)) if n < HEADER => return eof(),
        Ok((_, cl, cf)) => (u32::from_le_bytes(header) as usize, cl, cf),
        Err(e) => return as_err(e),
    };
    if len > MAX {
        // Not a frame of fwe's: what the stream holds cannot be read as
        // messages.
        return fail(err(errno::EIO));
    }
    let body: Vec<u8> = if peek {
        let mut whole = vec![0u8; HEADER + len];
        match read_exact(fd, &mut whole, (std::ptr::null_mut(), 0), true, false) {
            Ok((n, ..)) => whole.truncate(n),
            Err(e) => return as_err(e),
        }
        whole.split_off(HEADER.min(whole.len()))
    } else {
        let mut b = vec![0u8; len];
        match read_exact(fd, &mut b, (std::ptr::null_mut(), 0), false, true) {
            Ok((n, ..)) => b.truncate(n),
            Err(e) => return as_err(e),
        }
        b
    };
    // Into the caller's buffers, as much as fits.
    let mut at = 0;
    for v in iov {
        if at >= body.len() {
            break;
        }
        let n = v.iov_len.min(body.len() - at);
        if crate::uaccess::write_host(v.iov_base as u64, &body[at..at + n]).is_err() {
            return fail(err(errno::EFAULT));
        }
        at += n;
    }
    let truncated = at < len;
    let mut flags = cflags & libc::MSG_CTRUNC;
    if truncated {
        flags |= libc::MSG_TRUNC;
    }
    let result = if truncated && linux_flags & MSG_TRUNC != 0 { len } else { at };
    Received { result: result as i64, controllen, flags }
}

/// `read`/`readv` of a `SOCK_SEQPACKET` socket: one message.
pub fn read(fd: i32, iov: &[libc::iovec]) -> i64 {
    recv(fd, iov, (std::ptr::null_mut(), 0), 0, 0).result
}

/// `write`/`writev` of a `SOCK_SEQPACKET` socket: one message.
pub fn write(fd: i32, iov: &[libc::iovec]) -> i64 {
    send(fd, iov, (std::ptr::null_mut(), 0), 0)
}
