//! `SOCK_SEQPACKET` Unix sockets, which macOS lacks: each is a Unix stream
//! socket (a socketpair's end, or one made with `socket`, to bind, listen,
//! connect and accept with), marked ([`crate::fdmarks::Mark::SeqPacket`]),
//! whose messages are framed on the stream: a 4-byte length, then the
//! message. A send writes a whole frame (its descriptors passed with the
//! first byte); a receive takes one, cut to the buffer (`MSG_TRUNC`), the
//! rest of it dropped, as Linux keeps message boundaries. Everything else
//! is the stream's own: a peer that has gone reads end-of-file, a send to
//! it fails with `EPIPE`, and `poll` and `epoll` see both.

use crate::fdmarks::{self, Mark};
use crate::host::{self, last_error};
use fwe_abi::{err, errno};

/// The length a frame starts with.
const HEADER: usize = 4;

/// The largest message, as Linux's default socket buffer bounds one.
const MAX: usize = 212_992;

/// Whether `fd` is a `SOCK_SEQPACKET` socket of fwe's.
pub fn is(fd: i32) -> bool {
    fdmarks::any_marks() && fdmarks::marked(fd) == Some(Mark::SeqPacket)
}

fn nonblocking(fd: i32, host_flags: i32) -> bool {
    // SAFETY: plain host call.
    host_flags & libc::MSG_DONTWAIT != 0
        || unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0
}

/// Wait until `fd` can take a write (or has an error to report).
fn wait_writable(fd: i32) {
    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    // SAFETY: one valid pollfd.
    unsafe { libc::poll(&mut p, 1, -1) };
}

/// Send one message, the bytes of `iov` (host buffers), with the host
/// control data `control` (its descriptors), as Linux's `sendmsg` on a
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
    // A frame is never left half sent: the rest goes, waiting for room.
    let total = HEADER + len;
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
                    wait_writable(fd);
                    continue;
                }
                _ => return last_error(),
            }
        }
        sent += r;
    }
    len as i64
}

/// Read exactly `buf.len()` bytes (`peek`: look at them) from `fd`, the
/// host control data that comes with them into `control`. Returns how many
/// bytes there were (fewer at end-of-file), with the control length and
/// flags, or the host errno.
fn read_exact(
    fd: i32,
    buf: &mut [u8],
    control: (*mut libc::c_void, usize),
    peek: bool,
) -> Result<(usize, usize, i32), i32> {
    let mut got = 0;
    let (mut clen, mut cflags) = (0, 0);
    while got < buf.len() {
        let mut v =
            // SAFETY: within `buf`.
            libc::iovec { iov_base: unsafe { buf.as_mut_ptr().add(got) }.cast(), iov_len: buf.len() - got };
        // SAFETY: zeroed bytes are a valid `msghdr`, filled in below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut v;
        msg.msg_iovlen = 1;
        if got == 0 {
            msg.msg_control = control.0;
            msg.msg_controllen = control.1 as _;
        }
        let flags = libc::MSG_WAITALL | if peek { libc::MSG_PEEK } else { 0 };
        // SAFETY: a valid message header and buffers.
        let r = unsafe { libc::recvmsg(fd, &mut msg, flags) };
        if r < 0 {
            if host::last_errno() == libc::EINTR && got > 0 {
                continue;
            }
            return Err(host::last_errno());
        }
        if got == 0 {
            (clen, cflags) = (msg.msg_controllen as usize, msg.msg_flags);
        }
        if r == 0 {
            break;
        }
        if peek {
            // A peek sees the whole of what is there at once.
            return Ok((r as usize, clen, cflags));
        }
        got += r as usize;
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

/// Take one message into `iov` (host buffers), its descriptors into host
/// control buffer `control`, as Linux's `recvmsg` on a `SOCK_SEQPACKET`
/// socket. `linux_flags` are the guest's (`MSG_PEEK`, `MSG_TRUNC`,
/// `MSG_DONTWAIT`).
pub fn recv(
    fd: i32,
    iov: &[libc::iovec],
    control: (*mut libc::c_void, usize),
    linux_flags: u64,
    host_flags: i32,
) -> Received {
    use fwe_abi::socket::{MSG_PEEK, MSG_TRUNC};
    let fail = |e: i64| Received { result: e, controllen: 0, flags: 0 };
    let peek = linux_flags & MSG_PEEK != 0;
    if nonblocking(fd, host_flags) {
        // Only a whole frame is a message to take now.
        let mut header = [0u8; HEADER];
        // SAFETY: a valid buffer.
        let n = unsafe {
            libc::recv(fd, header.as_mut_ptr().cast(), HEADER, libc::MSG_PEEK | libc::MSG_DONTWAIT)
        };
        if n < 0 {
            return fail(last_error());
        }
        if n == 0 {
            return Received { result: 0, controllen: 0, flags: 0 };
        }
        let mut ready: libc::c_int = 0;
        // SAFETY: a valid out-parameter.
        unsafe { libc::ioctl(fd, libc::FIONREAD, &mut ready) };
        let need = HEADER + u32::from_le_bytes(header) as usize;
        if (n as usize) < HEADER || (ready as usize) < need {
            return fail(err(errno::EAGAIN));
        }
    }
    // The frame: its length (with the descriptors sent with it), then the
    // message.
    let mut header = [0u8; HEADER];
    let peeked;
    let (len, controllen, cflags) = if peek {
        let mut whole = vec![0u8; HEADER + MAX];
        let (n, cl, cf) = match read_exact(fd, &mut whole[..HEADER], control, true) {
            Ok(v) => v,
            Err(e) => return fail(err(host::errno_to_linux(e))),
        };
        if n == 0 {
            return Received { result: 0, controllen: 0, flags: 0 };
        }
        let len = u32::from_le_bytes(whole[..HEADER].try_into().unwrap()) as usize;
        let want = (HEADER + len).min(whole.len());
        whole.truncate(want);
        if let Err(e) = read_exact(fd, &mut whole, (std::ptr::null_mut(), 0), true) {
            return fail(err(host::errno_to_linux(e)));
        }
        peeked = whole;
        (len, cl, cf)
    } else {
        let (n, cl, cf) = match read_exact(fd, &mut header, control, false) {
            Ok(v) => v,
            Err(e) => return fail(err(host::errno_to_linux(e))),
        };
        if n == 0 {
            return Received { result: 0, controllen: 0, flags: 0 };
        }
        peeked = Vec::new();
        (u32::from_le_bytes(header) as usize, cl, cf)
    };
    let body: Vec<u8> = if peek {
        peeked[HEADER..].to_vec()
    } else {
        let mut b = vec![0u8; len];
        match read_exact(fd, &mut b, (std::ptr::null_mut(), 0), false) {
            Ok((n, _, _)) => b.truncate(n),
            Err(e) => return fail(err(host::errno_to_linux(e))),
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
        // SAFETY: the caller's buffer spans `iov_len` bytes.
        unsafe { std::ptr::copy_nonoverlapping(body[at..].as_ptr(), v.iov_base.cast(), n) };
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
