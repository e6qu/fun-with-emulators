//! `splice`, `tee` and `vmsplice`: moving data into, out of and between
//! pipes.
//!
//! Linux moves pipe buffers' pages; fwe's pipes are the host's, so it
//! copies, through a buffer of its own, as much as Linux would move: from
//! a pipe, what it holds (waiting for some unless asked not to); into a
//! pipe, what room it has (likewise), so a copy never blocks halfway with
//! data read and not yet written. A file, socket, device or loop device on
//! the other side is read and written as the guest's `read` and `write`
//! would ([`read_from`], [`write_to`]).
//!
//! `tee` copies a pipe's data without taking it. A host pipe cannot be
//! read without taking what is read, so fwe takes it all and puts it back
//! through a write end of the same pipe the process holds; without one,
//! `tee` fails with `EINVAL`.

use crate::host::{errno_to_linux, last_errno};
use crate::uaccess;
use fwe_abi::{err, errno};

/// `SPLICE_F_*`.
const SPLICE_F_NONBLOCK: u64 = 2;
const SPLICE_F_ALL: u64 = 0xf;
/// What one host pipe holds at most.
const HOST_PIPE: u64 = 65_536;
/// The most copied at a time.
const CHUNK: usize = 1 << 16;

fn last() -> i32 {
    errno_to_linux(last_errno())
}

/// What a descriptor is, as splicing sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Pipe,
    /// A regular file (a memfd, a synthetic file's content).
    File,
    Socket,
    /// A host character device (`/dev/null`, `zero`, `full`, `random`,
    /// `urandom`, `tty`).
    Char,
    /// A loop device.
    Block,
    /// Anything that neither reads nor writes for splicing: a directory, an
    /// event descriptor, an epoll instance and the like.
    Other,
}

/// What guest descriptor `fd` is, and whether it is open to read and to
/// write (`EBADF` if it is not open).
fn kind(fd: i32) -> Result<(Kind, bool, bool, i32), i32> {
    if fd < 0 || !crate::fdtable::guest_visible(fd) {
        return Err(errno::EBADF);
    }
    // SAFETY: plain host call on the guest's descriptor.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(errno::EBADF);
    }
    let (reads, writes) = match fl & libc::O_ACCMODE {
        libc::O_RDONLY => (true, false),
        libc::O_WRONLY => (false, true),
        _ => (true, true),
    };
    if crate::loopdev::device_of(fd).is_some() {
        return Ok((Kind::Block, reads, writes, fl));
    }
    let special = crate::loopdev::is_control(fd)
        || crate::specialfd::anon_name(fd).is_some()
        || crate::signalfd::is_signalfd(fd)
        || crate::bpf::is_bpf_fd(fd)
        || crate::synthdir::path_of(fd).is_some()
        || crate::netlink::is(fd)
        || matches!(
            crate::fdmarks::any_marks().then(|| crate::fdmarks::marked(fd)).flatten(),
            Some(
                crate::fdmarks::Mark::Mq
                    | crate::fdmarks::Mark::FsContext(_)
                    | crate::fdmarks::Mark::Ns(_)
                    | crate::fdmarks::Mark::Inotify(_)
                    | crate::fdmarks::Mark::Pid { .. }
            )
        );
    if special {
        return Ok((Kind::Other, reads, writes, fl));
    }
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(errno::EBADF);
    }
    let k = match st.st_mode & libc::S_IFMT {
        // A pipe, or a named FIFO; not a kqueue (an epoll descriptor),
        // which the host also reports as a FIFO.
        libc::S_IFIFO if pipe_ends(fd).is_some() || crate::fs::host_path_of(fd).is_some() => {
            Kind::Pipe
        }
        libc::S_IFREG => Kind::File,
        libc::S_IFSOCK => Kind::Socket,
        libc::S_IFCHR => Kind::Char,
        _ => Kind::Other,
    };
    Ok((k, reads, writes, fl))
}

/// A pipe end's identity and its other end's, as the host knows them.
pub(crate) fn pipe_ends(fd: i32) -> Option<(u64, u64)> {
    #[cfg(target_os = "macos")]
    {
        // `struct pipe_fdinfo` (184 bytes): the pipe's handle at 160, its
        // peer's at 168.
        const PROC_PIDFDPIPEINFO: i32 = 6;
        let mut info = [0u8; 184];
        // SAFETY: a valid out-buffer of its size.
        let n = unsafe {
            libc::proc_pidfdinfo(
                libc::getpid(),
                fd,
                PROC_PIDFDPIPEINFO,
                info.as_mut_ptr().cast(),
                info.len() as i32,
            )
        };
        if n as usize != info.len() {
            return None;
        }
        let word = |at: usize| u64::from_ne_bytes(info[at..at + 8].try_into().unwrap());
        Some((word(160), word(168)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        None
    }
}

/// Whether pipe ends `a` and `b` are of one pipe.
fn same_pipe(a: i32, b: i32) -> bool {
    match (pipe_ends(a), pipe_ends(b)) {
        (Some((ah, ap)), Some((bh, _))) => ah == bh || ap == bh,
        _ => false,
    }
}

/// What a pipe end's pipe holds now: the host's `st_size` of either end
/// (`FIONREAD` counts it only at the read end).
pub(crate) fn held(fd: i32) -> u64 {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) };
    st.st_size.max(0) as u64
}

/// The room a pipe's write end `fd` has: its capacity (as set, at most
/// what a host pipe takes) less what it holds.
pub(crate) fn room(fd: i32) -> u64 {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) };
    let capacity = crate::fdstate::pipe_size((st.st_dev as u64, st.st_ino)).min(HOST_PIPE);
    capacity.saturating_sub(st.st_size.max(0) as u64)
}

/// Wait until `fd` is ready for `events` (`EAGAIN` if `nonblock`, `EINTR`
/// for a signal).
fn ready(fd: i32, events: i16, nonblock: bool) -> Result<(), i32> {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: one pollfd.
    let n = unsafe { libc::poll(&mut p, 1, if nonblock { 0 } else { -1 }) };
    match n {
        n if n < 0 => Err(last()),
        0 => Err(errno::EAGAIN),
        _ => Ok(()),
    }
}

/// Wait for data in the pipe read end `fd`: `Ok(false)` if there will be
/// none (no writer is left).
fn wait_data(fd: i32, nonblock: bool) -> Result<bool, i32> {
    loop {
        if held(fd) > 0 {
            return Ok(true);
        }
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd, without waiting.
        let n = unsafe { libc::poll(&mut p, 1, 0) };
        if n > 0 && held(fd) == 0 {
            // Readable with nothing in it: no writer is left.
            return Ok(false);
        }
        ready(fd, libc::POLLIN, nonblock)?;
    }
}

/// Wait for room in the pipe write end `fd`: how much there is.
fn wait_room(fd: i32, nonblock: bool) -> Result<u64, i32> {
    loop {
        let r = room(fd);
        if r > 0 {
            return Ok(r);
        }
        ready(fd, libc::POLLOUT, nonblock)?;
    }
}

/// Read up to `buf.len()` bytes of `fd`, of kind `k`, at `pos` or its
/// position, as the guest's `read` would.
fn read_from(fd: i32, k: Kind, buf: &mut [u8], pos: Option<u64>) -> Result<usize, i32> {
    if k == Kind::Block {
        let r = crate::loopdev::read_into(fd, buf, pos).unwrap_or(err(errno::EBADF));
        return if r < 0 { Err(-r as i32) } else { Ok(r as usize) };
    }
    let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    if crate::seqpacket::is(fd) {
        let r = crate::seqpacket::read(fd, &[iov]);
        return if r < 0 { Err(-r as i32) } else { Ok(r as usize) };
    }
    // SAFETY: `buf` is fwe's, of its length.
    let n = unsafe {
        match pos {
            Some(p) => libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), p as libc::off_t),
            None => libc::read(fd, buf.as_mut_ptr().cast(), buf.len()),
        }
    };
    let r = if n < 0 { err(last()) } else { n as i64 };
    let r = crate::net::linux_read_error(fwe_abi::nr::READ, fd, r);
    if r < 0 { Err(-r as i32) } else { Ok(r as usize) }
}

/// Write `buf` to `fd`, of kind `k`, at `pos` or its position, as the
/// guest's `write` would: what was written.
fn write_to(fd: i32, k: Kind, buf: &[u8], pos: Option<u64>) -> Result<usize, i32> {
    use fwe_abi::nr;
    if k == Kind::Block {
        let r = crate::loopdev::write_at_pos(fd, buf, pos).unwrap_or(err(errno::EBADF));
        return if r < 0 { Err(-r as i32) } else { Ok(r as usize) };
    }
    let iov = libc::iovec { iov_base: buf.as_ptr() as *mut _, iov_len: buf.len() };
    let r = if let Some(r) =
        crate::specialwrite::write(fd, crate::specialwrite::Source::Host(&[iov]), buf.len() as u64)
    {
        r
    } else if crate::seqpacket::is(fd) {
        crate::seqpacket::write(fd, &[iov])
    } else {
        // SAFETY: `buf` is fwe's, of its length.
        let n = unsafe {
            match pos {
                Some(p) => libc::pwrite(fd, buf.as_ptr().cast(), buf.len(), p as libc::off_t),
                None => libc::write(fd, buf.as_ptr().cast(), buf.len()),
            }
        };
        if n < 0 { err(last()) } else { n as i64 }
    };
    // What Linux reports where the host differs: `/dev/full`, a sealed
    // memfd, a closed peer's `SIGPIPE`.
    let r = crate::linux_result(nr::WRITE, &[fd as u64, 0, buf.len() as u64, 0, 0, 0], r);
    if r < 0 { Err(-r as i32) } else { Ok(r as usize) }
}

/// The offset a guest pointer `ptr` holds, if it is not null (`EINVAL` if
/// negative).
fn offset_at(ptr: u64) -> Result<Option<u64>, i32> {
    if ptr == 0 {
        return Ok(None);
    }
    let off: i64 = uaccess::read(ptr)?;
    if off < 0 {
        return Err(errno::EINVAL);
    }
    Ok(Some(off as u64))
}

/// `splice(fd_in, off_in, fd_out, off_out, len, flags)`.
pub fn splice(fd_in: i32, off_in: u64, fd_out: i32, off_out: u64, len: u64, flags: u64) -> i64 {
    match splice_inner(fd_in, off_in, fd_out, off_out, len, flags) {
        Ok(n) => n as i64,
        Err(e) => err(e),
    }
}

fn splice_inner(
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    len: u64,
    flags: u64,
) -> Result<u64, i32> {
    if len == 0 {
        return Ok(0);
    }
    if flags & !SPLICE_F_ALL != 0 {
        return Err(errno::EINVAL);
    }
    let (ki, reads, _, fl_in) = kind(fd_in)?;
    let (ko, _, writes, fl_out) = kind(fd_out)?;
    // In Linux's order: an offset for a pipe, the offsets themselves, then
    // whether each end is open for its part.
    if (ki == Kind::Pipe && off_in != 0) || (ko == Kind::Pipe && off_out != 0) {
        return Err(errno::ESPIPE);
    }
    let pos_out = offset_at(off_out)?;
    let pos_in = offset_at(off_in)?;
    if !reads || !writes {
        return Err(errno::EBADF);
    }
    let nonblock_of = |fl: i32| flags & SPLICE_F_NONBLOCK != 0 || fl & libc::O_NONBLOCK != 0;
    match (ki == Kind::Pipe, ko == Kind::Pipe) {
        (true, true) => {
            if same_pipe(fd_in, fd_out) {
                return Err(errno::EINVAL);
            }
            let nonblock = nonblock_of(fl_in | fl_out);
            from_pipe(fd_in, nonblock, fd_out, Kind::Pipe, nonblock, None, len)
        }
        (true, false) => {
            if pos_out.is_some() && !matches!(ko, Kind::File | Kind::Block) {
                return Err(errno::EINVAL);
            }
            if fl_out & libc::O_APPEND != 0 {
                return Err(errno::EINVAL);
            }
            if !matches!(ko, Kind::File | Kind::Block | Kind::Socket | Kind::Char) {
                return Err(errno::EINVAL);
            }
            let socket_nonblock = flags & SPLICE_F_NONBLOCK != 0 && ko == Kind::Socket;
            let w =
                from_pipe(fd_in, nonblock_of(fl_in), fd_out, ko, socket_nonblock, pos_out, len)?;
            if let Some(p) = pos_out {
                uaccess::write(off_out, (p + w) as i64)?;
            }
            Ok(w)
        }
        (false, true) => {
            if pos_in.is_some() && !matches!(ki, Kind::File | Kind::Block) {
                return Err(errno::EINVAL);
            }
            if !matches!(ki, Kind::File | Kind::Block | Kind::Socket | Kind::Char) {
                return Err(errno::EINVAL);
            }
            if hung_up(fd_out) {
                return Err(broken_pipe());
            }
            // What the pipe has room for, which a write of it fills
            // without blocking or coming up short.
            let room = wait_room(fd_out, nonblock_of(fl_out))?;
            let want = len.min(room).min(CHUNK as u64) as usize;
            let mut buf = vec![0u8; want];
            let n = read_from(fd_in, ki, &mut buf, pos_in)?;
            let w = write_to(fd_out, Kind::Pipe, &buf[..n], None)?;
            if let Some(p) = pos_in {
                uaccess::write(off_in, (p + w as u64) as i64)?;
            }
            Ok(w as u64)
        }
        (false, false) => Err(errno::EINVAL),
    }
}

/// A write end of the pipe whose read end is `fd`, among the process's
/// descriptors.
fn write_end_of(fd: i32) -> Option<i32> {
    let (_, peer) = pipe_ends(fd)?;
    crate::fdtable::open_fds().into_iter().find(|&f| pipe_ends(f).is_some_and(|(h, _)| h == peer))
}

/// Whether a pipe's write end, or a socket, `fd` has no one left to read
/// it.
fn hung_up(fd: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    // SAFETY: one pollfd, without waiting.
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & (libc::POLLHUP | libc::POLLERR) != 0 }
}

/// A write to a pipe or socket with no reader: `EPIPE`, and `SIGPIPE` for
/// the process, as Linux sends them before taking anything.
fn broken_pipe() -> i32 {
    crate::signal::raise_self(fwe_abi::signal::SIGPIPE);
    errno::EPIPE
}

/// The least a socket that `poll` reports writable takes without blocking.
fn socket_low_water(fd: i32) -> u64 {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid out-parameters.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDLOWAT,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    v.max(1) as u64
}

/// Up to `len` bytes of pipe `fd_in` written to `fd_out` (of kind `ko`, at
/// `pos` or its position), taking from the pipe only what was written, as
/// Linux does: the pipe cannot be read without taking what is read, so
/// with a write end of it at hand, all it holds is taken and what was not
/// written put back in order; without one, no more than the output takes
/// now (a pipe's room; a socket asked not to wait, its low-water mark) or,
/// for an output a write fills (a file, a device, a waiting socket), what
/// is asked for.
fn from_pipe(
    fd_in: i32,
    nonblock_in: bool,
    fd_out: i32,
    ko: Kind,
    nonblock_out: bool,
    pos: Option<u64>,
    len: u64,
) -> Result<u64, i32> {
    if matches!(ko, Kind::Pipe | Kind::Socket) && hung_up(fd_out) {
        return Err(broken_pipe());
    }
    if !wait_data(fd_in, nonblock_in)? {
        return Ok(0);
    }
    let cap = match ko {
        Kind::Pipe => wait_room(fd_out, nonblock_out)?,
        Kind::Socket if nonblock_out => {
            ready(fd_out, libc::POLLOUT, true)?;
            socket_low_water(fd_out)
        }
        _ => u64::MAX,
    };
    let back = write_end_of(fd_in);
    let take = match back {
        Some(_) => held(fd_in),
        None => len.min(held(fd_in)).min(cap),
    };
    let mut buf = vec![0u8; take.min(CHUNK as u64) as usize];
    let n = read_from(fd_in, Kind::Pipe, &mut buf, None)?;
    let want = (len.min(cap) as usize).min(n);
    let w = write_to(fd_out, ko, &buf[..want], pos);
    if let Some(b) = back {
        let mut put = *w.as_ref().unwrap_or(&0);
        while put < n {
            put += write_to(b, Kind::Pipe, &buf[put..n], None)?;
        }
    }
    w.map(|w| w as u64)
}

/// `tee(fd_in, fd_out, len, flags)`: up to `len` bytes of pipe `fd_in`
/// copied into pipe `fd_out`, and left in `fd_in`.
pub fn tee(fd_in: i32, fd_out: i32, len: u64, flags: u64) -> i64 {
    let r = (|| {
        if flags & !SPLICE_F_ALL != 0 {
            return Err(errno::EINVAL);
        }
        if len == 0 {
            return Ok(0);
        }
        let (ki, reads, _, fl_in) = kind(fd_in)?;
        let (ko, _, writes, fl_out) = kind(fd_out)?;
        if !reads || !writes {
            return Err(errno::EBADF);
        }
        if ki != Kind::Pipe || ko != Kind::Pipe || same_pipe(fd_in, fd_out) {
            return Err(errno::EINVAL);
        }
        // The input pipe's write end, to put back what is read.
        let back = write_end_of(fd_in).ok_or(errno::EINVAL)?;
        let nonblock = flags & SPLICE_F_NONBLOCK != 0 || (fl_in | fl_out) & libc::O_NONBLOCK != 0;
        if !wait_data(fd_in, nonblock)? {
            return Ok(0);
        }
        let room = wait_room(fd_out, nonblock)?;
        // All of it, so what goes back keeps its order.
        let mut buf = vec![0u8; held(fd_in) as usize];
        let n = read_from(fd_in, Kind::Pipe, &mut buf, None)?;
        let buf = &buf[..n];
        let want = (len.min(room) as usize).min(n);
        let w = write_to(fd_out, Kind::Pipe, &buf[..want], None);
        let mut put = 0;
        while put < n {
            put += write_to(back, Kind::Pipe, &buf[put..], None)?;
        }
        w.map(|w| w as u64)
    })();
    match r {
        Ok(n) => n as i64,
        Err(e) => err(e),
    }
}

/// `vmsplice(fd, iov, nr_segs, flags)`: the guest's buffers into pipe
/// `fd` (its write end), or out of it into them (its read end).
pub fn vmsplice(fd: i32, iov: u64, nr_segs: u64, flags: u64) -> i64 {
    let r = (|| {
        if flags & !SPLICE_F_ALL != 0 {
            return Err(errno::EINVAL);
        }
        let (k, reads, writes, fl) = kind(fd)?;
        let to_pipe = writes;
        if !reads && !writes {
            return Err(errno::EBADF);
        }
        let bufs = uaccess::host_iovecs(iov, nr_segs, !to_pipe)?;
        // Nothing to move is done before the descriptor is looked at.
        let total: u64 = bufs.iter().map(|v| v.iov_len as u64).sum();
        if total == 0 {
            return Ok(0);
        }
        if k != Kind::Pipe {
            return Err(errno::EBADF);
        }
        let nonblock = flags & SPLICE_F_NONBLOCK != 0 || fl & libc::O_NONBLOCK != 0;
        // How much moves: what there is room for, or what the pipe holds.
        let mut left = if to_pipe {
            wait_room(fd, nonblock)?
        } else {
            if !wait_data(fd, nonblock)? {
                return Ok(0);
            }
            held(fd)
        };
        let mut done = 0u64;
        for v in bufs.iter().filter(|v| v.iov_len > 0) {
            if left == 0 {
                break;
            }
            let n = (v.iov_len as u64).min(left) as usize;
            // SAFETY: checked guest buffers the host reads or writes, and
            // reports a fault of.
            let r = unsafe {
                if to_pipe { libc::write(fd, v.iov_base, n) } else { libc::read(fd, v.iov_base, n) }
            };
            if r < 0 {
                if done == 0 {
                    return Err(last());
                }
                break;
            }
            done += r as u64;
            left -= r as u64;
            if (r as usize) < n {
                break;
            }
        }
        Ok(done)
    })();
    match r {
        Ok(n) => n as i64,
        Err(e) => err(e),
    }
}
