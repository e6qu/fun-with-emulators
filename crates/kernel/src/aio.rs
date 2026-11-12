//! Native AIO: `io_setup`, `io_submit`, `io_getevents`, `io_pgetevents`,
//! `io_cancel` and `io_destroy`.
//!
//! A context is the process's (not a fork child's), named as Linux names
//! it by the address of a ring mapped into the process: a page of zeros,
//! read-only, whose missing magic number sends libaio's `io_getevents` to
//! the system call rather than to the ring. A request is carried out as it
//! is submitted, as Linux carries out one on a file opened without
//! `O_DIRECT` (a read of an empty pipe waits in `io_submit`), and its
//! completion queued on the context; a `IOCB_CMD_POLL` of a descriptor not
//! yet ready waits on the context until `io_getevents` finds it ready.
//! `io_submit`, `io_getevents` and `io_cancel` run without the kernel lock.

use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{err, errno};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_POLL: u16 = 5;
const IOCB_CMD_PREADV: u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;

const IOCB_FLAG_RESFD: u32 = 1;
const IOCB_FLAG_IOPRIO: u32 = 2;

/// `RWF_*` flags a request may carry, and those fwe acts on.
const RWF_KNOWN: u32 = 0xff;
const RWF_DSYNC: u32 = 0x2;
const RWF_SYNC: u32 = 0x4;
const RWF_NOWAIT: u32 = 0x8;
const RWF_APPEND: u32 = 0x10;

/// `struct iocb` and `struct io_event`.
const IOCB_SIZE: usize = 64;
const EVENT_SIZE: u64 = 32;

/// The most events a context may ask for (`0x10000000 / sizeof(struct
/// io_event)`).
const MAX_EVENTS: u64 = 0x1000_0000 / EVENT_SIZE;

/// A request waiting for its descriptor (`IOCB_CMD_POLL`).
struct Poll {
    iocb: u64,
    data: u64,
    fd: i32,
    events: i16,
    resfd: Option<i32>,
}

pub(crate) struct Ctx {
    id: u64,
    /// Events reserved against `fs.aio-max-nr`.
    reserved: u64,
    /// Completions not yet read: `data`, `obj` (the request), `res`, `res2`.
    done: VecDeque<[u64; 4]>,
    polls: Vec<Poll>,
}

pub(crate) static CTXS: Mutex<Vec<Ctx>> = Mutex::new(Vec::new());

/// Events reserved by this process's contexts.
static RESERVED: AtomicU64 = AtomicU64::new(0);

fn ctxs<R>(f: impl FnOnce(&mut Vec<Ctx>) -> R) -> R {
    f(&mut CTXS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// A fork child has none of its parent's contexts, nor has a new program.
pub fn forget_all() {
    ctxs(Vec::clear);
    RESERVED.store(0, Ordering::Relaxed);
}

/// `fs.aio-max-nr`.
fn max_nr() -> u64 {
    crate::sysctl::number(b"fs/aio-max-nr").map_or(65536, |n| n.max(0) as u64)
}

impl<P: Platform> Kernel<P> {
    /// `io_setup(nr_events, ctxp)`.
    pub(crate) fn sys_io_setup(&mut self, nr: u64, ctxp: u64) -> i64 {
        let given: u64 = guest!(uaccess::read(ctxp));
        let nr = nr as u32 as u64;
        if given != 0 || nr == 0 || nr > MAX_EVENTS {
            return err(errno::EINVAL);
        }
        // Linux reserves twice what is asked, at least four a CPU.
        let reserve = nr.max(4) * 2;
        if RESERVED.load(Ordering::Relaxed) + reserve > max_nr() {
            return err(errno::EAGAIN);
        }
        const PROT_READ: u64 = 1;
        const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
        let page = self.page_size;
        let ring = self.sys_mmap(0, page, PROT_READ, MAP_PRIVATE_ANON, u64::MAX, 0);
        if ring < 0 {
            return ring;
        }
        let id = ring as u64;
        if let Err(e) = uaccess::write(ctxp, id) {
            self.sys_munmap(id, page);
            return err(e);
        }
        RESERVED.fetch_add(reserve, Ordering::Relaxed);
        ctxs(|c| c.push(Ctx { id, reserved: reserve, done: VecDeque::new(), polls: Vec::new() }));
        0
    }

    /// `io_destroy(ctx)`: what it still holds is dropped with it.
    pub(crate) fn sys_io_destroy(&mut self, id: u64) -> i64 {
        let Some(ctx) = ctxs(|c| c.iter().position(|x| x.id == id).map(|i| c.remove(i))) else {
            return err(errno::EINVAL);
        };
        RESERVED.fetch_sub(ctx.reserved, Ordering::Relaxed);
        let page = self.page_size;
        self.sys_munmap(id, page);
        0
    }
}

fn known(id: u64) -> bool {
    ctxs(|c| c.iter().any(|x| x.id == id))
}

/// The host's open flags of guest descriptor `fd`, or `EBADF`.
fn open_flags(fd: i32) -> Result<i32, i32> {
    if !crate::fdtable::guest_visible(fd)
        || crate::fdmarks::marked(fd) == Some(crate::fdmarks::Mark::Path)
    {
        return Err(errno::EBADF);
    }
    // SAFETY: plain host call.
    let f = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if f < 0 { Err(errno::EBADF) } else { Ok(f) }
}

/// Whether `fd` is a pipe, socket or character device: a stream, whose
/// offset a request's is not.
fn stream(fd: i32) -> bool {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    ok && matches!(st.st_mode & libc::S_IFMT, libc::S_IFIFO | libc::S_IFSOCK | libc::S_IFCHR)
}

fn ready(fd: i32, events: i16) -> i16 {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: one valid pollfd, not waited on.
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents
}

fn host_result(r: isize) -> i64 {
    if r < 0 { err(crate::host::errno_to_linux(crate::host::last_errno())) } else { r as i64 }
}

/// Read or write `len` bytes at guest `buf` (`write`), at `offset` unless
/// `fd` is a stream.
fn transfer(fd: i32, write: bool, buf: u64, len: u64, offset: i64, flags: u32) -> i64 {
    let io = match uaccess::host_buffer(buf, len, !write) {
        Ok(io) => io,
        Err(e) => return err(e),
    };
    transfer_vec(fd, write, &[io], offset, flags)
}

fn transfer_vec(fd: i32, write: bool, iov: &[libc::iovec], offset: i64, flags: u32) -> i64 {
    let is_stream = stream(fd);
    let n = iov.len() as libc::c_int;
    let want = if write { libc::POLLOUT } else { libc::POLLIN };
    if flags & RWF_NOWAIT != 0 && is_stream && ready(fd, want) == 0 {
        return err(errno::EAGAIN);
    }
    // SAFETY: host buffers of the guest's, validated; a live descriptor.
    let r = unsafe {
        match (write, is_stream) {
            (false, true) => libc::readv(fd, iov.as_ptr(), n),
            (true, true) => libc::writev(fd, iov.as_ptr(), n),
            (false, false) => libc::preadv(fd, iov.as_ptr(), n, offset),
            (true, false) if flags & RWF_APPEND != 0 => {
                let end = libc::lseek(fd, 0, libc::SEEK_END);
                libc::pwritev(fd, iov.as_ptr(), n, end)
            }
            (true, false) => libc::pwritev(fd, iov.as_ptr(), n, offset),
        }
    };
    let r = host_result(r);
    if r >= 0 && write && flags & (RWF_DSYNC | RWF_SYNC) != 0 {
        // SAFETY: plain host call.
        unsafe { libc::fsync(fd) };
    }
    r
}

/// Carry out request `iocb`: its result, or `None` for a poll that waits.
fn run(ctx: u64, at: u64, b: &[u8; IOCB_SIZE]) -> Result<Option<i64>, i32> {
    let u32_at = |i: usize| u32::from_ne_bytes(b[i..i + 4].try_into().unwrap());
    let u64_at = |i: usize| u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
    let rw_flags = u32_at(12);
    let opcode = u16::from_ne_bytes([b[16], b[17]]);
    let fd = u32_at(20) as i32;
    let (buf, len, offset) = (u64_at(24), u64_at(32), u64_at(40) as i64);
    let flags = u32_at(56);
    let resfd = (flags & IOCB_FLAG_RESFD != 0).then(|| u32_at(60) as i32);
    let mode = open_flags(fd)? & libc::O_ACCMODE;
    let readable = mode == libc::O_RDONLY || mode == libc::O_RDWR;
    let writable = mode == libc::O_WRONLY || mode == libc::O_RDWR;
    if rw_flags & !RWF_KNOWN != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    Ok(Some(match opcode {
        IOCB_CMD_PREAD | IOCB_CMD_PREADV if !readable => return Err(errno::EBADF),
        IOCB_CMD_PWRITE | IOCB_CMD_PWRITEV if !writable => return Err(errno::EBADF),
        IOCB_CMD_PREAD | IOCB_CMD_PWRITE => {
            transfer(fd, opcode == IOCB_CMD_PWRITE, buf, len, offset, rw_flags)
        }
        IOCB_CMD_PREADV | IOCB_CMD_PWRITEV => {
            let write = opcode == IOCB_CMD_PWRITEV;
            let iov = uaccess::host_iovecs(buf, len, !write)?;
            transfer_vec(fd, write, &iov, offset, rw_flags)
        }
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
            if len != 0 || offset != 0 || buf != 0 || rw_flags != 0 {
                return Err(errno::EINVAL);
            }
            if stream(fd) {
                return Err(errno::EINVAL);
            }
            // SAFETY: plain host call.
            host_result(unsafe { libc::fsync(fd) } as isize)
        }
        IOCB_CMD_POLL => {
            if len != 0 || offset != 0 || rw_flags != 0 || buf >> 16 != 0 {
                return Err(errno::EINVAL);
            }
            let events = buf as i16;
            let got = ready(fd, events | libc::POLLERR | libc::POLLHUP);
            if got == 0 {
                let data = u64_at(0);
                let poll = Poll { iocb: at, data, fd, events, resfd };
                ctxs(|c| {
                    if let Some(x) = c.iter_mut().find(|x| x.id == ctx) {
                        x.polls.push(poll);
                    }
                });
                return Ok(None);
            }
            i64::from(got)
        }
        _ => return Err(errno::EINVAL),
    }))
}

/// Queue the completion of request `at` on context `ctx`, and signal its
/// eventfd.
fn complete(ctx: u64, at: u64, data: u64, res: i64, resfd: Option<i32>) {
    ctxs(|c| {
        if let Some(x) = c.iter_mut().find(|x| x.id == ctx) {
            x.done.push_back([data, at, res as u64, 0]);
        }
    });
    if let Some(fd) = resfd {
        crate::specialfd::eventfd_signal(fd);
    }
}

/// `io_submit(ctx, nr, iocbpp)`: how many requests were taken, or the
/// first's error if none was.
pub fn submit(ctx: u64, nr: u64, list: u64) -> i64 {
    if (nr as i64) < 0 {
        return err(errno::EINVAL);
    }
    if !known(ctx) {
        return err(errno::EINVAL);
    }
    let mut taken = 0;
    for i in 0..nr {
        match submit_one(ctx, list + 8 * i) {
            Ok(()) => taken += 1,
            Err(e) if taken == 0 => return err(e),
            Err(_) => break,
        }
    }
    taken
}

fn submit_one(ctx: u64, slot: u64) -> Result<(), i32> {
    let at: u64 = uaccess::read(slot)?;
    let mut b = [0u8; IOCB_SIZE];
    uaccess::read_into(at, &mut b)?;
    let u32_at = |i: usize| u32::from_ne_bytes(b[i..i + 4].try_into().unwrap());
    let reserved2 = u64::from_ne_bytes(b[48..56].try_into().unwrap());
    let nbytes = u64::from_ne_bytes(b[32..40].try_into().unwrap());
    let flags = u32_at(56);
    if reserved2 != 0 || (nbytes as i64) < 0 || flags & !(IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO) != 0 {
        return Err(errno::EINVAL);
    }
    if flags & IOCB_FLAG_RESFD != 0 && crate::specialfd::eventfd_writable(u32_at(60) as i32) {
        // An eventfd (one at its maximum is still one).
    } else if flags & IOCB_FLAG_RESFD != 0 && !crate::fdtable::guest_visible(u32_at(60) as i32) {
        return Err(errno::EBADF);
    }
    // The request's key, as Linux sets it (`KIOCB_KEY`).
    uaccess::write(at + 8, 0u32)?;
    let data = u64::from_ne_bytes(b[..8].try_into().unwrap());
    let resfd = (flags & IOCB_FLAG_RESFD != 0).then(|| u32_at(60) as i32);
    if let Some(res) = run(ctx, at, &b)? {
        complete(ctx, at, data, res, resfd);
    }
    Ok(())
}

/// Complete the polls of `ctx` whose descriptors are ready; the
/// descriptors of those still waiting.
fn check_polls(ctx: u64) -> Vec<libc::pollfd> {
    let waiting: Vec<(u64, u64, i32, i16, Option<i32>)> = ctxs(|c| {
        c.iter()
            .find(|x| x.id == ctx)
            .map(|x| x.polls.iter().map(|p| (p.iocb, p.data, p.fd, p.events, p.resfd)).collect())
            .unwrap_or_default()
    });
    let mut left = Vec::new();
    for (at, data, fd, events, resfd) in waiting {
        let got = ready(fd, events | libc::POLLERR | libc::POLLHUP);
        if got == 0 {
            left.push(libc::pollfd { fd, events, revents: 0 });
            continue;
        }
        let taken = ctxs(|c| {
            let Some(x) = c.iter_mut().find(|x| x.id == ctx) else { return false };
            let before = x.polls.len();
            x.polls.retain(|p| p.iocb != at);
            x.polls.len() != before
        });
        if taken {
            complete(ctx, at, data, i64::from(got), resfd);
        }
    }
    left
}

/// `io_getevents(ctx, min_nr, nr, events, timeout)`; `io_pgetevents`
/// with its signal mask applied by the caller.
pub fn getevents(ctx: u64, min: i64, nr: i64, events: u64, timeout: u64) -> i64 {
    let deadline = if timeout == 0 {
        None
    } else {
        match uaccess::read::<fwe_abi::Timespec>(timeout) {
            Ok(ts) if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) => {
                return err(errno::EINVAL);
            }
            Ok(ts) => Some(
                std::time::Instant::now()
                    + std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32),
            ),
            Err(e) => return err(e),
        }
    };
    if !known(ctx) {
        return err(errno::EINVAL);
    }
    if min < 0 || min > nr {
        return err(errno::EINVAL);
    }
    loop {
        let waiting = check_polls(ctx);
        let have = ctxs(|c| c.iter().find(|x| x.id == ctx).map_or(0, |x| x.done.len()));
        let now = std::time::Instant::now();
        let out_of_time = deadline.is_some_and(|d| now >= d);
        if have as i64 >= min.max(1) || (have > 0 && out_of_time) || nr == 0 {
            return take_events(ctx, nr as usize, events);
        }
        if out_of_time {
            return 0;
        }
        if !known(ctx) {
            return err(errno::EINVAL);
        }
        // Wait for a polled descriptor, a signal, or another thread's
        // submission (looked for each few milliseconds).
        let mut fds = waiting;
        let left = deadline.map_or(20, |d| d.saturating_duration_since(now).as_millis() as i32);
        if let Err(e) = crate::thread::wait_ready(&mut fds, left.clamp(1, 20)) {
            return err(e);
        }
    }
}

/// Copy up to `nr` completions of `ctx` to guest `events`, taking those
/// copied.
fn take_events(ctx: u64, nr: usize, events: u64) -> i64 {
    let ready: Vec<[u64; 4]> = ctxs(|c| {
        c.iter()
            .find(|x| x.id == ctx)
            .map(|x| x.done.iter().take(nr).copied().collect())
            .unwrap_or_default()
    });
    if ready.is_empty() {
        return 0;
    }
    let bytes: Vec<u8> =
        ready.iter().flat_map(|e| e.iter().flat_map(|w| w.to_ne_bytes())).collect();
    if let Err(e) = uaccess::write_from(events, &bytes) {
        return err(e);
    }
    ctxs(|c| {
        if let Some(x) = c.iter_mut().find(|x| x.id == ctx) {
            x.done.drain(..ready.len().min(x.done.len()));
        }
    });
    ready.len() as i64
}

/// `io_pgetevents(ctx, min_nr, nr, events, timeout, usig)`: with the signal
/// mask `usig` names (a `struct __aio_sigset`) in force while it waits.
pub fn pgetevents(a: [u64; 6]) -> i64 {
    if a[5] != 0 {
        let sig: [u64; 2] = match uaccess::read(a[5]) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        if sig[0] != 0 {
            if sig[1] != 8 {
                return err(errno::EINVAL);
            }
            // SAFETY: the mask pointer is the guest's, read as a guest
            // address.
            return unsafe {
                crate::signal::with_call_mask(sig[0], || {
                    getevents(a[0], a[1] as i64, a[2] as i64, a[3], a[4])
                })
            };
        }
    }
    getevents(a[0], a[1] as i64, a[2] as i64, a[3], a[4])
}

/// `io_cancel(ctx, iocb, result)`: a poll still waiting is cancelled, its
/// completion queued (`EINPROGRESS`, as Linux reports one); anything else
/// has finished (`EINVAL`).
pub fn cancel(ctx: u64, iocb: u64, _result: u64) -> i64 {
    let key: u32 = match uaccess::read(iocb + 8) {
        Ok(k) => k,
        Err(e) => return err(e),
    };
    if key != 0 || !known(ctx) {
        return err(errno::EINVAL);
    }
    let found = ctxs(|c| {
        let x = c.iter_mut().find(|x| x.id == ctx)?;
        let i = x.polls.iter().position(|p| p.iocb == iocb)?;
        Some(x.polls.remove(i))
    });
    match found {
        Some(p) => {
            complete(ctx, iocb, p.data, err(errno::EINTR), p.resfd);
            err(errno::EINPROGRESS)
        }
        None => err(errno::EINVAL),
    }
}
