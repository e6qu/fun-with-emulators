//! `eventfd` and `timerfd` descriptors.
//!
//! On Linux these pass straight through to the host kernel. On macOS, which has
//! neither, they are emulated and tracked in a process-global registry so that
//! `read`, `write` and `close` on them are intercepted:
//!
//! - **eventfd** is backed by a pipe plus a 64-bit counter. The pipe holds one
//!   byte exactly while the counter is non-zero, so the read end (the fd handed
//!   to the guest) is readable — and pollable by `kqueue`, hence by our
//!   `epoll` — precisely when a read would succeed.
//! - **timerfd** is a `kqueue` holding one `EVFILT_TIMER`. `read` collects the
//!   expiration count with `kevent`; the kqueue fd is pollable by our `epoll`.
//!
//! Reads can block, so the backend routes `read`/`write` on any fd through
//! [`try_read`]/[`try_write`] from the lock-free `blocking_syscall` path: a
//! consumer blocking under the kernel lock while the producer needs that same
//! lock to post would deadlock. Both return `None` for a descriptor that is not
//! one of ours, so the caller falls back to the normal host `read`/`write`.

/// Handle `read` for an emulated descriptor. `Some(result)` if `fd` is one of
/// ours (possibly blocking without the kernel lock); `None` otherwise.
///
/// # Safety
/// `buf` must point to `len` writable guest bytes.
pub unsafe fn try_read(fd: i32, buf: u64, len: u64) -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let _ = (fd, buf, len);
        None
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: forwarded to the macOS implementation with the same contract.
    unsafe {
        imp::read(fd, buf, len)
    }
}

/// Handle `write` for an emulated descriptor. `Some(result)`/`None` as
/// [`try_read`].
///
/// # Safety
/// `buf` must point to `len` readable guest bytes.
pub unsafe fn try_write(fd: i32, buf: u64, len: u64) -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let _ = (fd, buf, len);
        None
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: forwarded to the macOS implementation with the same contract.
    unsafe {
        imp::write(fd, buf, len)
    }
}

/// Handle `close` for an emulated descriptor. `Some(result)` if `fd` was ours
/// (its host resources are released); `None` otherwise.
pub fn try_close(fd: i32) -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        imp::close(fd)
    }
}

/// `eventfd2(initval, flags)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn eventfd2(initval: u64, flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: plain host syscall; flags carry only EFD_* bits.
    unsafe {
        crate::host::ret(libc::syscall(
            libc::SYS_eventfd2,
            initval as libc::c_uint,
            flags as libc::c_int,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: no pointers; sets up a pipe-backed counter.
    unsafe {
        imp::eventfd2(initval, flags)
    }
}

/// `timerfd_create(clockid, flags)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn timerfd_create(clockid: u64, flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: plain host syscall.
    unsafe {
        crate::host::ret(libc::syscall(
            libc::SYS_timerfd_create,
            clockid as libc::c_int,
            flags as libc::c_int,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: no pointers; sets up a kqueue timer.
    unsafe {
        imp::timerfd_create(clockid, flags)
    }
}

/// `timerfd_settime(fd, flags, new_value, old_value)`.
///
/// # Safety
/// `new_value` must point to a valid `itimerspec`; `old_value`, if non-null, to
/// writable space for one.
pub unsafe fn timerfd_settime(fd: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the itimerspec pointers.
    unsafe {
        crate::host::ret(libc::syscall(
            libc::SYS_timerfd_settime,
            fd as libc::c_int,
            flags as libc::c_int,
            new_value as *const libc::c_void,
            old_value as *mut libc::c_void,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the itimerspec pointers.
    unsafe {
        imp::timerfd_settime(fd, flags, new_value, old_value)
    }
}

/// `timerfd_gettime(fd, curr_value)`.
///
/// # Safety
/// `curr_value` must point to writable space for an `itimerspec`.
pub unsafe fn timerfd_gettime(fd: u64, curr_value: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the itimerspec pointer.
    unsafe {
        crate::host::ret(libc::syscall(
            libc::SYS_timerfd_gettime,
            fd as libc::c_int,
            curr_value as *mut libc::c_void,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the itimerspec pointer.
    unsafe {
        imp::timerfd_gettime(fd, curr_value)
    }
}

/// Descriptors the emulation holds for itself, which `execve` must keep open.
pub fn internal_fds() -> Vec<i32> {
    #[cfg(target_os = "linux")]
    {
        Vec::new()
    }
    #[cfg(not(target_os = "linux"))]
    imp::internal_fds()
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::host::last_error;
    use fwe_abi::{err, errno};
    use std::collections::HashMap;
    use std::sync::Mutex;

    enum Special {
        Event(EventFd),
        Timer(TimerFd),
    }

    struct EventFd {
        /// Read end (the fd the guest holds) and write end of the readiness pipe.
        rfd: i32,
        wfd: i32,
        count: u64,
        semaphore: bool,
        nonblock: bool,
    }

    struct TimerFd {
        /// The kqueue fd (the fd the guest holds).
        kq: i32,
        nonblock: bool,
        interval: (i64, i64),
        value: (i64, i64),
    }

    static REG: Mutex<Option<HashMap<i32, Special>>> = Mutex::new(None);

    fn with_reg<R>(f: impl FnOnce(&mut HashMap<i32, Special>) -> R) -> R {
        let mut g = REG.lock().unwrap();
        f(g.get_or_insert_with(HashMap::new))
    }

    /// Descriptors the emulation holds for itself (the write ends of the
    /// eventfd readiness pipes), which the guest must never see closed.
    pub fn internal_fds() -> Vec<i32> {
        with_reg(|reg| {
            reg.values()
                .filter_map(|s| match s {
                    Special::Event(e) => Some(e.wfd),
                    Special::Timer(_) => None,
                })
                .collect()
        })
    }

    fn set_cloexec(fd: i32) {
        // SAFETY: plain host call on a fresh descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }

    /// Write/drain the single readiness byte on a pipe end.
    unsafe fn poke(wfd: i32) {
        let b = [0u8];
        // SAFETY: the pipe holds at most one byte, so this never blocks.
        unsafe { libc::write(wfd, b.as_ptr() as *const _, 1) };
    }
    unsafe fn drain(rfd: i32) {
        let mut b = 0u8;
        // SAFETY: a byte is present when we drain, so this does not block.
        unsafe { libc::read(rfd, &mut b as *mut _ as *mut _, 1) };
    }

    pub unsafe fn eventfd2(initval: u64, flags: u64) -> i64 {
        use fwe_abi::eventfd::*;
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return last_error();
        }
        let (rfd, wfd) = (fds[0], fds[1]);
        if flags & EFD_CLOEXEC != 0 {
            set_cloexec(rfd);
        }
        set_cloexec(wfd);
        let ev = EventFd {
            rfd,
            wfd,
            count: initval,
            semaphore: flags & EFD_SEMAPHORE != 0,
            nonblock: flags & EFD_NONBLOCK != 0,
        };
        if initval > 0 {
            // SAFETY: fresh pipe write end.
            unsafe { poke(wfd) };
        }
        with_reg(|m| m.insert(rfd, Special::Event(ev)));
        rfd as i64
    }

    pub unsafe fn timerfd_create(_clockid: u64, flags: u64) -> i64 {
        use fwe_abi::timerfd::*;
        // SAFETY: plain host call.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return last_error();
        }
        if flags & TFD_CLOEXEC != 0 {
            set_cloexec(kq);
        }
        with_reg(|m| {
            m.insert(
                kq,
                Special::Timer(TimerFd {
                    kq,
                    nonblock: flags & TFD_NONBLOCK != 0,
                    interval: (0, 0),
                    value: (0, 0),
                }),
            )
        });
        kq as i64
    }

    pub unsafe fn timerfd_settime(fd: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
        use fwe_abi::timerfd::*;
        let fd = fd as i32;
        // Read the requested interval and value.
        // SAFETY: the caller guarantees a valid itimerspec.
        let (iv_s, iv_ns, val_s, val_ns) = unsafe {
            (
                (new_value as *const i64).read_unaligned(),
                ((new_value + 8) as *const i64).read_unaligned(),
                ((new_value + 16) as *const i64).read_unaligned(),
                ((new_value + 24) as *const i64).read_unaligned(),
            )
        };

        let (prev_iv, prev_val, kq) = match with_reg(|m| match m.get_mut(&fd) {
            Some(Special::Timer(t)) => {
                let prev = (t.interval, t.value);
                t.interval = (iv_s, iv_ns);
                t.value = (val_s, val_ns);
                Some((prev.0, prev.1, t.kq))
            }
            _ => None,
        }) {
            Some(v) => v,
            None => return err(errno::EINVAL),
        };

        if old_value != 0 {
            // SAFETY: the caller guarantees writable space for an itimerspec.
            unsafe {
                ((old_value) as *mut i64).write_unaligned(prev_iv.0);
                ((old_value + 8) as *mut i64).write_unaligned(prev_iv.1);
                ((old_value + 16) as *mut i64).write_unaligned(prev_val.0);
                ((old_value + 24) as *mut i64).write_unaligned(prev_val.1);
            }
        }

        let value_ms = val_s.saturating_mul(1000) + val_ns / 1_000_000;
        let interval_ms = iv_s.saturating_mul(1000) + iv_ns / 1_000_000;

        // Disarm when it_value is zero.
        if val_s == 0 && val_ns == 0 {
            let change = timer_kevent(libc::EV_DELETE, 0);
            // SAFETY: single-change kevent with no event list.
            unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            return 0;
        }

        // kqueue fires relative; approximate an absolute deadline against now,
        // and periodic timers fire every it_interval (the distinct initial
        // it_value is not modelled when an interval is set).
        let mut first_ms = value_ms;
        if flags & TFD_TIMER_ABSTIME != 0 {
            let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: valid timespec out-parameter.
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
            let now_ms = now.tv_sec.saturating_mul(1000) + now.tv_nsec / 1_000_000;
            first_ms = (value_ms - now_ms).max(1);
        }
        let periodic = interval_ms > 0;
        let period = if periodic { interval_ms } else { first_ms }.max(1);
        let mut extra = libc::EV_ENABLE;
        if !periodic {
            extra |= libc::EV_ONESHOT;
        }
        let change = timer_kevent(libc::EV_ADD | extra, period);
        // SAFETY: single-change kevent with no event list.
        let r = unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if r < 0 { last_error() } else { 0 }
    }

    fn timer_kevent(flags: u16, period_ms: i64) -> libc::kevent {
        libc::kevent {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags,
            fflags: 0,
            data: period_ms as libc::intptr_t,
            udata: std::ptr::null_mut(),
        }
    }

    pub unsafe fn timerfd_gettime(fd: u64, curr_value: u64) -> i64 {
        let fd = fd as i32;
        match with_reg(|m| match m.get(&fd) {
            Some(Special::Timer(t)) => Some((t.interval, t.value)),
            _ => None,
        }) {
            Some((iv, val)) => {
                // SAFETY: the caller guarantees writable space for an itimerspec.
                unsafe {
                    (curr_value as *mut i64).write_unaligned(iv.0);
                    ((curr_value + 8) as *mut i64).write_unaligned(iv.1);
                    ((curr_value + 16) as *mut i64).write_unaligned(val.0);
                    ((curr_value + 24) as *mut i64).write_unaligned(val.1);
                }
                0
            }
            None => err(errno::EINVAL),
        }
    }

    pub unsafe fn read(fd: i32, buf: u64, len: u64) -> Option<i64> {
        // Classify the fd without holding the lock across any blocking wait.
        enum Kind {
            // eventfd blocking is decided under the lock from the live counter,
            // so only the pipe read end is needed here.
            Event { rfd: i32 },
            Timer { kq: i32, nonblock: bool },
        }
        let kind = with_reg(|m| match m.get(&fd) {
            Some(Special::Event(e)) => Some(Kind::Event { rfd: e.rfd }),
            Some(Special::Timer(t)) => Some(Kind::Timer { kq: t.kq, nonblock: t.nonblock }),
            None => None,
        })?;

        Some(match kind {
            Kind::Event { rfd } => {
                if len < 8 {
                    return Some(err(errno::EINVAL));
                }
                loop {
                    let got = with_reg(|m| {
                        let Some(Special::Event(e)) = m.get_mut(&fd) else {
                            return Some(err(errno::EBADF));
                        };
                        if e.count > 0 {
                            let v = if e.semaphore { 1 } else { e.count };
                            e.count -= v;
                            if e.count == 0 {
                                // SAFETY: a byte is present when count drops to 0.
                                unsafe { drain(e.rfd) };
                            }
                            // SAFETY: the caller guarantees 8 writable bytes.
                            unsafe { (buf as *mut u64).write_unaligned(v) };
                            Some(8)
                        } else if e.nonblock {
                            Some(err(errno::EAGAIN))
                        } else {
                            None
                        }
                    });
                    if let Some(r) = got {
                        break r;
                    }
                    // Wait for a writer to make the read end readable, lock-free.
                    let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
                    // SAFETY: a valid single-element pollfd; -1 waits indefinitely.
                    unsafe { libc::poll(&mut pfd, 1, -1) };
                }
            }
            Kind::Timer { kq, nonblock } => {
                if len < 8 {
                    return Some(err(errno::EINVAL));
                }
                let mut ev = empty_kevent();
                let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                let ts: *const libc::timespec = if nonblock { &zero } else { std::ptr::null() };
                // SAFETY: event list holds one entry; ts is null or valid.
                let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut ev, 1, ts) };
                if n < 0 {
                    return Some(last_error());
                }
                if n == 0 {
                    return Some(err(errno::EAGAIN));
                }
                let count = ev.data.max(1) as u64;
                // SAFETY: the caller guarantees 8 writable bytes.
                unsafe { (buf as *mut u64).write_unaligned(count) };
                8
            }
        })
    }

    pub unsafe fn write(fd: i32, buf: u64, len: u64) -> Option<i64> {
        let (is_event, is_timer) = with_reg(|m| match m.get(&fd) {
            Some(Special::Event(_)) => (true, false),
            Some(Special::Timer(_)) => (false, true),
            None => (false, false),
        });
        if is_timer {
            return Some(err(errno::EINVAL));
        }
        if !is_event {
            return None;
        }
        if len < 8 {
            return Some(err(errno::EINVAL));
        }
        // SAFETY: the caller guarantees 8 readable bytes.
        let add = unsafe { (buf as *const u64).read_unaligned() };
        if add == u64::MAX {
            return Some(err(errno::EINVAL));
        }
        Some(with_reg(|m| {
            let Some(Special::Event(e)) = m.get_mut(&fd) else {
                return err(errno::EBADF);
            };
            // eventfd caps at u64::MAX - 1; overflow would block, which we
            // report as EAGAIN (the counter reaching this is not expected).
            if add > u64::MAX - 1 - e.count {
                return err(errno::EAGAIN);
            }
            let was_zero = e.count == 0;
            e.count += add;
            if was_zero && e.count > 0 {
                // SAFETY: the pipe holds at most one byte.
                unsafe { poke(e.wfd) };
            }
            8
        }))
    }

    pub fn close(fd: i32) -> Option<i64> {
        let removed = with_reg(|m| m.remove(&fd));
        let s = removed?;
        // SAFETY: these descriptors were opened by this module and are ours.
        unsafe {
            match s {
                Special::Event(e) => {
                    libc::close(e.rfd);
                    libc::close(e.wfd);
                }
                Special::Timer(t) => {
                    libc::close(t.kq);
                }
            }
        }
        Some(0)
    }

    fn empty_kevent() -> libc::kevent {
        libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::eventfd::*;

    // Read/write an 8-byte word through the emulation when the fd is ours
    // (macOS) or through the host otherwise (Linux passthrough of a real
    // eventfd/timerfd), so these tests check both paths.
    fn read_into(fd: i32, v: &mut u64) -> i64 {
        let p = v as *mut u64;
        // SAFETY: `p` is 8 writable bytes.
        match unsafe { try_read(fd, p as u64, 8) } {
            Some(r) => r,
            None => {
                // SAFETY: host read into 8 writable bytes.
                crate::host::ret(unsafe { libc::read(fd, p as *mut _, 8) } as i64)
            }
        }
    }
    fn read_u64(fd: i32) -> i64 {
        let mut v: u64 = 0;
        read_into(fd, &mut v)
    }
    fn write_u64(fd: i32, val: u64) -> i64 {
        let v = val;
        let p = &v as *const u64;
        // SAFETY: `p` is 8 readable bytes.
        match unsafe { try_write(fd, p as u64, 8) } {
            Some(r) => r,
            None => {
                // SAFETY: host write from 8 readable bytes.
                crate::host::ret(unsafe { libc::write(fd, p as *const _, 8) } as i64)
            }
        }
    }
    fn close_fd(fd: i32) -> i64 {
        match try_close(fd) {
            Some(r) => r,
            None => {
                // SAFETY: plain host close.
                crate::host::ret(unsafe { libc::close(fd) })
            }
        }
    }

    #[test]
    fn eventfd_counter() {
        // SAFETY: no pointers.
        let fd = unsafe { eventfd2(0, EFD_NONBLOCK) } as i32;
        assert!(fd >= 0);
        // Empty and non-blocking: EAGAIN.
        assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN));
        // Accumulate 2 + 3 and read the sum.
        assert_eq!(write_u64(fd, 2), 8);
        assert_eq!(write_u64(fd, 3), 8);
        let mut v: u64 = 0;
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 5);
        // Drained: EAGAIN again.
        assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN));
        assert_eq!(close_fd(fd), 0);
    }

    #[test]
    fn eventfd_semaphore() {
        // SAFETY: no pointers.
        let fd = unsafe { eventfd2(2, EFD_SEMAPHORE | EFD_NONBLOCK) } as i32;
        assert!(fd >= 0);
        let mut v: u64 = 0;
        // Each read returns 1 until the count is exhausted.
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 1);
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 1);
        assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN));
        assert_eq!(close_fd(fd), 0);
    }

    #[test]
    fn timerfd_oneshot_fires() {
        // SAFETY: no pointers.
        let fd = unsafe { timerfd_create(0, 0) } as i32;
        assert!(fd >= 0, "timerfd_create failed: {fd}");
        // Fire once after 40ms (it_interval = 0).
        let spec: [i64; 4] = [0, 0, 0, 40_000_000];
        // SAFETY: `spec` is a valid itimerspec; no old_value.
        let r = unsafe { timerfd_settime(fd as u64, 0, spec.as_ptr() as u64, 0) };
        assert_eq!(r, 0, "settime failed: {r}");
        let mut v: u64 = 0;
        // Blocking read returns the expiration count once the timer fires.
        let n = read_into(fd, &mut v);
        assert_eq!(n, 8);
        assert!(v >= 1, "expirations: {v}");
        assert_eq!(close_fd(fd), 0);
    }

    #[test]
    fn unknown_fd_is_not_special() {
        // A normal fd (stderr) is never one of ours, on any host.
        let mut v: u64 = 0;
        // SAFETY: 8 writable bytes, though the fd is not special.
        assert!(unsafe { try_read(2, &mut v as *mut _ as u64, 8) }.is_none());
        assert!(try_close(2).is_none());
    }
}
