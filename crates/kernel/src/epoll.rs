//! `epoll` support.
//!
//! On Linux the three calls pass straight through to the host kernel, which
//! already speaks the arm64 Linux ABI. On macOS they are translated to
//! `kqueue`: the epoll descriptor is a kqueue fd, each watched fd becomes one
//! or two `kevent` filters (`EVFILT_READ` for `EPOLLIN`, `EVFILT_WRITE` for
//! `EPOLLOUT`), and the caller's `epoll_event.data` word rides in the kevent
//! `udata`. `EPOLLET` maps to `EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`.
//!
//! Guest addresses are host addresses, so `epoll_event` arrays are read and
//! written in place. The packed arm64 layout is `{ u32 events; u64 data; }`
//! with `data` at offset 4 and a 12-byte stride.

/// Size of a packed arm64 `struct epoll_event`.
#[cfg(not(target_os = "linux"))]
const EVENT_SIZE: usize = 12;

/// Read one guest `epoll_event` at `ptr`.
///
/// # Safety
/// `ptr` must point to a readable 12-byte `epoll_event`.
#[cfg(not(target_os = "linux"))]
unsafe fn read_event(ptr: u64) -> (u32, u64) {
    // SAFETY: the caller guarantees `ptr` spans a valid packed epoll_event.
    unsafe {
        let events = (ptr as *const u32).read_unaligned();
        let data = ((ptr + 4) as *const u64).read_unaligned();
        (events, data)
    }
}

/// `epoll_create1(flags)`.
///
/// # Safety
/// No pointer arguments; safe to call in any host state.
pub unsafe fn create1(flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain host syscall; `flags` carries only EPOLL_CLOEXEC.
        crate::host::ret(unsafe { libc::syscall(libc::SYS_epoll_create1, flags as libc::c_int) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: plain host call.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return crate::host::last_error();
        }
        if flags & fwe_abi::epoll::EPOLL_CLOEXEC != 0 {
            // SAFETY: plain host call on the descriptor just created.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        fd as i64
    }
}

/// `epoll_ctl(epfd, op, fd, event)`.
///
/// # Safety
/// `event` must point to a valid `epoll_event` unless `op` is `EPOLL_CTL_DEL`.
pub unsafe fn ctl(epfd: u64, op: u64, fd: u64, event: u64) -> i64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the host validates the guest `epoll_event` pointer.
        crate::host::ret(unsafe {
            libc::syscall(
                libc::SYS_epoll_ctl,
                epfd as libc::c_int,
                op as libc::c_int,
                fd as libc::c_int,
                event as *mut libc::c_void,
            )
        })
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees `event` is valid for ADD/MOD.
    unsafe {
        ctl_kqueue(epfd, op, fd, event)
    }
}

/// `epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)`.
///
/// This can block, so the backend runs it outside the kernel lock.
///
/// # Safety
/// `events` must point to space for `maxevents` `epoll_event`s; `sigmask`, if
/// non-null, to a Linux `sigset_t` of `sigsetsize` bytes.
pub unsafe fn pwait(
    epfd: u64,
    events: u64,
    maxevents: u64,
    timeout: u64,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    if (maxevents as libc::c_int) <= 0 {
        return fwe_abi::err(fwe_abi::errno::EINVAL);
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: raw Linux ABI; the host validates every pointer.
        crate::host::ret(unsafe {
            libc::syscall(
                libc::SYS_epoll_pwait,
                epfd as libc::c_int,
                events as *mut libc::c_void,
                maxevents as libc::c_int,
                timeout as libc::c_int,
                sigmask as *const libc::c_void,
                sigsetsize as libc::size_t,
            )
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sigmask, sigsetsize);
        // SAFETY: the caller guarantees `events` spans `maxevents` entries.
        unsafe { pwait_kqueue(epfd, events, maxevents, timeout) }
    }
}

#[cfg(not(target_os = "linux"))]
unsafe fn ctl_kqueue(epfd: u64, op: u64, fd: u64, event: u64) -> i64 {
    use fwe_abi::epoll::*;

    let (events, data) = if op == EPOLL_CTL_DEL {
        (0, 0)
    } else {
        // SAFETY: the caller guarantees a valid event for ADD/MOD.
        unsafe { read_event(event) }
    };

    let want_read = events & EPOLLIN != 0;
    let want_write = events & EPOLLOUT != 0;
    let extra = (if events & EPOLLONESHOT != 0 { libc::EV_ONESHOT } else { 0 })
        | (if events & EPOLLET != 0 { libc::EV_CLEAR } else { 0 });

    // Build one change per filter. For ADD/MOD a wanted filter is (re)added and
    // enabled; an unwanted one is deleted so a MOD that drops a direction takes
    // effect. For DEL both filters are removed. EV_RECEIPT makes `kevent` report
    // per-change status in the event list without reporting readiness.
    let mut changes: Vec<libc::kevent> = Vec::with_capacity(2);
    let mut push = |filter: i16, want: bool| {
        let flags = if op != EPOLL_CTL_DEL && want {
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_RECEIPT | extra
        } else {
            libc::EV_DELETE | libc::EV_RECEIPT
        };
        changes.push(libc::kevent {
            ident: fd as libc::uintptr_t,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: data as *mut libc::c_void,
        });
    };
    push(libc::EVFILT_READ, want_read);
    push(libc::EVFILT_WRITE, want_write);

    let mut out = changes.clone();
    // SAFETY: both lists are valid for `changes.len()` entries; no timeout.
    let n = unsafe {
        libc::kevent(
            epfd as libc::c_int,
            changes.as_ptr(),
            changes.len() as libc::c_int,
            out.as_mut_ptr(),
            out.len() as libc::c_int,
            std::ptr::null(),
        )
    };
    if n < 0 {
        return crate::host::last_error();
    }
    // Surface a real registration error (e.g. EBADF). A delete of a filter that
    // was never registered reports ENOENT, which epoll_ctl does not; ignore it.
    for r in &out[..n as usize] {
        if r.flags & libc::EV_ERROR != 0 {
            let e = r.data as i32;
            let is_delete = r.flags & libc::EV_DELETE != 0;
            if e != 0 && !(is_delete && e == libc::ENOENT) {
                return -(crate::host::errno_to_linux(e) as i64);
            }
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
unsafe fn pwait_kqueue(epfd: u64, events: u64, maxevents: u64, timeout: u64) -> i64 {
    use fwe_abi::epoll::*;

    let max = maxevents as usize;
    let mut out: Vec<libc::kevent> = vec![
        libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        max
    ];

    let ms = timeout as i32;
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    let ts_ptr: *const libc::timespec = if ms < 0 { std::ptr::null() } else { &ts };

    // SAFETY: `out` holds `max` entries; `ts_ptr` is null or a valid timespec.
    let n = unsafe {
        libc::kevent(
            epfd as libc::c_int,
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            max as libc::c_int,
            ts_ptr,
        )
    };
    if n < 0 {
        return crate::host::last_error();
    }

    for (i, ev) in out[..n as usize].iter().enumerate() {
        let mut bits: u32 = 0;
        match ev.filter {
            libc::EVFILT_READ => bits |= EPOLLIN,
            libc::EVFILT_WRITE => bits |= EPOLLOUT,
            _ => {}
        }
        if ev.flags & libc::EV_EOF != 0 {
            bits |= EPOLLHUP;
        }
        if ev.flags & libc::EV_ERROR != 0 {
            bits |= EPOLLERR;
        }
        let dst = events + (i * EVENT_SIZE) as u64;
        // SAFETY: the caller guarantees space for `maxevents` entries and
        // `i < n <= maxevents`.
        unsafe {
            (dst as *mut u32).write_unaligned(bits);
            ((dst + 4) as *mut u64).write_unaligned(ev.udata as u64);
        }
    }
    n as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::epoll::*;

    /// A pipe whose read end becomes readable once data is written, observed
    /// through the epoll translation on either host.
    #[test]
    fn pipe_readiness_round_trip() {
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);

        // SAFETY: create1 takes no pointers.
        let ep = unsafe { create1(0) };
        assert!(ep >= 0, "epoll_create1 failed: {ep}");

        let reg = fwe_abi::EpollEvent { events: EPOLLIN, data: 0xdead_beef };
        let reg_ptr = &reg as *const _ as u64;
        // SAFETY: `reg_ptr` points to a valid epoll_event for the add.
        let r = unsafe { ctl(ep as u64, EPOLL_CTL_ADD, rd as u64, reg_ptr) };
        assert_eq!(r, 0, "epoll_ctl ADD failed: {r}");

        // Nothing written yet: a zero timeout returns no events.
        let mut got = [fwe_abi::EpollEvent::default(); 4];
        let got_ptr = got.as_mut_ptr() as u64;
        // SAFETY: `got` has room for 4 events.
        let n = unsafe { pwait(ep as u64, got_ptr, 4, 0, 0, 0) };
        assert_eq!(n, 0, "expected no readiness before write, got {n}");

        // Write a byte; the read end becomes readable.
        // SAFETY: writing one byte from a valid local buffer.
        assert_eq!(unsafe { libc::write(wr, b"x".as_ptr() as *const _, 1) }, 1);
        // SAFETY: `got` has room for 4 events.
        let n = unsafe { pwait(ep as u64, got_ptr, 4, 1000, 0, 0) };
        assert_eq!(n, 1, "expected one ready fd, got {n}");
        let ev = got[0];
        assert_eq!({ ev.events } & EPOLLIN, EPOLLIN);
        assert_eq!({ ev.data }, 0xdead_beef);

        // SAFETY: plain host cleanup calls.
        unsafe {
            libc::close(rd);
            libc::close(wr);
            libc::close(ep as i32);
        }
    }

    #[test]
    fn mod_and_del() {
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        // SAFETY: create1 takes no pointers.
        let ep = unsafe { create1(EPOLL_CLOEXEC) };
        assert!(ep >= 0);

        // Register for EPOLLOUT only (read end is never writable): no readiness.
        let reg = fwe_abi::EpollEvent { events: EPOLLOUT, data: 1 };
        let p = &reg as *const _ as u64;
        // SAFETY: valid event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_ADD, rd as u64, p) }, 0);

        // SAFETY: writing one byte.
        assert_eq!(unsafe { libc::write(wr, b"x".as_ptr() as *const _, 1) }, 1);
        let mut got = [fwe_abi::EpollEvent::default(); 2];
        let gp = got.as_mut_ptr() as u64;
        // SAFETY: room for 2 events.
        assert_eq!(unsafe { pwait(ep as u64, gp, 2, 0, 0, 0) }, 0);

        // Modify to watch EPOLLIN: now the readable read end shows up.
        let reg = fwe_abi::EpollEvent { events: EPOLLIN, data: 7 };
        let p = &reg as *const _ as u64;
        // SAFETY: valid event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_MOD, rd as u64, p) }, 0);
        // SAFETY: room for 2 events.
        let n = unsafe { pwait(ep as u64, gp, 2, 1000, 0, 0) };
        assert_eq!(n, 1);
        assert_eq!({ got[0].data }, 7);

        // Delete the registration: no more readiness.
        // SAFETY: DEL ignores the event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_DEL, rd as u64, 0) }, 0);
        // SAFETY: room for 2 events.
        assert_eq!(unsafe { pwait(ep as u64, gp, 2, 0, 0, 0) }, 0);

        // SAFETY: plain host cleanup calls.
        unsafe {
            libc::close(rd);
            libc::close(wr);
            libc::close(ep as i32);
        }
    }

    #[test]
    fn bad_maxevents_is_einval() {
        // SAFETY: create1 takes no pointers.
        let ep = unsafe { create1(0) };
        assert!(ep >= 0);
        // SAFETY: maxevents 0 is rejected before any pointer use.
        let r = unsafe { pwait(ep as u64, 0, 0, 0, 0, 0) };
        assert_eq!(r, fwe_abi::err(fwe_abi::errno::EINVAL));
        // SAFETY: plain host cleanup.
        unsafe { libc::close(ep as i32) };
    }
}
