//! `epoll` support.
//!
//! On Linux the three calls pass straight through to the host kernel, which
//! already speaks the arm64 Linux ABI. On macOS they are translated to
//! `kqueue`: the epoll descriptor is a kqueue fd, each watched fd becomes one
//! or two `kevent` filters (`EVFILT_READ` for `EPOLLIN`, `EVFILT_WRITE` for
//! `EPOLLOUT`), and the caller's `epoll_event.data` word rides in the kevent
//! `udata`. `EPOLLET` maps to `EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`.
//!
//! A kqueue is not passed on to a child process, so each epoll descriptor's
//! interest list is also recorded here ([`save`], [`restore`]): a fork
//! child rebuilds its epoll descriptors from it.
//!
//! Guest addresses are host addresses, so `epoll_event` arrays are read and
//! written in place. The arm64 layout is `{ u32 events; u64 data; }`, not
//! packed as on x86-64: `data` sits at offset 8 and the stride is 16 bytes.

/// Each epoll descriptor's interest list: `fd -> (events, data)`.
#[cfg(not(target_os = "linux"))]
type Interest = std::collections::BTreeMap<i32, (u32, u64)>;

#[cfg(not(target_os = "linux"))]
static INTEREST: std::sync::Mutex<Option<std::collections::HashMap<i32, Interest>>> =
    std::sync::Mutex::new(None);

#[cfg(not(target_os = "linux"))]
fn interest<R>(f: impl FnOnce(&mut std::collections::HashMap<i32, Interest>) -> R) -> R {
    let mut g = INTEREST.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Default::default))
}

/// Descriptor `fd` is being closed: it leaves every interest list (as the
/// kqueue drops its filters), and if it is an epoll descriptor, its list goes.
pub fn closed(fd: i32) {
    #[cfg(target_os = "linux")]
    let _ = fd;
    #[cfg(not(target_os = "linux"))]
    interest(|m| {
        m.remove(&fd);
        for list in m.values_mut() {
            list.remove(&fd);
        }
    })
}

/// Write the interest lists into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    #[cfg(target_os = "linux")]
    e.u64(0);
    #[cfg(not(target_os = "linux"))]
    interest(|m| {
        let mut eps: Vec<&i32> = m.keys().collect();
        eps.sort();
        let ce: Vec<bool> = eps.iter().map(|&&fd| crate::snapshot::cloexec(fd)).collect();
        e.u64(ce.len() as u64);
        for c in ce {
            e.bool(c);
        }
        crate::snapshot::fd_map(e, m, |e, list| {
            e.u64(list.len() as u64);
            for (&fd, &(events, data)) in list {
                e.i32(fd);
                e.u32(events);
                e.u64(data);
            }
        })
    })
}

/// Rebuild every epoll descriptor in a fork child: a fresh kqueue at its
/// number, with its interest list registered again.
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    #[cfg(target_os = "linux")]
    let _ = d.count(1);
    #[cfg(not(target_os = "linux"))]
    {
        let n = d.count(1);
        let ce: Vec<bool> = (0..n).map(|_| d.bool()).collect();
        let lists = crate::snapshot::read_fd_map(d, |d| {
            let n = d.count(16);
            (0..n).map(|_| (d.i32(), (d.u32(), d.u64()))).collect::<Interest>()
        });
        // `lists` iterates in no particular order; `ce` is in fd order. Only
        // a kqueue made here is filled: a descriptor already open at an
        // epoll number (a stale record) is left alone.
        let mut eps: Vec<i32> = lists.keys().copied().collect();
        eps.sort();
        let fresh: Vec<i32> = eps
            .into_iter()
            .zip(ce.into_iter().chain(std::iter::repeat(false)))
            .filter(|&(epfd, c)| crate::snapshot::fresh_kqueue_at(epfd, c))
            .map(|(epfd, _)| epfd)
            .collect();
        // Nested epoll descriptors exist by now, whatever the order.
        for epfd in fresh {
            for (&fd, &(events, data)) in &lists[&epfd] {
                // SAFETY: plain host calls on the inherited descriptors.
                let _ = unsafe {
                    ctl_kqueue(
                        epfd as u64,
                        fwe_abi::epoll::EPOLL_CTL_ADD,
                        fd as u64,
                        (events, data),
                    )
                };
            }
        }
        interest(|m| *m = lists);
    }
}

/// Size of an arm64 `struct epoll_event`.
#[cfg(not(target_os = "linux"))]
const EVENT_SIZE: usize = size_of::<fwe_abi::EpollEvent>();

/// Read one guest `epoll_event` at `ptr`.
#[cfg(not(target_os = "linux"))]
fn read_event(ptr: u64) -> crate::uaccess::Result<(u32, u64)> {
    let ev: fwe_abi::EpollEvent = crate::uaccess::read(ptr)?;
    Ok((ev.events, ev.data))
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
        interest(|m| m.insert(fd, Interest::new()));
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
    {
        let entry = if op == fwe_abi::epoll::EPOLL_CTL_DEL {
            None
        } else {
            Some(crate::guest!(read_event(event)))
        };
        // SAFETY: plain host calls on the guest's descriptors.
        let r = unsafe { ctl_kqueue(epfd, op, fd, entry.unwrap_or((0, 0))) };
        if r == 0 {
            interest(|m| {
                if let Some(list) = m.get_mut(&(epfd as i32)) {
                    match entry {
                        Some(ev) => list.insert(fd as i32, ev),
                        None => list.remove(&(fd as i32)),
                    };
                }
            });
        }
        r
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
unsafe fn ctl_kqueue(epfd: u64, op: u64, fd: u64, (events, data): (u32, u64)) -> i64 {
    use fwe_abi::epoll::*;

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

/// `epoll_pwait` on a kqueue. A set that watches the read end of a named
/// FIFO waits in slices, looking between them for the end of its writers,
/// which the host does not report ([`crate::fifo`]).
#[cfg(not(target_os = "linux"))]
unsafe fn pwait_kqueue(epfd: u64, events: u64, maxevents: u64, timeout: u64) -> i64 {
    use fwe_abi::epoll::*;
    let ms = timeout as i32;
    let fifos: Vec<(i32, u64, u32)> = interest(|m| {
        m.get(&(epfd as i32)).map_or_else(Vec::new, |l| {
            l.iter()
                .filter(|(_, (ev, _))| ev & EPOLLIN != 0)
                .map(|(&fd, &(ev, d))| (fd, d, ev))
                .collect()
        })
    })
    .into_iter()
    .filter(|&(fd, ..)| crate::fifo::is_reader(fd))
    .collect();
    if fifos.is_empty() {
        // SAFETY: the caller's guarantee, passed on.
        return unsafe { kevent_into(epfd, events, 0, maxevents as usize, ms) };
    }
    let deadline =
        (ms >= 0).then(|| std::time::Instant::now() + std::time::Duration::from_millis(ms as u64));
    loop {
        // FIFOs whose writers have gone, or with bytes a probe kept.
        let mut ready: Vec<(u32, u64)> = Vec::new();
        for &(fd, data, ev) in &fifos {
            match crate::fifo::probe(fd) {
                crate::fifo::Probe::HungUp => {
                    // Edge-triggered: once, as Linux reports the change.
                    if ev & EPOLLET == 0 || hup_first(epfd as i32, fd) {
                        ready.push((EPOLLIN | EPOLLHUP, data));
                    }
                }
                _ => {
                    hup_clear(epfd as i32, fd);
                    if crate::fifo::has_kept(fd) {
                        ready.push((EPOLLIN, data));
                    }
                }
            }
        }
        let max = maxevents as usize;
        ready.truncate(max);
        if !ready.is_empty() {
            for (i, &(bits, data)) in ready.iter().enumerate() {
                let dst = events + (i * EVENT_SIZE) as u64;
                crate::guest!(crate::uaccess::write(
                    dst,
                    fwe_abi::EpollEvent { events: bits, data }
                ));
            }
            // And whatever else is ready now.
            // SAFETY: the caller's guarantee, passed on.
            let more = unsafe { kevent_into(epfd, events, ready.len(), max, 0) };
            return ready.len() as i64 + more.max(0);
        }
        let slice = match deadline {
            None => crate::fifo::SLICE_MS,
            Some(d) => {
                let left =
                    d.saturating_duration_since(std::time::Instant::now()).as_millis() as i32;
                left.min(crate::fifo::SLICE_MS)
            }
        };
        // SAFETY: the caller's guarantee, passed on.
        let n = unsafe { kevent_into(epfd, events, 0, max, slice) };
        if n != 0 || deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return n;
        }
    }
}

/// The FIFOs whose writers' end an edge-triggered set has reported, by
/// epoll descriptor and descriptor.
#[cfg(not(target_os = "linux"))]
static HUP: std::sync::Mutex<Vec<(i32, i32)>> = std::sync::Mutex::new(Vec::new());

/// Whether the hang-up of `fd` is news to epoll set `epfd` (and note it).
#[cfg(not(target_os = "linux"))]
fn hup_first(epfd: i32, fd: i32) -> bool {
    let mut h = HUP.lock().unwrap_or_else(|e| e.into_inner());
    if h.contains(&(epfd, fd)) {
        return false;
    }
    h.push((epfd, fd));
    true
}

#[cfg(not(target_os = "linux"))]
fn hup_clear(epfd: i32, fd: i32) {
    HUP.lock().unwrap_or_else(|e| e.into_inner()).retain(|&k| k != (epfd, fd));
}

/// Wait up to `ms` milliseconds (forever if negative) on kqueue `epfd`,
/// writing the events as `epoll_event`s from slot `first` of `events`, at
/// most `max` in all. Returns how many, or the error.
///
/// # Safety
/// `events` spans `max` entries.
#[cfg(not(target_os = "linux"))]
unsafe fn kevent_into(epfd: u64, events: u64, first: usize, max: usize, ms: i32) -> i64 {
    use fwe_abi::epoll::*;
    if first >= max {
        return 0;
    }
    let room = max - first;
    let mut out: Vec<libc::kevent> = vec![
        libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        room
    ];
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    let ts_ptr: *const libc::timespec = if ms < 0 { std::ptr::null() } else { &ts };
    // SAFETY: `out` holds `room` entries; `ts_ptr` is null or a valid timespec.
    let n = unsafe {
        libc::kevent(
            epfd as libc::c_int,
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            room as libc::c_int,
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
        let dst = events + ((first + i) * EVENT_SIZE) as u64;
        let out = fwe_abi::EpollEvent { events: bits, data: ev.udata as u64 };
        crate::guest!(crate::uaccess::write(dst, out));
    }
    n as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::epoll::*;

    // A Linux host takes its own `epoll_event` (packed on x86-64); a macOS
    // host goes through the translation, which takes the arm64 guest's.
    #[cfg(target_os = "linux")]
    type Event = libc::epoll_event;
    #[cfg(not(target_os = "linux"))]
    type Event = fwe_abi::EpollEvent;

    #[cfg(target_os = "linux")]
    fn event(events: u32, data: u64) -> Event {
        libc::epoll_event { events, u64: data }
    }
    #[cfg(not(target_os = "linux"))]
    fn event(events: u32, data: u64) -> Event {
        fwe_abi::EpollEvent { events, data }
    }
    #[cfg(target_os = "linux")]
    fn data(e: &Event) -> u64 {
        e.u64
    }
    #[cfg(not(target_os = "linux"))]
    fn data(e: &Event) -> u64 {
        e.data
    }

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

        let reg = event(EPOLLIN, 0x0123_4567_89ab_cdef);
        let reg_ptr = &reg as *const _ as u64;
        // SAFETY: `reg_ptr` points to a valid epoll_event for the add.
        let r = unsafe { ctl(ep as u64, EPOLL_CTL_ADD, rd as u64, reg_ptr) };
        assert_eq!(r, 0, "epoll_ctl ADD failed: {r}");

        // Nothing written yet: a zero timeout returns no events.
        let mut got = [event(0, 0); 4];
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
        assert_eq!(data(&ev), 0x0123_4567_89ab_cdef);

        closed(ep as i32);
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
        let reg = event(EPOLLOUT, 1);
        let p = &reg as *const _ as u64;
        // SAFETY: valid event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_ADD, rd as u64, p) }, 0);

        // SAFETY: writing one byte.
        assert_eq!(unsafe { libc::write(wr, b"x".as_ptr() as *const _, 1) }, 1);
        let mut got = [event(0, 0); 2];
        let gp = got.as_mut_ptr() as u64;
        // SAFETY: room for 2 events.
        assert_eq!(unsafe { pwait(ep as u64, gp, 2, 0, 0, 0) }, 0);

        // Modify to watch EPOLLIN: now the readable read end shows up.
        let reg = event(EPOLLIN, 7);
        let p = &reg as *const _ as u64;
        // SAFETY: valid event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_MOD, rd as u64, p) }, 0);
        // SAFETY: room for 2 events.
        let n = unsafe { pwait(ep as u64, gp, 2, 1000, 0, 0) };
        assert_eq!(n, 1);
        assert_eq!(data(&got[0]), 7);

        // Delete the registration: no more readiness.
        // SAFETY: DEL ignores the event pointer.
        assert_eq!(unsafe { ctl(ep as u64, EPOLL_CTL_DEL, rd as u64, 0) }, 0);
        // SAFETY: room for 2 events.
        assert_eq!(unsafe { pwait(ep as u64, gp, 2, 0, 0, 0) }, 0);

        closed(ep as i32);
        // SAFETY: plain host cleanup calls.
        unsafe {
            libc::close(rd);
            libc::close(wr);
            libc::close(ep as i32);
        }
    }

    /// A fork child rebuilds an epoll descriptor it did not inherit (a
    /// kqueue) from the recorded interest list, at the same number. The
    /// test uses a high number of its own, so tests running alongside never
    /// open a descriptor there, and restores only its own record.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn interest_list_survives_a_rebuild() {
        const EP: i32 = 900;
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: create1 takes no pointers; the kqueue moves to EP.
        unsafe {
            let ep = create1(0) as i32;
            closed(ep);
            assert_eq!(libc::dup2(ep, EP), EP);
            libc::close(ep);
            libc::fcntl(EP, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        interest(|m| m.insert(EP, Interest::new()));
        let reg = event(EPOLLIN, 77);
        // SAFETY: a valid event pointer.
        let r = unsafe { ctl(EP as u64, EPOLL_CTL_ADD, fds[0] as u64, &reg as *const _ as u64) };
        assert_eq!(r, 0);
        // What save writes, for this descriptor alone.
        let mut e = crate::snapshot::Enc::new();
        e.u64(1);
        e.bool(crate::snapshot::cloexec(EP));
        let only = std::collections::HashMap::from([(EP, interest(|m| m[&EP].clone()))]);
        crate::snapshot::fd_map(&mut e, &only, |e, list| {
            e.u64(list.len() as u64);
            for (&fd, &(events, data)) in list {
                e.i32(fd);
                e.u32(events);
                e.u64(data);
            }
        });
        // As in a child: the kqueue is gone.
        // SAFETY: closing the kqueue behind the record.
        unsafe { libc::close(EP) };
        let bytes = e.into_bytes();
        let mut d = crate::snapshot::Dec::new(&bytes);
        restore(&mut d);
        assert!(d.finish().is_ok());
        // SAFETY: F_GETFD only queries the descriptor.
        assert_eq!(unsafe { libc::fcntl(EP, libc::F_GETFD) }, libc::FD_CLOEXEC);
        // SAFETY: writing one byte.
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        let mut got = [event(0, 0); 1];
        // SAFETY: room for one event.
        assert_eq!(unsafe { pwait(EP as u64, got.as_mut_ptr() as u64, 1, 1000, 0, 0) }, 1);
        assert_eq!(data(&got[0]), 77);
        closed(EP);
        // SAFETY: plain host cleanup.
        unsafe {
            libc::close(EP);
            libc::close(fds[0]);
            libc::close(fds[1]);
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
        closed(ep as i32);
        // SAFETY: plain host cleanup.
        unsafe { libc::close(ep as i32) };
    }
}
