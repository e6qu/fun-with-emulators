//! `eventfd` and `timerfd` descriptors.
//!
//! On Linux these pass straight through to the host kernel. On macOS, which has
//! neither, they are emulated and tracked in a process-global registry so that
//! `read`, `write` and `close` on them are intercepted:
//!
//! - **eventfd** is backed by a pipe plus a 64-bit counter. The pipe holds one
//!   byte exactly while the counter is non-zero, so the read end (the fd handed
//!   to the guest) is readable — and pollable by `kqueue`, hence by our
//!   `epoll` — precisely when a read would succeed. The counter is in a
//!   file with no name, with a lock word, which each process holding the
//!   eventfd maps, so that a fork child, which shares the pipe, shares the
//!   counter too, and one it is passed to gets the file with the pipe's
//!   write end ([`crate::scm`]).
//! - **timerfd** is a `kqueue` holding one one-shot `EVFILT_TIMER`, armed
//!   for the timer's next expiry: the kqueue fd, pollable by our `epoll`,
//!   is readable once an expiry is due. The schedule (the first expiry on
//!   the host's monotonic clock, then one every interval) is fwe's: `read`
//!   counts the expiries due since the last read and arms the host timer
//!   for the next. An absolute time (`TFD_TIMER_ABSTIME`) is measured
//!   against the timer's own clock when it is set.
//!
//! Reads can block, so the backend routes `read`/`write` on any fd through
//! [`try_read`]/[`try_write`] from the lock-free `blocking_syscall` path: a
//! consumer blocking under the kernel lock while the producer needs that same
//! lock to post would deadlock. Both return `None` for a descriptor that is not
//! one of ours, so the caller falls back to the normal host `read`/`write`.

/// Whether `fd` is an emulated eventfd that may be written to: its count
/// short of its maximum (its pipe's read end, which the guest holds, never
/// is writable to the host).
pub fn eventfd_writable(fd: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        imp::writable(fd)
    }
}

/// How many writes emulated eventfd `fd` has had, if it is one: each is a
/// new edge to an edge-triggered `epoll` watcher ([`crate::epoll`]).
pub fn eventfd_writes(fd: i32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        imp::writes(fd)
    }
}

/// Whether `fd` is a timerfd that does not block, if it is one.
pub fn timer_nonblock(fd: i32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        None
    }
    #[cfg(not(target_os = "linux"))]
    imp::timer_nonblock(fd)
}

/// `F_SETFL`'s `O_NONBLOCK` on timerfd `fd`: whether it was one.
pub fn set_timer_nonblock(fd: i32, on: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        let _ = (fd, on);
        false
    }
    #[cfg(not(target_os = "linux"))]
    imp::set_timer_nonblock(fd, on)
}

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

/// Add 1 to eventfd `fd`'s count, as the kernel signals one (an AIO
/// completion's `IOCB_FLAG_RESFD`): whether `fd` is an eventfd.
pub fn eventfd_signal(fd: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let one = 1u64;
        // SAFETY: an 8-byte buffer on the stack.
        unsafe { libc::write(fd, (&one as *const u64).cast(), 8) == 8 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        imp::add_to(fd, 1) >= 0
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

/// `TFD_IOC_SET_TICKS` (`_IOW('T', 0, u64)`), the one request Linux's
/// timerfd takes (with `CONFIG_CHECKPOINT_RESTORE`).
pub const TFD_IOC_SET_TICKS: u64 = 0x4008_5400;

/// An `ioctl` of request `req` on `fd`, if `fd` is a timerfd: for
/// `TFD_IOC_SET_TICKS`, the count of expiries the next read returns, at
/// `arg`; any other request `ENOTTY`, as Linux's `timerfd_ioctl`.
pub fn timer_ioctl(fd: i32, req: u64, arg: u64) -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let _ = (fd, req, arg);
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        timer_nonblock(fd)?;
        if req != TFD_IOC_SET_TICKS {
            return Some(fwe_abi::err(fwe_abi::errno::ENOTTY));
        }
        imp::set_ticks(fd, arg)
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

/// What `/proc/self/fd` shows for an emulated descriptor: `[eventfd]` or
/// `[timerfd]`.
pub fn anon_name(fd: i32) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        None
    }
    #[cfg(not(target_os = "linux"))]
    imp::anon_name(fd)
}

/// What eventfd or timerfd `fd` takes to another process it is passed
/// to ([`crate::scm`]): an eventfd its pipe's write end and counter memory,
/// shared with the sender; a timerfd (a kqueue, which the host does not
/// pass) its clock and schedule, for the receiver's own.
#[cfg(not(target_os = "linux"))]
pub(crate) fn export(fd: i32) -> Option<crate::scm::Export> {
    imp::export(fd)
}

/// Make received descriptor `fd` the eventfd or timerfd an
/// [`export`] described: whether it was.
#[cfg(not(target_os = "linux"))]
pub(crate) fn import(
    kind: u8,
    fd: i32,
    d: &mut crate::snapshot::Dec,
    companions: Vec<i32>,
) -> bool {
    imp::import(kind, fd, d, companions)
}

/// Run `f` holding the registry lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(target_os = "linux")]
    {
        f()
    }
    #[cfg(not(target_os = "linux"))]
    imp::hold(f)
}

/// Write the registry into a fork snapshot.
pub(crate) fn save(e: &mut crate::snapshot::Enc) {
    #[cfg(target_os = "linux")]
    e.u64(0);
    #[cfg(not(target_os = "linux"))]
    imp::save(e)
}

/// Rebuild the registry in a fork child from [`save`]'s record: eventfd pipes
/// are inherited as they are; each timerfd gets a fresh kqueue at its number,
/// armed for what was left of its time.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub(crate) fn restore(d: &mut crate::snapshot::Dec) {
    #[cfg(target_os = "linux")]
    let _ = d.count(1);
    #[cfg(not(target_os = "linux"))]
    imp::restore(d)
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::host::last_error;
    use crate::{guest, uaccess};
    use fwe_abi::{err, errno};
    use std::collections::HashMap;
    enum Special {
        Event(EventFd),
        Timer(TimerFd),
    }

    struct EventFd {
        /// Read end (the fd the guest holds) and write end of the readiness pipe.
        rfd: i32,
        wfd: i32,
        /// The memory holding its [`Shared`] counter (fwe's descriptor,
        /// which passing the eventfd to another process passes too), and
        /// where this process maps it.
        mfd: i32,
        shared: usize,
        semaphore: bool,
        nonblock: bool,
    }

    /// An eventfd's counter, in memory every process holding the eventfd
    /// maps (a fork child's mapping is its parent's), and the lock its
    /// changes, with the pipe's, are made under; and how many writes it
    /// has had, each a new edge to an edge-triggered `epoll` watcher, as
    /// each wakes Linux's waiters ([`writes`]).
    #[repr(C)]
    struct Shared {
        magic: std::sync::atomic::AtomicU64,
        lock: std::sync::atomic::AtomicU32,
        count: std::sync::atomic::AtomicU64,
        writes: std::sync::atomic::AtomicU64,
    }

    const MAGIC: u64 = 0x6677_655f_6576_6664;

    /// A new counter holding `count`: its memory (a descriptor out of the
    /// guest's reach, of a host shared memory object with no name) and
    /// where it is mapped.
    fn new_shared(count: u64) -> Result<(i32, usize), i32> {
        let fd = crate::memobj::nameless(std::mem::size_of::<Shared>() as u64)?;
        let at = map_shared(std::os::fd::AsRawFd::as_raw_fd(&fd))?;
        let fd = std::os::fd::IntoRawFd::into_raw_fd(fd);
        // SAFETY: the memory just mapped, zeroed, large enough for a `Shared`.
        let sh = unsafe { &*(at as *const Shared) };
        sh.count.store(count, std::sync::atomic::Ordering::SeqCst);
        sh.magic.store(MAGIC, std::sync::atomic::Ordering::SeqCst);
        Ok((fd, at))
    }

    /// Map counter memory `mfd`: where.
    fn map_shared(mfd: i32) -> Result<usize, i32> {
        // SAFETY: a shared mapping of fwe's own counter memory.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<Shared>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                mfd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        Ok(p as usize)
    }

    /// Run `f` on the counter at `shared` under its lock (shared with every
    /// process the eventfd is in).
    fn locked<R>(shared: usize, f: impl FnOnce(&mut u64) -> R) -> R {
        use std::sync::atomic::Ordering;
        // SAFETY: the eventfd's own mapped `Shared`, mapped for as long as
        // the descriptor is registered.
        let sh = unsafe { &*(shared as *const Shared) };
        while sh.lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            std::thread::yield_now();
        }
        let mut c = sh.count.load(Ordering::SeqCst);
        let r = f(&mut c);
        sh.count.store(c, Ordering::SeqCst);
        sh.lock.store(0, Ordering::Release);
        r
    }

    struct TimerFd {
        /// The kqueue fd (the fd the guest holds).
        kq: i32,
        /// The host clock the guest's clock reads
        /// ([`crate::host::clock_to_host`]).
        clock: libc::clockid_t,
        nonblock: bool,
        interval: (i64, i64),
        value: (i64, i64),
        /// When (host monotonic nanoseconds) it first expires, `None` when
        /// disarmed; its period in nanoseconds, 0 for a one-shot timer; and
        /// how many of its expiries were read.
        first_at_ns: Option<i64>,
        period_ns: i64,
        taken: u64,
        /// Expiries `TFD_IOC_SET_TICKS` set as unread, beyond the
        /// schedule's.
        extra: u64,
    }

    impl TimerFd {
        /// How many times it has expired by monotonic time `now`.
        fn expired(&self, now: i64) -> u64 {
            match self.first_at_ns {
                Some(first) if now >= first => {
                    if self.period_ns > 0 {
                        1 + ((now - first) / self.period_ns) as u64
                    } else {
                        1
                    }
                }
                _ => 0,
            }
        }

        /// Arm the host timer for the first expiry not yet read (at once if
        /// it is due), or clear it once nothing is left to expire: 0 or a
        /// negated errno.
        fn arm(&self, now: i64) -> i64 {
            let next = match self.first_at_ns {
                // Set expiries are due at once.
                _ if self.extra > 0 => Some(now),
                Some(first) if self.period_ns > 0 => {
                    Some(first.saturating_add(self.period_ns.saturating_mul(self.taken as i64)))
                }
                Some(first) if self.taken == 0 => Some(first),
                _ => None,
            };
            let change = match next {
                // A kqueue timer of 0 fires at once.
                Some(at) => timer_kevent(
                    libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
                    at.saturating_sub(now).max(0),
                ),
                None => timer_kevent(libc::EV_DELETE, 0),
            };
            // SAFETY: single-change kevent with no event list.
            let r = unsafe {
                libc::kevent(self.kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null())
            };
            // Deleting a timer that is not armed is no failure.
            if r < 0 && next.is_some() { last_error() } else { 0 }
        }
    }

    /// `TFD_IOC_SET_TICKS` on timerfd `fd`: the expiries a read returns
    /// are `ticks` (0: `EINVAL`), those of the schedule so far taken, and
    /// the descriptor readable at once. `None` for another descriptor.
    pub fn set_ticks(fd: i32, arg: u64) -> Option<i64> {
        if !with_reg(|m| matches!(m.get(&fd), Some(Special::Timer(_)))) {
            return None;
        }
        let ticks: u64 = match uaccess::read(arg) {
            Ok(t) => t,
            Err(e) => return Some(err(e)),
        };
        if ticks == 0 {
            return Some(err(errno::EINVAL));
        }
        Some(with_reg(|m| match m.get_mut(&fd) {
            Some(Special::Timer(t)) => {
                let now = now_ns();
                t.taken = t.taken.max(t.expired(now));
                t.extra = ticks;
                t.arm(now)
            }
            _ => err(errno::EBADF),
        }))
    }

    fn now_ns() -> i64 {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: valid timespec out-parameter.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
        t.tv_sec.saturating_mul(1_000_000_000) + t.tv_nsec
    }

    pub(super) fn save(e: &mut crate::snapshot::Enc) {
        let mut g = REG.lock();
        let m = g.get_or_insert_with(HashMap::new);
        {
            crate::snapshot::fd_map(e, m, |e, s| match s {
                Special::Event(ev) => {
                    e.u8(0);
                    e.i32(ev.rfd);
                    e.i32(ev.wfd);
                    e.i32(ev.mfd);
                    e.u64(ev.shared as u64);
                    e.bool(ev.semaphore);
                    e.bool(ev.nonblock);
                }
                Special::Timer(t) => {
                    e.u8(1);
                    e.i32(t.kq);
                    e.bool(crate::snapshot::cloexec(t.kq));
                    e.u64(t.clock as u64);
                    e.bool(t.nonblock);
                    for v in [t.interval.0, t.interval.1, t.value.0, t.value.1] {
                        e.i64(v);
                    }
                    e.bool(t.first_at_ns.is_some());
                    e.i64(t.first_at_ns.unwrap_or(0));
                    e.i64(t.period_ns);
                    e.u64(t.taken);
                    e.u64(t.extra);
                }
            })
        }
    }

    pub(super) fn restore(d: &mut crate::snapshot::Dec) {
        let mut cloexec = std::collections::HashMap::new();
        let reg = crate::snapshot::read_fd_map(d, |d| {
            if d.u8() == 0 {
                let (rfd, wfd, mfd, at) = (d.i32(), d.i32(), d.i32(), d.u64() as usize);
                // A fork child has its parent's counter mapped at the same
                // place; anything else maps its file.
                // SAFETY: read only where the region is mapped.
                let inherited = crate::mm::host_mapped(at as u64, 1)
                    && unsafe { &*(at as *const Shared) }
                        .magic
                        .load(std::sync::atomic::Ordering::SeqCst)
                        == MAGIC;
                let shared = if inherited { at } else { map_shared(mfd).unwrap_or(at) };
                Special::Event(EventFd {
                    rfd,
                    wfd,
                    mfd,
                    shared,
                    semaphore: d.bool(),
                    nonblock: d.bool(),
                })
            } else {
                let kq = d.i32();
                cloexec.insert(kq, d.bool());
                Special::Timer(TimerFd {
                    kq,
                    clock: d.u64() as libc::clockid_t,
                    nonblock: d.bool(),
                    interval: (d.i64(), d.i64()),
                    value: (d.i64(), d.i64()),
                    first_at_ns: {
                        let (on, at) = (d.bool(), d.i64());
                        on.then_some(at)
                    },
                    period_ns: d.i64(),
                    taken: d.u64(),
                    extra: d.u64(),
                })
            }
        });
        let now = now_ns();
        for s in reg.values() {
            let Special::Timer(t) = s else { continue };
            let ce = cloexec.get(&t.kq).copied().unwrap_or(false);
            if !crate::snapshot::fresh_kqueue_at(t.kq, ce) {
                continue;
            }
            // The parent's schedule: the first expiry not read fires when
            // due, at once if it is due already.
            t.arm(now);
        }
        *REG.lock() = Some(reg);
    }

    static REG: crate::kept::Kept<Option<HashMap<i32, Special>>> = crate::kept::Kept::new(None);

    fn with_reg<R>(f: impl FnOnce(&mut HashMap<i32, Special>) -> R) -> R {
        let mut g = REG.lock();
        f(g.get_or_insert_with(HashMap::new))
    }

    pub(super) fn export(fd: i32) -> Option<crate::scm::Export> {
        use crate::scm::{Export, kind};
        with_reg(|m| {
            let mut e = crate::snapshot::Enc::new();
            Some(match m.get(&fd)? {
                Special::Event(ev) => {
                    e.bool(ev.semaphore);
                    e.bool(ev.nonblock);
                    Export {
                        kind: kind::EVENTFD,
                        state: e.into_bytes(),
                        companions: vec![ev.wfd, ev.mfd],
                        placeholder: false,
                    }
                }
                Special::Timer(t) => {
                    e.u64(t.clock as u64);
                    e.bool(t.nonblock);
                    for v in [t.interval.0, t.interval.1, t.value.0, t.value.1] {
                        e.i64(v);
                    }
                    e.bool(t.first_at_ns.is_some());
                    e.i64(t.first_at_ns.unwrap_or(0));
                    e.i64(t.period_ns);
                    e.u64(t.taken);
                    e.u64(t.extra);
                    Export {
                        kind: kind::TIMERFD,
                        state: e.into_bytes(),
                        companions: Vec::new(),
                        placeholder: true,
                    }
                }
            })
        })
    }

    pub(super) fn import(
        kind: u8,
        fd: i32,
        d: &mut crate::snapshot::Dec,
        companions: Vec<i32>,
    ) -> bool {
        if kind == crate::scm::kind::EVENTFD {
            let [wfd, mfd] = companions[..] else {
                for c in companions {
                    // SAFETY: descriptors received for this eventfd.
                    unsafe { libc::close(c) };
                }
                return false;
            };
            let close = |fd: i32| {
                // SAFETY: a descriptor received for this eventfd.
                unsafe { libc::close(fd) };
            };
            let Ok(wfd) = crate::fdtable::reserve(wfd) else {
                close(mfd);
                return false;
            };
            let Ok(mfd) = crate::fdtable::reserve(mfd) else {
                close(wfd);
                return false;
            };
            let Ok(shared) = map_shared(mfd) else {
                // SAFETY: fwe's own descriptors, received above.
                unsafe {
                    libc::close(wfd);
                    libc::close(mfd);
                }
                return false;
            };
            let ev = EventFd { rfd: fd, wfd, mfd, shared, semaphore: d.bool(), nonblock: d.bool() };
            with_reg(|m| m.insert(fd, Special::Event(ev)));
            return true;
        }
        // A timerfd: a kqueue of the receiver's in the placeholder's place,
        // on the sender's schedule.
        // SAFETY: plain host call.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 || !crate::scm::replace(fd, kq) {
            return false;
        }
        let t = TimerFd {
            kq: fd,
            clock: d.u64() as libc::clockid_t,
            nonblock: d.bool(),
            interval: (d.i64(), d.i64()),
            value: (d.i64(), d.i64()),
            first_at_ns: {
                let (on, at) = (d.bool(), d.i64());
                on.then_some(at)
            },
            period_ns: d.i64(),
            taken: d.u64(),
            extra: d.u64(),
        };
        t.arm(now_ns());
        with_reg(|m| m.insert(fd, Special::Timer(t)));
        true
    }

    /// How many writes eventfd `fd` (its pipe's read end) has had, if it
    /// is one.
    pub(super) fn writes(fd: i32) -> Option<u64> {
        with_reg(|m| match m.get(&fd) {
            // SAFETY: the eventfd's own mapped `Shared`, mapped while it
            // is registered (the registry is held).
            Some(Special::Event(e)) => Some(unsafe {
                (*(e.shared as *const Shared)).writes.load(std::sync::atomic::Ordering::SeqCst)
            }),
            _ => None,
        })
    }

    pub(super) fn writable(fd: i32) -> bool {
        let shared = with_reg(|m| match m.get(&fd) {
            Some(Special::Event(e)) => Some(e.shared),
            _ => None,
        });
        shared.is_some_and(|sh| locked(sh, |c| *c < u64::MAX - 1))
    }

    pub(super) fn anon_name(fd: i32) -> Option<&'static str> {
        with_reg(|m| match m.get(&fd)? {
            Special::Event(_) => Some("[eventfd]"),
            Special::Timer(_) => Some("[timerfd]"),
        })
    }

    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub(super) fn hold<R>(f: impl FnOnce() -> R) -> R {
        let _g = REG.lock();
        f()
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
        if flags & !(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK) != 0 {
            return err(errno::EINVAL);
        }
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return last_error();
        }
        // The write end is fwe's: out of the guest's reach.
        let wfd = match crate::fdtable::reserve(fds[1]) {
            Ok(w) => w,
            Err(e) => {
                // SAFETY: closing the read end made above.
                unsafe { libc::close(fds[0]) };
                return err(e);
            }
        };
        let rfd = fds[0];
        crate::exclusive::made(rfd);
        if flags & EFD_CLOEXEC != 0 {
            set_cloexec(rfd);
        }
        if flags & EFD_NONBLOCK != 0 {
            // SAFETY: plain host calls on the descriptor just made.
            unsafe {
                libc::fcntl(rfd, libc::F_SETFL, libc::fcntl(rfd, libc::F_GETFL) | libc::O_NONBLOCK)
            };
        }
        let (mfd, shared) = match new_shared(initval) {
            Ok(v) => v,
            Err(e) => {
                // SAFETY: closing the pipe made above.
                unsafe {
                    libc::close(rfd);
                    libc::close(wfd);
                }
                return err(e);
            }
        };
        let ev = EventFd {
            rfd,
            wfd,
            mfd,
            shared,
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

    pub unsafe fn timerfd_create(clockid: u64, flags: u64) -> i64 {
        use fwe_abi::clock::*;
        use fwe_abi::timerfd::*;
        // The clocks a timer may follow, and the flags Linux knows.
        let clocks = [
            CLOCK_REALTIME,
            CLOCK_MONOTONIC,
            CLOCK_BOOTTIME,
            CLOCK_REALTIME_ALARM,
            CLOCK_BOOTTIME_ALARM,
        ];
        if !clocks.contains(&clockid) || flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
            return err(errno::EINVAL);
        }
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
                    clock: crate::host::clock_to_host(clockid).unwrap_or(libc::CLOCK_MONOTONIC),
                    nonblock: flags & TFD_NONBLOCK != 0,
                    interval: (0, 0),
                    value: (0, 0),
                    first_at_ns: None,
                    period_ns: 0,
                    taken: 0,
                    extra: 0,
                }),
            )
        });
        kq as i64
    }

    pub unsafe fn timerfd_settime(fd: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
        use fwe_abi::timerfd::*;
        let fd = fd as i32;
        // In Linux's order: the flags, the new time, then the descriptor.
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return err(errno::EINVAL);
        }
        let [iv_s, iv_ns, val_s, val_ns]: [i64; 4] = guest!(uaccess::read(new_value));
        if [iv_ns, val_ns].iter().any(|ns| !(0..1_000_000_000).contains(ns))
            || iv_s < 0
            || val_s < 0
        {
            return err(errno::EINVAL);
        }
        if let Err(e) = timer_fd_check(fd) {
            return err(e);
        }

        let value = val_s.saturating_mul(1_000_000_000).saturating_add(val_ns);
        let interval = iv_s.saturating_mul(1_000_000_000).saturating_add(iv_ns);
        let now = now_ns();
        let set = with_reg(|m| {
            let Some(Special::Timer(t)) = m.get_mut(&fd) else {
                return Err(errno::EINVAL);
            };
            // The old setting as `timerfd_gettime` reads it.
            let prev = (t.interval, time_left(t, now));
            t.interval = (iv_s, iv_ns);
            t.value = (val_s, val_ns);
            t.first_at_ns = if value == 0 {
                // A zero it_value disarms.
                None
            } else if flags & TFD_TIMER_ABSTIME != 0 {
                // A time on the timer's own clock, as the guest reads it,
                // placed on the monotonic clock the schedule is kept on.
                // One already past is due at once, the periods since it
                // counted as expiries.
                let mut c = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                // SAFETY: valid timespec out-parameter.
                unsafe { libc::clock_gettime(t.clock, &mut c) };
                let clock_now = c.tv_sec.saturating_mul(1_000_000_000) + c.tv_nsec;
                Some(now.saturating_add(value.saturating_sub(clock_now)))
            } else {
                Some(now.saturating_add(value))
            };
            t.period_ns = interval;
            t.taken = 0;
            match t.arm(now) {
                0 => Ok(prev),
                e => Err(-e as i32),
            }
        });
        let (prev_iv, prev_val) = match set {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        if old_value != 0 {
            guest!(uaccess::write(old_value, [prev_iv.0, prev_iv.1, prev_val.0, prev_val.1]));
        }
        0
    }

    /// What is left until timer `t` next expires at monotonic time `now`
    /// (nanoseconds), as `(seconds, nanoseconds)`: zero when disarmed, or
    /// a one-shot timer that has expired.
    fn time_left(t: &TimerFd, now: i64) -> (i64, i64) {
        let Some(first) = t.first_at_ns else {
            return (0, 0);
        };
        let left = if now < first {
            first - now
        } else if t.period_ns > 0 {
            t.period_ns - (now - first) % t.period_ns
        } else {
            0
        };
        (left / 1_000_000_000, left % 1_000_000_000)
    }

    /// The host timer of a timerfd, in nanoseconds and on time
    /// (`NOTE_CRITICAL`: the host's usual leeway can make it fire a
    /// millisecond or more late).
    fn timer_kevent(flags: u16, period_ns: i64) -> libc::kevent {
        libc::kevent {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags,
            fflags: libc::NOTE_NSECONDS | libc::NOTE_CRITICAL,
            data: period_ns as libc::intptr_t,
            udata: std::ptr::null_mut(),
        }
    }

    /// `fd` is open (`EBADF`) and a timerfd (`EINVAL`).
    fn timer_fd_check(fd: i32) -> Result<(), i32> {
        // SAFETY: F_GETFD only queries.
        if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(errno::EBADF);
        }
        if with_reg(|m| matches!(m.get(&fd), Some(Special::Timer(_)))) {
            Ok(())
        } else {
            Err(errno::EINVAL)
        }
    }

    /// Whether `fd` is a timerfd that does not block, if it is one.
    pub fn timer_nonblock(fd: i32) -> Option<bool> {
        with_reg(|m| match m.get(&fd) {
            Some(Special::Timer(t)) => Some(t.nonblock),
            _ => None,
        })
    }

    /// `F_SETFL`'s `O_NONBLOCK` on timerfd `fd` (which the host takes on no
    /// kqueue): whether it was one.
    pub fn set_timer_nonblock(fd: i32, on: bool) -> bool {
        with_reg(|m| match m.get_mut(&fd) {
            Some(Special::Timer(t)) => {
                t.nonblock = on;
                true
            }
            _ => false,
        })
    }

    pub unsafe fn timerfd_gettime(fd: u64, curr_value: u64) -> i64 {
        let fd = fd as i32;
        if let Err(e) = timer_fd_check(fd) {
            return err(e);
        }
        match with_reg(|m| match m.get(&fd) {
            Some(Special::Timer(t)) => Some((t.interval, time_left(t, now_ns()))),
            _ => None,
        }) {
            Some((iv, val)) => {
                guest!(uaccess::write(curr_value, [iv.0, iv.1, val.0, val.1]));
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
                        let (rfd, semaphore) = (e.rfd, e.semaphore);
                        let taken = locked(e.shared, |count| {
                            if *count == 0 {
                                return None;
                            }
                            let v = if semaphore { 1 } else { *count };
                            *count -= v;
                            if *count == 0 {
                                // SAFETY: a byte is present while the count is
                                // not 0.
                                unsafe { drain(rfd) };
                            }
                            Some(v)
                        });
                        match taken {
                            Some(v) => Some(match uaccess::write(buf, v) {
                                Ok(()) => 8,
                                Err(e) => err(e),
                            }),
                            // Non-blocking as the descriptor is now (its
                            // own flag, which `fcntl` shows and changes).
                            // SAFETY: F_GETFL only queries the descriptor.
                            None if unsafe { libc::fcntl(rfd, libc::F_GETFL) }
                                & libc::O_NONBLOCK
                                != 0 =>
                            {
                                Some(err(errno::EAGAIN))
                            }
                            None => None,
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
                let count = loop {
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
                    // The expiries due since the last read, and the host
                    // timer armed for the next.
                    let now = now_ns();
                    let due = with_reg(|m| match m.get_mut(&fd) {
                        Some(Special::Timer(t)) => {
                            let total = t.expired(now);
                            let due = total.saturating_sub(t.taken).saturating_add(t.extra);
                            t.taken = t.taken.max(total);
                            t.extra = 0;
                            t.arm(now);
                            due
                        }
                        _ => 0,
                    });
                    if due > 0 {
                        break due;
                    }
                    // The host timer fired early or for a replaced setting.
                    if nonblock {
                        return Some(err(errno::EAGAIN));
                    }
                };
                match uaccess::write(buf, count) {
                    Ok(()) => 8,
                    Err(e) => err(e),
                }
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
        let add: u64 = match uaccess::read(buf) {
            Ok(v) => v,
            Err(e) => return Some(err(e)),
        };
        if add == u64::MAX {
            return Some(err(errno::EINVAL));
        }
        // One that would take the count past its maximum waits, as Linux's
        // does, until a read makes room (or fails with `EAGAIN` when the
        // descriptor does not block); a signal the guest handles ends the
        // wait (`EINTR`). Reads are looked for every millisecond: a count
        // this near its maximum is rare, and the wait keeps no hold on the
        // counter, which a close may unmap.
        loop {
            let r = add_to(fd, add);
            if r != err(errno::EAGAIN) {
                return Some(r);
            }
            let Some(rfd) = with_reg(|m| match m.get(&fd) {
                Some(Special::Event(e)) => Some(e.rfd),
                _ => None,
            }) else {
                return Some(err(errno::EBADF));
            };
            // SAFETY: F_GETFL only queries the descriptor.
            if unsafe { libc::fcntl(rfd, libc::F_GETFL) } & libc::O_NONBLOCK != 0 {
                return Some(r);
            }
            // The write waits for room, as Linux's sleeps.
            crate::procstore::guest_sleep(std::time::Duration::from_millis(1));
            if crate::thread::deliverable() != 0 {
                return Some(err(errno::EINTR));
            }
        }
    }

    /// Add `add` to eventfd `fd`'s count: 8, or `EAGAIN` past its maximum.
    pub fn add_to(fd: i32, add: u64) -> i64 {
        with_reg(|m| {
            let Some(Special::Event(e)) = m.get_mut(&fd) else {
                return err(errno::EBADF);
            };
            let (rfd, wfd, shared) = (e.rfd, e.wfd, e.shared);
            locked(shared, |count| {
                // The count stops at u64::MAX - 1.
                if add > u64::MAX - 1 - *count {
                    return err(errno::EAGAIN);
                }
                let was_zero = *count == 0;
                *count += add;
                // SAFETY: the eventfd's own mapped `Shared`, mapped while
                // it is registered (the registry is held).
                let sh = unsafe { &*(shared as *const Shared) };
                sh.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if was_zero && *count > 0 {
                    // SAFETY: the pipe holds at most one byte.
                    unsafe { poke(wfd) };
                } else if *count > 0 {
                    // Readable still, and a new edge to Linux's waiters:
                    // a byte written fires the host's watchers, and one
                    // read back leaves the pipe its one byte (the
                    // counter's lock keeps readers out meanwhile).
                    // SAFETY: the pipe holds one byte, so neither blocks.
                    unsafe {
                        poke(wfd);
                        drain(rfd);
                    }
                }
                8
            })
        })
    }

    pub fn close(fd: i32) -> Option<i64> {
        let s = REG.if_used()?.as_mut()?.remove(&fd)?;
        // SAFETY: these descriptors were opened by this module and are ours.
        unsafe {
            match s {
                Special::Event(e) => {
                    libc::close(e.rfd);
                    libc::close(e.wfd);
                    libc::close(e.mfd);
                    // This process's mapping of the counter (another that
                    // shares it keeps its own).
                    libc::munmap(e.shared as *mut libc::c_void, std::mem::size_of::<Shared>());
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
#[allow(clippy::disallowed_methods)] // tests sleep as they like
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

    /// A write that would take the count past its maximum waits for a
    /// read, or is `EAGAIN` when the descriptor does not block.
    #[test]
    fn eventfd_overflowing_write_waits_for_a_read() {
        // SAFETY: no pointers.
        let fd = unsafe { eventfd2(0, 0) } as i32;
        assert_eq!(write_u64(fd, u64::MAX - 2), 8);
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            read_u64(fd)
        });
        let start = std::time::Instant::now();
        assert_eq!(write_u64(fd, 5), 8);
        assert!(start.elapsed() >= std::time::Duration::from_millis(40));
        assert_eq!(reader.join().unwrap(), 8);
        let mut v = 0u64;
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 5);
        assert_eq!(close_fd(fd), 0);
        // SAFETY: no pointers.
        let fd = unsafe { eventfd2(0, EFD_NONBLOCK) } as i32;
        assert_eq!(write_u64(fd, u64::MAX - 2), 8);
        assert_eq!(write_u64(fd, 5), fwe_abi::err(fwe_abi::errno::EAGAIN));
        assert_eq!(close_fd(fd), 0);
    }

    #[test]
    fn eventfd_flags_are_checked() {
        // SAFETY: no pointers.
        assert_eq!(unsafe { eventfd2(0, 0o10) }, fwe_abi::err(fwe_abi::errno::EINVAL));
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

    /// `TFD_IOC_SET_TICKS` sets what the next read returns, readable at
    /// once, whether or not the timer is armed; 0 is `EINVAL` and another
    /// request `ENOTTY`.
    #[cfg(target_os = "macos")]
    #[test]
    fn timerfd_ticks_are_set() {
        // SAFETY: no pointers.
        let fd = unsafe { timerfd_create(1, 0o4000) } as i32;
        assert!(fd >= 0);
        assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN));
        let ticks = 7u64;
        let at = &ticks as *const u64 as u64;
        assert_eq!(timer_ioctl(fd, TFD_IOC_SET_TICKS, at), Some(0));
        let mut v = 0u64;
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 7);
        assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN));
        let zero = 0u64;
        let at = &zero as *const u64 as u64;
        let r = timer_ioctl(fd, TFD_IOC_SET_TICKS, at);
        assert_eq!(r, Some(fwe_abi::err(fwe_abi::errno::EINVAL)));
        assert_eq!(timer_ioctl(fd, 0x5401, 0), Some(fwe_abi::err(fwe_abi::errno::ENOTTY)));
        assert_eq!(timer_ioctl(-1, TFD_IOC_SET_TICKS, at), None);
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
        // Some of its time is left, at most what it was set to.
        let mut cur = [0i64; 4];
        // SAFETY: `cur` is a writable itimerspec.
        assert_eq!(unsafe { timerfd_gettime(fd as u64, cur.as_mut_ptr() as u64) }, 0);
        assert!(cur[2] == 0 && cur[3] > 0 && cur[3] <= 40_000_000, "{cur:?}");
        std::thread::sleep(std::time::Duration::from_millis(80));
        let mut v: u64 = 0;
        // Read well after it fired: it fired once, as a one-shot timer does.
        let n = read_into(fd, &mut v);
        assert_eq!(n, 8);
        assert_eq!(v, 1, "expirations");
        // Expired: disarmed.
        // SAFETY: as above.
        assert_eq!(unsafe { timerfd_gettime(fd as u64, cur.as_mut_ptr() as u64) }, 0);
        assert_eq!(cur, [0; 4]);
        assert_eq!(close_fd(fd), 0);
    }

    /// Now on clock `id` (a guest clock id), in nanoseconds.
    fn clock_ns(id: u64) -> i64 {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let hid = crate::host::clock_to_host(id).unwrap();
        // SAFETY: valid timespec out-parameter.
        unsafe { libc::clock_gettime(hid, &mut t) };
        t.tv_sec * 1_000_000_000 + t.tv_nsec
    }

    #[test]
    fn timerfd_absolute_time_is_on_its_own_clock() {
        use fwe_abi::clock::*;
        use fwe_abi::timerfd::*;
        for id in [CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_REALTIME] {
            // SAFETY: no pointers.
            let fd = unsafe { timerfd_create(id, TFD_NONBLOCK) } as i32;
            assert!(fd >= 0);
            // Due 60 ms from now on its clock.
            let at = clock_ns(id) + 60_000_000;
            let spec: [i64; 4] = [0, 0, at / 1_000_000_000, at % 1_000_000_000];
            // SAFETY: `spec` is a valid itimerspec; no old_value.
            let r =
                unsafe { timerfd_settime(fd as u64, TFD_TIMER_ABSTIME, spec.as_ptr() as u64, 0) };
            assert_eq!(r, 0);
            let mut cur = [0i64; 4];
            // SAFETY: `cur` is a writable itimerspec.
            assert_eq!(unsafe { timerfd_gettime(fd as u64, cur.as_mut_ptr() as u64) }, 0);
            assert!(cur[2] == 0 && cur[3] > 30_000_000 && cur[3] <= 60_000_000, "{id}: {cur:?}");
            // Not due yet.
            assert_eq!(read_u64(fd), fwe_abi::err(fwe_abi::errno::EAGAIN), "clock {id}");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let mut v = 0u64;
            assert_eq!(read_into(fd, &mut v), 8, "clock {id}");
            assert_eq!(v, 1);
            assert_eq!(close_fd(fd), 0);
        }
    }

    #[test]
    fn timerfd_absolute_time_past_counts_its_periods() {
        use fwe_abi::clock::*;
        use fwe_abi::timerfd::*;
        // SAFETY: no pointers.
        let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK) } as i32;
        // First due 10.5 s ago, every second: 11 expiries at once, the
        // next half a second away (however slowly the test runs).
        let at = clock_ns(CLOCK_MONOTONIC) - 10_500_000_000;
        let spec: [i64; 4] = [1, 0, at / 1_000_000_000, at % 1_000_000_000];
        // SAFETY: as above.
        let r = unsafe { timerfd_settime(fd as u64, TFD_TIMER_ABSTIME, spec.as_ptr() as u64, 0) };
        assert_eq!(r, 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut v = 0u64;
        assert_eq!(read_into(fd, &mut v), 8);
        assert_eq!(v, 11);
        assert_eq!(close_fd(fd), 0);
    }

    #[test]
    fn timerfd_periodic_first_expires_at_its_value() {
        use fwe_abi::timerfd::*;
        // SAFETY: no pointers.
        let fd = unsafe { timerfd_create(1, TFD_NONBLOCK) } as i32;
        // First after 30 ms, then every 400 ms.
        let spec: [i64; 4] = [0, 400_000_000, 0, 30_000_000];
        let set = std::time::Instant::now();
        // SAFETY: as above.
        assert_eq!(unsafe { timerfd_settime(fd as u64, 0, spec.as_ptr() as u64, 0) }, 0);
        std::thread::sleep(std::time::Duration::from_millis(80));
        let mut v = 0u64;
        assert_eq!(read_into(fd, &mut v), 8);
        let again = read_u64(fd);
        let mut cur = [0i64; 4];
        // SAFETY: `cur` is a writable itimerspec.
        assert_eq!(unsafe { timerfd_gettime(fd as u64, cur.as_mut_ptr() as u64) }, 0);
        // A loaded host may sleep longer than asked: what is left is
        // measured against the time that passed.
        let passed = set.elapsed().as_nanos() as i64;
        if passed >= 420_000_000 {
            return;
        }
        assert_eq!(v, 1);
        // The next is an interval after the first.
        assert_eq!(again, fwe_abi::err(fwe_abi::errno::EAGAIN));
        assert_eq!(cur[1], 400_000_000);
        // (A millisecond's slack: the host times the timer on a clock of
        // its own.)
        assert!(
            cur[3] >= 429_000_000 - passed && cur[3] <= 350_000_000,
            "{cur:?} after {passed} ns"
        );
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
