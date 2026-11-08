//! Signals: delivery into guest handlers, `rt_sigreturn`, and the system
//! calls that send, block and wait for signals.
//!
//! Dispositions are process-wide (in [`Kernel`]); the blocked mask, the
//! alternate stack and pending signals are per thread (in [`crate::thread`]).
//! Signals with a host equivalent travel as host signals: `kill` sends the
//! host signal, and the backend passes each disposition to the host
//! ([`Platform::set_host_signal`]) so a signal from anywhere — another
//! process, the terminal, a timer, a child exiting — is caught by the backend
//! and recorded pending for the guest, with its sender, or takes the host's
//! action where that is ignoring it or continuing. A default action that
//! ends or stops the process is fwe's to take. The host never blocks a
//! caught signal ([`caught`]): fwe keeps it pending while the guest blocks
//! it. Signals with no host equivalent (the real-time signals), and caught
//! ones sent with `tgkill`, are recorded here directly; the real-time ones
//! only travel within the process.
//!
//! A frame carries the general-purpose registers and the floating-point and
//! SIMD state (an `fpsimd_context` record), as on Linux.

use crate::thread::{self, SigInfo};
use crate::{HostSignal, Kernel, Platform, Regs, guest, host, uaccess};
use fwe_abi::{Sigaction, Stack, err, errno, signal};

/// `PSTATE.BTYPE` for a handler entered as if by `blr` (Linux's
/// `PSR_BTYPE_C`).
const BTYPE_C: u64 = 0b10 << 10;

/// The guest's code is run with BTI in force (the hypervisor backend sets
/// it where the VM offers BTI).
static BTI: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Have signal handlers entered as Linux enters them with BTI in force.
pub fn set_bti(on: bool) {
    BTI.store(on, std::sync::atomic::Ordering::Relaxed);
}

// Offsets within `struct rt_sigframe` on arm64 (`siginfo` then `ucontext`).
const SIGINFO_SIZE: u64 = 128;
/// `si_addr` within `siginfo` (the `_sigfault` member), and where `si_pid`,
/// `si_uid` and `si_status` start for the other members.
const SI_ADDR_OFF: u64 = 16;
const SI_PID_OFF: u64 = 16;
const SI_UID_OFF: u64 = 20;
const SI_STATUS_OFF: u64 = 24;
/// `ucontext` start.
const UC_OFF: u64 = SIGINFO_SIZE;
/// `uc_stack` within `ucontext`.
const UC_STACK_OFF: u64 = UC_OFF + 16;
/// `uc_sigmask` within `ucontext`.
const UC_SIGMASK_OFF: u64 = UC_OFF + 40;
/// `uc_mcontext` (a `struct sigcontext`) within `ucontext`: after the
/// 8-byte `uc_flags`, `uc_link`, the 24-byte `uc_stack`, the 8-byte
/// `uc_sigmask` and the 120 bytes padding it to 1024 bits, rounded up to the
/// 16-byte alignment `sigcontext` carries (its `__reserved` is aligned 16).
const UC_MCONTEXT_OFF: u64 = UC_OFF + 176;
/// `regs[31]` within `sigcontext` (after `fault_address`).
const MC_REGS_OFF: u64 = UC_MCONTEXT_OFF + 8;
const MC_SP_OFF: u64 = MC_REGS_OFF + 31 * 8;
const MC_PC_OFF: u64 = MC_SP_OFF + 8;
const MC_PSTATE_OFF: u64 = MC_PC_OFF + 8;
/// `__reserved` within `sigcontext`, holding FP/SVE records: 16-byte aligned,
/// so 8 bytes of padding follow `pstate`.
const MC_RESERVED_OFF: u64 = UC_MCONTEXT_OFF + 288;
/// Total frame size: through the 4096-byte `__reserved` area.
const FRAME_SIZE: u64 = MC_RESERVED_OFF + 4096;
/// Within the `fpsimd_context` record: `fpsr`, `fpcr`, then `vregs[32]`.
const FPSIMD_FPSR_OFF: u64 = 8;
const FPSIMD_FPCR_OFF: u64 = 12;
const FPSIMD_VREGS_OFF: u64 = 16;

/// The relayed signals the host delivers to the backend's handler
/// ([`HostSignal::Catch`]). The host never blocks these for the guest: a
/// signal macOS leaves pending while blocked loses its sender, so the
/// handler takes each one as it arrives and fwe keeps it pending, with its
/// sender, while the guest blocks it (see [`host::host_mask_for`]).
static CAUGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The relayed signals the host delivers to the backend's handler.
pub fn caught() -> u64 {
    CAUGHT.load(std::sync::atomic::Ordering::SeqCst)
}

/// The relayed signals the guest ignores (`SIG_IGN`) that the host catches
/// all the same: Linux keeps one pending while it is blocked (for a
/// `sigwaitinfo`, or until it is unblocked and dropped), which a host that
/// discards it cannot. One that arrives unblocked is dropped as it lands
/// ([`thread::post_landed`]).
static IGNORED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The signals the guest ignores whose host signal is caught ([`IGNORED`]).
pub fn ignored() -> u64 {
    IGNORED.load(std::sync::atomic::Ordering::SeqCst)
}

/// How many `rt_sigtimedwait` calls are waiting for each signal; while any
/// is, the host catches it whatever its disposition.
static WAITERS: [std::sync::atomic::AtomicU32; signal::NSIG as usize] =
    [const { std::sync::atomic::AtomicU32::new(0) }; signal::NSIG as usize];

const fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}

/// A signal frame (or `siginfo`) assembled or parsed in fwe's memory and
/// copied to or from the guest in one checked access.
struct Buf(Vec<u8>);

impl Buf {
    fn zeroed(len: u64) -> Buf {
        Buf(vec![0; len as usize])
    }
    fn put(&mut self, off: u64, val: u64) {
        self.0[off as usize..off as usize + 8].copy_from_slice(&val.to_ne_bytes());
    }
    fn put32(&mut self, off: u64, val: i32) {
        self.0[off as usize..off as usize + 4].copy_from_slice(&val.to_ne_bytes());
    }
    fn get(&self, off: u64) -> u64 {
        u64::from_ne_bytes(self.0[off as usize..off as usize + 8].try_into().unwrap())
    }
    fn get32(&self, off: u64) -> u32 {
        u32::from_ne_bytes(self.0[off as usize..off as usize + 4].try_into().unwrap())
    }
}

/// The `siginfo` fields fwe fills in, at offset 0 of `buf`.
fn put_siginfo(buf: &mut Buf, sig: u64, info: SigInfo, fault_addr: u64) {
    buf.put32(0, sig as i32); // si_signo
    buf.put32(8, info.code); // si_code
    if sig == signal::SIGSYS && info.code == SYS_SECCOMP {
        // `_sigsys`: the call's address (kept in `pid` and `uid`), its
        // number and the architecture; the filter's data is `si_errno`.
        buf.put32(4, info.status >> 16);
        buf.put32(SI_PID_OFF, info.pid);
        buf.put32(SI_UID_OFF, info.uid as i32);
        buf.put32(SI_STATUS_OFF, info.status & 0xffff);
        buf.put32(SI_STATUS_OFF + 4, crate::seccomp::AUDIT_ARCH_AARCH64 as i32);
    } else if fault_addr != 0 {
        buf.put(SI_ADDR_OFF, fault_addr);
    } else if let Some((fd, band)) = info.poll {
        // `_sigpoll`: the events and the descriptor.
        buf.put(SI_PID_OFF, band as u64);
        buf.put32(SI_STATUS_OFF, fd);
    } else {
        // Recorded as the host pid; the guest sees its own namespace's. A
        // signal from the kernel names no sender.
        if info.code != signal::SI_KERNEL {
            buf.put32(SI_PID_OFF, guest_pid(info.pid));
            buf.put32(SI_UID_OFF, crate::userns::to_ns(info.uid, false) as i32);
        }
        if queued(info.code) {
            // `si_value`, where a child's status is for `SIGCHLD`.
            buf.put(SI_STATUS_OFF, info.value);
        } else {
            buf.put32(SI_STATUS_OFF, info.status);
        }
    }
}

/// A `SIGIO` the host raised for an owned descriptor's readiness (one no
/// process sent) is, as on Linux, the signal that descriptor's `F_SETSIG`
/// chose, carrying the descriptor and its events (`POLL_IN` and the like);
/// the host knows only `SIGIO`.
fn route_io_signal() {
    if thread::pending() & bit(signal::SIGIO) == 0 {
        return;
    }
    let Some(info) = thread::take_pending(signal::SIGIO) else { return };
    // Only the host's own: another process's (a lease break's) names it.
    if info.code != signal::SI_KERNEL || info.pid != 0 {
        thread::post_process(signal::SIGIO, info);
        return;
    }
    let Some((fd, sig, tid)) = crate::fdstate::io_signal() else {
        // The host's, for no descriptor set to signal now (one closed since
        // the event): Linux would send none.
        if crate::fdstate::any_async() {
            thread::post_process(signal::SIGIO, info);
        }
        return;
    };
    let mut p =
        libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT | libc::POLLPRI, revents: 0 };
    // SAFETY: one valid pollfd, not waited on.
    unsafe { libc::poll(&mut p, 1, 0) };
    let ev = p.revents;
    // Linux's `si_code` for the events, and `si_band` as `poll` reports
    // them.
    let code = if ev & libc::POLLHUP != 0 {
        6
    } else if ev & libc::POLLIN != 0 {
        1
    } else if ev & libc::POLLOUT != 0 {
        2
    } else if ev & libc::POLLPRI != 0 {
        5
    } else {
        1
    };
    // The basic poll bits are Linux's on the host too.
    let band = i64::from(ev);
    let info = SigInfo { code, poll: Some((fd, band)), ..SigInfo::default() };
    match tid {
        Some(t) => {
            thread::post_thread(t, sig as u64, info);
        }
        None => thread::post_process(sig as u64, info),
    }
}

/// Whether a signal of `si_code` `code` carries a value (`si_value`):
/// one queued with `sigqueue`, by a timer, a message queue or AIO.
fn queued(code: i32) -> bool {
    matches!(code, signal::SI_QUEUE | signal::SI_TIMER | signal::SI_MESGQ | signal::SI_ASYNCIO)
}

fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}

/// Whether Linux signal `sig` is relayed through the host: it has a host
/// equivalent and is not one the backend itself owns. `SIGKILL` and
/// `SIGSTOP` cannot be caught; `SIGTRAP`, `SIGSEGV`, `SIGBUS`, `SIGILL` and
/// `SIGFPE` are the synchronous faults the backend handles itself.
pub fn relayed(sig: u64) -> bool {
    host::signal_to_host(sig).is_some()
        && !matches!(
            sig,
            signal::SIGKILL
                | signal::SIGSTOP
                | signal::SIGTRAP
                | signal::SIGSEGV
                | signal::SIGBUS
                | signal::SIGILL
                | signal::SIGFPE
        )
}

/// Send Linux signal `sig`, which the host has no equivalent of, to fwe
/// process `host` (not this one), with `code` and `value`: queued in its
/// mailbox, and the process woken to take it ([`crate::signote::queue`]).
/// A process that is not fwe's cannot take it (`EINVAL`).
pub(crate) fn send_unhosted(host: i32, sig: u64, code: i32, value: u64) -> i64 {
    if host <= 0 || crate::procreg::read(host).is_none() {
        return err(errno::EINVAL);
    }
    if let Err(e) = crate::signote::queue(host, sig, code, value) {
        return err(e);
    }
    host::kill_process(host, host::WAKE_SIGNAL)
}

/// `kill` of this process with `sig` it takes itself (one the host lacks,
/// or one fwe keeps).
fn post_own(sig: u64) -> i64 {
    if !thread::may_queue(sig) {
        return err(errno::EAGAIN);
    }
    thread::post_process(sig, own_info(signal::SI_USER));
    // Any thread may take it: interrupt the others' waits so one that does
    // not block it notices.
    thread::wake_others(host::WAKE_SIGNAL);
    0
}

fn me_host() -> i64 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() as i64 }
}

fn owned(sig: u64) -> bool {
    matches!(
        sig,
        signal::SIGTRAP | signal::SIGSEGV | signal::SIGBUS | signal::SIGILL | signal::SIGFPE
    )
}

/// Whether Linux restarts system call `nr` after a handler with
/// `SA_RESTART` (the calls that wait for I/O or a child, not those that wait
/// for time or for a signal).
pub fn restartable(nr: u64, args: &[u64; 6]) -> bool {
    use fwe_abi::nr as n;
    match nr {
        n::READ
        | n::WRITE
        | n::READV
        | n::WRITEV
        | n::PREAD64
        | n::PWRITE64
        | n::WAIT4
        | n::WAITID
        | n::ACCEPT
        | n::ACCEPT4
        | n::RECVFROM
        | n::RECVMSG
        | n::SENDTO
        | n::SENDMSG
        | n::OPENAT
        | n::IOCTL
        | n::FLOCK
        | n::FCNTL
        | n::MQ_TIMEDSEND
        | n::MQ_TIMEDRECEIVE => true,
        // A futex wait without a timeout.
        n::FUTEX => args[3] == 0,
        _ => false,
    }
}

/// Move pending signals that the calling thread blocks and a `signalfd`
/// watches onto that `signalfd`, as Linux queues them there.
pub fn drain_to_signalfd() {
    route_io_signal();
    let mut ready = thread::pending() & thread::mask() & crate::signalfd::watched();
    while ready != 0 {
        let sig = ready.trailing_zeros() as u64 + 1;
        ready &= !bit(sig);
        if let Some(info) = thread::take_pending(sig) {
            let record = crate::signalfd::siginfo_full(
                sig as u32,
                info.code,
                guest_pid(info.pid),
                crate::userns::to_ns(info.uid, false),
                info.status,
                info.value,
            );
            crate::signalfd::deliver(sig, record);
        }
    }
}

/// A sender's or child's host pid as the guest sees it.
fn guest_pid(host: i32) -> i32 {
    if host != 0 && crate::pidns::nested() { crate::pidns::to_guest(host) } else { host }
}

/// `si_code` of the `SIGSYS` a seccomp filter raises.
const SYS_SECCOMP: i32 = 1;

/// The `SIGSYS` a seccomp filter's `SECCOMP_RET_TRAP` raises for call `nr`
/// at `pc`, with the filter's `data`.
pub(crate) fn raise_sigsys(pc: u64, nr: u64, data: u16) {
    let info = SigInfo {
        code: SYS_SECCOMP,
        pid: pc as u32 as i32,
        uid: (pc >> 32) as u32,
        status: (i32::from(data) << 16) | (nr as i32 & 0xffff),
        value: 0,
        poll: None,
    };
    thread::post_self(signal::SIGSYS, info);
}

/// Raise `sig` against the calling thread, as the kernel raises `SIGPIPE`
/// for a write that hit a closed peer.
pub(crate) fn raise_self(sig: u64) {
    thread::post_self(sig, own_info(signal::SI_KERNEL));
}

fn own_info(code: i32) -> SigInfo {
    // SAFETY: plain host calls.
    let pid = unsafe { libc::getpid() };
    SigInfo { code, pid, ..SigInfo::default() }
}

impl<P: Platform> Kernel<P> {
    /// Mark `sig` pending against the calling thread (a signal the kernel
    /// raises itself).
    #[cfg(test)]
    pub(crate) fn raise_pending(&mut self, sig: u64) {
        thread::post_self(sig, own_info(signal::SI_KERNEL));
    }

    /// Tell the host how to treat relayed signal `sig`, from its disposition
    /// and whether a `signalfd` reads it.
    pub(crate) fn sync_host_signal(&mut self, sig: u64) {
        if !relayed(sig) {
            return;
        }
        let action = self.sigactions[(sig - 1) as usize];
        let watched = crate::signalfd::watched() & bit(sig) != 0
            || WAITERS[(sig - 1) as usize].load(std::sync::atomic::Ordering::SeqCst) > 0;
        // A default action that ends or stops the process is fwe's to take
        // too ([`Kernel::deliver_pending`]), not the host's: the host never
        // blocks a caught signal for the guest (see [`caught`]), so a
        // default action left to the host could strike a thread whose guest
        // mask blocks the signal, which Linux keeps pending instead.
        let fwe_default = matches!(
            signal::default_action(sig),
            signal::Default::Terminate | signal::Default::Stop
        );
        let how = match action.handler {
            _ if watched => HostSignal::Catch { flags: action.flags },
            signal::SIG_DFL if !fwe_default => HostSignal::Default,
            // An ignored `SIGCHLD` has the host reap the children.
            signal::SIG_IGN if sig == signal::SIGCHLD => HostSignal::Ignore,
            _ => HostSignal::Catch { flags: action.flags },
        };
        // Recorded first: from the moment the host catches it, the host
        // mask a thread takes on next leaves it unblocked.
        let ordering = std::sync::atomic::Ordering::SeqCst;
        if action.handler == signal::SIG_IGN && sig != signal::SIGCHLD {
            IGNORED.fetch_or(bit(sig), ordering);
        } else {
            IGNORED.fetch_and(!bit(sig), ordering);
        }
        if matches!(how, HostSignal::Catch { .. }) {
            CAUGHT.fetch_or(bit(sig), ordering);
            self.platform.set_host_signal(sig, how);
        } else {
            // Not caught any more: blocked again where the guest blocks it
            // from the next host mask a thread takes on.
            self.platform.set_host_signal(sig, how);
            CAUGHT.fetch_and(!bit(sig), ordering);
        }
        if sig == signal::SIGCHLD {
            // Whether the host now reaps the children as they end, which a
            // reaper adopting one must know (see `reaper`).
            crate::procreg::own_autoreap(host::children_reaped_by_host());
        }
    }

    pub(crate) fn sync_all_host_signals(&mut self) {
        for sig in 1..=signal::NSIG {
            self.sync_host_signal(sig);
        }
    }

    /// The handler the next pending signal will enter, if a handler (rather
    /// than a default action or nothing) is next.
    pub(crate) fn next_handler(&self) -> Option<Sigaction> {
        let mut ready = thread::deliverable();
        while ready != 0 {
            let sig = ready.trailing_zeros() as u64 + 1;
            ready &= !bit(sig);
            let action = self.sigactions[(sig - 1) as usize];
            if action.handler != signal::SIG_DFL && action.handler != signal::SIG_IGN {
                return Some(action);
            }
        }
        None
    }

    /// Act on the ready pending signals before returning to the guest:
    /// ignored ones are dropped, default actions are taken, and the first
    /// one with a handler enters it. Ends a finished `rt_sigsuspend` by
    /// restoring the mask it replaced, if no handler did.
    pub fn deliver_pending(&mut self, regs: &mut Regs) {
        thread::wake_others_if_asked(host::WAKE_SIGNAL);
        drain_to_signalfd();
        loop {
            let ready = thread::deliverable();
            if ready == 0 {
                break;
            }
            let sig = ready.trailing_zeros() as u64 + 1;
            let Some(info) = thread::take_pending(sig) else { continue };
            let action = self.sigactions[(sig - 1) as usize];
            match action.handler {
                signal::SIG_IGN => {}
                signal::SIG_DFL => match signal::default_action(sig) {
                    signal::Default::Terminate => self.terminate_with(sig, Some(regs)),
                    signal::Default::Stop => {
                        if let Some(h) = host::signal_to_host(sig) {
                            self.platform.stop_self(h);
                        }
                    }
                    signal::Default::Ignore | signal::Default::Continue => {}
                },
                _ => {
                    if self.deliver_to_handler(regs, sig, info, 0) {
                        break;
                    }
                    // No room for a frame, or a stack that cannot take one:
                    // Linux kills the process with SIGSEGV.
                    self.terminate_with(signal::SIGSEGV, Some(regs));
                }
            }
        }
        if let Some(mask) = thread::take_saved_mask() {
            thread::set_mask(mask);
        }
    }

    /// Terminate the process as killed by `sig`.
    pub(crate) fn terminate_by(&mut self, sig: u64) -> ! {
        self.terminate_with(sig, None)
    }

    /// Terminate the process as killed by `sig`, dumping core if `sig` does
    /// (with registers `regs`, where they are known).
    pub fn terminate_with(&mut self, sig: u64, regs: Option<&Regs>) -> ! {
        self.dump_core(sig, regs);
        crate::procreg::ending(sig as i32 | crate::coredump::status_bit());
        match crate::host::signal_to_host(sig) {
            Some(h) => self.platform.kill_self(h),
            None => self.platform.exit(128 + sig as i32),
        }
    }

    /// Build a signal frame and point `regs` at the handler for `sig`.
    /// Returns `false` without changing `regs` if `sig` has no handler or
    /// there is no room for a frame.
    pub(crate) fn deliver_to_handler(
        &mut self,
        regs: &mut Regs,
        sig: u64,
        info: SigInfo,
        fault_addr: u64,
    ) -> bool {
        let action = self.sigactions[(sig - 1) as usize];
        if action.handler == signal::SIG_DFL || action.handler == signal::SIG_IGN {
            return false;
        }
        if self.tracer.enabled && !self.tracer.failures_only {
            // As strace shows a delivery, with what the host gave the
            // signal it came as.
            let (code, pid) =
                crate::host::signal_to_host(sig).map_or((0, 0), crate::host::last_host_info);
            self.tracer.note(&format!(
                "--- signal {sig} {{si_code={}, si_pid={}, si_uid={}, si_value={:#x}}} (host: code {code:#x}, pid {pid}) ---",
                info.code, info.pid, info.uid, info.value
            ));
        }

        // Choose the stack: the alternate stack if requested and available.
        // A handler already running on the alternate stack keeps using it
        // from its current sp, as Linux does; starting over from the top would
        // overwrite the live frame beneath it.
        let altstack = thread::altstack();
        let alt_enabled = altstack.ss_flags & signal::SS_DISABLE == 0;
        let on_altstack = action.flags & signal::SA_ONSTACK != 0 && alt_enabled;
        let alt_top = altstack.ss_sp.wrapping_add(altstack.ss_size);
        let already_on_alt = alt_enabled && regs.sp >= altstack.ss_sp && regs.sp < alt_top;
        let base_sp = if on_altstack && !already_on_alt { alt_top } else { regs.sp };
        // If there is no room for a frame (e.g. a stack-overflow fault leaves sp
        // below FRAME_SIZE, or the chosen stack base is tiny), we cannot deliver
        // on this stack. Report it as undelivered rather than crashing `fwe`;
        // the caller then takes the default action and prints diagnostics.
        let frame = match base_sp.checked_sub(FRAME_SIZE) {
            Some(v) => align_down(v, 16),
            None => return false,
        };

        // An `rt_sigsuspend` in progress: the frame restores the mask from
        // before the call, and the handler runs with the call's mask.
        let mask = thread::mask();
        let old_mask_restore = thread::take_saved_mask();
        let old_mask = old_mask_restore.unwrap_or(mask);
        let mut f = Buf::zeroed(FRAME_SIZE);
        put_siginfo(&mut f, sig, info, fault_addr);
        // ucontext
        f.put(UC_STACK_OFF, altstack.ss_sp);
        f.put32(UC_STACK_OFF + 8, altstack.ss_flags);
        f.put(UC_STACK_OFF + 16, altstack.ss_size);
        f.put(UC_SIGMASK_OFF, old_mask);
        // sigcontext
        f.put(UC_MCONTEXT_OFF, fault_addr); // fault_address
        for (i, &v) in regs.x.iter().enumerate() {
            f.put(MC_REGS_OFF + i as u64 * 8, v);
        }
        f.put(MC_SP_OFF, regs.sp);
        f.put(MC_PC_OFF, regs.pc);
        f.put(MC_PSTATE_OFF, regs.pstate);
        // The FP/SIMD record, then the zero terminator (already zeroed).
        let fp = MC_RESERVED_OFF;
        f.put32(fp, signal::FPSIMD_MAGIC as i32);
        f.put32(fp + 4, signal::FPSIMD_CONTEXT_SIZE as i32);
        f.put32(fp + FPSIMD_FPSR_OFF, regs.fp.fpsr as i32);
        f.put32(fp + FPSIMD_FPCR_OFF, regs.fp.fpcr as i32);
        for (i, v) in regs.fp.v.iter().enumerate() {
            let at = fp + FPSIMD_VREGS_OFF + i as u64 * 16;
            f.put(at, *v as u64);
            f.put(at + 8, (*v >> 64) as u64);
        }
        if uaccess::write_from(frame, &f.0).is_err() {
            // The stack is not writable: Linux kills the process.
            if let Some(mask) = old_mask_restore {
                thread::save_mask(mask);
            }
            return false;
        }

        // Mask this and the handler's extra signals while it runs.
        let mut new_mask = mask | action.mask;
        if action.flags & signal::SA_NODEFER == 0 {
            new_mask |= bit(sig);
        }
        thread::set_mask(new_mask);
        if action.flags & signal::SA_RESETHAND != 0 {
            // The handler only, as Linux resets it: the flags and mask stay.
            self.sigactions[(sig - 1) as usize].handler = signal::SIG_DFL;
            self.sync_host_signal(sig);
        }

        // Enter the handler.
        let siginfo = action.flags & signal::SA_SIGINFO != 0;
        regs.x[0] = sig;
        regs.x[1] = if siginfo { frame } else { 0 };
        regs.x[2] = if siginfo { frame + UC_OFF } else { 0 };
        regs.x[30] = if action.flags & signal::SA_RESTORER != 0 {
            action.restorer
        } else {
            self.sigreturn_tramp
        };
        regs.sp = frame;
        regs.pc = action.handler;
        // Entered as if by `blr`: with BTI in use, the handler's first
        // instruction must be a landing pad, as Linux makes it.
        regs.pstate = if BTI.load(std::sync::atomic::Ordering::Relaxed) { BTYPE_C } else { 0 };
        true
    }

    /// Deliver synchronous fault signal `sig` (at `addr`) to a guest handler,
    /// returning `true` if a handler was entered. When `false`, the caller
    /// takes the default action (terminate).
    pub fn deliver_fault(&mut self, regs: &mut Regs, sig: u64, addr: u64) -> bool {
        let info = SigInfo { code: signal::SI_KERNEL, ..SigInfo::default() };
        self.deliver_to_handler(regs, sig, info, addr)
    }

    /// Restore `regs` from the signal frame at `regs.sp` (the `rt_sigreturn`
    /// system call). False if the frame is not readable.
    pub(crate) fn sys_rt_sigreturn(&mut self, regs: &mut Regs) -> bool {
        let Ok(bytes) = uaccess::read_bytes(regs.sp, (MC_RESERVED_OFF + 528) as usize) else {
            return false;
        };
        let f = Buf(bytes);
        for i in 0..31 {
            regs.x[i] = f.get(MC_REGS_OFF + i as u64 * 8);
        }
        regs.sp = f.get(MC_SP_OFF);
        regs.pc = f.get(MC_PC_OFF);
        regs.pstate = f.get(MC_PSTATE_OFF);
        let fp = MC_RESERVED_OFF;
        if f.get32(fp) == signal::FPSIMD_MAGIC {
            regs.fp.fpsr = f.get32(fp + FPSIMD_FPSR_OFF);
            regs.fp.fpcr = f.get32(fp + FPSIMD_FPCR_OFF);
            for (i, v) in regs.fp.v.iter_mut().enumerate() {
                let at = fp + FPSIMD_VREGS_OFF + i as u64 * 16;
                *v = f.get(at) as u128 | (f.get(at + 8) as u128) << 64;
            }
        }
        thread::set_mask(f.get(UC_SIGMASK_OFF));
        let ss_sp = f.get(UC_STACK_OFF);
        let ss_flags = f.get(UC_STACK_OFF + 8) as i32;
        let ss_size = f.get(UC_STACK_OFF + 16);
        thread::set_altstack(Stack { ss_sp, ss_flags, _pad: 0, ss_size });
        true
    }

    /// `kill(pid, sig)`. A relayed signal is sent as the host signal to
    /// whatever `pid` names (a process, `0` for the caller's process group,
    /// or `-pgid`); the host delivers it, to this process too. `-1` is every
    /// other process of the caller's pid namespace, or outside one, of the
    /// caller's run of fwe ([`Kernel::kill_every`]): never the host's other
    /// processes. A signal with no host equivalent can only be sent within
    /// this process.
    pub(crate) fn sys_kill(&mut self, pid: i64, sig: u64) -> i64 {
        if sig > signal::NSIG {
            return err(errno::EINVAL);
        }
        // A `pid_t`: the register's low half. Its least value has no
        // negation, so names no group (Linux refuses it so).
        let pid = pid as i32;
        if pid == i32::MIN {
            return err(errno::ESRCH);
        }
        let me = thread::tgid() as i64;
        // Another thread's id names its process, as on Linux.
        let pid = if pid > 0 && thread::host_thread(pid).is_some() { me } else { pid as i64 };
        // The host process (or group) `pid` names in the guest's pid
        // namespace.
        let target = match pid {
            0 | -1 => pid,
            p if p > 0 => match crate::pidns::to_host(p as i32) {
                Some(h) => h as i64,
                None => return err(errno::ESRCH),
            },
            p => match crate::pidns::to_host(-p as i32) {
                Some(h) => -(h as i64),
                None => return err(errno::ESRCH),
            },
        };
        if pid == -1 {
            return self.kill_every(sig);
        }
        if target > 0 && target != me_host() && !self.may_signal(target as i32, sig) {
            // SAFETY: plain host call; signal 0 only checks the target.
            let exists = unsafe { libc::kill(target as libc::pid_t, 0) } == 0
                || host::last_errno() == libc::EPERM;
            return err(if exists { errno::EPERM } else { errno::ESRCH });
        }
        if sig == 0 {
            // SAFETY: plain host call; signal 0 only checks the target.
            return host::ret(unsafe { libc::kill(target as libc::pid_t, 0) });
        }
        // A pid namespace's init cannot be killed or stopped from inside it
        // (it has no handler for either), as on Linux.
        if matches!(sig, signal::SIGKILL | signal::SIGSTOP)
            && target > 0
            && crate::pidns::current()
                .first()
                .is_some_and(|ns| ns.get().host_of(1) == Some(target as i32))
        {
            return 0;
        }
        let to_self = pid == me || pid == 0;
        if let Some(h) = host::signal_to_host(sig).filter(|_| !(to_self && owned(sig))) {
            // A namespace's init takes its namespace with it.
            let led = (sig == signal::SIGKILL && target > 0)
                .then(|| crate::pidns::led_by(target as i32))
                .flatten();
            // A note of the sender for another process; and for this one's
            // own SIGIO, which without one is taken for the host's I/O signal.
            let noted = target > 0 && (!to_self || sig == signal::SIGIO);
            if noted {
                crate::signote::note(target as i32, h);
            }
            let r = host::kill(target as libc::pid_t, h);
            if r != 0 && noted {
                crate::signote::unnote(target as i32, h);
            }
            if r == 0
                && let Some(ns) = led
            {
                crate::pidns::zap(&ns, target as i32);
            }
            return r;
        }
        if to_self && pid != 0 {
            return post_own(sig);
        }
        if target > 0 {
            return send_unhosted(target as i32, sig, signal::SI_USER, 0);
        }
        // A process group: each of its processes (this one too, when in it).
        // SAFETY: getpgrp cannot fail.
        let pgid = if target == 0 { unsafe { libc::getpgrp() } } else { -target as i32 };
        let mut r = err(errno::ESRCH);
        for member in host::group_members(pgid) {
            let one = if i64::from(member) == me_host() {
                post_own(sig)
            } else if !self.may_signal(member, sig) {
                err(errno::EPERM)
            } else if let Some(h) = host::signal_to_host(sig) {
                crate::signote::note(member, h);
                let r = host::kill_process(member, h);
                if r != 0 {
                    crate::signote::unnote(member, h);
                }
                r
            } else {
                send_unhosted(member, sig, signal::SI_USER, 0)
            };
            if r != 0 {
                r = one;
            }
        }
        r
    }

    /// `kill(-1, sig)`: every process the caller may signal but itself
    /// and its namespace's init, as on Linux. In a pid namespace of fwe's,
    /// the processes in it; outside one, those of the caller's run of fwe
    /// ([`crate::procreg::run`]), so a guest never signals the host's other
    /// processes. As on Linux, one the caller may not signal is passed
    /// over, and the result is that of the last one signalled otherwise.
    fn kill_every(&mut self, sig: u64) -> i64 {
        let me = me_host() as i32;
        let targets: Vec<i32> = match crate::pidns::current().first() {
            Some(ns) => ns
                .get()
                .pids
                .iter()
                .filter(|(n, e)| !e.thread && **n != 1 && e.host != 0)
                .map(|(_, e)| e.host)
                .collect(),
            None => crate::procreg::run(),
        };
        let mut count = 0;
        let mut ret = 0;
        for host in targets.into_iter().filter(|&h| h != me) {
            count += 1;
            if !self.may_signal(host, sig) {
                continue;
            }
            let r = match (sig, host::signal_to_host(sig)) {
                (0, _) => 0,
                (_, Some(h)) => {
                    crate::signote::note(host, h);
                    let r = host::kill_process(host, h);
                    if r != 0 {
                        crate::signote::unnote(host, h);
                    }
                    r
                }
                (_, None) => send_unhosted(host, sig, signal::SI_USER, 0),
            };
            if r != err(errno::EPERM) {
                ret = r;
            }
        }
        if count == 0 { err(errno::ESRCH) } else { ret }
    }

    /// Whether the caller may send `sig` to host process `target` (Linux's
    /// `check_kill_permission`): with `CAP_KILL`, when its real or
    /// effective user id is the target's real or saved one, or `SIGCONT`
    /// within its session. A process fwe has no record of counts as root's.
    fn may_signal(&self, target: i32, sig: u64) -> bool {
        if self.creds.has(crate::caps::CAP_KILL) {
            return true;
        }
        let ids = crate::procreg::ids(target);
        if [self.creds.uid, self.creds.euid].iter().any(|&u| u == ids[0] || u == ids[2]) {
            return true;
        }
        // SAFETY: plain host calls.
        sig == signal::SIGCONT && unsafe { libc::getsid(target) == libc::getsid(0) }
    }

    /// `tgkill(tgid, tid, sig)`, and `tkill(tid, sig)` as `tgid == -1`: send
    /// `sig` to one thread of this process. A relayed signal is sent to that
    /// host thread; any other is recorded pending against the thread, which
    /// is woken to take it.
    pub(crate) fn sys_tgkill(&mut self, tgid: i64, tid: i64, sig: u64) -> i64 {
        if sig > signal::NSIG || tid <= 0 || tgid == 0 || tgid < -1 {
            return err(errno::EINVAL);
        }
        let me = thread::tgid() as i64;
        if tgid != -1 && tgid != me {
            // A thread of another process: only its main thread is
            // reachable, through the process.
            return if tid == tgid { self.sys_kill(tid, sig) } else { err(errno::ESRCH) };
        }
        // A tid not registered here is not a thread of this process (an
        // exited one's number may already be another process's pid).
        let Some(host_thread) = thread::host_thread(tid as i32) else {
            return err(errno::ESRCH);
        };
        if sig == 0 {
            return 0;
        }
        if sig == signal::SIGKILL {
            // It ends the whole process, whichever thread it names.
            return self.sys_kill(me, sig);
        }
        if !thread::may_queue(sig) {
            return err(errno::EAGAIN);
        }
        // A signal the backend's handler catches is posted to the thread
        // directly, with the wake signal to interrupt it: sent as a host
        // signal, it would land on a thread that blocks it as if it were the
        // process's (see [`thread::post_landed`]).
        let r = match host::signal_to_host(sig).filter(|_| !owned(sig) && caught() & bit(sig) == 0)
        {
            // SAFETY: `host_thread` is a live registered guest thread.
            Some(h) if host_thread != 0 => unsafe { libc::pthread_kill(host_thread, h) },
            // Not started yet: it takes the signal at its first system call.
            Some(_) => {
                thread::post_thread(tid as i32, sig, own_info(signal::SI_TKILL));
                0
            }
            None => {
                thread::post_thread(tid as i32, sig, own_info(signal::SI_TKILL));
                if tid as i32 == thread::tid() || host_thread == 0 {
                    0
                } else {
                    // SAFETY: as above; the wake signal interrupts a blocking
                    // call so the thread takes the signal promptly.
                    unsafe { libc::pthread_kill(host_thread, host::WAKE_SIGNAL) }
                }
            }
        };
        if r == 0 { 0 } else { err(host::errno_to_linux(r)) }
    }

    /// Have the host catch the relayed signals in `want` for the duration of
    /// an [`sigtimedwait`]; [`Kernel::end_wait`] puts them back.
    pub fn catch_for_wait(&mut self, want: u64) {
        for sig in 1..=signal::NSIG {
            if want & bit(sig) != 0 {
                WAITERS[(sig - 1) as usize].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.sync_host_signal(sig);
            }
        }
    }

    /// Restore the host dispositions [`Kernel::catch_for_wait`] changed.
    pub fn end_wait(&mut self, want: u64) {
        for sig in 1..=signal::NSIG {
            if want & bit(sig) != 0 {
                WAITERS[(sig - 1) as usize].fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                self.sync_host_signal(sig);
            }
        }
    }

    /// `rt_sigpending(set, size)`: the signals pending and blocked.
    pub(crate) fn sys_rt_sigpending(&mut self, set: u64, size: u64) -> i64 {
        if size > signal::SIGSET_SIZE {
            return err(errno::EINVAL);
        }
        let pending = (thread::pending() | host::pending_signals()) & thread::mask();
        guest!(uaccess::write(set, pending));
        0
    }
}

/// Run a waiting call that takes a signal mask (`ppoll`, `epoll_pwait`)
/// with the calling thread's mask replaced by the one at `set`, if non-null,
/// as Linux does. If a signal interrupts the call, the mask stays replaced
/// until it is delivered and the frame restores the original (as for
/// [`sigsuspend`]); otherwise it is restored as the call returns.
///
/// # Safety
/// `set` must be null or point to a guest `sigset_t`.
pub(crate) unsafe fn with_call_mask(set: u64, call: impl FnOnce() -> i64) -> i64 {
    if set == 0 {
        return call();
    }
    let new: u64 = guest!(uaccess::read(set));
    thread::save_mask(thread::mask());
    thread::set_mask(new);
    let mut old = host::empty_sigset();
    let during = host::host_mask_for(new);
    // SAFETY: plain host calls on valid signal sets.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &during, &mut old) };
    let r = if thread::deliverable() != 0 { err(errno::EINTR) } else { call() };
    // SAFETY: restoring the mask saved above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    if r != err(errno::EINTR) {
        if let Some(mask) = thread::take_saved_mask() {
            thread::set_mask(mask);
        }
    }
    r
}

/// `rt_sigsuspend(set, size)`: replace the mask and wait for a signal.
/// Returns `EINTR` once one is pending; delivering it then restores the mask
/// from before the call (see [`Kernel::deliver_pending`]). Runs without the
/// kernel lock.
///
/// # Safety
/// `set` must point to a guest `sigset_t`.
pub(crate) unsafe fn sigsuspend(set: u64, size: u64) -> i64 {
    if size != signal::SIGSET_SIZE {
        return err(errno::EINVAL);
    }
    let new: u64 = guest!(uaccess::read(set));
    thread::save_mask(thread::mask());
    thread::set_mask(new);
    loop {
        drain_to_signalfd();
        // Block every relayed signal while checking, so one that arrives
        // between the check and the wait is not lost: sigsuspend unblocks
        // atomically.
        let all = host::host_sigset(u64::MAX);
        let mut old = host::empty_sigset();
        // SAFETY: plain host calls on valid signal sets.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old) };
        if thread::deliverable() != 0 {
            // SAFETY: restoring the mask saved above.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
            return err(errno::EINTR);
        }
        let wait = host::host_mask_for(thread::mask());
        // SAFETY: as above; returns after a host handler ran.
        unsafe {
            libc::sigsuspend(&wait);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
    }
}

/// `rt_sigtimedwait(set, info, timeout, size)`: take one pending signal in
/// `set` (normally blocked), waiting up to `timeout`. Returns the signal, or
/// `EAGAIN` on timeout. Runs without the kernel lock.
///
/// The caller first has the host catch the signals in `set`
/// ([`Kernel::catch_for_wait`]): they are unblocked on the host while this
/// waits, so one already pending in the host, or arriving, is recorded with
/// its sender, and taken here instead of running a handler.
///
/// # Safety
/// `set` must point to a guest `sigset_t`, `info` (if non-null) to a
/// `siginfo_t`, and `timeout` (if non-null) to a `timespec`.
pub unsafe fn sigtimedwait(set: u64, info: u64, timeout: u64, size: u64) -> i64 {
    use std::time::{Duration, Instant};
    if size != signal::SIGSET_SIZE {
        return err(errno::EINVAL);
    }
    let want: u64 = guest!(uaccess::read(set));
    let deadline = if timeout == 0 {
        None
    } else {
        let ts: fwe_abi::Timespec = guest!(uaccess::read(timeout));
        Some(
            Instant::now()
                + Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32),
        )
    };
    loop {
        drain_to_signalfd();
        // Block everything while checking, so a signal arriving between the
        // check and the wait is not lost: pselect unblocks atomically.
        let all = host::host_sigset(u64::MAX);
        let mut old = host::empty_sigset();
        // SAFETY: plain host calls on valid signal sets.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old) };
        let ready = thread::pending() & want;
        if ready != 0 {
            // SAFETY: restoring the mask saved above.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
            let sig = ready.trailing_zeros() as u64 + 1;
            let Some(i) = thread::take_pending(sig) else { continue };
            if info != 0 {
                let mut b = Buf::zeroed(SIGINFO_SIZE);
                put_siginfo(&mut b, sig, i, 0);
                guest!(uaccess::write_from(info, &b.0));
            }
            return sig as i64;
        }
        let remaining = match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    // SAFETY: restoring the mask saved above.
                    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
                    return err(errno::EAGAIN);
                }
                Some(d - now)
            }
            None => None,
        };
        let ts = remaining.map(|r| libc::timespec {
            tv_sec: r.as_secs() as libc::time_t,
            tv_nsec: r.subsec_nanos() as libc::c_long,
        });
        let wait = host::host_mask_for(thread::mask() & !want);
        // SAFETY: valid signal set and timeout; no descriptors are watched.
        unsafe {
            libc::pselect(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
                &wait,
            );
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
        if thread::deliverable() & !want != 0 {
            // A signal the guest handles arrived instead.
            return err(errno::EINTR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Tracer};

    /// The computed frame offsets match the arm64 kernel layout.
    #[test]
    fn frame_offsets() {
        // `offsetof(struct rt_sigframe, uc.uc_mcontext)` and friends on arm64
        // Linux; glibc's `getcontext` stores `x18`/`x19` at
        // `uc_mcontext + 8 + 18 * 8` = 328 from `ucontext`, which is 456 here.
        assert_eq!(UC_MCONTEXT_OFF, 304);
        assert_eq!(MC_REGS_OFF, 312);
        assert_eq!(MC_REGS_OFF + 18 * 8 - UC_OFF, 328);
        assert_eq!(MC_SP_OFF, 560);
        assert_eq!(MC_PC_OFF, 568);
        assert_eq!(MC_PSTATE_OFF, 576);
        assert_eq!(MC_RESERVED_OFF, 592);
        assert_eq!(FRAME_SIZE, 4688);
    }

    struct NoPlatform;
    impl Platform for NoPlatform {
        fn prepare_exec(
            &mut self,
            _a: u64,
            _l: u64,
            _k: Option<&[(u64, u64)]>,
        ) -> Result<(), crate::PrepareFailed> {
            Ok(())
        }
        fn exit(&mut self, code: i32) -> ! {
            panic!("exit({code})")
        }
        fn exit_thread(&mut self, code: i32) -> ! {
            panic!("exit_thread({code})")
        }
        fn kill_self(&mut self, sig: libc::c_int) -> ! {
            panic!("killed by {sig}")
        }
    }

    const HANDLER: u64 = 0x4444_0000;
    const TRAMP: u64 = 0x5555_0000;

    fn kernel() -> Kernel<NoPlatform> {
        // Pending signals are per thread; without a registration they would
        // land in the process-wide set the concurrently running tests share.
        thread::register_current();
        let mut k = Kernel::new(
            NoPlatform,
            16384,
            Brk { start: 0, current: 0, limit: 0 },
            None,
            Tracer::default(),
        );
        k.set_sigreturn_trampoline(TRAMP);
        k
    }

    #[test]
    fn delivers_handler_and_restores_on_sigreturn() {
        let mut k = kernel();
        let act = Sigaction { handler: HANDLER, flags: signal::SA_SIGINFO, restorer: 0, mask: 0 };
        k.sigactions[(signal::SIGUSR1 - 1) as usize] = act;

        // A guest stack to build the frame on.
        let stack = vec![0u8; 64 * 1024];
        let top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
        let mut regs = Regs { sp: top, pc: 0x1000, ..Regs::default() };
        regs.x[5] = 0xdead_beef;
        regs.x[30] = 0xcafe; // caller's lr, must be saved and restored

        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);

        // Entered the handler with the Linux calling convention.
        assert_eq!(regs.pc, HANDLER);
        assert_eq!(regs.x[0], signal::SIGUSR1);
        let frame = regs.sp;
        assert_eq!(frame % 16, 0);
        assert!(frame < top && top - frame >= FRAME_SIZE);
        assert_eq!(regs.x[1], frame); // siginfo
        assert_eq!(regs.x[2], frame + UC_OFF); // ucontext
        assert_eq!(regs.x[30], TRAMP); // return to the sigreturn trampoline
        // The handler runs with the signal masked.
        assert_eq!(thread::mask(), 1 << (signal::SIGUSR1 - 1));
        // Pending bit cleared.
        assert_eq!(thread::pending(), 0);

        // Now return from the handler.
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!(regs.pc, 0x1000);
        assert_eq!(regs.sp, top);
        assert_eq!(regs.x[5], 0xdead_beef);
        assert_eq!(regs.x[30], 0xcafe);
        assert_eq!(thread::mask(), 0);
    }

    /// A second signal delivered while a handler runs on the alternate stack
    /// builds its frame below the running handler's sp, not over it.
    #[test]
    fn nested_delivery_stays_below_live_altstack_frame() {
        let mut k = kernel();
        let act = Sigaction { handler: HANDLER, flags: signal::SA_ONSTACK, restorer: 0, mask: 0 };
        k.sigactions[(signal::SIGUSR1 - 1) as usize] = act;
        k.sigactions[(signal::SIGUSR2 - 1) as usize] = act;
        let alt = vec![0u8; 64 * 1024];
        let alt_base = alt.as_ptr() as u64;
        thread::set_altstack(Stack {
            ss_sp: alt_base,
            ss_flags: 0,
            _pad: 0,
            ss_size: alt.len() as u64,
        });

        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        let first = regs.sp;
        assert!(first >= alt_base && first < alt_base + alt.len() as u64);

        // Pretend the handler used some stack, then a second signal arrives.
        regs.sp = first - 256;
        k.raise_pending(signal::SIGUSR2);
        k.deliver_pending(&mut regs);
        let second = regs.sp;
        assert!(second + FRAME_SIZE <= first - 256, "second frame {second:#x} overlaps {first:#x}");
        thread::set_altstack(Stack { ss_flags: signal::SS_DISABLE, ..Stack::default() });
        thread::set_mask(0);
    }

    #[test]
    fn ignored_signal_is_dropped() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR1 - 1) as usize].handler = signal::SIG_IGN;
        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        assert_eq!(regs.pc, 0x1000); // unchanged
        assert_eq!(thread::pending(), 0);
    }

    #[test]
    fn blocked_signal_stays_pending() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR1 - 1) as usize].handler = HANDLER;
        thread::set_mask(1 << (signal::SIGUSR1 - 1));
        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        assert_eq!(regs.pc, 0x1000); // not delivered
        assert_eq!(thread::pending(), 1 << (signal::SIGUSR1 - 1)); // still pending
        thread::take_pending(signal::SIGUSR1);
        thread::set_mask(0);
    }

    fn stack() -> (Vec<u8>, u64) {
        let stack = vec![0u8; 64 * 1024];
        let top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
        (stack, top)
    }

    /// The FP/SIMD registers are saved in an `fpsimd_context` record and
    /// restored on `rt_sigreturn`, whatever the handler did to them.
    #[test]
    fn fp_state_survives_a_handler() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR2 - 1) as usize].handler = HANDLER;
        let (_stack, top) = stack();
        let mut regs = Regs { sp: top, pc: 0x1000, ..Regs::default() };
        for (i, v) in regs.fp.v.iter_mut().enumerate() {
            *v = (i as u128 + 1) * 0x0101_0101_0101_0101_0101_0101_0101_0101;
        }
        regs.fp.fpsr = 0x10;
        regs.fp.fpcr = 0x0040_0000;
        let saved = regs.fp;
        k.raise_pending(signal::SIGUSR2);
        k.deliver_pending(&mut regs);
        let fp = regs.sp + MC_RESERVED_OFF;
        let peek32 = |a: u64| uaccess::read::<u32>(a).unwrap();
        let peek = |a: u64| uaccess::read::<u64>(a).unwrap();
        assert_eq!(peek32(fp), signal::FPSIMD_MAGIC);
        assert_eq!(peek32(fp + 4), signal::FPSIMD_CONTEXT_SIZE);
        assert_eq!(peek(fp + FPSIMD_VREGS_OFF + 16 * 3), saved.v[3] as u64);
        // The record after it is the terminator.
        assert_eq!(peek(fp + signal::FPSIMD_CONTEXT_SIZE as u64), 0);
        // The handler clobbers the FP state.
        regs.fp = crate::FpRegs::default();
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!(regs.fp, saved);
        assert_eq!(regs.pc, 0x1000);
    }

    /// A handler entered from `rt_sigsuspend` runs with the call's mask and
    /// returns to the mask from before the call.
    #[test]
    fn sigsuspend_mask_is_restored_by_sigreturn() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR1 - 1) as usize].handler = HANDLER;
        let (_stack, top) = stack();
        let before = 1 << (signal::SIGUSR1 - 1);
        thread::save_mask(before);
        thread::set_mask(1 << (signal::SIGHUP - 1));
        k.raise_pending(signal::SIGUSR1);
        let mut regs = Regs { sp: top, pc: 0x1000, ..Regs::default() };
        k.finish_syscall(&mut regs, fwe_abi::nr::RT_SIGSUSPEND, &[0; 6], err(errno::EINTR));
        assert_eq!(regs.pc, HANDLER);
        assert_eq!(thread::mask(), (1 << (signal::SIGHUP - 1)) | before);
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!(thread::mask(), before);
        // sigsuspend is not restarted: it returned EINTR past the trap.
        assert_eq!(regs.pc, 0x1004);
        assert_eq!(regs.x[0] as i64, err(errno::EINTR));
        thread::set_mask(0);
    }

    /// An interrupted `read` reruns after an `SA_RESTART` handler, and also
    /// when no handler is waiting (the interruption was not the guest's).
    #[test]
    fn interrupted_calls_restart_as_on_linux() {
        let mut k = kernel();
        let (_stack, top) = stack();
        let args = [7, 0, 0, 0, 0, 0];
        let mut regs = Regs { sp: top, pc: 0x1000, ..Regs::default() };
        regs.x[0] = 7;
        k.finish_syscall(&mut regs, fwe_abi::nr::READ, &args, err(errno::EINTR));
        assert_eq!((regs.pc, regs.x[0]), (0x1000, 7), "nothing to deliver: rerun");

        let act = Sigaction { handler: HANDLER, flags: signal::SA_RESTART, restorer: 0, mask: 0 };
        k.sigactions[(signal::SIGUSR1 - 1) as usize] = act;
        k.raise_pending(signal::SIGUSR1);
        k.finish_syscall(&mut regs, fwe_abi::nr::READ, &args, err(errno::EINTR));
        assert_eq!(regs.pc, HANDLER);
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!((regs.pc, regs.x[0]), (0x1000, 7), "SA_RESTART: rerun after the handler");

        k.sigactions[(signal::SIGUSR1 - 1) as usize].flags = 0;
        k.raise_pending(signal::SIGUSR1);
        k.finish_syscall(&mut regs, fwe_abi::nr::READ, &args, err(errno::EINTR));
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!(regs.pc, 0x1004);
        assert_eq!(regs.x[0] as i64, err(errno::EINTR), "no SA_RESTART: EINTR");
    }
}
