//! The VMM: loading, the vCPU run loop and the system call path.

use super::ffi::*;
use super::pagetables::PAGE;
use super::{fork, mem, record, vm, window};
use crate::{Error, Options, STACK_SIZE, cmdline, hostname, hwcap, ncpu, stack};
use fwe_abi::{auxv, err, errno, mman, nr};
use fwe_elf::{Elf, LoadPlan, PF_R, PF_W, PF_X};
use fwe_kernel::{Brk, FpRegs, HostSignal, Kernel, Platform, Regs, host, thread, uaccess};
use std::cell::Cell;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;

/// The kernel of the guest running in this VM.
static KERNEL: fwe_kernel::KernelLock<HvPlatform> = fwe_kernel::KernelLock::new(None);

pub(super) fn kernel() -> fwe_kernel::klock::Exclusive<'static, Option<Kernel<HvPlatform>>> {
    KERNEL.lock()
}

thread_local! {
    /// This thread's vCPU, for the signal handler to stop it.
    static VCPU: Cell<Option<hv_vcpu_t>> = const { Cell::new(None) };
}

/// [`Platform`] for guests running in the VM.
pub struct HvPlatform;

impl Platform for HvPlatform {
    fn thread_pointer(&self) -> u64 {
        let mut v = 0;
        if let Some(id) = VCPU.with(Cell::get) {
            // SAFETY: reading a system register of this thread's vCPU.
            hvf(|| unsafe { hv_vcpu_get_sys_reg(id, HV_SYS_REG_TPIDR_EL0, &mut v) });
        }
        v
    }

    fn set_thread_pointer(&mut self, tp: u64) {
        if let Some(id) = VCPU.with(Cell::get) {
            // SAFETY: writing a system register of this thread's vCPU.
            hvf(|| unsafe { hv_vcpu_set_sys_reg(id, HV_SYS_REG_TPIDR_EL0, tp) });
        }
    }

    fn prepare_exec(
        &mut self,
        _addr: u64,
        _len: u64,
        _known: Option<&[(u64, u64)]>,
    ) -> Result<(), fwe_kernel::PrepareFailed> {
        // The guest's code runs as it is.
        Ok(())
    }

    fn exit(&mut self, code: i32) -> ! {
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        mem::finish_lazy();
        teardown();
        record::Line::new().s("exit ").dec(code as u32 as u64).emit();
        // SAFETY: terminating the process, its VM gone.
        unsafe { libc::_exit(code) }
    }

    fn exit_thread(&mut self, code: i32) -> ! {
        exit_thread(code)
    }

    fn kill_self(&mut self, sig: libc::c_int) -> ! {
        fwe_kernel::procreg::exiting(
            fwe_kernel::host::signal_to_linux(sig) as i32 | fwe_kernel::coredump::status_bit(),
        );
        mem::finish_lazy();
        teardown();
        record::Line::new().s("dies of host signal ").dec(sig as u64).emit();
        // SAFETY: resetting the disposition, unblocking and raising `sig`
        // terminates the process with that signal.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            let mut set = host::empty_sigset();
            libc::sigaddset(&mut set, sig);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::raise(sig);
            libc::_exit(128 + sig)
        }
    }

    fn stop_self(&mut self, sig: libc::c_int) {
        host::stop_with(sig);
    }

    fn set_host_signal(&mut self, sig: u64, how: HostSignal) {
        set_host_signal(sig, how);
    }

    fn memory(&mut self, call: fwe_kernel::MemCall, brk: &mut Brk) -> Option<i64> {
        Some(mem::call(call, brk))
    }
}

// --- Ending a VM process cleanly -----------------------------------------
//
// A process must never end, or exec, with its VM alive: misusing the
// framework can bring the machine down (see the safety rules in
// docs/hypervisor.md). So every way out — exit_group, the
// last thread's exit, a fatal signal's default action, fwe's own fatal errors
// and panics, execve — first stops and destroys every vCPU and then the VM,
// and a host fork, which would copy a VM the child cannot own, is refused.

/// Live vCPUs, readable from signal handlers. A slot holds `vcpu + 1`, or 0.
static VCPU_SLOTS: [std::sync::atomic::AtomicU64; 256] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 256];
/// The VM exists.
static VM_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The process is ending: every vCPU thread destroys its vCPU and stops.
static EXITING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    /// This thread is inside `hv_vcpu_run`.
    static IN_RUN: Cell<bool> = const { Cell::new(false) };
    /// This thread is inside another framework call on its vCPU ([`hvf`]).
    static IN_HVF: Cell<bool> = const { Cell::new(false) };
    /// The process began ending while this thread was in such a call: it
    /// gives up its vCPU as the call returns.
    static RETIRE_AFTER: Cell<bool> = const { Cell::new(false) };
}

/// Make framework call `f` on this thread's vCPU. The wake signal that
/// ends the process destroys a thread's vCPU from its handler, which must
/// not happen in the middle of a call on it, nor be followed by one: if it
/// arrives during `f`, the thread destroys its vCPU after `f` and stops;
/// if it came before, the thread stops instead of making the call.
///
/// The thread is marked as in a call before it looks whether the process
/// is ending: a wake that comes after the mark leaves the vCPU for the
/// thread to destroy (which the look then sees), and one that came before
/// it destroyed the vCPU already (which the look sees too). Looking first
/// would leave a moment in which the handler destroys the vCPU unmarked
/// and the call is then made on it.
fn hvf<T>(f: impl FnOnce() -> T) -> T {
    use std::sync::atomic::{Ordering::SeqCst, compiler_fence};
    let outer = IN_HVF.with(|c| c.replace(true));
    // The handler runs on this thread: keep the mark before the look.
    compiler_fence(SeqCst);
    if EXITING.load(SeqCst) && (VCPU.with(Cell::get).is_none() || RETIRE_AFTER.with(Cell::get)) {
        park();
    }
    let r = f();
    compiler_fence(SeqCst);
    IN_HVF.with(|c| c.set(outer));
    if !outer && RETIRE_AFTER.with(Cell::get) {
        park();
    }
    r
}

// --- Stopping the other vCPUs for a fork ----------------------------------

/// A fork is taking its snapshot: vCPU threads wait before running guest
/// code again.
static PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Threads inside, or about to enter, `hv_vcpu_run`.
static RUNNING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PAUSE: (Mutex<()>, std::sync::Condvar) = (Mutex::new(()), std::sync::Condvar::new());

/// Count this thread as running guest code, first waiting out a fork's
/// snapshot.
fn enter_run() {
    use std::sync::atomic::Ordering::SeqCst;
    loop {
        RUNNING.fetch_add(1, SeqCst);
        if !PAUSED.load(SeqCst) {
            return;
        }
        RUNNING.fetch_sub(1, SeqCst);
        let mut g = PAUSE.0.lock().unwrap_or_else(|e| e.into_inner());
        while PAUSED.load(SeqCst) && !EXITING.load(SeqCst) {
            g = PAUSE.1.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        drop(g);
        if EXITING.load(SeqCst) {
            park();
        }
    }
}

/// Stop every other vCPU and keep them stopped until [`resume_others`]: no
/// guest code runs meanwhile. Called with the kernel lock held, from a
/// thread in a system call.
pub(super) fn pause_others() {
    use std::sync::atomic::Ordering::SeqCst;
    PAUSED.store(true, SeqCst);
    let own = VCPU.with(Cell::get);
    loop {
        stop_others(own);
        if RUNNING.load(SeqCst) == 0 {
            return;
        }
        // SAFETY: plain host call.
        unsafe { libc::usleep(20) };
    }
}

/// Whether a vCPU other than the calling thread's exists.
pub(super) fn others_exist() -> bool {
    let own = VCPU.with(Cell::get);
    live_vcpus().iter().any(|&v| Some(v) != own)
}

/// Let the vCPUs [`pause_others`] stopped run again.
pub(super) fn resume_others() {
    let _g = PAUSE.0.lock().unwrap_or_else(|e| e.into_inner());
    PAUSED.store(false, std::sync::atomic::Ordering::SeqCst);
    PAUSE.1.notify_all();
}

fn register_vcpu(id: hv_vcpu_t) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    VCPU_SLOTS.iter().any(|s| s.compare_exchange(0, id + 1, SeqCst, SeqCst).is_ok())
}

/// A vCPU slot's mark while its vCPU is being destroyed: no longer
/// stopped by others, still waited for by teardown.
const RETIRING: u64 = 1 << 63;

/// Threads inside [`stop_others`]' call on other threads' vCPUs.
static STOPPING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

thread_local! {
    /// This thread is inside [`stop_others`].
    static IN_STOP: Cell<bool> = const { Cell::new(false) };
}

/// Make every vCPU but `own` stop running guest code (`hv_vcpus_exit`). A
/// vCPU its thread is destroying meanwhile is not passed: the destroying
/// thread marks it first, then waits for every stop under way (see
/// [`retire_vcpu`]). Async-signal-safe.
fn stop_others(own: Option<hv_vcpu_t>) {
    use std::sync::atomic::Ordering::SeqCst;
    IN_STOP.with(|c| c.set(true));
    STOPPING.fetch_add(1, SeqCst);
    let mut ids = [0 as hv_vcpu_t; 256];
    let mut n = 0;
    for s in &VCPU_SLOTS {
        let v = s.load(SeqCst);
        if v != 0 && v & RETIRING == 0 && Some(v - 1) != own {
            ids[n] = v - 1;
            n += 1;
        }
    }
    if n > 0 {
        // SAFETY: stopping other threads' vCPUs, which may be running and
        // are not destroyed before this returns.
        unsafe { hv_vcpus_exit(ids.as_mut_ptr(), n as u32) };
    }
    STOPPING.fetch_sub(1, SeqCst);
    IN_STOP.with(|c| c.set(false));
}

/// Destroy the calling thread's vCPU, if it has one. Async-signal-safe.
fn retire_vcpu() {
    use std::sync::atomic::Ordering::SeqCst;
    if let Some(id) = VCPU.with(|c| c.take()) {
        let slot = VCPU_SLOTS
            .iter()
            .find(|s| s.compare_exchange(id + 1, (id + 1) | RETIRING, SeqCst, SeqCst).is_ok());
        // No other thread's stop can still be passing it (one that read the
        // slot before the mark is counted in STOPPING); this thread's own
        // is not under way (see `on_signal`).
        while STOPPING.load(SeqCst) != 0 {
            std::hint::spin_loop();
        }
        // SAFETY: destroying this thread's own vCPU, which is not running.
        unsafe { hv_vcpu_destroy(id) };
        if let Some(s) = slot {
            s.store(0, SeqCst);
        }
    }
}

/// Every vCPU of the process, ones being destroyed included.
fn live_vcpus() -> Vec<hv_vcpu_t> {
    use std::sync::atomic::Ordering::SeqCst;
    VCPU_SLOTS
        .iter()
        .map(|s| s.load(SeqCst))
        .filter(|&v| v != 0)
        .map(|v| (v & !RETIRING) - 1)
        .collect()
}

/// Stop and destroy every vCPU, then the VM. Idempotent; safe to call from a
/// signal handler on a thread not inside `hv_vcpu_run`.
pub(super) fn teardown() {
    use std::sync::atomic::Ordering::SeqCst;
    if !VM_LIVE.load(SeqCst) {
        return;
    }
    EXITING.store(true, SeqCst);
    let own = VCPU.with(Cell::get);
    if live_vcpus().iter().any(|&v| Some(v) != own) {
        stop_others(own);
        // Threads blocked in a system call are interrupted, and destroy their
        // vCPU from the wake signal's handler.
        thread::wake_others(host::WAKE_SIGNAL);
        for _ in 0..2000 {
            if live_vcpus().iter().all(|&v| Some(v) == own) {
                break;
            }
            // SAFETY: plain host call.
            unsafe { libc::usleep(500) };
        }
    }
    retire_vcpu();
    // SAFETY: destroying this process's VM, every vCPU gone.
    let rc = unsafe { hv_vm_destroy() };
    if rc == 0 {
        VM_LIVE.store(false, SeqCst);
    } else {
        let msg = b"fwe: the VM could not be destroyed before exit\n";
        // SAFETY: writing a diagnostic to standard error.
        unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
    }
}

/// A guest thread ends: the last one ends the process.
fn exit_thread(code: i32) -> ! {
    use std::sync::atomic::Ordering::SeqCst;
    if crate::LIVE_THREADS.fetch_sub(1, SeqCst) == 1 {
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        mem::finish_lazy();
        teardown();
        record::Line::new().s("exit ").dec(code as u32 as u64).emit();
        // SAFETY: terminating the process, its VM gone.
        unsafe { libc::_exit(code) }
    }
    retire_vcpu();
    // SAFETY: ends the calling host thread; the process keeps running.
    unsafe { libc::pthread_exit(std::ptr::null_mut()) }
}

/// Park a vCPU thread for good once the process is ending (its vCPU is
/// already destroyed).
fn park() -> ! {
    retire_vcpu();
    loop {
        // SAFETY: plain host call.
        unsafe { libc::pause() };
    }
}

/// The handler for every signal the guest catches, and the wake signal:
/// record it and stop this thread's vCPU, so the run loop delivers it.
extern "C" fn on_signal(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if EXITING.load(std::sync::atomic::Ordering::SeqCst) {
        // The process is ending: a thread not running guest code gives up
        // its vCPU now (one inside hv_vcpu_run does as the run returns).
        // Not in the middle of a call on the vCPU, nor of this thread's
        // own stop of the others (which a retirement waits for).
        if IN_HVF.with(Cell::get) || IN_STOP.with(Cell::get) {
            RETIRE_AFTER.with(|c| c.set(true));
        } else if !IN_RUN.with(Cell::get) {
            retire_vcpu();
        }
        return;
    }
    if sig == libc::SIGXCPU && !fwe_kernel::rlimits::cpu_signal() {
        // Past the hard CPU limit: the process ends.
        return;
    }
    // A wait this thread is about to begin, or is in, ends for it.
    thread::poke_wait();
    if sig == host::WAKE_SIGNAL {
        // Signals the host lacks, queued by another process.
        fwe_kernel::signote::drain(|lsig, note| {
            // One for a thread of this process goes to it, if it is there.
            if note.tid != 0 {
                thread::post_directed(note.tid, lsig, host::sent_info(note));
            } else {
                thread::post_landed(lsig, host::sent_info(note));
            }
        });
    } else {
        // The host's own SIGINFO (Ctrl-T), no relay: nothing on Linux.
        // Before the note is looked at for the siginfo.
        if sig == host::KILL_RELAY && !host::kill_relayed() {
            return;
        }
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        let info = unsafe { host::signal_info(sig, info) };
        // The relayed form of a guest's SIGKILL (see host::KILL_RELAY).
        let lsig = if sig == host::KILL_RELAY {
            fwe_abi::signal::SIGKILL
        } else {
            host::signal_to_linux(sig)
        };
        thread::post_landed(lsig, info);
    }
    if let Some(mut vcpu) = VCPU.with(Cell::get) {
        // SAFETY: stopping this thread's own vCPU, if it is running.
        unsafe { hv_vcpus_exit(&mut vcpu, 1) };
    }
}

fn install(sig: libc::c_int, flags: libc::c_int) {
    // SAFETY: installing a fully initialized sigaction.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | flags;
        libc::sigfillset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn set_host_signal(sig: u64, how: HostSignal) {
    let Some(h) = host::signal_to_host(sig) else { return };
    // A signal whose default action ends the process is caught all the same,
    // so the process ends through the kernel's default action, which tears
    // the VM down first, never by the host's with the VM alive. The kernel
    // already asks for that (`Kernel::sync_host_signal`); this keeps it the
    // VM's own guarantee.
    let how = match how {
        HostSignal::Default
            if fwe_abi::signal::default_action(sig) == fwe_abi::signal::Default::Terminate =>
        {
            HostSignal::Catch { flags: 0 }
        }
        other => other,
    };
    match how {
        HostSignal::Catch { flags } => {
            let mut f = 0;
            if sig == fwe_abi::signal::SIGCHLD && flags & fwe_abi::signal::SA_NOCLDSTOP != 0 {
                f |= libc::SA_NOCLDSTOP;
            }
            install(h, f);
        }
        // SAFETY: resetting a disposition.
        HostSignal::Default => unsafe {
            libc::signal(h, libc::SIG_DFL);
        },
        // SAFETY: ignoring a signal.
        HostSignal::Ignore => unsafe {
            libc::signal(h, libc::SIG_IGN);
        },
    }
}

/// Linux protections for ELF segment flags.
fn prot_of(flags: u32) -> u64 {
    let mut p = 0;
    if flags & PF_R != 0 {
        p |= mman::PROT_READ;
    }
    if flags & PF_W != 0 {
        p |= mman::PROT_WRITE;
    }
    if flags & PF_X != 0 {
        p |= mman::PROT_EXEC;
    }
    p
}

/// A fault in fwe's own code: the kernel's checked copies recover from it
/// (EFAULT); anything else is fatal.
extern "C" fn on_fault(sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO handlers.
    let ss = unsafe { &mut (*(*(ctx as *mut crate::trap::Ucontext)).uc_mcontext).ss };
    if let Some(resume) = uaccess::fixup(ss.pc) {
        ss.pc = resume;
        return;
    }
    // A bug in fwe itself: take the VM down before dying of it.
    teardown();
    // SAFETY: resetting to the default action, which the re-executed
    // instruction then takes.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
}

/// Block every signal a guest can receive, the wake signal and the kill
/// relay, on the calling thread.
fn block_guest_signals() {
    let mut all = host::host_sigset(u64::MAX);
    // SAFETY: an initialized signal set; changing this thread's mask.
    unsafe {
        libc::sigaddset(&mut all, host::WAKE_SIGNAL);
        libc::sigaddset(&mut all, host::KILL_RELAY);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
}

fn mem_error(what: &str, e: i32) -> Error {
    Error::Unsupported(format!("{what} failed: errno {e}"))
}

/// Where an image ended up.
struct Placed {
    /// Added to the image's link addresses.
    bias: u64,
    entry: u64,
    phdr: Option<u64>,
    phnum: u16,
    phent: u16,
    end: u64,
}

/// Load `elf` into the guest's memory: a non-PIE image at its link address
/// (backed by slab memory elsewhere when that address is outside the slab,
/// and translated), a PIE one wherever there is room. Its pages get the
/// segments' protections, its code `PROT_BTI` with `bti`; the gaps between
/// segments are left inaccessible.
fn place(elf: &Elf<'_>, bti: bool) -> Result<Placed, Error> {
    let plan = LoadPlan::new(elf, PAGE);
    let rw = mman::PROT_READ | mman::PROT_WRITE;
    let guest = if elf.is_pie() {
        mem::map_anywhere(plan.len, rw).map_err(|e| mem_error("placing the image", e))?
    } else {
        mem::map_fixed(plan.start, plan.len, rw).map_err(|e| mem_error("placing the image", e))?;
        plan.start
    };
    let bias = guest - plan.start;
    for ph in elf.loads() {
        let src = &elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize];
        uaccess::write_from(ph.vaddr + bias, src).map_err(|e| mem_error("loading the image", e))?;
        mem::code_written(uaccess::g2h(ph.vaddr + bias), src.len() as u64);
    }
    mem::protect(guest, plan.len, mman::PROT_NONE)
        .map_err(|e| mem_error("protecting the image", e))?;
    for run in &plan.runs {
        let off = run.start - plan.start;
        let mut prot = prot_of(run.prot);
        if bti && prot & mman::PROT_EXEC != 0 {
            prot |= mman::PROT_BTI;
        }
        mem::protect(guest + off, run.len, prot)
            .map_err(|e| mem_error("protecting the image", e))?;
    }
    let (_, hi) = elf.bounds();
    Ok(Placed {
        bias,
        entry: elf.entry + bias,
        phdr: elf.phdr_vaddr().map(|a| a + bias),
        phnum: elf.phnum,
        phent: elf.phentsize,
        end: hi + bias,
    })
}

/// `movz x8, #139; svc #0`: the `rt_sigreturn` trampoline.
const SIGRETURN: [u32; 2] = [0xd280_1168, 0xd400_0001];

/// Create this process's VM, and from then on make every way out of the
/// process tear it down first: no host fork, a panic hook, fwe's own fault
/// handlers. Hypervisor.framework runs threads of its own, which inherit
/// the mask of the thread that creates the VM: with every guest signal
/// blocked there, the host delivers signals only to the vCPU threads, whose
/// masks follow the guest's.
pub(super) fn become_vm_process() -> Result<(), String> {
    block_guest_signals();
    // Code fwe writes (a tracer's breakpoint) is fetched afresh by the VM,
    // and by the stand-in's translations.
    fwe_kernel::procmem::on_code_written(mem::code_written);
    // From before the VM exists, no host signal may end the process by the
    // host's default action: every one whose default ends it is caught (for
    // the guest, whose default action tears the VM down first) until the
    // kernel sets the guest's dispositions, which keep that. A fork child,
    // started afresh, would otherwise have the host's defaults while a
    // signal sent to it at once arrives. One ignored as the process
    // started stays ignored.
    for lsig in 1..=fwe_abi::signal::SIGSYS {
        if fwe_abi::signal::default_action(lsig) != fwe_abi::signal::Default::Terminate
            || lsig == fwe_abi::signal::SIGKILL
        {
            continue;
        }
        let Some(h) = host::signal_to_host(lsig) else { continue };
        // SAFETY: querying the disposition into a zeroed sigaction.
        let ignored = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(h, std::ptr::null(), &mut old);
            old.sa_sigaction == libc::SIG_IGN
        };
        if !ignored && !matches!(h, libc::SIGSEGV | libc::SIGBUS) {
            install(h, 0);
        }
    }
    vm::create()?;
    VM_LIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    fwe_kernel::forbid_fork();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        teardown();
    }));
    install(host::WAKE_SIGNAL, 0);
    install(host::KILL_RELAY, 0);
    for sig in [libc::SIGSEGV, libc::SIGBUS] {
        // SAFETY: installing a fully initialized sigaction.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_fault as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    Ok(())
}

/// Run `path` (already read into `data`) in the VM. Returns only on failure.
pub fn run(
    path: &Path,
    data: &[u8],
    args: &[OsString],
    env: &[OsString],
    options: &Options,
) -> Error {
    let mode = if super::standin::active() { "start (stand-in)" } else { "start" };
    record::event(mode, path.as_os_str().as_bytes());
    match start(path, data, args, env, options) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

fn start(
    path: &Path,
    data: &[u8],
    args: &[OsString],
    env: &[OsString],
    options: &Options,
) -> Result<std::convert::Infallible, Error> {
    // The guest's pages are Linux's 4 KiB ones: its own page tables say so.
    let page = PAGE;
    let tracer = options.strace;
    // Hypervisor.framework runs threads of its own, which inherit the mask
    // of the thread that creates them. With every guest signal blocked
    // there, the host delivers signals only to the vCPU threads, whose masks
    // follow the guest's. The mask fwe started with is the guest's own.
    let inherited_mask = host::blocked_signals();
    let unsupported = |e: String| {
        Error::Unsupported(format!(
            "this program is linked below 4 GiB, which needs the hypervisor backend, \
             and creating the VM failed ({e}); fwe must be signed with the \
             com.apple.security.hypervisor entitlement (see docs/hypervisor.md) \
             on a Mac with hypervisor support"
        ))
    };
    // Asking the framework anything needs the entitlement too.
    let layout = vm::layout().map_err(unsupported)?;
    window::reserve(layout.slab).map_err(Error::Unsupported)?;
    become_vm_process().map_err(unsupported)?;
    let mut fs = crate::open_fs(options)?;

    let elf = Elf::parse(data).map_err(Error::Elf)?;
    mem::init();
    // The first vCPU now: it tells what the VM offers (BTI decides how the
    // images are mapped).
    let vcpu = Vcpu::create().map_err(Error::Unsupported)?;
    let features = vm::features();
    fwe_kernel::signal::set_bti(features.bti);
    // BTI as Linux applies it at load: to the interpreter where there is
    // one (it applies BTI to the program and its libraries itself), else to
    // a static program; each only if built for BTI.
    let has_interp = elf.interpreter().map_err(Error::Elf)?.is_some();
    let built_bti = |e: &Elf<'_>| e.aarch64_features() & fwe_elf::AARCH64_FEATURE_BTI != 0;
    let exe = place(&elf, features.bti && !has_interp && built_bti(&elf))?;
    // The program's file is told by `/proc/self/exe` when listed.
    fwe_kernel::maps::record().loaded(&elf, exe.bias, page, fwe_kernel::maps::Name::Exe, (0, 0));
    let interp = match elf.interpreter().map_err(Error::Elf)? {
        Some(ip) => {
            let idata = fs.read(ip).map_err(|e| {
                Error::Unsupported(format!(
                    "loading the dynamic linker {}: errno {e}",
                    String::from_utf8_lossy(ip)
                ))
            })?;
            let ielf = Elf::parse(&idata).map_err(Error::Elf)?;
            if !ielf.is_pie() {
                return Err(Error::Unsupported(
                    "the dynamic linker is not position-independent".into(),
                ));
            }
            let placed = place(&ielf, features.bti && built_bti(&ielf))?;
            let name = fwe_kernel::maps::Name::Path(ip.into());
            fwe_kernel::maps::record().loaded(
                &ielf,
                placed.bias,
                page,
                name,
                fs.file_id(ip).unwrap_or((0, 0)),
            );
            Some(placed)
        }
        None => None,
    };

    // The break: a reserved range the guest's `brk` maps page by page.
    let brk_start =
        mem::reserve_brk(Brk::RESERVATION).map_err(|e| mem_error("reserving the break", e))?;
    let brk = Brk { start: brk_start, current: brk_start, limit: brk_start + Brk::RESERVATION };
    let _ = exe.end;

    // The stack, with an inaccessible guard page below it.
    let rw = mman::PROT_READ | mman::PROT_WRITE;
    let stack_base =
        mem::map_anywhere(STACK_SIZE + page, rw).map_err(|e| mem_error("making the stack", e))?;
    mem::protect(stack_base, page, mman::PROT_NONE).map_err(|e| mem_error("the stack guard", e))?;
    let stack_top = stack_base + page + STACK_SIZE;
    fwe_kernel::maps::record().set_stack(stack_base + page, stack_top);
    fwe_kernel::maps::record().set_heap(brk.start, brk.start, brk.limit);

    let (mut hwcap, mut hwcap2) = hwcap::detect();
    // The VM's own pointer authentication and BTI, not the host's.
    hwcap2 &= !fwe_abi::hwcap2::BTI;
    if features.bti {
        hwcap2 |= fwe_abi::hwcap2::BTI;
    }
    if features.pac {
        hwcap |= fwe_abi::hwcap::PACA;
    }
    if features.pacg {
        hwcap |= fwe_abi::hwcap::PACG;
    }
    let (uid, euid, gid, egid) = host::ids();
    let mut aux = vec![
        (auxv::AT_HWCAP, hwcap),
        (auxv::AT_PAGESZ, page),
        (auxv::AT_CLKTCK, 100),
        (auxv::AT_PHENT, exe.phent as u64),
        (auxv::AT_PHNUM, exe.phnum as u64),
        (auxv::AT_BASE, interp.as_ref().map_or(0, |i| i.bias)),
        (auxv::AT_FLAGS, 0),
        (auxv::AT_ENTRY, exe.entry),
        (auxv::AT_UID, uid as u64),
        (auxv::AT_EUID, euid as u64),
        (auxv::AT_GID, gid as u64),
        (auxv::AT_EGID, egid as u64),
        (auxv::AT_SECURE, 0),
        (auxv::AT_HWCAP2, hwcap2),
        (auxv::AT_MINSIGSTKSZ, fwe_abi::signal::MINSIGSTKSZ),
    ];
    if let Some(phdr) = exe.phdr {
        aux.push((auxv::AT_PHDR, phdr));
    }
    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|e| e.as_bytes()).collect();
    let execfn = &crate::guest_execfn(path, options);
    let mut random = [0u8; 16];
    host::fill_random(&mut random);
    let image =
        stack::InitialStack { args: &arg_bytes, env: &env_bytes, execfn, auxv: &aux, random }
            .build(stack_top);
    uaccess::write_from(image.sp, &image.bytes).map_err(|e| mem_error("writing the stack", e))?;

    // The rt_sigreturn trampoline.
    let tramp = mem::map_anywhere(page, rw).map_err(|e| mem_error("the trampoline", e))?;
    let words: Vec<u8> = SIGRETURN.iter().flat_map(|w| w.to_le_bytes()).collect();
    uaccess::write_from(tramp, &words).map_err(|e| mem_error("the trampoline", e))?;
    mem::code_written(uaccess::g2h(tramp), words.len() as u64);
    mem::protect(tramp, page, mman::PROT_READ | mman::PROT_EXEC)
        .map_err(|e| mem_error("the trampoline", e))?;
    // No vCPU has run: nothing can hold an old translation.
    vm::flushed_without_vcpus();

    let entry = interp.as_ref().map_or(exe.entry, |i| i.entry);
    if tracer.enabled {
        tracer.note(&format!(
            "hypervisor backend: exe entry {:#x}, image translated to host {:#x}, \
             interp base {:#x}, brk {brk_start:#x}, stack top {stack_top:#x}",
            exe.entry,
            uaccess::g2h(exe.entry),
            interp.as_ref().map_or(0, |i| i.bias),
        ));
    }

    let exe = fs.exe_fd_target().unwrap_or_else(|| crate::guest_exe_path(path, options));
    fs.set_proc_info(exe, cmdline(&arg_bytes), ncpu(), hostname());
    fs.set_auxv(image.auxv.clone());
    fs.publish();
    thread::init_main(fwe_kernel::pidns::adopt(&fs.ns, 0));
    fwe_kernel::procreg::own_namespaces(fs.ns_dirs());
    // A subreaper stays one across execve; a namespace's init is one.
    fwe_kernel::reaper::start_if_reaper();
    let mut k = Kernel::new(HvPlatform, page, brk, Some(fs), tracer);
    crate::apply_exec_state(&mut k, options, path)?;
    k.set_sigreturn_trampoline(tramp);
    k.adopt_host_signals();
    thread::set_mask(inherited_mask);
    *kernel() = Some(k);

    let mut regs = Regs { sp: image.sp, pc: entry, ..Regs::default() };
    // A traced program stops for its tracer before its first instruction,
    // as after any `execve`.
    kernel().as_mut().unwrap().ptrace_exec_stop(&mut regs);
    vcpu.run(regs)
}

/// The virtual counter offset all vCPUs share, `u64::MAX` before the first.
static VTIMER_OFFSET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

/// Make `offset` the process's virtual counter offset (a fork child takes
/// its parent's), before any vCPU exists.
pub(super) fn use_vtimer_offset(offset: u64) {
    VTIMER_OFFSET.store(offset, std::sync::atomic::Ordering::SeqCst);
}

/// One vCPU, created on and run by the calling host thread.
pub(super) struct Vcpu {
    id: hv_vcpu_t,
    exit: *mut hv_vcpu_exit_t,
}

// Exception classes (ESR bits 31:26).
const EC_UNKNOWN: u64 = 0x00;
const EC_WFX: u64 = 0x01;
const EC_SYSREG: u64 = 0x18;
const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;
const EC_IABT_LOWER: u64 = 0x20;
const EC_PC_ALIGN: u64 = 0x22;
const EC_DABT_LOWER: u64 = 0x24;
const EC_SP_ALIGN: u64 = 0x26;
const EC_BRK64: u64 = 0x3c;

impl Vcpu {
    pub(super) fn create() -> Result<Vcpu, String> {
        let mut id = 0;
        let mut exit = std::ptr::null_mut();
        // Known as this thread's at once, so an end of the process during
        // the call destroys it.
        let rc = hvf(|| {
            // SAFETY: out-parameters for a vCPU owned by this thread.
            let rc = unsafe { hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut()) };
            if rc == 0 {
                VCPU.with(|c| c.set(Some(id)));
            }
            rc
        });
        check(rc, "hv_vcpu_create")?;
        let v = Vcpu { id, exit };
        // What the VM offers, asked of its first vCPU.
        let isar1 = v.get_sys(HV_SYS_REG_ID_AA64ISAR1_EL1);
        let pfr1 = v.get_sys(HV_SYS_REG_ID_AA64PFR1_EL1);
        let features = vm::set_features(vm::Features::from_id_registers(isar1, pfr1));
        for (reg, value) in vm::system_registers() {
            v.set_sys(reg, value);
        }
        if features.pac {
            for (&reg, value) in HV_SYS_REG_PAC_KEYS.iter().zip(thread_keys()) {
                v.set_sys(reg, value);
            }
        }
        // Every vCPU of the process reads the same virtual counter: the
        // first one's offset (or a fork parent's) is everyone's.
        use std::sync::atomic::Ordering::SeqCst;
        match VTIMER_OFFSET.load(SeqCst) {
            u64::MAX => VTIMER_OFFSET.store(v.vtimer_offset(), SeqCst),
            offset => v.set_vtimer_offset(offset),
        }
        VCPU.with(|c| c.set(Some(id)));
        if !register_vcpu(id) {
            retire_vcpu();
            return Err("too many vCPUs".into());
        }
        Ok(v)
    }

    fn get(&self, reg: hv_reg_t) -> u64 {
        let mut v = 0;
        // SAFETY: reading a register of this thread's vCPU.
        hvf(|| unsafe { hv_vcpu_get_reg(self.id, reg, &mut v) });
        v
    }

    fn set(&self, reg: hv_reg_t, v: u64) {
        // SAFETY: writing a register of this thread's vCPU.
        hvf(|| unsafe { hv_vcpu_set_reg(self.id, reg, v) });
    }

    fn get_sys(&self, reg: hv_sys_reg_t) -> u64 {
        let mut v = 0;
        // SAFETY: reading a system register of this thread's vCPU.
        hvf(|| unsafe { hv_vcpu_get_sys_reg(self.id, reg, &mut v) });
        v
    }

    fn set_sys(&self, reg: hv_sys_reg_t, v: u64) {
        // SAFETY: writing a system register of this thread's vCPU.
        hvf(|| unsafe { hv_vcpu_set_sys_reg(self.id, reg, v) });
    }

    /// The guest's registers, with `pc` and `pstate` as given.
    fn regs(&self, pc: u64, pstate: u64) -> Regs {
        let mut r = Regs { pc, pstate, sp: self.get_sys(HV_SYS_REG_SP_EL0), ..Regs::default() };
        for (i, x) in r.x.iter_mut().enumerate() {
            *x = self.get(HV_REG_X0 + i as u32);
        }
        let mut fp = FpRegs {
            fpsr: self.get(HV_REG_FPSR) as u32,
            fpcr: self.get(HV_REG_FPCR) as u32,
            ..FpRegs::default()
        };
        for (i, v) in fp.v.iter_mut().enumerate() {
            // SAFETY: reading a SIMD register of this thread's vCPU.
            hvf(|| unsafe { hv_vcpu_get_simd_fp_reg(self.id, i as u32, v) });
        }
        r.fp = fp;
        r
    }

    /// Resume the guest at EL0 with `r`.
    fn set_regs(&self, r: &Regs) {
        for (i, &x) in r.x.iter().enumerate() {
            self.set(HV_REG_X0 + i as u32, x);
        }
        self.set_sys(HV_SYS_REG_SP_EL0, r.sp);
        self.set(HV_REG_PC, r.pc);
        // EL0t with only the flags EL0 may hold (NZCV, SSBS, DIT, TCO,
        // BTYPE): a signal frame can hold anything, as on Linux, which
        // sanitises it the same way.
        const USER_PSTATE: u64 = 0xf000_0000 | (1 << 12) | (1 << 24) | (1 << 25) | 0xc00;
        self.set(HV_REG_CPSR, r.pstate & USER_PSTATE);
        self.set(HV_REG_FPSR, r.fp.fpsr as u64);
        self.set(HV_REG_FPCR, r.fp.fpcr as u64);
        for (i, v) in r.fp.v.iter().enumerate() {
            // SAFETY: writing a SIMD register of this thread's vCPU from 16
            // readable bytes.
            hvf(|| unsafe { set_simd_fp_reg(self.id, i as u32, v) });
        }
    }

    pub(super) fn set_thread_pointer(&self, tpidr: u64) {
        self.set_sys(HV_SYS_REG_TPIDR_EL0, tpidr);
    }

    pub(super) fn vtimer_offset(&self) -> u64 {
        let mut offset = 0;
        // SAFETY: reading this thread's vCPU's timer offset.
        hvf(|| unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut offset) });
        offset
    }

    fn set_vtimer_offset(&self, offset: u64) {
        // SAFETY: setting this thread's vCPU's timer offset.
        hvf(|| unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) });
    }

    /// Run the guest from `regs` until the process ends.
    pub(super) fn run(&self, mut regs: Regs) -> ! {
        self.set_regs(&regs);
        loop {
            if EXITING.load(std::sync::atomic::Ordering::SeqCst) {
                park();
            }
            // The host mask the guest's mask calls for is in force while it
            // runs, as in the native backend.
            let mask = host::host_mask_for(thread::mask());
            enter_run();
            // After the page tables lost a translation, resume through the
            // TLB stub: it invalidates every vCPU's TLBs, then returns to
            // the guest where it was.
            let flush = vm::Flush::needed();
            if flush.is_some() {
                self.set_sys(HV_SYS_REG_ELR_EL1, self.get(HV_REG_PC));
                self.set_sys(HV_SYS_REG_SPSR_EL1, self.get(HV_REG_CPSR));
                self.set(HV_REG_PC, vm::TLB_STUB);
                // EL1h, interrupts masked.
                self.set(HV_REG_CPSR, 0x3c5);
            }
            // SAFETY: plain host calls; `exit` is HVF's record for this vCPU.
            let (rc, exit) = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
                IN_RUN.with(|r| r.set(true));
                let rc = hvf(|| hv_vcpu_run(self.id));
                IN_RUN.with(|r| r.set(false));
                (rc, &*self.exit)
            };
            RUNNING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            if EXITING.load(std::sync::atomic::Ordering::SeqCst) {
                park();
            }
            if rc != 0 {
                fatal(&format!("hv_vcpu_run failed: {rc:#x}"));
            }
            if let Some(f) = flush {
                let pc = self.get(HV_REG_PC);
                if (vm::TLB_STUB..vm::TLB_STUB + 16).contains(&pc) {
                    // Stopped inside the stub: back to the guest's state;
                    // the flush is taken again next time.
                    self.set(HV_REG_PC, self.get_sys(HV_SYS_REG_ELR_EL1));
                    self.set(HV_REG_CPSR, self.get_sys(HV_SYS_REG_SPSR_EL1));
                } else {
                    f.done();
                }
            }
            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {
                    let syndrome = exit.exception.syndrome;
                    match syndrome >> 26 {
                        EC_HVC64 => regs = self.handle_el0_exception(),
                        // A stage-2 abort: the guest touched memory it has
                        // not mapped (or not for this access).
                        EC_DABT_LOWER | EC_IABT_LOWER => {
                            regs = self.regs(self.get(HV_REG_PC), self.get(HV_REG_CPSR));
                            fault(
                                &mut regs,
                                fwe_abi::signal::SIGSEGV,
                                exit.exception.virtual_address,
                            );
                        }
                        // `wfi`/`wfe`, which Linux lets EL0 execute: the
                        // wait is over.
                        EC_WFX => {
                            regs = self.regs(self.get(HV_REG_PC) + 4, self.get(HV_REG_CPSR));
                        }
                        // A system register access the hypervisor traps.
                        EC_SYSREG => regs = self.sysreg(syndrome),
                        ec => fatal(&format!(
                            "unexpected VM exit: EC {ec:#x}, syndrome {syndrome:#x}, pc {:#x}",
                            self.get(HV_REG_PC)
                        )),
                    }
                }
                HV_EXIT_REASON_CANCELED => {
                    // A signal for the guest (or the wake signal).
                    regs = self.regs(self.get(HV_REG_PC), self.get(HV_REG_CPSR));
                    if let Some(k) = kernel().as_mut() {
                        k.deliver_pending(&mut regs);
                    }
                }
                HV_EXIT_REASON_VTIMER_ACTIVATED => continue,
                other => fatal(&format!("unexpected VM exit reason {other}")),
            }
            // Whatever the exit, a signal that became deliverable meanwhile
            // (one a sigreturn just unblocked, or one the kernel queued
            // itself) is delivered now, not at the next system call.
            if thread::deliverable() != 0 {
                if let Some(k) = kernel().as_mut() {
                    k.deliver_pending(&mut regs);
                }
            }
            self.set_regs(&regs);
        }
    }

    /// A trapped system register access (ESR ISS for EC 0x18): a read of
    /// `CNTPCT_EL0`, the physical counter Linux lets EL0 read, is emulated
    /// with the virtual one the guest sees; anything else is `SIGILL`.
    fn sysreg(&self, syndrome: u64) -> Regs {
        let pc = self.get(HV_REG_PC);
        let mut regs = self.regs(pc, self.get(HV_REG_CPSR));
        let iss = syndrome & 0x1ff_ffff;
        let read = iss & 1 == 1;
        let rt = ((iss >> 5) & 0x1f) as usize;
        let key =
            (iss >> 10 & 0xf, iss >> 14 & 0x7, iss >> 17 & 0x7, iss >> 20 & 0x3, iss >> 1 & 0xf);
        // (CRn, Op1, Op2, Op0, CRm) of CNTPCT_EL0 and CNTPCTSS_EL0.
        if read && (key == (14, 3, 1, 3, 0) || key == (14, 3, 5, 3, 0)) {
            let mut offset = 0;
            // SAFETY: reading this thread's vCPU's timer offset.
            hvf(|| unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut offset) });
            // SAFETY: plain host call.
            let now = unsafe { mach_absolute_time() };
            if rt != 31 {
                regs.x[rt] = now.wrapping_sub(offset);
            }
            regs.pc = pc + 4;
            return regs;
        }
        fault(&mut regs, fwe_abi::signal::SIGILL, pc);
        regs
    }

    /// The guest took an exception at EL0, which our vector turned into
    /// `hvc`: handle it and return the registers to resume with.
    fn handle_el0_exception(&self) -> Regs {
        let esr = self.get_sys(HV_SYS_REG_ESR_EL1);
        let elr = self.get_sys(HV_SYS_REG_ELR_EL1);
        let spsr = self.get_sys(HV_SYS_REG_SPSR_EL1);
        let far = self.get_sys(HV_SYS_REG_FAR_EL1);
        let mut regs = self.regs(elr, spsr);
        use fwe_abi::signal as s;
        match esr >> 26 {
            EC_SVC64 => {
                // ELR is past the `svc`; the kernel advances pc past the
                // trapping instruction itself.
                regs.pc = elr - 4;
                syscall(self, &mut regs);
            }
            EC_BRK64 => fault(&mut regs, s::SIGTRAP, elr),
            EC_PC_ALIGN | EC_SP_ALIGN => fault(&mut regs, s::SIGBUS, far),
            EC_DABT_LOWER | EC_IABT_LOWER => {
                // A translation fault (DFSC/IFSC 0b0001xx) a vfork child
                // takes on memory it has not fetched yet: fetched now, the
                // access is tried again.
                if esr & 0x3c == 0x04 && mem::demand(far) {
                    regs.pc = elr;
                } else if esr & 0x3c == 0x0c && esr & (1 << 6) != 0 && mem::view_fault(far) {
                    // A write to a page of a private view of a file: it is
                    // a copy now, and the write is tried again.
                    regs.pc = elr;
                } else if esr & 0x3c == 0x0c && stale_permissions(esr, far) {
                    // A permission fault (0b0011xx) the tables no longer
                    // give: the TLBs are invalidated, the access tried
                    // again.
                    regs.pc = elr;
                } else {
                    let k = kernel();
                    if let Some(k) = k.as_ref().filter(|k| k.tracer.enabled) {
                        k.tracer.note(&format!("guest abort: esr {esr:#x}, far {far:#x}"));
                    }
                    drop(k);
                    fault(&mut regs, s::SIGSEGV, far)
                }
            }
            EC_UNKNOWN => fault(&mut regs, s::SIGILL, elr),
            _ => fault(&mut regs, s::SIGILL, elr),
        }
        regs
    }
}

thread_local! {
    /// The last permission fault taken as a stale TLB entry's, and the
    /// flush asked for it: the same fault after that flush is real.
    static STALE: Cell<(u64, u64)> = const { Cell::new((u64::MAX, 0)) };
}

/// Whether permission fault `esr` at `far` came from a TLB entry older
/// than the tables, which allow the access now: Arm lets a TLB keep a
/// translation's old permissions after they were widened, until it is
/// invalidated. If so, a flush is asked for, which the vCPU takes before
/// it resumes.
fn stale_permissions(esr: u64, far: u64) -> bool {
    let Some(p) = vm::page_perms(far) else { return false };
    let ec = esr >> 26;
    let allowed = if ec == EC_IABT_LOWER {
        p.exec
    } else if esr & (1 << 6) != 0 {
        // WnR: a write.
        p.write
    } else {
        p.read
    };
    if !allowed {
        return false;
    }
    let page = far & !(PAGE - 1);
    let (last, asked) = STALE.with(Cell::get);
    if last == page && vm::flushed_generation() >= asked {
        // Flushed since, and it faults still.
        STALE.with(|c| c.set((u64::MAX, 0)));
        return false;
    }
    STALE.with(|c| c.set((page, vm::request_flush())));
    true
}

/// Deliver synchronous fault `sig` at `addr`, or die of it.
fn fault(regs: &mut Regs, sig: u64, addr: u64) {
    let mut guard = kernel();
    let Some(k) = guard.as_mut() else { fatal("fault before the kernel exists") };
    if !k.deliver_fault(regs, sig, addr) {
        if k.tracer.enabled {
            k.tracer.note(&format!(
                "guest fault: signal {sig} at pc {:#x}, address {addr:#x}",
                regs.pc
            ));
        }
        // Its core first, as Linux dumps it; the VM goes as it ends.
        k.terminate_with(sig, Some(regs));
    }
}

pub(super) fn fatal(msg: &str) -> ! {
    let line = format!("fwe: {msg}\n");
    // SAFETY: writing a diagnostic to standard error.
    unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
    // Not synced: the VM is still alive.
    record::Line::new().s("fatal: ").bytes(msg.as_bytes()).emit_unsynced();
    teardown();
    // SAFETY: exiting, the VM gone.
    unsafe { libc::_exit(127) }
}

/// `execve(path, argv, envp)`: re-execute fwe on the new program, which
/// may run here in a VM or natively (see [`crate::reexec`]).
fn execve(args: &[u64; 6]) -> i64 {
    match uaccess::read_cstr(args[0], uaccess::PATH_MAX) {
        Ok(path) => exec_program(path, args[1], args[2]),
        Err(e) => err(e),
    }
}

/// `execveat(dirfd, path, argv, envp, flags)`: `execve` of the program
/// `dirfd`, `path` and `flags` name.
fn execveat(args: &[u64; 6]) -> i64 {
    let rel = match uaccess::read_cstr(args[1], uaccess::PATH_MAX) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let path = match kernel().as_ref().unwrap().execveat_path(args[0] as i32, &rel, args[4]) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    exec_program(path, args[2], args[3])
}

/// Re-execute fwe on the guest program at `path` with the argument and
/// environment arrays at `argv` and `envp`.
fn exec_program(path: Vec<u8>, argv: u64, envp: u64) -> i64 {
    // Linux's limit on one argument or environment string.
    const ARG_MAX: usize = 128 * 1024;
    let (argv, envp) =
        match (uaccess::read_cstr_array(argv, ARG_MAX), uaccess::read_cstr_array(envp, ARG_MAX)) {
            (Ok(a), Ok(e)) => (a, e),
            (Err(e), _) | (_, Err(e)) => return err(e),
        };
    // No arguments at all: one empty one, as Linux gives the program.
    let argv = if argv.is_empty() { vec![Vec::new()] } else { argv };
    let guard = kernel();
    let k = guard.as_ref().unwrap();
    if let Err(e) = k.may_exec(&path) {
        return err(e);
    }
    let fs = k.fs();
    // The VM goes before the host exec; once the program is known to be
    // runnable, there is no way back.
    let state = k.exec_state();
    let before_exec = || {
        // The robust futexes its threads hold, while its memory is there.
        fwe_kernel::release_robust_lists();
        // A vfork child's changes reach its parent before it goes on.
        mem::finish_lazy();
        teardown();
        record::event("execve", &path);
    };
    let r = crate::reexec(&path, &argv, &envp, fs, k.tracer, &state, before_exec);
    if !VM_LIVE.load(std::sync::atomic::Ordering::SeqCst) {
        fatal(&format!(
            "execve {} failed after the VM was destroyed: {r}",
            String::from_utf8_lossy(&path)
        ));
    }
    r
}

// --- Pointer authentication -------------------------------------------------

thread_local! {
    /// This thread's pointer-authentication keys (APIA, APIB, APDA, APDB,
    /// APGA; low, high), once made.
    static KEYS: Cell<Option<[u64; 10]>> = const { Cell::new(None) };
}

fn random_keys() -> [u64; 10] {
    let mut b = [0u8; 80];
    host::fill_random(&mut b);
    let mut k = [0u64; 10];
    for (i, w) in k.iter_mut().enumerate() {
        *w = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    k
}

/// This thread's keys: a program's first thread gets fresh random ones, as
/// Linux gives a program at `execve`.
pub(super) fn thread_keys() -> [u64; 10] {
    KEYS.with(|c| {
        let k = c.get().unwrap_or_else(random_keys);
        c.set(Some(k));
        k
    })
}

/// Give this thread `keys` (a new thread's creator's, a fork parent's), for
/// its vCPU to take when it is made.
pub(super) fn set_thread_keys(keys: [u64; 10]) {
    KEYS.with(|c| c.set(Some(keys)));
}

/// `prctl(PR_PAC_RESET_KEYS, which, 0, 0, 0)`: new random keys for the
/// calling thread, all of them for `which` = 0.
fn pac_reset_keys(vcpu: &Vcpu, a: &[u64; 6]) -> i64 {
    use fwe_abi::prctl::*;
    let all = PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY | PR_PAC_APGAKEY;
    let f = vm::features();
    if !f.pac || a[1] & !all != 0 || a[2] != 0 || a[3] != 0 || a[4] != 0 {
        return err(errno::EINVAL);
    }
    let which = if a[1] == 0 { all } else { a[1] };
    let fresh = random_keys();
    let mut keys = thread_keys();
    for bit in 0..5 {
        if which & (1 << bit) != 0 {
            keys[bit * 2] = fresh[bit * 2];
            keys[bit * 2 + 1] = fresh[bit * 2 + 1];
        }
    }
    set_thread_keys(keys);
    for (&reg, value) in HV_SYS_REG_PAC_KEYS.iter().zip(keys) {
        vcpu.set_sys(reg, value);
    }
    0
}

/// What a new thread needs to become a guest thread on its own vCPU.
struct Spawn {
    regs: Regs,
    /// The creating thread's pointer-authentication keys, which a new
    /// thread starts with as on Linux.
    keys: [u64; 10],
    tid: i32,
    tpidr: u64,
    clear_child_tid: u64,
    sigmask: u64,
    pending: std::sync::Arc<thread::Pending>,
}

/// `clone(flags, stack, parent_tid, tls, child_tid)`: for a thread (the
/// pthread flags), a new host thread with a vCPU of its own; for a new
/// process (`fork`, `vfork`), a fresh fwe process given this one's memory
/// and state (see [`fork`]).
fn clone(vcpu: &Vcpu, parent: &Regs, a: fwe_kernel::CloneArgs) -> i64 {
    if a.check().is_err() {
        return clone_checked(vcpu, parent, a);
    }
    // A traced parent whose tracer follows its children: its event is
    // raised once the result is in the registers ([`syscall`]).
    let event = fwe_kernel::ptrace::fork_event(a.flags);
    let r = clone_checked(vcpu, parent, a);
    fwe_kernel::ptrace::fork_done();
    if let Some(e) = event
        && r > 0
    {
        fwe_kernel::ptrace::note_fork(e, a.flags, r as u64);
    }
    r
}

fn clone_checked(vcpu: &Vcpu, parent: &Regs, a: fwe_kernel::CloneArgs) -> i64 {
    use fwe_abi::clone as cl;
    let fwe_kernel::CloneArgs { flags, stack, parent_tid: ptid, tls, child_tid: ctid, .. } = a;
    if let Err(e) = a.check() {
        return err(e);
    }
    let tpidr =
        if flags & cl::CLONE_SETTLS != 0 { tls } else { vcpu.get_sys(HV_SYS_REG_TPIDR_EL0) };
    if flags & cl::CLONE_THREAD == 0 {
        // A process sharing the memory while both run would put its pages
        // in two VMs at once, which a VM must never have (see `fork`): only
        // a vfork child, which runs while its parent waits, shares it.
        if flags & cl::CLONE_VM != 0 && flags & cl::CLONE_VFORK == 0 {
            return err(errno::ENOSYS);
        }
        return fork::fork(parent, a, tpidr, vcpu.vtimer_offset(), flags & cl::CLONE_VFORK != 0);
    }
    if flags & cl::CLONE_VM == 0 || stack == 0 {
        return err(errno::EINVAL);
    }
    let tid = thread::alloc_tid();
    // Traced from its start if the tracer follows new threads.
    fwe_kernel::ptrace::new_thread(tid);
    if flags & cl::CLONE_PARENT_SETTID != 0 && ptid != 0 {
        let _ = uaccess::write(ptid, tid);
    }
    if flags & cl::CLONE_CHILD_SETTID != 0 && ctid != 0 {
        let _ = uaccess::write(ctid, tid);
    }
    let mut regs = *parent;
    regs.x[0] = 0;
    regs.sp = stack;
    regs.pc = parent.pc + 4;
    let pending = thread::register(tid);
    let spawn = Box::new(Spawn {
        keys: thread_keys(),
        regs,
        tid,
        tpidr,
        clear_child_tid: if flags & cl::CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 },
        sigmask: thread::mask(),
        pending: pending.clone(),
    });
    crate::LIVE_THREADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let arg = Box::into_raw(spawn).cast::<libc::c_void>();
    let mut handle: libc::pthread_t = 0;
    // SAFETY: a detached pthread with the default stack; `thread_main` takes
    // ownership of the boxed `Spawn`.
    let r = unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        libc::pthread_attr_init(&mut attr);
        libc::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED);
        let r = libc::pthread_create(&mut handle, &attr, thread_main, arg);
        libc::pthread_attr_destroy(&mut attr);
        r
    };
    if r != 0 {
        // SAFETY: reclaiming the box the thread never received.
        drop(unsafe { Box::from_raw(arg.cast::<Spawn>()) });
        crate::LIVE_THREADS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        thread::unregister(&pending);
        return err(errno::EAGAIN);
    }
    thread::set_host_thread(&pending, handle);
    tid as i64
}

extern "C" fn thread_main(arg: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: `arg` is the `Spawn` box handed to `pthread_create`.
    let spawn = unsafe { Box::from_raw(arg.cast::<Spawn>()) };
    thread::set_tid(spawn.tid);
    thread::adopt(&spawn.pending);
    thread::set_mask(spawn.sigmask);
    thread::set_clear_child_tid(spawn.clear_child_tid);
    set_thread_keys(spawn.keys);
    let vcpu = match Vcpu::create() {
        Ok(v) => v,
        Err(e) => fatal(&e),
    };
    vcpu.set_sys(HV_SYS_REG_TPIDR_EL0, spawn.tpidr);
    let regs = spawn.regs;
    drop(spawn);
    vcpu.run(regs)
}

/// Whether pointer argument `i` of system call `n` points at guest memory
/// the call may use: a path, readable up to its terminator; a buffer with
/// a length argument, all of it (writable if the host writes it); anything
/// else, its first byte (`ioctl`'s argument is not checked: it is a
/// pointer only for some requests). The memory up to a page past it is
/// fetched first in a vfork child.
fn pointer_ok(n: u64, i: usize, a: &[u64; 6]) -> bool {
    let p = a[i];
    let path = matches!(
        (n, i),
        (nr::OPENAT | nr::MKDIRAT | nr::MKNODAT | nr::UNLINKAT | nr::FCHMODAT, 1)
            | (nr::FCHOWNAT | nr::FACCESSAT | nr::FACCESSAT2 | nr::NEWFSTATAT, 1)
            | (nr::READLINKAT | nr::STATX | nr::UTIMENSAT, 1)
            | (nr::CHDIR | nr::CHROOT | nr::TRUNCATE | nr::STATFS, 0)
            | (nr::SYMLINKAT, 0 | 2)
            | (nr::LINKAT | nr::RENAMEAT | nr::RENAMEAT2, 1 | 3)
    );
    if path {
        return uaccess::read_cstr(p, uaccess::PATH_MAX).is_ok();
    }
    let (len, write) = host_buffer(n, i, a).unwrap_or((1, false));
    mem::prepare_access(p, len.max(PAGE));
    // `ioctl`'s argument is a pointer only for some requests: translated,
    // and fetched for a vfork child, but not refused.
    n == nr::IOCTL || len == 0 || mem::valid(p, len, write)
}

/// Whether the buffer pointer argument `i` of system call `n` is, with its
/// length, in one translated range or none: the host is given one address
/// for it. (Paths and structures the kernel copies are split where they
/// cross; see `uaccess`.)
fn one_host_range(n: u64, i: usize, a: &[u64; 6]) -> bool {
    host_buffer(n, i, a).is_none_or(|(len, _)| !uaccess::crosses(a[i], len))
}

/// Pointer argument `i` of system call `n` as a buffer of known length the
/// host is given whole: its length, and whether the host writes it.
fn host_buffer(n: u64, i: usize, a: &[u64; 6]) -> Option<(u64, bool)> {
    Some(match (n, i) {
        (nr::READ | nr::PREAD64 | nr::GETDENTS64 | nr::RECVFROM, 1) => (a[2], true),
        (nr::WRITE | nr::PWRITE64 | nr::SENDTO, 1) => (a[2], false),
        (nr::READLINKAT, 2) => (a[3], true),
        (nr::GETCWD | nr::GETRANDOM, 0) => (a[1], true),
        (nr::SETSOCKOPT, 3) => (a[4], false),
        // The length is what the word at `optlen` says.
        (nr::GETSOCKOPT, 3) => (uaccess::read::<u32>(a[4]).map_or(0, u64::from), true),
        (nr::GETSOCKOPT, 4) => (4, true),
        // A struct itimerval.
        (nr::SETITIMER, 1) => (32, false),
        (nr::SETITIMER, 2) | (nr::GETITIMER, 1) => (32, true),
        _ => return None,
    })
}

/// Run the system call in `regs` (number in `x8`), leaving its result and
/// any signal delivery in `regs`.
fn syscall(vcpu: &Vcpu, regs: &mut Regs) {
    // A traced process stopping at system calls: the entry's stop.
    let syscall_stops = fwe_kernel::ptrace::stops_at_syscalls();
    if syscall_stops {
        kernel().as_mut().unwrap().ptrace_syscall_stop(regs, true);
    }
    let n = regs.x[8];
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    // The process's seccomp filters decide first, for every call.
    if fwe_kernel::seccomp::mode() != 0 {
        let action = fwe_kernel::seccomp::check(n, &args, regs.pc);
        if action == fwe_kernel::seccomp::Action::KillThread && thread::live_threads() > 1 {
            // The thread ends without the kernel lock, as `exit` does.
            let _ = vcpu;
            fwe_kernel::thread_exit_cleanup();
            exit_thread(128 + fwe_abi::signal::SIGSYS as i32)
        }
        if action != fwe_kernel::seccomp::Action::Allow {
            kernel().as_mut().unwrap().seccomp_refuse(regs, n, &args, action);
            return;
        }
    }
    // The kernel and the host see host addresses for guest pointers.
    let mask = match n {
        nr::FUTEX => uaccess::futex_pointer_args(args[1]),
        nr::FCNTL => uaccess::fcntl_pointer_args(args[1]),
        nr::PRCTL => uaccess::prctl_pointer_args(args[0]),
        _ => uaccess::pointer_args(n),
    };
    // Guest pointers the host is given must be guest memory: the host's
    // memory behind them is accessible either way (see `mem`). A vfork
    // child fetches what they reach first.
    uaccess::clear_host_args();
    for (i, &a) in args.iter().enumerate() {
        if mask & (1 << i) != 0 && a != 0 && !pointer_ok(n, i, &args) {
            kernel().as_mut().unwrap().finish_syscall(regs, n, &args, err(errno::EFAULT));
            return;
        }
    }
    // Buffers the host is given whole must have one host address.
    for (i, &a) in args.iter().enumerate() {
        if mask & (1 << i) != 0 && a != 0 && !one_host_range(n, i, &args) {
            kernel().as_mut().unwrap().finish_syscall(regs, n, &args, err(errno::EINVAL));
            return;
        }
    }
    let mut host_args = args;
    for (i, a) in host_args.iter_mut().enumerate() {
        if mask & (1 << i) != 0 {
            *a = uaccess::host_arg(*a);
        }
    }
    let result = match n {
        nr::RT_SIGRETURN => {
            kernel().as_mut().unwrap().enter_syscall(regs);
            return;
        }
        nr::EXIT => {
            let _ = vcpu;
            fwe_kernel::thread_exit_cleanup();
            exit_thread(args[0] as i32)
        }
        nr::CLONE => clone(vcpu, regs, fwe_kernel::CloneArgs::from_clone(&regs.x)),
        nr::CLONE3 => match fwe_kernel::CloneArgs::from_clone3(host_args[0], host_args[1]) {
            Ok(a) => clone(vcpu, regs, a),
            Err(e) => err(e),
        },
        nr::PRCTL if args[0] == fwe_abi::prctl::PR_PAC_RESET_KEYS => pac_reset_keys(vcpu, &args),
        nr::EXECVE => execve(&host_args),
        nr::EXECVEAT => execveat(&host_args),
        nr::WAIT4 => {
            let mut r = *regs;
            r.x[..6].copy_from_slice(&host_args);
            crate::process::do_wait4(&r)
        }
        nr::WAITID => {
            let mut r = *regs;
            r.x[..6].copy_from_slice(&host_args);
            crate::process::do_waitid(&r)
        }
        n if fwe_kernel::ipcops::waits(n) => {
            // As in the native backend: the context under the lock, the
            // wait without it.
            let ctx = kernel().as_ref().unwrap().ipc_context();
            fwe_kernel::ipcops::blocking(ctx, n, host_args)
        }
        nr::PIDFD_GETFD => {
            let req =
                kernel().as_ref().unwrap().getfd_request(host_args[0], host_args[1], host_args[2]);
            fwe_kernel::pidfd::getfd(req)
        }
        nr::RT_SIGTIMEDWAIT => {
            let want: u64 = uaccess::read(host_args[0]).unwrap_or(0);
            kernel().as_mut().unwrap().catch_for_wait(want);
            // SAFETY: guest pointers, translated, reference guest memory.
            let r = unsafe {
                fwe_kernel::signal::sigtimedwait(
                    host_args[0],
                    host_args[1],
                    host_args[2],
                    host_args[3],
                )
            };
            kernel().as_mut().unwrap().end_wait(want);
            r
        }
        _ => {
            // SAFETY: guest pointers, translated, reference guest memory.
            match unsafe { fwe_kernel::blocking_syscall(n, host_args) } {
                Some(r) => r,
                None => KERNEL.run_call(n, host_args),
            }
        }
    };
    // Guest addresses only from here on (a signal frame, say).
    uaccess::clear_host_args();
    KERNEL.finish(regs, n, &args, result);
    // A fork's event stops, the child's pid in `x0`.
    if matches!(n, nr::CLONE | nr::CLONE3) {
        kernel().as_mut().unwrap().ptrace_fork_stops(regs);
    }
    // The exit's stop, its result in `x0`.
    if syscall_stops {
        kernel().as_mut().unwrap().ptrace_syscall_stop(regs, false);
    }
}
