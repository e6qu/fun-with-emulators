//! The VMM: loading, the vCPU run loop and the system call path.

use super::ffi::*;
use super::{fork, vm, window};
use crate::{Error, Options, STACK_SIZE, cmdline, hostname, hwcap, ncpu, page_size, stack};
use fwe_abi::{auxv, err, errno, mman, nr};
use fwe_elf::{Elf, LoadPlan, PF_R, PF_W, PF_X};
use fwe_kernel::{Brk, FpRegs, HostSignal, Kernel, Platform, Regs, Tracer, host, thread, uaccess};
use std::cell::Cell;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// The kernel of the guest running in this VM.
static KERNEL: Mutex<Option<Kernel<HvPlatform>>> = Mutex::new(None);

pub(super) fn kernel() -> MutexGuard<'static, Option<Kernel<HvPlatform>>> {
    KERNEL.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    /// This thread's vCPU, for the signal handler to stop it.
    static VCPU: Cell<Option<hv_vcpu_t>> = const { Cell::new(None) };
}

/// [`Platform`] for guests running in the VM.
pub struct HvPlatform;

impl Platform for HvPlatform {
    fn prepare_exec(&mut self, _addr: u64, _len: u64) -> Result<(), i32> {
        // The guest's code runs as it is.
        Ok(())
    }

    fn exit(&mut self, code: i32) -> ! {
        teardown();
        // SAFETY: terminating the process, its VM gone.
        unsafe { libc::_exit(code) }
    }

    fn exit_thread(&mut self, code: i32) -> ! {
        exit_thread(code)
    }

    fn kill_self(&mut self, sig: libc::c_int) -> ! {
        teardown();
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

    fn stop_self(&mut self) {
        // SAFETY: plain host call; the process resumes on SIGCONT.
        unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
    }

    fn set_host_signal(&mut self, sig: u64, how: HostSignal) {
        set_host_signal(sig, how);
    }

    fn map_guest(&mut self, addr: u64, len: u64, prot: u64) -> Result<(), i32> {
        let host = uaccess::g2h(addr);
        window::mark_used(host, len);
        vm::map(addr, host, len, prot)
    }

    fn place_mapping(&mut self, len: u64) -> Option<u64> {
        window::alloc(len)
    }

    fn release_host(&mut self, addr: u64, len: u64) -> bool {
        window::release(addr, len)
    }

    fn unmap_guest(&mut self, addr: u64, len: u64) {
        vm::unmap(addr, len);
    }

    fn protect_guest(&mut self, addr: u64, len: u64, prot: u64) {
        vm::protect(addr, len, prot);
    }

    fn replacing_guest(&mut self, addr: u64, len: u64) {
        vm::detach(addr, len);
    }

    fn remapped_guest(&mut self, addr: u64, len: u64) {
        vm::refresh(addr, len);
    }
}

// --- Ending a VM process cleanly -----------------------------------------
//
// A process must never end, or exec, with its VM alive: the machine this was
// developed on panicked twice in that situation (a kernel NULL dereference in
// a kernel thread while a VM process was being torn down, and a watchdog
// reset two minutes after a VM process was killed by a signal), with another
// hypervisor client running alongside. So every way out — exit_group, the
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
        let mut others: Vec<hv_vcpu_t> =
            live_vcpus().into_iter().filter(|&v| Some(v) != own).collect();
        if !others.is_empty() {
            // SAFETY: stopping the other threads' vCPUs, which may be running.
            unsafe { hv_vcpus_exit(others.as_mut_ptr(), others.len() as u32) };
        }
        if RUNNING.load(SeqCst) == 0 {
            return;
        }
        // SAFETY: plain host call.
        unsafe { libc::usleep(20) };
    }
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

/// Destroy the calling thread's vCPU, if it has one. Async-signal-safe.
fn retire_vcpu() {
    use std::sync::atomic::Ordering::SeqCst;
    if let Some(id) = VCPU.with(|c| c.take()) {
        // SAFETY: destroying this thread's own vCPU, which is not running.
        unsafe { hv_vcpu_destroy(id) };
        for s in &VCPU_SLOTS {
            let _ = s.compare_exchange(id + 1, 0, SeqCst, SeqCst);
        }
    }
}

fn live_vcpus() -> Vec<hv_vcpu_t> {
    use std::sync::atomic::Ordering::SeqCst;
    VCPU_SLOTS.iter().map(|s| s.load(SeqCst)).filter(|&v| v != 0).map(|v| v - 1).collect()
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
    let mut others: Vec<hv_vcpu_t> = live_vcpus().into_iter().filter(|&v| Some(v) != own).collect();
    if !others.is_empty() {
        // SAFETY: stopping the other threads' vCPUs, which may be running.
        unsafe { hv_vcpus_exit(others.as_mut_ptr(), others.len() as u32) };
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
        teardown();
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
        if !IN_RUN.with(Cell::get) {
            retire_vcpu();
        }
        return;
    }
    if sig != host::WAKE_SIGNAL {
        // SAFETY: `info` is valid for SA_SIGINFO handlers.
        let (code, pid, uid, status) = unsafe { host::signal_info(sig, info) };
        // The relayed form of a guest's SIGKILL (see host::KILL_RELAY).
        let lsig = if sig == host::KILL_RELAY {
            fwe_abi::signal::SIGKILL
        } else {
            host::signal_to_linux(sig)
        };
        thread::post_self(lsig, thread::SigInfo { code, pid, uid, status });
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
    // the VM down first, never by the host's with the VM alive.
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

fn host_prot(prot: u64) -> libc::c_int {
    let mut h = libc::PROT_NONE;
    if prot & mman::PROT_READ != 0 {
        h |= libc::PROT_READ;
    }
    if prot & mman::PROT_WRITE != 0 {
        h |= libc::PROT_WRITE;
    }
    h
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

/// Fresh, zeroed, writable host memory.
fn host_alloc(len: u64) -> Result<u64, Error> {
    let at = window::alloc(len)
        .ok_or_else(|| Error::Unsupported("the guest memory window is full".into()))?;
    // SAFETY: fresh private anonymous memory replacing part of the window's
    // reservation.
    let p = unsafe {
        libc::mmap(
            at as *mut libc::c_void,
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Error::Unsupported(format!(
            "allocating guest memory failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    fwe_kernel::mm::track(p as u64, len);
    Ok(p as u64)
}

fn vm_map(guest: u64, host: u64, len: u64, prot: u64) -> Result<(), Error> {
    vm::map(guest, host, len, prot).map_err(|e| {
        Error::Unsupported(format!("mapping {guest:#x}+{len:#x} into the VM failed: errno {e}"))
    })
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

/// Load `elf` into host memory and the VM. A non-PIE image goes at its link
/// address in the VM, backed by host memory elsewhere (the translated range);
/// a PIE one wherever the host puts it, at the same address in both.
fn place(elf: &Elf<'_>, page: u64, translate: bool) -> Result<Placed, Error> {
    let plan = LoadPlan::new(elf, page);
    let host = host_alloc(plan.len)?;
    let (guest, bias) = if elf.is_pie() { (host, host - plan.start) } else { (plan.start, 0) };
    for ph in elf.loads() {
        let src = &elf.data[ph.offset as usize..(ph.offset + ph.filesz) as usize];
        let at = host + (ph.vaddr - plan.start);
        // SAFETY: the segment lies within the fresh allocation.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), at as *mut u8, src.len()) };
    }
    if translate && guest != host {
        uaccess::set_translation(guest, plan.len, host);
    }
    for run in &plan.runs {
        let off = run.start - plan.start;
        let prot = prot_of(run.prot);
        vm_map(guest + off, host + off, run.len, prot)?;
        // The host copy gets the same protections, so the kernel's own
        // accesses fault (and report EFAULT) where the guest's would.
        // SAFETY: changing protections of the allocation made above.
        unsafe {
            libc::mprotect((host + off) as *mut _, run.len as usize, host_prot(prot));
        }
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
    let page = page_size();
    let tracer = Tracer { enabled: options.strace };
    // Hypervisor.framework runs threads of its own, which inherit the mask
    // of the thread that creates them. With every guest signal blocked
    // there, the host delivers signals only to the vCPU threads, whose masks
    // follow the guest's. The mask fwe started with is the guest's own.
    let inherited_mask = host::blocked_signals();
    window::reserve().map_err(Error::Unsupported)?;
    become_vm_process().map_err(|e| {
        Error::Unsupported(format!(
            "this program is linked below 4 GiB, which needs the hypervisor backend, \
             and creating the VM failed ({e}); fwe must be signed with the \
             com.apple.security.hypervisor entitlement (see docs/hypervisor.md) \
             on a Mac with hypervisor support"
        ))
    })?;
    let mut fs = crate::open_fs(options)?;

    let elf = Elf::parse(data).map_err(Error::Elf)?;
    let exe = place(&elf, page, true)?;
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
            Some(place(&ielf, page, false)?)
        }
        None => None,
    };

    // The break: anywhere in the host above the image, the same address in
    // the VM; its pages enter the VM as `brk` commits them.
    let brk_start = host_alloc(Brk::RESERVATION)?;
    // SAFETY: making the reservation inaccessible until `brk` commits it.
    unsafe { libc::mprotect(brk_start as *mut _, Brk::RESERVATION as usize, libc::PROT_NONE) };
    let brk = Brk { start: brk_start, current: brk_start, limit: brk_start + Brk::RESERVATION };
    let _ = exe.end;

    // The stack, with an inaccessible guard page below it.
    let stack_base = host_alloc(STACK_SIZE + page)?;
    vm_map(stack_base + page, stack_base + page, STACK_SIZE, mman::PROT_READ | mman::PROT_WRITE)?;
    let stack_top = stack_base + page + STACK_SIZE;

    let (hwcap, hwcap2) = hwcap::detect();
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
    let execfn = path.as_os_str().as_bytes();
    let mut random = [0u8; 16];
    host::fill_random(&mut random);
    let image =
        stack::InitialStack { args: &arg_bytes, env: &env_bytes, execfn, auxv: &aux, random }
            .build(stack_top);
    // SAFETY: the image fits in the stack mapping, ending at its top.
    unsafe {
        std::ptr::copy_nonoverlapping(image.bytes.as_ptr(), image.sp as *mut u8, image.bytes.len())
    };

    // The rt_sigreturn trampoline.
    let tramp = host_alloc(page)?;
    // SAFETY: two instruction words into the fresh page.
    unsafe {
        (tramp as *mut u32).write(SIGRETURN[0]);
        ((tramp + 4) as *mut u32).write(SIGRETURN[1]);
    }
    vm_map(tramp, tramp, page, mman::PROT_READ | mman::PROT_EXEC)?;

    let entry = interp.as_ref().map_or(exe.entry, |i| i.entry);
    if options.strace {
        tracer.note(&format!(
            "hypervisor backend: exe entry {:#x}, image translated to host {:#x}, \
             interp base {:#x}, brk {brk_start:#x}, stack top {stack_top:#x}",
            exe.entry,
            uaccess::g2h(exe.entry),
            interp.as_ref().map_or(0, |i| i.bias),
        ));
    }

    fs.set_proc_info(crate::guest_exe_path(path, options), cmdline(&arg_bytes), ncpu(), hostname());
    fwe_kernel::net::set_rootfs(fs.root_host_path());
    thread::init_main(host::getpid() as i32);
    let mut k = Kernel::new(HvPlatform, page, brk, Some(fs), tracer);
    crate::apply_exec_state(&mut k, options)?;
    k.set_sigreturn_trampoline(tramp);
    k.adopt_host_signals();
    thread::set_mask(inherited_mask);
    *kernel() = Some(k);

    let regs = Regs { sp: image.sp, pc: entry, ..Regs::default() };
    let vcpu = Vcpu::create().map_err(Error::Unsupported)?;
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
        // SAFETY: out-parameters for a vCPU owned by this thread.
        let rc = unsafe { hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut()) };
        check(rc, "hv_vcpu_create")?;
        let v = Vcpu { id, exit };
        for (reg, value) in vm::system_registers() {
            v.set_sys(reg, value);
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
        unsafe { hv_vcpu_get_reg(self.id, reg, &mut v) };
        v
    }

    fn set(&self, reg: hv_reg_t, v: u64) {
        // SAFETY: writing a register of this thread's vCPU.
        unsafe { hv_vcpu_set_reg(self.id, reg, v) };
    }

    fn get_sys(&self, reg: hv_sys_reg_t) -> u64 {
        let mut v = 0;
        // SAFETY: reading a system register of this thread's vCPU.
        unsafe { hv_vcpu_get_sys_reg(self.id, reg, &mut v) };
        v
    }

    fn set_sys(&self, reg: hv_sys_reg_t, v: u64) {
        // SAFETY: writing a system register of this thread's vCPU.
        unsafe { hv_vcpu_set_sys_reg(self.id, reg, v) };
    }

    /// The guest's registers, with `pc` and `pstate` as given.
    fn regs(&self, pc: u64, pstate: u64) -> Regs {
        let mut r = Regs { pc, pstate, sp: self.get_sys(HV_SYS_REG_SP_EL0), ..Regs::default() };
        for i in 0..31 {
            r.x[i] = self.get(HV_REG_X0 + i as u32);
        }
        let mut fp = FpRegs {
            fpsr: self.get(HV_REG_FPSR) as u32,
            fpcr: self.get(HV_REG_FPCR) as u32,
            ..FpRegs::default()
        };
        for (i, v) in fp.v.iter_mut().enumerate() {
            // SAFETY: reading a SIMD register of this thread's vCPU.
            unsafe { hv_vcpu_get_simd_fp_reg(self.id, i as u32, v) };
        }
        r.fp = fp;
        r
    }

    /// Resume the guest at EL0 with `r`.
    fn set_regs(&self, r: &Regs) {
        for i in 0..31 {
            self.set(HV_REG_X0 + i as u32, r.x[i]);
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
            unsafe { set_simd_fp_reg(self.id, i as u32, v) };
        }
    }

    pub(super) fn set_thread_pointer(&self, tpidr: u64) {
        self.set_sys(HV_SYS_REG_TPIDR_EL0, tpidr);
    }

    pub(super) fn vtimer_offset(&self) -> u64 {
        let mut offset = 0;
        // SAFETY: reading this thread's vCPU's timer offset.
        unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut offset) };
        offset
    }

    fn set_vtimer_offset(&self, offset: u64) {
        // SAFETY: setting this thread's vCPU's timer offset.
        unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) };
    }

    /// Run the guest from `regs` until the process ends.
    pub(super) fn run(&self, mut regs: Regs) -> ! {
        self.set_regs(&regs);
        loop {
            if EXITING.load(std::sync::atomic::Ordering::SeqCst) {
                park();
            }
            // The guest's mask is in force on the host while it runs, so the
            // host routes signals as for the native backend.
            let mask = host::host_mask_for(thread::mask());
            enter_run();
            // SAFETY: plain host calls; `exit` is HVF's record for this vCPU.
            let (rc, exit) = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
                IN_RUN.with(|r| r.set(true));
                let rc = hv_vcpu_run(self.id);
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
            unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut offset) };
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
            EC_DABT_LOWER | EC_IABT_LOWER => fault(&mut regs, s::SIGSEGV, far),
            EC_UNKNOWN => fault(&mut regs, s::SIGILL, elr),
            _ => fault(&mut regs, s::SIGILL, elr),
        }
        regs
    }
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
        let h = host::signal_to_host(sig).unwrap_or(libc::SIGSEGV);
        k.platform.kill_self(h);
    }
}

fn fatal(msg: &str) -> ! {
    let line = format!("fwe: {msg}\n");
    // SAFETY: writing a diagnostic to standard error.
    unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
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
    let guard = kernel();
    let k = guard.as_ref().unwrap();
    let fs = k.fs.as_ref().expect("filesystem configured");
    // The VM goes before the host exec; once the program is known to be
    // runnable, there is no way back.
    let state = k.exec_state();
    let r = crate::reexec(&path, &argv, &envp, fs, k.tracer.enabled, &state, teardown);
    if !VM_LIVE.load(std::sync::atomic::Ordering::SeqCst) {
        fatal(&format!(
            "execve {} failed after the VM was destroyed: {r}",
            String::from_utf8_lossy(&path)
        ));
    }
    r
}

/// What a new thread needs to become a guest thread on its own vCPU.
struct Spawn {
    regs: Regs,
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
    use fwe_abi::clone as cl;
    let fwe_kernel::CloneArgs { flags, stack, parent_tid: ptid, tls, child_tid: ctid } = a;
    let tpidr =
        if flags & cl::CLONE_SETTLS != 0 { tls } else { vcpu.get_sys(HV_SYS_REG_TPIDR_EL0) };
    if flags & cl::CLONE_THREAD == 0 {
        return fork::fork(parent, a, tpidr, vcpu.vtimer_offset(), flags & cl::CLONE_VFORK != 0);
    }
    if flags & cl::CLONE_VM == 0 || stack == 0 {
        return err(errno::EINVAL);
    }
    let tid = thread::alloc_tid();
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
    let vcpu = match Vcpu::create() {
        Ok(v) => v,
        Err(e) => fatal(&e),
    };
    vcpu.set_sys(HV_SYS_REG_TPIDR_EL0, spawn.tpidr);
    let regs = spawn.regs;
    drop(spawn);
    vcpu.run(regs)
}

/// Run the system call in `regs` (number in `x8`), leaving its result and
/// any signal delivery in `regs`.
fn syscall(vcpu: &Vcpu, regs: &mut Regs) {
    let n = regs.x[8];
    let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
    // The kernel and the host see host addresses for guest pointers.
    let mask = if n == nr::FUTEX {
        uaccess::futex_pointer_args(args[1])
    } else {
        uaccess::pointer_args(n)
    };
    let mut host_args = args;
    for (i, a) in host_args.iter_mut().enumerate() {
        if mask & (1 << i) != 0 {
            *a = uaccess::g2h(*a);
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
                None => kernel().as_mut().unwrap().run_call(n, host_args),
            }
        }
    };
    kernel().as_mut().unwrap().finish_syscall(regs, n, &args, result);
}
