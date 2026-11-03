//! `fork` and `vfork` in the VM.
//!
//! A host `fork` of a VM process is out of the question: the child could not
//! use the VM it copied, and a VM process must never fork (see
//! `docs/hypervisor.md`). Instead the child is a fresh fwe process, started
//! with `posix_spawn`, that receives the parent's memory copy-on-write and
//! its kernel state, builds a VM of its own around them and resumes the
//! guest where the parent called `fork`, with `x0` = 0.
//!
//! - **Memory.** All guest memory lives in one host address window
//!   ([`super::window`]). For each region in it the parent takes a Mach
//!   memory entry: `MAP_MEM_VM_COPY` for private memory, a copy-on-write
//!   snapshot that costs nothing until either side writes a page, and
//!   `MAP_MEM_VM_SHARE` for `MAP_SHARED` memory, which stays shared. The
//!   child maps each entry at the same address, inside its own reservation
//!   of the window, and maps the VM's guest ranges onto them as the parent's
//!   are.
//! - **Hand-off.** The parent gives the child a receive right of its own as
//!   its bootstrap port. The child sends a request there; the reply carries
//!   the memory entries, the real bootstrap port (which the child puts back)
//!   and the state as out-of-line data.
//! - **State.** The kernel's own ([`fwe_kernel::Kernel::save_for_fork`]),
//!   then what the backend holds: the forking thread's registers and thread
//!   pointer, the VM's mappings and the memory regions.
//! - **Descriptors.** Every descriptor is inherited, close-on-exec ones
//!   too (their flag is cleared for the spawn and set back on both sides),
//!   except kqueues, which the host never passes on: the kernel rebuilds
//!   the ones behind `epoll` and `timerfd`.
//! - **Consistency.** The parent takes the snapshot with the kernel lock
//!   held and every other vCPU stopped, so the child sees one instant of the
//!   process, as Linux's fork copies the address space atomically.
//!
//! The parent returns once the child has its memory and state and is about
//! to run (a pipe carries its word); a `vfork` parent waits on, until the
//! child execs or exits. As for the native backend, the `vfork` child gets a
//! copy of the parent's memory rather than sharing it.

use super::backend::{self, HvPlatform};
use super::{vm, window};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::snapshot::{Dec, Enc};
use fwe_kernel::{FpRegs, Kernel, Regs, fdtable, host, mm, thread, uaccess};
use std::sync::atomic::{AtomicI32, Ordering};

// --- Mach ---------------------------------------------------------------

type Port = u32;

const KERN_SUCCESS: i32 = 0;
const TASK_BOOTSTRAP_PORT: i32 = 4;
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
const MACH_MSG_TYPE_MOVE_SEND_ONCE: u32 = 18;
const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const MACH_SEND_MSG: i32 = 1;
const MACH_RCV_MSG: i32 = 2;
const MACH_SEND_TIMEOUT: i32 = 0x10;
const MACH_RCV_TIMEOUT: i32 = 0x100;
const MACH_RCV_TIMED_OUT: i32 = 0x1000_4003;
const MACH_MSG_VIRTUAL_COPY: u32 = 1;
const MACH_MSG_OOL_DESCRIPTOR: u32 = 1;
const MACH_MSG_OOL_PORTS_DESCRIPTOR: u32 = 2;
const MAP_MEM_VM_COPY: i32 = 0x20_0000;
const MAP_MEM_VM_SHARE: i32 = 0x40_0000;
const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_FLAGS_OVERWRITE: i32 = 0x4000;
const VM_INHERIT_SHARE: u32 = 0;
const VM_INHERIT_COPY: u32 = 1;

/// `mach_msg_header_t`.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Default)]
struct Header {
    bits: u32,
    size: u32,
    remote: Port,
    local: Port,
    voucher: Port,
    id: i32,
}

/// `mach_msg_ool_ports_descriptor_t` and `mach_msg_ool_descriptor_t` (the
/// same shape in a 64-bit task): an address, then one word of bit fields
/// (`deallocate:8, copy:8, disposition or pad:8, type:8`), then a count.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Default)]
struct Ool {
    address: u64,
    bits: u32,
    count: u32,
}

/// The parent's reply: the ports (the real bootstrap port, then one memory
/// entry per region) and the state.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Default)]
struct Handoff {
    header: Header,
    descriptors: u32,
    ports: Ool,
    state: Ool,
}

/// Room for a received message and the trailer the kernel appends.
#[repr(C, packed(4))]
struct Received<T> {
    message: T,
    trailer: [u8; 64],
}

unsafe extern "C" {
    static mach_task_self_: Port;
    static mut bootstrap_port: Port;
    fn mach_port_allocate(task: Port, right: u32, name: *mut Port) -> i32;
    fn mach_port_insert_right(task: Port, name: Port, poly: Port, poly_type: u32) -> i32;
    fn mach_port_deallocate(task: Port, name: Port) -> i32;
    fn mach_port_mod_refs(task: Port, name: Port, right: u32, delta: i32) -> i32;
    fn task_get_special_port(task: Port, which: i32, port: *mut Port) -> i32;
    fn task_set_special_port(task: Port, which: i32, port: Port) -> i32;
    fn mach_msg(
        msg: *mut Header,
        option: i32,
        send_size: u32,
        rcv_size: u32,
        rcv_name: Port,
        timeout: u32,
        notify: Port,
    ) -> i32;
    fn mach_make_memory_entry_64(
        task: Port,
        size: *mut u64,
        offset: u64,
        permission: i32,
        handle: *mut Port,
        parent: Port,
    ) -> i32;
    fn mach_vm_map(
        task: Port,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: Port,
        offset: u64,
        copy: i32,
        cur: i32,
        max: i32,
        inheritance: u32,
    ) -> i32;
    fn mach_vm_deallocate(task: Port, address: u64, size: u64) -> i32;
    fn posix_spawnattr_setspecialport_np(
        attr: *mut libc::posix_spawnattr_t,
        port: Port,
        which: i32,
    ) -> i32;
    static environ: *const *const libc::c_char;
}

fn task() -> Port {
    // SAFETY: reading the task port the runtime set up at startup.
    unsafe { mach_task_self_ }
}

/// The `msgh_id` of the child's request and of the answer.
const HANDOFF_ID: i32 = 0x6677_6b01;
/// Leads the state: the format, and the build that wrote it, which must be
/// the build reading it.
const STATE_MAGIC: u64 = 0x6677_652d_666f_726b;

fn build_id() -> u64 {
    // The crate version and the size of this binary's executable file
    // tell builds apart well enough for a binary talking to itself.
    let size = crate::FWE_EXE.get().and_then(|p| std::fs::metadata(p).ok()).map_or(0, |m| m.len());
    size ^ env!("CARGO_PKG_VERSION").bytes().fold(0u64, |h, b| h.rotate_left(5) ^ b as u64)
}

/// How long either side waits for the other's message.
const HANDOFF_TIMEOUT_MS: u32 = 10_000;

// --- What the child is given ----------------------------------------------

/// A host memory region the child maps at the same address.
struct Region {
    addr: u64,
    size: u64,
    /// Host protections, `PROT_*` (the same bits as `VM_PROT_*`).
    prot: i32,
    /// The protections the entry carries, the most the child may use.
    max: i32,
    /// `MAP_SHARED` memory: parent and child keep sharing it.
    shared: bool,
}

/// One memory entry per region of guest memory, with the regions. Private
/// memory is snapshotted copy-on-write, shared memory shared. A region the
/// host has made unreadable is made readable for the moment it takes.
fn take_memory() -> Result<(Vec<Region>, Vec<Port>), String> {
    // The child can only rebuild a VM whose memory is all in the window.
    let used = window::used_ranges();
    for (guest, len, _, host) in vm::mapping_list() {
        let covered = used.range(..=host).next_back().is_some_and(|(_, &end)| end >= host + len);
        if !covered {
            return Err(format!(
                "guest memory at {guest:#x} lies outside fwe's window, so it cannot be handed on"
            ));
        }
    }
    let mut regions = Vec::new();
    let mut entries = Vec::new();
    for (start, end) in window::used_ranges() {
        let mut at = start;
        while at < end {
            let Some(r) = mm::region::query(at) else { break };
            if r.start >= end {
                break;
            }
            let (lo, hi) = (r.start.max(at), (r.start + r.size).min(end));
            at = hi;
            let prot = r.protection & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
            let shared = !r.private();
            if prot & libc::PROT_READ == 0 {
                // SAFETY: briefly readable, with every vCPU stopped and the
                // kernel lock held; restored below.
                unsafe { libc::mprotect(lo as *mut _, (hi - lo) as usize, libc::PROT_READ) };
            }
            let mode = if shared { MAP_MEM_VM_SHARE } else { MAP_MEM_VM_COPY };
            let mut entry = 0;
            let mut max = VM_PROT_READ | VM_PROT_WRITE;
            let mut kr = KERN_SUCCESS;
            for want in [VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ] {
                let mut size = hi - lo;
                // SAFETY: an entry for a range of this task's own memory.
                kr = unsafe {
                    mach_make_memory_entry_64(task(), &mut size, lo, mode | want, &mut entry, 0)
                };
                if kr == KERN_SUCCESS && size != hi - lo {
                    // SAFETY: dropping the entry, which does not cover the region.
                    unsafe { mach_port_deallocate(task(), entry) };
                    kr = -1;
                    break;
                }
                if kr == KERN_SUCCESS {
                    max = want;
                    break;
                }
            }
            if prot & libc::PROT_READ == 0 {
                // SAFETY: putting back the protections the region had.
                unsafe { libc::mprotect(lo as *mut _, (hi - lo) as usize, prot) };
            }
            if kr != KERN_SUCCESS {
                release_ports(&entries);
                return Err(format!("snapshotting memory at {lo:#x} failed ({kr:#x})"));
            }
            regions.push(Region { addr: lo, size: hi - lo, prot, max, shared });
            entries.push(entry);
        }
    }
    Ok((regions, entries))
}

fn release_ports(ports: &[Port]) {
    for &p in ports {
        // SAFETY: dropping a send right this task holds.
        unsafe { mach_port_deallocate(task(), p) };
    }
}

fn save_regs(e: &mut Enc, r: &Regs) {
    for &x in &r.x {
        e.u64(x);
    }
    e.u64(r.sp);
    e.u64(r.pc);
    e.u64(r.pstate);
    for &v in &r.fp.v {
        e.u64(v as u64);
        e.u64((v >> 64) as u64);
    }
    e.u32(r.fp.fpsr);
    e.u32(r.fp.fpcr);
}

fn read_regs(d: &mut Dec) -> Regs {
    let mut r = Regs::default();
    for x in &mut r.x {
        *x = d.u64();
    }
    r.sp = d.u64();
    r.pc = d.u64();
    r.pstate = d.u64();
    let mut fp = FpRegs::default();
    for v in &mut fp.v {
        *v = d.u64() as u128 | (d.u64() as u128) << 64;
    }
    fp.fpsr = d.u32();
    fp.fpcr = d.u32();
    r.fp = fp;
    r
}

/// In a `vfork` child, the write end of the pipe its parent waits on, or -1:
/// it closes on exec or exit, and is never handed down to a child of its own.
static VFORK_WORD: AtomicI32 = AtomicI32::new(-1);

/// Whether descriptor `fd` (of `proc_fdinfo` type `kind`) is guarded: XNU
/// kills a process that clears close-on-exec on a guarded descriptor, and
/// one is never the guest's. A descriptor whose state cannot be read counts
/// as guarded, so it is left alone.
fn guarded(fd: i32, kind: u32) -> bool {
    // <sys/proc_info.h>: the PROC_PIDFD*INFO flavor for each PROX_FDTYPE_*,
    // whose record starts with `struct proc_fileinfo`.
    let flavor = match kind {
        1 => 1, // vnode
        2 => 3, // socket
        3 => 5, // POSIX shared memory
        4 => 4, // POSIX semaphore
        6 => 6, // pipe
        _ => return true,
    };
    const PROC_FP_GUARDED: u32 = 4;
    let mut buf = [0u64; 512];
    // SAFETY: reading one descriptor's record into a 4 KiB buffer.
    let n =
        unsafe { libc::proc_pidfdinfo(libc::getpid(), fd, flavor, buf.as_mut_ptr().cast(), 4096) };
    // fi_status is the second 32-bit word.
    n < 8 || (buf[0] >> 32) as u32 & PROC_FP_GUARDED != 0
}

/// The host descriptors to hand down, with their close-on-exec flags:
/// everything open except kqueues, guarded descriptors, `skip` and a vfork
/// parent's pipe.
fn descriptors(skip: i32) -> Vec<(i32, bool)> {
    let vfork_word = VFORK_WORD.load(Ordering::SeqCst);
    // SAFETY: with no buffer, the call reports the size the list needs.
    let need = unsafe {
        libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    let room = need.max(0) as usize / size_of::<libc::proc_fdinfo>() + 64;
    let mut buf = vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; room];
    let bytes = (buf.len() * size_of::<libc::proc_fdinfo>()) as i32;
    // SAFETY: listing this process's descriptors into a buffer of `bytes`.
    let n = unsafe {
        libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), bytes)
    };
    let count = (n.max(0) as usize / size_of::<libc::proc_fdinfo>()).min(buf.len());
    buf[..count]
        .iter()
        .filter(|f| {
            f.proc_fdtype != libc::PROX_FDTYPE_KQUEUE as u32
                && f.proc_fd != skip
                && f.proc_fd != vfork_word
                && !guarded(f.proc_fd, f.proc_fdtype)
        })
        .map(|f| {
            // SAFETY: F_GETFD only queries the descriptor.
            let flags = unsafe { libc::fcntl(f.proc_fd, libc::F_GETFD) };
            (f.proc_fd, flags >= 0 && flags & libc::FD_CLOEXEC != 0)
        })
        .collect()
}

// --- The parent -----------------------------------------------------------

/// `fork` or `vfork` (a non-thread `clone`) from the guest thread whose
/// registers are `parent` and thread pointer `tpidr`. Returns the child's
/// pid or a negated Linux errno.
pub(super) fn fork(
    parent: &Regs,
    a: fwe_kernel::CloneArgs,
    tpidr: u64,
    vtimer_offset: u64,
    vfork: bool,
) -> i64 {
    let fwe_kernel::CloneArgs { flags, stack: child_stack, parent_tid, child_tid, .. } = a;
    let guard = backend::kernel();
    let Some(k) = guard.as_ref() else { return err(errno::EAGAIN) };
    // The child writes one byte here once it is ready to run; its end is
    // close-on-exec there, so a vfork parent also sees it close on exec. It
    // is made and the parent's write end closed under the kernel lock, so
    // no other thread's fork hands it to its child.
    let mut word = [-1i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::pipe(word.as_mut_ptr()) } != 0 {
        return host::last_error();
    }
    let word = [fdtable::reserve(word[0]), fdtable::reserve(word[1])];
    let spawned = {
        // One instant of the process: every other vCPU stopped while memory
        // and state are captured. The descriptors stay as captured until
        // the child holds them, as the kernel lock keeps every close out.
        backend::pause_others();
        let taken = take_memory();
        let mut e = Enc::new();
        if let Ok((regions, _)) = &taken {
            save_regs(&mut e, parent);
            e.u64(tpidr);
            e.u64(vtimer_offset);
            e.u64(flags);
            e.u64(child_stack);
            e.u64(child_tid);
            e.bool(vfork);
            e.i32(word[1]);
            let maps = vm::mapping_list();
            e.u64(maps.len() as u64);
            for (guest, len, prot, host) in maps {
                for v in [guest, len, prot, host] {
                    e.u64(v);
                }
            }
            e.map(&window::used_ranges());
            e.u64(regions.len() as u64);
            for r in regions {
                e.u64(r.addr);
                e.u64(r.size);
                e.i32(r.prot);
                e.i32(r.max);
                e.bool(r.shared);
            }
            k.save_for_fork(&mut e);
        }
        backend::resume_others();
        match taken {
            Ok((_, entries)) => {
                let fds = descriptors(word[0]);
                let mut e2 = Enc::new();
                e2.u64(STATE_MAGIC);
                e2.u64(build_id());
                e2.u64(fds.len() as u64);
                for &(fd, cloexec) in &fds {
                    e2.i32(fd);
                    e2.bool(cloexec);
                }
                let mut state = e2.into_bytes();
                state.extend_from_slice(&e.into_bytes());
                let r = spawn_child(&fds, &entries, &state);
                release_ports(&entries);
                r
            }
            Err(msg) => Err(msg),
        }
    };
    // SAFETY: the child holds its own copy of the write end.
    unsafe { libc::close(word[1]) };
    drop(guard);
    let pid = match spawned {
        Ok(pid) => pid,
        Err(msg) => {
            note(&format!("fork failed: {msg}"));
            // SAFETY: closing the read end opened above.
            unsafe { libc::close(word[0]) };
            return err(errno::EAGAIN);
        }
    };
    let ready = read_byte(word[0]);
    if ready && vfork {
        // Linux suspends a vfork parent until the child execs or exits.
        while read_byte(word[0]) {}
    }
    // SAFETY: closing the read end opened above.
    unsafe { libc::close(word[0]) };
    if !ready {
        // The child ended before it could run: reap it; the fork failed.
        let mut status = 0;
        // SAFETY: waiting for the child just spawned, which has ended.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        note(&format!("fork failed: the child could not start (wait status {status:#x})"));
        return err(errno::EAGAIN);
    }
    if flags & cl::CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        let _ = uaccess::write(parent_tid, pid);
    }
    pid as i64
}

fn note(msg: &str) {
    let line = format!("fwe: {msg}\n");
    // SAFETY: writing a diagnostic to standard error.
    unsafe { libc::write(2, line.as_ptr().cast(), line.len()) };
}

/// Read one byte from `fd`, retrying on `EINTR`: false at end of file.
fn read_byte(fd: i32) -> bool {
    let mut b = 0u8;
    loop {
        // SAFETY: reading one byte into a local.
        let n = unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) };
        if n < 0 && host::last_errno() == libc::EINTR {
            continue;
        }
        return n == 1;
    }
}

/// Start `fwe --hv-fork-child` with `fds` and hand it `entries` and `state`.
fn spawn_child(fds: &[(i32, bool)], entries: &[Port], state: &[u8]) -> Result<i32, String> {
    let Some(fwe) = crate::FWE_EXE.get() else { return Err("fwe's own path is unknown".into()) };
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(fwe.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let flag = c"--hv-fork-child";
    let argv = [path.as_ptr(), flag.as_ptr(), std::ptr::null()];

    // A receive right of ours becomes the child's bootstrap port.
    let mut rx: Port = 0;
    // SAFETY: allocating a receive right and a send right for it.
    unsafe {
        if mach_port_allocate(task(), MACH_PORT_RIGHT_RECEIVE, &mut rx) != KERN_SUCCESS {
            return Err("allocating a port failed".into());
        }
        mach_port_insert_right(task(), rx, rx, MACH_MSG_TYPE_MAKE_SEND);
    }
    let destroy_rx = || {
        // SAFETY: dropping the send and receive rights allocated above.
        unsafe {
            mach_port_deallocate(task(), rx);
            mach_port_mod_refs(task(), rx, MACH_PORT_RIGHT_RECEIVE, -1);
        }
    };

    let mut pid: libc::pid_t = 0;
    // SAFETY: spawn attributes and file actions are initialized, used and
    // destroyed here; every pointer passed lives across the call.
    let rc = unsafe {
        let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
        libc::posix_spawnattr_init(&mut attr);
        // The child starts with every signal blocked and at its default
        // action; it applies the guest's dispositions and mask itself.
        libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF) as libc::c_short,
        );
        let mut all = host::empty_sigset();
        libc::sigfillset(&mut all);
        libc::posix_spawnattr_setsigmask(&mut attr, &all);
        let mut defaults = all;
        // These cannot be caught or reset.
        libc::sigdelset(&mut defaults, libc::SIGKILL);
        libc::sigdelset(&mut defaults, libc::SIGSTOP);
        libc::posix_spawnattr_setsigdefault(&mut attr, &defaults);
        posix_spawnattr_setspecialport_np(&mut attr, rx, TASK_BOOTSTRAP_PORT);
        // File actions cannot name descriptors above OPEN_MAX, where fwe
        // keeps its own, so the descriptors are passed on by clearing their
        // close-on-exec flag for the moment of the spawn (the kernel lock
        // keeps any other exec out meanwhile); kqueues never pass.
        for &(fd, cloexec) in fds {
            if cloexec {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
        }
        let rc = libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr() as *const *mut libc::c_char,
            environ as *const *mut libc::c_char,
        );
        for &(fd, cloexec) in fds {
            if cloexec {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        libc::posix_spawnattr_destroy(&mut attr);
        rc
    };
    if rc != 0 {
        destroy_rx();
        return Err(format!("posix_spawn failed: {}", std::io::Error::from_raw_os_error(rc)));
    }
    let r = hand_off(rx, pid, entries, state);
    destroy_rx();
    match r {
        Ok(()) => Ok(pid),
        Err(e) => {
            // SAFETY: ending and reaping the child that could not be set up.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            Err(e)
        }
    }
}

/// Wait for the child's request on `rx` and answer it.
fn hand_off(rx: Port, pid: i32, entries: &[Port], state: &[u8]) -> Result<(), String> {
    let mut request = Received { message: Header::default(), trailer: [0; 64] };
    let mut waited = 0;
    loop {
        // SAFETY: receiving into a buffer of the size given.
        let kr = unsafe {
            mach_msg(
                &mut request.message,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                0,
                size_of::<Received<Header>>() as u32,
                rx,
                100,
                0,
            )
        };
        let (id, size) = (request.message.id, request.message.size);
        if kr == KERN_SUCCESS && id == HANDOFF_ID && size == size_of::<Header>() as u32 {
            break;
        }
        if kr == KERN_SUCCESS {
            // Not the child's request: drop it and keep waiting.
            continue;
        }
        if kr != MACH_RCV_TIMED_OUT {
            return Err(format!("receiving the child's request failed ({kr:#x})"));
        }
        // SAFETY: reaps the child only if it has already ended.
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) } != 0 {
            return Err("the child ended before asking for its state".into());
        }
        waited += 100;
        if waited >= HANDOFF_TIMEOUT_MS {
            return Err("the child did not ask for its state".into());
        }
    }
    let mut real_bootstrap: Port = 0;
    // SAFETY: reading this task's own bootstrap port.
    unsafe { task_get_special_port(task(), TASK_BOOTSTRAP_PORT, &mut real_bootstrap) };
    let mut ports = Vec::with_capacity(entries.len() + 1);
    ports.push(real_bootstrap);
    ports.extend_from_slice(entries);
    let mut reply = Handoff {
        header: Header {
            bits: MACH_MSG_TYPE_MOVE_SEND_ONCE | MACH_MSGH_BITS_COMPLEX,
            size: size_of::<Handoff>() as u32,
            remote: request.message.remote,
            id: HANDOFF_ID,
            ..Header::default()
        },
        descriptors: 2,
        ports: Ool {
            address: ports.as_ptr() as u64,
            bits: MACH_MSG_VIRTUAL_COPY << 8
                | MACH_MSG_TYPE_COPY_SEND << 16
                | MACH_MSG_OOL_PORTS_DESCRIPTOR << 24,
            count: ports.len() as u32,
        },
        state: Ool {
            address: state.as_ptr() as u64,
            bits: MACH_MSG_VIRTUAL_COPY << 8 | MACH_MSG_OOL_DESCRIPTOR << 24,
            count: state.len() as u32,
        },
    };
    // SAFETY: a complete message whose descriptors point at live buffers.
    let kr = unsafe {
        mach_msg(
            &mut reply.header,
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            size_of::<Handoff>() as u32,
            0,
            0,
            HANDOFF_TIMEOUT_MS,
            0,
        )
    };
    // SAFETY: the copy sent holds its own reference to the bootstrap port.
    unsafe { mach_port_deallocate(task(), real_bootstrap) };
    if kr != KERN_SUCCESS {
        return Err(format!("sending the child its state failed ({kr:#x})"));
    }
    Ok(())
}

// --- The child ------------------------------------------------------------

/// The child's side: `fwe --hv-fork-child`. Takes the parent's memory and
/// state, builds a VM and resumes the guest. Does not return.
pub fn child() -> ! {
    match become_child() {
        Ok(never) => match never {},
        Err(msg) => {
            // The parent sees the pipe close without its byte and reports
            // the fork failed. A VM made by then goes first.
            note(&format!("fork child: {msg}"));
            backend::teardown();
            // SAFETY: terminating the process, with no VM.
            unsafe { libc::_exit(127) }
        }
    }
}

fn become_child() -> Result<std::convert::Infallible, String> {
    // The window first, before anything else could take its addresses.
    window::reserve()?;
    let (ports, state) = receive()?;
    let (bootstrap, entries) = ports.split_first().ok_or("no ports in the hand-off")?;
    // SAFETY: putting back the real bootstrap port, so services resolve.
    unsafe {
        let mut parent_rx: Port = 0;
        task_get_special_port(task(), TASK_BOOTSTRAP_PORT, &mut parent_rx);
        task_set_special_port(task(), TASK_BOOTSTRAP_PORT, *bootstrap);
        bootstrap_port = *bootstrap;
        mach_port_deallocate(task(), parent_rx);
    }

    let mut d = Dec::new(&state);
    if d.u64() != STATE_MAGIC || d.u64() != build_id() {
        return Err("the parent is a different build of fwe".into());
    }
    let n = d.count(5);
    let fds: Vec<(i32, bool)> = (0..n).map(|_| (d.i32(), d.bool())).collect();
    for (fd, cloexec) in fds {
        if cloexec {
            // SAFETY: setting back the flag the parent's descriptor had.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
    let mut regs = read_regs(&mut d);
    let tpidr = d.u64();
    let vtimer_offset = d.u64();
    let flags = d.u64();
    let child_stack = d.u64();
    let child_tid = d.u64();
    let vfork = d.bool();
    let word = d.i32();
    let n = d.count(32);
    let maps: Vec<[u64; 4]> = (0..n).map(|_| [d.u64(), d.u64(), d.u64(), d.u64()]).collect();
    let used = d.map();
    let n = d.count(25);
    let regions: Vec<Region> = (0..n)
        .map(|_| Region {
            addr: d.u64(),
            size: d.u64(),
            prot: d.i32(),
            max: d.i32(),
            shared: d.bool(),
        })
        .collect();
    if regions.len() != entries.len() {
        return Err("the hand-off does not match its memory".into());
    }

    for (r, &entry) in regions.iter().zip(entries) {
        let mut at = r.addr;
        let inherit = if r.shared { VM_INHERIT_SHARE } else { VM_INHERIT_COPY };
        // SAFETY: mapping the parent's memory over our reservation of the
        // window, at the parent's address.
        let kr = unsafe {
            mach_vm_map(
                task(),
                &mut at,
                r.size,
                0,
                VM_FLAGS_OVERWRITE,
                entry,
                0,
                0,
                r.prot & r.max,
                r.max,
                inherit,
            )
        };
        if kr != KERN_SUCCESS || at != r.addr {
            return Err(format!("mapping the parent's memory at {:#x} failed ({kr:#x})", r.addr));
        }
    }
    release_ports(entries);
    window::set_used(used);

    // The process becomes a VM process: from here every way out tears the
    // VM down first.
    thread::init_main(host::getpid() as i32);
    let k = Kernel::restore_for_fork(HvPlatform, &mut d);
    d.finish()?;
    backend::become_vm_process()?;
    for [guest, len, prot, host] in maps {
        vm::map(guest, host, len, prot)
            .map_err(|e| format!("mapping {guest:#x}+{len:#x} into the VM failed: errno {e}"))?;
    }
    *backend::kernel() = Some(k);

    // SAFETY: the word's write end is ours: close-on-exec, so a vfork parent
    // also sees it close when the child execs.
    unsafe { libc::fcntl(word, libc::F_SETFD, libc::FD_CLOEXEC) };
    if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        let _ = uaccess::write(child_tid, thread::tid());
    }
    if flags & cl::CLONE_CHILD_CLEARTID != 0 && child_tid != 0 {
        thread::set_clear_child_tid(child_tid);
    }
    regs.x[0] = 0;
    regs.pc += 4;
    if child_stack != 0 {
        regs.sp = child_stack;
    }
    backend::use_vtimer_offset(vtimer_offset);
    let vcpu = backend::Vcpu::create()?;
    vcpu.set_thread_pointer(tpidr);
    // SAFETY: one byte from a local to the parent's pipe.
    unsafe { libc::write(word, b"1".as_ptr().cast(), 1) };
    if !vfork {
        // SAFETY: the parent has its answer; the pipe is done.
        unsafe { libc::close(word) };
    } else {
        VFORK_WORD.store(word, Ordering::SeqCst);
    }
    vcpu.run(regs)
}

/// Ask the parent, through the bootstrap port it gave us, for the ports and
/// the state.
fn receive() -> Result<(Vec<Port>, Vec<u8>), String> {
    let mut parent: Port = 0;
    let mut reply: Port = 0;
    // SAFETY: reading our bootstrap port and allocating a reply port.
    unsafe {
        task_get_special_port(task(), TASK_BOOTSTRAP_PORT, &mut parent);
        if mach_port_allocate(task(), MACH_PORT_RIGHT_RECEIVE, &mut reply) != KERN_SUCCESS {
            return Err("allocating a port failed".into());
        }
    }
    let mut request = Header {
        bits: MACH_MSG_TYPE_COPY_SEND | MACH_MSG_TYPE_MAKE_SEND_ONCE << 8,
        size: size_of::<Header>() as u32,
        remote: parent,
        local: reply,
        id: HANDOFF_ID,
        ..Header::default()
    };
    // SAFETY: a header-only message to the parent's port.
    let kr = unsafe {
        mach_msg(
            &mut request,
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            size_of::<Header>() as u32,
            0,
            0,
            HANDOFF_TIMEOUT_MS,
            0,
        )
    };
    // SAFETY: the parent's port was only needed for this message.
    unsafe { mach_port_deallocate(task(), parent) };
    if kr != KERN_SUCCESS {
        return Err(format!("asking the parent for the state failed ({kr:#x})"));
    }
    let mut got = Received { message: Handoff::default(), trailer: [0; 64] };
    // SAFETY: receiving into a buffer of the size given.
    let kr = unsafe {
        mach_msg(
            &mut got.message.header,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT,
            0,
            size_of::<Received<Handoff>>() as u32,
            reply,
            HANDOFF_TIMEOUT_MS,
            0,
        )
    };
    // SAFETY: the reply port has served its purpose.
    unsafe { mach_port_mod_refs(task(), reply, MACH_PORT_RIGHT_RECEIVE, -1) };
    if kr != KERN_SUCCESS {
        return Err(format!("receiving the state failed ({kr:#x})"));
    }
    let m = got.message;
    let (bits, id) = (m.header.bits, m.header.id);
    let descriptors = m.descriptors;
    if bits & MACH_MSGH_BITS_COMPLEX == 0 || descriptors != 2 || id != HANDOFF_ID {
        return Err("the parent's answer is malformed".into());
    }
    let (paddr, pcount) = (m.ports.address, m.ports.count as usize);
    let (saddr, scount) = (m.state.address, m.state.count as usize);
    // SAFETY: the kernel placed `pcount` port names and `scount` bytes in
    // our address space; we copy them out and give the memory back.
    let (ports, state) = unsafe {
        let ports = std::slice::from_raw_parts(paddr as *const Port, pcount).to_vec();
        let state = std::slice::from_raw_parts(saddr as *const u8, scount).to_vec();
        mach_vm_deallocate(task(), paddr, (pcount * size_of::<Port>()) as u64);
        mach_vm_deallocate(task(), saddr, scount as u64);
        (ports, state)
    };
    Ok((ports, state))
}
