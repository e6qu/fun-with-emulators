//! `fork` and `vfork` in the VM.
//!
//! A host `fork` of a VM process is out of the question: the child could not
//! use the VM it copied, and a VM process must never fork (see
//! `docs/hypervisor.md`). Instead the child is a fresh fwe process, started
//! with `posix_spawn`, that receives the parent's memory and kernel state,
//! builds a VM of its own around them and resumes the guest where the
//! parent called `fork`, with `x0` = 0. No page of private memory is ever
//! in both processes' VMs: the runtimes that run Linux programs this way
//! without trouble never share one either.
//!
//! - **Memory.** The child reserves the slab at the same address
//!   ([`super::window`]) and takes the parent's records of its mappings
//!   ([`super::mem`]), from which it fills its own page tables. A `fork`
//!   child is sent a copy of every page of the slab that exists (copying
//!   is about fifty times cheaper than an APFS file clone, which writes the
//!   memory to disk), with the parent's vCPUs stopped, so it sees one
//!   instant. A `vfork` child is sent nothing up front: its private pages
//!   are unmapped until it touches them, when it fetches them from the
//!   parent, whose waiting thread serves it; before it execs or ends it
//!   sends back the bytes it changed, and the parent resumes once they are
//!   in its memory, so what a vfork child writes the parent sees, as on
//!   Linux. Shared memory (`MAP_SHARED`) is passed as its file, which the
//!   child maps: those pages are in both VMs, as Linux shares them.
//! - **Hand-off.** The parent gives the child a receive right of its own as
//!   its bootstrap port. The child sends a request there; the reply carries
//!   the real bootstrap port (which the child puts back) and the state as
//!   out-of-line data. The memory goes over a socket pair.
//! - **State.** The kernel's own ([`fwe_kernel::Kernel::save_for_fork`]),
//!   then what the backend holds: the forking thread's registers and thread
//!   pointer, the memory records and the slab's use.
//! - **Descriptors.** Every descriptor is inherited, close-on-exec ones
//!   too (their flag is cleared for the spawn and set back on both sides),
//!   except kqueues, which the host never passes on: the kernel rebuilds
//!   the ones behind `epoll` and `timerfd`.

use super::backend::{self, HvPlatform};
use super::{mem, vm, window};
use fwe_abi::{clone as cl, err, errno};
use fwe_kernel::snapshot::{Dec, Enc};
use fwe_kernel::{FpRegs, Kernel, Regs, fdtable, host, thread, uaccess};
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

/// The parent's reply: the ports (the real bootstrap port) and the state.
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

/// Bytes per write of the memory a `fork` child is sent.
const STREAM_CHUNK: u64 = 1 << 20;

fn task_page_query(addr: u64, size: u64, out: &mut [i32]) -> bool {
    unsafe extern "C" {
        fn mach_vm_page_range_query(
            task: Port,
            addr: u64,
            size: u64,
            dispositions: u64,
            count: *mut u64,
        ) -> i32;
    }
    let mut n = out.len() as u64;
    // SAFETY: room for `n` dispositions, one per host page of the range.
    unsafe { mach_vm_page_range_query(task(), addr, size, out.as_mut_ptr() as u64, &mut n) == 0 }
}

/// Send a `fork` child every page of the slab that exists (untouched
/// pages are zero in the child too), as `(address, length, bytes)` runs,
/// then `(0, 0)`.
fn stream_memory(sock: i32) -> Result<(), String> {
    const HOST_PAGE: u64 = 16 << 10;
    let send = |addr: u64, len: u64| -> Result<(), String> {
        let mut hdr = [0u8; 16];
        hdr[..8].copy_from_slice(&addr.to_le_bytes());
        hdr[8..].copy_from_slice(&len.to_le_bytes());
        // SAFETY: the parent's slab memory, always readable.
        let data = unsafe { std::slice::from_raw_parts(addr as *const u8, len as usize) };
        if write_all(sock, &hdr) && write_all(sock, data) {
            Ok(())
        } else {
            Err("sending memory to the child failed".into())
        }
    };
    for (start, end) in window::used_ranges() {
        let mut at = start & !(HOST_PAGE - 1);
        while at < end {
            let span = (end - at).min(STREAM_CHUNK.max(HOST_PAGE));
            let pages = span.div_ceil(HOST_PAGE) as usize;
            let mut disp = vec![0i32; pages];
            if !task_page_query(at, pages as u64 * HOST_PAGE, &mut disp) {
                disp.iter_mut().for_each(|d| *d = 1);
            }
            let mut i = 0;
            while i < pages {
                if disp[i] == 0 {
                    i += 1;
                    continue;
                }
                let j = (i..pages).find(|&k| disp[k] == 0).unwrap_or(pages);
                let lo = (at + i as u64 * HOST_PAGE).max(start);
                let hi = (at + j as u64 * HOST_PAGE).min(end);
                if hi > lo {
                    send(lo, hi - lo)?;
                }
                i = j;
            }
            at += pages as u64 * HOST_PAGE;
        }
    }
    if write_all(sock, &[0u8; 16]) {
        Ok(())
    } else {
        Err("sending memory to the child failed".into())
    }
}

/// Receive the memory [`stream_memory`] sends into this child's slab.
fn receive_memory(sock: i32) -> Result<(), String> {
    loop {
        let mut hdr = [0u8; 16];
        if !mem::recv_all(sock, &mut hdr) {
            return Err("receiving the parent's memory failed".into());
        }
        let addr = u64::from_le_bytes(hdr[..8].try_into().unwrap());
        let len = u64::from_le_bytes(hdr[8..].try_into().unwrap());
        if len == 0 {
            return Ok(());
        }
        if !window::contains(addr, len) {
            return Err(format!("the parent sent memory outside the slab ({addr:#x}+{len:#x})"));
        }
        // SAFETY: this child's own slab memory, at the parent's address.
        let dst = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len as usize) };
        if !mem::recv_all(sock, dst) {
            return Err("receiving the parent's memory failed".into());
        }
        mem::code_written(addr, len);
    }
}

fn write_all(fd: i32, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: writing our buffer to our socket.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 && host::last_errno() == libc::EINTR {
            continue;
        }
        if n <= 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
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
fn descriptors(skip: &[i32]) -> Vec<(i32, bool)> {
    let vfork_word = VFORK_WORD.load(Ordering::SeqCst);
    // The flight recorder's and the stand-in's: the child opens its own.
    let mut own = super::record::own_fds();
    own.push(super::standin::own_fd());
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
                && !skip.contains(&f.proc_fd)
                && f.proc_fd != vfork_word
                && !own.contains(&f.proc_fd)
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
    // The memory's channel; the child's end is handed on like any
    // descriptor.
    let mut sv = [-1i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        let e = host::last_error();
        // SAFETY: closing the pipe made above.
        unsafe {
            libc::close(word[0]);
            libc::close(word[1]);
        }
        return e;
    }
    let sv = [fdtable::reserve(sv[0]), fdtable::reserve(sv[1])];
    let spawned = {
        // One instant of the process: every other vCPU stopped while the
        // state is captured — and, for a fork, the memory copied. The
        // descriptors stay as captured until the child holds them, as the
        // kernel lock keeps every close out.
        backend::pause_others();
        let mut e = Enc::new();
        save_regs(&mut e, parent);
        e.u64(tpidr);
        e.u64(vtimer_offset);
        e.u64(flags);
        e.u64(child_stack);
        e.u64(child_tid);
        e.bool(vfork);
        e.i32(word[1]);
        e.i32(sv[1]);
        e.map(&window::used_ranges());
        if let Some(m) = mem::mem().as_ref() {
            m.save(&mut e);
        }
        k.save_for_fork(&mut e);
        if vfork {
            // A vfork child fetches memory as it goes; the parent's other
            // threads go on meanwhile, as on Linux.
            backend::resume_others();
        }
        let fds = descriptors(&[word[0], sv[0]]);
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
        let r = spawn_child(&fds, &state)
            .and_then(|pid| if vfork { Ok(pid) } else { stream_memory(sv[0]).map(|()| pid) });
        if !vfork {
            backend::resume_others();
        }
        if let Ok(pid) = r {
            let what = if vfork { b"vfork child" } else { b"fork child " };
            super::record::Line::new().bytes(what).s(" ").dec(pid as u64).emit();
        }
        r
    };
    // SAFETY: the child holds its own copy of the socket's end.
    unsafe { libc::close(sv[1]) };
    // SAFETY: the child holds its own copy of the write end.
    unsafe { libc::close(word[1]) };
    drop(guard);
    let pid = match spawned {
        Ok(pid) => pid,
        Err(msg) => {
            note(&format!("fork failed: {msg}"));
            // SAFETY: closing the read end and the socket opened above.
            unsafe {
                libc::close(word[0]);
                libc::close(sv[0]);
            }
            return err(errno::EAGAIN);
        }
    };
    let ready = read_byte(word[0]);
    if ready && vfork {
        // Linux suspends a vfork parent until the child execs or exits;
        // meanwhile it serves the child's memory, and takes back what the
        // child changed before going on.
        mem::serve_vfork_child(sv[0]);
        while read_byte(word[0]) {}
    }
    // SAFETY: closing the read end and the socket opened above.
    unsafe {
        libc::close(word[0]);
        libc::close(sv[0]);
    }
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

/// Start `fwe --hv-fork-child` with `fds` and hand it `state`.
fn spawn_child(fds: &[(i32, bool)], state: &[u8]) -> Result<i32, String> {
    let Some(fwe) = crate::FWE_EXE.get() else { return Err("fwe's own path is unknown".into()) };
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(fwe.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut words: Vec<std::ffi::CString> = super::passed_on()
        .into_iter()
        .map(|w| std::ffi::CString::new(w).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    words.insert(0, path.clone());
    words.push(c"--hv-fork-child".to_owned());
    let mut argv: Vec<*const libc::c_char> = words.iter().map(|w| w.as_ptr()).collect();
    argv.push(std::ptr::null());

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
    let r = hand_off(rx, pid, state);
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
fn hand_off(rx: Port, pid: i32, state: &[u8]) -> Result<(), String> {
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
    let ports = [real_bootstrap];
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
    super::record::event("fork child starts", b"");
    match become_child() {
        Ok(never) => match never {},
        Err(msg) => {
            super::record::event("fork child failed:", msg.as_bytes());
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
    // The slab first, before anything else could take its addresses.
    let layout = vm::layout()?;
    window::reserve(layout.slab)?;
    let (ports, state) = receive()?;
    let bootstrap = *ports.first().ok_or("no ports in the hand-off")?;
    // SAFETY: putting back the real bootstrap port, so services resolve.
    unsafe {
        let mut parent_rx: Port = 0;
        task_get_special_port(task(), TASK_BOOTSTRAP_PORT, &mut parent_rx);
        task_set_special_port(task(), TASK_BOOTSTRAP_PORT, bootstrap);
        bootstrap_port = bootstrap;
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
    let sock = d.i32();
    let used = d.map();
    let mut m = mem::Mem::load(&mut d);
    if !vfork {
        receive_memory(sock)?;
    }
    window::set_used(used);

    // The process becomes a VM process: from here every way out tears the
    // VM down first.
    thread::init_main(host::getpid() as i32);
    let k = Kernel::restore_for_fork(HvPlatform, &mut d);
    d.finish()?;
    backend::become_vm_process()?;
    m.rebuild(vfork)?;
    mem::install(m);
    // No vCPU has run here: nothing holds an old translation.
    vm::flushed_without_vcpus();
    *backend::kernel() = Some(k);
    if vfork {
        mem::start_lazy(sock);
    } else {
        // SAFETY: the memory has arrived; the channel is done.
        unsafe { libc::close(sock) };
    }

    // SAFETY: the word's write end is ours: close-on-exec, so a vfork parent
    // also sees it close when the child execs.
    unsafe { libc::fcntl(word, libc::F_SETFD, libc::FD_CLOEXEC) };
    regs.x[0] = 0;
    regs.pc += 4;
    if child_stack != 0 {
        regs.sp = child_stack;
    }
    backend::use_vtimer_offset(vtimer_offset);
    let vcpu = backend::Vcpu::create()?;
    vcpu.set_thread_pointer(tpidr);
    // SAFETY: one byte from a local to the parent's pipe. Written before
    // any access to guest memory: a vfork child's first one asks the
    // parent, which serves it only once it has this byte.
    unsafe { libc::write(word, b"1".as_ptr().cast(), 1) };
    if flags & cl::CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        let _ = uaccess::write(child_tid, thread::tid());
    }
    if flags & cl::CLONE_CHILD_CLEARTID != 0 && child_tid != 0 {
        thread::set_clear_child_tid(child_tid);
    }
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
