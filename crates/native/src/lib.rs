//! The native execution backend: Linux code runs directly on the CPU inside
//! this macOS process, with system calls redirected to the kernel layer.
//!
//! The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
//! "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
//! "OPTIONAL" in this crate's documentation and comments are to be
//! interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
//! when, they appear in all capitals, as shown here.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod asm;
pub mod decode;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod gate;
pub mod hv;
pub mod hwcap;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod jit;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod jitcount;
pub mod loader;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod pool;
pub mod prepare;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod process;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod quiesce;
pub mod rewrite;
pub mod stack;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod stacks;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod threads;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod trap;

/// Live guest threads, so the last one to exit ends the process.
static LIVE_THREADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

/// `FWE_TIMING`'s mark as the process ends, with how many code pages were
/// written as they first ran.
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
fn mark_exit() {
    fwe_kernel::timing::mark("exit");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        prepare::keep_hot();
        jit::write_map();
        jitcount::write_seen();
        jit::keep_made();
    }
    if fwe_kernel::timing::on() {
        let pages = fwe_kernel::lazycode::written();
        fwe_kernel::timing::mark(&format!("exit: {pages} code pages written as first run"));
        fwe_kernel::timing::mark(&format!("exit: {}", fwe_kernel::timing::calls_and_signals()));
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Some(counts) = jit::counts() {
            fwe_kernel::timing::mark(&format!("exit: {counts}"));
        }
    }
}

/// End the calling guest thread: the last thread ends the process, any other
/// ends just its host thread, or, from the system-call gate (`from_gate`),
/// leaves it to run the next thread ([`threads::wait_for_next`]). Must be
/// called without the kernel lock held, since neither returns and the lock
/// would never be released.
pub(crate) fn exit_current_thread(code: i32, from_gate: bool) -> ! {
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let _ = from_gate;
    if LIVE_THREADS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
        mark_exit();
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        fwe_kernel::timing::mark("exit: recorded");
        // SAFETY: terminating the process.
        unsafe { libc::_exit(code) }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        quiesce::forget_current();
        if from_gate {
            threads::wait_for_next();
        }
        // Its stacks, for a thread that starts once this one has gone.
        if let (Some(gate), Some(alt)) = (gate::block_mapping(), trap::altstack_mapping()) {
            stacks::give(gate, alt);
        }
    }
    // SAFETY: ends the calling host thread; the process keeps running.
    unsafe { libc::pthread_exit(std::ptr::null_mut()) }
}

use fwe_abi::auxv;
use fwe_elf::Elf;
use fwe_kernel::{Brk, Kernel, Platform, Tracer};
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Size of the guest's main thread stack in the hypervisor backend.
pub const STACK_SIZE: u64 = 8 << 20;

/// The size of a program's main thread stack for a soft `RLIMIT_STACK` of
/// `limit`, in the native backend: the limit, which Linux lets the stack
/// grow to, mapped at once (the host gives it pages only as they are
/// used), from 128 KiB (Linux's least) up to 4 GiB for an unlimited one.
fn stack_size(limit: u64, page: u64) -> u64 {
    limit.clamp(128 << 10, 4 << 30).next_multiple_of(page)
}

/// The soft `RLIMIT_STACK` the program is started under: the one an
/// `execve` carried, else the process's own.
fn start_stack_limit(options: &Options) -> u64 {
    options
        .exec_state
        .as_deref()
        .and_then(unhex)
        .and_then(|s| fwe_kernel::exec_state_stack_limit(&s))
        .unwrap_or_else(|| fwe_kernel::rlimits::get(fwe_abi::resource::RLIMIT_STACK).0)
}

/// The kernel of the guest running in this process.
#[allow(dead_code)]
static KERNEL: fwe_kernel::KernelLock<NativePlatform> = fwe_kernel::KernelLock::new(None);

/// [`Platform`] for guests running natively in this process.
pub struct NativePlatform {
    /// The host TSD slots stubs use ([`slots`]).
    pub slots: rewrite::Slots,
    pub page_size: u64,
}

impl NativePlatform {
    fn prepare(
        &self,
        addr: u64,
        len: u64,
        arena: Option<&mut prepare::StubArena>,
        known: Option<&[(u64, u64)]>,
        cache: Option<&[u8]>,
    ) -> Result<prepare::Prepared, prepare::NoStubSpace> {
        // SAFETY: callers pass guest memory that was just made readable and
        // writable and is not executing yet.
        unsafe { prepare::prepare(addr, len, self.slots, self.page_size, arena, known, cache) }
    }
}

impl Platform for NativePlatform {
    fn thread_pointer(&self) -> u64 {
        let key = (thread_pointer_slot() / 8) as libc::pthread_key_t;
        // SAFETY: `key` is the process-wide key fwe allocated for the slot.
        unsafe { libc::pthread_getspecific(key) as u64 }
    }

    fn set_thread_pointer(&mut self, tp: u64) {
        let key = (thread_pointer_slot() / 8) as libc::pthread_key_t;
        // SAFETY: as above.
        unsafe { libc::pthread_setspecific(key, tp as *const libc::c_void) };
    }

    fn prepare_exec(
        &mut self,
        addr: u64,
        len: u64,
        known: Option<&[(u64, u64)]>,
        cache: Option<&[u8]>,
    ) -> Result<(), fwe_kernel::PrepareFailed> {
        self.prepare(addr, len, None, known, cache).map(|_| ()).map_err(|e| {
            // A mapping being kept as an image is not, failed.
            prepare::image_abandon();
            fwe_kernel::PrepareFailed { errno: fwe_abi::errno::ENOMEM, why: e.to_string() }
        })
    }

    fn translates_jit(&self) -> bool {
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    }

    fn jit_code(&mut self, addr: u64, len: u64) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        jit::code(addr, len);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = (addr, len);
    }

    fn jit_mapped(&mut self, addr: u64, len: u64) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        jit::mapped(addr, len);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = (addr, len);
    }

    fn jit_discarded(&mut self, addr: u64, len: u64) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        jit::discarded(addr, len);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = (addr, len);
    }

    fn cpu_prot(&self) -> u64 {
        if hwcap::detect().1 & fwe_abi::hwcap2::BTI != 0 { fwe_abi::mman::PROT_BTI } else { 0 }
    }

    fn code_gone(&mut self, addr: u64, len: u64) {
        prepare::forget(addr, len);
    }

    fn jit_changed(&mut self, addr: u64, len: u64) -> bool {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return jit::changed(addr, len);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            let _ = (addr, len);
            false
        }
    }

    fn map_image(&mut self, key: &[u8], addr: u64, len: u64, prot: i32) -> Result<bool, i32> {
        prepare::map_image(key, addr, len, prot, self.slots)
            .map_err(fwe_kernel::host::errno_to_linux)
    }

    fn image_begin(&mut self, _key: &[u8]) {
        prepare::image_begin();
    }

    fn keep_image(&mut self, key: &[u8], addr: u64, len: u64) {
        // SAFETY: the kernel's mapping, readable and just prepared.
        unsafe { prepare::keep_image(key, addr, len) };
    }

    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn exit(&mut self, code: i32) -> ! {
        mark_exit();
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        fwe_kernel::timing::mark("exit: recorded");
        // SAFETY: terminating the process; the guest owns all its state.
        unsafe { libc::_exit(code) }
    }

    fn exit_thread(&mut self, code: i32) -> ! {
        exit_current_thread(code, false)
    }

    fn kill_self(&mut self, sig: libc::c_int) -> ! {
        fwe_kernel::procreg::exiting(
            fwe_kernel::host::signal_to_linux(sig) as i32 | fwe_kernel::coredump::status_bit(),
        );
        // SAFETY: resetting the disposition, unblocking and raising `sig`
        // terminates the process with that signal.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            let mut set = fwe_kernel::host::empty_sigset();
            libc::sigaddset(&mut set, sig);
            fwe_kernel::host::unblock_signals(&set);
            libc::raise(sig);
            libc::_exit(128 + sig)
        }
    }

    fn stop_self(&mut self, sig: libc::c_int) {
        fwe_kernel::host::stop_with(sig);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn set_host_signal(&mut self, sig: u64, how: fwe_kernel::HostSignal) {
        trap::set_host_signal(sig, how);
    }
}

/// Trace to the file at `path` (`--strace-file`), every process of the run.
pub fn trace_to_file(path: &[u8]) -> Result<(), String> {
    // fwe's own descriptors live above the guest's range, which this sets:
    // the guest MUST NOT see, reuse or close the trace file's.
    fwe_kernel::fdtable::init();
    fwe_kernel::trace::to_file(path)
}

/// How to run a guest.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Trace system calls to standard error.
    pub strace: Tracer,
    /// Root filesystem directory; the host `/` when `None`.
    pub root: Option<std::path::PathBuf>,
    /// The program path is a guest path, resolved in the root filesystem
    /// (as when fwe re-executes itself for a guest `execve`).
    pub guest_path: bool,
    /// The guest's initial working directory.
    pub cwd: Option<Vec<u8>>,
    /// The guest's `argv[0]`, when not the program path.
    pub argv0: Option<OsString>,
    /// The name of the program's thread, when not the one its path gives
    /// (the guest's `execve` ran a script, or a program through a
    /// descriptor; [`fwe_kernel::fs::exec_name`]).
    pub comm: Option<Vec<u8>>,
    /// What the guest that exec'd this program carries into it
    /// ([`fwe_kernel::Kernel::exec_state`]), hex-encoded.
    pub exec_state: Option<Vec<u8>>,
    /// A descriptor fwe was handed the program on, for a program with no
    /// path (a memfd) that a guest `execve` ran.
    pub exe_fd: Option<i32>,
    /// The file of fwe's store that descriptor is of (a memfd's), and its
    /// description's id.
    pub exe_store: Option<(fwe_kernel::filestore::desc::File, u64)>,
}

/// What `--exe-store` names: a file of fwe's store and a description's id,
/// `<filesystem>:<inode>:<id>` in hex.
pub fn parse_exe_store(v: &str) -> Option<(fwe_kernel::filestore::desc::File, u64)> {
    let mut parts = v.split(':').map(|p| u64::from_str_radix(p, 16).ok());
    let (fs, ino, id) = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some((fwe_kernel::filestore::desc::File { fs, ino }, id))
}

/// Hex-encode `bytes`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// Decode [`hex`]'s output.
fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
}

/// What the auxiliary vector of the program fwe starts says of its
/// credentials: from [`Options::exec_state`] for one an `execve` re-executed
/// fwe for, once the filesystem has its namespaces.
fn start_aux_ids(options: &Options) -> Result<fwe_kernel::AuxIds, Error> {
    let state = match &options.exec_state {
        Some(text) => {
            Some(unhex(text).ok_or_else(|| Error::Unsupported("malformed --exec-state".into()))?)
        }
        None => None,
    };
    fwe_kernel::AuxIds::at_start(state.as_deref()).map_err(Error::Unsupported)
}

/// Apply [`Options::exec_state`] to a new kernel. A program fwe was handed
/// by descriptor (`--exe-fd`), run as `/dev/fd/N`, came through the mount
/// the guest's descriptor `N` was opened in.
fn apply_exec_state<P: fwe_kernel::Platform>(
    k: &mut Kernel<P>,
    options: &Options,
    path: &Path,
) -> Result<(), Error> {
    let Some(text) = &options.exec_state else { return Ok(()) };
    let state = unhex(text).ok_or_else(|| Error::Unsupported("malformed --exec-state".into()))?;
    k.restore_exec_state(&state).map_err(Error::Unsupported)?;
    let n = path
        .as_os_str()
        .as_bytes()
        .strip_prefix(b"/dev/fd/")
        .and_then(|n| std::str::from_utf8(n).ok()?.parse().ok());
    if let (Some(held), Some(n)) = (options.exe_fd, n) {
        fwe_kernel::fdmarks::duplicated(n, held);
    }
    fwe_kernel::fdmarks::forget_closed();
    // The files of fwe's store the host `execve` closed (close-on-exec)
    // are no longer this process's to hold; the program's, run by
    // descriptor, is, through fwe's own.
    fwe_kernel::filestore::desc::sync(&[]);
    Ok(())
}

/// Open the guest's root filesystem with its working directory.
fn open_fs(options: &Options) -> Result<fwe_kernel::Fs, Error> {
    let root_bytes = options.root.as_ref().map(|p| p.as_os_str().as_bytes().to_vec());
    let mut fs = fwe_kernel::Fs::new(root_bytes.as_deref()).map_err(|e| {
        Error::Unsupported(format!("opening the root filesystem failed: errno {e}"))
    })?;
    if let Some(text) = &options.exec_state {
        // The mount namespace and root the program is found in.
        let state =
            unhex(text).ok_or_else(|| Error::Unsupported("malformed --exec-state".into()))?;
        fs.adopt_exec_view(&state).map_err(Error::Unsupported)?;
    }
    if let Some(fd) = options.exe_fd {
        // fwe's own from here on, out of the guest's reach.
        // SAFETY: plain host call on the descriptor fwe was handed.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        // A file of fwe's store, which the descriptor stands in for.
        if let Some((file, id)) = options.exe_store {
            fwe_kernel::filestore::desc::adopt_exe(fd, file, id);
        }
        fs.set_exe_fd(Some(fd));
    }
    if let Some(cwd) = &options.cwd {
        fs.chdir(fwe_abi::fcntl::AT_FDCWD as i32, cwd).map_err(|e| {
            Error::Unsupported(format!("entering {}: errno {e}", String::from_utf8_lossy(cwd)))
        })?;
    } else if options.exec_state.is_none() {
        // A fresh start: the directory fwe was started in, in the guest's
        // terms (the root's `/` where it lies outside the root, as `chroot`
        // leaves a program).
        let host = std::env::current_dir().ok();
        let guest = match &options.root {
            None => host.map(|h| h.as_os_str().as_bytes().to_vec()),
            Some(_) => host.and_then(|h| guest_path_in_root(&h, options)),
        };
        if let Some(cwd) = guest {
            let _ = fs.chdir(fwe_abi::fcntl::AT_FDCWD as i32, &cwd);
        }
    }
    Ok(fs)
}

/// The program's bytes: a host path, or a guest path in the rootfs. A
/// host path inside the rootfs is read as the guest's path, so that a
/// symbolic link there resolves in the rootfs (Alpine's `/bin/sh` links to
/// `/bin/busybox`, which on the host is no file).
fn read_program(
    path: &Path,
    options: &Options,
    fs: &fwe_kernel::Fs,
) -> Result<fwe_kernel::ExecFile, Error> {
    let in_guest = |p: &[u8]| {
        fs.read_identified(p).map_err(|e| Error::Read(std::io::Error::from_raw_os_error(e)))
    };
    if options.exe_fd.is_some() {
        in_guest(b"/proc/self/exe")
    } else if options.guest_path {
        in_guest(path.as_os_str().as_bytes())
    } else if let Some(guest) = guest_path_in_root(path, options) {
        in_guest(&guest)
    } else {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(path).map_err(Error::Read)?;
        let data = fwe_kernel::fs::read_all_fd(f.as_raw_fd())
            .map_err(|e| Error::Read(std::io::Error::from_raw_os_error(e)))?;
        Ok((data, fwe_kernel::prepcache::FileId::of_fd(f.as_raw_fd())))
    }
}

/// The program to run, its arguments and options, and its file: the
/// program at `path` itself, or for a script the interpreter its `#!` line
/// names, as Linux's `execve` runs one ([`fwe_kernel::Kernel::exec_target`]):
/// a guest path, given the line's argument if it has one, then the script's
/// path (its guest path inside the root, otherwise as given), then `args`
/// but the first; an interpreter can be a script too, five deep.
fn script_target(
    path: &Path,
    args: &[OsString],
    options: &Options,
    fs: &fwe_kernel::Fs,
) -> Result<(PathBuf, Vec<OsString>, Options, fwe_kernel::ExecFile), Error> {
    let errno = |e| Error::Read(std::io::Error::from_raw_os_error(e));
    let (mut path, mut args, mut options) = (path.to_path_buf(), args.to_vec(), options.clone());
    for _ in 0..=5 {
        let file = read_program(&path, &options, fs)?;
        let head = &file.0[..file.0.len().min(256)];
        let Some((interp, arg)) = fwe_kernel::script_interpreter(head).map_err(errno)? else {
            return Ok((path, args, options, file));
        };
        let script = guest_path_in_root(&path, &options)
            .unwrap_or_else(|| path.as_os_str().as_bytes().to_vec());
        let mut new = vec![OsString::from_vec(interp.clone())];
        new.extend(arg.map(OsString::from_vec));
        new.push(OsString::from_vec(script));
        new.extend(args.into_iter().skip(1));
        (path, args) = (PathBuf::from(OsString::from_vec(interp)), new);
        options = Options { guest_path: true, argv0: None, ..options };
    }
    Err(errno(fwe_abi::errno::ELOOP))
}

/// The guest's arguments, with `argv[0]` replaced if asked. Otherwise an
/// `argv[0]` naming a host file inside the rootfs becomes its guest path, as
/// the program would have been named in the guest's filesystem (Python, for
/// one, finds itself by `argv[0]`).
fn guest_args(args: &[OsString], options: &Options) -> Vec<OsString> {
    let mut a = args.to_vec();
    match (a.first_mut(), &options.argv0) {
        (Some(first), Some(argv0)) => *first = argv0.clone(),
        (Some(first), None) => {
            if let Some(guest) = guest_path_in_root(Path::new(first), options) {
                *first = OsString::from_vec(guest);
            }
        }
        (None, _) => {}
    }
    a
}

/// The guest path of the host file `path`, if it is inside the rootfs and
/// was given as a host path (not by fwe re-executing itself on a guest
/// path).
fn guest_path_in_root(path: &Path, options: &Options) -> Option<Vec<u8>> {
    if options.guest_path {
        return None;
    }
    // The directory resolved on the host, the name itself not: a symbolic
    // link there is the guest's to resolve.
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let host = std::fs::canonicalize(parent).ok()?.join(name);
    let root = std::fs::canonicalize(options.root.as_ref()?).ok()?;
    let inside = host.strip_prefix(&root).ok()?;
    Some(Path::new("/").join(inside).as_os_str().as_bytes().to_vec())
}

/// The name the program was started by, as `AT_EXECFN` gives it: the path
/// fwe was given, in the guest's terms.
pub(crate) fn guest_execfn(path: &Path, options: &Options) -> Vec<u8> {
    guest_path_in_root(path, options).unwrap_or_else(|| path.as_os_str().as_bytes().to_vec())
}

/// Take `dir`, which the fwe that re-executed this one passed on
/// (`--user-dir`), as fwe's private directory, if it still is one: a
/// directory of this user's that no one else can enter.
pub fn adopt_user_dir(dir: &[u8]) {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(dir)) else { return };
    // SAFETY: getuid cannot fail.
    let mine = m.uid() == unsafe { libc::getuid() };
    if mine && m.is_dir() && m.mode() & 0o077 == 0 {
        fwe_kernel::fs::adopt_host_dir(dir.to_vec());
    }
}

/// This `fwe` executable, for re-executing it (see [`reexec`]).
static FWE_EXE: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Remember where this `fwe` executable is. Called at startup, before the
/// working directory could matter.
pub fn remember_exe() {
    if let Ok(p) = std::env::current_exe() {
        let _ = FWE_EXE.set(p);
    }
}

/// A program a guest's `execve` runs: its guest path, the name its thread
/// takes ([`fwe_kernel::fs::exec_name`]), its arguments and environment.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct Program<'a> {
    pub path: &'a [u8],
    pub named: &'a [u8],
    pub args: &'a [Vec<u8>],
    pub env: &'a [Vec<u8>],
}

/// `execve` by re-executing fwe on the new program: the new process image is
/// a fresh fwe, which picks the backend the program needs — the native one,
/// or the VM for a program linked below 4 GiB — so either backend can exec
/// a program of the other kind. What Linux keeps across `execve` the host
/// keeps across its own: the pid, descriptors not marked close-on-exec (the
/// guest's flag is the host's), the signal mask, pending signals and ignored
/// dispositions; the root filesystem, working directory, `--strace`, `--vm`,
/// `--hv-standin`, `--hv-record` and fwe's private directory are passed
/// on, and a program reached through a descriptor (a memfd, or
/// `/proc/self/exe`) by descriptor (`--exe-fd`), with the name the guest's
/// `execve` gives it (`--comm`). Other threads end, as on Linux. The
/// caller has checked the program (what the fresh fwe reads of it, it
/// reads itself). Returns a Linux errno only if the program cannot be run;
/// on success it does not return.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reexec(
    program: Program<'_>,
    fs: &fwe_kernel::Fs,
    strace: Tracer,
    state: &[u8],
    before_exec: impl FnOnce(),
) -> i64 {
    use fwe_abi::{err, errno};
    use std::ffi::CString;
    let Program { path, named, args, env } = program;
    // A `/proc` link names a program the new fwe would look for in itself.
    let target = fs.exec_target(path);
    let path = &target[..];
    let Some(fwe) = FWE_EXE.get() else { return err(errno::ENOEXEC) };
    let mut argv: Vec<Vec<u8>> = vec![fwe.as_os_str().as_bytes().to_vec()];
    argv.extend(hv::passed_on());
    argv.push(b"--guest-path".to_vec());
    if strace.failures_only {
        argv.push(b"--strace=failures".to_vec());
    } else if strace.enabled {
        argv.push(b"--strace".to_vec());
    }
    if let Some(file) = fwe_kernel::trace::file() {
        argv.push([&b"--strace-file="[..], file].concat());
    }
    if let Some(root) = fs.root_host_path() {
        argv.push(b"--root".to_vec());
        argv.push(root.as_os_str().as_bytes().to_vec());
    }
    argv.push(b"--cwd".to_vec());
    argv.push(fs.cwd().to_vec());
    if let Some(display) = fwe_kernel::x11::host_value() {
        argv.push(b"--host-display".to_vec());
        argv.push(display.to_vec());
    }
    // (Its file's path, never a cookie: arguments are for anyone to read.)
    if let Some(authority) = fwe_kernel::x11::host_authority() {
        argv.push(b"--host-xauthority".to_vec());
        argv.push(authority.to_vec());
    }
    if let Some(server) = fwe_kernel::pulse::host_server() {
        argv.push(b"--host-pulse".to_vec());
        argv.push(server.to_vec());
    }
    if let Some(cookie) = fwe_kernel::pulse::host_cookie() {
        argv.push(b"--host-pulse-cookie".to_vec());
        argv.push(cookie.to_vec());
    }
    // fwe's private directory, which the new fwe would otherwise look up
    // again (slowly).
    if let Some(dir) = fwe_kernel::fs::host_dir() {
        argv.push(b"--user-dir".to_vec());
        argv.push(dir);
    }
    argv.push(b"--exec-state".to_vec());
    argv.push(hex(state));
    if let Some(a0) = args.first() {
        argv.push(b"--argv0".to_vec());
        argv.push(a0.clone());
    }
    argv.push(b"--comm".to_vec());
    argv.push(named.to_vec());
    // A program with no path goes by descriptor: one of fwe's, kept open
    // across the host `execve`.
    let held = match fs.exec_fd(path).map(fwe_kernel::fdtable::dup_reserved) {
        Some(Ok(held)) => {
            // SAFETY: plain host call on fwe's own descriptor, which then
            // survives the host `execve` (the new fwe takes it over).
            unsafe { libc::fcntl(held, libc::F_SETFD, 0) };
            argv.push(b"--exe-fd".to_vec());
            argv.push(held.to_string().into_bytes());
            // A file of fwe's store: which, for the new fwe to read it by.
            let fd = fs.exec_fd(path).expect("a descriptor");
            if let (Some(file), Some(id)) =
                (fwe_kernel::filestore::desc::of(fd), fwe_kernel::filestore::desc::description(fd))
            {
                argv.push(b"--exe-store".to_vec());
                argv.push(format!("{:x}:{:x}:{id:x}", file.fs, file.ino).into_bytes());
            }
            Some(held)
        }
        Some(Err(e)) => return err(e),
        None => None,
    };
    // SAFETY: closing fwe's own descriptor, when the exec did not happen.
    let release = || held.map(|fd| unsafe { libc::close(fd) });
    argv.push(b"--".to_vec());
    argv.push(path.to_vec());
    argv.extend(args.iter().skip(1).cloned());
    let cargs: Result<Vec<CString>, _> = argv.into_iter().map(CString::new).collect();
    let cenv: Result<Vec<CString>, _> = env.iter().cloned().map(CString::new).collect();
    let (Ok(cargs), Ok(cenv)) = (cargs, cenv) else {
        release();
        return err(errno::EINVAL);
    };
    let mut pargs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    pargs.push(std::ptr::null());
    let mut penv: Vec<*const libc::c_char> = cenv.iter().map(|c| c.as_ptr()).collect();
    penv.push(std::ptr::null());
    before_exec();
    // The Mac's Vulkan driver's descriptors, which it does not close on exec.
    fwe_kernel::vulkan::device::before_exec(held);
    fwe_kernel::host::hand_over_for_exec();
    fwe_kernel::timing::mark("exec: host execve");
    // SAFETY: NUL-terminated argument and environment arrays of C strings
    // that live across the call.
    unsafe { libc::execve(pargs[0], pargs.as_ptr(), penv.as_ptr()) };
    let e = fwe_kernel::host::last_error();
    release();
    e
}

/// Die of `SIGKILL` on the relayed form of a guest's `SIGKILL`
/// ([`fwe_kernel::host::KILL_RELAY`]). Installed first thing in every fwe
/// process; the hypervisor backend replaces it with one that tears the VM
/// down first.
pub fn install_kill_relay() {
    #[cfg(target_os = "macos")]
    {
        extern "C" fn die(_: libc::c_int) {
            if !fwe_kernel::host::kill_relayed() {
                // The host's own SIGINFO (Ctrl-T): nothing on Linux.
                return;
            }
            // To the pid from the system call itself, not libc's copy, which
            // a fork child has the parent's of until `fork` returns in it.
            fwe_kernel::host::kill_self(libc::SIGKILL);
        }
        // SAFETY: installing a handler that only ends the process.
        unsafe { libc::signal(fwe_kernel::host::KILL_RELAY, die as *const () as usize) };
    }
}

#[derive(Debug)]
pub enum Error {
    Read(std::io::Error),
    Elf(fwe_elf::Error),
    Load(loader::LoadError),
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Read(e) => write!(f, "{e}"),
            Error::Elf(e) => write!(f, "{e}"),
            Error::Load(e) => write!(f, "{e}"),
            Error::Unsupported(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The address of the system-call gate rewritten system calls call
/// ([`gate`]), or 0 where there is none (they trap instead).
pub fn syscall_gate() -> u64 {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return gate::address();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    0
}

/// The host TSD slot holding the guest thread pointer, as a byte offset
/// from the TSD base that `TPIDRRO_EL0` points to.
pub fn thread_pointer_slot() -> u32 {
    static SLOT: OnceLock<u32> = OnceLock::new();
    *SLOT.get_or_init(|| {
        let mut key: libc::pthread_key_t = 0;
        // SAFETY: creating a key without destructor; it lives forever.
        let r = unsafe { libc::pthread_key_create(&mut key, None) };
        assert_eq!(r, 0, "pthread_key_create failed");
        // On Linux the thread pointer starts out as zero.
        // SAFETY: setting this thread's value for the key just created.
        unsafe { libc::pthread_setspecific(key, std::ptr::null()) };
        (key as u32) * 8
    })
}

/// The host TSD slot holding the guest `x18`, as a byte offset from the TSD
/// base. Every thread's slot defaults to zero (a fresh pthread key reads NULL),
/// which matches the guest's initial `x18`, so no per-thread setup is needed.
pub fn x18_slot() -> u32 {
    static SLOT: OnceLock<u32> = OnceLock::new();
    *SLOT.get_or_init(|| {
        let mut key: libc::pthread_key_t = 0;
        // SAFETY: creating a key without destructor; it lives forever.
        let r = unsafe { libc::pthread_key_create(&mut key, None) };
        assert_eq!(r, 0, "pthread_key_create failed");
        (key as u32) * 8
    })
}

/// The host TSD slots where translations keep the program's `x16` and
/// `x17` while they use the registers themselves, as byte offsets from the
/// TSD base: within reach of an `ldr`/`str` with an unsigned offset from it.
pub fn parked_slots() -> (u32, u32) {
    static SLOTS: OnceLock<(u32, u32)> = OnceLock::new();
    *SLOTS.get_or_init(|| {
        let key = || {
            let mut key: libc::pthread_key_t = 0;
            // SAFETY: creating a key without destructor; it lives forever.
            let r = unsafe { libc::pthread_key_create(&mut key, None) };
            assert_eq!(r, 0, "pthread_key_create failed");
            let off = (key as u32) * 8;
            assert!(off < 4096 * 8, "TSD key {key} out of an ldr's reach");
            off
        };
        (key(), key())
    })
}

/// The host TSD slots fwe's stubs keep the program's registers in while
/// they use the registers themselves (memory below the program's `sp` is
/// the program's: Go keeps a new thread's start there across its first
/// system call), as byte offsets from the TSD base, within reach of an
/// `ldr`/`str` with an unsigned offset from it.
pub fn scratch_slots() -> [u32; rewrite::SCRATCH] {
    static SLOTS: OnceLock<[u32; rewrite::SCRATCH]> = OnceLock::new();
    *SLOTS.get_or_init(|| {
        std::array::from_fn(|_| {
            let mut key: libc::pthread_key_t = 0;
            // SAFETY: creating a key without destructor; it lives forever.
            let r = unsafe { libc::pthread_key_create(&mut key, None) };
            assert_eq!(r, 0, "pthread_key_create failed");
            let off = (key as u32) * 8;
            assert!(off < 4096 * 8, "TSD key {key} out of an ldr's reach");
            off
        })
    })
}

/// The TSD slots a stub uses, as byte offsets from the TSD base.
pub fn slots() -> rewrite::Slots {
    rewrite::Slots { tp: thread_pointer_slot(), x18: x18_slot(), scratch: scratch_slots() }
}

/// This thread's TSD slot at byte offset `off` from its base (the host
/// keeps the base in `tpidrro_el0`, its low bits the processor's number).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn tsd_slot(off: u32) -> *mut u64 {
    let area: u64;
    // SAFETY: reading this thread's TSD base.
    unsafe { std::arch::asm!("mrs {}, tpidrro_el0", out(reg) area, options(nomem, nostack)) };
    ((area & !7) + u64::from(off)) as *mut u64
}

/// Host features that affect guest compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSupport {
    /// The host offers an opt-in to preserve x18, and it was requested.
    pub x18_opt_in: bool,
    /// The host left the opt-in mode on its own while the thread waited.
    pub x18_opt_in_dropped: bool,
    /// x18 was observed to survive kernel entry and preemption.
    pub x18_preserved: bool,
}

impl fmt::Display for HostSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let yn = |b: bool| if b { "yes" } else { "no" };
        write!(
            f,
            "x18 opt-in: {}{}, x18 preserved: {}",
            yn(self.x18_opt_in),
            if self.x18_opt_in_dropped { " (dropped by the host)" } else { "" },
            yn(self.x18_preserved)
        )
    }
}

/// The macOS custom x18 ABI (macOS 26.4 and later): a per-thread mode in
/// which x18 is saved and restored like any other register. While it is on,
/// the thread MUST NOT call macOS library code; see `<os/arch/arm64.h>`.
#[derive(Clone, Copy)]
pub struct X18Abi {
    set: extern "C" fn(bool),
    get: extern "C" fn() -> bool,
}

impl X18Abi {
    /// The host's custom x18 ABI, if it has one.
    pub fn get() -> Option<X18Abi> {
        static ABI: OnceLock<Option<X18Abi>> = OnceLock::new();
        *ABI.get_or_init(lookup_x18_abi)
    }

    /// Switch this thread into or out of the custom x18 ABI.
    pub fn set_enabled(&self, on: bool) {
        (self.set)(on)
    }

    pub fn enabled(&self) -> bool {
        (self.get)()
    }

    /// Run `f` with the custom ABI on and switch it off again, unless the
    /// host already did (switching to the current state aborts). Returns
    /// `f`'s result and whether the mode was still on. `f` MUST NOT call
    /// macOS library code.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> (R, bool) {
        self.set_enabled(true);
        let r = f();
        let still_on = self.enabled();
        if still_on {
            self.set_enabled(false);
        }
        (r, still_on)
    }
}

#[cfg(target_os = "macos")]
fn lookup_x18_abi() -> Option<X18Abi> {
    // SAFETY: looking up symbols in the already-loaded system libraries.
    let (set, get) = unsafe {
        (
            libc::dlsym(libc::RTLD_DEFAULT, c"os_set_custom_x18_abi_enabled".as_ptr()),
            libc::dlsym(libc::RTLD_DEFAULT, c"os_custom_x18_abi_enabled".as_ptr()),
        )
    };
    if set.is_null() || get.is_null() {
        return None;
    }
    // SAFETY: the libSystem functions declared in <os/arch/arm64.h> as
    // `void os_set_custom_x18_abi_enabled(bool)` and
    // `bool os_custom_x18_abi_enabled(void)`.
    unsafe {
        Some(X18Abi {
            set: std::mem::transmute::<*mut libc::c_void, extern "C" fn(bool)>(set),
            get: std::mem::transmute::<*mut libc::c_void, extern "C" fn() -> bool>(get),
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn lookup_x18_abi() -> Option<X18Abi> {
    None
}

/// Report host features that affect guest compatibility.
pub fn host_support() -> HostSupport {
    static SUPPORT: OnceLock<HostSupport> = OnceLock::new();
    *SUPPORT.get_or_init(|| {
        let abi = X18Abi::get();
        let (x18_preserved, dropped) = match abi {
            // No macOS library calls or system calls while the custom ABI is
            // on; preemption alone exercises the context switch.
            Some(abi) => {
                let (survived, still_on) = abi.run(|| x18_survives(false));
                (survived && still_on, !still_on)
            }
            None => (x18_survives_kernel_entry(), false),
        };
        HostSupport { x18_opt_in: abi.is_some(), x18_opt_in_dropped: dropped, x18_preserved }
    })
}

/// Set x18, optionally make host system calls, spin long enough to be
/// preempted, and check whether x18 kept its value.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn x18_survives(syscalls: bool) -> bool {
    let lost: u64;
    let rounds: u64 = 200;
    // SAFETY: self-contained register test. x18 is reserved on macOS and not
    // used by compiled code, so it is free to clobber; it is zeroed again
    // afterwards. All other registers used are declared.
    unsafe {
        core::arch::asm!(
            "movz x18, #0x1818",
            "movk x18, #0x1818, lsl #48",
            "mov x10, x18",
            "2:",
            "cbz {syscalls}, 4f",
            "mov x16, #20", // getpid
            "svc #0x80",
            "4:",
            "movz x11, #0x8, lsl #16",
            "3:",
            "subs x11, x11, #1",
            "b.ne 3b",
            "subs x9, x9, #1",
            "b.ne 2b",
            "eor {lost}, x18, x10",
            "mov x18, xzr",
            syscalls = in(reg) syscalls as u64,
            lost = lateout(reg) lost,
            inout("x9") rounds => _,
            out("x0") _,
            out("x1") _,
            out("x10") _,
            out("x11") _,
            out("x16") _,
            options(nostack),
        )
    }
    lost == 0
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn x18_survives(_syscalls: bool) -> bool {
    false
}

/// Write x18 and nothing else.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn write_x18(value: u64) {
    // SAFETY: x18 is not used by compiled code on macOS.
    unsafe { core::arch::asm!("mov x18, {}", in(reg) value, options(nostack)) }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn write_x18(_value: u64) {}

/// Spin long enough to be preempted without touching x18.
fn spin_without_x18() {
    let mut x = 0u64;
    for i in 0..100_000_000u64 {
        x = std::hint::black_box(x.wrapping_add(i));
    }
    std::hint::black_box(x);
}

fn x18_survives_kernel_entry() -> bool {
    x18_survives(true)
}

/// `fwe --probe <name>`. Prints the result; a crash identifies the step.
pub fn probe(name: &str) -> Result<String, String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    trap::install_probe_reporter();
    let with_mode = |f: &dyn Fn() -> bool| -> Result<bool, String> {
        let abi = X18Abi::get().ok_or("no custom x18 ABI on this host")?;
        match abi.run(f) {
            (r, true) => Ok(r),
            (_, false) => Err("the host left the custom x18 ABI on its own".into()),
        }
    };
    let yn = |b: bool| if b { "preserved" } else { "lost" }.to_string();
    match name {
        "x18-mode" => with_mode(&|| true).map(|_| "mode toggled".into()),
        "x18-spin" => Ok(yn(x18_survives(false))),
        "x18-syscall" => Ok(yn(x18_survives(true))),
        "x18-mode-spin" => with_mode(&|| x18_survives(false)).map(yn),
        "x18-mode-syscall" => with_mode(&|| x18_survives(true)).map(yn),
        "x18-mode-write" => with_mode(&|| {
            write_x18(0x1818_0000_0000_1818);
            true
        })
        .map(|_| "x18 written in mode".into()),
        "x18-mode-wait" => with_mode(&|| {
            spin_without_x18();
            true
        })
        .map(|_| "waited in mode".into()),
        // Creates a VM unless under --hv-standin (see hv::probe).
        "hv-map-rules" => hv::map_rules_probe(),
        _ => Err(format!("unknown probe {name}")),
    }
}

fn page_size() -> u64 {
    fwe_kernel::mm::host_page_size()
}

/// `movz x8, #139` (rt_sigreturn).
const MOVZ_X8_139: u32 = 0xd280_1168;

/// Map a one-page `rt_sigreturn` trampoline (`movz x8, #139; svc #0`), with
/// the `svc` rewritten to a trap like any other guest code.
fn make_sigreturn_trampoline(page: u64) -> Result<u64, Error> {
    // SAFETY: a fresh writable mapping.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Error::Load(loader::LoadError::Map(std::io::Error::last_os_error())));
    }
    let addr = p as u64;
    // The call is the trap itself, not a branch to a stub: the trampoline
    // is fwe's and outlives the program's memory (stub regions included)
    // across `execve`, and `rt_sigreturn` always takes the trap.
    // SAFETY: writing two instruction words into the fresh page.
    unsafe {
        (addr as *mut u32).write(MOVZ_X8_139);
        ((addr + 4) as *mut u32).write(rewrite::TRAP);
    }
    // SAFETY: making the trampoline executable and visible to fetch.
    unsafe {
        libc::mprotect(p, page as usize, libc::PROT_READ | libc::PROT_EXEC);
        prepare::flush_icache(addr, 8);
    }
    Ok(addr)
}

fn random16() -> [u8; 16] {
    let mut r = [0u8; 16];
    fwe_kernel::host::fill_random(&mut r);
    r
}

/// `argv` joined by NUL with a trailing NUL, for `/proc/self/cmdline`.
pub fn cmdline(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in args {
        out.extend_from_slice(a);
        out.push(0);
    }
    out
}

/// Online CPU count.
pub fn ncpu() -> u32 {
    // SAFETY: plain host call.
    (unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }).max(1) as u32
}

/// The host name, as the guest's kernel holds it.
pub fn hostname() -> Vec<u8> {
    fwe_kernel::ns::host_name()
}

/// Have the host schedule the calling thread, one running guest code, as
/// interactive work (`QOS_CLASS_USER_INTERACTIVE`): a guest's sleeps,
/// timeouts and wakes are then on time on a loaded machine, as Linux's
/// scheduler keeps them, rather than left behind the host's default work.
pub fn interactive() {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn pthread_set_qos_class_self_np(qos: u32, relative: i32) -> i32;
        }
        const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
        // SAFETY: changes only how the host schedules this thread.
        unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
    }
}

/// Load the Linux executable at `path` and run it with `args` (including
/// `argv[0]`) and `env`. Returns only on failure to start the program.
pub fn run(path: &Path, args: &[OsString], env: &[OsString], options: &Options) -> Error {
    interactive();
    match start(path, args, env, options) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

/// The result of loading a program image: where to start it.
pub struct Loadout {
    pub entry: u64,
    pub sp: u64,
    pub brk: Brk,
    /// The auxiliary vector given the program (see [`fwe_kernel::Fs::set_auxv`]).
    pub auxv: Vec<u8>,
}

/// Whether `file` is a program the hypervisor backend runs
/// ([`vm_reason`]).
pub fn needs_vm(file: &[u8]) -> bool {
    vm_reason(file).is_some()
}

/// Why `file` is a program the hypervisor backend runs, if it is: under
/// `--vm` any program; otherwise an executable linked into the low 4 GiB
/// that cannot be moved above it ([`loader::moved`]).
pub fn vm_reason(file: &[u8]) -> Option<String> {
    let elf = Elf::parse(file).ok()?;
    if hv::vm_always() {
        return Some("every program runs in the VM (--vm)".into());
    }
    let start = fwe_elf::LoadPlan::new(&elf, page_size()).start;
    match loader::moved(&elf, page_size())? {
        Ok(_) => None,
        Err(why) => Some(format!(
            "linked at {start:#x}, below 4 GiB, which macOS reserves, and not movable: {why}"
        )),
    }
}

/// Check that `file` is a program [`load_image`] can start, before `execve`
/// discards the old one: an arm64 ELF executable that fits the host's
/// address space, whose dynamic linker (if any) exists and is
/// position-independent. Fails with the Linux errno `execve` reports.
pub fn check_image(file: &[u8], fs: &fwe_kernel::Fs) -> Result<(), i32> {
    use fwe_abi::errno;
    let elf = Elf::parse(file).map_err(|_| errno::ENOEXEC)?;
    if loader::moved(&elf, page_size()).is_some_and(|m| m.is_err()) {
        return Err(errno::ENOEXEC);
    }
    check_interpreter(elf.interpreter().map_err(|_| errno::ENOEXEC)?, fs)
}

/// [`check_image`] of a program a fresh fwe runs, by its file's first
/// bytes (`head`): one not linked into the low 4 GiB without being
/// position-independent ([`loader::low`]), whose check needs the whole.
pub fn check_head(head: &fwe_elf::Head<'_>, fs: &fwe_kernel::Fs) -> Result<(), i32> {
    debug_assert!(!loader::low(head));
    check_interpreter(head.interpreter(), fs)
}

/// That a program's dynamic linker `ip`, if it has one, exists and is
/// position-independent, by its file's first bytes.
fn check_interpreter(ip: Option<&[u8]>, fs: &fwe_kernel::Fs) -> Result<(), i32> {
    use fwe_abi::errno;
    let Some(ip) = ip else { return Ok(()) };
    let (head, len) = fs.read_program_head(ip)?;
    let ihead = fwe_elf::Head::parse(&head, len).map_err(|_| errno::ELIBBAD)?;
    if !ihead.is_pie() {
        return Err(errno::ELIBBAD);
    }
    Ok(())
}

/// Load an ELF image (and its dynamic linker) and build the initial stack,
/// returning where to start the guest, whose auxiliary vector carries
/// `ids`. Shared by process startup and `execve`. Does not touch the
/// kernel; the caller installs or updates it.
#[allow(clippy::too_many_arguments)]
pub fn load_image(
    (file, file_id): (&[u8], Option<fwe_kernel::prepcache::FileId>),
    execfn: &[u8],
    args: &[&[u8]],
    env: &[&[u8]],
    fs: &fwe_kernel::Fs,
    platform: &NativePlatform,
    page: u64,
    tracer: Tracer,
    stack_limit: u64,
    ids: fwe_kernel::AuxIds,
) -> Result<Loadout, Error> {
    let elf = Elf::parse(file).map_err(Error::Elf)?;
    let interp_path = elf.interpreter().map_err(Error::Elf)?.map(<[u8]>::to_vec);

    let strace = tracer.enabled;
    let slots = platform.slots;
    let load_object = |elf: &Elf, id, at, what: &str| -> Result<loader::Loaded, Error> {
        let loaded = loader::load(elf, page, id, slots, at, |a, l, known, arena, cache| {
            let stats =
                platform.prepare(a, l, Some(arena), known, cache).map_err(|e| e.to_string())?;
            if strace {
                tracer.note(&format!(
                    "prepared {what} {a:#x}+{l:#x}: {} system calls, {} stubs, \
                     {} x18 uses left unrewritten",
                    stats.syscalls, stats.stubs, stats.x18_deferred
                ));
            }
            Ok(stats.beyond)
        })
        .map_err(Error::Load)?;
        // Code no stub space reaches (the middle of an image larger than a
        // branch reaches across) runs by translation.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        for &(a, l) in &loaded.translated {
            jit::code(a, l);
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        if let Some(&(start, _)) = loaded.translated.first() {
            return Err(Error::Load(loader::LoadError::Prepare {
                start,
                reason: "code beyond its stubs' reach, and no translation here".into(),
            }));
        }
        if strace && !loaded.translated.is_empty() {
            let kib: u64 = loaded.translated.iter().map(|r| r.1 >> 10).sum();
            tracer.note(&format!(
                "{what}: {kib} KiB of code beyond its stubs' reach, run by translation"
            ));
        }
        if strace && loaded.from_image {
            tracer.note(&format!("{what} from its prepared image"));
        }
        Ok(loaded)
    };

    let loaded = load_object(&elf, file_id, Some(loader::PIE_BASE), "exe")?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    jit::program_is(file_id);
    // The program's file is told by `/proc/self/exe` when listed.
    fwe_kernel::maps::record().loaded(&elf, loaded.bias, page, fwe_kernel::maps::Name::Exe, (0, 0));

    // The break starts after the main image and its stub space, reserved
    // before anything else is mapped (the dynamic linker would land there).
    let brk = Brk::reserve(
        loaded.stub_arena.end.max((loaded.end + page - 1) & !(page - 1)),
        Brk::RESERVATION,
    );

    // A dynamically linked executable names an interpreter (the dynamic
    // linker); load it too and start the guest there. It maps the executable's
    // libraries itself through our mmap and openat.
    let interp = match &interp_path {
        Some(ip) => {
            let (idata, iid) = fs.read_identified(ip).map_err(|e| {
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
            let placed = load_object(&ielf, iid, None, "interp")?;
            let name = fwe_kernel::maps::Name::Path(ip.as_slice().into());
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
    let entry = interp.as_ref().map_or(loaded.entry, |i| i.entry);
    let interp_base = interp.as_ref().map_or(0, |i| i.load_base);

    // A fresh thread stack, as large as `RLIMIT_STACK` lets it grow, with
    // an inaccessible guard page below it, ending at `loader::STACK_TOP`
    // where that is free.
    let stack = stack_size(stack_limit, page);
    // SAFETY: a fresh mapping owned by the guest; not MAP_FIXED, the
    // address is only a hint.
    let stack_base = unsafe {
        libc::mmap(
            (loader::STACK_TOP - stack - page) as *mut libc::c_void,
            (stack + page) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err(Error::Load(loader::LoadError::Map(std::io::Error::last_os_error())));
    }
    fwe_kernel::mm::track(stack_base as u64, stack + page);
    // SAFETY: protecting the lowest page of the mapping just made.
    unsafe { libc::mprotect(stack_base, page as usize, libc::PROT_NONE) };
    let stack_top = stack_base as u64 + stack + page;
    fwe_kernel::maps::record().set_stack(stack_base as u64 + page, stack_top);
    fwe_kernel::maps::record().set_heap(brk.start, brk.start, brk.limit);

    let (hwcap, hwcap2) = hwcap::detect();
    let mut aux = vec![
        (auxv::AT_HWCAP, hwcap),
        (auxv::AT_PAGESZ, page),
        (auxv::AT_CLKTCK, 100),
        (auxv::AT_PHENT, loaded.phent as u64),
        (auxv::AT_PHNUM, loaded.phnum as u64),
        (auxv::AT_BASE, interp_base),
        (auxv::AT_FLAGS, 0),
        (auxv::AT_ENTRY, loaded.entry),
        (auxv::AT_UID, u64::from(ids.uid)),
        (auxv::AT_EUID, u64::from(ids.euid)),
        (auxv::AT_GID, u64::from(ids.gid)),
        (auxv::AT_EGID, u64::from(ids.egid)),
        (auxv::AT_SECURE, u64::from(ids.secure)),
        (auxv::AT_HWCAP2, hwcap2),
        (auxv::AT_MINSIGSTKSZ, fwe_abi::signal::MINSIGSTKSZ),
    ];
    if let Some(phdr) = loaded.phdr {
        aux.push((auxv::AT_PHDR, phdr));
    }

    let image =
        stack::InitialStack { args, env, execfn, auxv: &aux, random: random16() }.build(stack_top);
    if stack_top - image.sp > stack / 2 {
        return Err(Error::Unsupported("argument list too long".into()));
    }
    // SAFETY: the image fits in the stack mapping, ending at its top.
    unsafe {
        std::ptr::copy_nonoverlapping(image.bytes.as_ptr(), image.sp as *mut u8, image.bytes.len())
    };

    if strace {
        tracer.note(&format!(
            "loaded exe entry {:#x}, interp base {interp_base:#x}, start entry {entry:#x}, \
             brk {:#x}, stack top {stack_top:#x}",
            loaded.entry, brk.start
        ));
    }
    Ok(Loadout { entry, sp: image.sp, brk, auxv: image.auxv })
}

fn start(
    path: &Path,
    args: &[OsString],
    env: &[OsString],
    options: &Options,
) -> Result<std::convert::Infallible, Error> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(Error::Unsupported(
            "the native backend runs only on macOS on Apple Silicon".into(),
        ));
    }
    // fwe's own descriptors go above the guest's range from here on.
    fwe_kernel::fdtable::init();
    fwe_kernel::timing::mark("main");
    if options.exec_state.is_none() {
        // A fresh start: what earlier runs left behind and no process holds
        // goes (see `fwe_kernel::shared::collect`).
        fwe_kernel::shared::collect();
    }
    let args = &guest_args(args, options);
    fwe_kernel::timing::mark("collect");
    // The root filesystem; also used to find the dynamic linker.
    let mut fs = open_fs(options)?;
    fwe_kernel::timing::mark("open_fs");
    // The path the program is run by, which names it (a script's own).
    let run_by = guest_execfn(path, options);
    let (path, args, options, (data, data_id)) = script_target(path, args, options, &fs)?;
    let (path, args, options) = (path.as_path(), &args, &options);
    fwe_kernel::timing::mark("read_program");
    // A non-PIE executable linked into the low 4 GiB cannot be mapped in
    // this process: it runs in a VM instead.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if let Some(why) = vm_reason(&data) {
        options.strace.note(&format!("runs in the VM: {why}"));
        fwe_kernel::timing::mark("backend: vm");
        drop(fs);
        return Err(hv::run(path, &data, args, env, options));
    }
    fwe_kernel::timing::mark("backend: native");

    let page = page_size();
    let tracer = options.strace;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    trap::set_tracing(tracer.enabled);
    let platform = NativePlatform { slots: slots(), page_size: page };

    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|e| e.as_bytes()).collect();
    let out = load_image(
        (&data, data_id),
        &guest_execfn(path, options),
        &arg_bytes,
        &env_bytes,
        &fs,
        &platform,
        page,
        options.strace,
        start_stack_limit(options),
        start_aux_ids(options)?,
    )?;
    fwe_kernel::timing::mark("load_image");
    // A trampoline used as the return address for signal handlers that have
    // no sa_restorer: it issues the rt_sigreturn system call.
    let sigreturn_tramp = make_sigreturn_trampoline(page)?;
    fwe_kernel::timing::mark("trampoline");
    // What the process's record tells of it, written once.
    fwe_kernel::procreg::batch(|| {
        let exe = fs.exe_fd_target().unwrap_or_else(|| guest_exe_path(path, options, &fs));
        let named =
            options.comm.clone().unwrap_or_else(|| fwe_kernel::fs::exec_name(&run_by, &exe));
        fs.set_proc_info(exe, &named, cmdline(&arg_bytes), ncpu(), hostname());
        if let Some(fd) = open_program(path, options, &fs) {
            fs.set_exe_fd(Some(fd));
        }
        fs.set_auxv(out.auxv.clone());
        fs.publish();
        // The main thread's id equals the process id, as on Linux: in its
        // pid namespace, for a process exec'd in one.
        fwe_kernel::thread::init_main(fwe_kernel::pidns::adopt(&fs.ns, 0));
        fwe_kernel::procreg::own_namespaces(fs.ns_dirs());
        if options.exec_state.is_none() {
            fwe_kernel::signote::job_reset();
        }
    });
    fwe_kernel::timing::mark("published");
    // A subreaper stays one across execve; a namespace's init is one.
    fwe_kernel::reaper::start_if_reaper();

    let mut kernel = Kernel::new(platform, page, out.brk, Some(fs), tracer);
    kernel.set_sigreturn_trampoline(sigreturn_tramp);
    apply_exec_state(&mut kernel, options, path)?;
    *KERNEL.lock() = Some(kernel);
    fwe_kernel::timing::mark("kernel");
    enter(out.sp, out.entry)
}

/// The guest's absolute path of the program fwe was asked to run, for
/// `/proc/self/exe`: the host path, made relative to the root filesystem when
/// the program lies inside it, its symbolic links followed there.
/// The program's file, open as fwe's own descriptor, for `/proc/self/exe`
/// to reach whatever becomes of its path (a file outside the root, too),
/// as Linux holds a process's `exe_file`; `None` when fwe holds it already
/// (it was run by descriptor).
fn open_program(path: &Path, options: &Options, fs: &fwe_kernel::Fs) -> Option<i32> {
    if options.exe_fd.is_some() {
        return None;
    }
    if options.guest_path {
        return fs.open_program(path.as_os_str().as_bytes());
    }
    if let Some(guest) = guest_path_in_root(path, options) {
        return fs.open_program(&guest);
    }
    use std::os::fd::IntoRawFd;
    let fd = std::fs::File::open(path).ok()?.into_raw_fd();
    fwe_kernel::fdtable::reserve(fd).ok()
}

fn guest_exe_path(path: &Path, options: &Options, fs: &fwe_kernel::Fs) -> Vec<u8> {
    if options.guest_path {
        return path.as_os_str().as_bytes().to_vec();
    }
    if let Some(guest) = guest_path_in_root(path, options) {
        let cwd = fwe_abi::fcntl::AT_FDCWD as i32;
        return fs.resolve(cwd, &guest, true).ok().and_then(|r| r.ns_path).unwrap_or(guest);
    }
    match std::fs::canonicalize(path) {
        Ok(host) => host.as_os_str().as_bytes().to_vec(),
        Err(_) => path.as_os_str().as_bytes().to_vec(),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enter(sp: u64, entry: u64) -> Result<std::convert::Infallible, Error> {
    trap::install_handlers();
    // Signals the guest inherits as ignored stay ignored; the rest go to
    // their default action until the guest says otherwise.
    KERNEL.lock().as_mut().unwrap().adopt_host_signals();
    // A traced program, re-executed by fwe, stops for its tracer before its
    // first instruction, as after any `execve`.
    let traced = fwe_kernel::ptrace::traced().then(|| {
        let mut regs = fwe_kernel::Regs { sp, pc: entry, ..fwe_kernel::Regs::default() };
        KERNEL.exec_stops(&mut regs);
        regs
    });
    // From here on this thread runs guest code, which can use x18 freely;
    // the trap handlers leave the mode while they run host code. Its waits
    // from here on are the program's.
    fwe_kernel::procstore::entered();
    trap::prepare_guest_entry();
    match traced {
        // SAFETY: the registers of the program's entry, as the tracer left them.
        Some(regs) => unsafe { trap::enter_guest_full(&regs) },
        None => trap::enter_guest(sp, entry),
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn enter(_sp: u64, _entry: u64) -> Result<std::convert::Infallible, Error> {
    unreachable!("checked in start")
}
