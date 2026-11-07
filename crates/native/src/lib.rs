//! The native execution backend: Linux code runs directly on the CPU inside
//! this macOS process, with system calls redirected to the kernel layer.

pub mod decode;
pub mod hv;
pub mod hwcap;
pub mod loader;
pub mod prepare;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod process;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod quiesce;
pub mod rewrite;
pub mod stack;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod threads;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod trap;

/// Live guest threads, so the last one to exit ends the process.
static LIVE_THREADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

/// End the calling guest thread: the last thread ends the process, any other
/// ends just its host thread. Must be called without the kernel lock held,
/// since `pthread_exit` does not return and would never release it.
pub(crate) fn exit_current_thread(code: i32) -> ! {
    if LIVE_THREADS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        // SAFETY: terminating the process.
        unsafe { libc::_exit(code) }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    quiesce::forget_current();
    // SAFETY: ends the calling host thread; the process keeps running.
    unsafe { libc::pthread_exit(std::ptr::null_mut()) }
}

use fwe_abi::auxv;
use fwe_elf::Elf;
use fwe_kernel::{Brk, Kernel, Platform, Tracer};
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Size of the guest's main thread stack.
pub const STACK_SIZE: u64 = 8 << 20;

/// The kernel of the guest running in this process.
#[allow(dead_code)]
static KERNEL: Mutex<Option<Kernel<NativePlatform>>> = Mutex::new(None);

/// [`Platform`] for guests running natively in this process.
pub struct NativePlatform {
    /// Byte offset of the guest thread pointer in the host TSD.
    pub tp_slot: u32,
    /// Byte offset of the guest `x18` in the host TSD.
    pub x18_slot: u32,
    pub page_size: u64,
}

impl NativePlatform {
    fn prepare(
        &self,
        addr: u64,
        len: u64,
        arena: Option<&mut prepare::StubArena>,
        known: Option<&[(u64, u64)]>,
    ) -> Result<prepare::Prepared, prepare::NoStubSpace> {
        // SAFETY: callers pass guest memory that was just made readable and
        // writable and is not executing yet.
        unsafe {
            let (tp, x18, page) = (self.tp_slot, self.x18_slot, self.page_size);
            prepare::prepare(addr, len, tp, x18, page, arena, known)
        }
    }
}

impl Platform for NativePlatform {
    fn prepare_exec(
        &mut self,
        addr: u64,
        len: u64,
        known: Option<&[(u64, u64)]>,
    ) -> Result<(), fwe_kernel::PrepareFailed> {
        self.prepare(addr, len, None, known).map(|_| ()).map_err(|e| fwe_kernel::PrepareFailed {
            errno: fwe_abi::errno::ENOMEM,
            why: e.to_string(),
        })
    }

    fn exit(&mut self, code: i32) -> ! {
        fwe_kernel::procreg::exiting((code & 0xff) << 8);
        // SAFETY: terminating the process; the guest owns all its state.
        unsafe { libc::_exit(code) }
    }

    fn exit_thread(&mut self, code: i32) -> ! {
        exit_current_thread(code)
    }

    fn kill_self(&mut self, sig: libc::c_int) -> ! {
        fwe_kernel::procreg::exiting(fwe_kernel::host::signal_to_linux(sig) as i32);
        // SAFETY: resetting the disposition, unblocking and raising `sig`
        // terminates the process with that signal.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, sig);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
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
    // the guest must never see, reuse or close the trace file's.
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
    /// What the guest that exec'd this program carries into it
    /// ([`fwe_kernel::Kernel::exec_state`]), hex-encoded.
    pub exec_state: Option<Vec<u8>>,
    /// A descriptor fwe was handed the program on, for a program with no
    /// path (a memfd) that a guest `execve` ran.
    pub exe_fd: Option<i32>,
}

/// Hex-encode `bytes`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// Decode [`hex`]'s output.
fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
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
        fs.set_exe_fd(Some(fd));
    }
    if let Some(cwd) = &options.cwd {
        fs.chdir(fwe_abi::fcntl::AT_FDCWD as i32, cwd).map_err(|e| {
            Error::Unsupported(format!("entering {}: errno {e}", String::from_utf8_lossy(cwd)))
        })?;
    }
    Ok(fs)
}

/// The program's bytes: a host path, or a guest path in the rootfs.
fn read_program(path: &Path, options: &Options, fs: &fwe_kernel::Fs) -> Result<Vec<u8>, Error> {
    if options.exe_fd.is_some() {
        fs.read(b"/proc/self/exe").map_err(|e| Error::Read(std::io::Error::from_raw_os_error(e)))
    } else if options.guest_path {
        fs.read(path.as_os_str().as_bytes())
            .map_err(|e| Error::Read(std::io::Error::from_raw_os_error(e)))
    } else {
        std::fs::read(path).map_err(Error::Read)
    }
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
    let host = std::fs::canonicalize(path).ok()?;
    let root = std::fs::canonicalize(options.root.as_ref()?).ok()?;
    let inside = host.strip_prefix(&root).ok()?;
    Some(Path::new("/").join(inside).as_os_str().as_bytes().to_vec())
}

/// The name the program was started by, as `AT_EXECFN` gives it: the path
/// fwe was given, in the guest's terms.
pub(crate) fn guest_execfn(path: &Path, options: &Options) -> Vec<u8> {
    guest_path_in_root(path, options).unwrap_or_else(|| path.as_os_str().as_bytes().to_vec())
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

/// `execve` by re-executing fwe on the new program: the new process image is
/// a fresh fwe, which picks the backend the program needs — the native one,
/// or the VM for a program linked below 4 GiB — so either backend can exec
/// a program of the other kind. What Linux keeps across `execve` the host
/// keeps across its own: the pid, descriptors not marked close-on-exec (the
/// guest's flag is the host's), the signal mask, pending signals and ignored
/// dispositions; the root filesystem, working directory, `--strace`,
/// `--hv-standin` and `--hv-record` are passed on, and a program with no
/// path (a memfd) by descriptor (`--exe-fd`). Other threads end, as on Linux. Returns a Linux errno only if
/// the program cannot be run; on success it does not return.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reexec(
    path: &[u8],
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    fs: &fwe_kernel::Fs,
    strace: Tracer,
    state: &[u8],
    before_exec: impl FnOnce(),
) -> i64 {
    use fwe_abi::{err, errno};
    use std::ffi::CString;
    let file = match fs.read(path) {
        Ok(f) => f,
        Err(e) => return err(e),
    };
    if Elf::parse(&file).is_err() {
        return err(errno::ENOEXEC);
    }
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
    argv.push(b"--exec-state".to_vec());
    argv.push(hex(state));
    if let Some(a0) = args.first() {
        argv.push(b"--argv0".to_vec());
        argv.push(a0.clone());
    }
    // A program with no path goes by descriptor: one of fwe's, kept open
    // across the host `execve`.
    let held = match fs.exec_fd(path).map(fwe_kernel::fdtable::dup_reserved) {
        Some(Ok(held)) => {
            // SAFETY: plain host call on fwe's own descriptor; it must
            // survive the host `execve` (the new fwe takes it over).
            unsafe { libc::fcntl(held, libc::F_SETFD, 0) };
            argv.push(b"--exe-fd".to_vec());
            argv.push(held.to_string().into_bytes());
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
    fwe_kernel::host::hand_over_for_exec();
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
            // The pid from the system call itself, not libc's copy, which a
            // fork child has the parent's of until `fork` returns in it.
            // SAFETY: async-signal-safe calls ending the process.
            unsafe {
                // <sys/syscall.h>: SYS_getpid.
                const SYS_GETPID: libc::c_int = 20;
                #[allow(deprecated)]
                let me = libc::syscall(SYS_GETPID) as libc::pid_t;
                libc::kill(me, libc::SIGKILL)
            };
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
/// the thread must not call macOS library code; see `<os/arch/arm64.h>`.
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
    /// `f`'s result and whether the mode was still on. `f` must not call
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

/// Diagnostic probes of host behaviour, run one per process with
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
    // SAFETY: plain host call.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// `movz x8, #139` (rt_sigreturn).
const MOVZ_X8_139: u32 = 0xd280_1168;

/// Map a one-page `rt_sigreturn` trampoline (`movz x8, #139; svc #0`), with
/// the `svc` rewritten to a trap like any other guest code.
fn make_sigreturn_trampoline(platform: &NativePlatform, page: u64) -> Result<u64, Error> {
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
    // SAFETY: writing two instruction words into the fresh page.
    unsafe {
        (addr as *mut u32).write(MOVZ_X8_139);
        ((addr + 4) as *mut u32).write(rewrite::SVC0);
    }
    platform
        .prepare(addr, 8, None, None)
        .map_err(|e| Error::Unsupported(format!("preparing the sigreturn trampoline: {e}")))?;
    // SAFETY: making the trampoline executable.
    unsafe { libc::mprotect(p, page as usize, libc::PROT_READ | libc::PROT_EXEC) };
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

/// Load the Linux executable at `path` and run it with `args` (including
/// `argv[0]`) and `env`. Returns only on failure to start the program.
pub fn run(path: &Path, args: &[OsString], env: &[OsString], options: &Options) -> Error {
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

/// Whether `file` is a program only the hypervisor backend can run: a non-PIE
/// executable linked into the low 4 GiB.
pub fn needs_vm(file: &[u8]) -> bool {
    Elf::parse(file).is_ok_and(|elf| {
        !elf.is_pie()
            && fwe_elf::LoadPlan::new(&elf, page_size()).start < loader::host_min_address()
    })
}

/// Check that `file` is a program [`load_image`] can start, before `execve`
/// discards the old one: an arm64 ELF executable that fits the host's
/// address space, whose dynamic linker (if any) exists and is
/// position-independent. Fails with the Linux errno `execve` reports.
pub fn check_image(file: &[u8], fs: &fwe_kernel::Fs) -> Result<(), i32> {
    use fwe_abi::errno;
    let elf = Elf::parse(file).map_err(|_| errno::ENOEXEC)?;
    if !elf.is_pie() && fwe_elf::LoadPlan::new(&elf, page_size()).start < loader::host_min_address()
    {
        return Err(errno::ENOEXEC);
    }
    if let Some(ip) = elf.interpreter().map_err(|_| errno::ENOEXEC)? {
        let idata = fs.read(ip)?;
        let ielf = Elf::parse(&idata).map_err(|_| errno::ELIBBAD)?;
        if !ielf.is_pie() {
            return Err(errno::ELIBBAD);
        }
    }
    Ok(())
}

/// Load an ELF image (and its dynamic linker) and build the initial stack,
/// returning where to start the guest. Shared by process startup and
/// `execve`. Does not touch the kernel; the caller installs or updates it.
#[allow(clippy::too_many_arguments)]
pub fn load_image(
    file: &[u8],
    execfn: &[u8],
    args: &[&[u8]],
    env: &[&[u8]],
    fs: &fwe_kernel::Fs,
    platform: &NativePlatform,
    page: u64,
    tracer: Tracer,
) -> Result<Loadout, Error> {
    let elf = Elf::parse(file).map_err(Error::Elf)?;
    let interp_path = elf.interpreter().map_err(Error::Elf)?.map(<[u8]>::to_vec);

    let strace = tracer.enabled;
    let load_object = |elf: &Elf, what: &str| -> Result<loader::Loaded, Error> {
        loader::load(elf, page, |a, l, known, arena| {
            let stats = platform.prepare(a, l, Some(arena), known).map_err(|e| e.to_string())?;
            if strace {
                tracer.note(&format!(
                    "prepared {what} {a:#x}+{l:#x}: {} system calls, {} stubs, \
                     {} x18 uses left unrewritten",
                    stats.syscalls, stats.stubs, stats.x18_deferred
                ));
            }
            Ok(())
        })
        .map_err(Error::Load)
    };

    let loaded = load_object(&elf, "exe")?;
    // The program's file is told by `/proc/self/exe` when listed.
    fwe_kernel::maps::record().loaded(&elf, loaded.bias, page, fwe_kernel::maps::Name::Exe, (0, 0));

    // A dynamically linked executable names an interpreter (the dynamic
    // linker); load it too and start the guest there. It maps the executable's
    // libraries itself through our mmap and openat.
    let interp = match &interp_path {
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
            let placed = load_object(&ielf, "interp")?;
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
    let entry = interp.map_or(loaded.entry, |i| i.entry);
    let interp_base = interp.map_or(0, |i| i.load_base);

    // The break starts after the main image and its stub space.
    let brk = Brk::reserve(
        loaded.stub_arena.end.max((loaded.end + page - 1) & !(page - 1)),
        Brk::RESERVATION,
    );

    // A fresh thread stack, with an inaccessible guard page below it.
    // SAFETY: a fresh mapping owned by the guest.
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            (STACK_SIZE + page) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err(Error::Load(loader::LoadError::Map(std::io::Error::last_os_error())));
    }
    fwe_kernel::mm::track(stack_base as u64, STACK_SIZE + page);
    // SAFETY: protecting the lowest page of the mapping just made.
    unsafe { libc::mprotect(stack_base, page as usize, libc::PROT_NONE) };
    let stack_top = stack_base as u64 + STACK_SIZE + page;
    fwe_kernel::maps::record().set_stack(stack_base as u64 + page, stack_top);
    fwe_kernel::maps::record().set_heap(brk.start, brk.start, brk.limit);

    let (hwcap, hwcap2) = hwcap::detect();
    let (uid, euid, gid, egid) = fwe_kernel::host::ids();
    let mut aux = vec![
        (auxv::AT_HWCAP, hwcap),
        (auxv::AT_PAGESZ, page),
        (auxv::AT_CLKTCK, 100),
        (auxv::AT_PHENT, loaded.phent as u64),
        (auxv::AT_PHNUM, loaded.phnum as u64),
        (auxv::AT_BASE, interp_base),
        (auxv::AT_FLAGS, 0),
        (auxv::AT_ENTRY, loaded.entry),
        (auxv::AT_UID, uid as u64),
        (auxv::AT_EUID, euid as u64),
        (auxv::AT_GID, gid as u64),
        (auxv::AT_EGID, egid as u64),
        (auxv::AT_SECURE, 0),
        (auxv::AT_HWCAP2, hwcap2),
        (auxv::AT_MINSIGSTKSZ, fwe_abi::signal::MINSIGSTKSZ),
    ];
    if let Some(phdr) = loaded.phdr {
        aux.push((auxv::AT_PHDR, phdr));
    }

    let image =
        stack::InitialStack { args, env, execfn, auxv: &aux, random: random16() }.build(stack_top);
    if stack_top - image.sp > STACK_SIZE / 2 {
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
    if options.exec_state.is_none() {
        // A fresh start: what earlier runs left behind and no process holds
        // goes (see `fwe_kernel::shared::collect`).
        fwe_kernel::shared::collect();
    }
    let args = &guest_args(args, options);
    let data = read_program(path, options, &open_fs(options)?)?;
    // A non-PIE executable linked into the low 4 GiB cannot be mapped in
    // this process: it runs in a VM instead.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if needs_vm(&data) {
        return Err(hv::run(path, &data, args, env, options));
    }

    let page = page_size();
    let tracer = options.strace;
    let host = host_support();
    if tracer.enabled {
        tracer.note(&format!("host: {host}"));
    }
    let platform =
        NativePlatform { tp_slot: thread_pointer_slot(), x18_slot: x18_slot(), page_size: page };

    // The root filesystem; also used to find the dynamic linker.
    let mut fs = open_fs(options)?;

    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|e| e.as_bytes()).collect();
    let out = load_image(
        &data,
        &guest_execfn(path, options),
        &arg_bytes,
        &env_bytes,
        &fs,
        &platform,
        page,
        options.strace,
    )?;
    let exe = fs.exe_fd_target().unwrap_or_else(|| guest_exe_path(path, options));
    fs.set_proc_info(exe, cmdline(&arg_bytes), ncpu(), hostname());
    fs.set_auxv(out.auxv.clone());
    fs.publish();

    // A trampoline used as the return address for signal handlers that have
    // no sa_restorer: it issues the rt_sigreturn system call.
    let sigreturn_tramp = make_sigreturn_trampoline(&platform, page)?;

    // The main thread's id equals the process id, as on Linux: in its pid
    // namespace, for a process exec'd in one.
    fwe_kernel::thread::init_main(fwe_kernel::pidns::adopt(&fs.ns, 0));
    fwe_kernel::procreg::own_namespaces(fs.ns_dirs());
    // A subreaper stays one across execve; a namespace's init is one.
    fwe_kernel::reaper::start_if_reaper();

    let mut kernel = Kernel::new(platform, page, out.brk, Some(fs), tracer);
    kernel.set_sigreturn_trampoline(sigreturn_tramp);
    apply_exec_state(&mut kernel, options, path)?;
    *KERNEL.lock().unwrap() = Some(kernel);
    enter(out.sp, out.entry)
}

/// The guest's absolute path of the program fwe was asked to run, for
/// `/proc/self/exe`: the host path, made relative to the root filesystem when
/// the program lies inside it.
fn guest_exe_path(path: &Path, options: &Options) -> Vec<u8> {
    if options.guest_path {
        return path.as_os_str().as_bytes().to_vec();
    }
    if let Some(guest) = guest_path_in_root(path, options) {
        return guest;
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
    KERNEL.lock().unwrap().as_mut().unwrap().adopt_host_signals();
    // From here on this thread runs guest code, which may use x18 freely;
    // the trap handlers leave the mode while they run host code.
    trap::prepare_guest_entry();
    trap::enter_guest(sp, entry)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn enter(_sp: u64, _entry: u64) -> Result<std::convert::Infallible, Error> {
    unreachable!("checked in start")
}
