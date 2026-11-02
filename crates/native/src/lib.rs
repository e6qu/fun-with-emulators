//! The native execution backend: Linux code runs directly on the CPU inside
//! this macOS process, with system calls redirected to the kernel layer.

pub mod hwcap;
pub mod loader;
pub mod prepare;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod process;
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
        // SAFETY: terminating the process.
        unsafe { libc::_exit(code) }
    }
    // SAFETY: ends the calling host thread; the process keeps running.
    unsafe { libc::pthread_exit(std::ptr::null_mut()) }
}

use fwe_abi::auxv;
use fwe_elf::Elf;
use fwe_kernel::{Brk, Kernel, Platform, Tracer};
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
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
    pub page_size: u64,
}

impl NativePlatform {
    fn prepare(
        &self,
        addr: u64,
        len: u64,
        arena: Option<&mut prepare::StubArena>,
    ) -> Result<prepare::Prepared, prepare::NoStubSpace> {
        // SAFETY: callers pass guest memory that was just made readable and
        // writable and is not executing yet.
        unsafe { prepare::prepare(addr, len, self.tp_slot, self.page_size, arena) }
    }
}

impl Platform for NativePlatform {
    fn prepare_exec(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        self.prepare(addr, len, None).map(|_| ()).map_err(|_| fwe_abi::errno::ENOMEM)
    }

    fn exit(&mut self, code: i32) -> ! {
        // SAFETY: terminating the process; the guest owns all its state.
        unsafe { libc::_exit(code) }
    }

    fn exit_thread(&mut self, code: i32) -> ! {
        exit_current_thread(code)
    }

    fn kill_self(&mut self, sig: libc::c_int) -> ! {
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
}

/// How to run a guest.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Trace system calls to standard error.
    pub strace: bool,
    /// Root filesystem directory; the host `/` when `None`.
    pub root: Option<std::path::PathBuf>,
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
        .prepare(addr, 8, None)
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

/// The host name, without a trailing NUL.
pub fn hostname() -> Vec<u8> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid buffer of its length.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return b"localhost".to_vec();
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf[..end].to_vec()
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
    strace: bool,
) -> Result<Loadout, Error> {
    let elf = Elf::parse(file).map_err(Error::Elf)?;
    let interp_path = elf.interpreter().map_err(Error::Elf)?.map(<[u8]>::to_vec);

    let tracer = Tracer { enabled: strace };
    let load_object = |elf: &Elf, what: &str| -> Result<loader::Loaded, Error> {
        loader::load(elf, page, |a, l, arena| {
            let stats = platform.prepare(a, l, Some(arena)).map_err(|e| e.to_string())?;
            if strace {
                tracer.note(&format!(
                    "prepared {what} {a:#x}+{l:#x}: {} system calls, {} thread pointer accesses",
                    stats.syscalls, stats.stubs
                ));
            }
            Ok(())
        })
        .map_err(Error::Load)
    };

    let loaded = load_object(&elf, "exe")?;

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
            Some(load_object(&ielf, "interp")?)
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
    // SAFETY: protecting the lowest page of the mapping just made.
    unsafe { libc::mprotect(stack_base, page as usize, libc::PROT_NONE) };
    let stack_top = stack_base as u64 + STACK_SIZE + page;

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
    Ok(Loadout { entry, sp: image.sp, brk })
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
    let data = std::fs::read(path).map_err(Error::Read)?;

    let page = page_size();
    let tracer = Tracer { enabled: options.strace };
    let host = host_support();
    if options.strace {
        tracer.note(&format!("host: {host}"));
    }
    let platform = NativePlatform { tp_slot: thread_pointer_slot(), page_size: page };

    // The root filesystem; also used to find the dynamic linker.
    let root_bytes = options.root.as_ref().map(|p| p.as_os_str().as_bytes().to_vec());
    let mut fs = fwe_kernel::Fs::new(root_bytes.as_deref()).map_err(|e| {
        Error::Unsupported(format!("opening the root filesystem failed: errno {e}"))
    })?;

    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|e| e.as_bytes()).collect();
    let out = load_image(
        &data,
        path.as_os_str().as_bytes(),
        &arg_bytes,
        &env_bytes,
        &fs,
        &platform,
        page,
        options.strace,
    )?;
    fs.set_proc_info(path.as_os_str().as_bytes().to_vec(), cmdline(&arg_bytes), ncpu(), hostname());

    // A trampoline used as the return address for signal handlers that have
    // no sa_restorer: it issues the rt_sigreturn system call.
    let sigreturn_tramp = make_sigreturn_trampoline(&platform, page)?;

    // The main thread's id equals the process id, as on Linux.
    fwe_kernel::thread::init_main(fwe_kernel::host::getpid() as i32);

    let mut kernel = Kernel::new(platform, page, out.brk, Some(fs), tracer);
    kernel.set_sigreturn_trampoline(sigreturn_tramp);
    *KERNEL.lock().unwrap() = Some(kernel);
    enter(out.sp, out.entry)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enter(sp: u64, entry: u64) -> Result<std::convert::Infallible, Error> {
    trap::install_handlers();
    if let Some(abi) = X18Abi::get() {
        // From here on this thread runs guest code, which may use x18 freely;
        // the trap handlers leave the mode while they run host code.
        abi.set_enabled(true);
    }
    trap::enter_guest(sp, entry)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn enter(_sp: u64, _entry: u64) -> Result<std::convert::Infallible, Error> {
    unreachable!("checked in start")
}
