//! The native execution backend: Linux code runs directly on the CPU inside
//! this macOS process, with system calls redirected to the kernel layer.

pub mod hwcap;
pub mod loader;
pub mod prepare;
pub mod rewrite;
pub mod stack;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod trap;

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
    /// x18 was observed to survive kernel entry and preemption.
    pub x18_preserved: bool,
}

impl fmt::Display for HostSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let yn = |b: bool| if b { "yes" } else { "no" };
        write!(f, "x18 opt-in: {}, x18 preserved: {}", yn(self.x18_opt_in), yn(self.x18_preserved))
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
        let x18_preserved = match abi {
            Some(abi) => {
                abi.set_enabled(true);
                // No macOS library calls (or system calls) while the custom
                // ABI is on; preemption alone exercises the context switch.
                let ok = x18_survives(false);
                abi.set_enabled(false);
                ok
            }
            None => x18_survives_kernel_entry(),
        };
        HostSupport { x18_opt_in: abi.is_some(), x18_preserved }
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

fn x18_survives_kernel_entry() -> bool {
    x18_survives(true)
}

/// Diagnostic probes of host behaviour, run one per process with
/// `fwe --probe <name>`. Prints the result; a crash identifies the step.
pub fn probe(name: &str) -> Result<String, String> {
    let with_mode = |f: &dyn Fn() -> bool| -> Result<bool, String> {
        let abi = X18Abi::get().ok_or("no custom x18 ABI on this host")?;
        abi.set_enabled(true);
        let r = f();
        abi.set_enabled(false);
        Ok(r)
    };
    let yn = |b: bool| if b { "preserved" } else { "lost" }.to_string();
    match name {
        "x18-mode" => with_mode(&|| true).map(|_| "mode toggled".into()),
        "x18-spin" => Ok(yn(x18_survives(false))),
        "x18-syscall" => Ok(yn(x18_survives(true))),
        "x18-mode-spin" => with_mode(&|| x18_survives(false)).map(yn),
        "x18-mode-syscall" => with_mode(&|| x18_survives(true)).map(yn),
        _ => Err(format!("unknown probe {name}")),
    }
}

fn page_size() -> u64 {
    // SAFETY: plain host call.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn random16() -> [u8; 16] {
    let mut r = [0u8; 16];
    fwe_kernel::host::fill_random(&mut r);
    r
}

/// Load the Linux executable at `path` and run it with `args` (including
/// `argv[0]`) and `env`. Returns only on failure to start the program.
pub fn run(path: &Path, args: &[OsString], env: &[OsString], options: &Options) -> Error {
    match start(path, args, env, options) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

fn start(
    path: &Path,
    args: &[OsString],
    env: &[OsString],
    options: &Options,
) -> Result<std::convert::Infallible, Error> {
    let data = std::fs::read(path).map_err(Error::Read)?;
    let elf = Elf::parse(&data).map_err(Error::Elf)?;
    if let Some(interp) = elf.interpreter().map_err(Error::Elf)? {
        return Err(Error::Unsupported(format!(
            "dynamically linked executables are not supported yet (interpreter {})",
            String::from_utf8_lossy(interp)
        )));
    }
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(Error::Unsupported(
            "the native backend runs only on macOS on Apple Silicon".into(),
        ));
    }

    let page = page_size();
    let tracer = Tracer { enabled: options.strace };
    let host = host_support();
    if options.strace {
        tracer.note(&format!("host: {host}"));
    }
    let platform = NativePlatform { tp_slot: thread_pointer_slot(), page_size: page };
    let loaded = loader::load(&elf, page, |a, l, arena| {
        let stats = platform.prepare(a, l, Some(arena)).map_err(|e| e.to_string())?;
        if options.strace {
            tracer.note(&format!(
                "prepared {a:#x}+{l:#x}: {} system calls, {} thread pointer accesses",
                stats.syscalls, stats.stubs
            ));
        }
        Ok(())
    })
    .map_err(Error::Load)?;
    // The break starts after the image and its stub space.
    let brk = Brk::reserve(
        loaded.stub_arena.end.max((loaded.end + page - 1) & !(page - 1)),
        Brk::RESERVATION,
    );

    // The main thread stack, with an inaccessible guard page below it.
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
        (auxv::AT_BASE, 0),
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

    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|e| e.as_bytes()).collect();
    let image = stack::InitialStack {
        args: &arg_bytes,
        env: &env_bytes,
        execfn: path.as_os_str().as_bytes(),
        auxv: &aux,
        random: random16(),
    }
    .build(stack_top);
    if stack_top - image.sp > STACK_SIZE / 2 {
        return Err(Error::Unsupported("argument list too long".into()));
    }
    // SAFETY: the image fits in the stack mapping, ending at its top.
    unsafe {
        std::ptr::copy_nonoverlapping(image.bytes.as_ptr(), image.sp as *mut u8, image.bytes.len())
    };

    if options.strace {
        tracer.note(&format!(
            "loaded {} at bias {:#x}, entry {:#x}, brk {:#x}, stack top {stack_top:#x}",
            path.display(),
            loaded.bias,
            loaded.entry,
            brk.start
        ));
    }

    *KERNEL.lock().unwrap() = Some(Kernel::new(platform, page, brk, tracer));
    enter(image.sp, loaded.entry)
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
