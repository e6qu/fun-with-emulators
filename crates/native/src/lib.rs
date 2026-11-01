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
    fn prepare(&self, addr: u64, len: u64) -> Result<prepare::Prepared, prepare::NoStubSpace> {
        // SAFETY: callers pass guest memory that was just made readable and
        // writable and is not executing yet.
        unsafe { prepare::prepare(addr, len, self.tp_slot, self.page_size) }
    }
}

impl Platform for NativePlatform {
    fn prepare_exec(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        self.prepare(addr, len).map(|_| ()).map_err(|_| fwe_abi::errno::ENOMEM)
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
    /// The host preserves x18 for this process.
    pub x18_preserved: bool,
}

impl fmt::Display for HostSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x18 preserved: {}", if self.x18_preserved { "yes" } else { "no" })
    }
}

/// Opt in to host features guests need and report what is available.
///
/// macOS reserves x18 and clears it on context switches. Newer releases let
/// a process opt in to a custom x18 ABI, under which x18 is preserved.
pub fn host_support() -> HostSupport {
    static SUPPORT: OnceLock<HostSupport> = OnceLock::new();
    *SUPPORT.get_or_init(|| HostSupport { x18_preserved: enable_custom_x18_abi() })
}

#[cfg(target_os = "macos")]
fn enable_custom_x18_abi() -> bool {
    let name = c"os_set_custom_x18_abi_enabled";
    // SAFETY: looking up a symbol in the already-loaded system libraries.
    let f = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if f.is_null() {
        return false;
    }
    // SAFETY: the libSystem function takes a bool enabling the custom x18
    // ABI for this process.
    let set: extern "C" fn(bool) = unsafe { std::mem::transmute(f) };
    set(true);
    true
}

#[cfg(not(target_os = "macos"))]
fn enable_custom_x18_abi() -> bool {
    false
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
    let loaded = loader::load(&elf, page, |a, l| {
        let stats = platform
            .prepare(a, l)
            .map_err(|e| format!("no room for code stubs near {:#x}", e.near))?;
        if options.strace {
            tracer.note(&format!(
                "prepared {a:#x}+{l:#x}: {} system calls, {} thread pointer accesses",
                stats.syscalls, stats.stubs
            ));
        }
        Ok(())
    })
    .map_err(Error::Load)?;
    let brk = Brk::reserve((loaded.end + page - 1) & !(page - 1), Brk::RESERVATION);

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
    trap::enter_guest(sp, entry)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn enter(_sp: u64, _entry: u64) -> Result<std::convert::Infallible, Error> {
    unreachable!("checked in start")
}
