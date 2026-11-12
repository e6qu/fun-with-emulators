//! The hypervisor backend: Linux programs the native backend cannot map —
//! non-PIE executables linked into the low 4 GiB that macOS reserves in
//! every process (Debian's `python3.11` at `0x400000`, static Go at
//! `0x10000`) — run in a Hypervisor.framework VM instead.
//!
//! The guest runs at EL0 under a minimal EL1 (see [`vm`]): its own `svc #0`
//! traps to the backend unchanged, so no code is rewritten, and `x18` and
//! `TPIDR_EL0` are simply the guest's. System calls go to the same kernel
//! layer as the native backend's.
//!
//! The VM's stage 2 is set up once (the slab and fwe's region, see [`vm`])
//! and does not change while it runs; the guest's own page tables
//! ([`pagetables`]) decide what it sees, and its memory system calls edit
//! them ([`mem`]). Private guest memory is slab memory, at the same address
//! as guest and host address unless the guest placed it outside the slab
//! (the executable's image at its low link address), when it is translated
//! ([`fwe_kernel::uaccess::add_translation`]) wherever the kernel or a host
//! call uses a guest pointer; every such pointer is checked against the
//! guest's mappings first.
//!
//! Each guest thread runs on a vCPU of its own; `execve` re-executes fwe.
//! A VM process never forks on the host and never ends or execs with its VM
//! alive (see `docs/hypervisor.md`): a guest `fork` or `vfork` starts a
//! fresh fwe process that takes a copy of the parent's memory, or for
//! `vfork` fetches it as it goes (see [`fork`]).
//!
//! Under `--hv-standin` every framework call goes to a software stand-in
//! instead ([`standin`]), which creates no VM: what the tests use unless
//! asked for the real framework.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod backend;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod ffi;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod fork;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod mem;
// Pure table logic: unit-tested on every host.
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
mod pagetables;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod probe;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod record;
pub mod spike;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod standin;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vm;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod window;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use backend::run;
/// The child side of a `fork` in the VM (`fwe --hv-fork-child`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use fork::child as fork_child;

/// The child side of a `fork` in the VM; there is no VM on this host.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn fork_child() -> ! {
    eprintln!("fwe: --hv-fork-child needs the hypervisor backend");
    std::process::exit(2)
}
pub use spike::{Spike, spike};

/// Use the software stand-in for Hypervisor.framework from now on; false
/// where there is no VM backend.
pub fn use_standin() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        standin::enable();
        true
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    false
}

/// `fwe --hv-standin-watch <pid>` (see [`standin`]).
pub fn standin_watch(pid: &str) -> ! {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    standin::watch(pid);
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = pid;
        std::process::exit(2)
    }
}

/// `fwe --probe hv-map-rules` (see [`probe`]).
pub fn map_rules_probe() -> Result<String, String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return probe::map_rules();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    Err("the hypervisor backend needs Apple Silicon macOS".into())
}

/// Start the flight recorder (`--hv-record DEST`, see [`record`]).
pub fn start_recording(spec: &str) -> Result<(), String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return record::start(spec);
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = spec;
        Err("the flight recorder needs Apple Silicon macOS".into())
    }
}

/// The leading options every fwe that fwe starts for the guest is given:
/// the stand-in and the flight recorder, when in use.
pub fn passed_on() -> Vec<Vec<u8>> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let mut words = Vec::new();
        if standin::active() {
            words.push(b"--hv-standin".to_vec());
        }
        if let Some(spec) = record::spec() {
            words.push(b"--hv-record".to_vec());
            words.push(spec.as_bytes().to_vec());
        }
        words
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    Vec::new()
}

/// Whether this host can run a program in the VM: the stand-in is on, or
/// fwe carries the hypervisor entitlement on a Mac with hypervisor support
/// (`kern.hv_support`). Asked once, of the kernel, never of the framework.
pub fn usable() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *USABLE.get_or_init(|| standin_active() || (hv_support() && entitled()))
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    false
}

/// `sysctl kern.hv_support`: the Mac supports the hypervisor.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hv_support() -> bool {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: reading an int sysctl into a buffer of its size.
    let r = unsafe {
        libc::sysctlbyname(
            c"kern.hv_support".as_ptr(),
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    r == 0 && v == 1
}

/// Whether this process carries the `com.apple.security.hypervisor`
/// entitlement, by its code signature's entitlements (`csops`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn entitled() -> bool {
    unsafe extern "C" {
        fn csops(pid: libc::pid_t, ops: u32, buf: *mut libc::c_void, size: usize) -> libc::c_int;
    }
    /// `CS_OPS_ENTITLEMENTS_BLOB`: a blob header, then the XML plist.
    const CS_OPS_ENTITLEMENTS_BLOB: u32 = 7;
    let mut buf = vec![0u8; 64 * 1024];
    // SAFETY: a buffer of its length, for this process's own signature.
    let r = unsafe {
        csops(libc::getpid(), CS_OPS_ENTITLEMENTS_BLOB, buf.as_mut_ptr().cast(), buf.len())
    };
    if r != 0 || buf.len() < 8 {
        return false;
    }
    let len =
        (u32::from_be_bytes(buf[4..8].try_into().unwrap_or_default()) as usize).min(buf.len());
    let text = String::from_utf8_lossy(&buf[8.min(len)..len]);
    let key = "<key>com.apple.security.hypervisor</key>";
    text.find(key).is_some_and(|at| text[at + key.len()..].trim_start().starts_with("<true/>"))
}

/// Whether the VM backend uses the software stand-in (`--hv-standin`).
pub fn standin_active() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return standin::active();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    false
}
