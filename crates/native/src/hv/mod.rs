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
//! Guest memory is host memory mapped into the VM. Everything the guest maps
//! itself — its stack, break, `mmap`s, the dynamic linker — is mapped at the
//! same address in the VM as in the host, so guest pointers are host
//! pointers. Only the executable's image, at the low address the host cannot
//! map, lives elsewhere in the host; that one range is registered with
//! [`fwe_kernel::uaccess::set_translation`], and guest pointers into it are
//! translated wherever the kernel or a host call uses them.
//!
//! Each guest thread runs on a vCPU of its own; `execve` re-executes fwe.
//! A VM process never forks on the host and never ends or execs with its VM
//! alive (see `docs/hypervisor.md`): a guest `fork` or `vfork` starts a
//! fresh fwe process that takes the parent's memory copy-on-write (see
//! [`fork`]).
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
    let mut words = Vec::new();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if standin::active() {
            words.push(b"--hv-standin".to_vec());
        }
        if let Some(spec) = record::spec() {
            words.push(b"--hv-record".to_vec());
            words.push(spec.as_bytes().to_vec());
        }
    }
    words
}

/// Whether the VM backend uses the software stand-in (`--hv-standin`).
pub fn standin_active() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return standin::active();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    false
}
