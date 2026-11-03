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
//! Not yet supported here: threads, `fork` and `execve` (they fail with
//! `ENOSYS`).

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod backend;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod ffi;
pub mod spike;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vm;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use backend::run;
pub use spike::{Spike, spike};
