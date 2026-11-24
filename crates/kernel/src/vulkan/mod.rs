//! fwe's Vulkan driver, the host side: each Vulkan command a Linux program
//! makes reaches the Mac's Vulkan driver in this process, called as the
//! Mac's code is called.
//!
//! - **The guest side** is fwe's Linux Vulkan driver, `libvulkan_fwe.so`
//!   (`driver/vulkan/`), which the program's own Vulkan loader loads from
//!   its manifest in `/usr/share/vulkan/icd.d`. Its stub for a command packs
//!   the command's arguments into 64-bit words and makes one ioctl on fwe's
//!   GPU device ([`generated::IOCTL_CALL`]).
//! - **The call**: fwe calls the driver's function for the command with
//!   those words, typed as the command is ([`generated::call`]), so the
//!   Mac's calling convention is the compiler's to apply. The guest's
//!   pointers are the process's: the driver reads and writes the guest's
//!   memory itself. Pages fwe has yet to make writable there are made so
//!   first ([`generated::outputs`], [`crate::mm::host_writes`]).
//! - **Handles** are the driver's own. The guest's loader writes its
//!   dispatch table into the first word of a dispatchable object (a device,
//!   queue or command buffer), which a driver keeps for a loader and never
//!   reads. Each object's functions are the ones its instance or device
//!   gave ([`objects`]).
//! - **No host code calls guest code**: every allocator argument reaches
//!   the driver as NULL, the extensions whose structures hold callbacks are
//!   not offered, and their structures are left out of the chains fwe
//!   copies ([`chain`]).
//! - **Instances and devices** are made from copies of the guest's create
//!   infos, with the window systems' extensions (the guest library's own)
//!   replaced by the driver's it builds them on, and a portability
//!   driver's extensions put in.
//! - **Window systems** are the guest library's (`driver/vulkan/wsi.c`):
//!   a program's swapchain is the driver's, on a surface of no window
//!   (`VK_EXT_headless_surface`), whose frames the library shows in the
//!   program's X window. fwe answers its queries of an object's parent and
//!   a queue's family ([`generated::PARENT`], [`generated::QUEUE_FAMILY`]).
//! - **Null descriptors** where the driver has none are stand-ins of fwe's
//!   ([`null`]).
//! - **Waits** with a timeout end at the deadline the stub computed, and
//!   are made in slices of [`SLICE_NS`]: a signal for the waiting thread
//!   ends the call with `EINTR`, and the stub makes it again.

pub mod chain;
pub mod device;
pub mod driver;
pub mod files;
#[rustfmt::skip]
pub mod generated;
pub mod null;
pub mod objects;

use fwe_abi::errno;
use generated::{COMMANDS, MOST_ARGS, cmd};
use std::ffi::{CStr, c_void};

/// What a command's first argument is: nothing (a global command), an
/// instance or physical device, or a device or an object of one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Global,
    Instance,
    Device,
}

/// How long one slice of a wait is: the longest a signal waits for a thread
/// waiting on the GPU.
pub const SLICE_NS: u64 = 5_000_000;

/// `VkResult`s fwe gives.
pub mod result {
    pub const SUCCESS: i32 = 0;
    pub const TIMEOUT: i32 = 2;
    pub const INCOMPLETE: i32 = 5;
    pub const ERROR_INITIALIZATION_FAILED: i32 = -3;
    pub const ERROR_LAYER_NOT_PRESENT: i32 = -6;
    pub const ERROR_EXTENSION_NOT_PRESENT: i32 = -7;
    pub const ERROR_UNKNOWN: i32 = -13;
}

/// The driver's extensions a surface of the guest library's is built on: a
/// surface of no window.
const SURFACE: &[&CStr] = &[c"VK_KHR_surface", c"VK_EXT_headless_surface"];

/// The extensions the guest library implements itself (the window
/// systems), with their versions, and the driver's it builds each on:
/// offered where the driver has those, which are enabled in its place.
pub const GUEST_EXTENSIONS: [(&CStr, u32, Level, &[&CStr]); 4] = [
    (c"VK_KHR_surface", 25, Level::Instance, SURFACE),
    (c"VK_KHR_xcb_surface", 6, Level::Instance, SURFACE),
    (c"VK_KHR_xlib_surface", 6, Level::Instance, SURFACE),
    (c"VK_KHR_swapchain", 70, Level::Device, &[c"VK_KHR_swapchain"]),
];

/// The size of a `VkExtensionProperties`: a 256-byte name and a version.
const EXTENSION_PROPERTIES: usize = 260;

/// Run command `index` with the stub's words `w`: its result as the
/// command returns it (a `VkResult`, or a value), or an errno for the
/// ioctl itself.
pub fn call(index: u32, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let driver = driver::get().map_err(|_| errno::ENODEV)?;
    match index {
        generated::HAS => return Ok(u64::from(objects::has(driver, w[0], w[1]))),
        generated::PARENT => return Ok(objects::parent(w[0])),
        generated::QUEUE_FAMILY => return Ok(u64::from(objects::queue_family(w[0]))),
        _ => {}
    }
    let index = index as usize;
    if index >= COMMANDS {
        return Err(errno::EINVAL);
    }
    if generated::SPECIAL[index] {
        return special(driver, index, w);
    }
    plain(driver, index, w)
}

/// Command `index` as the driver has it, after fwe makes ready the guest
/// memory it writes.
fn plain(driver: &driver::Driver, index: usize, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let f = objects::function(driver, index, w[0]).ok_or(errno::EINVAL)?;
    outputs_writable(index, w);
    // SAFETY: `f` is the driver's function for command `index` for the
    // object in `w[0]`, and `w` the command's arguments as its stub packed
    // them; the guest's pointers among them are the process's.
    let r = unsafe { generated::call(index, f, w) };
    objects::after(driver, index, w, r);
    Ok(r)
}

/// Make the guest memory command `index` writes writable by the host
/// ([`crate::mm::host_writes`]), each structure of the `pNext` chains the
/// driver fills too.
fn outputs_writable(index: usize, w: &[u64; MOST_ARGS]) {
    if !crate::mm::host_writes_watched() {
        return;
    }
    let read_count = |addr: u64, width: u64| match width {
        8 => crate::uaccess::read::<u64>(addr).unwrap_or(0),
        _ => u64::from(crate::uaccess::read::<u32>(addr).unwrap_or(0)),
    };
    let read_u32 = |addr: u64, offset: u64| {
        u64::from(crate::uaccess::read::<u32>(addr.wrapping_add(offset)).unwrap_or(0))
    };
    generated::outputs(index, w, read_count, read_u32, |addr, count, size, chained| {
        if addr == 0 {
            return;
        }
        let count = count.min(1 << 20);
        crate::mm::host_writes(addr, count.saturating_mul(size));
        if chained {
            for i in 0..count {
                chain_writable(addr + i * size);
            }
        }
    });
}

/// Make the structures of the `pNext` chain of guest structure `addr`
/// writable by the host.
fn chain_writable(addr: u64) {
    let mut at = crate::uaccess::read::<u64>(addr + 8).unwrap_or(0);
    for _ in 0..256 {
        if at == 0 {
            return;
        }
        let Ok(stype) = crate::uaccess::read::<u32>(at) else { return };
        if let Some(size) = generated::struct_size(stype) {
            crate::mm::host_writes(at, size);
        }
        at = crate::uaccess::read::<u64>(at + 8).unwrap_or(0);
    }
}

/// The commands fwe answers with code of its own ([`generated::SPECIAL`]).
fn special(driver: &driver::Driver, index: usize, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let vk = |r: i32| Ok(r as u32 as u64);
    match index {
        cmd::vkEnumerateInstanceVersion => {
            let f = objects::global(driver, index);
            let mut version = 0u32;
            let r = match f {
                // SAFETY: the driver's function, given a valid out-parameter.
                Some(f) => unsafe {
                    generated::call(index, f, &words(&[&mut version as *mut u32 as u64]))
                },
                None => {
                    version = 1 << 22; // Vulkan 1.0
                    0
                }
            };
            let version = version.min(registry_version());
            crate::uaccess::write(w[0], version).map_err(|_| errno::EFAULT)?;
            Ok(r)
        }
        cmd::vkEnumerateInstanceLayerProperties | cmd::vkEnumerateDeviceLayerProperties => {
            // Layers are the guest loader's; a driver has none.
            let count = if index == cmd::vkEnumerateDeviceLayerProperties { w[1] } else { w[0] };
            crate::uaccess::write(count, 0u32).map_err(|_| errno::EFAULT)?;
            vk(result::SUCCESS)
        }
        cmd::vkEnumerateInstanceExtensionProperties => {
            if w[0] != 0 {
                return vk(result::ERROR_LAYER_NOT_PRESENT);
            }
            let f = objects::global(driver, index).ok_or(errno::EINVAL)?;
            let list = host_extensions(|count, props| {
                // SAFETY: the driver's function, with valid out-parameters.
                unsafe { generated::call(index, f, &words(&[0, count, props])) as i32 }
            });
            vk(give_extensions(w[1], w[2], &offered(&list, Level::Instance)))
        }
        cmd::vkEnumerateDeviceExtensionProperties => {
            if w[1] != 0 {
                return vk(result::ERROR_LAYER_NOT_PRESENT);
            }
            let f = objects::function(driver, index, w[0]).ok_or(errno::EINVAL)?;
            let list = host_extensions(|count, props| {
                // SAFETY: the driver's function, with valid out-parameters.
                unsafe { generated::call(index, f, &words(&[w[0], 0, count, props])) as i32 }
            });
            vk(give_extensions(w[2], w[3], &offered(&list, Level::Device)))
        }
        cmd::vkCreateInstance => objects::create_instance(driver, w),
        cmd::vkCreateDevice => objects::create_device(driver, w),
        cmd::vkDestroyInstance => plain(driver, index, w),
        cmd::vkDestroyDevice => {
            null::stop(driver, w[0]);
            plain(driver, index, w)
        }
        cmd::vkGetPhysicalDeviceFeatures2 => {
            let r = plain(driver, index, w)?;
            null::features(driver, w[0], w[1]);
            Ok(r)
        }
        cmd::vkUpdateDescriptorSets
        | cmd::vkUpdateDescriptorSetWithTemplate
        | cmd::vkCmdPushDescriptorSet
        | cmd::vkCmdPushDescriptorSetWithTemplate
        | cmd::vkCmdPushDescriptorSet2
        | cmd::vkCmdPushDescriptorSetWithTemplate2
        | cmd::vkCmdBindVertexBuffers
        | cmd::vkCmdBindVertexBuffers2
        | cmd::vkCreateDescriptorUpdateTemplate
        | cmd::vkDestroyDescriptorUpdateTemplate => null::call(driver, index, w),
        cmd::vkWaitForFences
        | cmd::vkWaitSemaphores
        | cmd::vkWaitSemaphoresKHR
        | cmd::vkAcquireNextImageKHR => wait(driver, index, w),
        _ => plain(driver, index, w),
    }
}

/// A command's words from the first few.
fn words(first: &[u64]) -> [u64; MOST_ARGS] {
    let mut w = [0u64; MOST_ARGS];
    w[..first.len()].copy_from_slice(first);
    w
}

/// The Vulkan version of the registry fwe's commands are from: the newest a
/// guest is told of.
fn registry_version() -> u32 {
    let mut parts = generated::REGISTRY.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(1), parts.next().unwrap_or(0));
    (major << 22) | (minor << 12) | 0xfff
}

/// A wait with a timeout (`vkWaitForFences`, `vkWaitSemaphores`,
/// `vkAcquireNextImageKHR`), whose
/// stub made the timeout argument an absolute `CLOCK_MONOTONIC` deadline:
/// waited for in slices of [`SLICE_NS`] until the GPU is done, the
/// deadline passes, or a signal for the thread comes (`EINTR`: the stub
/// asks again, with the same deadline).
fn wait(driver: &driver::Driver, index: usize, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let at = generated::deadline_arg(index).ok_or(errno::EINVAL)?;
    let deadline = w[at];
    let mut slice = *w;
    loop {
        let left = deadline.saturating_sub(monotonic_ns());
        slice[at] = left.min(SLICE_NS);
        let r = plain(driver, index, &slice)?;
        // A slice that ended with time left: `VK_TIMEOUT` (an acquire's
        // `VK_NOT_READY` is for a timeout of 0, which a slice never is).
        if r as u32 as i32 != result::TIMEOUT || left <= SLICE_NS {
            return Ok(r);
        }
        if crate::thread::deliverable() != 0 {
            return Err(errno::EINTR);
        }
    }
}

/// The host's `CLOCK_MONOTONIC` (the guest's), in nanoseconds.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid out-parameter.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The driver's extensions, from its enumeration function `enumerate`
/// (given the count's and the list's addresses).
fn host_extensions(enumerate: impl Fn(u64, u64) -> i32) -> Vec<(Vec<u8>, u32)> {
    let mut count = 0u32;
    enumerate(&mut count as *mut u32 as u64, 0);
    let mut props = vec![[0u8; EXTENSION_PROPERTIES]; count as usize];
    enumerate(&mut count as *mut u32 as u64, props.as_mut_ptr() as u64);
    props.truncate(count as usize);
    props
        .iter()
        .map(|p| {
            let name = p[..256].split(|&b| b == 0).next().unwrap_or_default().to_vec();
            let version = u32::from_ne_bytes([p[256], p[257], p[258], p[259]]);
            (name, version)
        })
        .collect()
}

/// The extensions of `level` offered to the guest: the driver's that fwe
/// covers ([`generated::EXTENSIONS`]), and the guest library's own where
/// the driver has those they are built on.
pub fn offered(host: &[(Vec<u8>, u32)], level: Level) -> Vec<(Vec<u8>, u32)> {
    let has = |name: &[u8]| host.iter().any(|(n, _)| n.as_slice() == name);
    let mut list: Vec<(Vec<u8>, u32)> = host
        .iter()
        .filter(|(name, _)| {
            generated::EXTENSIONS
                .iter()
                .any(|(n, l)| n.as_bytes() == name.as_slice() && *l == level)
                && !GUEST_EXTENSIONS.iter().any(|(n, ..)| n.to_bytes() == name.as_slice())
        })
        .cloned()
        .collect();
    list.extend(
        GUEST_EXTENSIONS
            .iter()
            .filter(|(_, _, l, on)| *l == level && on.iter().all(|e| has(e.to_bytes())))
            .map(|(n, v, ..)| (n.to_bytes().to_vec(), *v)),
    );
    list
}

/// The driver's extensions to enable for the guest's `names`: each of the
/// guest library's replaced by those it is built on, once each.
pub fn host_names(names: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for name in names {
        let replaced = GUEST_EXTENSIONS.iter().find(|(n, ..)| n.to_bytes() == name.as_slice());
        let these = match replaced {
            Some((.., on)) => on.iter().map(|e| e.to_bytes().to_vec()).collect(),
            None => vec![name],
        };
        for n in these {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Write extension list `list` to the guest as Vulkan's enumerations do: the
/// count to `count_at`, and, where `props_at` is not NULL, as many as fit
/// (`VK_INCOMPLETE` if not all do).
fn give_extensions(count_at: u64, props_at: u64, list: &[(Vec<u8>, u32)]) -> i32 {
    if props_at == 0 {
        return match crate::uaccess::write(count_at, list.len() as u32) {
            Ok(()) => result::SUCCESS,
            Err(_) => result::ERROR_UNKNOWN,
        };
    }
    let Ok(room) = crate::uaccess::read::<u32>(count_at) else { return result::ERROR_UNKNOWN };
    let given = list.len().min(room as usize);
    for (i, (name, version)) in list.iter().take(given).enumerate() {
        let mut p = [0u8; EXTENSION_PROPERTIES];
        p[..name.len().min(255)].copy_from_slice(&name[..name.len().min(255)]);
        p[256..].copy_from_slice(&version.to_ne_bytes());
        if crate::uaccess::write(props_at + (i * EXTENSION_PROPERTIES) as u64, p).is_err() {
            return result::ERROR_UNKNOWN;
        }
    }
    if crate::uaccess::write(count_at, given as u32).is_err() {
        return result::ERROR_UNKNOWN;
    }
    if given < list.len() { result::INCOMPLETE } else { result::SUCCESS }
}

/// A function of the driver's, as a pointer.
pub type Function = *const c_void;

#[cfg(test)]
mod tests;
