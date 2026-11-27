//! Host image copy (`VK_IMAGE_USAGE_HOST_TRANSFER_BIT`) as the driver can
//! back it.
//!
//! A driver can accept an image usage with host transfer in its format
//! queries and then give such an image memory types it cannot use:
//! MoltenVK takes the private memory type from any image with host
//! transfer while a depth-stencil attachment has only that type, so the
//! image has none (which Vulkan rules out), and every other image moves to
//! memory the CPU shares, while it reports that host transfer changes
//! neither memory layout nor device access. A Linux program that trusts
//! the queries (Mesa's Zink adds host transfer wherever a format offers
//! it) gets no depth buffers.
//!
//! fwe answers the format queries with what the driver's memory
//! requirements say, for a usage with host transfer:
//!
//! - **No memory type** for such an image: the combination is unsupported
//!   (`VK_ERROR_FORMAT_NOT_SUPPORTED`).
//! - **Memory types other than the same image's without host transfer**:
//!   host transfer is not free for the device
//!   (`VkHostImageCopyDevicePerformanceQuery`'s `optimalDeviceAccess` and
//!   `identicalMemoryLayout` false).
//!
//! The requirements come from `vkGetDeviceImageMemoryRequirements` (Vulkan
//! 1.3, or `VK_KHR_maintenance4`) on a device of fwe's for the physical
//! device, made as a program first asks of host transfer there ([`prepare`],
//! under the kernel lock with the guest's descriptor range plugged, as a
//! device is made) and destroyed with its instance ([`stop`]). Where no
//! such device can be made, host transfer is unsupported.

use super::driver::Driver;
use super::generated::{self, MOST_ARGS, cmd};
use super::{objects, result, words};
use crate::uaccess;
use std::collections::BTreeMap;
use std::ffi::{CStr, c_void};

/// `VK_IMAGE_USAGE_HOST_TRANSFER_BIT`.
const HOST_TRANSFER: u32 = 0x40_0000;
/// `VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT`, `VK_IMAGE_CREATE_DISJOINT_BIT`.
const CUBE: u32 = 0x10;
const DISJOINT: u32 = 0x200;
/// `VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT`.
const MODIFIER_TILING: u32 = 1_000_158_000;
/// Structure types: `VkImageCreateInfo`, `VkDeviceImageMemoryRequirements`,
/// `VkMemoryRequirements2`, `VkHostImageCopyDevicePerformanceQuery`,
/// `VkImageFormatListCreateInfo`, `VkImageStencilUsageCreateInfo`,
/// `VkDeviceCreateInfo`, `VkDeviceQueueCreateInfo`.
const IMAGE_CREATE_INFO: u32 = 14;
const DEVICE_IMAGE_REQUIREMENTS: u32 = 1_000_413_003;
const REQUIREMENTS2: u32 = 1_000_146_003;
const PERFORMANCE_QUERY: u32 = 1_000_270_009;
const FORMAT_LIST: u32 = 1_000_147_000;
const STENCIL_USAGE: u32 = 1_000_246_000;
const DEVICE_CREATE_INFO: u32 = 3;
const QUEUE_CREATE_INFO: u32 = 2;

/// fwe's device for a physical device's requirements: none (`device` 0)
/// where it could not be made.
#[derive(Clone, Copy)]
pub(crate) struct Helper {
    instance: u64,
    device: u64,
    requirements: usize,
    destroy: usize,
}

/// The helpers, by physical device. Held across a host fork
/// ([`crate::forklock`]).
pub(crate) static HELPERS: crate::forklock::ForkRwLock<BTreeMap<u64, Helper>> =
    crate::forklock::ForkRwLock::new(BTreeMap::new());

/// Whether `index` is an image format query.
fn is_query(index: usize) -> bool {
    matches!(
        index,
        cmd::vkGetPhysicalDeviceImageFormatProperties
            | cmd::vkGetPhysicalDeviceImageFormatProperties2
            | cmd::vkGetPhysicalDeviceImageFormatProperties2KHR
    )
}

/// The usage an image format query with words `w` asks about.
fn usage_of(index: usize, w: &[u64; MOST_ARGS]) -> Option<u32> {
    if index == cmd::vkGetPhysicalDeviceImageFormatProperties {
        Some(w[4] as u32)
    } else {
        uaccess::read::<u32>(w[1].checked_add(28)?).ok()
    }
}

/// Whether the call of record `arg` (`[command | count << 32, words,
/// result]`) is an image format query of host transfer on a physical
/// device fwe has no helper for yet: one to run under the kernel lock, the
/// guest's range plugged, after [`prepare`].
pub fn needs_lock(command: usize, arg: u64) -> bool {
    if !is_query(command) {
        return false;
    }
    let Ok(record) = uaccess::read::<[u64; 2]>(arg) else { return false };
    let count = ((record[0] >> 32) as usize).min(MOST_ARGS);
    let Ok(bytes) = uaccess::read_bytes(record[1], count * 8) else { return false };
    let mut w = [0u64; MOST_ARGS];
    for (word, b) in w.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_ne_bytes(*b);
    }
    usage_of(command, &w).is_some_and(|u| u & HOST_TRANSFER != 0)
        && !HELPERS.read().unwrap_or_else(|e| e.into_inner()).contains_key(&w[0])
}

/// Make the helper for the physical device of the call of record `arg`
/// ([`needs_lock`]), under the kernel lock with the guest's range plugged.
pub fn prepare(arg: u64) {
    let Ok(driver) = super::driver::get() else { return };
    let Ok(record) = uaccess::read::<[u64; 2]>(arg) else { return };
    let Ok(pd) = uaccess::read::<u64>(record[1]) else { return };
    if HELPERS.read().unwrap_or_else(|e| e.into_inner()).contains_key(&pd) {
        return;
    }
    let helper = make(driver, pd);
    HELPERS.write().unwrap_or_else(|e| e.into_inner()).insert(pd, helper);
}

/// A helper for `pd`: a device with one queue, every core feature the
/// physical device has, `VK_KHR_portability_subset` where it has that,
/// and `VK_KHR_maintenance4` below Vulkan 1.3.
fn make(driver: &Driver, pd: u64) -> Helper {
    let none = Helper { instance: objects::parent(pd), device: 0, requirements: 0, destroy: 0 };
    let call = |index: usize, args: &[u64]| -> Option<u64> {
        let f = objects::function(driver, index, pd)?;
        // SAFETY: the driver's function for `pd`, with arguments of its
        // type that fwe made.
        Some(unsafe { generated::call(index, f, &words(args)) })
    };
    // `VkPhysicalDeviceProperties` (824 bytes), its `apiVersion` first.
    let mut properties = super::Structure::<824>::zeroed();
    if call(cmd::vkGetPhysicalDeviceProperties, &[pd, properties.as_mut_ptr() as u64]).is_none() {
        return none;
    }
    let version = u32::from_ne_bytes(properties[..4].try_into().expect("four bytes"));
    let Some(f) = objects::function(driver, cmd::vkEnumerateDeviceExtensionProperties, pd) else {
        return none;
    };
    let extensions = super::host_extensions(|count, props| {
        // SAFETY: the driver's function, with valid out-parameters.
        unsafe {
            generated::call(
                cmd::vkEnumerateDeviceExtensionProperties,
                f,
                &words(&[pd, 0, count, props]),
            ) as i32
        }
    });
    let has = |name: &CStr| extensions.iter().any(|(n, _)| n.as_slice() == name.to_bytes());
    let core = version >= (1 << 22) | (3 << 12);
    let mut names: Vec<*const std::ffi::c_char> = Vec::new();
    if has(c"VK_KHR_portability_subset") {
        names.push(c"VK_KHR_portability_subset".as_ptr());
    }
    if !core {
        if !has(c"VK_KHR_maintenance4") {
            return none;
        }
        names.push(c"VK_KHR_maintenance4".as_ptr());
    }
    // `VkPhysicalDeviceFeatures` (220 bytes, in 224).
    let mut features = super::Structure::<224>::zeroed();
    if call(cmd::vkGetPhysicalDeviceFeatures, &[pd, features.as_mut_ptr() as u64]).is_none() {
        return none;
    }
    let priority = 1.0f32;
    let mut queue = super::Structure::<40>::zeroed();
    queue[..4].copy_from_slice(&QUEUE_CREATE_INFO.to_ne_bytes());
    queue[24..28].copy_from_slice(&1u32.to_ne_bytes());
    queue[32..40].copy_from_slice(&(&raw const priority as u64).to_ne_bytes());
    let mut info = super::Structure::<72>::zeroed();
    info[..4].copy_from_slice(&DEVICE_CREATE_INFO.to_ne_bytes());
    info[20..24].copy_from_slice(&1u32.to_ne_bytes());
    info[24..32].copy_from_slice(&(queue.as_ptr() as u64).to_ne_bytes());
    info[48..52].copy_from_slice(&(names.len() as u32).to_ne_bytes());
    info[56..64].copy_from_slice(&(names.as_ptr() as u64).to_ne_bytes());
    info[64..72].copy_from_slice(&(features.as_ptr() as u64).to_ne_bytes());
    let mut device = 0u64;
    let made = crate::host::with_signals_blocked(|| {
        call(cmd::vkCreateDevice, &[pd, info.as_ptr() as u64, 0, &raw mut device as u64])
    });
    if made.is_none_or(|r| r as u32 as i32 != result::SUCCESS) || device == 0 {
        return none;
    }
    // The driver's functions as its instance gives them, which a device's
    // first word leads to.
    let destroy = objects::function(driver, cmd::vkDestroyDevice, pd).map_or(0, |f| f as usize);
    let index = if core {
        cmd::vkGetDeviceImageMemoryRequirements
    } else {
        cmd::vkGetDeviceImageMemoryRequirementsKHR
    };
    let requirements = objects::function(driver, index, pd).map_or(0, |f| f as usize);
    let helper = Helper { device, requirements, destroy, ..none };
    if requirements == 0 {
        drop_helper(&helper);
        return none;
    }
    helper
}

/// Destroy `helper`'s device.
fn drop_helper(helper: &Helper) {
    if helper.device == 0 || helper.destroy == 0 {
        return;
    }
    type Destroy = unsafe extern "C" fn(u64, *const c_void);
    // SAFETY: the driver's `vkDestroyDevice` for fwe's own device, which
    // nothing else has.
    unsafe {
        std::mem::transmute::<usize, Destroy>(helper.destroy)(helper.device, std::ptr::null())
    };
}

/// Instance `instance` is about to be destroyed: so are its helpers.
pub(super) fn stop(instance: u64) {
    let gone: Vec<Helper> = {
        let mut helpers = HELPERS.write().unwrap_or_else(|e| e.into_inner());
        let pds: Vec<u64> =
            helpers.iter().filter(|(_, h)| h.instance == instance).map(|(&pd, _)| pd).collect();
        pds.iter().filter_map(|pd| helpers.remove(pd)).collect()
    };
    for h in &gone {
        drop_helper(h);
    }
}

/// What an image format query asks about.
struct Asked {
    format: u32,
    kind: u32,
    tiling: u32,
    flags: u32,
    /// Its `VkImageFormatListCreateInfo` and `VkImageStencilUsageCreateInfo`
    /// (which an image's create info takes too), copied.
    list: Option<super::Structure<32>>,
    stencil: Option<super::Structure<24>>,
}

fn asked(index: usize, w: &[u64; MOST_ARGS]) -> Option<Asked> {
    if index == cmd::vkGetPhysicalDeviceImageFormatProperties {
        let [format, kind, tiling] = [w[1], w[2], w[3]].map(|v| v as u32);
        return Some(Asked { format, kind, tiling, flags: w[5] as u32, list: None, stencil: None });
    }
    // `VkPhysicalDeviceImageFormatInfo2`: its chain at 8, then format,
    // type, tiling, usage and flags from 16.
    let info = uaccess::read::<[u32; 10]>(w[1]).ok()?;
    let mut a = Asked {
        format: info[4],
        kind: info[5],
        tiling: info[6],
        flags: info[8],
        list: None,
        stencil: None,
    };
    let mut at = uaccess::read::<u64>(w[1] + 8).ok()?;
    for _ in 0..256 {
        if at == 0 {
            break;
        }
        match uaccess::read::<u32>(at).ok()? {
            FORMAT_LIST => a.list = Some(uaccess::read(at).ok()?),
            STENCIL_USAGE => a.stencil = Some(uaccess::read(at).ok()?),
            _ => {}
        }
        at = uaccess::read::<u64>(at + 8).ok()?;
    }
    Some(a)
}

impl Helper {
    /// The memory types an image of `a` with `usage` takes, as the driver
    /// gives them: `None` where fwe cannot ask.
    fn types(&self, a: &Asked, usage: u32) -> Option<u32> {
        if self.device == 0 || a.tiling == MODIFIER_TILING {
            return None;
        }
        let mut list = a.list;
        let mut stencil = a.stencil;
        let mut next = 0u64;
        if let Some(s) = stencil.as_mut() {
            s[8..16].copy_from_slice(&next.to_ne_bytes());
            next = s.as_ptr() as u64;
        }
        if let Some(l) = list.as_mut() {
            l[8..16].copy_from_slice(&next.to_ne_bytes());
            next = l.as_ptr() as u64;
        }
        let mut info = super::Structure::<88>::zeroed();
        let mut put = |at: usize, v: u32| info[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        put(0, IMAGE_CREATE_INFO);
        put(16, a.flags);
        put(20, a.kind);
        put(24, a.format);
        put(28, 1);
        put(32, 1);
        put(36, 1);
        put(40, 1);
        put(44, if a.flags & CUBE != 0 { 6 } else { 1 });
        put(48, 1);
        put(52, a.tiling);
        put(56, usage);
        info[8..16].copy_from_slice(&next.to_ne_bytes());
        let mut asked = super::Structure::<32>::zeroed();
        asked[..4].copy_from_slice(&DEVICE_IMAGE_REQUIREMENTS.to_ne_bytes());
        asked[16..24].copy_from_slice(&(info.as_ptr() as u64).to_ne_bytes());
        // A disjoint image's first plane (`VK_IMAGE_ASPECT_PLANE_0_BIT`).
        let plane: u32 = if a.flags & DISJOINT != 0 { 0x10 } else { 0 };
        asked[24..28].copy_from_slice(&plane.to_ne_bytes());
        let mut got = super::Structure::<40>::zeroed();
        got[..4].copy_from_slice(&REQUIREMENTS2.to_ne_bytes());
        type Requirements = unsafe extern "C" fn(u64, *const u8, *mut u8);
        // SAFETY: the driver's `vkGetDeviceImageMemoryRequirements` for
        // fwe's device, with structures fwe made.
        unsafe {
            std::mem::transmute::<usize, Requirements>(self.requirements)(
                self.device,
                asked.as_ptr(),
                got.as_mut_ptr(),
            )
        };
        Some(u32::from_ne_bytes(got[32..36].try_into().expect("four bytes")))
    }
}

/// An image format query (`vkGetPhysicalDeviceImageFormatProperties`, its
/// `2` and `2KHR`): the driver's answer, made to agree with its memory
/// requirements for a usage with host transfer.
pub(super) fn query(driver: &Driver, index: usize, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let r = super::plain(driver, index, w)?;
    let helper = HELPERS.read().unwrap_or_else(|e| e.into_inner()).get(&w[0]).copied();
    answer(index, w, r, helper)
}

/// The answer to image format query `index` with words `w`, whose driver
/// answered `r`, by `helper`'s requirements.
fn answer(index: usize, w: &[u64; MOST_ARGS], r: u64, helper: Option<Helper>) -> Result<u64, i32> {
    if r as u32 as i32 != result::SUCCESS {
        return Ok(r);
    }
    let Some(usage) = usage_of(index, w).filter(|u| u & HOST_TRANSFER != 0) else { return Ok(r) };
    let a = asked(index, w);
    let measure = |usage: u32| helper.zip(a.as_ref()).and_then(|(h, a)| h.types(a, usage));
    let (with, without) = (measure(usage), measure(usage & !HOST_TRANSFER));
    // Where its `VkImageFormatProperties` are.
    let props =
        if index == cmd::vkGetPhysicalDeviceImageFormatProperties { w[6] } else { w[2] + 16 };
    match with {
        None | Some(0) => {
            // Unsupported: its properties zero, as Vulkan has them then.
            uaccess::write(props, [0u8; 32]).map_err(|_| fwe_abi::errno::EFAULT)?;
            Ok(result::ERROR_FORMAT_NOT_SUPPORTED as u32 as u64)
        }
        Some(types)
            if Some(types) != without && index != cmd::vkGetPhysicalDeviceImageFormatProperties =>
        {
            let mut at = uaccess::read::<u64>(w[2] + 8).unwrap_or(0);
            for _ in 0..256 {
                if at == 0 {
                    break;
                }
                if uaccess::read::<u32>(at).is_ok_and(|t| t == PERFORMANCE_QUERY) {
                    uaccess::write(at + 16, [0u32; 2]).map_err(|_| fwe_abi::errno::EFAULT)?;
                }
                at = uaccess::read::<u64>(at + 8).unwrap_or(0);
            }
            Ok(r)
        }
        Some(_) => Ok(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory requirements as MoltenVK gives them: a depth-stencil
    /// attachment (`0x20`) only the private type (bit 0), host transfer
    /// never that type.
    unsafe extern "C" fn moltenvk(_device: u64, asked: *const u8, got: *mut u8) {
        // SAFETY: the structures `Helper::types` made.
        unsafe {
            let info = *(asked.add(16) as *const *const u8);
            let usage = *(info.add(56) as *const u32);
            let mut types = if usage & 0x20 != 0 { 0b1 } else { 0b111 };
            if usage & HOST_TRANSFER != 0 {
                types &= !0b1;
            }
            *(got.add(32) as *mut u32) = types;
        }
    }

    fn helper() -> Helper {
        Helper { instance: 1, device: 2, requirements: moltenvk as *const () as usize, destroy: 0 }
    }

    /// A `vkGetPhysicalDeviceImageFormatProperties2` call: its info (format
    /// D32_SFLOAT, 2D, optimal) with `usage`, and properties chaining a
    /// performance query the driver filled with true.
    fn query2(usage: u32) -> ([u32; 10], [u64; 6], [u32; 6]) {
        let mut info = [0u32; 10];
        info[0] = 1_000_059_004;
        info[4] = 126;
        info[5] = 1;
        info[7] = usage;
        let mut perf = [0u32; 6];
        perf[0] = PERFORMANCE_QUERY;
        perf[4] = 1;
        perf[5] = 1;
        let mut props = [7u64; 6];
        props[0] = 1_000_059_003;
        (info, props, perf)
    }

    fn ask(usage: u32) -> (u64, [u64; 6], [u32; 6]) {
        let (info, mut props, mut perf) = query2(usage);
        props[1] = perf.as_mut_ptr() as u64;
        let w = words(&[3, info.as_ptr() as u64, props.as_mut_ptr() as u64]);
        let r = answer(cmd::vkGetPhysicalDeviceImageFormatProperties2, &w, 0, Some(helper()));
        (r.unwrap(), props, perf)
    }

    /// A depth-stencil attachment with host transfer, which would have no
    /// memory type, is unsupported, its properties zero; without host
    /// transfer it is the driver's answer.
    #[test]
    fn host_transfer_with_no_memory_type_is_unsupported() {
        let (r, props, _) = ask(0x20 | HOST_TRANSFER);
        assert_eq!(r as u32 as i32, result::ERROR_FORMAT_NOT_SUPPORTED);
        assert_eq!(props[2..], [0; 4]);
        let (r, props, perf) = ask(0x20);
        assert_eq!(r, 0);
        assert_eq!(props[2..], [7; 4]);
        assert_eq!(perf[4..], [1, 1]);
    }

    /// Host transfer that takes a memory type away is not free for the
    /// device: the performance query says so.
    #[test]
    fn host_transfer_that_moves_memory_is_not_optimal() {
        let (r, props, perf) = ask(0x4 | HOST_TRANSFER);
        assert_eq!(r, 0);
        assert_eq!(props[2..], [7; 4]);
        assert_eq!(perf[4..], [0, 0]);
    }

    /// Where fwe has no device to ask (none made, or none can be), host
    /// transfer is unsupported; a driver's error stays.
    #[test]
    fn host_transfer_without_a_helper_is_unsupported() {
        let (info, mut props, _) = query2(0x4 | HOST_TRANSFER);
        let w = words(&[3, info.as_ptr() as u64, props.as_mut_ptr() as u64]);
        let index = cmd::vkGetPhysicalDeviceImageFormatProperties2;
        let r = answer(index, &w, 0, None).unwrap();
        assert_eq!(r as u32 as i32, result::ERROR_FORMAT_NOT_SUPPORTED);
        let none = Helper { device: 0, ..helper() };
        assert_eq!(
            answer(index, &w, 0, Some(none)).unwrap() as u32 as i32,
            result::ERROR_FORMAT_NOT_SUPPORTED
        );
        let failed = (-11i32) as u32 as u64;
        assert_eq!(answer(index, &w, failed, Some(helper())).unwrap(), failed);
    }

    /// The first query: a usage with host transfer, through
    /// `vkGetPhysicalDeviceImageFormatProperties`' own arguments too.
    #[test]
    fn the_first_query_of_host_transfer_takes_the_lock() {
        let mut props = [7u8; 32];
        let w =
            words(&[9, 126, 1, 0, u64::from(0x20 | HOST_TRANSFER), 0, props.as_mut_ptr() as u64]);
        let record =
            [cmd::vkGetPhysicalDeviceImageFormatProperties as u64 | 7 << 32, w.as_ptr() as u64, 0];
        assert!(needs_lock(cmd::vkGetPhysicalDeviceImageFormatProperties, record.as_ptr() as u64));
        let r =
            answer(cmd::vkGetPhysicalDeviceImageFormatProperties, &w, 0, Some(helper())).unwrap();
        assert_eq!(r as u32 as i32, result::ERROR_FORMAT_NOT_SUPPORTED);
        assert_eq!(props, [0; 32]);
        let plain = words(&[9, 126, 1, 0, 0x20, 0, props.as_mut_ptr() as u64]);
        let record = [
            cmd::vkGetPhysicalDeviceImageFormatProperties as u64 | 7 << 32,
            plain.as_ptr() as u64,
            0,
        ];
        assert!(!needs_lock(cmd::vkGetPhysicalDeviceImageFormatProperties, record.as_ptr() as u64));
    }
}
