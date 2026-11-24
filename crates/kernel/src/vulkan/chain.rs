//! Copies of the guest's structures that fwe changes before the driver sees
//! them: an instance's or device's create info, and its `pNext` chain.
//!
//! A chain is copied a structure at a time, each of a structure type of the
//! versions and extensions fwe covers ([`super::generated::struct_size`]);
//! a structure of any other type is left out, as a driver ignores one it
//! does not know. That leaves out the loader's own (`VkLayer*CreateInfo`,
//! for its layers, not the driver) and every structure that would have the
//! driver call guest code (debug messengers' and reports' callbacks,
//! device memory reports, a list of drivers to load), whose extensions fwe
//! does not offer. The structures' own pointers still point at the guest's
//! memory, which is the process's.

use super::generated::struct_size;
use crate::uaccess;
use fwe_abi::errno;

/// The most structures a chain is followed through: a chain is the
/// guest's, and may loop.
const MOST: usize = 256;

/// Copies of structures, kept as long as the call that uses them.
#[derive(Default)]
pub struct Copies {
    nodes: Vec<Box<[u64]>>,
}

impl Copies {
    /// Copy guest structure `addr` of `size` bytes; its copy's address.
    pub fn structure(&mut self, addr: u64, size: usize) -> Result<*mut u8, i32> {
        let bytes = uaccess::read_bytes(addr, size).map_err(|_| errno::EFAULT)?;
        Ok(self.bytes(&bytes))
    }

    /// A copy of `bytes`, aligned for any structure; its address.
    pub fn bytes(&mut self, bytes: &[u8]) -> *mut u8 {
        let mut words = vec![0u64; bytes.len().div_ceil(8)].into_boxed_slice();
        // SAFETY: `words` holds at least `bytes.len()` bytes, and the two
        // do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len())
        };
        let p = words.as_mut_ptr().cast();
        self.nodes.push(words);
        p
    }

    /// A copy of the chain from guest address `first` on, keeping the
    /// structures `keep` allows of the types fwe knows; the copy's first
    /// structure's address (0 for none).
    pub fn chain(&mut self, first: u64, keep: impl Fn(u32) -> bool) -> Result<u64, i32> {
        let mut kept = Vec::new();
        let mut at = first;
        for _ in 0..MOST {
            if at == 0 {
                break;
            }
            let header: [u64; 2] = uaccess::read(at).map_err(|_| errno::EFAULT)?;
            let stype = header[0] as u32;
            if let Some(size) = struct_size(stype).filter(|_| keep(stype)) {
                kept.push(self.structure(at, size as usize)?);
            }
            at = header[1];
        }
        // Each copy's `pNext` is the next copy.
        let mut next = 0u64;
        for &node in kept.iter().rev() {
            // SAFETY: `node` is a copy of a structure, which has `pNext` at
            // offset 8.
            unsafe { node.add(8).cast::<u64>().write(next) };
            next = node as u64;
        }
        Ok(next)
    }

    /// A copy of a list of strings (as `ppEnabledExtensionNames`), with
    /// `extra` added; the list's address and length.
    pub fn names(&mut self, list: &[Vec<u8>], extra: &[&std::ffi::CStr]) -> (u64, u32) {
        let mut pointers: Vec<u64> = list
            .iter()
            .map(|n| {
                let mut z = n.clone();
                z.push(0);
                self.bytes(&z) as u64
            })
            .collect();
        pointers.extend(extra.iter().map(|e| e.as_ptr() as u64));
        let len = pointers.len() as u32;
        let bytes: Vec<u8> = pointers.iter().flat_map(|p| p.to_ne_bytes()).collect();
        (self.bytes(&bytes) as u64, len)
    }
}

/// Guest list of `count` strings at `addr` (as `ppEnabledExtensionNames`).
pub fn read_names(addr: u64, count: u32) -> Result<Vec<Vec<u8>>, i32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = count.min(4096) as usize;
    let pointers = uaccess::read_bytes(addr, count * 8).map_err(|_| errno::EFAULT)?;
    pointers
        .as_chunks::<8>()
        .0
        .iter()
        .map(|p| uaccess::read_cstr(u64::from_ne_bytes(*p), 256).map_err(|_| errno::EFAULT))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A structure's header and one member, as Vulkan lays them out.
    #[repr(C)]
    struct Node {
        stype: u32,
        next: u64,
        member: u64,
    }

    #[test]
    fn a_chain_is_copied_without_the_structures_fwe_leaves_out() {
        // VkPhysicalDeviceVulkan11Features (49), the loader's
        // VkLayerDeviceCreateInfo (48, not Vulkan's), a debug messenger's
        // create info (1000128004, its extension not offered), and
        // VkPhysicalDeviceVulkan12Features (51).
        let n4 = Node { stype: 51, next: 0, member: 4 };
        let n3 = Node { stype: 1_000_128_004, next: &n4 as *const Node as u64, member: 3 };
        let n2 = Node { stype: 48, next: &n3 as *const Node as u64, member: 2 };
        let n1 = Node { stype: 49, next: &n2 as *const Node as u64, member: 1 };
        let mut copies = Copies::default();
        let first = copies.chain(&n1 as *const Node as u64, |_| true).unwrap();
        // SAFETY: the copies live in `copies`; each begins with a header.
        let (a, b) = unsafe {
            let a = &*(first as *const Node);
            (a, &*(a.next as *const Node))
        };
        assert_eq!((a.stype, a.member), (49, 1));
        assert_eq!((b.stype, b.member, b.next), (51, 4, 0));
        assert_ne!(first, &n1 as *const Node as u64, "a copy, not the guest's own");
        // What `keep` refuses goes too.
        let first = copies.chain(&n1 as *const Node as u64, |t| t != 49).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { &*(first as *const Node) }.stype, 51);
    }

    #[test]
    fn fwe_knows_no_structure_that_calls_back() {
        for stype in [
            47,            // VkLayerInstanceCreateInfo (the loader's)
            48,            // VkLayerDeviceCreateInfo (the loader's)
            1_000_011_000, // VkDebugReportCallbackCreateInfoEXT
            1_000_128_004, // VkDebugUtilsMessengerCreateInfoEXT
            1_000_284_001, // VkDeviceDeviceMemoryReportCreateInfoEXT
            1_000_459_001, // VkDirectDriverLoadingListLUNARG
        ] {
            assert_eq!(struct_size(stype), None, "{stype}");
        }
    }

    #[test]
    fn a_looping_chain_ends() {
        let mut n = Node { stype: 49, next: 0, member: 0 };
        n.next = &n as *const Node as u64;
        let mut copies = Copies::default();
        assert_ne!(copies.chain(&n as *const Node as u64, |_| true).unwrap(), 0);
    }
}
