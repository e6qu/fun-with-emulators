//! Null descriptors where the driver has none (MoltenVK): robustness2's
//! `nullDescriptor`, which Mesa's Zink needs.
//!
//! - **The feature** is reported to the guest
//!   (`VkPhysicalDeviceRobustness2FeaturesKHR`), and taken out of the
//!   device's create info for the driver, where the driver lacks it
//!   ([`features`], [`device_wants`]).
//! - **Such a device** has stand-ins made with it ([`Dummies`]): a buffer,
//!   two texel buffer views (a uniform and a storage one) and a 1×1 2D
//!   image's view, their memory zeroed.
//! - **Where a program writes or binds a null handle** for a device of
//!   these (descriptor writes, update templates, push descriptors, vertex
//!   buffers), fwe passes the driver a copy with the stand-in in its place
//!   ([`call`]); calls with no null handle pass as they are. A null image
//!   reads as zeros of the stand-in's 2D view whatever the shader's image
//!   type, and a null buffer as zeros: what is written to a stand-in may be
//!   read back from it, where Linux's drivers would drop the writes.

use super::chain::Copies;
use super::driver::Driver;
use super::generated::{self, MOST_ARGS, cmd};
use super::{objects, result, words};
use crate::uaccess;
use fwe_abi::errno;
use std::collections::BTreeMap;

/// `VkPhysicalDeviceRobustness2FeaturesKHR` (the EXT's too): its structure
/// type, and `nullDescriptor`'s offset in it.
pub(super) const ROBUSTNESS2: u32 = 1_000_286_000;
const NULL_DESCRIPTOR: u64 = 24;
/// `VkPhysicalDeviceFeatures2`'s structure type.
const FEATURES2: u32 = 1_000_059_000;

/// `VK_WHOLE_SIZE`.
const WHOLE: u64 = !0;
/// How big the stand-in buffer is: a uniform buffer's largest range on
/// most drivers.
const BUFFER_SIZE: u64 = 65_536;

/// A device's stand-ins, and what holds them.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Dummies {
    pub buffer: u64,
    pub buffer_memory: u64,
    pub uniform_texel: u64,
    pub storage_texel: u64,
    pub image: u64,
    pub image_memory: u64,
    pub view: u64,
}

/// The devices with stand-ins, by handle. Held across a host fork
/// ([`crate::forklock`]).
pub(crate) static DEVICES: crate::forklock::ForkRwLock<BTreeMap<u64, Dummies>> =
    crate::forklock::ForkRwLock::new(BTreeMap::new());
/// The update templates of such devices: their device and entries.
pub(crate) static TEMPLATES: crate::forklock::ForkRwLock<BTreeMap<u64, (u64, Vec<Entry>)>> =
    crate::forklock::ForkRwLock::new(BTreeMap::new());

/// Some device has stand-ins.
static ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn dummies_of(device: u64) -> Option<Dummies> {
    DEVICES.read().unwrap_or_else(|e| e.into_inner()).get(&device).copied()
}

/// One entry of an update template (`VkDescriptorUpdateTemplateEntry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    kind: u32,
    count: u32,
    offset: u64,
    stride: u64,
}

/// What a descriptor of type `kind` is in memory: its element's size and
/// kind, and where a `VkWriteDescriptorSet` points at its elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Element {
    /// `VkDescriptorImageInfo`, its view at 8.
    Image,
    /// `VkDescriptorBufferInfo`: buffer, offset, range.
    Buffer,
    /// A `VkBufferView`: a uniform (false) or storage (true) one.
    Texel(bool),
}

/// The element of descriptor type `kind`, its size, and the offset of its
/// array in a `VkWriteDescriptorSet`; none for kinds with no null handle
/// to stand in for.
fn element(kind: u32) -> Option<(Element, u64, u64)> {
    Some(match kind {
        // Combined image sampler, sampled image, storage image, input
        // attachment.
        1 | 2 | 3 | 10 => (Element::Image, 24, 40),
        4 => (Element::Texel(false), 8, 56),
        5 => (Element::Texel(true), 8, 56),
        // Uniform and storage buffers, dynamic or not.
        6..=9 => (Element::Buffer, 24, 48),
        _ => return None,
    })
}

/// The bytes a template entry of type `kind` takes from its data: an inline
/// uniform block's `count` bytes, or one element per descriptor.
fn entry_bytes(e: &Entry) -> u64 {
    match e.kind {
        // Inline uniform block: its bytes.
        1_000_138_000 => u64::from(e.count),
        _ => {
            let size = element(e.kind).map_or(8, |(_, s, _)| s);
            if e.count == 0 { 0 } else { (u64::from(e.count) - 1) * e.stride + size }
        }
    }
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}

fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// Put the stand-in in place of a null handle in element `item` of kind
/// `el`: whether there was one.
fn patch(d: &Dummies, el: Element, item: &mut [u8]) -> bool {
    match el {
        Element::Image if get_u64(item, 8) == 0 => put_u64(item, 8, d.view),
        Element::Buffer if get_u64(item, 0) == 0 => {
            put_u64(item, 0, d.buffer);
            put_u64(item, 8, 0);
            put_u64(item, 16, WHOLE);
        }
        Element::Texel(storage) if get_u64(item, 0) == 0 => {
            put_u64(item, 0, if storage { d.storage_texel } else { d.uniform_texel })
        }
        _ => return false,
    }
    true
}

/// `count` `VkWriteDescriptorSet`s at guest address `at` with stand-ins for
/// their null handles: the copy's address, kept in `copies`, or none if
/// they have none.
fn fix_writes(d: &Dummies, count: u64, at: u64, copies: &mut Copies) -> Result<Option<u64>, i32> {
    const WRITE: usize = 64;
    if count == 0 || at == 0 {
        return Ok(None);
    }
    let count = usize::try_from(count.min(1 << 16)).expect("small");
    let mut writes = uaccess::read_bytes(at, count * WRITE).map_err(|_| errno::EFAULT)?;
    let mut any = false;
    for w in writes.as_chunks_mut::<WRITE>().0 {
        let (n, kind) = (u64::from(get_u32(w, 32)), get_u32(w, 36));
        let Some((el, size, field)) = element(kind) else { continue };
        let array = get_u64(w, field as usize);
        if n == 0 || array == 0 {
            continue;
        }
        let mut items = uaccess::read_bytes(array, (n.min(1 << 16) * size) as usize)
            .map_err(|_| errno::EFAULT)?;
        let mut patched = false;
        for item in items.chunks_exact_mut(size as usize) {
            patched |= patch(d, el, item);
        }
        if patched {
            put_u64(w, field as usize, copies.bytes(&items) as u64);
            any = true;
        }
    }
    Ok(any.then(|| copies.bytes(&writes) as u64))
}

/// A template's data at guest address `data` with stand-ins for its null
/// handles: the copy's address, or none if it has none.
fn fix_template(
    d: &Dummies,
    entries: &[Entry],
    data: u64,
    copies: &mut Copies,
) -> Result<Option<u64>, i32> {
    if data == 0 {
        return Ok(None);
    }
    let extent = entries.iter().map(|e| e.offset + entry_bytes(e)).max().unwrap_or(0);
    if extent == 0 {
        return Ok(None);
    }
    let mut bytes =
        uaccess::read_bytes(data, extent.min(1 << 24) as usize).map_err(|_| errno::EFAULT)?;
    let mut any = false;
    for e in entries {
        let Some((el, size, _)) = element(e.kind) else { continue };
        for i in 0..u64::from(e.count) {
            let at = (e.offset + i * e.stride) as usize;
            if let Some(item) = bytes.get_mut(at..at + size as usize) {
                any |= patch(d, el, item);
            }
        }
    }
    Ok(any.then(|| copies.bytes(&bytes) as u64))
}

/// Vertex buffers `count` at `buffers`, with their offsets and sizes (0:
/// none given), with the stand-in for each null one (offset 0, the whole
/// buffer): the copies' addresses, or none if there is no null one.
fn fix_vertex(
    d: &Dummies,
    count: u64,
    buffers: u64,
    offsets: u64,
    sizes: u64,
    copies: &mut Copies,
) -> Result<Option<[u64; 3]>, i32> {
    if count == 0 || buffers == 0 {
        return Ok(None);
    }
    let n = count.min(1 << 16) as usize * 8;
    let read = |at: u64| -> Result<Option<Vec<u8>>, i32> {
        if at == 0 {
            return Ok(None);
        }
        uaccess::read_bytes(at, n).map(Some).map_err(|_| errno::EFAULT)
    };
    let mut b = read(buffers)?.expect("buffers given");
    let (mut o, mut s) = (read(offsets)?, read(sizes)?);
    let mut any = false;
    for i in 0..n / 8 {
        if get_u64(&b, i * 8) == 0 {
            put_u64(&mut b, i * 8, d.buffer);
            if let Some(o) = o.as_mut() {
                put_u64(o, i * 8, 0);
            }
            if let Some(s) = s.as_mut() {
                put_u64(s, i * 8, WHOLE);
            }
            any = true;
        }
    }
    if !any {
        return Ok(None);
    }
    let mut copy = |v: Option<Vec<u8>>| v.map_or(0, |v| copies.bytes(&v) as u64);
    Ok(Some([copy(Some(b)), copy(o), copy(s)]))
}

/// The device of the object `handle` a command is called on: a device's
/// own, a command buffer's (from its pool).
fn device_of(index: usize, handle: u64) -> u64 {
    match generated::NAMES[index].starts_with("vkCmd") {
        true => objects::grandparent(handle),
        false => handle,
    }
}

/// The commands of null handles ([`generated::SPECIAL`]): with stand-ins
/// where the device has them, as they are otherwise.
pub(super) fn call(driver: &Driver, index: usize, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    if !ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return super::plain(driver, index, w);
    }
    let device = device_of(index, w[0]);
    let Some(d) = dummies_of(device) else { return super::plain(driver, index, w) };
    let mut copies = Copies::default();
    let mut w2 = *w;
    match index {
        cmd::vkUpdateDescriptorSets => {
            if let Some(p) = fix_writes(&d, u64::from(w[1] as u32), w[2], &mut copies)? {
                w2[2] = p;
            }
        }
        cmd::vkCmdPushDescriptorSet => {
            if let Some(p) = fix_writes(&d, u64::from(w[4] as u32), w[5], &mut copies)? {
                w2[5] = p;
            }
        }
        cmd::vkCmdPushDescriptorSet2 => {
            // VkPushDescriptorSetInfo: the writes' count at 36, the writes
            // at 40; 48 bytes.
            let mut info = uaccess::read_bytes(w[1], 48).map_err(|_| errno::EFAULT)?;
            let (n, at) = (u64::from(get_u32(&info, 36)), get_u64(&info, 40));
            if let Some(p) = fix_writes(&d, n, at, &mut copies)? {
                put_u64(&mut info, 40, p);
                w2[1] = copies.bytes(&info) as u64;
            }
        }
        cmd::vkUpdateDescriptorSetWithTemplate | cmd::vkCmdPushDescriptorSetWithTemplate => {
            let (template, data) =
                if index == cmd::vkUpdateDescriptorSetWithTemplate { (w[2], 3) } else { (w[1], 4) };
            if let Some(entries) = entries_of(template)
                && let Some(p) = fix_template(&d, &entries, w[data], &mut copies)?
            {
                w2[data] = p;
            }
        }
        cmd::vkCmdPushDescriptorSetWithTemplate2 => {
            // VkPushDescriptorSetWithTemplateInfo: the template at 16, the
            // data at 40; 48 bytes.
            let mut info = uaccess::read_bytes(w[1], 48).map_err(|_| errno::EFAULT)?;
            if let Some(entries) = entries_of(get_u64(&info, 16))
                && let Some(p) = fix_template(&d, &entries, get_u64(&info, 40), &mut copies)?
            {
                put_u64(&mut info, 40, p);
                w2[1] = copies.bytes(&info) as u64;
            }
        }
        cmd::vkCmdBindVertexBuffers => {
            if let Some([b, o, _]) = fix_vertex(&d, w[2], w[3], w[4], 0, &mut copies)? {
                (w2[3], w2[4]) = (b, o);
            }
        }
        cmd::vkCmdBindVertexBuffers2 => {
            if let Some([b, o, s]) = fix_vertex(&d, w[2], w[3], w[4], w[5], &mut copies)? {
                (w2[3], w2[4], w2[5]) = (b, o, s);
            }
        }
        cmd::vkCreateDescriptorUpdateTemplate => {
            let r = super::plain(driver, index, w)?;
            if r as u32 as i32 == result::SUCCESS
                && let Ok(template) = uaccess::read::<u64>(w[3])
            {
                let entries = read_entries(w[1])?;
                TEMPLATES
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(template, (device, entries));
            }
            return Ok(r);
        }
        cmd::vkDestroyDescriptorUpdateTemplate => {
            TEMPLATES.write().unwrap_or_else(|e| e.into_inner()).remove(&w[1]);
        }
        _ => {}
    }
    super::plain(driver, index, &w2)
}

fn entries_of(template: u64) -> Option<Vec<Entry>> {
    TEMPLATES.read().unwrap_or_else(|e| e.into_inner()).get(&template).map(|(_, e)| e.clone())
}

/// The entries of the guest's `VkDescriptorUpdateTemplateCreateInfo` at
/// `info`: their count at 20, their array at 24, each 32 bytes (type at
/// 12, offset at 16, stride at 24).
fn read_entries(info: u64) -> Result<Vec<Entry>, i32> {
    let head = uaccess::read_bytes(info, 32).map_err(|_| errno::EFAULT)?;
    let (n, at) = (u64::from(get_u32(&head, 20)).min(1 << 16), get_u64(&head, 24));
    if n == 0 || at == 0 {
        return Ok(Vec::new());
    }
    let bytes = uaccess::read_bytes(at, (n * 32) as usize).map_err(|_| errno::EFAULT)?;
    Ok(bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|e| Entry {
            count: get_u32(e, 8),
            kind: get_u32(e, 12),
            offset: get_u64(e, 16),
            stride: get_u64(e, 24),
        })
        .collect())
}

/// After `vkGetPhysicalDeviceFeatures2(pd, features)` filled the guest's
/// chain: where the driver has no null descriptors, the guest is told it
/// has them.
pub(super) fn features(driver: &Driver, pd: u64, features: u64) {
    if native(driver, pd) {
        return;
    }
    let mut at = uaccess::read::<u64>(features + 8).unwrap_or(0);
    for _ in 0..256 {
        if at == 0 {
            return;
        }
        if uaccess::read::<u32>(at) == Ok(ROBUSTNESS2) {
            let _ = uaccess::write(at + NULL_DESCRIPTOR, 1u32);
            return;
        }
        at = uaccess::read::<u64>(at + 8).unwrap_or(0);
    }
}

/// Whether the driver has null descriptors for physical device `pd`.
fn native(driver: &Driver, pd: u64) -> bool {
    let Some(f) = objects::function(driver, cmd::vkGetPhysicalDeviceFeatures2, pd) else {
        return false;
    };
    let mut rb2 = [0u64; 4];
    rb2[0] = u64::from(ROBUSTNESS2);
    let mut f2 = [0u64; 30];
    f2[0] = u64::from(FEATURES2);
    f2[1] = rb2.as_mut_ptr() as u64;
    // SAFETY: the driver's function for `pd`, given a features structure
    // and a robustness2 one of fwe's, chained.
    unsafe {
        generated::call(cmd::vkGetPhysicalDeviceFeatures2, f, &words(&[pd, f2.as_mut_ptr() as u64]))
    };
    (rb2[3] & 0xffff_ffff) != 0
}

/// Whether the device create info `chain` (fwe's copy of the guest's)
/// asks for null descriptors the driver for `pd` lacks: if so, the
/// request is taken out of the copy, and the device is to have stand-ins
/// ([`start`]).
pub(super) fn device_wants(driver: &Driver, pd: u64, chain: u64) -> bool {
    let mut at = chain;
    for _ in 0..256 {
        if at == 0 {
            return false;
        }
        // SAFETY: `at` is a structure of fwe's copy of the chain, each of
        // them at least a header and as long as its type's structure.
        unsafe {
            let p = at as *mut u8;
            if p.cast::<u32>().read() == ROBUSTNESS2 {
                let null = p.add(NULL_DESCRIPTOR as usize).cast::<u32>();
                if null.read() == 0 || native(driver, pd) {
                    return false;
                }
                null.write(0);
                return true;
            }
            at = p.add(8).cast::<u64>().read();
        }
    }
    false
}

/// A call of the device's function `index` with `args`.
fn device_call(driver: &Driver, device: u64, index: usize, args: &[u64]) -> Result<u64, i32> {
    let f = objects::function(driver, index, device).ok_or(errno::EINVAL)?;
    // SAFETY: the driver's function for the device, with arguments of
    // fwe's own built for it.
    Ok(unsafe { generated::call(index, f, &words(args)) })
}

fn vk_ok(r: u64) -> Result<(), i32> {
    if r as u32 as i32 == result::SUCCESS { Ok(()) } else { Err(errno::ENOMEM) }
}

#[repr(C)]
struct BufferInfo {
    s_type: u32,
    next: u64,
    flags: u32,
    size: u64,
    usage: u32,
    sharing: u32,
    families: u32,
    family_list: u64,
}

#[repr(C)]
struct AllocateInfo {
    s_type: u32,
    next: u64,
    size: u64,
    type_index: u32,
}

#[repr(C)]
struct BufferViewInfo {
    s_type: u32,
    next: u64,
    flags: u32,
    buffer: u64,
    format: u32,
    offset: u64,
    range: u64,
}

#[repr(C)]
struct ImageInfo {
    s_type: u32,
    next: u64,
    flags: u32,
    image_type: u32,
    format: u32,
    extent: [u32; 3],
    mips: u32,
    layers: u32,
    samples: u32,
    tiling: u32,
    usage: u32,
    sharing: u32,
    families: u32,
    family_list: u64,
    initial_layout: u32,
}

#[repr(C)]
struct ImageViewInfo {
    s_type: u32,
    next: u64,
    flags: u32,
    image: u64,
    view_type: u32,
    format: u32,
    components: [u32; 4],
    range: [u32; 5],
}

#[repr(C)]
#[derive(Default)]
struct Requirements {
    size: u64,
    alignment: u64,
    type_bits: u32,
}

#[repr(C)]
struct MemoryProperties {
    type_count: u32,
    types: [[u32; 2]; 32],
    heap_count: u32,
    heaps: [[u64; 2]; 16],
}

/// Sizes as Vulkan's headers have them, checked against vk.xml's.
#[cfg(test)]
pub(super) const LAYOUTS: [(u32, usize); 5] = [
    (12, std::mem::size_of::<BufferInfo>()),
    (5, std::mem::size_of::<AllocateInfo>()),
    (13, std::mem::size_of::<BufferViewInfo>()),
    (14, std::mem::size_of::<ImageInfo>()),
    (15, std::mem::size_of::<ImageViewInfo>()),
];
const _: () = assert!(std::mem::size_of::<MemoryProperties>() == 520);

/// `VK_FORMAT_R8G8B8A8_UNORM`, `VK_FORMAT_R32_UINT`.
const RGBA8: u32 = 37;
const R32_UINT: u32 = 98;

/// Memory of `bits` the process can write (to zero it): host-visible and
/// coherent.
fn host_memory(driver: &Driver, pd: u64, bits: u32) -> Result<u32, i32> {
    let f = objects::function(driver, cmd::vkGetPhysicalDeviceMemoryProperties, pd)
        .ok_or(errno::EINVAL)?;
    // SAFETY: zeroed bytes are a valid `MemoryProperties`.
    let mut props: MemoryProperties = unsafe { std::mem::zeroed() };
    // SAFETY: the driver's function for `pd`, with an out-parameter of
    // fwe's of its structure's layout.
    unsafe {
        generated::call(
            cmd::vkGetPhysicalDeviceMemoryProperties,
            f,
            &words(&[pd, &mut props as *mut MemoryProperties as u64]),
        )
    };
    const WANT: u32 = 0x2 | 0x4; // host-visible, host-coherent
    (0..props.type_count.min(32))
        .find(|&i| bits >> i & 1 == 1 && props.types[i as usize][0] & WANT == WANT)
        .ok_or(errno::ENOMEM)
}

/// Allocate memory for `req`, zeroed: its handle.
fn zeroed_memory(driver: &Driver, device: u64, pd: u64, req: &Requirements) -> Result<u64, i32> {
    let info = AllocateInfo {
        s_type: 5,
        next: 0,
        size: req.size,
        type_index: host_memory(driver, pd, req.type_bits)?,
    };
    let mut memory = 0u64;
    vk_ok(device_call(
        driver,
        device,
        cmd::vkAllocateMemory,
        &[device, &info as *const AllocateInfo as u64, 0, &mut memory as *mut u64 as u64],
    )?)?;
    let mut at = 0u64;
    let mapped = device_call(
        driver,
        device,
        cmd::vkMapMemory,
        &[device, memory, 0, WHOLE, 0, &mut at as *mut u64 as u64],
    )
    .and_then(vk_ok);
    if mapped.is_err() || at == 0 {
        let _ = device_call(driver, device, cmd::vkFreeMemory, &[device, memory, 0]);
        return Err(errno::ENOMEM);
    }
    // SAFETY: the driver mapped `req.size` bytes of the memory at `at`.
    unsafe { std::ptr::write_bytes(at as *mut u8, 0, req.size as usize) };
    let _ = device_call(driver, device, cmd::vkUnmapMemory, &[device, memory]);
    Ok(memory)
}

/// Make the stand-ins for `device` (of physical device `pd`): every one,
/// or none.
pub(super) fn start(driver: &Driver, device: u64, pd: u64) -> Result<(), i32> {
    let mut d = Dummies::default();
    let made = make(driver, device, pd, &mut d);
    if made.is_err() {
        destroy(driver, device, &d);
        return made;
    }
    DEVICES.write().unwrap_or_else(|e| e.into_inner()).insert(device, d);
    ANY.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

fn make(driver: &Driver, device: u64, pd: u64, d: &mut Dummies) -> Result<(), i32> {
    let out = |h: &mut u64| h as *mut u64 as u64;
    // The buffer: every use a null buffer or texel buffer may stand for.
    let info = BufferInfo {
        s_type: 12,
        next: 0,
        flags: 0,
        size: BUFFER_SIZE,
        usage: 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100,
        sharing: 0,
        families: 0,
        family_list: 0,
    };
    vk_ok(device_call(
        driver,
        device,
        cmd::vkCreateBuffer,
        &[device, &info as *const BufferInfo as u64, 0, out(&mut d.buffer)],
    )?)?;
    let mut req = Requirements::default();
    device_call(
        driver,
        device,
        cmd::vkGetBufferMemoryRequirements,
        &[device, d.buffer, &mut req as *mut Requirements as u64],
    )?;
    d.buffer_memory = zeroed_memory(driver, device, pd, &req)?;
    vk_ok(device_call(
        driver,
        device,
        cmd::vkBindBufferMemory,
        &[device, d.buffer, d.buffer_memory, 0],
    )?)?;
    for (format, view) in [(RGBA8, &mut d.uniform_texel), (R32_UINT, &mut d.storage_texel)] {
        let info = BufferViewInfo {
            s_type: 13,
            next: 0,
            flags: 0,
            buffer: d.buffer,
            format,
            offset: 0,
            range: WHOLE,
        };
        vk_ok(device_call(
            driver,
            device,
            cmd::vkCreateBufferView,
            &[device, &info as *const BufferViewInfo as u64, 0, out(view)],
        )?)?;
    }
    // The image: 1×1, linear, so its memory, zeroed, is its texel; sampled,
    // and a storage image where the driver can make one linear.
    let f = objects::function(driver, cmd::vkGetPhysicalDeviceFormatProperties, pd)
        .ok_or(errno::EINVAL)?;
    let mut props = [0u32; 3];
    // SAFETY: the driver's function for `pd`, with a `VkFormatProperties`
    // out-parameter of fwe's.
    unsafe {
        generated::call(
            cmd::vkGetPhysicalDeviceFormatProperties,
            f,
            &words(&[pd, u64::from(RGBA8), props.as_mut_ptr() as u64]),
        )
    };
    let linear = props[0];
    if linear & 0x1 == 0 {
        return Err(errno::ENODEV);
    }
    let usage = 0x4 | if linear & 0x2 != 0 { 0x8 } else { 0 };
    let info = ImageInfo {
        s_type: 14,
        next: 0,
        flags: 0,
        image_type: 1,
        format: RGBA8,
        extent: [1, 1, 1],
        mips: 1,
        layers: 1,
        samples: 1,
        tiling: 1,
        usage,
        sharing: 0,
        families: 0,
        family_list: 0,
        initial_layout: 8, // preinitialized: its memory is its content
    };
    vk_ok(device_call(
        driver,
        device,
        cmd::vkCreateImage,
        &[device, &info as *const ImageInfo as u64, 0, out(&mut d.image)],
    )?)?;
    let mut req = Requirements::default();
    device_call(
        driver,
        device,
        cmd::vkGetImageMemoryRequirements,
        &[device, d.image, &mut req as *mut Requirements as u64],
    )?;
    d.image_memory = zeroed_memory(driver, device, pd, &req)?;
    vk_ok(device_call(
        driver,
        device,
        cmd::vkBindImageMemory,
        &[device, d.image, d.image_memory, 0],
    )?)?;
    let info = ImageViewInfo {
        s_type: 15,
        next: 0,
        flags: 0,
        image: d.image,
        view_type: 1,
        format: RGBA8,
        components: [0; 4],
        range: [1, 0, 1, 0, 1],
    };
    vk_ok(device_call(
        driver,
        device,
        cmd::vkCreateImageView,
        &[device, &info as *const ImageViewInfo as u64, 0, out(&mut d.view)],
    )?)
}

fn destroy(driver: &Driver, device: u64, d: &Dummies) {
    let calls = [
        (cmd::vkDestroyImageView, d.view),
        (cmd::vkDestroyImage, d.image),
        (cmd::vkFreeMemory, d.image_memory),
        (cmd::vkDestroyBufferView, d.uniform_texel),
        (cmd::vkDestroyBufferView, d.storage_texel),
        (cmd::vkDestroyBuffer, d.buffer),
        (cmd::vkFreeMemory, d.buffer_memory),
    ];
    for (index, handle) in calls {
        if handle != 0 {
            let _ = device_call(driver, device, index, &[device, handle, 0]);
        }
    }
}

/// Before `device` is destroyed: its stand-ins, and its templates' records,
/// go.
pub(super) fn stop(driver: &Driver, device: u64) {
    let d = DEVICES.write().unwrap_or_else(|e| e.into_inner()).remove(&device);
    if let Some(d) = d {
        destroy(driver, device, &d);
        TEMPLATES.write().unwrap_or_else(|e| e.into_inner()).retain(|_, (dev, _)| *dev != device);
    }
}

#[cfg(test)]
pub(super) fn fix_writes_for_test(d: &Dummies, count: u64, at: u64) -> Option<Vec<u8>> {
    // Kept for the test to read the arrays the copy points at.
    let copies = Box::leak(Box::new(Copies::default()));
    let p = fix_writes(d, count, at, copies).unwrap()?;
    Some(uaccess::read_bytes(p, count as usize * 64).unwrap())
}

#[cfg(test)]
pub(super) fn fix_template_for_test(
    d: &Dummies,
    entries: &[(u32, u32, u64, u64)],
    data: u64,
) -> Option<Vec<u8>> {
    let entries: Vec<Entry> = entries
        .iter()
        .map(|&(kind, count, offset, stride)| Entry { kind, count, offset, stride })
        .collect();
    let extent = entries.iter().map(|e| e.offset + entry_bytes(e)).max().unwrap_or(0);
    let mut copies = Copies::default();
    let p = fix_template(d, &entries, data, &mut copies).unwrap()?;
    Some(uaccess::read_bytes(p, extent as usize).unwrap())
}
