//! The driver's dispatchable objects (instances, physical devices, devices,
//! queues, command buffers) and the functions each calls: an instance's
//! are those `vk_icdGetInstanceProcAddr` gives for it, a device's those
//! its `vkGetDeviceProcAddr` gives, as a loader keeps them. An object is
//! known from the call that made it or gave it out to the call that
//! destroyed or freed it.

use super::chain::{self, Copies};
use super::driver::Driver;
use super::generated::{self, COMMANDS, LEVELS, MOST_ARGS, NAMES, cmd};
use super::{Function, Level, result, words};
use crate::uaccess;
use fwe_abi::errno;
use std::collections::BTreeMap;
use std::ffi::{CString, c_void};
use std::sync::{Arc, OnceLock};

/// An object's functions, by command index (0 where it has none).
pub struct Table(Box<[usize]>);

impl Table {
    fn get(&self, index: usize) -> Option<Function> {
        let f = self.0[index];
        (f != 0).then_some(f as Function)
    }
}

/// An object, with what made it: the object it is of (an instance's
/// physical device, a device's queue, a command pool's command buffer), and
/// that one's.
pub(crate) struct Entry {
    table: Arc<Table>,
    parent: u64,
    grandparent: u64,
    /// A queue's family.
    family: u32,
}

/// Every object, by handle. Held across a host fork ([`crate::forklock`]).
pub(crate) static OBJECTS: crate::forklock::ForkRwLock<BTreeMap<u64, Entry>> =
    crate::forklock::ForkRwLock::new(BTreeMap::new());
static GLOBAL: OnceLock<Table> = OnceLock::new();

fn objects() -> std::sync::RwLockReadGuard<'static, BTreeMap<u64, Entry>> {
    OBJECTS.read().unwrap_or_else(|e| e.into_inner())
}

fn objects_mut() -> std::sync::RwLockWriteGuard<'static, BTreeMap<u64, Entry>> {
    OBJECTS.write().unwrap_or_else(|e| e.into_inner())
}

/// The driver's function `name` for `instance` (NULL: a global command).
fn proc_addr(driver: &Driver, instance: u64, name: &str) -> usize {
    let name = CString::new(name).expect("a command's name");
    // SAFETY: the driver's `vk_icdGetInstanceProcAddr`, with an instance of
    // the driver's (or NULL) and a NUL-terminated name.
    unsafe { (driver.get_instance_proc_addr)(instance as *mut c_void, name.as_ptr()) as usize }
}

/// The driver's function for global command `index`.
pub fn global(driver: &Driver, index: usize) -> Option<Function> {
    GLOBAL
        .get_or_init(|| {
            Table(
                (0..COMMANDS)
                    .map(|i| {
                        if LEVELS[i] == Level::Global { proc_addr(driver, 0, NAMES[i]) } else { 0 }
                    })
                    .collect(),
            )
        })
        .get(index)
}

/// The driver's function for command `index` called on object `first` (its
/// first argument).
pub fn function(driver: &Driver, index: usize, first: u64) -> Option<Function> {
    if LEVELS[index] == Level::Global {
        return global(driver, index);
    }
    objects().get(&first)?.table.get(index)
}

/// Whether object `handle` (0: none, for a global command) has command
/// `index`: what `vkGet*ProcAddr` answers with the guest library's stub
/// or NULL.
pub fn has(driver: &Driver, handle: u64, index: u64) -> bool {
    let Ok(index) = usize::try_from(index) else { return false };
    if index >= COMMANDS {
        return false;
    }
    if handle == 0 {
        return LEVELS[index] == Level::Global && global(driver, index).is_some();
    }
    function(driver, index, handle).is_some()
}

/// Instance `instance`'s functions.
fn instance_table(driver: &Driver, instance: u64) -> Table {
    Table(
        (0..COMMANDS)
            .map(|i| match LEVELS[i] {
                Level::Global => 0,
                _ => proc_addr(driver, instance, NAMES[i]),
            })
            .collect(),
    )
}

type GetDeviceProcAddr = unsafe extern "C" fn(*mut c_void, *const std::ffi::c_char) -> usize;

/// Device `device`'s functions: its instance's, with the device's own for
/// device commands.
fn device_table(driver: &Driver, instance: u64, device: u64, of_instance: &Table) -> Table {
    let gdpa = proc_addr(driver, instance, "vkGetDeviceProcAddr");
    let mut fns = of_instance.0.clone();
    if gdpa != 0 {
        // SAFETY: the driver's `vkGetDeviceProcAddr`, by its name.
        let gdpa: GetDeviceProcAddr = unsafe { std::mem::transmute(gdpa) };
        for (i, f) in fns.iter_mut().enumerate() {
            if LEVELS[i] == Level::Device {
                let name = CString::new(NAMES[i]).expect("a command's name");
                // SAFETY: a device of the driver's, and a NUL-terminated name.
                *f = unsafe { gdpa(device as *mut c_void, name.as_ptr()) };
            }
        }
    }
    Table(fns)
}

fn add(handle: u64, table: Arc<Table>, parent: u64, grandparent: u64) {
    add_with_family(handle, table, parent, grandparent, 0);
}

fn add_with_family(handle: u64, table: Arc<Table>, parent: u64, grandparent: u64, family: u32) {
    if handle != 0 {
        objects_mut().insert(handle, Entry { table, parent, grandparent, family });
    }
}

/// The object `handle` is of: a physical device's instance, a device's
/// physical device, a queue's device, a command buffer's pool (0 if none,
/// or unknown).
pub fn parent(handle: u64) -> u64 {
    objects().get(&handle).map_or(0, |e| e.parent)
}

/// The object `handle`'s parent is of: a queue's physical device, a command
/// buffer's device (0 if none, or unknown).
pub fn grandparent(handle: u64) -> u64 {
    objects().get(&handle).map_or(0, |e| e.grandparent)
}

/// The family of queue `handle` (0 if it is not a queue known).
pub fn queue_family(handle: u64) -> u32 {
    objects().get(&handle).map_or(0, |e| e.family)
}

/// `handle` is gone, and the objects of it.
fn remove(handle: u64) {
    objects_mut().retain(|&h, e| h != handle && e.parent != handle && e.grandparent != handle);
}

fn table_of(handle: u64) -> Option<(Arc<Table>, u64)> {
    objects().get(&handle).map(|e| (e.table.clone(), e.parent))
}

/// After plain command `index` with words `w` returned `r`: the objects it
/// gave out are known, and those it destroyed are not.
pub fn after(_driver: &Driver, index: usize, w: &[u64; MOST_ARGS], r: u64) {
    let ok = r as u32 as i32;
    match index {
        cmd::vkEnumeratePhysicalDevices if w[2] != 0 && (ok == 0 || ok == result::INCOMPLETE) => {
            let Some((table, _)) = table_of(w[0]) else { return };
            let count = uaccess::read::<u32>(w[1]).unwrap_or(0).min(4096);
            for i in 0..u64::from(count) {
                add(uaccess::read::<u64>(w[2] + i * 8).unwrap_or(0), table.clone(), w[0], 0);
            }
        }
        cmd::vkEnumeratePhysicalDeviceGroups | cmd::vkEnumeratePhysicalDeviceGroupsKHR
            if w[2] != 0 && (ok == 0 || ok == result::INCOMPLETE) =>
        {
            // VkPhysicalDeviceGroupProperties: the count at 16, up to 32
            // devices from 24; 288 bytes.
            let Some((table, _)) = table_of(w[0]) else { return };
            let groups = uaccess::read::<u32>(w[1]).unwrap_or(0).min(4096);
            for g in 0..u64::from(groups) {
                let at = w[2] + g * 288;
                let n = uaccess::read::<u32>(at + 16).unwrap_or(0).min(32);
                for i in 0..u64::from(n) {
                    add(uaccess::read::<u64>(at + 24 + i * 8).unwrap_or(0), table.clone(), w[0], 0);
                }
            }
        }
        cmd::vkGetDeviceQueue | cmd::vkGetDeviceQueue2 => {
            // vkGetDeviceQueue's family is its second argument;
            // VkDeviceQueueInfo2's at 20.
            let (out, family) = if index == cmd::vkGetDeviceQueue {
                (w[3], w[1] as u32)
            } else {
                (w[2], uaccess::read::<u32>(w[1] + 20).unwrap_or(0))
            };
            let Some((table, pd)) = table_of(w[0]) else { return };
            add_with_family(uaccess::read::<u64>(out).unwrap_or(0), table, w[0], pd, family);
        }
        cmd::vkAllocateCommandBuffers if ok == 0 => {
            // VkCommandBufferAllocateInfo: the pool at 16, the count at 28.
            let Some((table, _)) = table_of(w[0]) else { return };
            let pool = uaccess::read::<u64>(w[1] + 16).unwrap_or(0);
            let count = uaccess::read::<u32>(w[1] + 28).unwrap_or(0);
            for i in 0..u64::from(count) {
                add(uaccess::read::<u64>(w[2] + i * 8).unwrap_or(0), table.clone(), pool, w[0]);
            }
        }
        cmd::vkFreeCommandBuffers => {
            let mut objects = objects_mut();
            for i in 0..w[2].min(1 << 20) {
                if let Ok(cb) = uaccess::read::<u64>(w[3] + i * 8) {
                    objects.remove(&cb);
                }
            }
        }
        cmd::vkDestroyCommandPool | cmd::vkDestroyDevice | cmd::vkDestroyInstance => {
            let handle = if index == cmd::vkDestroyCommandPool { w[1] } else { w[0] };
            if handle != 0 {
                remove(handle);
            }
        }
        _ => {}
    }
}

/// `VkInstanceCreateInfo`'s fields fwe changes, by offset: flags (16),
/// layers (32, 40), extensions (48, 56); 64 bytes.
pub(super) const INSTANCE_INFO: usize = 64;
/// `VkDeviceCreateInfo`'s likewise: layers (32, 40), extensions (48, 56);
/// 72 bytes.
pub(super) const DEVICE_INFO: usize = 72;
/// `VkInstanceCreateFlags`' `VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR`.
const ENUMERATE_PORTABILITY: u32 = 1;

fn field<T: Copy>(info: *mut u8, offset: usize) -> *mut T {
    // SAFETY: callers name a field inside the copy's bytes.
    unsafe { info.add(offset).cast() }
}

/// The driver is MoltenVK on the paravirtual GPU of Apple's virtual
/// machines (as GitHub's macOS runners have), which needs [`no_heaps`]:
/// learnt from the first instance made.
static MOLTENVK_PARAVIRTUAL: OnceLock<bool> = OnceLock::new();

/// The name Metal gives the GPU of Apple's virtual machines.
const PARAVIRTUAL_GPU: &[u8] = b"Apple Paravirtual device";
/// `VK_DRIVER_ID_MOLTENVK`.
const MOLTENVK: u32 = 14;

/// One of `VkLayerSettingsCreateInfoEXT`'s settings (`VkLayerSettingEXT`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct LayerSetting {
    layer: *const std::ffi::c_char,
    name: *const std::ffi::c_char,
    kind: u32,
    count: u32,
    values: *const c_void,
}

/// `VK_STRUCTURE_TYPE_LAYER_SETTINGS_CREATE_INFO_EXT`.
const LAYER_SETTINGS: u32 = 1_000_496_000;
/// `VK_LAYER_SETTING_TYPE_INT32_EXT`.
const SETTING_INT32: u32 = 1;
/// `MVK_CONFIG_USE_MTLHEAP_NEVER`.
static NO_HEAPS: i32 = 0;

/// MoltenVK's setting that its device memory is no Metal placement heap.
///
/// On the paravirtual GPU, MoltenVK (1.4.2) draws nothing from a vertex or
/// index buffer bound 64 KiB or more into a memory that is a placement
/// heap, as Zink binds an OpenGL display list's; memory that is one Metal
/// buffer, as with this setting, draws. The same program draws at every
/// offset on an Apple GPU (an M4 Pro), and buffers Metal places in a heap
/// there read right on the paravirtual GPU: the fault is in MoltenVK's heap
/// path on that GPU.
pub(super) fn no_heaps() -> LayerSetting {
    LayerSetting {
        layer: c"MoltenVK".as_ptr(),
        name: c"MVK_CONFIG_USE_MTLHEAP".as_ptr(),
        kind: SETTING_INT32,
        count: 1,
        values: (&raw const NO_HEAPS).cast(),
    }
}

/// Whether a device of `instance` (just made) is MoltenVK's on the
/// paravirtual GPU: its driver's ID and its name, from
/// `vkGetPhysicalDeviceProperties2` with `VkPhysicalDeviceDriverProperties`.
fn moltenvk_paravirtual(driver: &Driver, instance: u64) -> bool {
    let enumerate = proc_addr(driver, instance, "vkEnumeratePhysicalDevices");
    let properties = proc_addr(driver, instance, "vkGetPhysicalDeviceProperties2");
    if enumerate == 0 || properties == 0 {
        return false;
    }
    type Enumerate = unsafe extern "C" fn(u64, *mut u32, *mut u64) -> i32;
    type Properties = unsafe extern "C" fn(u64, *mut u8);
    // SAFETY: the driver's functions, by their names.
    let (enumerate, properties) = unsafe {
        (
            std::mem::transmute::<usize, Enumerate>(enumerate),
            std::mem::transmute::<usize, Properties>(properties),
        )
    };
    let mut count = 0u32;
    // SAFETY: the instance's count, into fwe's variable.
    if unsafe { enumerate(instance, &mut count, std::ptr::null_mut()) } < 0 {
        return false;
    }
    let mut devices = vec![0u64; count as usize];
    // SAFETY: room for `count` devices.
    if unsafe { enumerate(instance, &mut count, devices.as_mut_ptr()) } < 0 {
        return false;
    }
    devices.truncate(count as usize);
    devices.iter().any(|&pd| {
        // `VkPhysicalDeviceDriverProperties` (536 bytes, its ID at 16), and
        // `VkPhysicalDeviceProperties2` (840 bytes) chaining it, its
        // properties at 16 and in them the device's name at 20.
        let mut ids = vec![0u8; 536];
        ids[0..4].copy_from_slice(&1_000_196_000u32.to_ne_bytes());
        let mut p = vec![0u8; 840];
        p[0..4].copy_from_slice(&1_000_059_001u32.to_ne_bytes());
        p[8..16].copy_from_slice(&(ids.as_mut_ptr() as u64).to_ne_bytes());
        // SAFETY: a device of the instance's, and room for the structures.
        unsafe { properties(pd, p.as_mut_ptr()) };
        let id = u32::from_ne_bytes(ids[16..20].try_into().expect("four bytes"));
        let name = &p[16 + 20..16 + 20 + 256];
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        id == MOLTENVK && &name[..len] == PARAVIRTUAL_GPU
    })
}

/// In the chain from `first` (copies of fwe's): `setting` added to the
/// program's own layer settings, after them so that it holds, or a
/// structure of fwe's with it put first. The chain's first structure.
pub(super) fn with_setting(
    copies: &mut Copies,
    first: u64,
    setting: LayerSetting,
) -> Result<u64, i32> {
    let mut at = first;
    while at != 0 {
        // SAFETY: a structure of the copied chain, its type at 0 and next at 8.
        let (stype, next) =
            unsafe { (*field::<u32>(at as *mut u8, 0), *field::<u64>(at as *mut u8, 8)) };
        if stype == LAYER_SETTINGS {
            // SAFETY: a copy of the program's `VkLayerSettingsCreateInfoEXT`:
            // its count at 16, its settings (the program's) at 24.
            unsafe {
                let s = at as *mut u8;
                let n = *field::<u32>(s, 16) as usize;
                let theirs = uaccess::read_bytes(
                    *field::<u64>(s, 24),
                    n.min(1 << 12) * size_of::<LayerSetting>(),
                )
                .map_err(|_| errno::EFAULT)?;
                let mut all = theirs;
                all.extend_from_slice(std::slice::from_raw_parts(
                    (&raw const setting).cast::<u8>(),
                    size_of::<LayerSetting>(),
                ));
                *field::<u32>(s, 16) = (all.len() / size_of::<LayerSetting>()) as u32;
                *field::<u64>(s, 24) = copies.bytes(&all) as u64;
            }
            return Ok(first);
        }
        at = next;
    }
    let settings = copies.bytes(
        // SAFETY: the setting's bytes, a plain C structure.
        unsafe {
            std::slice::from_raw_parts((&raw const setting).cast::<u8>(), size_of::<LayerSetting>())
        },
    );
    let mut info = [0u8; 32];
    info[0..4].copy_from_slice(&LAYER_SETTINGS.to_ne_bytes());
    info[8..16].copy_from_slice(&first.to_ne_bytes());
    info[16..20].copy_from_slice(&1u32.to_ne_bytes());
    info[24..32].copy_from_slice(&(settings as u64).to_ne_bytes());
    Ok(copies.bytes(&info) as u64)
}

/// `vkCreateInstance(pCreateInfo, pAllocator, pInstance)`: from a copy of
/// the guest's create info, its chain the structures fwe passes on, its
/// extensions the driver's (a portability driver's enumeration added), no
/// layers. MoltenVK on the paravirtual GPU is told to keep its device
/// memory out of placement heaps ([`no_heaps`]): the first instance a
/// process makes there is made again so.
pub fn create_instance(driver: &Driver, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let listed = global(driver, cmd::vkEnumerateInstanceExtensionProperties)
        .map(|f| {
            super::host_extensions(|count, props| {
                // SAFETY: the driver's function, with valid out-parameters.
                unsafe {
                    generated::call(
                        cmd::vkEnumerateInstanceExtensionProperties,
                        f,
                        &words(&[0, count, props]),
                    ) as i32
                }
            })
        })
        .unwrap_or_default();
    let lists = |e: &std::ffi::CStr| listed.iter().any(|(n, _)| n.as_slice() == e.to_bytes());
    // A portability driver's enumeration is the loader's extension, which
    // a driver called with no loader between might lack: enabled where the
    // driver lists it.
    let enumeration = c"VK_KHR_portability_enumeration";
    let portability = driver.portability && lists(enumeration);
    let settings = c"VK_EXT_layer_settings";
    let make = |heaps_off: bool| -> Result<(u64, u64), i32> {
        let mut copies = Copies::default();
        let info = copies.structure(w[0], INSTANCE_INFO)?;
        // SAFETY: `info` is a copy of the guest's `VkInstanceCreateInfo`.
        unsafe {
            let next = *field::<u64>(info, 8);
            let mut chain = copies.chain(next, |_| true)?;
            if heaps_off {
                chain = with_setting(&mut copies, chain, no_heaps())?;
            }
            *field::<u64>(info, 8) = chain;
            let names = chain::read_names(*field::<u64>(info, 56), *field::<u32>(info, 48))?;
            let names = super::host_names(names);
            let named = |e: &std::ffi::CStr| names.iter().any(|n| n.as_slice() == e.to_bytes());
            let mut extra = Vec::new();
            if portability && !named(enumeration) {
                extra.push(enumeration);
                *field::<u32>(info, 16) |= ENUMERATE_PORTABILITY;
            }
            if heaps_off && !named(settings) {
                extra.push(settings);
            }
            let (list, len) = copies.names(&names, &extra);
            *field::<u32>(info, 48) = len;
            *field::<u64>(info, 56) = list;
            *field::<u32>(info, 32) = 0;
            *field::<u64>(info, 40) = 0;
        }
        let f = global(driver, cmd::vkCreateInstance).ok_or(errno::EINVAL)?;
        let mut instance = 0u64;
        // Threads the driver starts take no signal the guest's thread had
        // unblocked ([`crate::host::with_signals_blocked`]).
        let r = crate::host::with_signals_blocked(|| {
            // SAFETY: the driver's vkCreateInstance, with a create info of
            // the guest's copied and an out-parameter of fwe's.
            unsafe {
                generated::call(
                    cmd::vkCreateInstance,
                    f,
                    &words(&[info as u64, 0, &mut instance as *mut u64 as u64]),
                )
            }
        });
        Ok((r, instance))
    };
    let known = MOLTENVK_PARAVIRTUAL.get().copied();
    // MoltenVK on the paravirtual GPU needs the setting, which needs the
    // extension: without it, it cannot draw right there.
    if known == Some(true) && !lists(settings) {
        return Ok(result::ERROR_INCOMPATIBLE_DRIVER as u32 as u64);
    }
    let (mut r, mut instance) = make(known == Some(true))?;
    if known.is_none() && r as u32 as i32 == result::SUCCESS {
        let on_it = moltenvk_paravirtual(driver, instance);
        let _ = MOLTENVK_PARAVIRTUAL.set(on_it);
        if on_it {
            let destroy = proc_addr(driver, instance, "vkDestroyInstance");
            if destroy != 0 {
                type Destroy = unsafe extern "C" fn(u64, *const c_void);
                // SAFETY: the driver's vkDestroyInstance, on the instance it
                // just made, which nothing else has.
                unsafe {
                    std::mem::transmute::<usize, Destroy>(destroy)(instance, std::ptr::null())
                };
            }
            if !lists(settings) {
                return Ok(result::ERROR_INCOMPATIBLE_DRIVER as u32 as u64);
            }
            (r, instance) = make(true)?;
        }
    }
    if r as u32 as i32 == result::SUCCESS {
        add(instance, Arc::new(instance_table(driver, instance)), 0, 0);
        uaccess::write(w[2], instance).map_err(|_| errno::EFAULT)?;
    }
    Ok(r)
}

/// `vkCreateDevice(physicalDevice, pCreateInfo, pAllocator, pDevice)`: from
/// a copy of the guest's create info, its chain the structures fwe passes
/// on, its extensions the driver's, with `VK_KHR_portability_subset` where
/// the device has it (which Vulkan requires then), and no layers.
pub fn create_device(driver: &Driver, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    let (of_instance, instance) = table_of(w[0]).ok_or(errno::EINVAL)?;
    let subset = c"VK_KHR_portability_subset";
    let has_subset = {
        let f = of_instance.get(cmd::vkEnumerateDeviceExtensionProperties).ok_or(errno::EINVAL)?;
        super::host_extensions(|count, props| {
            // SAFETY: the driver's function, with valid out-parameters.
            unsafe {
                generated::call(
                    cmd::vkEnumerateDeviceExtensionProperties,
                    f,
                    &words(&[w[0], 0, count, props]),
                ) as i32
            }
        })
        .iter()
        .any(|(n, _)| n.as_slice() == subset.to_bytes())
    };
    let mut copies = Copies::default();
    let info = copies.structure(w[1], DEVICE_INFO)?;
    let null_descriptors;
    // SAFETY: `info` is a copy of the guest's `VkDeviceCreateInfo`.
    unsafe {
        let next = *field::<u64>(info, 8);
        *field::<u64>(info, 8) = copies.chain(next, |_| true)?;
        null_descriptors = super::null::device_wants(driver, w[0], *field::<u64>(info, 8));
        let names = chain::read_names(*field::<u64>(info, 56), *field::<u32>(info, 48))?;
        let names = super::host_names(names);
        let mut extra = Vec::new();
        if has_subset && !names.iter().any(|n| n.as_slice() == subset.to_bytes()) {
            extra.push(subset);
        }
        let (list, len) = copies.names(&names, &extra);
        *field::<u32>(info, 48) = len;
        *field::<u64>(info, 56) = list;
        *field::<u32>(info, 32) = 0;
        *field::<u64>(info, 40) = 0;
    }
    let f = of_instance.get(cmd::vkCreateDevice).ok_or(errno::EINVAL)?;
    let mut device = 0u64;
    let r = crate::host::with_signals_blocked(|| {
        // SAFETY: the driver's vkCreateDevice for this physical device, with
        // a create info of the guest's copied and an out-parameter of fwe's.
        unsafe {
            generated::call(
                cmd::vkCreateDevice,
                f,
                &words(&[w[0], info as u64, 0, &mut device as *mut u64 as u64]),
            )
        }
    });
    if r as u32 as i32 == result::SUCCESS {
        let table = device_table(driver, instance, device, &of_instance);
        add(device, Arc::new(table), w[0], instance);
        // Null descriptors the driver lacks: stand-ins of fwe's, or no
        // device.
        if null_descriptors && super::null::start(driver, device, w[0]).is_err() {
            if let Some(f) = function(driver, cmd::vkDestroyDevice, device) {
                // SAFETY: the driver's vkDestroyDevice for the device just
                // made, which nothing else has.
                unsafe { generated::call(cmd::vkDestroyDevice, f, &words(&[device, 0])) };
            }
            remove(device);
            return Ok(result::ERROR_INITIALIZATION_FAILED as u32 as u64);
        }
        uaccess::write(w[3], device).map_err(|_| errno::EFAULT)?;
    }
    Ok(r)
}

#[cfg(test)]
pub(super) fn add_for_test(handle: u64, fns: &[(usize, Function)]) {
    let mut t = vec![0usize; COMMANDS];
    for &(i, f) in fns {
        t[i] = f as usize;
    }
    add(handle, Arc::new(Table(t.into_boxed_slice())), 0, 0);
}
