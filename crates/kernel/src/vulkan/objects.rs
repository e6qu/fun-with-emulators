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

/// `vkCreateInstance(pCreateInfo, pAllocator, pInstance)`: from a copy of
/// the guest's create info, its chain the structures fwe passes on, its
/// extensions the driver's (a portability driver's enumeration added), no
/// layers.
pub fn create_instance(driver: &Driver, w: &[u64; MOST_ARGS]) -> Result<u64, i32> {
    // A portability driver's enumeration is the loader's extension, which
    // a driver called with no loader between may lack: enabled where the
    // driver lists it.
    let enumeration = c"VK_KHR_portability_enumeration";
    let portability = driver.portability
        && global(driver, cmd::vkEnumerateInstanceExtensionProperties).is_some_and(|f| {
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
            .iter()
            .any(|(n, _)| n.as_slice() == enumeration.to_bytes())
        });
    let mut copies = Copies::default();
    let info = copies.structure(w[0], INSTANCE_INFO)?;
    // SAFETY: `info` is a copy of the guest's `VkInstanceCreateInfo`.
    unsafe {
        let next = *field::<u64>(info, 8);
        *field::<u64>(info, 8) = copies.chain(next, |_| true)?;
        let names = chain::read_names(*field::<u64>(info, 56), *field::<u32>(info, 48))?;
        let names = super::host_names(names);
        let mut extra = Vec::new();
        if portability && !names.iter().any(|n| n.as_slice() == enumeration.to_bytes()) {
            extra.push(enumeration);
            *field::<u32>(info, 16) |= ENUMERATE_PORTABILITY;
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
        // SAFETY: the driver's vkCreateInstance, with a create info of the
        // guest's copied and an out-parameter of fwe's.
        unsafe {
            generated::call(
                cmd::vkCreateInstance,
                f,
                &words(&[info as u64, 0, &mut instance as *mut u64 as u64]),
            )
        }
    });
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
