//! The calls as a driver receives them, through fake driver functions of
//! each command's type.

use super::generated::{self, MOST_ARGS, cmd};
use super::{Function, Level, host_names, offered, words};
use std::ffi::c_void;
use std::sync::Mutex;

/// What the last fake function was called with, as words.
static SEEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn seen(v: Vec<u64>) {
    *SEEN.lock().unwrap() = v;
}

fn run(index: usize, f: Function, w: &[u64]) -> (u64, Vec<u64>) {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: `f` has command `index`'s type, and `w` its arguments.
    let r = unsafe { generated::call(index, f, &words(w)) };
    (r, SEEN.lock().unwrap().clone())
}

/// The tests share [`SEEN`]: one at a time.
static ONE: Mutex<()> = Mutex::new(());

#[allow(clippy::too_many_arguments)]
extern "C" fn pipeline_barrier(
    cb: *mut c_void,
    src: u32,
    dst: u32,
    deps: u32,
    n_mem: u32,
    mem: *mut c_void,
    n_buf: u32,
    buf: *mut c_void,
    n_img: u32,
    img: *mut c_void,
) {
    seen(vec![
        cb as u64,
        src.into(),
        dst.into(),
        deps.into(),
        n_mem.into(),
        mem as u64,
        n_buf.into(),
        buf as u64,
        n_img.into(),
        img as u64,
    ]);
}

#[test]
fn ten_arguments_reach_the_driver_some_on_the_stack() {
    let w = [0x1000, 1, 2, 3, 4, 0x5000, 6, 0x7000, 8, 0x9000];
    let (_, got) = run(cmd::vkCmdPipelineBarrier, pipeline_barrier as Function, &w);
    assert_eq!(got, w);
}

#[allow(clippy::too_many_arguments)]
extern "C" fn wait_events(
    cb: *mut c_void,
    n: u32,
    events: *mut c_void,
    src: u32,
    dst: u32,
    n_mem: u32,
    mem: *mut c_void,
    n_buf: u32,
    buf: *mut c_void,
    n_img: u32,
    img: *mut c_void,
) {
    seen(vec![
        cb as u64,
        n.into(),
        events as u64,
        src.into(),
        dst.into(),
        n_mem.into(),
        mem as u64,
        n_buf.into(),
        buf as u64,
        n_img.into(),
        img as u64,
    ]);
}

#[test]
fn eleven_arguments_reach_the_driver() {
    let w = [0x1000, 1, 0x2000, 3, 4, 5, 0x6000, 7, 0x8000, 0xffff_ffff, 0xa000];
    let (_, got) = run(cmd::vkCmdWaitEvents, wait_events as Function, &w);
    assert_eq!(got, w);
}

extern "C" fn depth_bounds(cb: *mut c_void, min: f32, max: f32) {
    seen(vec![cb as u64, min.to_bits().into(), max.to_bits().into()]);
}

#[test]
fn floats_reach_the_driver_in_float_registers() {
    let w = [0x1000, 0.25f32.to_bits().into(), (-7.5f32).to_bits().into()];
    let (_, got) = run(cmd::vkCmdSetDepthBounds, depth_bounds as Function, &w);
    assert_eq!(got, w);
}

extern "C" fn line_stipple(cb: *mut c_void, factor: u32, pattern: u16) {
    seen(vec![cb as u64, factor.into(), pattern.into()]);
}

#[test]
fn a_16_bit_argument_reaches_the_driver_as_one() {
    // A word with bits above the u16: the driver gets the u16 alone.
    let (_, got) =
        run(cmd::vkCmdSetLineStippleKHR, line_stipple as Function, &[0x1000, 3, 0xdead_beef]);
    assert_eq!(got, [0x1000, 3, 0xbeef]);
}

extern "C" fn create_buffer(
    dev: *mut c_void,
    info: *mut c_void,
    alloc: *mut c_void,
    out: *mut c_void,
) -> i32 {
    seen(vec![dev as u64, info as u64, alloc as u64, out as u64]);
    -2
}

#[test]
fn an_allocator_never_reaches_the_driver_and_a_result_comes_back() {
    let (r, got) =
        run(cmd::vkCreateBuffer, create_buffer as Function, &[0x1000, 0x2000, 0x3000, 0x4000]);
    assert_eq!(got, [0x1000, 0x2000, 0, 0x4000]);
    assert_eq!(r as u32 as i32, -2);
}

extern "C" fn device_address(dev: *mut c_void, info: *mut c_void) -> u64 {
    seen(vec![dev as u64, info as u64]);
    0xffff_0000_1234_5678
}

#[test]
fn a_64_bit_result_comes_back_whole() {
    let (r, _) = run(cmd::vkGetBufferDeviceAddress, device_address as Function, &[0x1000, 0x2000]);
    assert_eq!(r, 0xffff_0000_1234_5678);
}

/// The outputs `generated::outputs` names for command `index` with `w`,
/// counts read as `count` gives them.
fn outputs(index: usize, w: &[u64], count: u64) -> Vec<(u64, u64, u64, bool)> {
    let mut got = Vec::new();
    generated::outputs(
        index,
        &words(w),
        |_, _| count,
        |_, _| count,
        |a, n, s, c| got.push((a, n, s, c)),
    );
    got
}

#[test]
fn the_memory_a_command_writes_is_named() {
    // vkEnumeratePhysicalDevices(instance, pCount, pDevices): the count,
    // and as many handles as it says there is room for.
    assert_eq!(
        outputs(cmd::vkEnumeratePhysicalDevices, &[1, 0x100, 0x200], 3),
        [(0x100, 1, 4, false), (0x200, 3, 8, false)]
    );
    // vkGetQueryPoolResults(dev, pool, first, count, dataSize, pData, ...):
    // dataSize bytes.
    assert_eq!(
        outputs(cmd::vkGetQueryPoolResults, &[1, 2, 0, 4, 64, 0x300, 16, 0], 0),
        [(0x300, 64, 1, false)]
    );
    // vkGetPhysicalDeviceProperties2(pd, pProperties): the structure and
    // the chain the guest put on it.
    let props2 = generated::struct_size(1_000_059_001).unwrap();
    assert_eq!(
        outputs(cmd::vkGetPhysicalDeviceProperties2, &[1, 0x400], 0),
        [(0x400, 1, props2, true)]
    );
    // A command that writes nothing names nothing.
    assert_eq!(outputs(cmd::vkCmdDraw, &[1, 3, 1, 0, 0], 0), []);
}

#[test]
fn the_create_infos_fwe_copies_are_the_sizes_it_takes() {
    assert_eq!(generated::struct_size(1), Some(super::objects::INSTANCE_INFO as u64)); // VkInstanceCreateInfo
    assert_eq!(generated::struct_size(3), Some(super::objects::DEVICE_INFO as u64)); // VkDeviceCreateInfo
    assert_eq!(generated::CALL_RECORD, 24);
}

#[test]
fn the_guest_is_offered_what_fwe_covers_and_the_window_systems() {
    let host: Vec<(Vec<u8>, u32)> = [
        ("VK_KHR_get_physical_device_properties2", 2),
        ("VK_EXT_debug_utils", 2),             // calls back: not offered
        ("VK_KHR_portability_enumeration", 1), // fwe's to use
        ("VK_KHR_surface", 25),                // the guest library's
        ("VK_EXT_headless_surface", 1),        // what it is built on
        ("VK_EXT_metal_surface", 1),           // the Mac's window system
    ]
    .iter()
    .map(|(n, v)| (n.as_bytes().to_vec(), *v))
    .collect();
    let names: Vec<String> = offered(&host, Level::Instance)
        .into_iter()
        .map(|(n, _)| String::from_utf8(n).unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "VK_KHR_get_physical_device_properties2",
            "VK_KHR_surface",
            "VK_KHR_xcb_surface",
            "VK_KHR_xlib_surface"
        ]
    );
    // Without a surface of no window, no window systems.
    let bare = &host[..4];
    let names: Vec<Vec<u8>> = offered(bare, Level::Instance).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, [b"VK_KHR_get_physical_device_properties2".to_vec()]);
    let device: Vec<String> = offered(
        &[
            (b"VK_KHR_portability_subset".to_vec(), 1),
            (b"VK_KHR_external_memory_fd".to_vec(), 1),
            (b"VK_KHR_swapchain".to_vec(), 70),
        ],
        Level::Device,
    )
    .into_iter()
    .map(|(n, _)| String::from_utf8(n).unwrap())
    .collect();
    assert_eq!(device, ["VK_KHR_portability_subset", "VK_KHR_swapchain"]);
    let none = offered(&[(b"VK_KHR_portability_subset".to_vec(), 1)], Level::Device);
    assert_eq!(none.len(), 1, "no swapchains where the driver has none");
}

#[test]
fn the_window_systems_extensions_are_the_drivers_its_built_on() {
    let names = |l: &[&str]| l.iter().map(|n| n.as_bytes().to_vec()).collect::<Vec<_>>();
    assert_eq!(
        host_names(names(&[
            "VK_KHR_surface",
            "VK_KHR_xcb_surface",
            "VK_KHR_get_physical_device_properties2",
            "VK_KHR_xlib_surface"
        ])),
        names(&[
            "VK_KHR_surface",
            "VK_EXT_headless_surface",
            "VK_KHR_get_physical_device_properties2"
        ])
    );
    assert_eq!(host_names(names(&["VK_KHR_swapchain"])), names(&["VK_KHR_swapchain"]));
}

#[test]
fn a_queue_knows_its_family_and_an_object_its_parent() {
    let (device, queue) = (0x7000_0000_5000u64, 0x7000_0000_6000u64);
    super::objects::add_for_test(device, &[]);
    let mut out = queue;
    let w = words(&[device, 3, 0, &mut out as *mut u64 as u64]);
    super::objects::after(fake_driver(), cmd::vkGetDeviceQueue, &w, 0);
    assert_eq!(super::objects::queue_family(queue), 3);
    assert_eq!(super::objects::parent(queue), device);
    assert_eq!(super::objects::parent(0x7000_0000_7000), 0);
}

#[test]
fn an_objects_functions_are_its_own() {
    let (a, b) = (0x7000_0000_1000u64, 0x7000_0000_2000u64);
    super::objects::add_for_test(a, &[(cmd::vkCmdDraw, depth_bounds as Function)]);
    super::objects::add_for_test(b, &[]);
    let driver = fake_driver();
    assert_eq!(super::objects::function(driver, cmd::vkCmdDraw, a), Some(depth_bounds as Function));
    assert_eq!(super::objects::function(driver, cmd::vkCmdDraw, b), None);
    assert!(super::objects::has(driver, a, cmd::vkCmdDraw as u64));
    assert!(!super::objects::has(driver, b, cmd::vkCmdDraw as u64));
    assert!(!super::objects::has(driver, 0x7000_0000_3000, cmd::vkCmdDraw as u64));
    assert!(!super::objects::has(driver, a, generated::COMMANDS as u64));
}

unsafe extern "C" fn no_proc_addr(_: *mut c_void, _: *const std::ffi::c_char) -> *const c_void {
    std::ptr::null()
}

fn fake_driver() -> &'static super::driver::Driver {
    static FAKE: std::sync::OnceLock<super::driver::Driver> = std::sync::OnceLock::new();
    FAKE.get_or_init(|| super::driver::Driver {
        get_instance_proc_addr: no_proc_addr,
        interface: 7,
        portability: false,
        manifest: "fake.json".into(),
    })
}

const _: () = assert!(MOST_ARGS >= 11 && MOST_ARGS <= 16);
