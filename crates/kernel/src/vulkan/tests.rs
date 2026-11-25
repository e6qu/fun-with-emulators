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

#[test]
fn null_descriptors_structures_are_vulkans() {
    for (stype, size) in super::null::LAYOUTS {
        assert_eq!(generated::struct_size(stype), Some(size as u64), "structure type {stype}");
    }
}

fn dummies() -> super::null::Dummies {
    super::null::Dummies {
        buffer: 0xb0,
        uniform_texel: 0xc0,
        storage_texel: 0xc1,
        view: 0xd0,
        ..Default::default()
    }
}

/// A `VkWriteDescriptorSet` of `n` descriptors of type `kind` with its
/// elements at `array`.
fn write(kind: u32, n: u32, array: u64) -> [u8; 64] {
    let mut w = [0u8; 64];
    w[32..36].copy_from_slice(&n.to_ne_bytes());
    w[36..40].copy_from_slice(&kind.to_ne_bytes());
    let field = match kind {
        1 | 2 | 3 | 10 => 40,
        4 | 5 => 56,
        _ => 48,
    };
    w[field..field + 8].copy_from_slice(&array.to_ne_bytes());
    w
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

#[test]
fn null_handles_in_descriptor_writes_are_stand_ins() {
    let d = dummies();
    // Two sampled images (one null), a null storage texel buffer, a null
    // uniform buffer, and one with no null handle.
    let images: [[u64; 3]; 2] = [[0x5a, 0x77, 5], [0x5a, 0, 5]];
    let texel: [u64; 1] = [0];
    let buffers: [[u64; 3]; 1] = [[0, 16, 64]];
    let whole: [[u64; 3]; 1] = [[0x99, 0, 64]];
    let writes = [
        write(1, 2, images.as_ptr() as u64),
        write(5, 1, texel.as_ptr() as u64),
        write(6, 1, buffers.as_ptr() as u64),
        write(7, 1, whole.as_ptr() as u64),
    ];
    let fixed = super::null::fix_writes_for_test(&d, 4, writes.as_ptr() as u64).unwrap();
    let images = crate::uaccess::read_bytes(word(&fixed, 40), 48).unwrap();
    assert_eq!((word(&images, 8), word(&images, 32)), (0x77, 0xd0), "the null view only");
    assert_eq!(word(&images, 24), 0x5a, "its sampler kept");
    assert_eq!(crate::uaccess::read::<u64>(word(&fixed, 64 + 56)).unwrap(), 0xc1);
    let buffer = crate::uaccess::read_bytes(word(&fixed, 128 + 48), 24).unwrap();
    assert_eq!((word(&buffer, 0), word(&buffer, 8), word(&buffer, 16)), (0xb0, 0, !0));
    assert_eq!(word(&fixed, 192 + 48), whole.as_ptr() as u64, "no null: the guest's own");
    // Writes with no null handle pass as they are.
    let plain = [write(7, 1, whole.as_ptr() as u64)];
    assert!(super::null::fix_writes_for_test(&d, 1, plain.as_ptr() as u64).is_none());
}

#[test]
fn null_handles_in_template_data_are_stand_ins() {
    let d = dummies();
    // A uniform texel buffer view at 0, then two image infos at 16 with a
    // stride of 32.
    let mut data = [0u64; 12];
    data[2 + 1] = 0x77;
    data[2 + 4] = 0x5a;
    let entries = [(4, 1, 0, 8), (2, 2, 16, 32)];
    let fixed = super::null::fix_template_for_test(&d, &entries, data.as_ptr() as u64).unwrap();
    assert_eq!(word(&fixed, 0), 0xc0);
    assert_eq!(word(&fixed, 16 + 8), 0x77);
    assert_eq!(word(&fixed, 48 + 8), 0xd0);
    assert_eq!(word(&fixed, 48), 0x5a);
}

/// fwe's MoltenVK setting in an instance's chain: a structure of its own
/// first where the program gives no settings; after the program's own, so
/// that it holds, where it does.
#[test]
fn moltenvk_is_told_no_heaps_after_the_programs_own_settings() {
    use super::objects::{no_heaps, with_setting};
    let setting_bytes = 32usize;
    let name_of = |setting: &[u8]| {
        // SAFETY: a NUL-terminated name of a setting the test made.
        unsafe { std::ffi::CStr::from_ptr(word(setting, 8) as *const std::ffi::c_char) }
            .to_str()
            .unwrap()
            .to_string()
    };
    // No settings: one of fwe's, first, the chain after it.
    let mut copies = super::chain::Copies::default();
    // A structure of another type (VkValidationFeaturesEXT's), the chain.
    let mut other = [0u8; 16];
    other[0..4].copy_from_slice(&1_000_247_000u32.to_ne_bytes());
    let chain = copies.bytes(&other) as u64;
    let first = with_setting(&mut copies, chain, no_heaps()).unwrap();
    let info = crate::uaccess::read_bytes(first, 32).unwrap();
    assert_eq!(u32::from_ne_bytes(info[0..4].try_into().unwrap()), 1_000_496_000);
    assert_eq!(word(&info, 8), chain, "the chain goes on after it");
    assert_eq!(u32::from_ne_bytes(info[16..20].try_into().unwrap()), 1);
    let ours = crate::uaccess::read_bytes(word(&info, 24), setting_bytes).unwrap();
    assert_eq!(name_of(&ours), "MVK_CONFIG_USE_MTLHEAP");
    assert_eq!(
        crate::uaccess::read::<i32>(word(&ours, 24)).unwrap(),
        0,
        "MVK_CONFIG_USE_MTLHEAP_NEVER"
    );

    // The program's settings (a copy of its structure in the chain): kept,
    // fwe's after them.
    let theirs_name = c"MVK_CONFIG_LOG_LEVEL";
    let level = 3i32;
    let theirs: [u64; 4] = [
        c"MoltenVK".as_ptr() as u64,
        theirs_name.as_ptr() as u64,
        1 | (1u64 << 32),
        &level as *const i32 as u64,
    ];
    let mut copies = super::chain::Copies::default();
    let mut structure = [0u8; 32];
    structure[0..4].copy_from_slice(&1_000_496_000u32.to_ne_bytes());
    structure[16..20].copy_from_slice(&1u32.to_ne_bytes());
    structure[24..32].copy_from_slice(&(theirs.as_ptr() as u64).to_ne_bytes());
    let copied = copies.bytes(&structure) as u64;
    assert_eq!(
        with_setting(&mut copies, copied, no_heaps()).unwrap(),
        copied,
        "no structure added"
    );
    let info = crate::uaccess::read_bytes(copied, 32).unwrap();
    assert_eq!(u32::from_ne_bytes(info[16..20].try_into().unwrap()), 2);
    let both = crate::uaccess::read_bytes(word(&info, 24), 2 * setting_bytes).unwrap();
    assert_eq!(name_of(&both[..32]), "MVK_CONFIG_LOG_LEVEL", "the program's first");
    assert_eq!(name_of(&both[32..]), "MVK_CONFIG_USE_MTLHEAP", "fwe's last, so it holds");
}
