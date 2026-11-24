//! virglrenderer, the renderer behind fwe's GPU device ([`crate::drm`]):
//! its Venus renderer takes Vulkan's commands as Mesa's Venus driver writes
//! them for a virtio-gpu device and runs them on the host's Vulkan (MoltenVK,
//! over Metal, on macOS), in this process. It is loaded with `dlopen` when
//! the device's node is first looked up (`/dev/dri`; `FWE_VIRGLRENDERER`,
//! else Homebrew's place for it), so a process that never uses the GPU
//! never loads it (`/sys` shows the device by the library being there),
//! and fwe runs where it is not installed (the device is then absent, as
//! on a Linux machine with no GPU).
//!
//! It runs threads of its own (fences, rings). Every call into it is made
//! with every host signal blocked ([`crate::host::with_signals_blocked`]),
//! so the threads it starts in a call have them blocked too, and no signal
//! meant for the guest lands on one of them; and one at a time, as its
//! callers in a VM's host make them.

use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

/// `VIRGL_RENDERER_THREAD_SYNC`: fences are waited for on a thread of its
/// own.
const THREAD_SYNC: c_int = 1 << 1;
/// `VIRGL_RENDERER_VENUS`.
const VENUS: c_int = 1 << 6;
/// `VIRGL_RENDERER_NO_VIRGL`: no OpenGL renderer (Venus only).
const NO_VIRGL: c_int = 1 << 7;
/// `VIRGL_RENDERER_ASYNC_FENCE_CB`: a fence is reported from that thread
/// as it signals.
const ASYNC_FENCE_CB: c_int = 1 << 8;

/// `struct virgl_renderer_callbacks`, version 3.
#[repr(C)]
struct Callbacks {
    version: c_int,
    write_fence: Option<extern "C" fn(*mut c_void, u32)>,
    create_gl_context: Option<extern "C" fn()>,
    destroy_gl_context: Option<extern "C" fn()>,
    make_current: Option<extern "C" fn()>,
    get_drm_fd: Option<extern "C" fn()>,
    write_context_fence: Option<extern "C" fn(*mut c_void, u32, u32, u64)>,
    get_server_fd: Option<extern "C" fn()>,
    get_egl_display: Option<extern "C" fn()>,
}

/// `struct virgl_renderer_resource_create_blob_args`.
#[repr(C)]
struct BlobArgs {
    res_handle: u32,
    ctx_id: u32,
    blob_mem: u32,
    blob_flags: u32,
    blob_id: u64,
    size: u64,
    iovecs: *const libc::iovec,
    num_iovs: u32,
}

type InitFn = unsafe extern "C" fn(*mut c_void, c_int, *mut Callbacks) -> c_int;
type GetCapSetFn = unsafe extern "C" fn(u32, *mut u32, *mut u32);
type FillCapsFn = unsafe extern "C" fn(u32, u32, *mut c_void);
type ContextCreateFn = unsafe extern "C" fn(u32, u32, u32, *const c_char) -> c_int;
type ContextDestroyFn = unsafe extern "C" fn(u32);
type SubmitCmdFn = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int;
type CreateBlobFn = unsafe extern "C" fn(*const BlobArgs) -> c_int;
type MapPtrFn = unsafe extern "C" fn(u32, *mut u64) -> c_int;
type UnrefFn = unsafe extern "C" fn(u32);
type AttachFn = unsafe extern "C" fn(c_int, c_int);
type CreateFenceFn = unsafe extern "C" fn(u32, u32, u32, u64) -> c_int;

/// The library's calls fwe makes.
struct Api {
    init: InitFn,
    get_cap_set: GetCapSetFn,
    fill_caps: FillCapsFn,
    context_create_with_flags: ContextCreateFn,
    context_destroy: ContextDestroyFn,
    submit_cmd: SubmitCmdFn,
    resource_create_blob: CreateBlobFn,
    resource_get_map_ptr: MapPtrFn,
    resource_unref: UnrefFn,
    ctx_attach_resource: AttachFn,
    ctx_detach_resource: AttachFn,
    context_create_fence: CreateFenceFn,
}

/// Where virglrenderer is looked for after `FWE_VIRGLRENDERER`: Homebrew's
/// places (krunkit's tap builds it with Venus, in-process, on MoltenVK).
const LIBRARIES: &[&str] = &[
    "/opt/homebrew/opt/virglrenderer/lib/libvirglrenderer.1.dylib",
    "/usr/local/opt/virglrenderer/lib/libvirglrenderer.1.dylib",
];

/// The paths the renderer is looked for at, in order.
fn candidates() -> Vec<String> {
    let mut names: Vec<String> = std::env::var("FWE_VIRGLRENDERER").into_iter().collect();
    names.extend(LIBRARIES.iter().map(|s| s.to_string()));
    names
}

/// The renderer, once looked for: loaded and started, or why not.
static RENDERER: OnceLock<Result<Api, String>> = OnceLock::new();

/// The renderer, loaded and started: why not, if it is not.
fn renderer() -> Result<&'static Api, &'static str> {
    RENDERER
        .get_or_init(|| {
            let r = crate::host::with_signals_blocked(start);
            if let Err(e) = &r {
                crate::trace::note_to_file(&format!("no GPU: {e}"));
            }
            r
        })
        .as_ref()
        .map_err(|e| e.as_str())
}

/// Whether the renderer is loaded and started (loading and starting it
/// the first time): whether the GPU device exists. Why not, in fwe's trace.
pub fn available() -> Result<(), &'static str> {
    renderer().map(|_| ())
}

/// Whether the renderer is there to start, without starting it: started,
/// or not yet looked for and installed (a file where it is looked for).
pub fn installed() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    match RENDERER.get() {
        Some(r) => r.is_ok(),
        None => *INSTALLED
            .get_or_init(|| candidates().iter().any(|p| std::path::Path::new(p).is_file())),
    }
}

/// Whether this process image started the renderer (without starting it):
/// its threads and the host's GPU objects are then this image's, and a
/// fork child's copy of it is unusable.
pub fn started() -> bool {
    RENDERER.get().is_some_and(Result::is_ok)
}

fn start() -> Result<Api, String> {
    let api = load()?;
    static CALLBACKS: std::sync::Mutex<Callbacks> = std::sync::Mutex::new(Callbacks {
        version: 3,
        write_fence: Some(write_fence),
        create_gl_context: None,
        destroy_gl_context: None,
        make_current: None,
        get_drm_fd: None,
        write_context_fence: Some(write_context_fence),
        get_server_fd: None,
        get_egl_display: None,
    });
    let mut cb = CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: the callbacks live as long as the process (a static), as the
    // library keeps the pointer.
    let r = unsafe {
        (api.init)(std::ptr::null_mut(), VENUS | NO_VIRGL | THREAD_SYNC | ASYNC_FENCE_CB, &mut *cb)
    };
    if r != 0 {
        return Err(format!("virglrenderer did not start Venus ({r})"));
    }
    Ok(api)
}

fn load() -> Result<Api, String> {
    let handle = candidates()
        .iter()
        .find_map(|n| {
            let c = std::ffi::CString::new(n.as_str()).ok()?;
            // SAFETY: loading a library by a NUL-terminated name.
            let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            (!h.is_null()).then_some(h)
        })
        .ok_or_else(|| {
            "virglrenderer is not installed (`brew tap slp/krunkit && brew install \
             slp/krunkit/virglrenderer`)"
                .to_string()
        })?;
    let sym = |name: &str| -> Result<*mut c_void, String> {
        let c = std::ffi::CString::new(name).expect("no NUL in a symbol name");
        // SAFETY: looking up a symbol in the library just loaded.
        let p = unsafe { libc::dlsym(handle, c.as_ptr()) };
        if p.is_null() { Err(format!("virglrenderer has no {name}")) } else { Ok(p) }
    };
    // SAFETY: each symbol has the C signature of the field it fills
    // (virglrenderer.h).
    unsafe {
        Ok(Api {
            init: std::mem::transmute::<*mut c_void, InitFn>(sym("virgl_renderer_init")?),
            get_cap_set: std::mem::transmute::<*mut c_void, GetCapSetFn>(sym(
                "virgl_renderer_get_cap_set",
            )?),
            fill_caps: std::mem::transmute::<*mut c_void, FillCapsFn>(sym(
                "virgl_renderer_fill_caps",
            )?),
            context_create_with_flags: std::mem::transmute::<*mut c_void, ContextCreateFn>(sym(
                "virgl_renderer_context_create_with_flags",
            )?),
            context_destroy: std::mem::transmute::<*mut c_void, ContextDestroyFn>(sym(
                "virgl_renderer_context_destroy",
            )?),
            submit_cmd: std::mem::transmute::<*mut c_void, SubmitCmdFn>(sym(
                "virgl_renderer_submit_cmd",
            )?),
            resource_create_blob: std::mem::transmute::<*mut c_void, CreateBlobFn>(sym(
                "virgl_renderer_resource_create_blob",
            )?),
            resource_get_map_ptr: std::mem::transmute::<*mut c_void, MapPtrFn>(sym(
                "virgl_renderer_resource_get_map_ptr",
            )?),
            resource_unref: std::mem::transmute::<*mut c_void, UnrefFn>(sym(
                "virgl_renderer_resource_unref",
            )?),
            ctx_attach_resource: std::mem::transmute::<*mut c_void, AttachFn>(sym(
                "virgl_renderer_ctx_attach_resource",
            )?),
            ctx_detach_resource: std::mem::transmute::<*mut c_void, AttachFn>(sym(
                "virgl_renderer_ctx_detach_resource",
            )?),
            context_create_fence: std::mem::transmute::<*mut c_void, CreateFenceFn>(sym(
                "virgl_renderer_context_create_fence",
            )?),
        })
    }
}

/// A fence of the context-less queue signalled: fwe makes none.
extern "C" fn write_fence(_cookie: *mut c_void, _fence: u32) {}

/// Context `ctx`'s fence `fence` on ring `ring` signalled (and every
/// earlier one of that ring): on the renderer's own thread.
extern "C" fn write_context_fence(_cookie: *mut c_void, ctx: u32, ring: u32, fence: u64) {
    crate::drm::fence_signalled(ctx, ring, fence);
}

/// Calls into the renderer, one at a time: it keeps no locks of its own
/// for its callers, which are one thread in a VM's host (libkrun's, crosvm's
/// virtio-gpu worker), and here are the guest's threads.
static CALLS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `f` called on the renderer, the only call on it, with every host signal
/// blocked: `ENODEV` if there is no renderer.
fn with<R>(f: impl FnOnce(&Api) -> R) -> Result<R, i32> {
    let api = renderer().map_err(|_| fwe_abi::errno::ENODEV)?;
    let _one = CALLS.lock().unwrap_or_else(|e| e.into_inner());
    Ok(crate::host::with_signals_blocked(|| f(api)))
}

/// A status of the renderer's as fwe's answer: 0 is done.
fn done(r: c_int) -> Result<(), i32> {
    if r == 0 { Ok(()) } else { Err(fwe_abi::errno::EINVAL) }
}

/// Capability set `set`'s newest version and its size.
pub fn cap_set(set: u32) -> Result<(u32, u32), i32> {
    let (mut ver, mut size) = (0u32, 0u32);
    // SAFETY: two out-parameters of this frame.
    with(|api| unsafe { (api.get_cap_set)(set, &mut ver, &mut size) })?;
    Ok((ver, size))
}

/// Capability set `set`, version `ver`, `size` bytes of it (the set's size,
/// as [`cap_set`] gave it).
pub fn caps(set: u32, ver: u32, size: u32) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; size as usize];
    // SAFETY: a buffer of the set's size, which the library fills.
    with(|api| unsafe { (api.fill_caps)(set, ver, buf.as_mut_ptr().cast()) })?;
    Ok(buf)
}

/// Make context `ctx` of capability set `set`, named `name`.
pub fn context_create(ctx: u32, set: u32, name: &[u8]) -> Result<(), i32> {
    // SAFETY: `name` is `name.len()` bytes; the library copies it.
    done(with(|api| unsafe {
        (api.context_create_with_flags)(ctx, set, name.len() as u32, name.as_ptr().cast())
    })?)
}

/// Context `ctx` is gone.
pub fn context_destroy(ctx: u32) {
    // SAFETY: a context made by `context_create`.
    let _ = with(|api| unsafe { (api.context_destroy)(ctx) });
}

/// Run the commands in `cmd` (whole 32-bit words) in context `ctx`.
pub fn submit(ctx: u32, cmd: &mut [u8]) -> Result<(), i32> {
    let words = (cmd.len() / 4) as c_int;
    // SAFETY: a buffer of `words` words, read during the call.
    done(with(|api| unsafe { (api.submit_cmd)(cmd.as_mut_ptr().cast(), ctx as c_int, words) })?)
}

/// Make resource `res` of context `ctx`: a blob of `size` bytes of memory
/// kind `mem` with `flags`, object `id` of the context's.
pub fn create_blob(
    ctx: u32,
    res: u32,
    mem: u32,
    flags: u32,
    id: u64,
    size: u64,
) -> Result<(), i32> {
    let args = BlobArgs {
        res_handle: res,
        ctx_id: ctx,
        blob_mem: mem,
        blob_flags: flags,
        blob_id: id,
        size,
        iovecs: std::ptr::null(),
        num_iovs: 0,
    };
    // SAFETY: arguments of this frame, read during the call.
    done(with(|api| unsafe { (api.resource_create_blob)(&args) })?)
}

/// Resource `res`'s memory in this process, as the renderer keeps it
/// mapped for as long as the resource lives (Apple's build gives its
/// address, where others map it on request), the resource's size long.
pub fn map(res: u32) -> Result<u64, i32> {
    let mut p = 0u64;
    // SAFETY: an out-parameter of this frame.
    done(with(|api| unsafe { (api.resource_get_map_ptr)(res, &mut p) })?)?;
    if p == 0 { Err(fwe_abi::errno::EINVAL) } else { Ok(p) }
}

/// Resource `res` is gone: taken from context `ctx`, and let go.
pub fn unref(ctx: u32, res: u32) {
    // SAFETY: a resource `create_blob` made.
    let _ = with(|api| unsafe {
        (api.ctx_detach_resource)(ctx as c_int, res as c_int);
        (api.resource_unref)(res);
    });
}

/// Resource `res` is used by context `ctx`'s commands.
pub fn attach(ctx: u32, res: u32) -> Result<(), i32> {
    // SAFETY: plain call; an unknown resource is ignored by the library.
    with(|api| unsafe { (api.ctx_attach_resource)(ctx as c_int, res as c_int) })
}

/// Fence `fence` on context `ctx`'s ring `ring`, signalled once the
/// commands before it have run ([`write_context_fence`], perhaps on this
/// thread, before this returns).
pub fn create_fence(ctx: u32, ring: u32, fence: u64) -> Result<(), i32> {
    // SAFETY: plain call.
    done(with(|api| unsafe { (api.context_create_fence)(ctx, 0, ring, fence) })?)
}
