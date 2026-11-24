//! The GPU helper: the process that runs virglrenderer for fwe's GPU device
//! ([`crate::virgl`] is its client, in the guest's process).
//!
//! virglrenderer's Venus renderer takes Vulkan's commands as Mesa's Venus
//! driver writes them for a virtio-gpu device and runs them on the host's
//! Vulkan (MoltenVK, over Metal); its render server is a thread of the
//! process that loads it. It opens descriptors of its own (a shared memory
//! object for each block of GPU memory, sockets, pipes) and runs threads,
//! and Metal is not fork-safe: in the guest's process its descriptors would
//! be among the guest's, and a fork child could not use it. So it runs
//! here, in a process of its own, which fwe talks to over two sockets:
//!
//! - requests, one at a time, some answered ([`Op`]): a blob of GPU memory
//!   comes back as the descriptor of its shared memory object, which the
//!   guest's process maps where the guest maps the blob;
//! - and the fences the renderer signals, as they signal ([`Event`]).
//!
//! It ends when fwe's end of the requests' socket closes (the process that
//! used the GPU ended or exec'd), or on its first error writing to it.
//!
//! It is started by a launcher (`fwe --gpu-launch`, [`launch`]), which ends
//! at once: the helper is then no child of the guest's process, which a
//! guest's `wait` would otherwise see.

use std::ffi::{c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// The descriptor numbers the helper is given: the requests' socket and the
/// events' socket.
pub const REQUESTS_FD: RawFd = 3;
pub const EVENTS_FD: RawFd = 4;

/// A request's operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Op {
    /// `set` → `[max_ver, size]`.
    CapSet = 1,
    /// `set, ver, size` → the set's bytes.
    Caps = 2,
    /// `ctx, set, name…` → status.
    ContextCreate = 3,
    /// `ctx`; unanswered.
    ContextDestroy = 4,
    /// `ctx, words…`; unanswered (as a virtio-gpu queues them: a context
    /// whose commands fail is the renderer's to report, to its driver).
    Submit = 5,
    /// `ctx, res, mem, flags, id, size, export` → status, and the blob's
    /// shared memory's descriptor if `export`.
    CreateBlob = 6,
    /// `ctx, res`; unanswered.
    Unref = 7,
    /// `ctx, res`; unanswered.
    Attach = 8,
    /// `ctx, ring, id`; unanswered: [`Event`] when it signals.
    CreateFence = 9,
}

impl Op {
    fn from_u32(v: u32) -> Option<Op> {
        Some(match v {
            1 => Op::CapSet,
            2 => Op::Caps,
            3 => Op::ContextCreate,
            4 => Op::ContextDestroy,
            5 => Op::Submit,
            6 => Op::CreateBlob,
            7 => Op::Unref,
            8 => Op::Attach,
            9 => Op::CreateFence,
            _ => return None,
        })
    }

    /// Whether the helper answers it.
    pub fn answered(self) -> bool {
        matches!(self, Op::CapSet | Op::Caps | Op::ContextCreate | Op::CreateBlob)
    }
}

/// A fence signalled: context, ring, and the last fence id of that ring
/// signalled. Sixteen bytes on the events' socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub ctx: u32,
    pub ring: u32,
    pub id: u64,
}

impl Event {
    pub const SIZE: usize = 16;

    pub fn encode(self) -> [u8; Event::SIZE] {
        let mut b = [0u8; Event::SIZE];
        b[0..4].copy_from_slice(&self.ctx.to_le_bytes());
        b[4..8].copy_from_slice(&self.ring.to_le_bytes());
        b[8..16].copy_from_slice(&self.id.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; Event::SIZE]) -> Event {
        Event {
            ctx: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            ring: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            id: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        }
    }
}

/// A request: its operation and the length of what follows, then that.
pub fn request(op: Op, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + payload.len());
    b.extend_from_slice(&(op as u32).to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// An answer's head: a status (0, or a positive errno) and the length of
/// what follows. A descriptor, if it carries one, comes with the head.
pub const ANSWER_HEAD: usize = 8;

/// The first answer, the helper's start: its status and, if it failed,
/// why, as text.
pub fn answer(status: i32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(ANSWER_HEAD + payload.len());
    b.extend_from_slice(&status.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// Little-endian words of a request's payload.
pub struct Words<'a>(&'a [u8]);

impl<'a> Words<'a> {
    pub fn new(b: &'a [u8]) -> Words<'a> {
        Words(b)
    }
    fn u32(&mut self) -> Option<u32> {
        let (h, t) = self.0.split_first_chunk::<4>()?;
        self.0 = t;
        Some(u32::from_le_bytes(*h))
    }
    fn u64(&mut self) -> Option<u64> {
        let (h, t) = self.0.split_first_chunk::<8>()?;
        self.0 = t;
        Some(u64::from_le_bytes(*h))
    }
    fn rest(self) -> &'a [u8] {
        self.0
    }
}

// --- The launcher -----------------------------------------------------------

/// `fwe --gpu-launch <library>`: start the helper with the sockets it was
/// given (3 and 4) and its standard error, in a process group of its own,
/// then wait for its standard input to close (the guest's process, which
/// started this one, recorded it as its own child by then:
/// [`crate::ownchild`]) and end. Never returns.
pub fn launch(fwe: &std::path::Path, library: &std::ffi::OsStr) -> ! {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(fwe.as_os_str().as_bytes()).expect("no NUL in a path");
    let lib = std::ffi::CString::new(library.as_bytes()).expect("no NUL in a path");
    let flag = c"--gpu-helper";
    let argv = [path.as_ptr(), flag.as_ptr(), lib.as_ptr(), std::ptr::null()];
    let started = crate::hostproc::spawn(&path, &argv, &[], &[2, REQUESTS_FD, EVENTS_FD])
        .inspect_err(|e| eprintln!("fwe: the GPU helper did not start (errno {e})"))
        .is_ok();
    // SAFETY: closing this process's copies, which only the helper needs.
    unsafe {
        libc::close(REQUESTS_FD);
        libc::close(EVENTS_FD);
    }
    let mut stdin = std::io::stdin();
    let _ = stdin.read_to_end(&mut Vec::new());
    std::process::exit(if started { 0 } else { 1 })
}

// --- The helper -------------------------------------------------------------

/// `VIRGL_RENDERER_THREAD_SYNC`: fences are waited for on a thread.
const THREAD_SYNC: c_int = 1 << 1;
/// `VIRGL_RENDERER_VENUS`.
const VENUS: c_int = 1 << 6;
/// `VIRGL_RENDERER_NO_VIRGL`: no OpenGL renderer (Venus only).
const NO_VIRGL: c_int = 1 << 7;
/// `VIRGL_RENDERER_ASYNC_FENCE_CB`: a fence is reported from that thread
/// as it signals.
const ASYNC_FENCE_CB: c_int = 1 << 8;
/// `VIRGL_RENDERER_RENDER_SERVER`: Venus runs in its render server (a
/// thread of this process, as fwe's build of virglrenderer has it).
const RENDER_SERVER: c_int = 1 << 9;
/// `VIRGL_RENDERER_BLOB_FD_TYPE_SHM`: a blob's memory as a shared memory
/// object's descriptor.
const BLOB_FD_TYPE_SHM: u32 = 3;

/// `struct virgl_renderer_callbacks`, version 4.
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
type ExportBlobFn = unsafe extern "C" fn(u32, *mut u32, *mut c_int) -> c_int;
type UnrefFn = unsafe extern "C" fn(u32);
type AttachFn = unsafe extern "C" fn(c_int, c_int);
type CreateFenceFn = unsafe extern "C" fn(u32, u32, u32, u64) -> c_int;

/// The library's calls the helper makes.
struct Api {
    init: InitFn,
    get_cap_set: GetCapSetFn,
    fill_caps: FillCapsFn,
    context_create_with_flags: ContextCreateFn,
    context_destroy: ContextDestroyFn,
    submit_cmd: SubmitCmdFn,
    resource_create_blob: CreateBlobFn,
    resource_export_blob: ExportBlobFn,
    resource_unref: UnrefFn,
    ctx_attach_resource: AttachFn,
    ctx_detach_resource: AttachFn,
    context_create_fence: CreateFenceFn,
}

fn load(library: &std::ffi::CStr) -> Result<Api, String> {
    // SAFETY: loading a library by a NUL-terminated name.
    let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        // SAFETY: dlerror's message, valid until the next dl call.
        let why = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        return Err(format!(
            "{} did not load: {}",
            library.to_string_lossy(),
            why.to_string_lossy()
        ));
    }
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
            resource_export_blob: std::mem::transmute::<*mut c_void, ExportBlobFn>(sym(
                "virgl_renderer_resource_export_blob",
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

/// The events' socket, written by the renderer's threads one event at a
/// time.
static EVENTS: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

/// A fence of the context-less queue signalled: the helper makes none.
extern "C" fn write_fence(_cookie: *mut c_void, _fence: u32) {}

/// Context `ctx`'s fence `id` on ring `ring` signalled (and every earlier
/// one of that ring): on a thread of the renderer's. The helper ends if fwe
/// is gone.
extern "C" fn write_context_fence(_cookie: *mut c_void, ctx: u32, ring: u32, id: u64) {
    let mut events = EVENTS.lock().unwrap_or_else(|e| e.into_inner());
    let sent =
        events.as_mut().is_some_and(|f| f.write_all(&Event { ctx, ring, id }.encode()).is_ok());
    if !sent {
        std::process::exit(0);
    }
}

/// `fwe --gpu-helper <library>`: load and start virglrenderer from
/// `library`, say so on the requests' socket (status 0, or an errno and why
/// as text), then serve fwe's requests until it goes. Never returns.
pub fn serve(library: &std::ffi::OsStr) -> ! {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: plain host call: a write to a closed socket fails (EPIPE),
    // which ends the helper, rather than killing it.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    // SAFETY: the descriptors fwe gave this process, owned here.
    let (requests, events) =
        unsafe { (std::fs::File::from_raw_fd(REQUESTS_FD), std::fs::File::from_raw_fd(EVENTS_FD)) };
    *EVENTS.lock().unwrap_or_else(|e| e.into_inner()) = Some(events);
    let mut requests = requests;
    let lib = std::ffi::CString::new(library.as_bytes()).expect("no NUL in a path");
    let api = match start(&lib) {
        Ok(api) => api,
        Err(why) => {
            let _ = requests.write_all(&answer(fwe_abi::errno::ENODEV, why.as_bytes()));
            std::process::exit(1);
        }
    };
    if requests.write_all(&answer(0, &[])).is_err() {
        std::process::exit(0);
    }
    let mut head = [0u8; 8];
    loop {
        if requests.read_exact(&mut head).is_err() {
            std::process::exit(0);
        }
        let op = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        if requests.read_exact(&mut payload).is_err() {
            std::process::exit(0);
        }
        let Some(op) = Op::from_u32(op) else {
            eprintln!("fwe GPU helper: unknown request {op}");
            std::process::exit(1);
        };
        let (status, out, fd) = run(&api, op, &mut payload);
        if op.answered() && send_answer(requests.as_raw_fd(), status, &out, fd).is_err() {
            std::process::exit(0);
        }
    }
}

fn start(library: &std::ffi::CStr) -> Result<Api, String> {
    let api = load(library)?;
    static CALLBACKS: std::sync::Mutex<Callbacks> = std::sync::Mutex::new(Callbacks {
        version: 4,
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
    let flags = VENUS | NO_VIRGL | THREAD_SYNC | ASYNC_FENCE_CB | RENDER_SERVER;
    // SAFETY: the callbacks live as long as the process (a static), as the
    // library keeps the pointer.
    let r = unsafe { (api.init)(std::ptr::null_mut(), flags, &mut *cb) };
    if r != 0 {
        return Err(format!("virglrenderer did not start Venus ({r})"));
    }
    Ok(api)
}

/// A status of the renderer's as an answer's: 0 is done.
fn status(r: c_int) -> i32 {
    if r == 0 { 0 } else { fwe_abi::errno::EINVAL }
}

/// Carry out request `op` with `payload`: its answer's status and what it
/// carries, and a descriptor to pass with it.
fn run(api: &Api, op: Op, payload: &mut [u8]) -> (i32, Vec<u8>, Option<OwnedFd>) {
    let malformed = (fwe_abi::errno::EINVAL, Vec::new(), None);
    let mut w = Words::new(payload);
    match op {
        Op::CapSet => {
            let Some(set) = w.u32() else { return malformed };
            let (mut ver, mut size) = (0u32, 0u32);
            // SAFETY: two out-parameters of this frame.
            unsafe { (api.get_cap_set)(set, &mut ver, &mut size) };
            let mut out = ver.to_le_bytes().to_vec();
            out.extend_from_slice(&size.to_le_bytes());
            (0, out, None)
        }
        Op::Caps => {
            let (Some(set), Some(ver), Some(size)) = (w.u32(), w.u32(), w.u32()) else {
                return malformed;
            };
            let mut buf = vec![0u8; size as usize];
            // SAFETY: a buffer of the set's size, which the library fills.
            unsafe { (api.fill_caps)(set, ver, buf.as_mut_ptr().cast()) };
            (0, buf, None)
        }
        Op::ContextCreate => {
            let (Some(ctx), Some(set)) = (w.u32(), w.u32()) else { return malformed };
            let name = w.rest();
            // SAFETY: `name` is `name.len()` bytes; the library copies it.
            let r = unsafe {
                (api.context_create_with_flags)(ctx, set, name.len() as u32, name.as_ptr().cast())
            };
            (status(r), Vec::new(), None)
        }
        Op::ContextDestroy => {
            if let Some(ctx) = w.u32() {
                // SAFETY: a context made by ContextCreate.
                unsafe { (api.context_destroy)(ctx) };
            }
            (0, Vec::new(), None)
        }
        Op::Submit => {
            let Some(ctx) = w.u32() else { return malformed };
            let cmd = w.rest();
            let words = (cmd.len() / 4) as c_int;
            // SAFETY: a buffer of `words` words, read during the call.
            let r = unsafe { (api.submit_cmd)(cmd.as_ptr() as *mut c_void, ctx as c_int, words) };
            if r != 0 {
                eprintln!("fwe GPU helper: context {ctx}'s commands failed ({r})");
            }
            (0, Vec::new(), None)
        }
        Op::CreateBlob => {
            let fields = (w.u32(), w.u32(), w.u32(), w.u32(), w.u64(), w.u64(), w.u32());
            let (Some(ctx), Some(res), Some(mem), Some(flags), Some(id), Some(size), Some(export)) =
                fields
            else {
                return malformed;
            };
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
            let r = status(unsafe { (api.resource_create_blob)(&args) });
            if r != 0 || export == 0 {
                return (r, Vec::new(), None);
            }
            let (mut kind, mut fd) = (0u32, -1);
            // SAFETY: two out-parameters of this frame; the descriptor is
            // a duplicate the caller owns.
            let e = unsafe { (api.resource_export_blob)(res, &mut kind, &mut fd) };
            if e != 0 || fd < 0 {
                return (fwe_abi::errno::EINVAL, Vec::new(), None);
            }
            // SAFETY: the descriptor just made, owned here.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if kind != BLOB_FD_TYPE_SHM {
                eprintln!(
                    "fwe GPU helper: blob {res}'s memory is of kind {kind}, not shared memory"
                );
                return (fwe_abi::errno::ENODEV, Vec::new(), None);
            }
            (0, Vec::new(), Some(fd))
        }
        Op::Unref => {
            if let (Some(ctx), Some(res)) = (w.u32(), w.u32()) {
                // SAFETY: a resource CreateBlob made.
                unsafe {
                    (api.ctx_detach_resource)(ctx as c_int, res as c_int);
                    (api.resource_unref)(res);
                }
            }
            (0, Vec::new(), None)
        }
        Op::Attach => {
            if let (Some(ctx), Some(res)) = (w.u32(), w.u32()) {
                // SAFETY: plain call; an unknown resource is ignored.
                unsafe { (api.ctx_attach_resource)(ctx as c_int, res as c_int) };
            }
            (0, Vec::new(), None)
        }
        Op::CreateFence => {
            let (Some(ctx), Some(ring), Some(id)) = (w.u32(), w.u32(), w.u64()) else {
                return malformed;
            };
            // SAFETY: plain call.
            let r = unsafe { (api.context_create_fence)(ctx, 0, ring, id) };
            if r != 0 {
                eprintln!("fwe GPU helper: context {ctx}'s fence {id} was refused ({r})");
            }
            (0, Vec::new(), None)
        }
    }
}

/// Send an answer on socket `sock`: its head with `fd` (if any) passed
/// alongside, then what it carries.
fn send_answer(sock: RawFd, status: i32, out: &[u8], fd: Option<OwnedFd>) -> std::io::Result<()> {
    let head = answer(status, out);
    crate::hostproc::send_with_fd(sock, &head, fd.as_ref().map(AsRawFd::as_raw_fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_kind_reads_back_as_itself() {
        for v in 0..16 {
            if let Some(op) = Op::from_u32(v) {
                assert_eq!(op as u32, v);
            }
        }
        assert_eq!(Op::from_u32(Op::CreateFence as u32), Some(Op::CreateFence));
        assert_eq!(Op::from_u32(0), None);
    }

    #[test]
    fn a_request_is_its_kind_length_and_payload() {
        let r = request(Op::Submit, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut w = Words::new(&r);
        assert_eq!(w.u32(), Some(Op::Submit as u32));
        assert_eq!(w.u32(), Some(8));
        assert_eq!(w.u64(), Some(u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8])));
        assert!(w.rest().is_empty());
    }

    #[test]
    fn an_answer_is_its_status_length_and_payload() {
        let a = answer(-22, b"why");
        assert_eq!(a.len(), ANSWER_HEAD + 3);
        assert_eq!(i32::from_le_bytes(a[0..4].try_into().unwrap()), -22);
        assert_eq!(u32::from_le_bytes(a[4..8].try_into().unwrap()), 3);
        assert_eq!(&a[ANSWER_HEAD..], b"why");
    }

    #[test]
    fn an_event_reads_back_as_itself() {
        let e = Event { ctx: 7, ring: 1, id: u64::MAX - 3 };
        assert_eq!(Event::decode(&e.encode()), e);
    }

    #[test]
    fn a_short_payload_reads_as_none() {
        let mut w = Words::new(&[1, 2, 3]);
        assert_eq!(w.u32(), None);
        let mut w = Words::new(&[1, 0, 0, 0, 9]);
        assert_eq!(w.u32(), Some(1));
        assert_eq!(w.u64(), None);
    }
}
