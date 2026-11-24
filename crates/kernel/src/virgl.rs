//! The renderer behind fwe's GPU device ([`crate::drm`]): virglrenderer's
//! Venus renderer, which runs Vulkan's commands as Mesa's Venus driver
//! writes them for a virtio-gpu device on the host's Vulkan (MoltenVK, over
//! Metal), in a process of its own, the GPU helper
//! ([`crate::virglhelper`]), which this module starts and talks to.
//!
//! The helper is started when the device's node is first opened by a
//! process (`fwe --gpu-launch`, which starts it and ends: the helper is no
//! child of the guest's process, and the launcher is fwe's own child while
//! it lives, [`crate::ownchild`]). The library is found as
//! `FWE_VIRGLRENDERER` names it, else where fwe's Homebrew formula for it
//! installs it (`fwe-virglrenderer`); fwe runs where it is not installed
//! (the device is then absent, as on a Linux machine with no GPU), and a
//! process that never opens the device never starts the helper.
//! The helper is a macOS program, so its environment is not fwe's (the
//! guest's) but the variables of fwe's named for it, `FWE_GPU_<NAME>`
//! given it as `<NAME>`.
//!
//! Requests go one at a time over one socket ([`crate::virglhelper::Op`]);
//! the fences the renderer signals come back over another, which a thread
//! of fwe's reads ([`crate::drm::fence_signalled`]). Both sockets are fwe's
//! own descriptors (the reserved range). A process keeps its helper across
//! `execve`; a fork child closes its copies of its parent's sockets and
//! starts a helper of its own if it opens the device ([`forked_child`]).
//! Every call is made with every host signal blocked, so a signal for the
//! guest does not cut a request short, and the reading thread, started in
//! one, never takes one.

use crate::virglhelper::{ANSWER_HEAD, Event, Op, request};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering::SeqCst};

/// Where fwe's Homebrew formula installs virglrenderer (Apple Silicon's
/// prefix, then Intel's).
const LIBRARIES: &[&str] = &[
    "/opt/homebrew/opt/fwe-virglrenderer/lib/libvirglrenderer.1.dylib",
    "/usr/local/opt/fwe-virglrenderer/lib/libvirglrenderer.1.dylib",
];

/// This `fwe` executable, which runs the helper.
static EXE: OnceLock<PathBuf> = OnceLock::new();

/// Remember fwe's own executable, for starting the helper.
pub fn set_executable(path: PathBuf) {
    let _ = EXE.set(path);
}

/// The renderer's library: the one `FWE_VIRGLRENDERER` names if it is set,
/// else the formula's, if it is installed.
fn library() -> Option<&'static PathBuf> {
    static LIBRARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    LIBRARY
        .get_or_init(|| match std::env::var_os("FWE_VIRGLRENDERER") {
            Some(p) => Some(PathBuf::from(p)).filter(|p| p.is_file()),
            None => LIBRARIES.iter().map(PathBuf::from).find(|p| p.is_file()),
        })
        .as_ref()
}

/// Whether the renderer is installed (without starting the helper).
pub fn installed() -> bool {
    library().is_some()
}

/// The helper's requests' socket, fwe's end, and the events' socket's
/// (the reading thread's): -1 for none.
static REQUESTS: AtomicI32 = AtomicI32::new(-1);
static EVENTS: AtomicI32 = AtomicI32::new(-1);

/// The process's helper.
pub(crate) enum Helper {
    /// Not started: the device was not opened yet (in this process).
    Unstarted,
    /// Started, its sockets in [`REQUESTS`] and [`EVENTS`].
    Running,
    /// It did not start, for the reason given (in fwe's trace).
    Failed,
}

/// The helper; held across a host fork ([`crate::forklock`]), and while it
/// starts.
pub(crate) static HELPER: std::sync::Mutex<Helper> = std::sync::Mutex::new(Helper::Unstarted);

fn helper() -> std::sync::MutexGuard<'static, Helper> {
    HELPER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether the helper runs, starting it the first time (why not, if it
/// does not, goes to fwe's trace).
pub fn available() -> bool {
    let mut h = helper();
    if matches!(*h, Helper::Unstarted) {
        *h = match crate::host::with_signals_blocked(connect) {
            Ok(()) => Helper::Running,
            Err(e) => {
                crate::trace::note_to_file(&format!("no GPU: {e}"));
                Helper::Failed
            }
        };
    }
    matches!(*h, Helper::Running)
}

/// Two connected stream sockets, the first close-on-exec in fwe's reserved
/// range (fwe's end), the second as made (the helper's, given to it).
fn socket_pair() -> Result<(OwnedFd, OwnedFd), String> {
    use std::os::fd::FromRawFd;
    let mut ends = [0; 2];
    // SAFETY: plain host call into this frame's array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, ends.as_mut_ptr()) } != 0 {
        return Err(format!("no socket for the GPU helper: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: the descriptor just made, owned here.
    let theirs = unsafe { OwnedFd::from_raw_fd(ends[1]) };
    let ours = crate::fdtable::reserve(ends[0])
        .map_err(|e| format!("no descriptor for the GPU helper's socket (errno {e})"))?;
    // SAFETY: the descriptor just reserved, owned here.
    let ours = unsafe { OwnedFd::from_raw_fd(ours) };
    // A write after the helper went fails (EPIPE) rather than raising
    // SIGPIPE.
    #[cfg(target_os = "macos")]
    let one: libc::c_int = 1;
    #[cfg(target_os = "macos")]
    // SAFETY: plain host call with a value of this frame.
    unsafe {
        libc::setsockopt(
            ours.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&one as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    Ok((ours, theirs))
}

/// What a name in fwe's environment starts with to be in the helper's.
const HELPER_PREFIX: &str = "FWE_GPU_";

/// The helper's environment, a macOS program's: not fwe's, which is the
/// guest's (a guest's `VK_DRIVER_FILES` names its own Vulkan driver, which
/// the host's Vulkan loader would look for), but each `FWE_GPU_<NAME>` of
/// fwe's as `<NAME>` (`FWE_GPU_VK_LOADER_DEBUG`, `FWE_GPU_MVK_CONFIG_...`).
fn helper_environment() -> crate::hostproc::Env {
    crate::hostproc::Env::new(helper_vars(std::env::vars_os()))
}

/// The helper's variables of those of fwe's environment, `vars`.
fn helper_vars(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)> {
    use std::os::unix::ffi::OsStrExt;
    vars.filter_map(|(k, v)| {
        let name = k.as_bytes().strip_prefix(HELPER_PREFIX.as_bytes())?;
        (!name.is_empty()).then(|| (std::ffi::OsStr::from_bytes(name).to_owned(), v))
    })
}

/// Start the helper (through its launcher) and wait for it to say whether
/// the renderer started; then start the thread that takes its events.
fn connect() -> Result<(), String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let exe = EXE.get().ok_or("fwe's own path is unknown")?;
    let lib = library().ok_or(
        "virglrenderer is not installed (`brew install e6qu/fwe/fwe-virglrenderer`, or \
         FWE_VIRGLRENDERER naming it)",
    )?;
    let (requests, requests_theirs) = socket_pair()?;
    let (events, events_theirs) = socket_pair()?;
    // The launcher's standard input: it ends once this closes.
    let mut hold = [0; 2];
    // SAFETY: plain host call into this frame's array.
    if unsafe { libc::pipe(hold.as_mut_ptr()) } != 0 {
        return Err("no pipe for the GPU helper's launcher".into());
    }
    // SAFETY: the descriptors just made, owned here.
    let (hold_read, hold_write) =
        unsafe { (OwnedFd::from_raw_fd(hold[0]), OwnedFd::from_raw_fd(hold[1])) };
    let path = std::ffi::CString::new(exe.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let libc_path =
        std::ffi::CString::new(lib.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let argv = [path.as_ptr(), c"--gpu-launch".as_ptr(), libc_path.as_ptr(), std::ptr::null()];
    let moved = [
        (requests_theirs.as_raw_fd(), crate::virglhelper::REQUESTS_FD),
        (events_theirs.as_raw_fd(), crate::virglhelper::EVENTS_FD),
        (hold_read.as_raw_fd(), 0),
    ];
    let launcher = crate::hostproc::spawn(&path, &argv, &helper_environment(), &moved, &[2])
        .map_err(|e| format!("the GPU helper's launcher did not start (errno {e})"))?;
    // Recorded as fwe's own before it may end (it ends when `hold_write`
    // closes); dropped, it is reaped.
    let own = crate::ownchild::OwnChild::record(launcher);
    drop((requests_theirs, events_theirs, hold_read, hold_write));
    match own {
        Some(own) => drop(own),
        None => {
            // No slot (never so: one launcher at a time): reaped here.
            let mut status = 0;
            // SAFETY: plain host call on the child just started.
            unsafe { libc::waitpid(launcher.get(), &mut status, 0) };
        }
    }
    // The helper's first answer: whether the renderer started.
    let mut head = [0u8; ANSWER_HEAD];
    crate::hostproc::recv_with_fd(requests.as_raw_fd(), &mut head)
        .map_err(|e| format!("the GPU helper did not start: {e}"))?;
    let status = i32::from_le_bytes(head[0..4].try_into().unwrap());
    let mut why = vec![0u8; u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize];
    crate::hostproc::recv_with_fd(requests.as_raw_fd(), &mut why)
        .map_err(|e| format!("the GPU helper did not start: {e}"))?;
    if status != 0 {
        return Err(String::from_utf8_lossy(&why).into_owned());
    }
    REQUESTS.store(std::os::fd::IntoRawFd::into_raw_fd(requests), SeqCst);
    EVENTS.store(events.as_raw_fd(), SeqCst);
    std::thread::Builder::new()
        .name("fwe-gpu-events".into())
        .spawn(move || take_events(events))
        .map_err(|e| format!("no thread for the GPU's fences: {e}"))?;
    Ok(())
}

/// The events' reader: each fence signalled to the device; at the helper's
/// end, every fence (the renderer's work is gone with it).
fn take_events(events: OwnedFd) {
    let mut b = [0u8; Event::SIZE];
    while crate::hostproc::recv_with_fd(events.as_raw_fd(), &mut b).is_ok() {
        let e = Event::decode(&b);
        crate::drm::fence_signalled(e.ctx, e.ring, e.id);
    }
    crate::drm::renderer_gone();
}

/// In a fork child (its locks free, [`crate::forklock`]): the helper is the
/// parent's, and so are the sockets to it, which the child closes (the
/// helper ends when its parent's go); the child starts its own if it opens
/// the device.
pub fn forked_child() {
    for s in [&REQUESTS, &EVENTS] {
        let fd = s.swap(-1, SeqCst);
        if fd >= 0 {
            // SAFETY: this process's copy of fwe's socket.
            unsafe { libc::close(fd) };
        }
    }
    *helper() = Helper::Unstarted;
}

/// Requests, one at a time: an answered request's answer is the next on the
/// socket. Held across a host fork ([`crate::forklock`]).
pub(crate) static CALLS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Make request `op` with `payload`: what its answer carries and the
/// descriptor passed with it (none for a request not answered).
/// `ENODEV` if there is no helper (or it went).
fn call(op: Op, payload: &[u8]) -> Result<(Vec<u8>, Option<OwnedFd>), i32> {
    if !available() {
        return Err(fwe_abi::errno::ENODEV);
    }
    let _one = CALLS.lock().unwrap_or_else(|e| e.into_inner());
    let sock = REQUESTS.load(SeqCst);
    if sock < 0 {
        return Err(fwe_abi::errno::ENODEV);
    }
    crate::host::with_signals_blocked(|| {
        let gone = |_| fwe_abi::errno::ENODEV;
        crate::hostproc::send_with_fd(sock, &request(op, payload), None).map_err(gone)?;
        if !op.answered() {
            return Ok((Vec::new(), None));
        }
        let mut head = [0u8; ANSWER_HEAD];
        let fd = crate::hostproc::recv_with_fd(sock, &mut head).map_err(gone)?;
        let status = i32::from_le_bytes(head[0..4].try_into().unwrap());
        let mut out = vec![0u8; u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize];
        crate::hostproc::recv_with_fd(sock, &mut out).map_err(gone)?;
        if status != 0 { Err(status) } else { Ok((out, fd)) }
    })
}

/// A request's payload: its fields, little-endian.
fn payload(words: &[u32], rest: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(words.len() * 4 + rest.len());
    for w in words {
        b.extend_from_slice(&w.to_le_bytes());
    }
    b.extend_from_slice(rest);
    b
}

/// Capability set `set`'s newest version and its size.
pub fn cap_set(set: u32) -> Result<(u32, u32), i32> {
    let (out, _) = call(Op::CapSet, &payload(&[set], &[]))?;
    let word = |at: usize| out.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    Ok((word(0).ok_or(fwe_abi::errno::EIO)?, word(4).ok_or(fwe_abi::errno::EIO)?))
}

/// Capability set `set`, version `ver`, `size` bytes of it (the set's
/// size, as [`cap_set`] gave it).
pub fn caps(set: u32, ver: u32, size: u32) -> Result<Vec<u8>, i32> {
    let (out, _) = call(Op::Caps, &payload(&[set, ver, size], &[]))?;
    if out.len() == size as usize { Ok(out) } else { Err(fwe_abi::errno::EIO) }
}

/// Make context `ctx` of capability set `set`, named `name`.
pub fn context_create(ctx: u32, set: u32, name: &[u8]) -> Result<(), i32> {
    call(Op::ContextCreate, &payload(&[ctx, set], name)).map(|_| ())
}

/// Context `ctx` is gone.
pub fn context_destroy(ctx: u32) {
    let _ = call(Op::ContextDestroy, &payload(&[ctx], &[]));
}

/// Run the commands in `cmd` (whole 32-bit words) in context `ctx`.
pub fn submit(ctx: u32, cmd: &[u8]) -> Result<(), i32> {
    call(Op::Submit, &payload(&[ctx], cmd)).map(|_| ())
}

/// Make resource `res` of context `ctx`: a blob of `size` bytes of memory
/// kind `mem` with `flags`, object `id` of the context's. With `export`,
/// its memory's descriptor (a shared memory object's, fwe's own).
pub fn create_blob(
    ctx: u32,
    res: u32,
    mem: u32,
    flags: u32,
    id: u64,
    size: u64,
    export: bool,
) -> Result<Option<OwnedFd>, i32> {
    let mut p = payload(&[ctx, res, mem, flags], &[]);
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&u32::from(export).to_le_bytes());
    let (_, fd) = call(Op::CreateBlob, &p)?;
    if export && fd.is_none() {
        return Err(fwe_abi::errno::EIO);
    }
    Ok(fd)
}

/// Resource `res` is gone: taken from context `ctx`, and let go.
pub fn unref(ctx: u32, res: u32) {
    let _ = call(Op::Unref, &payload(&[ctx, res], &[]));
}

/// Resource `res` is used by context `ctx`'s commands.
pub fn attach(ctx: u32, res: u32) -> Result<(), i32> {
    call(Op::Attach, &payload(&[ctx, res], &[])).map(|_| ())
}

/// Fence `id` on context `ctx`'s ring `ring`, signalled once the commands
/// before it have run ([`crate::drm::fence_signalled`], from the events'
/// thread).
pub fn create_fence(ctx: u32, ring: u32, id: u64) -> Result<(), i32> {
    let mut p = payload(&[ctx, ring], &[]);
    p.extend_from_slice(&id.to_le_bytes());
    call(Op::CreateFence, &p).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_helper_has_only_the_variables_named_for_it() {
        let os = |k: &str, v: &str| (k.into(), v.into());
        let fwe = [
            os("VK_DRIVER_FILES", "/usr/share/vulkan/icd.d/virtio_icd.aarch64.json"),
            os("HOME", "/root"),
            os("FWE_GPU_VK_LOADER_DEBUG", "error"),
            os("FWE_GPU_", "nameless"),
            os("FWE_VIRGLRENDERER", "/x.dylib"),
        ];
        let got: Vec<_> = helper_vars(fwe.into_iter()).collect();
        assert_eq!(got, [os("VK_LOADER_DEBUG", "error")]);
    }
}
