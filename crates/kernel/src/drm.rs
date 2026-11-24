//! The GPU: a Linux render node, `/dev/dri/renderD128`, that speaks the
//! virtio-gpu driver's device interface (the one a Linux VM's GPU has), so
//! that Mesa's Venus Vulkan driver uses it, its commands run in this
//! process by virglrenderer's Venus on the host's Vulkan ([`crate::virgl`]).
//!
//! - **The node** is one of fwe's (a node file in its own directory of
//!   them, [`crate::fs`]), `/dev/dri` in the rootfs's `/dev`, present only
//!   where the renderer loads ([`present`]), as Linux has no render node
//!   without a GPU. libdrm finds it as Linux shows a virtio-gpu PCI device:
//!   `/sys/dev/char/226:128` and the device's directories ([`sys_lookup`]).
//! - **A descriptor** of it has a context (`DRM_IOCTL_VIRTGPU_CONTEXT_INIT`)
//!   and the resources it made, under GEM handles (the resources' ids,
//!   unique in the process), kept by the descriptor's mark
//!   ([`Mark::Drm`]) and let go with its last descriptor.
//! - **Resources** are the renderer's blobs (host memory Vulkan uses, a
//!   Venus ring among them); `mmap` of the offset `DRM_IOCTL_VIRTGPU_MAP`
//!   gives maps the same pages in guest memory ([`map_source`]).
//! - **Fences** a submission asks for (`VIRTGPU_EXECBUF_FENCE_FD_OUT`) are
//!   pipes: the guest holds the read end, which becomes readable as the
//!   renderer signals the fence ([`fence_signalled`]), as a sync file
//!   polls. Venus needs no other synchronization from the kernel: with no
//!   timeline syncobjs it keeps its own.
//! - **A fork child** has none of it: the renderer's state (its threads, the
//!   host's GPU objects) is the parent's, so a child's calls on the device
//!   fail with `ENODEV`.

use crate::fdmarks::{self, Mark};
use crate::uaccess;
use fwe_abi::drm::*;
use fwe_abi::errno;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::*};

/// The render node's numbers.
pub fn node() -> crate::devnodes::Node {
    crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: MAJOR, minor: RENDER_MINOR }
}

/// Whether `n` is the render node.
pub fn is_node(n: crate::devnodes::Node) -> bool {
    n == node()
}

/// A fork child, whose renderer is its parent's.
static FORKED: AtomicBool = AtomicBool::new(false);
/// The backend has no place for the GPU's memory (the VM's).
static ABSENT: AtomicBool = AtomicBool::new(false);

/// Whether the device is there: the backend can map its memory, the
/// renderer loads and starts, and this process is not a fork child of one
/// that started it.
pub fn present() -> bool {
    !FORKED.load(Relaxed) && !ABSENT.load(Relaxed) && crate::virgl::available().is_ok()
}

/// Whether the device is to be shown in `/sys`: as [`present`], but by the
/// renderer being installed, not started (a program reading `/sys` need
/// not start the GPU's renderer; one opening `/dev/dri` does).
fn listed() -> bool {
    !FORKED.load(Relaxed) && !ABSENT.load(Relaxed) && crate::virgl::installed()
}

/// The backend cannot map the GPU's memory into the guest's (the VM's
/// guest memory is the VM's): there is no device.
pub fn absent() {
    ABSENT.store(true, Relaxed);
}

/// An open of the device ([`Mark::Drm`]).
#[derive(Default)]
struct File {
    /// Its context, once made: its id and its number of rings.
    ctx: Option<(u32, u32)>,
    /// Its resources, by GEM handle (the resource's id).
    handles: BTreeMap<u32, Resource>,
}

/// A resource a descriptor made.
#[derive(Clone, Copy)]
struct Resource {
    size: u64,
    blob_mem: u32,
    /// Its memory in this process, once mapped.
    host: Option<u64>,
}

/// Every open of the device, by its mark's key.
static FILES: Mutex<BTreeMap<u32, File>> = Mutex::new(BTreeMap::new());
static NEXT_KEY: AtomicU32 = AtomicU32::new(1);
/// Contexts' and resources' ids: unique in the process, as the renderer
/// keeps them for every context alike.
static NEXT_CTX: AtomicU32 = AtomicU32::new(1);
static NEXT_RES: AtomicU32 = AtomicU32::new(1);

fn files() -> std::sync::MutexGuard<'static, BTreeMap<u32, File>> {
    FILES.lock().unwrap_or_else(|e| e.into_inner())
}

/// `fd` was opened on the render node: an open of the device of its own.
pub fn opened(fd: i32) {
    let key = NEXT_KEY.fetch_add(1, Relaxed);
    files().insert(key, File::default());
    fdmarks::mark(fd, Mark::Drm(key));
}

/// An open of the device kept across `execve` (its descriptor's mark),
/// `key`: the new program finds it open, with no context (the renderer's
/// state went with the old one), and new opens numbered past it.
pub fn restored(key: u32) -> u32 {
    NEXT_KEY.fetch_max(key + 1, Relaxed);
    files().entry(key).or_default();
    key
}

/// Descriptor `fd` is being closed: the open of the device it is goes with
/// its last descriptor.
pub fn fd_closed(fd: i32) {
    if let Some(key) = key_of(fd)
        && !fdmarks::shared_elsewhere(fd)
    {
        release(key);
    }
}

/// The device may be opened.
pub fn check_open() -> Result<(), i32> {
    if present() { Ok(()) } else { Err(errno::ENODEV) }
}

/// Open `key` of the device is gone: its context and resources with it.
fn release(key: u32) {
    let Some(f) = files().remove(&key) else { return };
    if FORKED.load(Relaxed) {
        return;
    }
    if let Some((ctx, _)) = f.ctx {
        for (&res, r) in &f.handles {
            crate::virgl::unref(ctx, res, r.host.is_some());
        }
        crate::virgl::context_destroy(ctx);
        context_gone(ctx);
    }
}

/// A new program is about to replace this one in this process image:
/// whether it needs a fresh image instead, to have the GPU (a fork child
/// of a process that started the renderer, whose copy of it is the
/// parent's). If not, the new program has the device as any other.
pub fn exec_needs_new_image() -> bool {
    if !FORKED.load(Relaxed) {
        return false;
    }
    if crate::virgl::started() {
        return true;
    }
    FORKED.store(false, Relaxed);
    false
}

/// In a fork child: the renderer's state is the parent's. (Its fences'
/// table is left alone: the renderer's thread, which the child does not
/// have, may have held its lock.)
pub fn forked_child() {
    FORKED.store(true, Relaxed);
}

/// The open of the device `fd` is, if it is one.
fn key_of(fd: i32) -> Option<u32> {
    if !fdmarks::any_marks() {
        return None;
    }
    match fdmarks::marked(fd)? {
        Mark::Drm(key) => Some(key),
        _ => None,
    }
}

/// A DRM ioctl on `fd`, if it is the device: Linux's answer. (Others, as
/// `FIOCLEX`, are any descriptor's.)
pub fn ioctl(fd: i32, req: u64, arg: u64) -> Option<i64> {
    if ioc_type(req) != TYPE {
        return None;
    }
    let key = key_of(fd)?;
    // An argument that is a number, not a pointer, as the guest gave it.
    let arg = uaccess::guest_of(arg);
    let began = crate::timing::call_began();
    let r = call(key, req, arg);
    counted(ioc_nr(req), began);
    Some(match r {
        Ok(v) => v,
        Err(e) => -(e as i64),
    })
}

/// The device's calls by kind, for `FWE_TIMING` ([`counts`]): DRM's own,
/// then virtio-gpu's by number (`DRM_VIRTGPU_MAP` 1 to `CONTEXT_INIT` 11).
const KINDS: [&str; 12] = [
    "DRM",
    "MAP",
    "EXECBUFFER",
    "GETPARAM",
    "RESOURCE_CREATE",
    "RESOURCE_INFO",
    "TRANSFER_FROM_HOST",
    "TRANSFER_TO_HOST",
    "WAIT",
    "GET_CAPS",
    "RESOURCE_CREATE_BLOB",
    "CONTEXT_INIT",
];
static CALLS: [AtomicU64; KINDS.len()] = [const { AtomicU64::new(0) }; KINDS.len()];
static CALL_NS: [AtomicU64; KINDS.len()] = [const { AtomicU64::new(0) }; KINDS.len()];
/// Bytes of the device's memory mapped into the guest's, and the mappings.
static MAPPED: AtomicU64 = AtomicU64::new(0);
static MAPPINGS: AtomicU64 = AtomicU64::new(0);

/// A call of number `nr` done, begun at `began` (counted with `FWE_TIMING`).
fn counted(nr: u64, began: Option<std::time::Instant>) {
    let Some(b) = began else { return };
    let i = if nr >= COMMAND_BASE { (nr - COMMAND_BASE).min(KINDS.len() as u64 - 1) } else { 0 };
    CALLS[i as usize].fetch_add(1, Relaxed);
    CALL_NS[i as usize].fetch_add(b.elapsed().as_nanos() as u64, Relaxed);
}

/// `len` bytes of the device's memory mapped (counted with `FWE_TIMING`).
pub fn mapped(len: u64) {
    if crate::timing::on() {
        MAPPED.fetch_add(len, Relaxed);
        MAPPINGS.fetch_add(1, Relaxed);
    }
}

/// The device's calls by kind with the microseconds they took, and its
/// memory mapped, as text: none if it was not used.
pub fn counts() -> Option<String> {
    let calls: Vec<String> = KINDS
        .iter()
        .enumerate()
        .map(|(i, k)| (k, CALLS[i].load(Relaxed), CALL_NS[i].load(Relaxed)))
        .filter(|c| c.1 > 0)
        .map(|(k, n, ns)| format!("{k} {n} ({} us)", ns / 1000))
        .collect();
    (!calls.is_empty()).then(|| {
        format!(
            "GPU calls: {}; GPU memory mapped: {} bytes in {} mappings",
            calls.join(", "),
            MAPPED.load(Relaxed),
            MAPPINGS.load(Relaxed)
        )
    })
}

/// The argument of ioctl `req` at `arg`: as many bytes as the caller's
/// structure has, the rest of `size` zero (the DRM core's way with older
/// and newer callers).
fn arg_in(req: u64, arg: u64, size: usize) -> Result<Vec<u8>, i32> {
    let n = ioc_size(req).min(size);
    let mut v = uaccess::read_bytes(arg, n)?;
    v.resize(size, 0);
    Ok(v)
}

/// `v` back to the caller's structure at `arg`, as much of it as it has.
fn arg_out(req: u64, arg: u64, v: &[u8]) -> Result<(), i32> {
    uaccess::write_from(arg, &v[..ioc_size(req).min(v.len())])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn call(key: u32, req: u64, arg: u64) -> Result<i64, i32> {
    if FORKED.load(Relaxed) {
        return Err(errno::ENODEV);
    }
    match ioc_nr(req) {
        NR_VERSION => version(req, arg),
        NR_GET_CAP => {
            let mut c = arg_in(req, arg, CAP_SIZE)?;
            let value = match u64_at(&c, 0) {
                // No buffers shared as descriptors, and no syncobjs: Venus
                // then keeps its own on the fences it is given.
                CAP_PRIME | CAP_SYNCOBJ | CAP_SYNCOBJ_TIMELINE => 0,
                CAP_TIMESTAMP_MONOTONIC => 1,
                _ => return Err(errno::EINVAL),
            };
            put_u64(&mut c, 8, value);
            arg_out(req, arg, &c)?;
            Ok(0)
        }
        // A render node has no client capabilities to set.
        NR_SET_CLIENT_CAP => Err(errno::EINVAL),
        NR_GEM_CLOSE => {
            let c = arg_in(req, arg, GEM_CLOSE_SIZE)?;
            gem_close(key, u32_at(&c, 0))
        }
        NR_PRIME_HANDLE_TO_FD | NR_PRIME_FD_TO_HANDLE => Err(errno::EOPNOTSUPP),
        NR_VIRTGPU_GETPARAM => {
            let c = arg_in(req, arg, GETPARAM_SIZE)?;
            let value = match u64_at(&c, 0) {
                PARAM_3D_FEATURES
                | PARAM_CAPSET_QUERY_FIX
                | PARAM_RESOURCE_BLOB
                | PARAM_HOST_VISIBLE
                | PARAM_CONTEXT_INIT => 1,
                PARAM_CROSS_DEVICE | PARAM_EXPLICIT_DEBUG_NAME => 0,
                PARAM_SUPPORTED_CAPSET_IDS => 1 << CAPSET_VENUS,
                // Blobs in whole host pages, which map into guest memory
                // as they are.
                PARAM_BLOB_ALIGNMENT => crate::mm::host_page_size(),
                _ => return Err(errno::EINVAL),
            };
            uaccess::write(u64_at(&c, 8), value)?;
            Ok(0)
        }
        NR_VIRTGPU_GET_CAPS => {
            let c = arg_in(req, arg, GET_CAPS_SIZE)?;
            let (set, ver, addr, size) =
                (u32_at(&c, 0), u32_at(&c, 4), u64_at(&c, 8), u32_at(&c, 16));
            if set != CAPSET_VENUS {
                return Err(errno::EINVAL);
            }
            let (max_ver, max_size) = crate::virgl::cap_set(set)?;
            if ver > max_ver {
                return Err(errno::EINVAL);
            }
            let caps = crate::virgl::caps(set, ver, max_size)?;
            uaccess::write_from(addr, &caps[..caps.len().min(size as usize)])?;
            Ok(0)
        }
        NR_VIRTGPU_CONTEXT_INIT => context_init(key, req, arg),
        NR_VIRTGPU_RESOURCE_CREATE_BLOB => create_blob(key, req, arg),
        NR_VIRTGPU_RESOURCE_INFO => {
            let mut c = arg_in(req, arg, RESOURCE_INFO_SIZE)?;
            let handle = u32_at(&c, 0);
            let r = resource(key, handle)?;
            put_u32(&mut c, 4, handle);
            put_u32(&mut c, 8, r.size.min(u32::MAX as u64) as u32);
            put_u32(&mut c, 12, r.blob_mem);
            arg_out(req, arg, &c)?;
            Ok(0)
        }
        NR_VIRTGPU_MAP => {
            let mut c = arg_in(req, arg, MAP_SIZE)?;
            let handle = u32_at(&c, MAP_HANDLE);
            resource(key, handle)?;
            put_u64(&mut c, MAP_OFFSET, map_offset(handle));
            arg_out(req, arg, &c)?;
            Ok(0)
        }
        NR_VIRTGPU_EXECBUFFER => execbuffer(key, req, arg),
        // A blob's commands are done in order with the context's: nothing
        // holds a resource busy beyond them.
        NR_VIRTGPU_WAIT => {
            let c = arg_in(req, arg, 8)?;
            resource(key, u32_at(&c, 0))?;
            Ok(0)
        }
        // OpenGL's (virgl's) resources and transfers: this device has no
        // virgl renderer, as a Venus-only device has none.
        NR_VIRTGPU_RESOURCE_CREATE
        | NR_VIRTGPU_TRANSFER_FROM_HOST
        | NR_VIRTGPU_TRANSFER_TO_HOST => Err(errno::ENOSYS),
        _ => Err(errno::EINVAL),
    }
}

/// `VIRTGPU_PARAM_BLOB_ALIGNMENT`, a parameter Mesa asks for beside
/// `HOST_VISIBLE` (a downstream kernel's): the alignment of blobs' sizes.
const PARAM_BLOB_ALIGNMENT: u64 = 9;

/// `DRM_IOCTL_VERSION`: virtio-gpu's name, date and description, each into
/// the caller's buffer as far as it reaches, and their lengths.
fn version(req: u64, arg: u64) -> Result<i64, i32> {
    let mut c = arg_in(req, arg, VERSION_SIZE)?;
    put_u32(&mut c, VERSION_MAJOR, 0);
    put_u32(&mut c, VERSION_MINOR, 1);
    put_u32(&mut c, VERSION_PATCHLEVEL, 0);
    for (len_at, buf_at, text) in [
        (VERSION_NAME_LEN, VERSION_NAME, &b"virtio_gpu"[..]),
        (VERSION_DATE_LEN, VERSION_DATE, b"0"),
        (VERSION_DESC_LEN, VERSION_DESC, b"virtio GPU and 3D"),
    ] {
        let (room, buf) = (u64_at(&c, len_at) as usize, u64_at(&c, buf_at));
        if room > 0 && buf != 0 {
            uaccess::write_from(buf, &text[..text.len().min(room)])?;
        }
        put_u64(&mut c, len_at, text.len() as u64);
    }
    arg_out(req, arg, &c)?;
    Ok(0)
}

/// `DRM_IOCTL_VIRTGPU_CONTEXT_INIT`: the descriptor's context, of Venus's
/// capability set, once.
fn context_init(key: u32, req: u64, arg: u64) -> Result<i64, i32> {
    let c = arg_in(req, arg, CONTEXT_INIT_SIZE)?;
    let (count, params) = (u32_at(&c, 0) as u64, u64_at(&c, 8));
    // Linux's bound on the parameters: one of each kind.
    if count > 4 {
        return Err(errno::EINVAL);
    }
    let raw = uaccess::read_bytes(params, (count as usize) * SET_PARAM_SIZE)?;
    let (mut set, mut rings, mut name) = (None, 0u64, b"fwe".to_vec());
    for p in raw.as_chunks::<SET_PARAM_SIZE>().0 {
        let (param, value) = (u64_at(p, 0), u64_at(p, 8));
        match param {
            CONTEXT_PARAM_CAPSET_ID => set = Some(value),
            CONTEXT_PARAM_NUM_RINGS if value <= MAX_RINGS => rings = value,
            // Events on the descriptor as rings' fences signal: none asked.
            CONTEXT_PARAM_POLL_RINGS_MASK if value == 0 => {}
            CONTEXT_PARAM_DEBUG_NAME => name = uaccess::read_cstr(value, 64)?,
            _ => return Err(errno::EINVAL),
        }
    }
    if set != Some(CAPSET_VENUS as u64) {
        return Err(errno::EINVAL);
    }
    let mut f = files();
    let file = f.get_mut(&key).ok_or(errno::EBADF)?;
    if file.ctx.is_some() {
        return Err(errno::EEXIST);
    }
    let ctx = NEXT_CTX.fetch_add(1, Relaxed);
    crate::virgl::context_create(ctx, CAPSET_VENUS, &name)?;
    file.ctx = Some((ctx, rings as u32));
    Ok(0)
}

/// The descriptor's context.
fn context(key: u32) -> Result<(u32, u32), i32> {
    files().get(&key).ok_or(errno::EBADF)?.ctx.ok_or(errno::EINVAL)
}

/// Resource `handle` of the descriptor.
fn resource(key: u32, handle: u32) -> Result<Resource, i32> {
    files().get(&key).ok_or(errno::EBADF)?.handles.get(&handle).copied().ok_or(errno::ENOENT)
}

/// `DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB`: a blob of the renderer's,
/// made by the context's commands given with it (or its shared memory,
/// blob 0), under a new handle.
fn create_blob(key: u32, req: u64, arg: u64) -> Result<i64, i32> {
    let mut c = arg_in(req, arg, CREATE_BLOB_SIZE)?;
    let (mem, flags, size) = (u32_at(&c, BLOB_MEM), u32_at(&c, BLOB_FLAGS), u64_at(&c, BLOB_SIZE));
    let (cmd_size, cmd, id) =
        (u32_at(&c, BLOB_CMD_SIZE), u64_at(&c, BLOB_CMD), u64_at(&c, BLOB_ID));
    // The host's memory only: Venus's blobs (guest memory would be the
    // guest's pages lent to the renderer).
    if mem != BLOB_MEM_HOST3D
        || flags & !(BLOB_FLAG_USE_MAPPABLE | BLOB_FLAG_USE_SHAREABLE) != 0
        || size == 0
        || cmd_size % 4 != 0
    {
        return Err(errno::EINVAL);
    }
    let (ctx, _) = context(key)?;
    if cmd_size > 0 {
        let mut commands = uaccess::read_bytes(cmd, cmd_size as usize)?;
        crate::virgl::submit(ctx, &mut commands)?;
    }
    let res = NEXT_RES.fetch_add(1, Relaxed);
    crate::virgl::create_blob(ctx, res, mem, flags, id, size)?;
    crate::virgl::attach(ctx, res)?;
    files()
        .get_mut(&key)
        .ok_or(errno::EBADF)?
        .handles
        .insert(res, Resource { size, blob_mem: mem, host: None });
    put_u32(&mut c, BLOB_BO_HANDLE, res);
    put_u32(&mut c, BLOB_RES_HANDLE, res);
    arg_out(req, arg, &c)?;
    Ok(0)
}

/// `DRM_IOCTL_GEM_CLOSE`: the descriptor lets go of resource `handle`.
fn gem_close(key: u32, handle: u32) -> Result<i64, i32> {
    let mut f = files();
    let file = f.get_mut(&key).ok_or(errno::EBADF)?;
    let r = file.handles.remove(&handle).ok_or(errno::EINVAL)?;
    let ctx = file.ctx;
    drop(f);
    if let Some((ctx, _)) = ctx {
        crate::virgl::unref(ctx, handle, r.host.is_some());
    }
    Ok(0)
}

/// The `mmap` offset of resource `handle`: unique to it, page-aligned.
fn map_offset(handle: u32) -> u64 {
    (handle as u64) << 32
}

/// Mapping `len` bytes at `offset` of device descriptor `fd`: the host
/// memory of the resource the offset names ([`map_offset`]), mapped once
/// in this process (the renderer keeps it), and that memory's start for
/// the part asked for.
pub fn map_source(fd: i32, offset: u64, len: u64) -> Option<Result<u64, i32>> {
    let key = key_of(fd)?;
    Some((|| {
        if FORKED.load(Relaxed) {
            return Err(errno::ENODEV);
        }
        let (handle, within) = ((offset >> 32) as u32, offset & 0xffff_ffff);
        let r = resource(key, handle)?;
        if within
            .checked_add(len)
            .is_none_or(|end| end > r.size.next_multiple_of(crate::mm::host_page_size()))
        {
            return Err(errno::EINVAL);
        }
        let host = match r.host {
            Some(h) => h,
            None => {
                let (h, _) = crate::virgl::map(handle)?;
                if let Some(res) = files().get_mut(&key).and_then(|f| f.handles.get_mut(&handle)) {
                    res.host = Some(h);
                }
                h
            }
        };
        Ok(host + within)
    })())
}

/// `DRM_IOCTL_VIRTGPU_EXECBUFFER`: the context's commands run, the
/// resources named attached to it, and a fence on its ring if asked for.
fn execbuffer(key: u32, req: u64, arg: u64) -> Result<i64, i32> {
    let mut c = arg_in(req, arg, EXECBUFFER_SIZE)?;
    let flags = u32_at(&c, EXECBUFFER_FLAGS);
    let size = u32_at(&c, EXECBUFFER_SIZE_FIELD);
    let (command, bos) = (u64_at(&c, EXECBUFFER_COMMAND), u64_at(&c, EXECBUFFER_BO_HANDLES));
    let nbos = u32_at(&c, EXECBUFFER_NUM_BO_HANDLES);
    let ring = u32_at(&c, EXECBUFFER_RING_IDX);
    let syncobjs = u32_at(&c, EXECBUFFER_NUM_IN_SYNCOBJS) | u32_at(&c, EXECBUFFER_NUM_OUT_SYNCOBJS);
    if flags & !EXECBUF_FLAGS != 0 || !size.is_multiple_of(4) || syncobjs != 0 {
        return Err(errno::EINVAL);
    }
    // A fence to wait for first: one of this device's, as Venus passes.
    if flags & EXECBUF_FENCE_FD_IN != 0 {
        return Err(errno::EINVAL);
    }
    let (ctx, rings) = context(key)?;
    let ring = if flags & EXECBUF_RING_IDX != 0 {
        if ring >= rings {
            return Err(errno::EINVAL);
        }
        ring
    } else {
        0
    };
    let raw = uaccess::read_bytes(bos, nbos as usize * 4)?;
    let handles: Vec<u32> = raw.as_chunks::<4>().0.iter().map(|&b| u32::from_le_bytes(b)).collect();
    for &h in &handles {
        resource(key, h)?;
        crate::virgl::attach(ctx, h)?;
    }
    let mut commands = uaccess::read_bytes(command, size as usize)?;
    crate::virgl::submit(ctx, &mut commands)?;
    if flags & EXECBUF_FENCE_FD_OUT != 0 {
        let fd = fence(ctx, ring)?;
        put_u32(&mut c, EXECBUFFER_FENCE_FD, fd as u32);
        if let Err(e) = arg_out(req, arg, &c) {
            // SAFETY: the descriptor just made, never given out.
            unsafe { libc::close(fd) };
            return Err(e);
        }
    }
    Ok(0)
}

/// A fence asked for and not yet signalled.
struct Pending {
    /// Its id on its context's ring, in the order given.
    id: u64,
    /// The write end of its pipe (fwe's).
    write: i32,
}

/// A context's ring: (context, ring).
type Ring = (u32, u32);

/// Each ring's fences not yet signalled, in order, and the last id given.
static FENCES: Mutex<BTreeMap<Ring, (u64, Vec<Pending>)>> = Mutex::new(BTreeMap::new());

fn fences() -> std::sync::MutexGuard<'static, BTreeMap<Ring, (u64, Vec<Pending>)>> {
    FENCES.lock().unwrap_or_else(|e| e.into_inner())
}

/// A fence on context `ctx`'s ring `ring`, after the commands submitted:
/// the read end of a pipe (close-on-exec, as Linux's sync files are),
/// readable once it signals.
fn fence(ctx: u32, ring: u32) -> Result<i32, i32> {
    let mut ends = [0i32; 2];
    crate::fsops::make_pipe(&mut ends, fwe_abi::fcntl::O_CLOEXEC)?;
    let [read, write] = ends;
    // The write end is fwe's own, out of the guest's descriptors' way.
    let write = match crate::fdtable::reserve(write) {
        Ok(w) => w,
        Err(e) => {
            // SAFETY: the read end just made, never given out.
            unsafe { libc::close(read) };
            return Err(e);
        }
    };
    let id = {
        let mut f = fences();
        let (last, list) = f.entry((ctx, ring)).or_default();
        *last += 1;
        list.push(Pending { id: *last, write });
        *last
    };
    // The lock let go first: the renderer may signal on this thread.
    if let Err(e) = crate::virgl::create_fence(ctx, ring, id) {
        fence_signalled(ctx, ring, id);
        // SAFETY: the read end just made, never given out.
        unsafe { libc::close(read) };
        return Err(e);
    }
    Ok(read)
}

/// Context `ctx`'s fences on ring `ring` up to `id` signalled: their pipes
/// become readable. On the renderer's thread; takes no lock a guest's call
/// holds while it calls the renderer.
pub fn fence_signalled(ctx: u32, ring: u32, id: u64) {
    let done: Vec<Pending> = {
        let mut f = fences();
        let Some((_, list)) = f.get_mut(&(ctx, ring)) else { return };
        let split = list.partition_point(|p| p.id <= id);
        list.drain(..split).collect()
    };
    signal(done);
}

/// Context `ctx` is gone, and its work: every fence on it signals.
fn context_gone(ctx: u32) {
    let done: Vec<Pending> = {
        let mut f = fences();
        let rings: Vec<Ring> = f.range((ctx, 0)..=(ctx, u32::MAX)).map(|(&r, _)| r).collect();
        rings.into_iter().filter_map(|r| f.remove(&r)).flat_map(|(_, list)| list).collect()
    };
    signal(done);
}

/// `fences`' pipes made readable, and fwe's ends of them closed.
fn signal(fences: Vec<Pending>) {
    for p in fences {
        // SAFETY: a pipe's write end of fwe's, closed once written.
        unsafe {
            libc::write(p.write, [0u8].as_ptr().cast(), 1);
            libc::close(p.write);
        }
    }
}

/// The virtio-gpu PCI device's directory, as Linux shows a VM's.
const PCI_DIR: &[u8] = b"/sys/devices/pci0000:00/0000:00:02.0";
/// Its virtio device's directory.
const VIRTIO_DIR: &[u8] = b"/sys/devices/pci0000:00/0000:00:02.0/virtio0";
/// The render node's directory.
const NODE_DIR: &[u8] = b"/sys/devices/pci0000:00/0000:00:02.0/virtio0/drm/renderD128";

/// A synthetic `/sys` entry of the device, if `path` is one and the device
/// is there.
pub fn sys_lookup(path: &[u8]) -> Option<crate::procfs::Entry> {
    if !path.starts_with(b"/sys/") || !listed() {
        return None;
    }
    entry(&within(path))
}

/// The entries of a synthetic `/sys` directory of the device, if `path`
/// is one and the device is there (names and their types).
pub fn sys_children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    if !(path == b"/sys" || path.starts_with(b"/sys/")) || !listed() {
        return None;
    }
    listing(&within(path))
}

/// `path` with the device's links before its last component followed, as
/// Linux follows them in a path (`/sys/dev/char/226:128/device/drm` is the
/// node's device's `drm`); a path of fwe's `/sys` reaches the device's
/// entries whole.
fn within(path: &[u8]) -> Vec<u8> {
    let mut p = path.to_vec();
    'again: for _ in 0..8 {
        let mut i = 1;
        while let Some(j) = p[i..].iter().position(|&b| b == b'/').map(|j| i + j) {
            if let Some(crate::procfs::Entry::Symlink(target)) = entry(&p[..j]) {
                let parent = &p[..p[..j].iter().rposition(|&b| b == b'/').unwrap_or(0)];
                let mut joined = [parent, b"/", &target].concat();
                joined.extend_from_slice(&p[j..]);
                p = lexical(&joined);
                continue 'again;
            }
            i = j + 1;
        }
        break;
    }
    p
}

/// Absolute path `p` with `.` and `..` taken out by name.
fn lexical(p: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in p.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::new();
    for c in parts {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// The device's `/sys` entry `path`, if it is one: Linux's for a
/// virtio-gpu PCI device and its render node.
fn entry(path: &[u8]) -> Option<crate::procfs::Entry> {
    use crate::procfs::Entry;
    let link = |t: &str| Some(Entry::Symlink(t.as_bytes().to_vec()));
    let file = |t: &str| Some(Entry::File(t.as_bytes().to_vec()));
    let under = |dir: &[u8]| path.strip_prefix(dir).map(<[u8]>::to_vec);
    match path {
        b"/sys/dev/char"
        | b"/sys/class"
        | b"/sys/class/drm"
        | b"/sys/bus"
        | b"/sys/bus/pci"
        | b"/sys/bus/virtio"
        | b"/sys/devices/pci0000:00" => return Some(Entry::Dir),
        // (Both two levels below `/sys`.)
        b"/sys/dev/char/226:128" | b"/sys/class/drm/renderD128" => {
            return link("../../devices/pci0000:00/0000:00:02.0/virtio0/drm/renderD128");
        }
        _ => {}
    }
    if let Some(rest) = under(NODE_DIR) {
        return match rest.as_slice() {
            b"" => Some(Entry::Dir),
            b"/dev" => file(&format!("{MAJOR}:{RENDER_MINOR}\n")),
            b"/uevent" => file(&format!(
                "MAJOR={MAJOR}\nMINOR={RENDER_MINOR}\nDEVNAME=dri/renderD{RENDER_MINOR}\nDEVTYPE=drm_minor\n"
            )),
            b"/device" => link("../../../virtio0"),
            b"/subsystem" => link("../../../../../../class/drm"),
            _ => None,
        };
    }
    if let Some(rest) = under(VIRTIO_DIR) {
        return match rest.as_slice() {
            b"" | b"/drm" => Some(Entry::Dir),
            b"/subsystem" => link("../../../../bus/virtio"),
            b"/uevent" => file("DRIVER=virtio_gpu\nMODALIAS=virtio:d00000010v00001AF4\n"),
            b"/device" => file("0x0010\n"),
            b"/vendor" => file("0x1af4\n"),
            _ => None,
        };
    }
    if let Some(rest) = under(PCI_DIR) {
        return match rest.as_slice() {
            b"" => Some(Entry::Dir),
            b"/subsystem" => link("../../../bus/pci"),
            b"/uevent" => file(&format!(
                "DRIVER=virtio-pci\nPCI_CLASS=38000\nPCI_ID={PCI_VENDOR:04X}:{PCI_DEVICE:04X}\n\
                 PCI_SUBSYS_ID={PCI_VENDOR:04X}:1100\nPCI_SLOT_NAME=0000:00:02.0\n\
                 MODALIAS=pci:v0000{PCI_VENDOR:04X}d0000{PCI_DEVICE:04X}sv0000{PCI_VENDOR:04X}sd00001100bc03sc80i00\n"
            )),
            b"/vendor" | b"/subsystem_vendor" => file(&format!("{PCI_VENDOR:#06x}\n")),
            b"/device" => file(&format!("{PCI_DEVICE:#06x}\n")),
            b"/subsystem_device" => file("0x1100\n"),
            b"/revision" => file("0x01\n"),
            b"/class" => file("0x038000\n"),
            _ => None,
        };
    }
    None
}

/// The device's entries of `/sys` directory `path`, if it has any.
fn listing(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    use crate::procfs::{DT_DIR, DT_LNK, DT_REG};
    let names = |n: &[(&str, u8)]| n.iter().map(|(s, t)| (s.as_bytes().to_vec(), *t)).collect();
    Some(match path {
        b"/sys" => names(&[("class", DT_DIR), ("bus", DT_DIR)]),
        b"/sys/dev" => names(&[("char", DT_DIR)]),
        b"/sys/dev/char" => names(&[("226:128", DT_LNK)]),
        b"/sys/class" => names(&[("drm", DT_DIR)]),
        b"/sys/class/drm" => names(&[("renderD128", DT_LNK)]),
        b"/sys/bus" => names(&[("pci", DT_DIR), ("virtio", DT_DIR)]),
        b"/sys/bus/pci" | b"/sys/bus/virtio" => Vec::new(),
        b"/sys/devices" => names(&[("pci0000:00", DT_DIR)]),
        b"/sys/devices/pci0000:00" => names(&[("0000:00:02.0", DT_DIR)]),
        p if p == PCI_DIR => names(&[
            ("virtio0", DT_DIR),
            ("subsystem", DT_LNK),
            ("uevent", DT_REG),
            ("vendor", DT_REG),
            ("device", DT_REG),
            ("subsystem_vendor", DT_REG),
            ("subsystem_device", DT_REG),
            ("revision", DT_REG),
            ("class", DT_REG),
        ]),
        p if p == VIRTIO_DIR => names(&[
            ("drm", DT_DIR),
            ("subsystem", DT_LNK),
            ("uevent", DT_REG),
            ("device", DT_REG),
            ("vendor", DT_REG),
        ]),
        b"/sys/devices/pci0000:00/0000:00:02.0/virtio0/drm" => names(&[("renderD128", DT_DIR)]),
        p if p == NODE_DIR => {
            names(&[("dev", DT_REG), ("uevent", DT_REG), ("device", DT_LNK), ("subsystem", DT_LNK)])
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Entry;

    /// `path` with its links followed, as `realpath` does: a component at a
    /// time, a link's target taken from where the link is.
    fn real(path: &str) -> String {
        let mut done = String::new();
        let mut rest: Vec<String> =
            path.split('/').filter(|c| !c.is_empty()).map(String::from).collect();
        rest.reverse();
        while let Some(c) = rest.pop() {
            match c.as_str() {
                "." => {}
                ".." => done.truncate(done.rfind('/').unwrap_or(0)),
                _ => {
                    let next = format!("{done}/{c}");
                    match entry(next.as_bytes()) {
                        Some(Entry::Symlink(t)) => {
                            let t = String::from_utf8(t).unwrap();
                            for c in t.split('/').filter(|c| !c.is_empty()).rev() {
                                rest.push(c.to_string());
                            }
                        }
                        _ => done = next,
                    }
                }
            }
        }
        done
    }

    fn link(path: &str) -> String {
        match entry(&within(path.as_bytes())) {
            Some(Entry::Symlink(t)) => String::from_utf8(t).unwrap(),
            _ => panic!("{path} is not a link"),
        }
    }

    fn file(path: &str) -> String {
        match entry(&within(path.as_bytes())) {
            Some(Entry::File(t)) => String::from_utf8(t).unwrap(),
            _ => panic!("{path} is not a file"),
        }
    }

    /// libdrm's way to the device (`drmGetDevices2`): the node is a DRM
    /// device, its bus virtio on PCI, its PCI slot and ids where it reads
    /// them.
    #[test]
    fn libdrm_finds_a_virtio_gpu_on_pci() {
        let node = "/sys/dev/char/226:128";
        assert!(matches!(entry(real(&format!("{node}/device/drm")).as_bytes()), Some(Entry::Dir)));
        // The same, as fwe's `/sys` is asked for it: the path whole.
        assert!(matches!(
            entry(&within(format!("{node}/device/drm").as_bytes())),
            Some(Entry::Dir)
        ));
        let device = real(&format!("{node}/device"));
        assert_eq!(device, "/sys/devices/pci0000:00/0000:00:02.0/virtio0");
        assert!(link(&format!("{device}/subsystem")).ends_with("/virtio"));
        let pci = device.strip_suffix("/virtio0").unwrap();
        assert!(link(&format!("{pci}/subsystem")).ends_with("/pci"));
        assert_eq!(real(&format!("{pci}/subsystem")), "/sys/bus/pci");
        assert!(file(&format!("{pci}/uevent")).contains("PCI_SLOT_NAME=0000:00:02.0\n"));
        assert_eq!(file(&format!("{pci}/vendor")), "0x1af4\n");
        assert_eq!(file(&format!("{pci}/device")), "0x1050\n");
        assert_eq!(file(&format!("{node}/dev")), "226:128\n");
        assert_eq!(real("/sys/class/drm/renderD128"), real(node));
        assert_eq!(real(&format!("{node}/subsystem")), "/sys/class/drm");
        let names = |p: &str| -> Vec<String> {
            listing(p.as_bytes())
                .unwrap()
                .into_iter()
                .map(|(n, _)| String::from_utf8(n).unwrap())
                .collect()
        };
        assert_eq!(names(&format!("{device}/drm")), ["renderD128"]);
        for (dir, names) in [("/sys/dev/char", names("/sys/dev/char")), (pci, names(pci))] {
            for n in names {
                assert!(entry(format!("{dir}/{n}").as_bytes()).is_some(), "{dir}/{n} is listed");
            }
        }
    }

    /// `DRM_IOCTL_VERSION`, asked twice as `drmGetVersion` asks: the
    /// lengths first, then the text into buffers that size.
    #[test]
    fn the_version_names_virtio_gpu() {
        let req = (3u64 << 30) | ((VERSION_SIZE as u64) << 16) | (TYPE << 8) | NR_VERSION;
        let mut v = [0u8; VERSION_SIZE];
        version(req, v.as_mut_ptr() as u64).unwrap();
        assert_eq!(u64_at(&v, VERSION_NAME_LEN), 10);
        let mut name = [0u8; 10];
        put_u64(&mut v, VERSION_NAME, name.as_mut_ptr() as u64);
        version(req, v.as_mut_ptr() as u64).unwrap();
        assert_eq!(&name, b"virtio_gpu");
        assert_eq!(u32_at(&v, VERSION_MAJOR), 0);
        // A caller whose structure is shorter gets as much as it has.
        let short = (3u64 << 30) | (8 << 16) | (TYPE << 8) | NR_VERSION;
        let mut s = [0xffu8; 12];
        version(short, s.as_mut_ptr() as u64).unwrap();
        assert_eq!(&s[8..], &[0xff; 4], "nothing past its 8 bytes");
    }
}
