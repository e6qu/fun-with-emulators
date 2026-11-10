//! Loop devices: `/dev/loop-control` and the block devices `/dev/loopN`,
//! each showing a file's contents, from an offset and up to a size limit.
//!
//! Linux's loop devices are the kernel's, the same for every process; so
//! are fwe's: their state is a shared record ([`crate::shared`]) of which
//! devices exist and what each is attached to (the file's host path and
//! identity, the guest path it was attached by, the offset, size limit,
//! flags and block size). A process reads and writes a device through the
//! file at that path, opened for the call, so the file must stay at its
//! path while attached (Linux holds it open; fwe cannot reach one unlinked).
//!
//! The device nodes are fwe's ([`crate::devnodes`]): block 7:N and
//! character 10:237, in the rootfs's `/dev` as the standard nodes are
//! ([`crate::fs`]), or wherever `mknod` makes them. An open device is a
//! descriptor of its node file, marked ([`Mark::Loop`]): the host keeps its
//! position, shared through `dup` and `fork` as Linux shares it, and fwe
//! carries out its reads, writes, seeks, syncs, `fallocate`, mappings and
//! requests on the attached file. `/sys/block/loopN` and `/proc/partitions`
//! show the devices.
//!
//! fwe does not count a device's openers across processes, so
//! `LOOP_CLR_FD` detaches at once (Linux waits for the last close when
//! another opener remains); the device is then run down, as Linux's is
//! when the caller is its only opener, until the caller's descriptors of
//! it close or the caller ends: another `LOOP_CLR_FD` finds nothing
//! attached (`ENXIO`), and no one attaches it (`EBUSY`) or is given it as
//! free, so a detach retried until `ENXIO` never detaches what another
//! process attached after it, `LO_FLAGS_AUTOCLEAR` is kept and shown but
//! detaches nothing on the last close, and `LOOP_CTL_REMOVE` removes an
//! unattached device even while open. A device `LOOP_CTL_GET_FREE` named is
//! not named to another process for a few seconds, until it is attached,
//! or until the process that asked ends: tests that each look for a free
//! device and attach it, run side by side, then get different ones (on
//! Linux they race).

use crate::fdmarks::{self, Mark};
use crate::procfs::{DT_DIR, DT_LNK, DT_REG, Entry};
use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use crate::{Kernel, Platform, uaccess};
use fwe_abi::loopdev::*;
use fwe_abi::{err, errno, ioctl};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

/// The block major number of loop devices, and `/dev/loop-control`'s
/// numbers.
pub const MAJOR: u32 = 7;
pub const CONTROL_MAJOR: u32 = 10;
pub const CONTROL_MINOR: u32 = 237;
/// The devices there are at first (Linux's `CONFIG_BLK_DEV_LOOP_MIN_COUNT`).
const MIN_COUNT: u32 = 8;
/// One past the highest device number (a minor number's range).
const MAX_DEVICES: u64 = 1 << 20;
const SECTOR: u64 = 512;
/// The page size block devices count read-ahead in.
const PAGE: u64 = 4096;
/// A new device's read-ahead in pages (Linux's 128 KiB).
const DEFAULT_RA_PAGES: u64 = 32;
/// The largest logical block size (Linux's `BLK_MAX_BLOCK_SIZE`).
const MAX_BLOCK_SIZE: u64 = 64 * 1024;
/// The most sectors one request carries (`BLKSECTGET`).
const MAX_SECTORS: u16 = 2560;
/// The flags `LOOP_SET_STATUS` sets, those it may clear, and those
/// `LOOP_CONFIGURE` takes.
const SETTABLE: u32 = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN;
const CLEARABLE: u32 = LO_FLAGS_AUTOCLEAR;
const CONFIGURE_SETTABLE: u32 =
    LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO;
/// How long a device `LOOP_CTL_GET_FREE` named is kept for the process
/// that asked, in seconds.
const CLAIM: u64 = 10;

/// What a device shows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Backing {
    /// A file, at host path `host` with host identity `dev`, `ino`.
    File { host: Vec<u8>, dev: u64, ino: u64 },
    /// Another loop device.
    Loop(u32),
}

/// A device's attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    backing: Backing,
    /// The guest path the file was attached by (`backing_file`).
    path: Vec<u8>,
    /// The file's numbers, as Linux's `stat` gives them.
    st_dev: u64,
    st_ino: u64,
    st_rdev: u64,
    /// `lo_file_name` and `lo_crypt_name`, as last set.
    file_name: [u8; LO_NAME_SIZE],
    crypt_name: [u8; LO_NAME_SIZE],
    offset: u64,
    sizelimit: u64,
    flags: u32,
    block_size: u32,
    /// The device's size in bytes, whole sectors: worked out when it is
    /// attached and when the offset, size limit or capacity is set.
    size: u64,
}

/// One device.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Device {
    /// Read-ahead, in pages (`BLKRASET`).
    ra_pages: u64,
    /// Made read-only by `BLKROSET`.
    read_only: bool,
    /// The block size `BLKBSZSET` set (0: from the size, as Linux picks).
    soft_block: u32,
    /// The disk sequence number, new with each attach and detach.
    diskseq: u64,
    /// The host process `LOOP_CTL_GET_FREE` named it to, and when.
    claim: Option<(i32, u64)>,
    /// The host process whose `LOOP_CLR_FD` detached it, while that
    /// process holds it open (run down: not to be attached again yet).
    rundown: Option<i32>,
    bound: Option<Binding>,
}

impl Device {
    /// Whether it is run down by a process that still holds it.
    fn run_down(&self) -> bool {
        self.rundown.is_some_and(alive)
    }
}

/// Every loop device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Loops {
    devices: BTreeMap<u32, Device>,
    /// The last disk sequence number given.
    seq: u64,
}

impl Loops {
    fn initial() -> Loops {
        let mut l = Loops::default();
        for n in 0..MIN_COUNT {
            l.add(n);
        }
        l
    }

    fn add(&mut self, n: u32) {
        self.seq += 1;
        let d = Device {
            ra_pages: DEFAULT_RA_PAGES,
            read_only: false,
            soft_block: 0,
            diskseq: self.seq,
            claim: None,
            rundown: None,
            bound: None,
        };
        self.devices.insert(n, d);
    }
}

impl Data for Loops {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.seq);
        e.u64(self.devices.len() as u64);
        for (&n, d) in &self.devices {
            e.u32(n);
            e.u64(d.ra_pages);
            e.bool(d.read_only);
            e.u32(d.soft_block);
            e.u64(d.diskseq);
            e.bool(d.claim.is_some());
            let (pid, at) = d.claim.unwrap_or_default();
            e.i32(pid);
            e.u64(at);
            e.i32(d.rundown.unwrap_or(0));
            e.bool(d.bound.is_some());
            if let Some(b) = &d.bound {
                match &b.backing {
                    Backing::File { host, dev, ino } => {
                        e.u8(0);
                        e.bytes(host);
                        e.u64(*dev);
                        e.u64(*ino);
                    }
                    Backing::Loop(m) => {
                        e.u8(1);
                        e.u32(*m);
                    }
                }
                e.bytes(&b.path);
                e.u64(b.st_dev);
                e.u64(b.st_ino);
                e.u64(b.st_rdev);
                e.bytes(&b.file_name);
                e.bytes(&b.crypt_name);
                e.u64(b.offset);
                e.u64(b.sizelimit);
                e.u32(b.flags);
                e.u32(b.block_size);
                e.u64(b.size);
            }
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let seq = d.u64();
        let mut devices = BTreeMap::new();
        // An unattached device's 43 bytes at least.
        for _ in 0..d.count(43) {
            let n = d.u32();
            let (ra_pages, read_only, soft_block, diskseq) = (d.u64(), d.bool(), d.u32(), d.u64());
            let (claimed, pid, at) = (d.bool(), d.i32(), d.u64());
            let rundown = Some(d.i32()).filter(|&p| p != 0);
            let bound = d.bool().then(|| {
                let backing = match d.u8() {
                    0 => Backing::File { host: d.bytes(), dev: d.u64(), ino: d.u64() },
                    _ => Backing::Loop(d.u32()),
                };
                let name = |d: &mut Dec| {
                    let mut a = [0u8; LO_NAME_SIZE];
                    let b = d.bytes();
                    let n = b.len().min(LO_NAME_SIZE);
                    a[..n].copy_from_slice(&b[..n]);
                    a
                };
                Binding {
                    backing,
                    path: d.bytes(),
                    st_dev: d.u64(),
                    st_ino: d.u64(),
                    st_rdev: d.u64(),
                    file_name: name(d),
                    crypt_name: name(d),
                    offset: d.u64(),
                    sizelimit: d.u64(),
                    flags: d.u32(),
                    block_size: d.u32(),
                    size: d.u64(),
                }
            });
            let claim = claimed.then_some((pid, at));
            devices.insert(
                n,
                Device { ra_pages, read_only, soft_block, diskseq, claim, rundown, bound },
            );
        }
        Loops { devices, seq }
    }
}

/// The shared record, made with the initial devices on first use.
fn record() -> Result<&'static Record<Loops>, i32> {
    static RECORD: std::sync::OnceLock<Result<Record<Loops>, i32>> = std::sync::OnceLock::new();
    RECORD.get_or_init(|| Record::named("loop", 0, Loops::initial)).as_ref().map_err(|&e| e)
}

fn state() -> Result<Arc<Loops>, i32> {
    Ok(record()?.get())
}

fn update<R>(f: impl FnOnce(&mut Loops) -> Result<R, i32>) -> Result<R, i32> {
    record()?.update(f)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn host_pid() -> i32 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() }
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks the process exists.
    unsafe { libc::kill(pid, 0) == 0 || crate::host::last_errno() == libc::EPERM }
}

/// Descriptor `fd` is being closed: a device this process ran down
/// ([`Device::rundown`]) may be attached again once none of its
/// descriptors holds it.
pub fn closed(fd: i32) {
    let Some(Mark::Loop(n)) = fdmarks::marked(fd) else { return };
    if fdmarks::marks().iter().any(|&(o, m)| o != fd && m == Mark::Loop(n)) {
        return;
    }
    let me = host_pid();
    let mine = |l: &Loops| l.devices.get(&n).is_some_and(|d| d.rundown == Some(me));
    if state().is_ok_and(|l| mine(&l)) {
        let _ = update(|l| {
            if let Some(d) = l.devices.get_mut(&n)
                && d.rundown == Some(me)
            {
                d.rundown = None;
            }
            Ok(())
        });
    }
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

// --- Device nodes ---

/// The device node `/dev/<name>` names, for the loop devices' names:
/// `loop-control`, and `loopN` for a device that exists.
pub fn node_named(name: &[u8]) -> Option<crate::devnodes::Node> {
    use crate::devnodes::{Node, S_IFBLK, S_IFCHR};
    if name == b"loop-control" {
        return Some(Node { kind: S_IFCHR, major: CONTROL_MAJOR, minor: CONTROL_MINOR });
    }
    let digits = name.strip_prefix(b"loop")?;
    if digits.is_empty() || (digits[0] == b'0' && digits.len() > 1) {
        return None;
    }
    let n: u32 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    state().ok()?.devices.contains_key(&n).then_some(Node { kind: S_IFBLK, major: MAJOR, minor: n })
}

/// Whether `node` is a loop device or `/dev/loop-control`.
pub fn is_loop_node(node: crate::devnodes::Node) -> bool {
    use crate::devnodes::{S_IFBLK, S_IFCHR};
    (node.kind == S_IFBLK && node.major == MAJOR)
        || (node.kind == S_IFCHR && node.major == CONTROL_MAJOR && node.minor == CONTROL_MINOR)
}

/// Open `node` (a loop node, [`is_loop_node`]) on its node file's
/// descriptor `fd`: `ENXIO` for a device that does not exist.
pub fn check_open(node: crate::devnodes::Node) -> Result<(), i32> {
    if node.kind == crate::devnodes::S_IFCHR {
        return Ok(());
    }
    if state()?.devices.contains_key(&node.minor) { Ok(()) } else { Err(errno::ENXIO) }
}

/// `fd` was opened on the loop node `node`: mark it.
pub fn opened(fd: i32, node: crate::devnodes::Node) {
    let mark = if node.kind == crate::devnodes::S_IFCHR {
        Mark::LoopControl
    } else {
        Mark::Loop(node.minor)
    };
    fdmarks::mark(fd, mark);
}

/// What `fd` is open on, if it is a loop device (`Some(n)`) or
/// `/dev/loop-control` (`None`).
fn opened_on(fd: i32) -> Option<Option<u32>> {
    if !fdmarks::any_marks() {
        return None;
    }
    match fdmarks::marked(fd)? {
        Mark::Loop(n) => Some(Some(n)),
        Mark::LoopControl => Some(None),
        _ => None,
    }
}

/// The loop device `fd` is open on, if it is one.
pub fn device_of(fd: i32) -> Option<u32> {
    opened_on(fd).flatten()
}

/// Whether `fd` is open on `/dev/loop-control`.
pub fn is_control(fd: i32) -> bool {
    opened_on(fd) == Some(None)
}

/// `ftruncate` on a loop device or `/dev/loop-control`, which only a
/// regular file takes (`None` for another descriptor).
pub fn ftruncate(fd: i32) -> Option<i64> {
    opened_on(fd).map(|_| err(errno::EINVAL))
}

// --- Data ---

/// A descriptor fwe holds for the call it is in, out of the guest's range.
fn transient(fd: i32) -> Result<OwnedFd, i32> {
    if fd < 0 {
        return Err(last());
    }
    let high = crate::fdtable::dup_transient(fd);
    // SAFETY: closing the descriptor just opened, now moved (or not wanted).
    unsafe { libc::close(fd) };
    // SAFETY: a fresh descriptor fwe owns.
    high.map(|h| unsafe { OwnedFd::from_raw_fd(h) })
}

/// The attached file, open for writing if `write`: `EIO` if another file
/// has taken its path.
fn open_file(host: &[u8], dev: u64, ino: u64, write: bool) -> Result<OwnedFd, i32> {
    let c = std::ffi::CString::new(host).map_err(|_| errno::EIO)?;
    let mode = if write { libc::O_RDWR } else { libc::O_RDONLY };
    // SAFETY: a NUL-terminated path; the result is checked.
    let fd = transient(unsafe { libc::open(c.as_ptr(), mode | libc::O_CLOEXEC) })
        .map_err(|e| if e == errno::ENOENT { errno::EIO } else { e })?;
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
        || (st.st_dev as u64, st.st_ino as u64) != (dev, ino)
    {
        return Err(errno::EIO);
    }
    Ok(fd)
}

/// The size of what `backing` holds, in bytes.
fn backing_size(loops: &Loops, backing: &Backing) -> Result<u64, i32> {
    match backing {
        Backing::File { host, dev, ino } => {
            let f = open_file(host, *dev, *ino, false)?;
            // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a valid out-parameter.
            if unsafe { libc::fstat(f.as_raw_fd(), &mut st) } != 0 {
                return Err(last());
            }
            Ok(st.st_size.max(0) as u64)
        }
        Backing::Loop(m) => {
            Ok(loops.devices.get(m).and_then(|d| d.bound.as_ref()).map_or(0, |b| b.size))
        }
    }
}

/// A device's size for a file of `file_size` bytes, as Linux works it out:
/// what follows the offset, no more than the size limit, in whole sectors.
fn device_size(file_size: u64, offset: u64, sizelimit: u64) -> u64 {
    let mut size = file_size.saturating_sub(offset);
    if sizelimit > 0 && sizelimit < size {
        size = sizelimit;
    }
    size & !(SECTOR - 1)
}

/// A device's size in bytes (0 when it is not attached).
fn size_of(loops: &Loops, n: u32) -> u64 {
    loops.devices.get(&n).and_then(|d| d.bound.as_ref()).map_or(0, |b| b.size)
}

/// Whether writes to device `n` are refused.
fn read_only(d: &Device) -> bool {
    d.read_only || d.bound.as_ref().is_some_and(|b| b.flags & LO_FLAGS_READ_ONLY != 0)
}

/// Fill `len` bytes at host address `buf` (checked guest memory) with
/// zeros.
fn zeros_into(buf: *mut u8, len: usize) -> Result<(), i32> {
    // SAFETY: a constant NUL-terminated path.
    let zero =
        transient(unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })?;
    let mut done = 0;
    while done < len {
        // SAFETY: the host checks the buffer and reports a fault.
        let r = unsafe { libc::read(zero.as_raw_fd(), buf.add(done).cast(), len - done) };
        if r <= 0 {
            return Err(if r < 0 { last() } else { errno::EIO });
        }
        done += r as usize;
    }
    Ok(())
}

/// Read up to `len` bytes of device `n` at `pos` into host address `buf`
/// (checked guest memory): how many, short only at the device's end.
fn read_at(loops: &Loops, n: u32, pos: u64, buf: *mut u8, len: usize) -> Result<usize, i32> {
    let d = loops.devices.get(&n).ok_or(errno::ENXIO)?;
    let Some(b) = &d.bound else { return Ok(0) };
    if pos >= b.size || len == 0 {
        return Ok(0);
    }
    let len = len.min((b.size - pos) as usize);
    let at = b.offset + pos;
    let got = match &b.backing {
        Backing::Loop(m) => read_at(loops, *m, at, buf, len)?,
        Backing::File { host, dev, ino } => {
            let f = open_file(host, *dev, *ino, false)?;
            let mut got = 0;
            while got < len {
                // SAFETY: the host checks the buffer and reports a fault.
                let r = unsafe {
                    libc::pread(
                        f.as_raw_fd(),
                        buf.add(got).cast(),
                        len - got,
                        (at + got as u64) as libc::off_t,
                    )
                };
                if r < 0 {
                    if got == 0 {
                        return Err(last());
                    }
                    return Ok(got);
                }
                if r == 0 {
                    break;
                }
                got += r as usize;
            }
            got
        }
    };
    // Past the end of a file that has shrunk: zeros, as Linux reads them.
    if got < len {
        // SAFETY: within the buffer the caller gave.
        zeros_into(unsafe { buf.add(got) }, len - got)?;
    }
    Ok(len)
}

/// Write up to `len` bytes from host address `buf` (checked guest memory)
/// to device `n` at `pos`: how many, short only at the device's end.
fn write_at(loops: &Loops, n: u32, pos: u64, buf: *const u8, len: usize) -> Result<usize, i32> {
    let d = loops.devices.get(&n).ok_or(errno::ENXIO)?;
    if read_only(d) {
        return Err(errno::EPERM);
    }
    let size = d.bound.as_ref().map_or(0, |b| b.size);
    if len == 0 {
        return Ok(0);
    }
    if pos >= size {
        return Err(errno::ENOSPC);
    }
    let Some(b) = &d.bound else { return Err(errno::ENOSPC) };
    let len = len.min((size - pos) as usize);
    let at = b.offset + pos;
    match &b.backing {
        Backing::Loop(m) => write_at(loops, *m, at, buf, len),
        Backing::File { host, dev, ino } => {
            let f = open_file(host, *dev, *ino, true)?;
            let mut done = 0;
            while done < len {
                // SAFETY: the host checks the buffer and reports a fault.
                let r = unsafe {
                    libc::pwrite(
                        f.as_raw_fd(),
                        buf.add(done).cast(),
                        len - done,
                        (at + done as u64) as libc::off_t,
                    )
                };
                if r <= 0 {
                    if done == 0 {
                        return Err(if r < 0 { last() } else { errno::EIO });
                    }
                    break;
                }
                done += r as usize;
            }
            Ok(done)
        }
    }
}

/// Write zeros over `len` bytes of device `n` at `pos` (a discard or a
/// zeroing request, checked by the caller).
fn zero_range(loops: &Loops, n: u32, pos: u64, len: u64) -> Result<(), i32> {
    let zeros = vec![0u8; 1 << 16];
    let mut done = 0;
    while done < len {
        let want = (len - done).min(zeros.len() as u64) as usize;
        let w = write_at(loops, n, pos + done, zeros.as_ptr(), want)?;
        if w == 0 {
            return Err(errno::EIO);
        }
        done += w as u64;
    }
    Ok(())
}

/// Sync what device `n` shows to its file.
fn sync(loops: &Loops, n: u32) -> Result<(), i32> {
    let Some(b) = loops.devices.get(&n).and_then(|d| d.bound.as_ref()) else { return Ok(()) };
    match &b.backing {
        Backing::Loop(m) => sync(loops, *m),
        Backing::File { host, dev, ino } => {
            let f = open_file(host, *dev, *ino, false)?;
            // SAFETY: plain host call on the descriptor just opened.
            if unsafe { libc::fsync(f.as_raw_fd()) } != 0 { Err(last()) } else { Ok(()) }
        }
    }
}

/// The access mode `fd` was opened with: whether it reads, whether it
/// writes.
fn access(fd: i32) -> Result<(bool, bool), i32> {
    // SAFETY: plain host call on the guest's descriptor.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(last());
    }
    Ok(match fl & libc::O_ACCMODE {
        libc::O_RDONLY => (true, false),
        libc::O_WRONLY => (false, true),
        _ => (true, true),
    })
}

/// A read or write on a loop device of the buffers `iov`, at `pos` or
/// (`None`) at the descriptor's position, which then moves past what was
/// moved.
fn transfer(fd: i32, n: u32, iov: &[libc::iovec], pos: Option<u64>, write: bool) -> i64 {
    let (reads, writes) = match access(fd) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    if !(if write { writes } else { reads }) {
        return err(errno::EBADF);
    }
    let start = match pos {
        Some(p) => p,
        // SAFETY: plain host call on the guest's descriptor.
        None => match unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } {
            p if p < 0 => return err(last()),
            p => p as u64,
        },
    };
    let loops = match state() {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let mut done: u64 = 0;
    for v in iov.iter().filter(|v| v.iov_len > 0) {
        let at = start + done;
        let r = if write {
            write_at(&loops, n, at, v.iov_base as *const u8, v.iov_len)
        } else {
            read_at(&loops, n, at, v.iov_base as *mut u8, v.iov_len)
        };
        match r {
            Ok(k) => {
                done += k as u64;
                if k < v.iov_len {
                    break;
                }
            }
            Err(e) if done == 0 => return err(e),
            Err(_) => break,
        }
    }
    if pos.is_none() {
        // SAFETY: plain host call on the guest's descriptor.
        unsafe { libc::lseek(fd, (start + done) as libc::off_t, libc::SEEK_SET) };
    }
    done as i64
}

/// The reads and writes (`read`, `pread64`, `readv`, `preadv`, `preadv2`
/// and the writes alike) on a loop device: `None` for another descriptor.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    let single = matches!(nr, n::READ | n::WRITE | n::PREAD64 | n::PWRITE64);
    let vectored =
        matches!(nr, n::READV | n::WRITEV | n::PREADV | n::PWRITEV | n::PREADV2 | n::PWRITEV2);
    if !single && !vectored {
        return None;
    }
    // `/dev/loop-control` is neither read nor written.
    let Some(dev) = opened_on(a[0] as i32)? else { return Some(err(errno::EINVAL)) };
    let write = matches!(nr, n::WRITE | n::WRITEV | n::PWRITE64 | n::PWRITEV | n::PWRITEV2);
    let pos = match nr {
        n::READ | n::WRITE | n::READV | n::WRITEV => None,
        n::PREADV2 | n::PWRITEV2 if a[3] as i64 == -1 => None,
        _ if (a[3] as i64) < 0 => return Some(err(errno::EINVAL)),
        _ => Some(a[3]),
    };
    if matches!(nr, n::PREADV2 | n::PWRITEV2) {
        use fwe_abi::rwf;
        if a[5] & !(rwf::HIPRI | rwf::DSYNC | rwf::SYNC | rwf::NOWAIT) != 0 {
            return Some(err(errno::EOPNOTSUPP));
        }
    }
    let bufs = if single {
        uaccess::host_buffer(a[1], a[2], !write).map(|v| vec![v])
    } else {
        uaccess::host_iovecs(a[1], a[2], !write)
    };
    Some(match bufs {
        Ok(iov) => transfer(a[0] as i32, dev, &iov, pos, write),
        Err(e) => err(e),
    })
}

/// `lseek` on a loop device, within the device as Linux keeps it: `None`
/// for another descriptor.
pub fn lseek(fd: i32, off: i64, whence: i32) -> Option<i64> {
    let n = device_of(fd)?;
    let size = match state() {
        Ok(l) => size_of(&l, n) as i64,
        Err(e) => return Some(err(e)),
    };
    // SAFETY: plain host call on the guest's descriptor.
    let cur = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if cur < 0 {
        return Some(err(last()));
    }
    const SEEK_DATA: i32 = 3;
    const SEEK_HOLE: i32 = 4;
    let new = match whence {
        libc::SEEK_SET => off,
        libc::SEEK_CUR if off == 0 => return Some(cur),
        libc::SEEK_CUR => cur.saturating_add(off),
        libc::SEEK_END => size.saturating_add(off),
        SEEK_DATA | SEEK_HOLE if off < 0 || off >= size => return Some(err(errno::ENXIO)),
        SEEK_DATA => off,
        SEEK_HOLE => size,
        _ => return Some(err(errno::EINVAL)),
    };
    if new < 0 || new > size {
        return Some(err(errno::EINVAL));
    }
    // SAFETY: as above.
    Some(crate::host::ret(unsafe { libc::lseek(fd, new as libc::off_t, libc::SEEK_SET) }))
}

/// `fsync` and `fdatasync` on a loop device: `None` for another.
pub fn fsync(fd: i32) -> Option<i64> {
    let Some(n) = opened_on(fd)? else { return Some(err(errno::EINVAL)) };
    Some(match state().and_then(|l| sync(&l, n)) {
        Ok(()) => 0,
        Err(e) => err(e),
    })
}

/// `fallocate` on a loop device, which zeroes a range (`None` for another
/// descriptor).
pub fn fallocate(fd: i32, mode: u64, offset: u64, len: u64) -> Option<i64> {
    use fwe_abi::falloc::*;
    let Some(n) = opened_on(fd)? else { return Some(err(errno::ENODEV)) };
    const NO_HIDE_STALE: u64 = 0x04;
    // Every fallocate mode Linux knows, of which a block device does a few.
    const KNOWN: u64 = 0xff;
    let r = (|| {
        // In Linux's order: the range, the mode, the descriptor, overflow,
        // then what a block device does.
        if (offset as i64) < 0 || (len as i64) <= 0 {
            return Err(errno::EINVAL);
        }
        if mode & !KNOWN != 0 {
            return Err(errno::EOPNOTSUPP);
        }
        if !access(fd)?.1 {
            return Err(errno::EBADF);
        }
        if (offset as i64).checked_add(len as i64).is_none() {
            return Err(errno::EFBIG);
        }
        if mode
            & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | NO_HIDE_STALE | FALLOC_FL_ZERO_RANGE)
            != 0
        {
            return Err(errno::EOPNOTSUPP);
        }
        let loops = state()?;
        let size = size_of(&loops, n);
        if offset >= size {
            return Err(errno::EINVAL);
        }
        let mut len = len;
        if offset.saturating_add(len) > size {
            if mode & FALLOC_FL_KEEP_SIZE == 0 {
                return Err(errno::EINVAL);
            }
            len = size - offset;
        }
        let bs = loops.devices[&n].bound.as_ref().map_or(SECTOR, |b| b.block_size as u64);
        if (offset | len) & (bs - 1) != 0 {
            return Err(errno::EINVAL);
        }
        match mode & !NO_HIDE_STALE {
            FALLOC_FL_ZERO_RANGE => {}
            m if m == FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE => {}
            m if m == FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE => {}
            _ => return Err(errno::EOPNOTSUPP),
        }
        zero_range(&loops, n, offset, len)
    })();
    Some(match r {
        Ok(()) => 0,
        Err(e) => err(e),
    })
}

/// What a mapping of loop device descriptor `fd` maps instead: the attached
/// file, open as `fd` is, and where the device starts in it (`None` for
/// another descriptor). The device's start must fall on a page of
/// `page_size` bytes, the host's mappings' grain (`EINVAL`).
pub fn map_source(fd: i32, page_size: u64) -> Option<Result<(OwnedFd, u64), i32>> {
    let Some(n) = opened_on(fd)? else { return Some(Err(errno::ENODEV)) };
    Some((|| {
        let (reads, write) = access(fd)?;
        // A mapping reads the device.
        if !reads {
            return Err(errno::EACCES);
        }
        let loops = state()?;
        let (mut n, mut start) = (n, 0u64);
        loop {
            let b = loops.devices.get(&n).and_then(|d| d.bound.as_ref()).ok_or(errno::ENXIO)?;
            start += b.offset;
            match &b.backing {
                Backing::Loop(m) => n = *m,
                Backing::File { host, dev, ino } => {
                    if start % page_size != 0 {
                        return Err(errno::EINVAL);
                    }
                    let write = write && !read_only(&loops.devices[&n]);
                    return Ok((open_file(host, *dev, *ino, write)?, start));
                }
            }
        }
    })())
}

/// For `sendfile` and `splice`: read up to `len` bytes of the loop device `fd` is open
/// on into `buf`, at `pos` or at the descriptor's position (`None` for
/// another descriptor).
pub fn read_into(fd: i32, buf: &mut [u8], pos: Option<u64>) -> Option<i64> {
    let n = device_of(fd)?;
    let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    Some(transfer(fd, n, &[iov], pos, false))
}

/// For `sendfile` and `splice`: write `buf` to the loop device `fd` is
/// open on, at `pos` or at the descriptor's position (`None` for another
/// descriptor).
pub fn write_at_pos(fd: i32, buf: &[u8], pos: Option<u64>) -> Option<i64> {
    let n = device_of(fd)?;
    let iov = libc::iovec { iov_base: buf.as_ptr() as *mut _, iov_len: buf.len() };
    Some(transfer(fd, n, &[iov], pos, true))
}

// --- Requests ---

/// What a `loop_info64` (or `loop_info`) sets: its device and inode
/// numbers are the device's to report, not to set.
struct Info {
    offset: u64,
    sizelimit: u64,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; LO_NAME_SIZE],
    crypt_name: [u8; LO_NAME_SIZE],
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn name_at(b: &[u8], at: usize) -> [u8; LO_NAME_SIZE] {
    let mut n = [0u8; LO_NAME_SIZE];
    n.copy_from_slice(&b[at..at + LO_NAME_SIZE]);
    n[LO_NAME_SIZE - 1] = 0;
    n
}

impl Info {
    fn empty() -> Info {
        Info {
            offset: 0,
            sizelimit: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: 0,
            file_name: [0; LO_NAME_SIZE],
            crypt_name: [0; LO_NAME_SIZE],
        }
    }

    /// A `struct loop_info64`.
    fn from64(b: &[u8]) -> Info {
        Info {
            offset: u64_at(b, INFO64_OFFSET),
            sizelimit: u64_at(b, INFO64_SIZELIMIT),
            encrypt_type: u32_at(b, INFO64_ENCRYPT_TYPE),
            encrypt_key_size: u32_at(b, INFO64_ENCRYPT_KEY_SIZE),
            flags: u32_at(b, INFO64_FLAGS),
            file_name: name_at(b, INFO64_FILE_NAME),
            crypt_name: name_at(b, INFO64_CRYPT_NAME),
        }
    }

    /// A `struct loop_info`, as Linux widens it: the offset sign-extended,
    /// no size limit.
    fn from_old(b: &[u8]) -> Info {
        Info {
            offset: u32_at(b, OLD_OFFSET) as i32 as i64 as u64,
            sizelimit: 0,
            encrypt_type: u32_at(b, OLD_ENCRYPT_TYPE),
            encrypt_key_size: u32_at(b, OLD_ENCRYPT_KEY_SIZE),
            flags: u32_at(b, OLD_FLAGS),
            file_name: name_at(b, OLD_NAME),
            crypt_name: [0; LO_NAME_SIZE],
        }
    }

    /// Linux's checks of what a status sets: no encryption, and offsets
    /// that fit a file offset.
    fn check(&self) -> Result<(), i32> {
        if self.encrypt_key_size as usize > LO_KEY_SIZE || self.encrypt_type != 0 {
            return Err(errno::EINVAL);
        }
        if self.offset > i64::MAX as u64 || self.sizelimit > i64::MAX as u64 {
            return Err(errno::EOVERFLOW);
        }
        Ok(())
    }
}

/// A `struct loop_info64` of attachment `b` of device `n`.
fn status64(n: u32, b: &Binding) -> Vec<u8> {
    let mut o = vec![0u8; INFO64_SIZE];
    let mut put64 = |at: usize, v: u64| o[at..at + 8].copy_from_slice(&v.to_le_bytes());
    put64(INFO64_DEVICE, b.st_dev);
    put64(INFO64_INODE, b.st_ino);
    put64(INFO64_RDEVICE, b.st_rdev);
    put64(INFO64_OFFSET, b.offset);
    put64(INFO64_SIZELIMIT, b.sizelimit);
    o[INFO64_NUMBER..INFO64_NUMBER + 4].copy_from_slice(&n.to_le_bytes());
    o[INFO64_FLAGS..INFO64_FLAGS + 4].copy_from_slice(&b.flags.to_le_bytes());
    o[INFO64_FILE_NAME..INFO64_FILE_NAME + LO_NAME_SIZE].copy_from_slice(&b.file_name);
    o[INFO64_CRYPT_NAME..INFO64_CRYPT_NAME + LO_NAME_SIZE].copy_from_slice(&b.crypt_name);
    o
}

/// A `struct loop_info` of attachment `b` of device `n`: `EOVERFLOW` for
/// numbers it cannot hold.
fn status_old(n: u32, b: &Binding) -> Result<Vec<u8>, i32> {
    if b.st_dev > u32::MAX as u64 || b.st_rdev > u32::MAX as u64 || b.offset > i32::MAX as u64 {
        return Err(errno::EOVERFLOW);
    }
    let mut o = vec![0u8; OLD_SIZE];
    o[OLD_NUMBER..OLD_NUMBER + 4].copy_from_slice(&n.to_le_bytes());
    o[OLD_DEVICE..OLD_DEVICE + 4].copy_from_slice(&(b.st_dev as u32).to_le_bytes());
    o[OLD_INODE..OLD_INODE + 8].copy_from_slice(&b.st_ino.to_le_bytes());
    o[OLD_RDEVICE..OLD_RDEVICE + 4].copy_from_slice(&(b.st_rdev as u32).to_le_bytes());
    o[OLD_OFFSET..OLD_OFFSET + 4].copy_from_slice(&(b.offset as u32).to_le_bytes());
    o[OLD_FLAGS..OLD_FLAGS + 4].copy_from_slice(&b.flags.to_le_bytes());
    o[OLD_NAME..OLD_NAME + LO_NAME_SIZE].copy_from_slice(&b.file_name);
    Ok(o)
}

/// The flags `LOOP_SET_STATUS` leaves a device with `prev` set when asked
/// for `new`: those it may set as asked, except that what it may not clear
/// stays set, and the rest as they were.
fn status_flags(prev: u32, new: u32) -> u32 {
    (new & SETTABLE) | (prev & !SETTABLE) | (prev & !CLEARABLE)
}

/// Linux's check of a logical block size.
fn valid_block_size(bs: u64) -> bool {
    (SECTOR..=MAX_BLOCK_SIZE).contains(&bs) && bs.is_power_of_two()
}

/// The block size Linux gives a device of `size` bytes and logical block
/// size `logical` (`BLKBSZGET`), unless one was set.
fn soft_block(d: &Device) -> u32 {
    if d.soft_block != 0 {
        return d.soft_block;
    }
    let logical = d.bound.as_ref().map_or(SECTOR, |b| b.block_size as u64);
    let size = d.bound.as_ref().map_or(0, |b| b.size);
    let mut bs = logical;
    while bs < PAGE && size & bs == 0 {
        bs <<= 1;
    }
    bs as u32
}

/// What `LOOP_SET_FD`, `LOOP_CHANGE_FD` and `LOOP_CONFIGURE` attach: the
/// file (or loop device) open on guest descriptor `file`.
struct Attach {
    backing: Backing,
    path: Vec<u8>,
    st_dev: u64,
    st_ino: u64,
    st_rdev: u64,
    /// Whether it is open for writing.
    writable: bool,
}

/// Linux's check of a loop device `m` given as what device `n` is to
/// show: `EBADF` where its chain of loop devices comes back to `n`,
/// `EINVAL` where one in it is not attached.
fn check_chain(loops: &Loops, n: u32, m: u32) -> Result<(), i32> {
    let mut at = m;
    for _ in 0..=loops.devices.len() {
        if at == n {
            return Err(errno::EBADF);
        }
        let b = loops.devices.get(&at).and_then(|d| d.bound.as_ref()).ok_or(errno::EINVAL)?;
        match b.backing {
            Backing::Loop(next) => at = next,
            Backing::File { .. } => return Ok(()),
        }
    }
    Err(errno::EINVAL)
}

/// `EBADF` unless the guest has descriptor `fd` open.
fn check_fd(fd: i32) -> Result<(), i32> {
    // SAFETY: F_GETFD only queries the descriptor.
    if fd < 0 || !crate::fdtable::guest_visible(fd) || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
    {
        return Err(errno::EBADF);
    }
    Ok(())
}

impl<P: Platform> Kernel<P> {
    /// The file open on guest descriptor `fd` (checked with [`check_fd`]),
    /// to attach: `EINVAL` for one that is not a file or a block device.
    fn attach_source(&self, fd: i32) -> Result<Attach, i32> {
        let st = crate::fsops::linux_fstat(fd).map_err(|_| errno::EBADF)?;
        let (_, writable) = access(fd)?;
        let path = self.fs().fd_target(fd);
        if let Some(m) = device_of(fd) {
            return Ok(Attach {
                backing: Backing::Loop(m),
                path,
                st_dev: st.st_dev,
                st_ino: st.st_ino,
                st_rdev: st.st_rdev,
                writable,
            });
        }
        if st.st_mode & fwe_abi::stat::S_IFMT != fwe_abi::stat::S_IFREG
            || crate::specialfd::anon_name(fd).is_some()
        {
            return Err(errno::EINVAL);
        }
        let host = crate::fs::host_path_of(fd).ok_or(errno::EINVAL)?;
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut hs: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if unsafe { libc::fstat(fd, &mut hs) } != 0 {
            return Err(errno::EBADF);
        }
        Ok(Attach {
            backing: Backing::File { host, dev: hs.st_dev as u64, ino: hs.st_ino as u64 },
            path,
            st_dev: st.st_dev,
            st_ino: st.st_ino,
            st_rdev: st.st_rdev,
            writable,
        })
    }

    /// `LOOP_SET_FD` (`config` `None`) and `LOOP_CONFIGURE` on device `n`,
    /// open on `dev_fd`.
    fn attach(
        &self,
        dev_fd: i32,
        n: u32,
        file: i32,
        config: Option<(u32, Info)>,
    ) -> Result<i64, i32> {
        check_fd(file)?;
        let dev_writes = access(dev_fd)?.1;
        update(|l| {
            let d = l.devices.get(&n).ok_or(errno::ENXIO)?;
            if d.bound.is_some() || d.run_down() && d.rundown != Some(host_pid()) {
                return Err(errno::EBUSY);
            }
            let a = self.attach_source(file)?;
            if let Backing::Loop(m) = a.backing {
                check_chain(l, n, m)?;
            }
            let (block_size, info) = config.unwrap_or((0, Info::empty()));
            if info.flags & !CONFIGURE_SETTABLE != 0 {
                return Err(errno::EINVAL);
            }
            info.check()?;
            if block_size != 0 && !valid_block_size(block_size as u64) {
                return Err(errno::EINVAL);
            }
            let mut flags = info.flags;
            if !a.writable || !dev_writes {
                flags |= LO_FLAGS_READ_ONLY;
            }
            let file_size = backing_size(l, &a.backing)?;
            let size = device_size(file_size, info.offset, info.sizelimit);
            l.seq += 1;
            let seq = l.seq;
            let d = l.devices.get_mut(&n).ok_or(errno::ENXIO)?;
            d.claim = None;
            d.rundown = None;
            d.soft_block = 0;
            d.diskseq = seq;
            d.bound = Some(Binding {
                backing: a.backing.clone(),
                path: a.path.clone(),
                st_dev: a.st_dev,
                st_ino: a.st_ino,
                st_rdev: a.st_rdev,
                file_name: info.file_name,
                crypt_name: info.crypt_name,
                offset: info.offset,
                sizelimit: info.sizelimit,
                flags,
                block_size: if block_size == 0 { SECTOR as u32 } else { block_size },
                size,
            });
            Ok(0)
        })
    }

    /// `LOOP_CHANGE_FD`: a read-only device's file swapped for another of
    /// the same size.
    fn change_fd(&self, n: u32, file: i32) -> Result<i64, i32> {
        check_fd(file)?;
        update(|l| {
            let b = l.devices.get(&n).and_then(|d| d.bound.as_ref()).ok_or(errno::ENXIO)?;
            if b.flags & LO_FLAGS_READ_ONLY == 0 {
                return Err(errno::EINVAL);
            }
            let a = self.attach_source(file)?;
            if let Backing::Loop(m) = a.backing {
                check_chain(l, n, m)?;
            }
            let old = device_size(backing_size(l, &b.backing)?, b.offset, b.sizelimit);
            let new = device_size(backing_size(l, &a.backing)?, b.offset, b.sizelimit);
            if old != new {
                return Err(errno::EINVAL);
            }
            let b = l.devices.get_mut(&n).and_then(|d| d.bound.as_mut()).ok_or(errno::ENXIO)?;
            b.backing = a.backing.clone();
            b.path = a.path.clone();
            (b.st_dev, b.st_ino, b.st_rdev) = (a.st_dev, a.st_ino, a.st_rdev);
            b.size = new;
            Ok(0)
        })
    }

    /// A request on loop device descriptor `fd` or on `/dev/loop-control`:
    /// `None` for another descriptor.
    pub(crate) fn loop_ioctl(&mut self, fd: i32, req: u64, arg: u64) -> Option<i64> {
        if !fdmarks::any_marks() {
            return None;
        }
        // What Linux does for any descriptor, before the device sees it.
        if matches!(req, ioctl::FIOCLEX | ioctl::FIONCLEX | ioctl::FIONBIO | ioctl::FIOASYNC) {
            return None;
        }
        // An argument that is a number, not a pointer, as the guest gave
        // it (a backend translates the argument as a pointer); a pointer's
        // copies go back to the guest address themselves.
        let arg = uaccess::guest_of(arg);
        let r = match fdmarks::marked(fd)? {
            Mark::LoopControl => control(req, arg),
            Mark::Loop(n) => self.device_ioctl(fd, n, req, arg),
            _ => return None,
        };
        Some(r.unwrap_or_else(err))
    }

    fn device_ioctl(&mut self, fd: i32, n: u32, req: u64, arg: u64) -> Result<i64, i32> {
        let writes = access(fd)?.1;
        let admin = self.creds.has_admin();
        // What Linux asks of a request that changes the device.
        let may_change = || if writes || admin { Ok(()) } else { Err(errno::EPERM) };
        let put_u64 = |v: u64| uaccess::write(arg, v).map(|_| 0);
        let put_u32 = |v: u32| uaccess::write(arg, v).map(|_| 0);
        let put_u16 = |v: u16| uaccess::write(arg, v).map(|_| 0);
        let bound = |l: &Loops| -> Result<Binding, i32> {
            l.devices.get(&n).and_then(|d| d.bound.clone()).ok_or(errno::ENXIO)
        };
        match req {
            LOOP_SET_FD => self.attach(fd, n, arg as i32, None),
            LOOP_CONFIGURE => {
                let c = uaccess::read_bytes(arg, CONFIG_SIZE)?;
                let (file, block_size) = (u32_at(&c, 0) as i32, u32_at(&c, 4));
                let info = Info::from64(&c[CONFIG_INFO..CONFIG_INFO + INFO64_SIZE]);
                self.attach(fd, n, file, Some((block_size, info)))
            }
            LOOP_CHANGE_FD => self.change_fd(n, arg as i32),
            LOOP_CLR_FD => update(|l| {
                let seq = l.seq + 1;
                let d = l.devices.get_mut(&n).ok_or(errno::ENXIO)?;
                if d.bound.take().is_none() {
                    return Err(errno::ENXIO);
                }
                d.rundown = Some(host_pid());
                d.soft_block = 0;
                d.diskseq = seq;
                l.seq = seq;
                Ok(0)
            }),
            LOOP_SET_STATUS | LOOP_SET_STATUS64 => {
                may_change()?;
                let info = if req == LOOP_SET_STATUS {
                    Info::from_old(&uaccess::read_bytes(arg, OLD_SIZE)?)
                } else {
                    Info::from64(&uaccess::read_bytes(arg, INFO64_SIZE)?)
                };
                update(|l| {
                    let b = bound(l)?;
                    info.check()?;
                    let resize = b.offset != info.offset || b.sizelimit != info.sizelimit;
                    let size = if resize {
                        device_size(backing_size(l, &b.backing)?, info.offset, info.sizelimit)
                    } else {
                        b.size
                    };
                    let b =
                        l.devices.get_mut(&n).and_then(|d| d.bound.as_mut()).ok_or(errno::ENXIO)?;
                    b.flags = status_flags(b.flags, info.flags);
                    b.offset = info.offset;
                    b.sizelimit = info.sizelimit;
                    b.file_name = info.file_name;
                    b.crypt_name = info.crypt_name;
                    b.size = size;
                    Ok(0)
                })
            }
            LOOP_GET_STATUS | LOOP_GET_STATUS64 => {
                if arg == 0 {
                    return Err(errno::EINVAL);
                }
                let b = bound(&*state()?)?;
                let out = if req == LOOP_GET_STATUS { status_old(n, &b)? } else { status64(n, &b) };
                uaccess::write_from(arg, &out).map(|_| 0)
            }
            LOOP_SET_CAPACITY => {
                may_change()?;
                update(|l| {
                    let b = bound(l)?;
                    let size = device_size(backing_size(l, &b.backing)?, b.offset, b.sizelimit);
                    l.devices
                        .get_mut(&n)
                        .and_then(|d| d.bound.as_mut())
                        .ok_or(errno::ENXIO)?
                        .size = size;
                    Ok(0)
                })
            }
            LOOP_SET_DIRECT_IO => {
                may_change()?;
                update(|l| {
                    let b =
                        l.devices.get_mut(&n).and_then(|d| d.bound.as_mut()).ok_or(errno::ENXIO)?;
                    if arg != 0 {
                        // Direct I/O needs the device to start on a block
                        // of the file's device (whose blocks fwe counts as
                        // sectors).
                        if b.offset % SECTOR != 0 {
                            return Err(errno::EINVAL);
                        }
                        b.flags |= LO_FLAGS_DIRECT_IO;
                    } else {
                        b.flags &= !LO_FLAGS_DIRECT_IO;
                    }
                    Ok(0)
                })
            }
            LOOP_SET_BLOCK_SIZE => {
                may_change()?;
                update(|l| {
                    let b =
                        l.devices.get_mut(&n).and_then(|d| d.bound.as_mut()).ok_or(errno::ENXIO)?;
                    if !valid_block_size(arg) {
                        return Err(errno::EINVAL);
                    }
                    b.block_size = arg as u32;
                    Ok(0)
                })
            }
            ioctl::BLKGETSIZE64 => put_u64(size_of(&*state()?, n)),
            ioctl::BLKGETSIZE => put_u64(size_of(&*state()?, n) / SECTOR),
            ioctl::BLKSSZGET | ioctl::BLKPBSZGET | ioctl::BLKIOMIN => {
                let l = state()?;
                let bs =
                    l.devices.get(&n).and_then(|d| d.bound.as_ref()).map_or(512, |b| b.block_size);
                put_u32(bs)
            }
            ioctl::BLKBSZGET => {
                let l = state()?;
                put_u32(l.devices.get(&n).map_or(PAGE as u32, soft_block))
            }
            ioctl::BLKBSZSET => {
                if !admin {
                    return Err(errno::EACCES);
                }
                let bs: i32 = uaccess::read(arg)?;
                update(|l| {
                    let d = l.devices.get_mut(&n).ok_or(errno::ENXIO)?;
                    let logical = d.bound.as_ref().map_or(SECTOR, |b| b.block_size as u64);
                    if bs < 0 || !valid_block_size(bs as u64) || (bs as u64) < logical {
                        return Err(errno::EINVAL);
                    }
                    d.soft_block = bs as u32;
                    Ok(0)
                })
            }
            ioctl::BLKIOOPT | ioctl::BLKALIGNOFF | ioctl::BLKDISCARDZEROES => put_u32(0),
            ioctl::BLKROTATIONAL => put_u16(0),
            ioctl::BLKSECTGET => put_u16(MAX_SECTORS),
            ioctl::BLKGETDISKSEQ => put_u64(state()?.devices.get(&n).map_or(0, |d| d.diskseq)),
            ioctl::BLKROGET => {
                let ro = state()?.devices.get(&n).is_some_and(read_only);
                put_u32(u32::from(ro))
            }
            ioctl::BLKROSET => {
                if !admin {
                    return Err(errno::EACCES);
                }
                let ro: i32 = uaccess::read(arg)?;
                update(|l| {
                    l.devices.get_mut(&n).ok_or(errno::ENXIO)?.read_only = ro != 0;
                    Ok(0)
                })
            }
            ioctl::BLKRAGET | ioctl::BLKFRAGET => {
                if arg == 0 {
                    return Err(errno::EINVAL);
                }
                let pages = state()?.devices.get(&n).map_or(DEFAULT_RA_PAGES, |d| d.ra_pages);
                put_u64(pages * (PAGE / SECTOR))
            }
            ioctl::BLKRASET | ioctl::BLKFRASET => {
                if !admin {
                    return Err(errno::EACCES);
                }
                update(|l| {
                    l.devices.get_mut(&n).ok_or(errno::ENXIO)?.ra_pages = arg / (PAGE / SECTOR);
                    Ok(0)
                })
            }
            ioctl::BLKFLSBUF => {
                if !admin {
                    return Err(errno::EACCES);
                }
                sync(&*state()?, n).map(|_| 0)
            }
            ioctl::BLKRRPART => {
                if !admin {
                    return Err(errno::EACCES);
                }
                let l = state()?;
                let scans = l
                    .devices
                    .get(&n)
                    .and_then(|d| d.bound.as_ref())
                    .is_some_and(|b| b.flags & LO_FLAGS_PARTSCAN != 0);
                if scans { Ok(0) } else { Err(errno::EINVAL) }
            }
            // A loop device erases nothing securely.
            ioctl::BLKSECDISCARD => Err(errno::EOPNOTSUPP),
            ioctl::BLKDISCARD | ioctl::BLKZEROOUT => {
                if !writes {
                    return Err(errno::EBADF);
                }
                let l = state()?;
                let d = l.devices.get(&n).ok_or(errno::ENXIO)?;
                if req == ioctl::BLKDISCARD && read_only(d) {
                    return Err(errno::EPERM);
                }
                let [start, len]: [u64; 2] = uaccess::read(arg)?;
                // A discard is in logical blocks, zeroing in sectors; an
                // empty range is refused either way.
                let grain = if req == ioctl::BLKDISCARD {
                    d.bound.as_ref().map_or(SECTOR, |b| b.block_size as u64)
                } else {
                    SECTOR
                };
                let end = start.checked_add(len).ok_or(errno::EINVAL)?;
                if len == 0 || (start | len) & (grain - 1) != 0 || end > size_of(&l, n) {
                    return Err(errno::EINVAL);
                }
                zero_range(&l, n, start, len).map(|_| 0)
            }
            // Linux's loop driver refuses what it does not know.
            _ => Err(errno::EINVAL),
        }
    }
}

/// A request on `/dev/loop-control`.
fn control(req: u64, arg: u64) -> Result<i64, i32> {
    match req {
        LOOP_CTL_ADD => update(|l| {
            let n = match arg as i32 {
                i if i < 0 => (0..).find(|n| !l.devices.contains_key(n)).ok_or(errno::ENOSPC)?,
                i if i as u64 >= MAX_DEVICES => return Err(errno::EINVAL),
                i => i as u32,
            };
            if l.devices.contains_key(&n) {
                return Err(errno::EEXIST);
            }
            l.add(n);
            Ok(n as i64)
        }),
        LOOP_CTL_REMOVE => update(|l| {
            let n = arg as i32;
            if n < 0 {
                return Err(errno::EINVAL);
            }
            let d = l.devices.get(&(n as u32)).ok_or(errno::ENODEV)?;
            if d.bound.is_some() || d.run_down() {
                return Err(errno::EBUSY);
            }
            l.devices.remove(&(n as u32));
            Ok(0)
        }),
        LOOP_CTL_GET_FREE => update(|l| {
            let (me, now) = (host_pid(), now_secs());
            let free = l.devices.iter().find_map(|(&n, d)| {
                let held = d.claim.is_some_and(|(pid, at)| {
                    pid != me && now.saturating_sub(at) < CLAIM && alive(pid)
                });
                (d.bound.is_none() && !held && !d.run_down()).then_some(n)
            });
            let n = match free {
                Some(n) => n,
                None => {
                    let n = (0..).find(|n| !l.devices.contains_key(n)).ok_or(errno::ENOSPC)?;
                    if n as u64 >= MAX_DEVICES {
                        return Err(errno::ENOSPC);
                    }
                    l.add(n);
                    n
                }
            };
            l.devices.get_mut(&n).ok_or(errno::ENXIO)?.claim = Some((me, now));
            Ok(n as i64)
        }),
        _ => Err(errno::ENOSYS),
    }
}

// --- /sys and /proc ---

/// `/proc/partitions`: the loop devices with something attached (Linux
/// leaves out empty disks), with their sizes in KiB.
pub fn partitions() -> Vec<u8> {
    let mut out = b"major minor  #blocks  name\n\n".to_vec();
    if let Ok(l) = state() {
        for (&n, d) in &l.devices {
            let Some(b) = d.bound.as_ref().filter(|b| b.size > 0) else { continue };
            let kib = b.size / 1024;
            out.extend(format!("{MAJOR:4}  {n:7} {kib:10} loop{n}\n").as_bytes());
        }
    }
    out
}

/// Where the devices' own directories are.
const DEVICES_DIR: &[u8] = b"/sys/devices/virtual/block";

/// The device `name` names (`loopN`), if it exists.
fn device_named(l: &Loops, name: &[u8]) -> Option<u32> {
    let digits = name.strip_prefix(b"loop")?;
    let n: u32 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    (l.devices.contains_key(&n) && format!("loop{n}").as_bytes() == name).then_some(n)
}

/// The device `numbers` names (`7:N`), if it exists.
fn device_numbered(l: &Loops, numbers: &[u8]) -> Option<u32> {
    let minor = std::str::from_utf8(numbers.strip_prefix(b"7:")?).ok()?;
    let n: u32 = minor.parse().ok()?;
    (l.devices.contains_key(&n) && n.to_string() == minor).then_some(n)
}

/// A path under a device's directory in `/sys/block` or `/sys/dev/block`
/// as the path in its own directory (which those link to).
fn canonical(l: &Loops, path: &[u8]) -> Option<(u32, Vec<u8>)> {
    for (base, by_name) in [
        (&b"/sys/block/"[..], true),
        (b"/sys/dev/block/", false),
        (b"/sys/devices/virtual/block/", true),
    ] {
        let Some(rest) = path.strip_prefix(base) else { continue };
        let (first, sub) = match rest.iter().position(|&b| b == b'/') {
            Some(i) => (&rest[..i], rest[i..].to_vec()),
            None => (rest, Vec::new()),
        };
        let n = if by_name { device_named(l, first) } else { device_numbered(l, first) }?;
        return Some((n, sub));
    }
    None
}

fn line(v: impl std::fmt::Display) -> Entry {
    Entry::File(format!("{v}\n").into_bytes())
}

/// A `/sys` entry of the loop devices, if `path` is one.
pub fn sys_lookup(path: &[u8]) -> Option<Entry> {
    if !path.starts_with(b"/sys/") {
        return None;
    }
    if matches!(path, b"/sys/block" | b"/sys/dev" | b"/sys/dev/block" | b"/sys/devices/virtual")
        || path == DEVICES_DIR
    {
        return Some(Entry::Dir);
    }
    let l = state().ok()?;
    let (n, sub) = canonical(&l, path)?;
    let d = &l.devices[&n];
    let b = d.bound.as_ref();
    let link = |up: &str| Entry::Symlink(format!("{up}devices/virtual/block/loop{n}").into_bytes());
    Some(match sub.as_slice() {
        b"" if path.starts_with(b"/sys/block/") => link("../"),
        b"" if path.starts_with(b"/sys/dev/") => link("../../"),
        b"" | b"/queue" => Entry::Dir,
        b"/loop" if b.is_some() => Entry::Dir,
        b"/dev" => line(format!("{MAJOR}:{n}")),
        b"/size" => line(b.map_or(0, |b| b.size / SECTOR)),
        b"/ro" => line(u8::from(read_only(d))),
        b"/removable" | b"/hidden" => line(0),
        b"/range" => line(1),
        b"/diskseq" => line(d.diskseq),
        b"/queue/logical_block_size"
        | b"/queue/physical_block_size"
        | b"/queue/hw_sector_size"
        | b"/queue/minimum_io_size" => line(b.map_or(512, |b| b.block_size)),
        b"/queue/optimal_io_size" | b"/queue/rotational" => line(0),
        b"/queue/dma_alignment" => line(SECTOR - 1),
        b"/queue/read_ahead_kb" => line(d.ra_pages * PAGE / 1024),
        b"/queue/max_sectors_kb" => line(MAX_SECTORS as u64 * SECTOR / 1024),
        p if b.is_some() && p.starts_with(b"/loop/") => {
            let b = b.unwrap();
            match &p[6..] {
                b"backing_file" => Entry::File([&b.path[..], b"\n"].concat()),
                b"offset" => line(b.offset),
                b"sizelimit" => line(b.sizelimit),
                b"autoclear" => line(u8::from(b.flags & LO_FLAGS_AUTOCLEAR != 0)),
                b"partscan" => line(u8::from(b.flags & LO_FLAGS_PARTSCAN != 0)),
                b"dio" => line(u8::from(b.flags & LO_FLAGS_DIRECT_IO != 0)),
                _ => Entry::Missing,
            }
        }
        _ => Entry::Missing,
    })
}

/// The entries of a `/sys` directory of the loop devices (without `.` and
/// `..`), if `path` is one.
pub fn sys_children(path: &[u8]) -> Option<Vec<(Vec<u8>, u8)>> {
    if !path.starts_with(b"/sys/") {
        return None;
    }
    let l = state().ok()?;
    let names = |kind| l.devices.keys().map(|n| (format!("loop{n}").into_bytes(), kind)).collect();
    Some(match path {
        b"/sys/block" => names(DT_LNK),
        b"/sys/dev" => vec![(b"block".to_vec(), DT_DIR)],
        b"/sys/dev/block" => {
            l.devices.keys().map(|n| (format!("{MAJOR}:{n}").into_bytes(), DT_LNK)).collect()
        }
        b"/sys/devices/virtual" => vec![(b"block".to_vec(), DT_DIR)],
        p if p == DEVICES_DIR => names(DT_DIR),
        _ => {
            let (n, sub) = canonical(&l, path)?;
            let files =
                |names: &[&str]| names.iter().map(|f| (f.as_bytes().to_vec(), DT_REG)).collect();
            match sub.as_slice() {
                b"" => {
                    let mut v: Vec<(Vec<u8>, u8)> =
                        files(&["dev", "size", "ro", "removable", "hidden", "range", "diskseq"]);
                    v.push((b"queue".to_vec(), DT_DIR));
                    if l.devices[&n].bound.is_some() {
                        v.push((b"loop".to_vec(), DT_DIR));
                    }
                    v
                }
                b"/queue" => files(&[
                    "logical_block_size",
                    "physical_block_size",
                    "hw_sector_size",
                    "minimum_io_size",
                    "optimal_io_size",
                    "rotational",
                    "dma_alignment",
                    "read_ahead_kb",
                    "max_sectors_kb",
                ]),
                b"/loop" if l.devices[&n].bound.is_some() => {
                    files(&["backing_file", "offset", "sizelimit", "autoclear", "partscan", "dio"])
                }
                _ => return None,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_whole_sectors_after_the_offset_within_the_limit() {
        assert_eq!(device_size(10 * 1024, 0, 0), 10 * 1024);
        assert_eq!(device_size(10 * 1024 + 100, 0, 0), 10 * 1024);
        assert_eq!(device_size(1 << 20, 0, 4 << 20), 1 << 20);
        assert_eq!(device_size(1 << 20, 0, 512 << 10), 512 << 10);
        assert_eq!(device_size(1 << 20, 1024, 0), (1 << 20) - 1024);
        assert_eq!(device_size(100, 4096, 0), 0);
    }

    #[test]
    fn block_sizes_are_powers_of_two_from_a_sector_to_64_kib() {
        for bs in [512, 1024, 4096, 65536] {
            assert!(valid_block_size(bs));
        }
        for bs in [0, 256, 4095, 131072] {
            assert!(!valid_block_size(bs));
        }
    }

    fn round_trip(l: &Loops) {
        let mut e = Enc::new();
        l.encode(&mut e);
        let bytes = e.into_bytes();
        let mut d = Dec::new(&bytes);
        assert_eq!(&Loops::decode(&mut d), l);
        assert!(d.finish().is_ok());
    }

    #[test]
    fn the_record_round_trips() {
        round_trip(&Loops::initial());
        let mut l = Loops::initial();
        l.devices.get_mut(&3).unwrap().bound = Some(Binding {
            backing: Backing::File { host: b"/x/f".to_vec(), dev: 1, ino: 2 },
            path: b"/tmp/f".to_vec(),
            st_dev: 3,
            st_ino: 4,
            st_rdev: 0,
            file_name: [7; LO_NAME_SIZE],
            crypt_name: [0; LO_NAME_SIZE],
            offset: 512,
            sizelimit: 0,
            flags: LO_FLAGS_READ_ONLY,
            block_size: 4096,
            size: 1 << 20,
        });
        l.devices.get_mut(&5).unwrap().claim = Some((42, 7));
        round_trip(&l);
    }

    #[test]
    fn set_status_keeps_what_it_may_not_change() {
        // Read-only stays; partition scanning may be set, not cleared;
        // autoclear may be both.
        let apply = status_flags;
        let all = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO;
        assert_eq!(apply(0, all), LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN);
        assert_eq!(apply(LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN, 0), LO_FLAGS_PARTSCAN);
        assert_eq!(apply(LO_FLAGS_READ_ONLY, 0), LO_FLAGS_READ_ONLY);
    }

    #[test]
    fn device_names_and_numbers() {
        let l = Loops::initial();
        assert_eq!(device_named(&l, b"loop7"), Some(7));
        assert_eq!(device_named(&l, b"loop8"), None);
        assert_eq!(device_named(&l, b"loop01"), None);
        assert_eq!(device_numbered(&l, b"7:2"), Some(2));
        assert_eq!(device_numbered(&l, b"8:2"), None);
        assert_eq!(
            canonical(&l, b"/sys/block/loop2/queue/rotational"),
            Some((2, b"/queue/rotational".to_vec()))
        );
    }
}
