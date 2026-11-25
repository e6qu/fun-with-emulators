//! fwe's GPU device, `/dev/fwe-gpu`: the node fwe's Linux Vulkan driver
//! opens to reach the Mac's ([`super`]).
//!
//! - **The node** is one of fwe's (a node file in its own directory of
//!   them, [`crate::fs`]), present where a Mac Vulkan driver is installed
//!   and the backend runs guest code in fwe's process ([`present`]).
//! - **A descriptor** of it is marked as an open of the device
//!   ([`Mark::Gpu`]); its one ioctl ([`super::generated::IOCTL_CALL`]) runs a
//!   command. Most run without the kernel lock ([`io`]), so a program's
//!   threads call the driver at once.
//! - **The driver's own descriptors** (Metal's caches, which it opens as a
//!   device is made and as pipelines are compiled, read-write and not
//!   close-on-exec) are kept out of the guest's range: those commands
//!   ([`LOCKED`]) run under the kernel lock with the guest's range plugged
//!   ([`crate::fdtable::plugged`]), and an `execve` closes them
//!   ([`before_exec`]).
//! - **A fork child** never calls the driver: the driver's threads, and
//!   the dispatch queues and Metal objects it holds, are its parent's
//!   (macOS's own libraries do not work in a fork child). Its copies of its
//!   parent's opens fail with `ENODEV`, and its own opens are refused while
//!   the driver is in its memory; an `execve` makes it a fresh process.

use crate::fdmarks::{self, Mark};
use fwe_abi::errno;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::*};

use super::generated::{self, COMMANDS, MOST_ARGS, cmd};

/// The node's numbers: a misc device (major 10) of fwe's.
pub fn node() -> crate::devnodes::Node {
    crate::devnodes::Node { kind: crate::devnodes::S_IFCHR, major: 10, minor: 241 }
}

/// Whether `n` is the device's node.
pub fn is_node(n: crate::devnodes::Node) -> bool {
    n == node()
}

/// The backend runs guest code in a VM, whose memory is not the process's.
static ABSENT: AtomicBool = AtomicBool::new(false);

/// This process is a fork child of one that had loaded the Mac's driver.
static FORKED_WITH_DRIVER: AtomicBool = AtomicBool::new(false);

/// Whether the device is there: a Mac Vulkan driver is installed, and guest
/// code runs in fwe's process.
pub fn present() -> bool {
    !ABSENT.load(Relaxed) && super::driver::installed()
}

/// The backend's guest memory is not the process's (the VM's): there is no
/// device.
pub fn absent() {
    ABSENT.store(true, Relaxed);
}

/// An open of the device.
#[derive(Default)]
pub(crate) struct File {
    /// A fork child's copy of its parent's open: its calls fail (`ENODEV`).
    parents: bool,
}

/// Every open of the device, by its mark's key. Held across a host fork
/// ([`crate::forklock`]).
pub(crate) static FILES: Mutex<BTreeMap<u32, File>> = Mutex::new(BTreeMap::new());
static NEXT_KEY: AtomicU32 = AtomicU32::new(1);

fn files() -> std::sync::MutexGuard<'static, BTreeMap<u32, File>> {
    FILES.lock().unwrap_or_else(|e| e.into_inner())
}

/// `fd` was opened on the device's node: an open of the device.
pub fn opened(fd: i32) {
    let key = NEXT_KEY.fetch_add(1, Relaxed);
    files().insert(key, File::default());
    fdmarks::mark(fd, Mark::Gpu(key));
}

/// An open of the device kept across `execve` (its descriptor's mark),
/// `key`: the new program finds it open, and new opens numbered past it.
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
        files().remove(&key);
    }
}

/// The device can be opened: it is there, and the driver is not a fork
/// parent's.
pub fn check_open() -> Result<(), i32> {
    if !present() || FORKED_WITH_DRIVER.load(Relaxed) {
        return Err(errno::ENODEV);
    }
    Ok(())
}

/// In a fork child: the opens it has are its parent's, and the driver in
/// its memory, if any, is its parent's too.
pub fn forked_child() {
    for f in files().values_mut() {
        f.parents = true;
    }
    if super::driver::loaded() {
        FORKED_WITH_DRIVER.store(true, Relaxed);
    }
}

/// Whether the Mac's driver is in this process's memory (loaded here, or in
/// the parent this process is a fork child of): an `execve` then starts a
/// fresh process, as the driver's threads and the host's objects it holds
/// cannot be carried into the new program's.
pub fn driver_in_memory() -> bool {
    super::driver::loaded() || FORKED_WITH_DRIVER.load(Relaxed)
}

/// The open of the device `fd` is, if it is one.
fn key_of(fd: i32) -> Option<u32> {
    if !fdmarks::any_marks() {
        return None;
    }
    match fdmarks::marked(fd)? {
        Mark::Gpu(key) => Some(key),
        _ => None,
    }
}

/// Commands that run holding the kernel lock, the guest's descriptor range
/// plugged: those the driver opens descriptors of its own in (Metal's
/// library cache as a device is made, its function cache as a pipeline is
/// compiled).
pub const LOCKED: [usize; 3] =
    [cmd::vkCreateDevice, cmd::vkCreateComputePipelines, cmd::vkCreateGraphicsPipelines];

/// The device's ioctl on `fd` with record `arg`, if `fd` is the device:
/// Linux's answer. Under the kernel lock: a command of [`LOCKED`] runs with
/// the guest's range plugged, as does a query that makes fwe's device for
/// host image copy ([`super::hostcopy::needs_lock`]).
pub fn ioctl(fd: i32, req: u64, arg: u64) -> Option<i64> {
    if req != generated::IOCTL_CALL {
        return None;
    }
    let key = key_of(fd)?;
    let command = crate::uaccess::read::<u32>(arg).ok()? as usize;
    let helper = super::hostcopy::needs_lock(command, arg);
    if !LOCKED.contains(&command) && !helper {
        return Some(run(key, arg));
    }
    let locked = || {
        if helper {
            super::hostcopy::prepare(arg);
        }
        run(key, arg)
    };
    Some(crate::fdtable::plugged(locked).unwrap_or_else(|e| -(e as i64)))
}

/// Before an `execve` that starts a fresh fwe, from a process with the
/// driver in its memory: the descriptors out of the guest's range but
/// `keep` (the driver's, which it did not make close-on-exec) are closed
/// by it.
pub fn before_exec(keep: Option<i32>) {
    if !driver_in_memory() {
        return;
    }
    for fd in all_fds() {
        if !crate::fdtable::guest_visible(fd) && Some(fd) != keep {
            // SAFETY: a plain host call; the descriptor is not used again.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
}

/// Every descriptor of the process.
fn all_fds() -> Vec<i32> {
    #[cfg(target_os = "macos")]
    {
        let size = std::mem::size_of::<libc::proc_fdinfo>();
        let mut n = 256usize;
        loop {
            // SAFETY: zeroed bytes are valid `proc_fdinfo`s.
            let mut buf: Vec<libc::proc_fdinfo> = vec![unsafe { std::mem::zeroed() }; n];
            // SAFETY: a valid out-buffer of `n` entries.
            let got = unsafe {
                libc::proc_pidinfo(
                    libc::getpid(),
                    libc::PROC_PIDLISTFDS,
                    0,
                    buf.as_mut_ptr().cast(),
                    (n * size) as i32,
                )
            };
            if got <= 0 {
                return Vec::new();
            }
            let count = got as usize / size;
            if count < n {
                return buf[..count].iter().map(|f| f.proc_fd).collect();
            }
            n *= 2;
        }
    }
    #[cfg(not(target_os = "macos"))]
    Vec::new()
}

/// The device's ioctl without the kernel lock ([`crate::blocking_syscall`]):
/// its answer, or `None` for any other call and the commands that need the
/// lock ([`LOCKED`], [`super::hostcopy::needs_lock`]).
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    if nr != fwe_abi::nr::IOCTL || a[1] as u32 as u64 != generated::IOCTL_CALL {
        return None;
    }
    let key = key_of(a[0] as i32)?;
    let command = crate::uaccess::read::<u32>(a[2]).ok()? as usize;
    if LOCKED.contains(&command) || super::hostcopy::needs_lock(command, a[2]) {
        return None;
    }
    Some(run(key, a[2]))
}

/// Run the command of record `arg` for open `key`: 0, the result written
/// back to the record, or an errno.
fn run(key: u32, arg: u64) -> i64 {
    if files().get(&key).is_none_or(|f| f.parents) {
        return -(errno::ENODEV as i64);
    }
    let Ok(record) = crate::uaccess::read::<[u64; 3]>(arg) else {
        return -(errno::EFAULT as i64);
    };
    let (command, count, words_at) = (record[0] as u32, (record[0] >> 32) as usize, record[1]);
    if count > MOST_ARGS {
        return -(errno::EINVAL as i64);
    }
    let mut w = [0u64; MOST_ARGS];
    if count > 0 {
        let Ok(bytes) = crate::uaccess::read_bytes(words_at, count * 8) else {
            return -(errno::EFAULT as i64);
        };
        for (word, b) in w.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_ne_bytes(*b);
        }
    }
    let began = crate::timing::call_began();
    let r = super::call(command, &w);
    counted(command as usize, began);
    // In a trace to a file: every command, its result and what it wrote
    // where every call is traced; a command that failed, and how, otherwise.
    if crate::trace::calls_traced() {
        let name = generated::NAMES.get(command as usize).copied().unwrap_or("fwe's query");
        let got = match r {
            Ok(v) => format!("{v:#x}"),
            Err(e) => format!("errno {e}"),
        };
        let wrote = match r {
            Ok(_) => super::written(command as usize, &w),
            Err(_) => String::new(),
        };
        crate::trace::note_to_file(&format!("vulkan: {name}{:x?} = {got}{wrote}", &w[..count]));
    } else if crate::trace::file().is_some() {
        let index = command as usize;
        let failed = match r {
            Ok(v) => generated::RESULTS.get(index) == Some(&true) && (v as i32) < 0,
            Err(_) => true,
        };
        if failed {
            let name = generated::NAMES.get(index).copied().unwrap_or("fwe's query");
            let how = match r {
                Ok(v) => format!("VkResult {}", v as i32),
                Err(e) => format!("errno {e}"),
            };
            crate::trace::note_to_file(&format!("vulkan: {name} failed: {how}"));
        }
    }
    match r {
        Ok(result) => match crate::uaccess::write(arg + 16, result) {
            Ok(()) => 0,
            Err(_) => -(errno::EFAULT as i64),
        },
        Err(e) => -(e as i64),
    }
}

/// The commands run and the time they took, by command, for `FWE_TIMING`.
static CALLS: [AtomicU64; COMMANDS] = [const { AtomicU64::new(0) }; COMMANDS];
static CALL_NS: [AtomicU64; COMMANDS] = [const { AtomicU64::new(0) }; COMMANDS];

fn counted(index: usize, began: Option<std::time::Instant>) {
    let Some(b) = began else { return };
    if index < COMMANDS {
        CALLS[index].fetch_add(1, Relaxed);
        CALL_NS[index].fetch_add(b.elapsed().as_nanos() as u64, Relaxed);
    }
}

/// The Vulkan commands run, with the microseconds they took, as text: none
/// if the device was not used.
pub fn counts() -> Option<String> {
    let calls: Vec<String> = (0..COMMANDS)
        .map(|i| (generated::NAMES[i], CALLS[i].load(Relaxed), CALL_NS[i].load(Relaxed)))
        .filter(|c| c.1 > 0)
        .map(|(k, n, ns)| format!("{k} {n} ({} us)", ns / 1000))
        .collect();
    (!calls.is_empty()).then(|| format!("Vulkan calls: {}", calls.join(", ")))
}
