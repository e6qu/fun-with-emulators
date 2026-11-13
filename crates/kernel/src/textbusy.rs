//! `ETXTBSY`: Linux refuses to open for writing (or truncate) the file of
//! a program a process is running, and to run a program whose file is
//! open for writing. The host knows neither of a guest's program, so fwe
//! keeps both in a table every fwe process of the user maps:
//!
//! - each process's program (its file's host device and inode), in a slot
//!   of its own, set when it runs one (`execve`, and a fork child's from
//!   its parent's), let go as it ends (or taken over once it has ended);
//! - the files opened for writing lately, in a ring each such open writes
//!   over the oldest of. One found there is open for writing only if the
//!   process still holds a descriptor of it open to write, which the host
//!   tells ([`holds_for_writing`]), so an entry outliving its descriptor
//!   costs nothing but that look, when the file is run.
//!
//! An open to write or a run checks the table without a lock; recording
//! a run or an open is a few stores.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Processes whose programs are kept, and files open for writing kept.
const RUN_SLOTS: usize = 1024;
const WRITE_SLOTS: usize = 4096;
/// A slot: device, inode, process (0: free).
const SLOT: usize = 3;
/// The table's words: the run slots in use (a high-water mark) and the
/// ring's next slot, then the run slots, then the ring.
const HEAD: usize = 8;
const RUNS_AT: usize = HEAD;
const WRITES_AT: usize = RUNS_AT + RUN_SLOTS * SLOT;
const WORDS: usize = WRITES_AT + WRITE_SLOTS * SLOT;

static TABLE: std::sync::OnceLock<Option<&'static [AtomicU64]>> = std::sync::OnceLock::new();

/// This process's run slot (its index plus 1; 0: none), and its program.
static MY_SLOT: AtomicUsize = AtomicUsize::new(0);
static MY_DEV: AtomicU64 = AtomicU64::new(0);
static MY_INO: AtomicU64 = AtomicU64::new(0);

/// The shared table, mapped on first use.
fn table() -> Option<&'static [AtomicU64]> {
    *TABLE.get_or_init(|| {
        let mut path = crate::fs::shm::user_dir().ok()?;
        path.extend_from_slice(b"/text-busy");
        let c = std::ffi::CString::new(path).ok()?;
        let len = WORDS * 8;
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe {
            libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: plain host calls on the descriptor just opened; a file
        // shorter than the table is grown with zeros.
        let map = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) == 0 && (st.st_size as usize) < len {
                libc::ftruncate(fd, len as libc::off_t);
            }
            let m = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            m
        };
        if map == libc::MAP_FAILED {
            return None;
        }
        // SAFETY: the mapping is `len` bytes, page-aligned, shared and never
        // unmapped; every access is atomic.
        Some(unsafe { std::slice::from_raw_parts(map as *const AtomicU64, WORDS) })
    })
}

fn me() -> u64 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() as u64 }
}

/// Whether host process `pid` is there.
fn alive(pid: u64) -> bool {
    if pid == 0 || pid > i32::MAX as u64 {
        return false;
    }
    // SAFETY: signal 0 only asks whether the process exists.
    unsafe { libc::kill(pid as i32, 0) == 0 || crate::host::last_errno() == libc::EPERM }
}

/// This process runs the program whose file is host `dev`, `ino`.
pub fn running(dev: u64, ino: u64) {
    if std::env::var_os("FWE_NO_TEXTBUSY").is_some() {
        return;
    }
    MY_DEV.store(dev, Ordering::Relaxed);
    MY_INO.store(ino, Ordering::Relaxed);
    let Some(t) = table() else { return };
    let me = me();
    let slot = |i: usize| &t[RUNS_AT + i * SLOT..RUNS_AT + (i + 1) * SLOT];
    let own = MY_SLOT.load(Ordering::Relaxed);
    let i = if own != 0 && slot(own - 1)[2].load(Ordering::Acquire) == me {
        own - 1
    } else {
        // A free slot, or one whose process has ended.
        let Some(i) = (0..RUN_SLOTS).find(|&i| {
            let p = slot(i)[2].load(Ordering::Acquire);
            (p == 0 || !alive(p))
                && slot(i)[2].compare_exchange(p, me, Ordering::AcqRel, Ordering::Acquire).is_ok()
        }) else {
            return;
        };
        MY_SLOT.store(i + 1, Ordering::Relaxed);
        t[0].fetch_max(i as u64 + 1, Ordering::AcqRel);
        i
    };
    slot(i)[0].store(dev, Ordering::Release);
    slot(i)[1].store(ino, Ordering::Release);
}

/// In a fork child: it runs its parent's program, in a slot of its own.
pub fn forked_child() {
    MY_SLOT.store(0, Ordering::Relaxed);
    let (dev, ino) = (MY_DEV.load(Ordering::Relaxed), MY_INO.load(Ordering::Relaxed));
    if dev != 0 || ino != 0 {
        running(dev, ino);
    }
}

/// This process is ending: its slot is free.
pub fn exiting() {
    let own = MY_SLOT.swap(0, Ordering::Relaxed);
    if own == 0 {
        return;
    }
    if let Some(t) = table() {
        let _ = t[RUNS_AT + (own - 1) * SLOT + 2].compare_exchange(
            me(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// Whether some process runs the program whose file is host `dev`, `ino`
/// (an open of it to write is `ETXTBSY`).
pub fn is_running(dev: u64, ino: u64) -> bool {
    let Some(t) = table() else { return false };
    let used = (t[0].load(Ordering::Acquire) as usize).min(RUN_SLOTS);
    (0..used).any(|i| {
        let s = &t[RUNS_AT + i * SLOT..RUNS_AT + (i + 1) * SLOT];
        s[1].load(Ordering::Acquire) == ino
            && s[0].load(Ordering::Acquire) == dev
            && alive(s[2].load(Ordering::Acquire))
    })
}

/// The file host `dev`, `ino` was opened for writing by this process.
pub fn opened_for_writing(dev: u64, ino: u64) {
    let Some(t) = table() else { return };
    let i = (t[1].fetch_add(1, Ordering::AcqRel) as usize) % WRITE_SLOTS;
    let s = &t[WRITES_AT + i * SLOT..WRITES_AT + (i + 1) * SLOT];
    s[2].store(0, Ordering::Release);
    s[0].store(dev, Ordering::Release);
    s[1].store(ino, Ordering::Release);
    s[2].store(me(), Ordering::Release);
}

/// Whether the file host `dev`, `ino` is open for writing (running it is
/// `ETXTBSY`).
pub fn is_being_written(dev: u64, ino: u64) -> bool {
    let Some(t) = table() else { return false };
    let mut checked: Vec<u64> = Vec::new();
    for i in 0..WRITE_SLOTS {
        let s = &t[WRITES_AT + i * SLOT..WRITES_AT + (i + 1) * SLOT];
        if s[1].load(Ordering::Acquire) != ino || s[0].load(Ordering::Acquire) != dev {
            continue;
        }
        let pid = s[2].load(Ordering::Acquire);
        if pid == 0 || checked.contains(&pid) {
            continue;
        }
        checked.push(pid);
        if alive(pid) && holds_for_writing(pid as i32, dev, ino) {
            return true;
        }
        // Its descriptor is gone: so is the entry.
        let _ = s[2].compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    false
}

/// Whether host process `pid` holds a descriptor of the file host `dev`,
/// `ino` open to write.
#[cfg(target_os = "macos")]
fn holds_for_writing(pid: i32, dev: u64, ino: u64) -> bool {
    /// `PROC_PIDFDVNODEPATHINFO`: its size, and where in it the open flags
    /// (`pfi.fi_openflags`), the device (`pvip.vip_vi.vi_stat.vst_dev`) and
    /// the inode (`vst_ino`) are (measured against the SDK's headers).
    const VNODE_PATH: i32 = 2;
    const VNODE_PATH_SIZE: usize = 1200;
    const FLAGS_AT: usize = 0;
    const DEV_AT: usize = 24;
    const INO_AT: usize = 32;
    /// The kernel's `FWRITE`.
    const FWRITE: u32 = 2;
    let size = std::mem::size_of::<libc::proc_fdinfo>();
    let mut n = 64usize;
    let fds = loop {
        let mut buf = vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; n];
        // SAFETY: a valid out-buffer of `n` entries.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                (n * size) as i32,
            )
        };
        if got <= 0 {
            return false;
        }
        let count = got as usize / size;
        if count < n {
            buf.truncate(count);
            break buf;
        }
        n *= 2;
    };
    let mut b = vec![0u8; VNODE_PATH_SIZE];
    fds.iter().filter(|f| f.proc_fdtype as i32 == libc::PROX_FDTYPE_VNODE).any(|f| {
        // SAFETY: a valid out-buffer of its size.
        let got = unsafe {
            libc::proc_pidfdinfo(
                pid,
                f.proc_fd,
                VNODE_PATH,
                b.as_mut_ptr().cast(),
                VNODE_PATH_SIZE as i32,
            )
        };
        let word = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap_or_default());
        got as usize == VNODE_PATH_SIZE
            && word(FLAGS_AT) & FWRITE != 0
            && u64::from(word(DEV_AT)) == dev & 0xffff_ffff
            && u64::from_ne_bytes(b[INO_AT..INO_AT + 8].try_into().unwrap_or_default()) == ino
    })
}

#[cfg(not(target_os = "macos"))]
fn holds_for_writing(_: i32, _: u64, _: u64) -> bool {
    false
}
