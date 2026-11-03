//! Access to guest memory from the kernel layer.
//!
//! Guest addresses are host addresses, so the kernel can read and write guest
//! memory directly — but a guest may pass any pointer, and a bad one must
//! make the system call fail with `EFAULT`, not crash fwe. Every read and
//! write the kernel itself makes of guest memory goes through this module.
//! On macOS on Apple Silicon the copies run in a small assembly routine;
//! when one of its loads or stores faults, the backend's fault handler asks
//! [`fixup`] for the routine's recovery point and resumes there, and the copy
//! reports the fault (the scheme Linux's exception tables use). Elsewhere the
//! copies are plain, unchecked ones.
//!
//! Pointers the kernel passes straight to a host system call need none of
//! this: the host checks them and fails with its own `EFAULT`.
//!
//! Guest addresses are host addresses, with one exception: a backend that
//! runs the guest in a VM can place a program image where the host process
//! cannot map anything (the low 4 GiB on macOS), backing it with host memory
//! elsewhere. It registers that range with [`set_translation`], and every
//! guest address is passed through [`g2h`] before the kernel or the host
//! touches it.

use fwe_abi::errno;
use std::sync::atomic::{AtomicU64, Ordering};

/// The one translated guest range `[LO, HI)` and the host address of `LO`.
static LO: AtomicU64 = AtomicU64::new(0);
static HI: AtomicU64 = AtomicU64::new(0);
static HOST: AtomicU64 = AtomicU64::new(0);

/// Back guest addresses `[guest, guest + len)` with host memory at `host`.
pub fn set_translation(guest: u64, len: u64, host: u64) {
    HI.store(0, Ordering::SeqCst);
    LO.store(guest, Ordering::SeqCst);
    HOST.store(host, Ordering::SeqCst);
    HI.store(guest + len, Ordering::SeqCst);
}

/// Whether `[addr, addr + len)` straddles the edge of the translated range
/// (partly inside, partly out): such a range has no single host address,
/// and memory calls on it are refused.
pub fn crosses(addr: u64, len: u64) -> bool {
    let (lo, hi) = (LO.load(Ordering::Relaxed), HI.load(Ordering::Relaxed));
    let end = addr.saturating_add(len);
    lo < hi && addr < hi && end > lo && (addr < lo || end > hi)
}

/// The host address of guest address `addr` (itself, outside the translated
/// range).
pub fn g2h(addr: u64) -> u64 {
    let lo = LO.load(Ordering::Relaxed);
    if addr >= lo && addr < HI.load(Ordering::Relaxed) {
        HOST.load(Ordering::Relaxed) + (addr - lo)
    } else {
        addr
    }
}

/// The longest path the kernel reads, with its terminator (Linux's
/// `PATH_MAX`).
pub const PATH_MAX: usize = 4096;

/// What a failed access returns: always `EFAULT`.
pub type Result<T> = std::result::Result<T, i32>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    // fwe_uaccess_copy(dst, src, len) -> 0, or 1 if an access faulted.
    // Copies 8 bytes at a time, then single bytes. Every load and store lies
    // between `_fwe_uaccess_start` and `_fwe_uaccess_fault`; a fault there
    // resumes at `_fwe_uaccess_fault`, which returns 1 to the caller (the
    // routine is a leaf, so `lr` still holds the return address).
    core::arch::global_asm!(
        ".p2align 2",
        ".globl _fwe_uaccess_copy",
        "_fwe_uaccess_copy:",
        ".globl _fwe_uaccess_start",
        "_fwe_uaccess_start:",
        "    cmp x2, #8",
        "    b.lo 2f",
        "1:  ldr x3, [x1], #8",
        "    str x3, [x0], #8",
        "    sub x2, x2, #8",
        "    cmp x2, #8",
        "    b.hs 1b",
        "2:  cbz x2, 4f",
        "3:  ldrb w3, [x1], #1",
        "    strb w3, [x0], #1",
        "    subs x2, x2, #1",
        "    b.ne 3b",
        "4:  mov x0, #0",
        "    ret",
        ".globl _fwe_uaccess_fault",
        "_fwe_uaccess_fault:",
        "    mov x0, #1",
        "    ret",
    );

    unsafe extern "C" {
        fn fwe_uaccess_copy(dst: *mut u8, src: *const u8, len: usize) -> u64;
        static fwe_uaccess_start: u8;
        static fwe_uaccess_fault: u8;
    }

    /// Copy `len` bytes; false if an access faulted.
    ///
    /// # Safety
    /// Whichever side is fwe's own memory must be valid for `len` bytes.
    pub unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) -> bool {
        // SAFETY: the routine only touches the two ranges; a fault in it is
        // recovered by the backend (see `fixup`).
        unsafe { fwe_uaccess_copy(dst, src, len) == 0 }
    }

    pub fn fixup(pc: u64) -> Option<u64> {
        let (start, fault) =
            (&raw const fwe_uaccess_start as u64, &raw const fwe_uaccess_fault as u64);
        (start..fault).contains(&pc).then_some(fault)
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    /// Copy `len` bytes (unchecked on this host).
    ///
    /// # Safety
    /// Both ranges must be valid for `len` bytes.
    pub unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) -> bool {
        // SAFETY: guaranteed by the caller.
        unsafe { std::ptr::copy(src, dst, len) };
        true
    }

    pub fn fixup(_pc: u64) -> Option<u64> {
        None
    }
}

/// Where to resume after a fault at `pc`, if `pc` is inside a guest-memory
/// copy. The backend's fault handler calls this for faults in fwe's own
/// code.
pub fn fixup(pc: u64) -> Option<u64> {
    imp::fixup(pc)
}

fn check(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(errno::EFAULT) }
}

/// Copy `dst.len()` bytes from guest address `addr`.
pub fn read_into(addr: u64, dst: &mut [u8]) -> Result<()> {
    // SAFETY: `dst` is fwe's own buffer; the guest side is checked.
    check(unsafe { imp::copy(dst.as_mut_ptr(), g2h(addr) as *const u8, dst.len()) })
}

/// Copy `src` to guest address `addr`.
pub fn write_from(addr: u64, src: &[u8]) -> Result<()> {
    // SAFETY: `src` is fwe's own buffer; the guest side is checked.
    check(unsafe { imp::copy(g2h(addr) as *mut u8, src.as_ptr(), src.len()) })
}

/// Read a `T` from guest address `addr`.
pub fn read<T: Copy>(addr: u64) -> Result<T> {
    let mut v = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `v` is `size_of::<T>()` writable bytes; the guest side is
    // checked.
    let ok = unsafe { imp::copy(v.as_mut_ptr().cast(), g2h(addr) as *const u8, size_of::<T>()) };
    check(ok)?;
    // SAFETY: fully written by the copy; the kernel only reads plain-data
    // ABI types, for which any bit pattern is valid.
    Ok(unsafe { v.assume_init() })
}

/// Write `value` to guest address `addr`.
pub fn write<T: Copy>(addr: u64, value: T) -> Result<()> {
    // SAFETY: `value` is a readable `T`; the guest side is checked.
    let ok = unsafe { imp::copy(g2h(addr) as *mut u8, (&raw const value).cast(), size_of::<T>()) };
    check(ok)
}

/// Read `len` bytes from guest address `addr`.
pub fn read_bytes(addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    read_into(addr, &mut out)?;
    Ok(out)
}

/// Zero `len` bytes at guest address `addr`.
pub fn zero(addr: u64, len: usize) -> Result<()> {
    write_from(addr, &vec![0u8; len])
}

/// Read a NUL-terminated string (without the NUL) of at most `max` bytes
/// from guest address `addr`. Reads a page at most at a time, never past
/// the page holding the terminator. Fails with `ENAMETOOLONG` past `max`.
pub fn read_cstr(addr: u64, max: usize) -> Result<Vec<u8>> {
    const CHUNK: u64 = 4096;
    let mut out = Vec::new();
    let mut at = addr;
    loop {
        // Never cross into the next page in one copy: it may be unmapped
        // although the string ends before it.
        let n = (CHUNK - at % CHUNK) as usize;
        let mut chunk = vec![0u8; n];
        read_into(at, &mut chunk)?;
        if let Some(end) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..end]);
            return if out.len() > max { Err(errno::ENAMETOOLONG) } else { Ok(out) };
        }
        out.extend_from_slice(&chunk);
        if out.len() > max {
            return Err(errno::ENAMETOOLONG);
        }
        at += n as u64;
    }
}

/// Read a NULL-terminated array of string pointers (`argv`, `envp`); a null
/// `addr` is an empty array.
pub fn read_cstr_array(addr: u64, max_each: usize) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if addr == 0 {
        return Ok(out);
    }
    let mut p = addr;
    loop {
        let ptr: u64 = read(p)?;
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_cstr(ptr, max_each)?);
        p += 8;
    }
}

/// A guest `iovec` array of `count` entries at `addr`, with each buffer's
/// address translated, ready to hand to the host.
pub fn host_iovecs(addr: u64, count: u64) -> Result<Vec<libc::iovec>> {
    if count > 1024 {
        return Err(errno::EINVAL);
    }
    let raw = read_bytes(addr, count as usize * 16)?;
    Ok(raw
        .chunks_exact(16)
        .map(|c| libc::iovec {
            iov_base: g2h(u64::from_ne_bytes(c[0..8].try_into().unwrap())) as *mut libc::c_void,
            iov_len: u64::from_ne_bytes(c[8..16].try_into().unwrap()) as usize,
        })
        .collect())
}

/// Which arguments of system call `nr` are pointers to guest memory the
/// call reads or writes, as a bit mask (bit `i` for argument `i`). A backend
/// with a translated range passes these through [`g2h`] before the call; an
/// address outside the range is unchanged, so listing a pointer argument is
/// always safe. Addresses the kernel keeps as guest addresses (`mmap` and
/// friends, `brk`, `clone`'s stack and tid words) are not listed.
pub fn pointer_args(nr: u64) -> u8 {
    use fwe_abi::nr as n;
    match nr {
        n::READ | n::WRITE | n::PREAD64 | n::PWRITE64 => 0b10,
        n::OPENAT | n::MKDIRAT | n::MKNODAT | n::UNLINKAT | n::FCHMODAT | n::FCHOWNAT => 0b10,
        n::FACCESSAT | n::FACCESSAT2 => 0b10,
        n::CHDIR | n::CHROOT => 0b1,
        n::NEWFSTATAT | n::READLINKAT => 0b110,
        n::STATX => 0b1_0010,
        n::FSTAT | n::FSTATFS | n::GETDENTS64 => 0b10,
        n::STATFS => 0b11,
        n::TRUNCATE => 0b1,
        n::SYMLINKAT => 0b101,
        n::LINKAT | n::RENAMEAT | n::RENAMEAT2 => 0b1010,
        n::UTIMENSAT => 0b110,
        n::GETCWD | n::UNAME | n::SYSINFO | n::TIMES => 0b1,
        n::PIPE2 => 0b1,
        n::IOCTL => 0b100,
        n::CLOCK_GETTIME | n::CLOCK_GETRES | n::CLOCK_SETTIME => 0b10,
        n::CLOCK_NANOSLEEP => 0b1100,
        n::NANOSLEEP | n::GETTIMEOFDAY => 0b11,
        n::GETRANDOM => 0b1,
        n::RT_SIGACTION | n::RT_SIGPROCMASK => 0b110,
        n::RT_SIGPENDING | n::RT_SIGSUSPEND => 0b1,
        n::RT_SIGTIMEDWAIT => 0b111,
        n::SIGALTSTACK => 0b11,
        // The timeout (argument 3) is a pointer only for the waits; the
        // backend translates it then (see `futex_pointer_args`).
        n::FUTEX => 0b1_0001,
        n::PRLIMIT64 => 0b1100,
        n::GETRLIMIT | n::SETRLIMIT => 0b10,
        n::GETRUSAGE => 0b10,
        n::SETITIMER => 0b110,
        n::GETITIMER => 0b10,
        n::WAIT4 => 0b1010,
        n::WAITID => 0b1_0100,
        n::SCHED_GETAFFINITY | n::SCHED_SETAFFINITY => 0b100,
        n::GETRESUID | n::GETRESGID => 0b111,
        n::GETGROUPS | n::SETGROUPS => 0b10,
        n::PPOLL => 0b1101,
        n::EPOLL_CTL => 0b1000,
        n::EPOLL_PWAIT => 0b1_0010,
        n::SIGNALFD4 => 0b10,
        n::TIMERFD_SETTIME => 0b1100,
        n::TIMERFD_GETTIME => 0b10,
        n::SOCKETPAIR => 0b1000,
        n::BIND | n::CONNECT => 0b10,
        n::ACCEPT | n::ACCEPT4 | n::GETSOCKNAME | n::GETPEERNAME => 0b110,
        n::SENDTO => 0b1_0010,
        n::RECVFROM => 0b11_0010,
        n::SENDMSG | n::RECVMSG => 0b10,
        n::SETSOCKOPT => 0b1000,
        n::GETSOCKOPT => 0b1_1000,
        _ => 0,
    }
}

/// [`pointer_args`] for a `futex` call with operation `op`: argument 3 is
/// a timeout pointer for the waits, a count for the requeues and `WAKE_OP`.
pub fn futex_pointer_args(op: u64) -> u8 {
    use fwe_abi::futex::*;
    match op & FUTEX_CMD_MASK {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => 0b1001,
        _ => 0b1_0001,
    }
}

/// Evaluate a guest access, returning the system call's `EFAULT` (or other
/// errno) from the enclosing function on failure.
#[macro_export]
macro_rules! guest {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return fwe_abi::err(e),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_values_and_strings() {
        let mut buf = [0u8; 64];
        let at = buf.as_mut_ptr() as u64;
        write(at + 3, 0x1122_3344_5566_7788u64).unwrap();
        assert_eq!(read::<u64>(at + 3).unwrap(), 0x1122_3344_5566_7788);
        write_from(at + 20, b"hello\0").unwrap();
        assert_eq!(read_cstr(at + 20, 100).unwrap(), b"hello");
        assert_eq!(read_cstr(at + 20, 2), Err(errno::ENAMETOOLONG));
        zero(at, 64).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn strings_stop_at_the_terminator_page() {
        // A string ending just before an inaccessible page reads fine.
        let page = 16384;
        // SAFETY: a fresh two-page mapping, the second made inaccessible.
        let base = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            libc::mprotect(p.cast::<u8>().add(page).cast(), page, libc::PROT_NONE);
            p as u64
        };
        let s = base + page as u64 - 4;
        write_from(s, b"abc\0").unwrap();
        assert_eq!(read_cstr(s, 100).unwrap(), b"abc");
        let argv = [s, 0u64];
        assert_eq!(read_cstr_array(argv.as_ptr() as u64, 100).unwrap(), vec![b"abc".to_vec()]);
        // SAFETY: unmapping the mapping made above.
        unsafe { libc::munmap(base as *mut _, 2 * page) };
    }
}
