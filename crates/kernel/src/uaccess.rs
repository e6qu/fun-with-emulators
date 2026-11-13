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
//! Guest addresses are host addresses, with exceptions in a backend that
//! runs the guest in a VM: it can back guest ranges with host memory
//! elsewhere — a program image where the host process cannot map anything
//! (the low 4 GiB on macOS), a shared mapping. It registers each such range
//! with [`add_translation`], and every guest address is passed through
//! [`g2h`] before the kernel or the host touches it; copies that cross from
//! one translation into another are split where they do. Pointer arguments
//! a system call hands the host are translated with [`host_arg`], which
//! remembers them for the call, so a copy the kernel makes through one is
//! taken as a copy of the guest address it came from ([`guest_of`]).
//!
//! Such a backend also keeps host memory accessible where the guest's is
//! not (its guest has page tables of its own), so a bad pointer would not
//! fault on the host: it registers a [`set_validator`] that every copy here
//! asks first.

use fwe_abi::errno;

/// A translated guest range `[lo, hi)`, backed at `host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Translation {
    lo: u64,
    hi: u64,
    host: u64,
}

/// The translated ranges, sorted and disjoint.
pub(crate) static TABLE: crate::forklock::ForkRwLock<Vec<Translation>> =
    crate::forklock::ForkRwLock::new(Vec::new());

fn table() -> std::sync::RwLockReadGuard<'static, Vec<Translation>> {
    TABLE.read().unwrap_or_else(|e| e.into_inner())
}

fn table_mut() -> std::sync::RwLockWriteGuard<'static, Vec<Translation>> {
    TABLE.write().unwrap_or_else(|e| e.into_inner())
}

/// Every translated range as `(guest, len, host)`, for a fork child.
pub fn translations() -> Vec<(u64, u64, u64)> {
    table().iter().map(|t| (t.lo, t.hi - t.lo, t.host)).collect()
}

/// Back guest addresses `[guest, guest + len)` with host memory at `host`,
/// replacing any translation of part of the range.
pub fn add_translation(guest: u64, len: u64, host: u64) {
    remove_translation(guest, len);
    if len == 0 {
        return;
    }
    let mut t = table_mut();
    let at = t.partition_point(|x| x.lo < guest);
    t.insert(at, Translation { lo: guest, hi: guest + len, host });
}

/// Guest addresses `[guest, guest + len)` are their own host addresses
/// again.
pub fn remove_translation(guest: u64, len: u64) {
    let end = guest.saturating_add(len);
    let mut t = table_mut();
    let mut out = Vec::with_capacity(t.len() + 1);
    for x in t.iter() {
        if x.hi <= guest || x.lo >= end {
            out.push(*x);
            continue;
        }
        if x.lo < guest {
            out.push(Translation { lo: x.lo, hi: guest, host: x.host });
        }
        if x.hi > end {
            out.push(Translation { lo: end, hi: x.hi, host: x.host + (end - x.lo) });
        }
    }
    *t = out;
}

/// Take a parent's translations, in a fork child.
pub fn set_translations(all: &[(u64, u64, u64)]) {
    let mut t: Vec<Translation> =
        all.iter().map(|&(g, l, h)| Translation { lo: g, hi: g + l, host: h }).collect();
    t.sort_by_key(|x| x.lo);
    *table_mut() = t;
}

/// Back guest addresses `[guest, guest + len)` with host memory at `host`,
/// as the only translated range.
pub fn set_translation(guest: u64, len: u64, host: u64) {
    set_translations(&[(guest, len, host)]);
}

/// Whether `[addr, addr + len)` straddles the edge of a translated range
/// (partly inside, partly out): such a range has no single host address,
/// and memory calls on it are refused where host memory is mapped for it.
pub fn crosses(addr: u64, len: u64) -> bool {
    let end = addr.saturating_add(len);
    table().iter().any(|t| addr < t.hi && end > t.lo && (addr < t.lo || end > t.hi))
}

/// The host address of guest address `addr`, and how many bytes from it
/// on share its translation (`u64::MAX` for an untranslated run).
fn run(addr: u64) -> (u64, u64) {
    let t = table();
    let i = t.partition_point(|x| x.hi <= addr);
    match t.get(i) {
        Some(x) if x.lo <= addr => (x.host + (addr - x.lo), x.hi - addr),
        Some(x) => (addr, x.lo - addr),
        None => (addr, u64::MAX),
    }
}

/// [`run`] without waiting for the table: `None` while it is being
/// changed. For a signal handler, which must not wait on a lock its own
/// thread may hold.
pub fn try_run(addr: u64) -> Option<(u64, u64)> {
    let t = TABLE.try_read().ok()?;
    let i = t.partition_point(|x| x.hi <= addr);
    Some(match t.get(i) {
        Some(x) if x.lo <= addr => (x.host + (addr - x.lo), x.hi - addr),
        Some(x) => (addr, x.lo - addr),
        None => (addr, u64::MAX),
    })
}

/// The host address of guest address `addr` (itself, outside every
/// translated range).
pub fn g2h(addr: u64) -> u64 {
    if table().is_empty() {
        return addr;
    }
    run(addr).0
}

thread_local! {
    /// The pointer arguments of the system call this thread is in that the
    /// backend translated ([`host_arg`]), as `(host, host end, guest)`: the
    /// kernel holds host addresses for them, which stand for those guest
    /// addresses — and nothing else does.
    static HOST_ARGS: std::cell::RefCell<Vec<(u64, u64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The host address for pointer argument `addr` of the system call this
/// thread is starting ([`g2h`]), remembered so the kernel's own copies
/// through it are taken as copies of `addr` ([`guest_of`]).
pub fn host_arg(addr: u64) -> u64 {
    if table().is_empty() {
        return addr;
    }
    let (host, room) = run(addr);
    if host != addr {
        HOST_ARGS.with(|h| h.borrow_mut().push((host, host.saturating_add(room), addr)));
    }
    host
}

/// The system call [`host_arg`] translated arguments for is over.
pub fn clear_host_args() {
    HOST_ARGS.with(|h| h.borrow_mut().clear());
}

/// The guest address an address the kernel holds stands for: the guest
/// address a translated pointer argument came from, else itself.
pub fn guest_of(addr: u64) -> u64 {
    HOST_ARGS.with(|h| {
        h.borrow()
            .iter()
            .find(|&&(lo, hi, _)| addr >= lo && addr < hi)
            .map_or(addr, |&(lo, _, g)| g + (addr - lo))
    })
}

/// Whether the guest may access `[addr, addr + len)` (for writing, with
/// `write`), as the backend's registered validator says.
type Validator = fn(u64, u64, bool) -> bool;

static VALIDATOR: std::sync::OnceLock<Validator> = std::sync::OnceLock::new();

/// Have every copy of guest memory first ask `f` whether the guest may
/// access the range, failing with `EFAULT` where it may not. For a backend
/// whose host memory stays accessible where the guest's is not.
pub fn set_validator(f: Validator) {
    let _ = VALIDATOR.set(f);
}

/// Whether the guest may access `[addr, addr + len)` (writing, with
/// `write`): always, without a validator (the host faults instead).
pub fn valid(addr: u64, len: u64, write: bool) -> bool {
    if write {
        // Pages of a file view become the guest's own first (as its own
        // write makes them).
        crate::mm::views_written(addr, len);
    }
    len == 0 || VALIDATOR.get().is_none_or(|f| f(addr, len, write))
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
    // fwe_uaccess_cas32(ptr, expected, new, old) -> 0, or 1 if the access
    // faulted: an atomic compare-and-swap of a 32-bit word, the value it
    // held stored at `old`. A leaf in the same range.
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
        ".globl _fwe_uaccess_cas32",
        "_fwe_uaccess_cas32:",
        // (Every Apple Silicon core has the atomics of ARMv8.1, LSE.)
        "    .arch_extension lse",
        "    casal w1, w2, [x0]",
        "    str w1, [x3]",
        "    mov x0, #0",
        "    ret",
        ".globl _fwe_uaccess_fault",
        "_fwe_uaccess_fault:",
        "    mov x0, #1",
        "    ret",
    );

    unsafe extern "C" {
        fn fwe_uaccess_copy(dst: *mut u8, src: *const u8, len: usize) -> u64;
        fn fwe_uaccess_cas32(ptr: *mut u32, expected: u32, new: u32, old: *mut u32) -> u64;
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

    /// Compare-and-swap the word at `ptr`: the value it held, or `None` if
    /// the access faulted.
    ///
    /// # Safety
    /// `ptr` must be 4-byte aligned; a fault there is recovered.
    pub unsafe fn cas32(ptr: *mut u32, expected: u32, new: u32) -> Option<u32> {
        let mut old = 0u32;
        // SAFETY: the routine touches only `ptr` and `old`; a fault at
        // `ptr` is recovered by the backend (see `fixup`).
        let r = unsafe { fwe_uaccess_cas32(ptr, expected, new, &mut old) };
        (r == 0).then_some(old)
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

    /// Compare-and-swap the word at `ptr` (unchecked on this host).
    ///
    /// # Safety
    /// `ptr` must be valid and 4-byte aligned.
    pub unsafe fn cas32(ptr: *mut u32, expected: u32, new: u32) -> Option<u32> {
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        // SAFETY: guaranteed by the caller.
        let word = unsafe { AtomicU32::from_ptr(ptr) };
        Some(word.compare_exchange(expected, new, SeqCst, SeqCst).unwrap_or_else(|v| v))
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

/// Copy between guest range `[addr, addr + len)` and fwe's buffer `buf`,
/// run by run of one translation: into the guest with `to_guest`.
///
/// # Safety
/// `buf` must be valid for `len` bytes.
unsafe fn copy_guest(addr: u64, buf: *mut u8, len: usize, to_guest: bool) -> Result<()> {
    let addr = guest_of(addr);
    // Past a user address space (48 bits), or wrapping: never the guest's,
    // and a fault there is not one a copy recovers from.
    if len != 0 && addr.checked_add(len as u64).is_none_or(|end| end > 1 << 48) {
        return Err(errno::EFAULT);
    }
    check(valid(addr, len as u64, to_guest))?;
    let mut done = 0usize;
    while done < len {
        let at = addr + done as u64;
        let (host, room) = run(at);
        let n = (len - done).min(room.min(usize::MAX as u64) as usize);
        // SAFETY: `buf + done` has `n` bytes (the caller's guarantee); the
        // guest side was validated and faults are recovered.
        let ok = unsafe {
            if to_guest {
                imp::copy(host as *mut u8, buf.add(done), n)
            } else {
                imp::copy(buf.add(done), host as *const u8, n)
            }
        };
        check(ok)?;
        done += n;
    }
    Ok(())
}

/// Atomically set the guest's 32-bit word at `addr` to `new` if it holds
/// `expected`: the value it held, or `EFAULT` (also for a word not
/// aligned).
pub fn cmpxchg_u32(addr: u64, expected: u32, new: u32) -> Result<u32> {
    let addr = guest_of(addr);
    if !addr.is_multiple_of(4) || addr >= 1 << 48 {
        return Err(errno::EFAULT);
    }
    check(valid(addr, 4, true))?;
    let host = run(addr).0;
    // SAFETY: an aligned guest word, validated; a fault is recovered.
    unsafe { imp::cas32(host as *mut u32, expected, new) }.ok_or(errno::EFAULT)
}

/// Copy `src` to host address `dst`, a guest buffer already translated
/// ([`host_buffer`], [`host_iovecs`]): `EFAULT`, not a crash, where the
/// guest's memory is not there.
pub fn write_host(dst: u64, src: &[u8]) -> Result<()> {
    // SAFETY: `src` is fwe's own buffer; a fault on `dst` is recovered.
    check(unsafe { imp::copy(dst as *mut u8, src.as_ptr(), src.len()) })
}

/// Copy `dst.len()` bytes from host address `src`, a guest buffer already
/// translated ([`host_buffer`], [`host_iovecs`]): `EFAULT`, not a crash,
/// where the guest's memory is not there (gone since it was checked).
pub fn read_host(src: u64, dst: &mut [u8]) -> Result<()> {
    // SAFETY: `dst` is fwe's own buffer; a fault on `src` is recovered.
    check(unsafe { imp::copy(dst.as_mut_ptr(), src as *const u8, dst.len()) })
}

/// Copy `dst.len()` bytes from guest address `addr`.
pub fn read_into(addr: u64, dst: &mut [u8]) -> Result<()> {
    // SAFETY: `dst` is fwe's own buffer of that length.
    unsafe { copy_guest(addr, dst.as_mut_ptr(), dst.len(), false) }
}

/// Copy `src` to guest address `addr`.
pub fn write_from(addr: u64, src: &[u8]) -> Result<()> {
    // SAFETY: `src` is fwe's own buffer of that length; it is only read.
    unsafe { copy_guest(addr, src.as_ptr() as *mut u8, src.len(), true) }
}

/// Read a `T` from guest address `addr`.
pub fn read<T: Copy>(addr: u64) -> Result<T> {
    let mut v = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `v` is `size_of::<T>()` writable bytes.
    unsafe { copy_guest(addr, v.as_mut_ptr().cast(), size_of::<T>(), false) }?;
    // SAFETY: fully written by the copy; the kernel only reads plain-data
    // ABI types, for which any bit pattern is valid.
    Ok(unsafe { v.assume_init() })
}

/// Write `value` to guest address `addr`.
pub fn write<T: Copy>(addr: u64, value: T) -> Result<()> {
    // SAFETY: `value` is a readable `T`; it is only read.
    unsafe { copy_guest(addr, (&raw const value) as *mut u8, size_of::<T>(), true) }
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
/// address translated, ready to hand to the host, which writes into the
/// buffers with `write`. Each buffer must be guest memory (`EFAULT`), in
/// one translated range or none (`EINVAL`: the host is given one address
/// for it).
/// The guest buffer of `len` bytes at `base` (written to if `write`) as
/// a host `iovec`, checked as [`host_iovecs`] checks each of its own.
/// `base` may be a pointer argument the backend translated already
/// ([`host_arg`]): it stands for the guest address it came from.
pub fn host_buffer(base: u64, len: u64, write: bool) -> Result<libc::iovec> {
    let base = guest_of(base);
    check(len == 0 || valid(base, len, write))?;
    if crosses(base, len) {
        return Err(errno::EINVAL);
    }
    let host = g2h(base);
    check(write || readable(host, len))?;
    Ok(libc::iovec { iov_base: host as *mut libc::c_void, iov_len: len as usize })
}

/// Whether all of host range `[host, host + len)`, a guest buffer the
/// host is to read whole, reads without faulting. Without a validator (the
/// in-process backend) the host would otherwise find a hole itself, partway
/// through, and a write would fail having written what came before it;
/// Linux refuses such a write, or writes only what it reports (`writev07`).
fn readable(host: u64, len: u64) -> bool {
    if len == 0
        || VALIDATOR.get().is_some()
        || !cfg!(all(target_os = "macos", target_arch = "aarch64"))
    {
        return true;
    }
    // A byte from each page, the guest's (4 KiB) as the finest grain.
    const PAGE: u64 = 4096;
    let end = host.saturating_add(len);
    let mut at = host;
    let mut byte = 0u8;
    while at < end {
        // SAFETY: one byte into a local; a fault on the guest's side is
        // recovered.
        if !unsafe { imp::copy(&mut byte, at as *const u8, 1) } {
            return false;
        }
        at = (at & !(PAGE - 1)) + PAGE;
    }
    true
}

/// The most buffers one vectored call takes (Linux's `UIO_MAXIOV`).
pub const UIO_MAXIOV: u64 = 1024;

pub fn host_iovecs(addr: u64, count: u64, write: bool) -> Result<Vec<libc::iovec>> {
    if count > UIO_MAXIOV {
        return Err(errno::EINVAL);
    }
    let raw = read_bytes(addr, count as usize * 16)?;
    let mut out = Vec::with_capacity(count as usize);
    for c in raw.as_chunks::<16>().0.iter() {
        let base = u64::from_ne_bytes(c[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(c[8..16].try_into().unwrap());
        // A length that is negative as a `ssize_t` is refused before any
        // address is looked at, as on Linux.
        if (len as i64) < 0 {
            return Err(errno::EINVAL);
        }
        // An empty buffer is never touched, as on Linux.
        out.push(host_buffer(base, len, write)?);
    }
    Ok(out)
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
        n::OPENAT2 => 0b110,
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
        n::FUTEX_WAITV => 0b1001,
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
        n::PSELECT6 => 0b11_1110,
        n::EPOLL_CTL => 0b1000,
        n::EPOLL_PWAIT => 0b1_0010,
        n::EPOLL_PWAIT2 => 0b1_1010,
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
/// a timeout pointer for the waits, a count for the requeues and `WAKE_OP`;
/// argument 4 a second word for those, unused by the wakes.
pub fn futex_pointer_args(op: u64) -> u8 {
    use fwe_abi::futex::*;
    match op & FUTEX_CMD_MASK {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => 0b1001,
        // A wake uses only the word: the other arguments may hold anything.
        FUTEX_WAKE | FUTEX_WAKE_BITSET => 0b1,
        _ => 0b1_0001,
    }
}

/// [`pointer_args`] for an `fcntl` call with command `cmd`: argument 2 is a
/// `struct flock` pointer for the record-lock commands, a number otherwise.
pub fn fcntl_pointer_args(cmd: u64) -> u8 {
    use fwe_abi::fcntl::*;
    match cmd {
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => 0b100,
        _ => 0,
    }
}

/// [`pointer_args`] for a `prctl` call with option `option`: argument 1 is a
/// pointer for the name and death-signal queries, a number otherwise.
pub fn prctl_pointer_args(option: u64) -> u8 {
    use fwe_abi::prctl::*;
    match option {
        PR_SET_NAME | PR_GET_NAME | PR_GET_PDEATHSIG => 0b10,
        _ => 0,
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

    /// Guest ranges in the low 4 GiB, which no test's real memory uses, so
    /// tests running alongside are not affected.
    #[test]
    fn translated_ranges_split_copies_where_they_meet() {
        let a = vec![0xaau8; 0x2000];
        let b = vec![0xbbu8; 0x1000];
        add_translation(0x1_0000, 0x2000, a.as_ptr() as u64);
        add_translation(0x1_2000, 0x1000, b.as_ptr() as u64);
        assert_eq!(g2h(0x1_0010), a.as_ptr() as u64 + 0x10);
        assert_eq!(g2h(0x1_2004), b.as_ptr() as u64 + 4);
        assert_eq!(g2h(0x9_0000), 0x9_0000, "untranslated");
        let mut got = [0u8; 32];
        read_into(0x1_1ff0, &mut got).unwrap();
        assert_eq!(&got[..16], &[0xaa; 16]);
        assert_eq!(&got[16..], &[0xbb; 16]);
        assert!(crosses(0x1_2800, 0x1000));
        assert!(crosses(0x1_0000, 0x3000), "no single host address for both");
        assert!(!crosses(0x1_0000, 0x2000));
        // Removing the middle of one splits it.
        remove_translation(0x1_0800, 0x800);
        assert_eq!(g2h(0x1_0900), 0x1_0900);
        assert_eq!(g2h(0x1_1004), a.as_ptr() as u64 + 0x1004);
        // A translated pointer argument stands for its guest address, and
        // copies through it are copies of the guest's memory.
        let h = host_arg(0x1_1000);
        assert_eq!(h, a.as_ptr() as u64 + 0x1000);
        assert_eq!(guest_of(h + 8), 0x1_1008);
        let mut one = [0u8; 4];
        read_into(h, &mut one).unwrap();
        assert_eq!(one, [0xaa; 4]);
        clear_host_args();
        assert_eq!(guest_of(h + 8), h + 8);
        remove_translation(0x1_0000, 0x3000);
        assert!(translations().iter().all(|&(g, _, _)| !(0x1_0000..0x1_0000_0000).contains(&g)));
    }

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
