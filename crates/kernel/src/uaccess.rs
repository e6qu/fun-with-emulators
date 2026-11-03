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

use fwe_abi::errno;

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
    check(unsafe { imp::copy(dst.as_mut_ptr(), addr as *const u8, dst.len()) })
}

/// Copy `src` to guest address `addr`.
pub fn write_from(addr: u64, src: &[u8]) -> Result<()> {
    // SAFETY: `src` is fwe's own buffer; the guest side is checked.
    check(unsafe { imp::copy(addr as *mut u8, src.as_ptr(), src.len()) })
}

/// Read a `T` from guest address `addr`.
pub fn read<T: Copy>(addr: u64) -> Result<T> {
    let mut v = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `v` is `size_of::<T>()` writable bytes; the guest side is
    // checked.
    let ok = unsafe { imp::copy(v.as_mut_ptr().cast(), addr as *const u8, size_of::<T>()) };
    check(ok)?;
    // SAFETY: fully written by the copy; the kernel only reads plain-data
    // ABI types, for which any bit pattern is valid.
    Ok(unsafe { v.assume_init() })
}

/// Write `value` to guest address `addr`.
pub fn write<T: Copy>(addr: u64, value: T) -> Result<()> {
    // SAFETY: `value` is a readable `T`; the guest side is checked.
    let ok = unsafe { imp::copy(addr as *mut u8, (&raw const value).cast(), size_of::<T>()) };
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
