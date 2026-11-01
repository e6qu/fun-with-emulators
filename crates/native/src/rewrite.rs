//! Redirection of guest system calls.
//!
//! A Linux system call is `svc #0`. Executed in a macOS process it would enter
//! the macOS kernel, so before guest code becomes executable every `svc #0`
//! is replaced with a `brk` carrying a distinctive immediate. The resulting
//! trap is delivered to our handler, which runs the Linux system call and
//! resumes the guest after the instruction.
//!
//! arm64 instructions are 4 bytes and 4-byte aligned, so scanning aligned
//! words finds every instruction exactly. A data word that happens to equal
//! `svc #0` inside an executable segment would also be rewritten.

/// `svc #0`.
pub const SVC0: u32 = 0xd400_0001;

/// Immediate of the trap instruction that replaces `svc #0` ("LX").
pub const TRAP_IMM: u32 = 0x4c58;

/// `brk #TRAP_IMM`.
pub const TRAP: u32 = 0xd420_0000 | (TRAP_IMM << 5);

/// Replace every aligned `svc #0` in `code` with [`TRAP`]. `code` must start
/// at a 4-byte aligned address. Returns the number of rewritten instructions.
pub fn patch(code: &mut [u8]) -> usize {
    let mut count = 0;
    for word in code.chunks_exact_mut(4) {
        if u32::from_le_bytes([word[0], word[1], word[2], word[3]]) == SVC0 {
            word.copy_from_slice(&TRAP.to_le_bytes());
            count += 1;
        }
    }
    count
}

/// Rewrite system calls in guest memory and make the result visible to
/// instruction fetch.
///
/// # Safety
/// `[addr, addr + len)` must be readable and writable guest memory that no
/// thread is executing.
pub unsafe fn patch_memory(addr: u64, len: u64) -> usize {
    let start = addr & !3;
    let len = (len + (addr - start)) & !3;
    // SAFETY: guaranteed by the caller.
    let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len as usize) };
    let count = patch(code);
    // SAFETY: the range was just validated as accessible memory.
    unsafe { flush_icache(start, len) };
    count
}

/// Invalidate the instruction cache for freshly written code.
///
/// # Safety
/// The range must be mapped.
#[cfg(target_os = "macos")]
pub unsafe fn flush_icache(addr: u64, len: u64) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
    }
    // SAFETY: guaranteed by the caller.
    unsafe { sys_icache_invalidate(addr as *mut libc::c_void, len as usize) }
}

/// Invalidate the instruction cache for freshly written code.
///
/// # Safety
/// The range must be mapped.
#[cfg(not(target_os = "macos"))]
pub unsafe fn flush_icache(_addr: u64, _len: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn trap_encoding() {
        // brk #0x4c58
        assert_eq!(TRAP, 0xd429_8b00);
    }

    #[test]
    fn rewrites_only_svc0() {
        let mov_x8 = 0xd280_0808; // mov x8, #64
        let svc1 = 0xd400_0021; // svc #1
        let mut code = words(&[mov_x8, SVC0, svc1, SVC0]);
        assert_eq!(patch(&mut code), 2);
        assert_eq!(code, words(&[mov_x8, TRAP, svc1, TRAP]));
    }

    #[test]
    fn ignores_unaligned_matches() {
        let mut code = vec![0u8; 2];
        code.extend_from_slice(&SVC0.to_le_bytes());
        code.extend_from_slice(&[0, 0]);
        assert_eq!(patch(&mut code), 0);
    }
}
