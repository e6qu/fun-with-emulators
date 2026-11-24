//! fwe's memory allocator: the host's (`malloc`), but for blocks of
//! [`MAPPED_FROM`] bytes or more, each mapped on its own.
//!
//! A host `fork` makes the child's copy of the parent's memory, and every
//! page the parent has written in the host allocator's regions makes the
//! fork dearer, freed or not: about 120 instructions a KiB, 200,000 more
//! for the 1.5 MB of a program read into memory (mapped on its own, the
//! same memory adds nothing). A guest's `fork` is a host `fork` of fwe, so
//! fwe's own large blocks (a program's bytes, a cache entry read whole)
//! are kept out of those regions; there are few of them, so a mapping each
//! costs little.
//!
//! A debug build ends the process if a host signal handler that interrupted
//! fwe's own code allocates or frees ([`fwe_kernel::host::NoAllocation`]):
//! that code may have been inside the host allocator.

use std::alloc::{GlobalAlloc, Layout, System};

/// The size from which a block is mapped on its own: the host allocator's
/// "medium" blocks start here.
const MAPPED_FROM: usize = 32 << 10;

/// The host's page size, the most a mapping's start is aligned to.
const PAGE: usize = 16 << 10;

pub struct Allocator;

/// In a debug build: end the process, saying why, if the calling thread
/// is in a signal handler that may not allocate.
#[inline(always)]
fn not_in_a_handler() {
    #[cfg(debug_assertions)]
    if fwe_kernel::host::allocation_forbidden() {
        const WHY: &[u8] = b"fwe: an allocation in a signal handler that interrupted fwe\n";
        // SAFETY: a write of a static message, then the end of the process
        // by `SIGABRT` at its default action (fwe's handler for it is
        // where the allocation may be).
        unsafe {
            libc::write(2, WHY.as_ptr().cast(), WHY.len());
            libc::signal(libc::SIGABRT, libc::SIG_DFL);
            let mut abrt = fwe_kernel::host::empty_sigset();
            libc::sigaddset(&mut abrt, libc::SIGABRT);
            fwe_kernel::host::unblock_signals(&abrt);
            libc::abort();
        }
    }
}

fn mapped(l: Layout) -> bool {
    l.size() >= MAPPED_FROM && l.align() <= PAGE
}

// SAFETY: blocks are from `System` or from a mapping of their own, made and
// let go by the same test of their layout; a mapping is page-aligned and
// zero-filled, as `alloc_zeroed` needs.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        not_in_a_handler();
        if !mapped(l) {
            // SAFETY: the caller's layout, as `GlobalAlloc` asks.
            return unsafe { System.alloc(l) };
        }
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                l.size(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED { std::ptr::null_mut() } else { p.cast() }
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        not_in_a_handler();
        if !mapped(l) {
            // SAFETY: the caller's layout.
            return unsafe { System.alloc_zeroed(l) };
        }
        // SAFETY: as `alloc`; a new mapping reads as zero.
        unsafe { self.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        not_in_a_handler();
        if !mapped(l) {
            // SAFETY: a block `System` made for this layout.
            return unsafe { System.dealloc(p, l) };
        }
        // SAFETY: the block's own mapping, of its size.
        unsafe { libc::munmap(p.cast(), l.size()) };
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        not_in_a_handler();
        // SAFETY: the caller's layout and size, as `GlobalAlloc` asks.
        let new = unsafe { Layout::from_size_align_unchecked(size, l.align()) };
        if !mapped(l) && !mapped(new) {
            // SAFETY: a block `System` made for `l`.
            return unsafe { System.realloc(p, l, size) };
        }
        // SAFETY: a new block of the new layout, the old one's bytes copied
        // into it, and the old one let go.
        unsafe {
            let q = self.alloc(new);
            if !q.is_null() {
                std::ptr::copy_nonoverlapping(p, q, l.size().min(size));
                self.dealloc(p, l);
            }
            q
        }
    }
}
