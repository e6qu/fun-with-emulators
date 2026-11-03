//! The host address range all guest memory of a VM process lives in.
//!
//! A forked child is a fresh fwe process that must map the parent's memory
//! at the same host addresses (the VM's guest addresses equal them), so guest
//! memory cannot be wherever the host's allocator happens to put it: the
//! child's own heap, `dyld` and stacks land unpredictably. Instead fwe
//! reserves one large window at startup, inaccessible and backed by nothing,
//! and places guest memory inside it — the image's host copy, the stack, the
//! break, the trampoline and each `mmap` the guest does not place itself. A
//! child reserves the same window first thing, before anything else could
//! land there. Unmapped guest memory goes back to the reservation in one
//! step, so the host never reuses it. A guest's `MAP_FIXED` mapping at an
//! address outside the window works, but a process holding one cannot fork.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// The window: from 512 GiB to just under the VM's 1 TiB address limit
/// (the top 64 GiB are left for fwe's own structures and slack).
pub const LO: u64 = 512 << 30;
pub const HI: u64 = 960 << 30;
const PAGE: u64 = 16 << 10;

/// Ranges of the window in use, `start -> end`.
static USED: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn used() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    USED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Turn `[addr, addr + len)` back into inaccessible reserved space.
fn reserve_range(addr: u64, len: u64) -> bool {
    // SAFETY: replacing guest memory inside the window with a fresh
    // inaccessible mapping; nothing of fwe's lives there.
    let p = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    p as u64 == addr
}

/// Reserve the whole window. Called once, early, in every VM process.
pub fn reserve() -> Result<(), String> {
    let mut at = LO;
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: i32) -> i32;
    }
    // SAFETY: a fixed allocation in our own task that fails rather than
    // replace anything (no VM_FLAGS_OVERWRITE); then made inaccessible.
    let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut at, HI - LO, 0) };
    if kr != 0 {
        return Err(format!("reserving guest memory at {LO:#x}..{HI:#x} failed ({kr})"));
    }
    if !reserve_range(LO, HI - LO) {
        return Err("protecting the guest memory reservation failed".into());
    }
    Ok(())
}

/// The ranges in use, `start -> end`: all of the guest's memory.
pub fn used_ranges() -> BTreeMap<u64, u64> {
    used().clone()
}

/// Take the parent's ranges, in a fork child that has mapped them.
pub fn set_used(ranges: BTreeMap<u64, u64>) {
    *used() = ranges;
}

/// A free page-aligned range of `len` bytes in the window, now marked used.
pub fn alloc(len: u64) -> Option<u64> {
    let len = len.div_ceil(PAGE) * PAGE;
    let mut u = used();
    let mut at = LO;
    for (&s, &e) in u.iter() {
        if s >= at + len {
            break;
        }
        at = at.max(e);
    }
    if at + len > HI {
        return None;
    }
    u.insert(at, at + len);
    Some(at)
}

/// Record `[addr, addr + len)` as in use (a fixed mapping the guest made).
pub fn mark_used(addr: u64, len: u64) {
    let (lo, hi) = (addr.max(LO), (addr + len).min(HI));
    if lo >= hi {
        return;
    }
    let mut u = used();
    let (mut s, mut e) = (lo, hi);
    let touching: Vec<(u64, u64)> =
        u.range(..=e).rev().take_while(|&(_, &x)| x >= s).map(|(&a, &b)| (a, b)).collect();
    for (a, b) in touching {
        u.remove(&a);
        s = s.min(a);
        e = e.max(b);
    }
    u.insert(s, e);
}

/// Give `[addr, addr + len)` back: it becomes reserved space again, in one
/// step that replaces whatever was mapped there. False, doing nothing, for
/// a range not inside the window.
pub fn release(addr: u64, len: u64) -> bool {
    if addr < LO || addr.saturating_add(len) > HI || len == 0 {
        return false;
    }
    let (lo, hi) = (addr, addr + len);
    if !reserve_range(lo, hi - lo) {
        return false;
    }
    let mut u = used();
    let hit: Vec<(u64, u64)> =
        u.range(..hi).rev().take_while(|&(_, &x)| x > lo).map(|(&a, &b)| (a, b)).collect();
    for (a, b) in hit {
        u.remove(&a);
        if a < lo {
            u.insert(a, lo);
        }
        if b > hi {
            u.insert(hi, b);
        }
    }
    true
}
