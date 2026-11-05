//! The slab: the one host range all of a VM process's private guest memory
//! lives in, mapped into the VM once, whole, when the VM is made
//! ([`super::vm`]). Nothing ever replaces host memory inside it — the
//! framework keeps the host pages it found at mapping time — so it is plain
//! zero-fill memory from start to end of the process, and what the guest
//! sees is decided by the guest's own page tables, not by the host's
//! mappings.
//!
//! It sits at the same host address in every VM process (from 512 GiB up),
//! reserved first thing, so a fork child can take its parent's memory at
//! the same addresses. Within it, this module hands out ranges: a guest
//! mapping placed where the guest did not ask for an address uses the same
//! address as guest address and host address; a guest mapping at a fixed
//! address outside the slab (a program image linked low, say) is backed by
//! a range of the slab and translated. A range given back has held data,
//! so it is zeroed before it is handed out again — the host's own
//! `madvise` is not used on memory the VM maps.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

/// Where the slab starts.
pub const LO: u64 = 512 << 30;
/// The page size ranges are handed out in (the guest's).
const PAGE: u64 = 4 << 10;

static SIZE: AtomicU64 = AtomicU64::new(0);

/// The end of the slab.
pub fn hi() -> u64 {
    LO + SIZE.load(SeqCst)
}

/// What the slab's ranges are doing.
struct State {
    /// In use, `start -> end`.
    used: BTreeMap<u64, u64>,
    /// Free but holding old data, `start -> end`: zeroed before reuse.
    dirty: BTreeMap<u64, u64>,
}

static STATE: Mutex<State> = Mutex::new(State { used: BTreeMap::new(), dirty: BTreeMap::new() });

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reserve the slab, `size` bytes of fresh zero-fill memory at [`LO`].
/// Called once, early, in every VM process.
pub fn reserve(size: u64) -> Result<(), String> {
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: i32) -> i32;
    }
    let mut at = LO;
    // SAFETY: a fixed allocation in our own task that fails rather than
    // replace anything (no VM_FLAGS_OVERWRITE).
    let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut at, size, 0) };
    if kr != 0 {
        return Err(format!("reserving guest memory at {LO:#x}+{size:#x} failed ({kr})"));
    }
    SIZE.store(size, SeqCst);
    Ok(())
}

/// Whether `[addr, addr + len)` lies inside the slab.
pub fn contains(addr: u64, len: u64) -> bool {
    addr >= LO && addr.checked_add(len).is_some_and(|end| end <= hi())
}

fn add(map: &mut BTreeMap<u64, u64>, start: u64, end: u64) {
    let (mut s, mut e) = (start, end);
    let touching: Vec<(u64, u64)> =
        map.range(..=e).rev().take_while(|&(_, &x)| x >= s).map(|(&a, &b)| (a, b)).collect();
    for (a, b) in touching {
        map.remove(&a);
        s = s.min(a);
        e = e.max(b);
    }
    map.insert(s, e);
}

/// Take `[start, end)` out of `map`, returning the parts that were in it.
fn take(map: &mut BTreeMap<u64, u64>, start: u64, end: u64) -> Vec<(u64, u64)> {
    let hit: Vec<(u64, u64)> =
        map.range(..end).rev().take_while(|&(_, &x)| x > start).map(|(&a, &b)| (a, b)).collect();
    let mut out = Vec::new();
    for (a, b) in hit {
        map.remove(&a);
        if a < start {
            map.insert(a, start);
        }
        if b > end {
            map.insert(end, b);
        }
        out.push((a.max(start), b.min(end)));
    }
    out
}

/// Mark `[start, end)` used, zeroing whatever of it held old data.
fn claim(st: &mut State, start: u64, end: u64) {
    for (a, b) in take(&mut st.dirty, start, end) {
        // SAFETY: slab memory, now in use by the caller, which no one else
        // reaches (it was free; any translation of it was flushed before it
        // was given back).
        unsafe { std::ptr::write_bytes(a as *mut u8, 0, (b - a) as usize) };
    }
    add(&mut st.used, start, end);
}

/// A free range of `len` bytes (page-rounded), now in use and zeroed.
pub fn alloc(len: u64) -> Option<u64> {
    let len = len.div_ceil(PAGE) * PAGE;
    let mut st = state();
    let mut at = LO;
    for (&s, &e) in st.used.iter() {
        if s >= at + len {
            break;
        }
        at = at.max(e);
    }
    if at.checked_add(len)? > hi() {
        return None;
    }
    claim(&mut st, at, at + len);
    Some(at)
}

/// Use `[addr, addr + len)` (a mapping the guest placed itself), zeroing
/// what of it held old data. False if any of it is in use, or it is not in
/// the slab.
pub fn take_fixed(addr: u64, len: u64) -> bool {
    if !contains(addr, len) {
        return false;
    }
    let mut st = state();
    let end = addr + len;
    if st.used.range(..end).next_back().is_some_and(|(_, &e)| e > addr) {
        return false;
    }
    claim(&mut st, addr, end);
    true
}

/// Give back `[addr, addr + len)`: free, and zeroed when reused. The
/// caller has made sure no translation of it is left in any TLB.
pub fn release(addr: u64, len: u64) {
    let mut st = state();
    let end = addr + len;
    for (a, b) in take(&mut st.used, addr, end) {
        add(&mut st.dirty, a, b);
    }
}

/// The ranges in use, `start -> end`.
pub fn used_ranges() -> BTreeMap<u64, u64> {
    state().used.clone()
}

/// Take the parent's ranges, in a fork child that holds their contents.
pub fn set_used(ranges: BTreeMap<u64, u64>) {
    let mut st = state();
    st.used = ranges;
    st.dirty.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_split_and_merge() {
        let mut m = BTreeMap::new();
        add(&mut m, 0x1000, 0x3000);
        add(&mut m, 0x3000, 0x5000);
        assert_eq!(m.iter().map(|(&a, &b)| (a, b)).collect::<Vec<_>>(), vec![(0x1000, 0x5000)]);
        assert_eq!(take(&mut m, 0x2000, 0x4000), vec![(0x2000, 0x4000)]);
        assert_eq!(
            m.iter().map(|(&a, &b)| (a, b)).collect::<Vec<_>>(),
            vec![(0x1000, 0x2000), (0x4000, 0x5000)]
        );
    }
}
