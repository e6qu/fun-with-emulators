//! The words fwe changed in code a JIT wrote, so that a JIT finds its code
//! as it wrote it whenever it can write to it.
//!
//! A JIT keeps its code in memory it writes again: it patches calls and
//! constants in place, and builds code in one place to copy to another
//! (HotSpot compiles into a buffer in its code cache, then copies the
//! result into the method it makes). fwe changes some of the words of
//! that code when it becomes executable (a system call, a thread-pointer
//! access or an `x18` use becomes a branch to a stub), and a JIT that then
//! wrote over such a word, or copied it elsewhere, would break: a branch
//! to a stub is relative to where it is.
//!
//! So each changed word is recorded with what it was and what it became.
//! When a page of such code is made writable again
//! ([`crate::mm::write_exec_writable`]), every word there still as fwe
//! made it goes back to what the JIT wrote; the next time the page runs it
//! is prepared again, and a site that is what it was gets its old stub
//! back ([`reusable`]), so stub space does not grow with each round.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Changed words of JIT code: address -> (the JIT's word, fwe's word).
static SITES: Mutex<BTreeMap<u64, (u32, u32)>> = Mutex::new(BTreeMap::new());

fn sites() -> std::sync::MutexGuard<'static, BTreeMap<u64, (u32, u32)>> {
    SITES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record that fwe changed the JIT's word `was` at `addr` to `now`.
pub fn record(addr: u64, was: u32, now: u32) {
    sites().insert(addr, (was, now));
}

/// fwe's word for the site at `addr`, if the JIT's word there is `was` as
/// it was when fwe changed it last: its stub is there still, for the same
/// instruction at the same place.
pub fn reusable(addr: u64, was: u32) -> Option<u32> {
    sites().get(&addr).filter(|&&(w, _)| w == was).map(|&(_, now)| now)
}

/// Put back the JIT's words in `[addr, addr + len)`, which is writable:
/// each word still as fwe made it. The records are kept, for
/// [`reusable`].
pub fn restore(addr: u64, len: u64) {
    for (&at, &(was, now)) in sites().range(addr..addr.saturating_add(len)) {
        let p = at as *mut u32;
        // SAFETY: a word of guest code fwe changed, in memory the caller
        // has just made writable.
        unsafe {
            if p.read_volatile() == now {
                p.write_volatile(was);
            }
        }
    }
}

/// Forget the records of `[addr, addr + len)`, which no longer holds the
/// code they were of (unmapped, or mapped anew).
pub fn forget(addr: u64, len: u64) {
    let mut s = sites();
    let gone: Vec<u64> = s.range(addr..addr.saturating_add(len)).map(|(&a, _)| a).collect();
    for a in gone {
        s.remove(&a);
    }
}

/// fwe's word at `addr`, if it changed the JIT's word there.
pub fn written(addr: u64) -> Option<u32> {
    sites().get(&addr).map(|&(_, now)| now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A word fwe changed goes back when its page is writable again, unless
    /// the JIT has written it since; the record stays, for the stub's reuse
    /// while the JIT's word is what it was.
    #[test]
    fn changed_words_go_back_and_their_stubs_are_kept() {
        let mut code = vec![0u32; 4];
        let base = code.as_mut_ptr() as u64;
        let (was, now) = (0xf940_0640, 0x1400_0100);
        code[1] = now;
        code[2] = now;
        record(base + 4, was, now);
        record(base + 8, was, now);
        // The JIT wrote its own word over the second.
        code[2] = 0xd503_201f;
        restore(base, 16);
        assert_eq!(code[1], was);
        assert_eq!(code[2], 0xd503_201f);
        assert_eq!(reusable(base + 4, was), Some(now));
        assert_eq!(reusable(base + 4, 0xd503_201f), None);
        forget(base, 16);
        assert_eq!(reusable(base + 4, was), None);
    }
}
