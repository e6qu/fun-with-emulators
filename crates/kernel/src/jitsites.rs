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
//!
//! A JIT may also copy code out of a page while the page is executable
//! (macOS has no execute-only memory, so nothing stops it reading fwe's
//! words): HotSpot copies a method from the buffer it built it in, and the
//! buffer's page may have run (other code shares it) and been prepared
//! since the last write. A branch to a stub copied elsewhere leads to the
//! same distance from its new place, where there is no stub. A branch's
//! word is its distance alone, so each word fwe writes is kept with the
//! JIT's word it stands for, and before code a JIT wrote is prepared,
//! [`repair_copies`] puts back the JIT's word for each copy found there.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Changed words of JIT code: address -> (the JIT's word, fwe's word).
static SITES: Mutex<BTreeMap<u64, (u32, u32)>> = Mutex::new(BTreeMap::new());

/// Each word fwe wrote in JIT code -> the JIT's word it stands for, or
/// `None` where it has stood for more than one.
static WORDS: Mutex<Option<HashMap<u32, Option<u32>>>> = Mutex::new(None);

fn sites() -> std::sync::MutexGuard<'static, BTreeMap<u64, (u32, u32)>> {
    SITES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record that fwe changed the JIT's word `was` at `addr` to `now`.
pub fn record(addr: u64, was: u32, now: u32) {
    sites().insert(addr, (was, now));
    let mut words = WORDS.lock().unwrap_or_else(|e| e.into_inner());
    words
        .get_or_insert_with(HashMap::new)
        .entry(now)
        .and_modify(|w| {
            if *w != Some(was) {
                *w = None;
            }
        })
        .or_insert(Some(was));
}

/// Whether `w` decodes in one of the instruction classes a program's code
/// is made of: not the reserved class (`udf`, and any small number), the
/// unallocated ones, or SVE's (which Apple's cores do not have).
fn instruction_class(w: u32) -> bool {
    !matches!((w >> 25) & 0xf, 0b0000..=0b0011)
}

/// Whether word `i` of `words` sits among instructions: the two words on
/// each side of it that the range holds all decode in an instruction
/// class. Words past either end of the range are not held against it (the
/// code goes on in a page not being prepared). Code a JIT writes keeps
/// data among it, mostly pointers and small numbers, and a pointer above
/// 4 GiB has a small number for its high half, which decodes as no
/// instruction: so a word of data that happens to read as an instruction
/// fwe would change is told from one by its neighbours.
pub fn among_instructions(words: &[u32], i: usize) -> bool {
    (1..=2).all(|n| {
        (i < n || instruction_class(words[i - n]))
            && words.get(i + n).is_none_or(|&w| instruction_class(w))
    })
}

/// Whether `w` is an unconditional branch (`b`), and where it leads from
/// `at`.
fn branch_target(at: u64, w: u32) -> Option<u64> {
    (w >> 26 == 0b000101).then(|| at.wrapping_add_signed(i64::from(((w << 6) as i32) >> 4)))
}

/// In `[addr, addr + len)`, code a JIT wrote and is writable: put back the
/// JIT's word for each copy of a branch fwe wrote elsewhere, found as a
/// branch fwe did not write here, with the bits of one it did, among
/// instructions ([`among_instructions`]: not the low half of a pointer),
/// that leads where `code` says there is no code (a JIT's own branches
/// lead to its code). How many were put back.
pub fn repair_copies(addr: u64, len: u64, code: impl Fn(u64) -> bool) -> usize {
    let words = WORDS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(words) = words.as_ref() else { return 0 };
    let sites = sites();
    // SAFETY: the caller's range, readable.
    let here: Vec<u32> =
        unsafe { std::slice::from_raw_parts(addr as *const u32, (len / 4) as usize) }.to_vec();
    let mut repaired = 0;
    for (i, &w) in here.iter().enumerate() {
        let at = addr + 4 * i as u64;
        let p = at as *mut u32;
        let Some(to) = branch_target(at, w) else { continue };
        if !among_instructions(&here, i) {
            continue;
        }
        if sites.get(&at).is_some_and(|&(_, now)| now == w) {
            continue;
        }
        if let Some(&Some(was)) = words.get(&w)
            && !code(to)
        {
            // SAFETY: as above.
            unsafe { p.write_volatile(was) };
            repaired += 1;
        }
    }
    repaired
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy, elsewhere, of a branch fwe wrote gets the JIT's word back
    /// when its target is no code; one whose target is code is the JIT's.
    #[test]
    fn copied_branches_get_the_jits_word_back() {
        const NOP: u32 = 0xd503_201f;
        // `b .+0x100000`, standing for `ldr x0, [x18, #8]` at base.
        let (was, now) = (0xf940_0640, 0x1404_0000);
        // fwe's own at 0; the same bits as a pointer's low half at 1 (its
        // high half beside it); copies among instructions at 5 and 8.
        let mut code = vec![now, now, 0x0000_0200, NOP, NOP, now, NOP, NOP, now, NOP, NOP];
        let base = code.as_mut_ptr() as u64;
        record(base, was, now);
        // The copy at 8 leads to code; the one at 5 does not.
        let to8 = base + 32 + 0x10_0000;
        assert_eq!(repair_copies(base, 44, |t| t == to8), 1);
        assert_eq!((code[0], code[1], code[5], code[8]), (now, now, was, now));
        forget(base, 44);
    }

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
