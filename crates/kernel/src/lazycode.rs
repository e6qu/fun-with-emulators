//! Code whose preparation is finished on first use: the instructions a
//! mapping's preparation rewrites in a page (its sites' branches to their
//! stubs, its system calls) are written when the guest first runs code in
//! that page, not when it is mapped. A large library is mostly not run (a
//! `clang --version` runs little of LLVM), and a page written is a page
//! copied: preparing every page as the library is mapped copies most of it.
//!
//! A page with writes owed is kept readable but not executable; the guest's
//! first instruction fetch there faults, the backend's fault handler asks
//! [`fault`], which writes them and gives the page the protections the
//! guest gave it. A read of the page sees the file's own bytes, as it
//! would on Linux. The guest making the page writable has the writes made
//! first ([`protected`]), so that none lands on what the guest wrote.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A write owed: where, the word there now, and the word to put there.
pub type Write = (u64, u32, u32);

/// A page with writes owed: the writes, and the protections the guest
/// gave the page (host bits).
struct Owed {
    writes: Vec<Write>,
    prot: i32,
}

/// Pages by their host address.
static OWED: Mutex<BTreeMap<u64, Owed>> = Mutex::new(BTreeMap::new());

fn owed() -> std::sync::MutexGuard<'static, BTreeMap<u64, Owed>> {
    OWED.lock().unwrap_or_else(|e| e.into_inner())
}

/// The host's page size, which protections are set by.
fn page() -> u64 {
    static PAGE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    // SAFETY: plain host call.
    *PAGE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64)
}

/// Owe `writes` to the pages they fall in, which the caller has prepared
/// otherwise; their protections are set once the mapping's are
/// ([`protected`]).
pub fn owe(writes: Vec<Write>) {
    let page = page();
    let mut o = owed();
    for w in writes {
        o.entry(w.0 & !(page - 1)).or_insert(Owed { writes: Vec::new(), prot: 0 }).writes.push(w);
    }
}

/// Whether any page is owed writes.
fn any() -> bool {
    !owed().is_empty()
}

/// Host memory `[addr, addr + len)` was given host protections `prot`: the
/// pages in it that are owed writes keep them, but not to run, so the
/// first run faults; made writable, they are written now.
pub fn protected(addr: u64, len: u64, prot: i32) {
    if !any() {
        return;
    }
    let page = page();
    let mut o = owed();
    let pages: Vec<u64> =
        o.range(addr & !(page - 1)..addr.saturating_add(len)).map(|(&p, _)| p).collect();
    for p in pages {
        if prot & libc::PROT_WRITE != 0 {
            let owed = o.remove(&p).expect("listed");
            write(p, &owed.writes, prot);
            continue;
        }
        let e = o.get_mut(&p).expect("listed");
        e.prot = prot;
        // SAFETY: a page of guest code fwe prepared, made not to run until
        // its writes are made.
        unsafe { libc::mprotect(p as *mut libc::c_void, page as usize, prot & !libc::PROT_EXEC) };
    }
}

/// Host memory `[addr, addr + len)` is gone: nothing is owed there.
pub fn unmapped(addr: u64, len: u64) {
    if !any() {
        return;
    }
    let page = page();
    let mut o = owed();
    let pages: Vec<u64> =
        o.range(addr & !(page - 1)..addr.saturating_add(len)).map(|(&p, _)| p).collect();
    for p in pages {
        o.remove(&p);
    }
}

/// Make what is owed in `[addr, addr + len)` now, the pages keeping their
/// protections: before their contents move ([`crate::mm`]'s `mremap`).
pub fn settle(addr: u64, len: u64) {
    if !any() {
        return;
    }
    let page = page();
    let mut o = owed();
    let pages: Vec<u64> =
        o.range(addr & !(page - 1)..addr.saturating_add(len)).map(|(&p, _)| p).collect();
    for p in pages {
        let owed = o.remove(&p).expect("listed");
        write(p, &owed.writes, owed.prot);
    }
}

/// The guest faulted at host address `pc`: if the fault is the first run
/// of a page owed writes, make them and give the page its protections, and
/// the guest runs on. Called from the fault handler.
pub fn fault(pc: u64) -> bool {
    if !any() {
        return false;
    }
    let p = pc & !(page() - 1);
    let Some(owed) = owed().remove(&p) else { return false };
    write(p, &owed.writes, owed.prot);
    true
}

/// Make `writes` in page `p` and give it host protections `prot`. A word
/// that is not what it was when the write was owed (the file changed in
/// place, keeping its size and time) is left as it is.
fn write(p: u64, writes: &[Write], prot: i32) {
    let page = page();
    // SAFETY: a page of guest code fwe prepared, writable while the words
    // are written, then as the guest protected it, with the instruction
    // cache made to see the change.
    unsafe {
        libc::mprotect(p as *mut libc::c_void, page as usize, libc::PROT_READ | libc::PROT_WRITE);
        for &(at, was, word) in writes {
            if (at as *const u32).read() == was {
                (at as *mut u32).write(word);
            }
        }
        libc::mprotect(p as *mut libc::c_void, page as usize, prot);
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
            }
            sys_icache_invalidate(p as *mut libc::c_void, page as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owed writes are made on the first run, and at once when the page is
    /// made writable.
    #[test]
    fn writes_owed_until_run_or_written() {
        let page = page();
        // SAFETY: a fresh anonymous mapping of the test's own.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        } as u64;
        owe(vec![
            (p + 8, 0, 0x1111_1111),
            (p + page + 4, 0, 0x2222_2222),
            (p + 12, 7, 0x3333_3333),
        ]);
        protected(p, 2 * page, libc::PROT_READ);
        // SAFETY: the mapping above, readable.
        assert_eq!(unsafe { ((p + 8) as *const u32).read() }, 0);
        assert!(fault(p + 100));
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + 8) as *const u32).read() }, 0x1111_1111);
        // Not what it was: left alone.
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + 12) as *const u32).read() }, 0);
        assert!(!fault(p + 100));
        protected(p + page, page, libc::PROT_READ | libc::PROT_WRITE);
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + page + 4) as *const u32).read() }, 0x2222_2222);
        assert!(!any() || owed().range(p..p + 2 * page).next().is_none());
        // SAFETY: the test's own mapping.
        unsafe { libc::munmap(p as *mut libc::c_void, 2 * page as usize) };
    }
}
