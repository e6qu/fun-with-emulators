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

/// Pages by their host address: those owed writes, and those whose writes
/// were made (a thread that faulted there while another made them runs on).
#[derive(Default)]
struct Pages {
    owed: BTreeMap<u64, Owed>,
    done: std::collections::BTreeSet<u64>,
}

static PAGES: Mutex<Pages> =
    Mutex::new(Pages { owed: BTreeMap::new(), done: std::collections::BTreeSet::new() });

fn pages() -> std::sync::MutexGuard<'static, Pages> {
    PAGES.lock().unwrap_or_else(|e| e.into_inner())
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
    let mut pg = pages();
    for w in writes {
        let p = w.0 & !(page - 1);
        pg.done.remove(&p);
        pg.owed.entry(p).or_insert(Owed { writes: Vec::new(), prot: 0 }).writes.push(w);
    }
}

/// Whether any page is owed writes.
fn any() -> bool {
    let pg = pages();
    !pg.owed.is_empty() || !pg.done.is_empty()
}

/// The owed pages in `[addr, addr + len)`.
fn owed_in(pg: &Pages, addr: u64, len: u64) -> Vec<u64> {
    let page = page();
    pg.owed.range(addr & !(page - 1)..addr.saturating_add(len)).map(|(&p, _)| p).collect()
}

/// Host memory `[addr, addr + len)` was given host protections `prot`: the
/// pages in it that are owed writes keep them, but not to run, so the
/// first run faults; made writable, they are written now.
pub fn protected(addr: u64, len: u64, prot: i32) {
    if !any() {
        return;
    }
    let page = page();
    let mut pg = pages();
    for p in owed_in(&pg, addr, len) {
        if prot & libc::PROT_WRITE != 0 {
            let owed = pg.owed.remove(&p).expect("listed");
            write(p, &owed.writes, prot);
            pg.done.insert(p);
            continue;
        }
        let e = pg.owed.get_mut(&p).expect("listed");
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
    let mut pg = pages();
    for p in owed_in(&pg, addr, len) {
        pg.owed.remove(&p);
    }
    let end = addr.saturating_add(len);
    let done: Vec<u64> = pg.done.range(addr & !(page - 1)..end).copied().collect();
    for p in done {
        pg.done.remove(&p);
    }
}

/// Make what is owed in `[addr, addr + len)` now, the pages keeping their
/// protections: before their contents move ([`crate::mm`]'s `mremap`).
pub fn settle(addr: u64, len: u64) {
    if !any() {
        return;
    }
    let mut pg = pages();
    for p in owed_in(&pg, addr, len) {
        let owed = pg.owed.remove(&p).expect("listed");
        write(p, &owed.writes, owed.prot);
        pg.done.insert(p);
    }
}

/// The guest faulted at host address `pc` on `addr`: if the fault is the
/// first run of a page owed writes (an instruction fetch there, `addr` in
/// the page of `pc`), make them and give the page its protections, and the
/// guest runs on. Any other fault (a data access) is not one of these.
/// Called from the fault handler.
pub fn fault(pc: u64, addr: u64) -> bool {
    if !any() {
        return false;
    }
    let p = pc & !(page() - 1);
    if addr & !(page() - 1) != p {
        return false;
    }
    // Under the lock throughout: another thread that faults on the page
    // meanwhile waits, then finds it done and runs on.
    let mut pg = pages();
    if pg.done.contains(&p) {
        return true;
    }
    let Some(owed) = pg.owed.remove(&p) else { return false };
    write(p, &owed.writes, owed.prot);
    pg.done.insert(p);
    WRITTEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    true
}

/// How many pages were written as they first ran ([`fault`]).
static WRITTEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many pages were written as they first ran, for `FWE_TIMING`.
pub fn written() -> u64 {
    WRITTEN.load(std::sync::atomic::Ordering::Relaxed)
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
        assert!(fault(p + 100, p + 100));
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + 8) as *const u32).read() }, 0x1111_1111);
        // Not what it was: left alone.
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + 12) as *const u32).read() }, 0);
        // Done: a thread that faulted there meanwhile runs on; a data
        // fault there is not one of these.
        assert!(fault(p + 100, p + 100));
        assert!(!fault(p + 100, p + 3 * page));
        protected(p + page, page, libc::PROT_READ | libc::PROT_WRITE);
        // SAFETY: as above.
        assert_eq!(unsafe { ((p + page + 4) as *const u32).read() }, 0x2222_2222);
        assert!(pages().owed.range(p..p + 2 * page).next().is_none());
        unmapped(p, 2 * page);
        // SAFETY: the test's own mapping.
        unsafe { libc::munmap(p as *mut libc::c_void, 2 * page as usize) };
    }
}
