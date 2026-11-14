//! Shared futexes: those without `FUTEX_PRIVATE_FLAG`, which Linux keys by
//! the memory the futex word is in, so a process may wait on a word in
//! memory it shares with another (a `MAP_SHARED` mapping, a file in
//! `/dev/shm`) and be woken from there: process-shared locks, conditions
//! and semaphores, and test harnesses that count whom they woke.
//!
//! Every fwe process maps one table ([`table`]), a file in fwe's private
//! directory. A waiter takes a slot in it, writes its futex's key there
//! (what memory the word is in, as [`crate::mm::region::sharing`] tells
//! it: the memory object and offset for shared memory, as Linux keys the
//! page; the process and address for private memory), and sleeps on the
//! slot's own state word, a shared host address wait (`__ulock_wait2`
//! with `UL_COMPARE_AND_WAIT_SHARED`). A wake claims the waiting slots of
//! the key, oldest first, marking each woken and waking its word: so it
//! knows exactly whom it woke, as Linux reports it, which the host's own
//! address waits cannot say. A requeue moves a slot to another key.
//!
//! A slot's state carries a generation, which every change of what the
//! slot stands for bumps (freeing it, moving it to another futex): a wake
//! claims a slot only in the state it saw it in, so never one freed and
//! taken again meanwhile, nor one moved off the futex it is waking. A slot
//! is its owner's, a process known by pid and start time: one whose owner
//! has gone (killed while it waited) is freed by the next process that
//! looks, and a process frees what its pid holds as it starts or runs
//! another program (`execve`), whose threads cannot be waiting.

use fwe_abi::{err, errno};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};
use std::time::Instant;

const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
const ULF_NO_ERRNO: u32 = 0x0100_0000;

unsafe extern "C" {
    fn __ulock_wait2(
        op: u32,
        addr: *mut libc::c_void,
        value: u64,
        timeout_ns: u64,
        value2: u64,
    ) -> libc::c_int;
    fn __ulock_wake(op: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

/// One waiter.
#[repr(C)]
struct Slot {
    /// Generation (above) and state (the low byte): [`FREE`], [`TAKEN`]
    /// while it is filled in, [`WAITING`], [`MOVING`] while a requeue
    /// changes its key, [`WOKEN`].
    state: AtomicU32,
    /// The `FUTEX_WAIT_BITSET` bits it waits for (all, for `FUTEX_WAIT`).
    bits: AtomicU32,
    /// The host pid of the process waiting.
    owner: AtomicU32,
    /// When it came, from [`Header::tickets`]: the oldest is woken first.
    ticket: AtomicU32,
    /// When the owner started ([`crate::procreg::start_time`]).
    owner_start: AtomicU64,
    /// The futex's key.
    key: [AtomicU64; 2],
}

const FREE: u32 = 0;
const TAKEN: u32 = 1;
const WAITING: u32 = 2;
const WOKEN: u32 = 3;
const MOVING: u32 = 4;

/// The first slot's room: the counter tickets are drawn from, and how far
/// into the table a slot has ever been taken (a waiter takes the first
/// free one), so a wake looks no further.
#[repr(C)]
struct Header {
    tickets: AtomicU32,
    high: AtomicU32,
}

/// The slots that may be in use: those up to the highest ever taken.
fn in_use(t: &[Slot]) -> &[Slot] {
    let high = header().map_or(t.len(), |h| h.high.load(SeqCst) as usize);
    &t[..high.min(t.len())]
}

/// Slots in the table (more threads than this waiting on shared futexes
/// at once, across every fwe process of the user, is beyond any program
/// fwe runs).
const SLOTS: usize = 16384;

fn st(state: u32) -> u32 {
    state & 0xff
}

fn with_state(state: u32, st: u32) -> u32 {
    (state & !0xff) | st
}

/// `state` as what the slot stands for changes: the next generation.
fn next(state: u32, st: u32) -> u32 {
    (state.wrapping_add(0x100) & !0xff) | st
}

/// The table, mapped once per process.
fn table() -> Option<&'static [Slot]> {
    static TABLE: OnceLock<Option<usize>> = OnceLock::new();
    let base = (*TABLE.get_or_init(map_table))?;
    // SAFETY: a live shared mapping of `SLOTS + 1` slots (the first the
    // header), never unmapped; slots are only touched atomically.
    Some(unsafe { std::slice::from_raw_parts((base as *const Slot).add(1), SLOTS) })
}

fn header() -> Option<&'static Header> {
    let t = table()?;
    // SAFETY: the header is the slot before the first, in the same mapping.
    Some(unsafe { &*(t.as_ptr().sub(1) as *const Header) })
}

fn map_table() -> Option<usize> {
    let mut path = crate::fs::shm::user_dir().ok()?;
    path.extend_from_slice(format!("/v{}-futexes", crate::shared::FORMAT).as_bytes());
    let path = std::ffi::CString::new(path).ok()?;
    let size = (SLOTS + 1) * size_of::<Slot>();
    // SAFETY: plain host calls; the file is fwe's own, and the mapping is
    // kept for the process's life.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd < 0 {
            return None;
        }
        // Zeroes (every slot free) the first time; the same size after.
        let grown = libc::ftruncate(fd, size as libc::off_t) == 0;
        let p = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        (grown && p != libc::MAP_FAILED).then_some(p as usize)
    }
}

/// Where guest address `uaddr` is in the host's address space (a backend
/// may have given the call it already translated).
fn host_of(uaddr: u64) -> u64 {
    crate::uaccess::g2h(crate::uaccess::guest_of(uaddr))
}

/// The key of the futex word at host address `host`, as Linux tells
/// futexes apart: shared memory by what it is, private memory by process
/// and address. The word must have been read first (a shared page the
/// process has not touched has no memory object yet, so no identity).
fn key_of(host: u64) -> Option<[u64; 2]> {
    Some(match crate::mm::region::sharing(host)? {
        Some((0, _)) => return None,
        Some((object, offset)) => [1 << 63 | object as u64, offset],
        None => [me() as u64, host],
    })
}

fn me() -> u32 {
    crate::host::pid() as u32
}

/// This process, as slots name their owner: (pid, start time).
fn me_proc() -> (u32, u64) {
    static ME: std::sync::Mutex<(u32, u64)> = std::sync::Mutex::new((0, 0));
    let pid = me();
    let mut m = ME.lock().unwrap_or_else(|e| e.into_inner());
    if m.0 != pid {
        *m = (pid, crate::procreg::start_time(pid as i32).unwrap_or(0));
    }
    *m
}

/// Whether slot `s`'s owner still runs.
fn owner_alive(s: &Slot) -> bool {
    let (pid, start) = (s.owner.load(SeqCst), s.owner_start.load(SeqCst));
    (pid, start) == me_proc() || crate::procreg::alive((pid as i32, start))
}

/// Free slot `s`, seen in state `seen`, if it is still so.
fn free(s: &Slot, seen: u32) -> bool {
    s.state.compare_exchange(seen, next(seen, FREE), SeqCst, SeqCst).is_ok()
}

/// This process starts (or runs another program): what its pid holds in
/// the table is no waiter's, whether left by a process its pid had
/// before or by its own threads before the `execve`.
pub fn process_started() {
    let Some(t) = table() else { return };
    let pid = me();
    for s in in_use(t) {
        let cur = s.state.load(SeqCst);
        if st(cur) != FREE && s.owner.load(SeqCst) == pid {
            free(s, cur);
        }
    }
}

/// Take a free slot for this waiter, filled in and waiting: its index and
/// state. With none free, those of processes that have gone are freed.
fn take_slot(t: &[Slot], key: [u64; 2], bits: u32) -> Option<(usize, u32)> {
    for round in 0..2 {
        for (i, s) in t.iter().enumerate() {
            let cur = s.state.load(SeqCst);
            if st(cur) != FREE {
                if round == 1 && !owner_alive(s) {
                    free(s, cur);
                }
                continue;
            }
            if s.state.compare_exchange(cur, with_state(cur, TAKEN), SeqCst, SeqCst).is_err() {
                continue;
            }
            let (pid, start) = me_proc();
            s.key[0].store(key[0], SeqCst);
            s.key[1].store(key[1], SeqCst);
            s.bits.store(bits, SeqCst);
            s.owner.store(pid, SeqCst);
            s.owner_start.store(start, SeqCst);
            let h = header()?;
            s.ticket.store(h.tickets.fetch_add(1, SeqCst), SeqCst);
            // Before it is seen waiting, so a wake's scan reaches it.
            h.high.fetch_max(i as u32 + 1, SeqCst);
            let waiting = with_state(cur, WAITING);
            s.state.store(waiting, SeqCst);
            return Some((i, waiting));
        }
    }
    None
}

/// Give back this waiter's slot `s`: `Ok` if it was still waiting, `Err`
/// if a wake claimed it first (the waiter was woken). A requeue moving it
/// meanwhile is let finish.
fn give_back(s: &Slot) -> Result<(), ()> {
    let mut spins = 0u32;
    loop {
        let cur = s.state.load(SeqCst);
        match st(cur) {
            WAITING if free(s, cur) => return Ok(()),
            WOKEN => {
                s.state.store(next(cur, FREE), SeqCst);
                return Err(());
            }
            _ => {
                // Being moved to another futex ([`requeue`]): back at once,
                // unless its mover was stopped there.
                spins += 1;
                if spins < 128 {
                    std::hint::spin_loop();
                } else {
                    std::thread::yield_now();
                }
            }
        }
    }
}

/// Block while the word at guest `uaddr` still equals `val`, until a wake
/// for `bits` claims this waiter, the `deadline` passes or a signal for
/// the guest comes (`EINTR`), checked in slices as the private wait does.
pub fn wait(uaddr: u64, val: u32, deadline: Option<Instant>, bits: u32) -> i64 {
    // Read first, as Linux finds the word's page before keying it.
    match crate::futex::load(uaddr) {
        Ok(v) if v == val => {}
        Ok(_) => return err(errno::EAGAIN),
        Err(e) => return err(e),
    }
    let (Some(t), Some(key)) = (table(), key_of(host_of(uaddr))) else {
        return crate::futex::wait_private_bits(uaddr, val, deadline, bits);
    };
    let Some((i, _)) = take_slot(t, key, bits) else {
        return err(errno::ENOMEM);
    };
    let slot = &t[i];
    // Waiting before the word is read again: a waker that changed it first
    // is seen here, and one that changes it after finds this slot.
    match crate::futex::load(uaddr) {
        Ok(v) if v == val => {}
        other => {
            return match give_back(slot) {
                Ok(()) => err(other.err().unwrap_or(errno::EAGAIN)),
                // Claimed meanwhile: woken, and counted so.
                Err(()) => 0,
            };
        }
    }
    let word = slot.state.as_ptr().cast::<libc::c_void>();
    loop {
        let cur = slot.state.load(SeqCst);
        // Only a wake ends the wait (or moves it, a requeue): as on Linux,
        // the word is compared once, as the wait begins, and a change to it
        // afterwards wakes nobody.
        if st(cur) == WOKEN {
            let _ = give_back(slot);
            return 0;
        }
        let gone = |e| match give_back(slot) {
            Ok(()) => err(e),
            Err(()) => 0,
        };
        if crate::thread::deliverable() != 0 {
            return gone(errno::EINTR);
        }
        if crate::thread::pending() & crate::signalfd::watched() != 0 {
            crate::signal::drain_to_signalfd();
        }
        let now = Instant::now();
        let slice = match deadline {
            Some(d) if now >= d => return gone(errno::ETIMEDOUT),
            Some(d) => (d - now).min(crate::futex::SIGNAL_CHECK),
            None => crate::futex::SIGNAL_CHECK,
        };
        if let Some(step) = deadline.and_then(|d| crate::futex::near(d, now)) {
            // Close to the deadline: on time, looking for the wake between
            // short steps.
            crate::futex::precise_sleep(step);
            continue;
        }
        // SAFETY: the slot's word, in fwe's shared table; the host sleeps
        // while it still reads `cur`.
        unsafe {
            __ulock_wait2(
                UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO,
                word,
                cur as u64,
                slice.as_nanos().max(1) as u64,
                0,
            )
        };
    }
}

/// `futex_waitv`'s wait on the shared futex at guest `uaddr` (its word
/// read first): the slot it waits in, or `None` where the word's memory
/// has no shared identity (a private futex's queue then takes it).
pub fn enter(uaddr: u64) -> Option<Result<usize, i32>> {
    let (t, key) = (table()?, key_of(host_of(uaddr))?);
    Some(take_slot(t, key, u32::MAX).map(|(i, _)| i).ok_or(errno::ENOMEM))
}

/// Whether slot `i` ([`enter`]) has been woken.
pub fn woken(i: usize) -> bool {
    table().is_some_and(|t| st(t[i].state.load(SeqCst)) == WOKEN)
}

/// Leave slot `i` ([`enter`]): whether it was woken meanwhile.
pub fn leave(i: usize) -> bool {
    table().is_some_and(|t| give_back(&t[i]).is_err())
}

/// Wake up to `count` waiters of the futex at guest `uaddr` waiting for
/// any of `bits`, oldest first: the number woken.
pub fn wake(uaddr: u64, count: u32, bits: u32) -> i64 {
    let (Some(t), Some(key)) = (table(), key_of(host_of(uaddr))) else {
        return crate::futex::wake_private_bits(uaddr, count, bits);
    };
    claim(t, key, bits, count, |s, state| {
        if s.state.compare_exchange(state, with_state(state, WOKEN), SeqCst, SeqCst).is_err() {
            return false;
        }
        // SAFETY: wakes whoever sleeps on the slot's word; reads nothing.
        unsafe {
            __ulock_wake(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, s.state.as_ptr().cast(), 0)
        };
        true
    })
}

/// `FUTEX_CMP_REQUEUE` (and `FUTEX_REQUEUE`) of shared futexes: wake up
/// to `wake` waiters of the futex at guest `uaddr`, then move up to
/// `requeue` of the rest to the futex at `uaddr2`: the number woken and
/// moved.
pub fn requeue(uaddr: u64, wake_n: u32, requeue_n: u32, uaddr2: u64) -> i64 {
    let woken = wake(uaddr, wake_n, u32::MAX);
    let (Some(t), Some(from), Some(to)) =
        (table(), key_of(host_of(uaddr)), key_of(host_of(uaddr2)))
    else {
        return woken;
    };
    // A waiter sleeps on its slot, not the word: moving it is changing its
    // key, while it is held so no wake claims it half moved, and in a new
    // generation, so a wake that saw it on `from` does not claim it after.
    let moved = claim(t, from, u32::MAX, requeue_n, |s, state| {
        if s.state.compare_exchange(state, with_state(state, MOVING), SeqCst, SeqCst).is_err() {
            return false;
        }
        s.key[0].store(to[0], SeqCst);
        s.key[1].store(to[1], SeqCst);
        s.state.store(next(state, WAITING), SeqCst);
        // SAFETY: as in [`wake`]: the waiter goes back to sleep on the new
        // state.
        unsafe {
            __ulock_wake(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, s.state.as_ptr().cast(), 0)
        };
        true
    });
    woken + moved
}

/// Act on up to `count` slots of `key` waiting for any of `bits`, oldest
/// first, with `act`, which reports whether it took the slot: the number
/// taken. A slot left by a process that has gone is freed on the way.
fn claim(
    t: &[Slot],
    key: [u64; 2],
    bits: u32,
    count: u32,
    act: impl Fn(&Slot, u32) -> bool,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let mut waiting: Vec<(u32, usize, u32)> = Vec::new();
    for (i, s) in in_use(t).iter().enumerate() {
        let state = s.state.load(SeqCst);
        if st(state) != WAITING
            || s.key[0].load(SeqCst) != key[0]
            || s.key[1].load(SeqCst) != key[1]
            || s.bits.load(SeqCst) & bits == 0
        {
            continue;
        }
        if !owner_alive(s) {
            free(s, state);
            continue;
        }
        waiting.push((s.ticket.load(SeqCst), i, state));
    }
    // Oldest first.
    waiting.sort_by_key(|w| w.0);
    let mut taken = 0i64;
    for (_, i, state) in waiting {
        if taken >= count as i64 {
            break;
        }
        if act(&t[i], state) {
            taken += 1;
        }
    }
    taken
}
