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
//! address waits cannot say. A slot's state carries a generation, so a
//! slot freed and taken again meanwhile is never claimed for the old
//! waiter.

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
    /// while it is filled in, [`WAITING`], [`WOKEN`].
    state: AtomicU32,
    /// The `FUTEX_WAIT_BITSET` bits it waits for (all, for `FUTEX_WAIT`).
    bits: AtomicU32,
    /// The host pid of the process waiting.
    owner: AtomicU32,
    /// When it came, from [`Header::tickets`]: the oldest is woken first.
    ticket: AtomicU32,
    /// The futex's key.
    key: [AtomicU64; 2],
}

const FREE: u32 = 0;
const TAKEN: u32 = 1;
const WAITING: u32 = 2;
const WOKEN: u32 = 3;

/// The first slot's room: the counter tickets are drawn from.
#[repr(C)]
struct Header {
    tickets: AtomicU32,
}

/// Slots in the table (more threads than this waiting on shared futexes
/// at once, across every fwe process of the user, is beyond any program
/// fwe runs).
const SLOTS: usize = 16384;

fn with_state(state: u32, st: u32) -> u32 {
    (state & !0xff) | st
}

fn next_generation(state: u32) -> u32 {
    state.wrapping_add(0x100) & !0xff
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
/// and address.
fn key_of(host: u64) -> Option<[u64; 2]> {
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() } as u64;
    Some(match crate::mm::region::sharing(host)? {
        Some((object, offset)) => [1 << 63 | object as u64, offset],
        None => [me, host],
    })
}

fn me() -> u32 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() as u32 }
}

/// Take a free slot for this waiter, filled in and waiting: its index and
/// state.
fn take_slot(t: &[Slot], key: [u64; 2], bits: u32) -> Option<(usize, u32)> {
    for (i, s) in t.iter().enumerate() {
        let cur = s.state.load(SeqCst);
        if cur & 0xff != FREE
            || s.state.compare_exchange(cur, with_state(cur, TAKEN), SeqCst, SeqCst).is_err()
        {
            continue;
        }
        s.key[0].store(key[0], SeqCst);
        s.key[1].store(key[1], SeqCst);
        s.bits.store(bits, SeqCst);
        s.owner.store(me(), SeqCst);
        s.ticket.store(header()?.tickets.fetch_add(1, SeqCst), SeqCst);
        let waiting = with_state(cur, WAITING);
        s.state.store(waiting, SeqCst);
        return Some((i, waiting));
    }
    None
}

/// Give back slot `s`, which this waiter holds in state `held`: `Ok` if it
/// was still waiting, `Err` if a wake claimed it first (the waiter was
/// woken). A requeue moving it meanwhile is let finish.
fn give_back(s: &Slot, held: u32) -> Result<(), ()> {
    let free = with_state(next_generation(held), FREE);
    loop {
        match s.state.compare_exchange(held, free, SeqCst, SeqCst) {
            Ok(_) => return Ok(()),
            Err(cur) if cur == with_state(held, WOKEN) => {
                s.state.store(free, SeqCst);
                return Err(());
            }
            // Being moved to another futex ([`requeue`]): back shortly.
            Err(_) => std::hint::spin_loop(),
        }
    }
}

/// Block while the word at guest `uaddr` still equals `val`, until a wake
/// for `bits` claims this waiter, the `deadline` passes or a signal for
/// the guest comes (`EINTR`), checked in slices as the private wait does.
pub fn wait(uaddr: u64, val: u32, deadline: Option<Instant>, bits: u32) -> i64 {
    let (Some(t), Some(key)) = (table(), key_of(host_of(uaddr))) else {
        return super_wait(uaddr, val, deadline);
    };
    let Some((i, held)) = take_slot(t, key, bits) else {
        return err(errno::ENOMEM);
    };
    let slot = &t[i];
    // Waiting before the word is read: a waker that changed it first is
    // seen here, and one that changes it after finds this slot.
    match crate::futex::load(uaddr) {
        Ok(v) if v == val => {}
        other => {
            return match give_back(slot, held) {
                Ok(()) => err(other.err().unwrap_or(errno::EAGAIN)),
                // Claimed meanwhile: woken, and counted so.
                Err(()) => 0,
            };
        }
    }
    let word = slot.state.as_ptr().cast::<libc::c_void>();
    loop {
        if slot.state.load(SeqCst) == with_state(held, WOKEN) {
            let _ = give_back(slot, held);
            return 0;
        }
        if crate::thread::deliverable() != 0 {
            return match give_back(slot, held) {
                Ok(()) => err(errno::EINTR),
                Err(()) => 0,
            };
        }
        if crate::thread::pending() & crate::signalfd::watched() != 0 {
            crate::signal::drain_to_signalfd();
        }
        let now = Instant::now();
        let slice = match deadline {
            Some(d) if now >= d => {
                return match give_back(slot, held) {
                    Ok(()) => err(errno::ETIMEDOUT),
                    Err(()) => 0,
                };
            }
            Some(d) => (d - now).min(crate::futex::SIGNAL_CHECK),
            None => crate::futex::SIGNAL_CHECK,
        };
        // SAFETY: the slot's word, in fwe's shared table; the host sleeps
        // while it still reads `held`.
        unsafe {
            __ulock_wait2(
                UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO,
                word,
                held as u64,
                slice.as_nanos().max(1) as u64,
                0,
            )
        };
    }
}

/// Without the table, the process's own wait.
fn super_wait(uaddr: u64, val: u32, deadline: Option<Instant>) -> i64 {
    crate::futex::wait_private(uaddr, val, deadline)
}

/// Whether host process `pid` lives (a waiter killed while it waited
/// leaves its slot behind).
fn alive(pid: u32) -> bool {
    // SAFETY: plain host call; signal 0 only checks.
    pid == me()
        || unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
        || crate::host::last_errno() == libc::EPERM
}

/// Wake up to `count` waiters of the futex at guest `uaddr` waiting for
/// any of `bits`, oldest first: the number woken.
pub fn wake(uaddr: u64, count: u32, bits: u32) -> i64 {
    let (Some(t), Some(key)) = (table(), key_of(host_of(uaddr))) else {
        return crate::futex::wake_private(uaddr, count);
    };
    claim(t, key, bits, count, |s, state| {
        let woken = with_state(state, WOKEN);
        if s.state.compare_exchange(state, woken, SeqCst, SeqCst).is_err() {
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
    // key, while it is held so no wake claims it half moved.
    let moved = claim(t, from, u32::MAX, requeue_n, |s, state| {
        let taken = with_state(state, TAKEN);
        if s.state.compare_exchange(state, taken, SeqCst, SeqCst).is_err() {
            return false;
        }
        s.key[0].store(to[0], SeqCst);
        s.key[1].store(to[1], SeqCst);
        s.state.store(state, SeqCst);
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
    for (i, s) in t.iter().enumerate() {
        let state = s.state.load(SeqCst);
        if state & 0xff != WAITING
            || s.key[0].load(SeqCst) != key[0]
            || s.key[1].load(SeqCst) != key[1]
            || s.bits.load(SeqCst) & bits == 0
        {
            continue;
        }
        if !alive(s.owner.load(SeqCst)) {
            let free = with_state(next_generation(state), FREE);
            let _ = s.state.compare_exchange(state, free, SeqCst, SeqCst);
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
