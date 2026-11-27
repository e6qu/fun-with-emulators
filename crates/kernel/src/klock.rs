//! The kernel lock: the process's [`Kernel`] behind one read-write lock.
//!
//! A system call that only reads what the kernel keeps for the process
//! (its ids, its filesystem view, its signal actions) runs on the lock's
//! shared side, alongside the same calls of other threads
//! ([`Kernel::dispatch_shared`] lists them). Any other call takes the lock
//! for itself: one that changes that state, or that changes several of
//! the kernel's registries that need to change together (a descriptor and
//! what fwe keeps for it, a mapping and its records). The calls that wait
//! run without the lock ([`crate::blocking_syscall`]) and take its shared
//! side to finish, unless a signal is to be delivered.
//!
//! The shared side costs a thread no cache line another thread writes:
//! readers count themselves in one of [`SHARDS`] counters, each on a line
//! of its own and each thread keeping to one, and look at a flag only a
//! writer sets. A writer takes the writers' mutex, sets the flag and waits
//! for every counter given to a thread to drain; a reader that finds the flag set steps back
//! and comes in holding the mutex, and a writer lets the readers waiting
//! so come in first, and the writers waiting for the mutex, so that no
//! thread is kept out by others making one exclusive call after another
//! (the host's mutex goes to whichever thread asks first, often the one
//! that just let it go). Shared sections are short (no call on this side
//! waits), so a writer spins. A host `fork` is made holding the lock for
//! writing; the child clears the counters and the count of waiting
//! readers, which might hold readers of other threads stepping back
//! ([`KernelLock::forked_child`]), and lets the mutex go as any other.

use crate::{Kernel, Platform, Regs, thread};
use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
use std::sync::{Mutex, MutexGuard};

/// How many counters readers spread over.
const SHARDS: usize = 32;

/// A reader counter on a cache line of its own.
#[repr(align(128))]
struct Shard(AtomicUsize);

/// The next counter a thread is given.
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This thread's counter, its index plus one (0 until it has one).
    static SHARD: Cell<usize> = const { Cell::new(0) };
}

/// A read-write lock whose shared side writes only this thread's counter.
pub struct Lock<T> {
    value: UnsafeCell<T>,
    readers: [Shard; SHARDS],
    writers: Mutex<()>,
    writing: AtomicBool,
    /// Readers that stepped back for a writer and wait to come in.
    waiting: AtomicUsize,
    /// Writers waiting for the writers' mutex.
    writers_waiting: AtomicUsize,
}

/// A backend's kernel, `None` until the program is loaded.
pub type KernelLock<P> = Lock<Option<Kernel<P>>>;

// SAFETY: the value is reached only through `Shared` (many threads, `&`)
// and `Exclusive` (one thread, no `Shared` alive), as a `RwLock` shares it.
unsafe impl<T: Send + Sync> Sync for Lock<T> {}

/// A [`Lock`] held for writing.
pub struct Exclusive<'a, T> {
    lock: &'a Lock<T>,
    _writers: MutexGuard<'a, ()>,
}

/// A [`Lock`] held shared.
pub struct Shared<'a, T> {
    lock: &'a Lock<T>,
    shard: usize,
}

impl<T> std::ops::Deref for Exclusive<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: held for writing: no other reference to the value.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> std::ops::DerefMut for Exclusive<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Exclusive<'_, T> {
    fn drop(&mut self) {
        // Before the writers' mutex is let go (the field drops after).
        self.lock.writing.store(false, Release);
    }
}

impl<T> std::ops::Deref for Shared<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: held shared: only `&` references to the value.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for Shared<'_, T> {
    fn drop(&mut self) {
        self.lock.readers[self.shard].0.fetch_sub(1, Release);
    }
}

impl<T> Lock<T> {
    pub const fn new(value: T) -> Self {
        Lock {
            value: UnsafeCell::new(value),
            readers: [const { Shard(AtomicUsize::new(0)) }; SHARDS],
            writers: Mutex::new(()),
            writing: AtomicBool::new(false),
            waiting: AtomicUsize::new(0),
            writers_waiting: AtomicUsize::new(0),
        }
    }

    /// The value, for this thread alone. The thread MUST NOT hold a [`Shared`]
    /// of this lock.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn lock(&self) -> Exclusive<'_, T> {
        // Readers and writers that wait come in first: a thread making one
        // exclusive call after another would otherwise take the mutex back
        // each time (the host's mutex gives it to whoever asks first), and
        // keep another thread out of every call it makes.
        let mut turns = 0;
        while (self.waiting.load(Acquire) != 0 || self.writers_waiting.load(Acquire) != 0)
            && turns < 10_000
        {
            std::thread::yield_now();
            turns += 1;
        }
        // A writer counts as waiting only while another holds the mutex.
        let writers = match self.writers.try_lock() {
            Ok(w) => w,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.writers_waiting.fetch_add(1, SeqCst);
                let w = self.writers.lock().unwrap_or_else(|e| e.into_inner());
                self.writers_waiting.fetch_sub(1, Release);
                w
            }
        };
        self.writing.store(true, SeqCst);
        // Only the counters given out can count readers: a thread given one
        // after this look finds `writing` set, and steps back (the given
        // count, the counter and the flag are all sequentially consistent).
        let given = NEXT_SHARD.load(SeqCst).min(SHARDS);
        for shard in &self.readers[..given] {
            let mut spins = 0u32;
            while shard.0.load(SeqCst) != 0 {
                spins += 1;
                if spins < 1000 {
                    std::hint::spin_loop();
                } else {
                    std::thread::yield_now();
                }
            }
        }
        Exclusive { lock: self, _writers: writers }
    }

    /// The value, shared with other threads' readers. The thread MUST NOT hold
    /// another [`Shared`] or [`Exclusive`] of this lock: a writer waiting
    /// between the two would wait for it.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn shared(&self) -> Shared<'_, T> {
        let mut shard = SHARD.with(Cell::get);
        if shard == 0 {
            shard = NEXT_SHARD.fetch_add(1, SeqCst) % SHARDS + 1;
            SHARD.with(|s| s.set(shard));
        }
        let shard = shard - 1;
        let count = &self.readers[shard].0;
        count.fetch_add(1, SeqCst);
        if !self.writing.load(SeqCst) {
            return Shared { lock: self, shard };
        }
        // A writer is in or coming: step back, and come in holding the
        // writers' mutex, when no writer is in. The next writer then waits
        // for this reader, so readers get their turns with writers that
        // follow one another.
        self.waiting.fetch_add(1, SeqCst);
        count.fetch_sub(1, Release);
        let _writers = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        count.fetch_add(1, SeqCst);
        self.waiting.fetch_sub(1, Release);
        Shared { lock: self, shard }
    }

    /// In the child of a host `fork` made holding the lock for writing:
    /// forget the parent's other threads' readers, which the child does
    /// not have.
    ///
    /// # Safety
    /// Only in a fork's child, whose only thread holds the lock for writing.
    pub unsafe fn forked_child(&self, _held: &Exclusive<'_, T>) {
        for shard in &self.readers {
            shard.0.store(0, SeqCst);
        }
        self.waiting.store(0, SeqCst);
        self.writers_waiting.store(0, SeqCst);
    }
}

impl<P: Platform> KernelLock<P> {
    /// Run the system call named in `regs` as [`Kernel::run_syscall`]
    /// does: on the shared side if it is one that can, else exclusively.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn syscall(&self, regs: &mut Regs) {
        let nr = regs.x[8];
        let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
        if crate::syscalls::shares(nr) {
            let shared = self.shared();
            if let Some(r) = shared.as_ref().and_then(|k| k.dispatch_shared(nr, args)) {
                self.finish_holding(shared, regs, nr, &args, r);
                return;
            }
        }
        self.lock().as_mut().expect("kernel initialized").run_syscall(regs);
        self.deliver_pending(regs);
    }

    /// Run call `nr` with `args` (already translated for the host) and
    /// return its raw result, as [`Kernel::run_call`] does: shared if it
    /// can be.
    pub fn run_call(&self, nr: u64, args: [u64; 6]) -> i64 {
        if crate::syscalls::shares(nr)
            && let Some(r) = self.shared().as_ref().and_then(|k| k.dispatch_shared(nr, args))
        {
            return r;
        }
        self.lock().as_mut().expect("kernel initialized").run_call(nr, args)
    }

    /// Store the result of a call run without the lock, as
    /// [`Kernel::complete_syscall`] does: on the shared side, unless the call
    /// was interrupted or a signal is to be delivered.
    pub fn finish(&self, regs: &mut Regs, nr: u64, args: &[u64; 6], result: i64) {
        self.finish_holding(self.shared(), regs, nr, args, result);
    }

    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    fn finish_holding(
        &self,
        shared: Shared<'_, Option<Kernel<P>>>,
        regs: &mut Regs,
        nr: u64,
        args: &[u64; 6],
        result: i64,
    ) {
        if let Some(k) = shared.as_ref()
            && result != fwe_abi::err(fwe_abi::errno::EINTR)
        {
            k.tracer.syscall(nr, args, result);
            regs.x[0] = result as u64;
            regs.pc = regs.pc.wrapping_add(4);
            if k.settle_shared() {
                return;
            }
            drop(shared);
            self.deliver_pending(regs);
            return;
        }
        drop(shared);
        self.lock().as_mut().expect("kernel initialized").complete_syscall(regs, nr, args, result);
        self.deliver_pending(regs);
    }

    /// Serve the tracer's `stop` of this thread without the lock: the
    /// thread pointer read before it and written back after under the
    /// lock, which the wait for the tracer does not hold, so the
    /// process's other threads go on, and stop for their tracer in their
    /// turn (each attached to, or each sent `SIGSTOP`, by a debugger that
    /// waits for each).
    pub fn serve_stop(&self, regs: &mut Regs, stop: crate::ptrace::Stop) -> crate::ptrace::Resume {
        let mut tls = {
            let mut held = self.lock();
            let k = held.as_mut().expect("kernel initialized");
            k.resync_if_asked();
            k.platform.thread_pointer()
        };
        let before = tls;
        let r = stop.serve(regs, &mut tls);
        let mut held = self.lock();
        let k = held.as_mut().expect("kernel initialized");
        if tls != before {
            k.platform.set_thread_pointer(tls);
        }
        k.resync_if_asked();
        r
    }

    /// Serve `stop`, if there is one, raising a signal the tracer resumed
    /// with ([`crate::ptrace::raise_resumed`]).
    fn serve_and_raise(&self, regs: &mut Regs, stop: Option<crate::ptrace::Stop>) {
        if let Some(stop) = stop {
            crate::ptrace::raise_resumed(self.serve_stop(regs, stop));
        }
    }

    /// Act on the ready pending signals before returning to the guest
    /// ([`Kernel::deliver_step`]), each tracer's stop they make served
    /// without the lock ([`KernelLock::serve_stop`]).
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn deliver_pending(&self, regs: &mut Regs) {
        let mut carried = None;
        loop {
            let met = match self.lock().as_mut() {
                Some(k) => k.deliver_step(regs, carried.take()),
                None => return,
            };
            let Some(met) = met else { return };
            let r = self.serve_stop(regs, met.stop);
            carried = met.after(r);
        }
    }

    /// Deliver synchronous fault signal `sig` (at `addr`, of syndrome `esr`
    /// where the fault has one) to a guest handler, returning `true` if a
    /// handler was entered, or the tracer took it; when `false`, the caller
    /// takes the default action (terminate). A tracer sees it first (a
    /// breakpoint's SIGTRAP, say, or the step it asked for), its stop served
    /// without the lock, and the guest goes on as it leaves the registers,
    /// or takes the signal it chooses.
    pub fn deliver_fault(&self, regs: &mut Regs, sig: u64, addr: u64, esr: Option<u64>) -> bool {
        use fwe_abi::signal::SIGTRAP;
        if crate::ptrace::traced() {
            // A breakpoint of a step a tracer asked for: the step's stop.
            if sig == SIGTRAP && crate::ptrace::step_hit(regs.pc) {
                const TRAP_TRACE: i32 = 2;
                let info = thread::SigInfo { code: TRAP_TRACE, ..thread::SigInfo::default() };
                let r = self.serve_stop(regs, crate::ptrace::Stop::signal(sig, info));
                if let Some((s, i)) = crate::ptrace::chosen(sig, r) {
                    thread::post_process(s, i);
                }
                return true;
            }
            let info = crate::signal::fault_info(sig, addr, esr);
            let r = self.serve_stop(regs, crate::ptrace::Stop::signal(sig, info));
            match crate::ptrace::chosen(sig, r) {
                None => return true,
                Some((s, i)) if s != sig => {
                    thread::post_process(s, i);
                    return true;
                }
                Some(_) => {}
            }
        }
        let info = crate::signal::fault_info(sig, addr, esr);
        self.lock().as_mut().is_some_and(|k| k.deliver_to_handler(regs, sig, info, addr, esr))
    }

    /// A system call's entry stop (`entry`) or exit stop, if the tracer
    /// stops this thread at system calls (`PTRACE_SYSCALL`).
    pub fn syscall_stop(&self, regs: &mut Regs, entry: bool) {
        self.serve_and_raise(regs, crate::ptrace::Stop::syscall(entry));
    }

    /// `SECCOMP_RET_TRACE` with `data` for the call in `regs`: a tracer
    /// that asked for these events (`PTRACE_O_TRACESECCOMP`) stops there,
    /// and can change the call or skip it (`x8` -1); the filters then look
    /// again at what it left. With no such tracer, `Trace` stands.
    pub fn seccomp_trace(&self, regs: &mut Regs, data: u16) -> crate::seccomp::Action {
        use crate::seccomp::Action;
        if !crate::ptrace::traced()
            || crate::ptrace::options() & crate::ptrace::PTRACE_O_TRACESECCOMP == 0
        {
            return Action::Trace(data);
        }
        let event = crate::ptrace::PTRACE_EVENT_SECCOMP;
        self.serve_and_raise(regs, crate::ptrace::Stop::event(event, u64::from(data)));
        let nr = regs.x[8];
        if nr as i64 == -1 {
            return Action::Skip;
        }
        let args = [regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5]];
        crate::seccomp::recheck(nr, &args, crate::SvcSite(regs.pc))
    }

    /// The stops of a fork a backend noted ([`crate::ptrace::note_fork`]):
    /// the parent's event, the child's pid its message, and for a vfork
    /// the vfork-done event.
    pub fn fork_stops(&self, regs: &mut Regs) {
        if let Some((event, child, vfork)) = crate::ptrace::Stop::fork() {
            self.serve_and_raise(regs, event);
            if vfork {
                self.serve_and_raise(regs, crate::ptrace::Stop::vfork_done(child));
            }
        }
    }

    /// A clone's event stop (`event`, a `PTRACE_EVENT_*` the tracer asked
    /// for), the child `child` its message; for a vfork (`vfork`), the
    /// vfork-done event's after it.
    pub fn clone_stops(&self, regs: &mut Regs, event: i32, child: u64, vfork: bool) {
        self.serve_and_raise(regs, crate::ptrace::Stop::event(event, child));
        if vfork {
            self.serve_and_raise(regs, crate::ptrace::Stop::vfork_done(child));
        }
    }

    /// The stops after a successful `execve` of a traced process
    /// ([`crate::ptrace::Stop::exec`]); its exit stop's result in `x0`, 0.
    pub fn exec_stops(&self, regs: &mut Regs) {
        let [event, trap] = crate::ptrace::Stop::exec();
        self.serve_and_raise(regs, event);
        // Whether it stops at the call's exit is as the tracer left it at
        // the event.
        if let Some(exit) = crate::ptrace::Stop::syscall(false) {
            regs.x[0] = 0;
            self.serve_and_raise(regs, Some(exit));
        }
        self.serve_and_raise(regs, trap);
    }
}

impl<P: Platform> Kernel<P> {
    /// After a call run on the shared side: what delivering pending signals
    /// does short of delivering one. `false` when a signal is ready, for
    /// [`KernelLock::deliver_pending`].
    pub(crate) fn settle_shared(&self) -> bool {
        let (pending, _, saved) = thread::after_call(crate::host::WAKE_SIGNAL);
        // With nothing pending there is nothing for a signalfd and nothing
        // to deliver.
        if pending != 0 {
            crate::signal::drain_to_signalfd();
            if thread::deliverable() != 0 {
                return false;
            }
        }
        if saved.is_some()
            && let Some(mask) = thread::take_saved_mask()
        {
            thread::set_mask(mask);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// Readers on the shared side never see a writer's change half made,
    /// and every thread gets through.
    #[test]
    fn readers_see_whole_writes() {
        let lock = Lock::new((0u64, 0u64));
        let torn = AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..20_000 {
                        let v = lock.shared();
                        if v.0 != v.1 {
                            torn.fetch_add(1, Relaxed);
                        }
                    }
                });
            }
            for _ in 0..2 {
                s.spawn(|| {
                    for _ in 0..5_000 {
                        let mut v = lock.lock();
                        v.0 += 1;
                        std::hint::spin_loop();
                        v.1 += 1;
                    }
                });
            }
        });
        assert_eq!(torn.load(Relaxed), 0);
        assert_eq!(*lock.lock(), (10_000, 10_000));
    }

    /// A thread taking the lock for writing over and over does not keep
    /// readers out.
    #[test]
    fn readers_get_in_between_writers() {
        let lock = Lock::new(0u64);
        let done = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                while !done.load(Relaxed) {
                    *lock.lock() += 1;
                }
            });
            for _ in 0..2_000 {
                let _ = *lock.shared();
            }
            done.store(true, Relaxed);
        });
    }

    /// A fork's child holding the lock forgets readers of threads it does
    /// not have, and takes the lock again.
    #[test]
    fn a_fork_child_forgets_other_readers() {
        let lock = Lock::new(());
        let held = lock.lock();
        // As another thread left them when the host forked.
        lock.readers[3].0.store(1, SeqCst);
        lock.waiting.store(1, SeqCst);
        // SAFETY: standing in for the child: nothing else uses the lock.
        unsafe { lock.forked_child(&held) };
        drop(held);
        drop(lock.lock());
        drop(lock.shared());
    }
}
