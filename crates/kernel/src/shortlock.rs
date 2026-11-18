//! Mutexes held for moments (a futex's waiters queued or taken, a
//! translation placed): a thread that finds one held tries it again for a
//! while before it sleeps on it, as sleeping and being woken cost the
//! host's scheduler far more than such a hold. A host mutex sleeps at once.

use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

/// How long a thread tries for a held lock before it sleeps on it: a few
/// holds' time.
pub const SPIN: Duration = Duration::from_micros(20);

/// `m` locked (whatever a panic left in it).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    let mut began = None;
    loop {
        match m.try_lock() {
            Ok(g) => return g,
            Err(TryLockError::Poisoned(e)) => return e.into_inner(),
            Err(TryLockError::WouldBlock)
                if began.get_or_insert_with(Instant::now).elapsed() < SPIN =>
            {
                std::hint::spin_loop();
            }
            Err(TryLockError::WouldBlock) => return m.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}
