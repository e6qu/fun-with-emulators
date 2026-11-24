//! A table behind a lock that a frequent call can pass by while it never
//! held anything: what a feature keeps per descriptor (epoll interest
//! lists, socket options, signalfds, pseudo-terminals) is looked up on every
//! `close`, and most programs never use most features.
//!
//! A table is marked once it holds something, as its lock is let go
//! ([`Kept::lock`]); [`Kept::if_used`] takes the lock only once it is. A
//! look that races with a first entry is as racy as with the lock alone:
//! what it misses is what it would have found locked a moment earlier.

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::{Mutex, MutexGuard};

/// A collection that can say it is empty.
pub(crate) trait Table {
    fn is_empty(&self) -> bool;
}

impl<T> Table for Vec<T> {
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

impl<K, V, S> Table for std::collections::HashMap<K, V, S> {
    fn is_empty(&self) -> bool {
        std::collections::HashMap::is_empty(self)
    }
}

impl<T: Table> Table for Option<T> {
    fn is_empty(&self) -> bool {
        self.as_ref().is_none_or(Table::is_empty)
    }
}

pub(crate) struct Kept<T> {
    used: AtomicBool,
    value: Mutex<T>,
}

/// A [`Kept`] table, locked.
#[must_use = "dropped at once, it lets go at once"]
pub(crate) struct Held<'a, T: Table> {
    used: &'a AtomicBool,
    guard: MutexGuard<'a, T>,
}

impl<T> Kept<T> {
    pub(crate) const fn new(value: T) -> Self {
        Kept { used: AtomicBool::new(false), value: Mutex::new(value) }
    }
}

impl<T: Table> Kept<T> {
    /// The table, locked.
    pub(crate) fn lock(&self) -> Held<'_, T> {
        Held { used: &self.used, guard: self.value.lock().unwrap_or_else(|e| e.into_inner()) }
    }

    /// The table, locked, if it ever held anything.
    pub(crate) fn if_used(&self) -> Option<Held<'_, T>> {
        self.used.load(Acquire).then(|| self.lock())
    }
}

impl<T: Table> std::ops::Deref for Held<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: Table> std::ops::DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T: Table> Drop for Held<'_, T> {
    fn drop(&mut self) {
        // Marked before the lock is let go (the guard is dropped after).
        if !self.used.load(Relaxed) && !self.guard.is_empty() {
            self.used.store(true, Release);
        }
    }
}

impl<T: Send + 'static> crate::forklock::ForkLock for Kept<T> {
    fn try_take(&'static self) -> Option<Box<dyn Any>> {
        crate::forklock::ForkLock::try_take(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_is_looked_at_once_it_held_something() {
        static T: Kept<Vec<i32>> = Kept::new(Vec::new());
        assert!(T.if_used().is_none());
        // Looking is no use.
        assert!(T.lock().is_empty());
        assert!(T.if_used().is_none());
        T.lock().push(3);
        assert_eq!(T.if_used().map(|t| t.clone()), Some(vec![3]));
        // Emptied again, it is still looked at.
        T.lock().clear();
        assert!(T.if_used().is_some_and(|t| t.is_empty()));
    }
}
