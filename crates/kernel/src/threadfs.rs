//! A thread's own filesystem view and namespaces.
//!
//! On Linux each thread has its own root, working directory and umask
//! (shared with the others unless it unshares `CLONE_FS`) and its own
//! namespaces (`setns` and `unshare` change only the caller's). A Go
//! program changes them on a locked thread while its others carry on:
//! Docker unpacks an image on a thread that unshares `CLONE_FS` and the
//! mount namespace and then changes its root, and sets up a network
//! namespace on one that unshares it and joins its own again.
//!
//! A thread of fwe's has the process's view ([`crate::Kernel::fs`]) until
//! it changes one of these while other threads run; then it gets its own
//! copy. A copy made for a namespace alone still shares the root, working
//! directory and umask with the process ([`share_view`] passes a change of
//! them on); one made by unsharing `CLONE_FS` does not. A copy made for a
//! namespace goes once the thread is back in the process's namespaces. A
//! thread a thread with its own view starts has a copy of that view.

use crate::fs::Fs;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

/// A thread's own view.
struct Own {
    fs: Box<Fs>,
    /// It shares the root, working directory and umask with the process
    /// (made for a namespace, not by unsharing `CLONE_FS`).
    shares: bool,
}

thread_local! {
    /// This thread's own view, if it has one (owned by [`OWNERS`]).
    static CURRENT: Cell<*mut Fs> = const { Cell::new(std::ptr::null_mut()) };
}

/// Each thread's own view, by thread id.
static OWNERS: Mutex<Option<HashMap<i32, Own>>> = Mutex::new(None);

/// How many threads have their own view (a cheap check for none).
static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn owners<R>(f: impl FnOnce(&mut HashMap<i32, Own>) -> R) -> R {
    let mut g = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let r = f(map);
    COUNT.store(map.len(), std::sync::atomic::Ordering::Relaxed);
    r
}

/// Show in the process's record the namespaces the threads' own views are
/// in, which they hold as the process holds its own.
fn publish_held() {
    let held: Vec<Vec<u8>> = owners(|o| o.values().flat_map(|w| w.fs.ns_dirs()).collect());
    crate::procreg::own_held(held);
}

/// This thread's own view, if it has one. The kernel lock guards it, as it
/// does the process's.
pub fn current() -> Option<*mut Fs> {
    let p = CURRENT.with(Cell::get);
    (!p.is_null()).then_some(p)
}

/// Whether this thread's own view shares the root, working directory and
/// umask with the process (false without one).
pub fn shares() -> bool {
    current().is_some() && owners(|o| o.get(&crate::thread::tid()).is_some_and(|w| w.shares))
}

/// Give this thread `fs` as its own view.
pub fn take(fs: Fs, shares: bool) {
    let mut fs = Box::new(fs);
    let p: *mut Fs = &mut *fs;
    owners(|o| o.insert(crate::thread::tid(), Own { fs, shares }));
    CURRENT.with(|c| c.set(p));
    crate::ns::Namespaces::activate_thread(current_ns());
    publish_held();
}

/// This thread's own namespaces, if it has its own view.
fn current_ns() -> Option<crate::ns::Namespaces> {
    // SAFETY: this thread's own view, live while it is in `OWNERS`.
    current().map(|p| unsafe { (*p).ns.clone() })
}

/// This thread goes back to the process's view.
pub fn release() {
    if current().is_none() {
        return;
    }
    CURRENT.with(|c| c.set(std::ptr::null_mut()));
    crate::ns::Namespaces::activate_thread(None);
    let own = owners(|o| o.remove(&crate::thread::tid()));
    drop(own);
    publish_held();
}

/// After this thread's namespaces changed: its own view, if it shares the
/// rest with the process and is in the process's namespaces (`process`)
/// again, goes; otherwise its sockets and IPC act in its namespaces.
pub fn namespaces_changed(process: &Fs) {
    let Some(p) = current() else { return };
    // SAFETY: this thread's own view, live while it is in `OWNERS`.
    let own = unsafe { &*p };
    if shares() && own.ns_dirs() == process.ns_dirs() {
        release();
    } else {
        crate::ns::Namespaces::activate_thread(current_ns());
        publish_held();
    }
}

/// Pass this thread's root, working directory and umask (`from`) on to the
/// process's view and the other threads' that share them, after it changed
/// them; with an own view not shared, nothing is.
pub fn share_view(from: &Fs, process: Option<&mut Fs>) {
    let own = current();
    if own.is_some() && !shares() {
        return;
    }
    if let (Some(_), Some(p)) = (own, process) {
        p.set_view(from);
    }
    let me = crate::thread::tid();
    owners(|o| {
        for (tid, w) in o.iter_mut() {
            if *tid != me && w.shares {
                w.fs.set_view(from);
            }
        }
    });
}

/// `f` of thread `tid`'s own view, if it has one (under the kernel lock,
/// which guards it).
pub fn view_of<R>(tid: i32, f: impl FnOnce(&Fs) -> R) -> Option<R> {
    owners(|o| o.get(&tid).map(|w| f(&w.fs)))
}

/// Whether any thread has its own view.
pub fn any() -> bool {
    COUNT.load(std::sync::atomic::Ordering::Relaxed) != 0
}

/// A thread `parent` (this one) starts, with id `tid`: a copy of this
/// thread's own view, if it has one, as the new thread's.
pub fn started(tid: i32) {
    let Some(p) = current() else { return };
    // SAFETY: this thread's own view, live while it is in `OWNERS`.
    let Ok(copy) = (unsafe { (*p).copy() }) else { return };
    let shares = shares();
    owners(|o| o.insert(tid, Own { fs: Box::new(copy), shares }));
}

/// A new thread picks up the view [`started`] left for it.
pub fn enter(tid: i32) {
    let p = owners(|o| o.get_mut(&tid).map(|w| &mut *w.fs as *mut Fs));
    if let Some(p) = p {
        CURRENT.with(|c| c.set(p));
        crate::ns::Namespaces::activate_thread(current_ns());
    }
}

/// Whether this thread's own view shares the rest with the process: no
/// longer once it unshares `CLONE_FS`.
pub fn unshare_fs() {
    let me = crate::thread::tid();
    owners(|o| {
        if let Some(w) = o.get_mut(&me) {
            w.shares = false;
        }
    });
}

/// Thread `tid`, which never started, has no view.
pub fn forget(tid: i32) {
    if owners(|o| o.remove(&tid)).is_some() {
        publish_held();
    }
}

/// This thread ends: its own view goes.
pub fn thread_exit() {
    release();
}

/// In the child of a `fork`, whose one thread is this one: its own view,
/// if it has one, which becomes the process's; the other threads' go.
pub fn take_for_child() -> Option<Fs> {
    let me = crate::thread::tid();
    CURRENT.with(|c| c.set(std::ptr::null_mut()));
    crate::ns::Namespaces::activate_thread(None);
    let mut all = owners(std::mem::take);
    if !all.is_empty() {
        publish_held();
    }
    all.remove(&me).map(|w| *w.fs)
}
