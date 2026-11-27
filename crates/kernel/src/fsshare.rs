//! The root, working directory and umask processes share: a process made
//! by `clone` with `CLONE_FS`, as threads share them.
//!
//! On Linux such a process shares its parent's `fs_struct`: a `chdir`,
//! `fchdir`, `chroot`, `pivot_root` or `umask` either makes is the other's
//! too, across `execve`, until one unshares it (`unshare(CLONE_FS)`, which
//! `CLONE_NEWNS` implies). Chromium's sandbox empties its root so: a child
//! made with `CLONE_FS` changes the root to its own `/proc/self/fdinfo`
//! and ends, which leaves its parent's root in a directory of a process
//! that has ended.
//!
//! fwe keeps what they share in a shared record ([`crate::shared`]) that
//! each of them holds. Each change of a process's view is written to it
//! ([`changed`]); each process takes the others' changes as its next
//! system call starts ([`take`]), and a call made without the kernel lock
//! takes them into the view such calls resolve paths in
//! ([`take_published`]). A process that shares nothing pays one relaxed
//! load per call.

use crate::procreg::alive_kept;
use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A filesystem view's shared part: its root and working directory (as
/// [`crate::fs::Fs::set_shared_view`] takes them) and its umask.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// The root, a path in the mount namespace's view.
    pub root: Vec<u8>,
    /// The working directory, a path from the root.
    pub cwd: Vec<u8>,
    /// Where the working directory is when a `chroot` left it outside the
    /// root (a path in the namespace's view).
    pub cwd_outside: Option<Vec<u8>>,
    /// The mounts the root and the working directory are in (0: not known).
    pub root_mount: u32,
    pub cwd_mount: u32,
    /// The processes whose directories in `/proc` they are in, if they are
    /// ([`crate::fs::ProcPin`]).
    pub root_pin: Option<crate::fs::ProcPin>,
    pub cwd_pin: Option<crate::fs::ProcPin>,
    pub umask: u32,
}

/// What the record holds: the view, and the processes that share it (a
/// host pid and its start time each).
#[derive(Clone, Debug, Default)]
struct Shared {
    view: View,
    members: Vec<(i32, u64)>,
}

impl Data for Shared {
    fn encode(&self, e: &mut Enc) {
        let v = &self.view;
        e.bytes(&v.root);
        e.bytes(&v.cwd);
        e.bool(v.cwd_outside.is_some());
        e.bytes(v.cwd_outside.as_deref().unwrap_or_default());
        e.u32(v.root_mount);
        e.u32(v.cwd_mount);
        crate::fs::ProcPin::save(&v.root_pin, e);
        crate::fs::ProcPin::save(&v.cwd_pin, e);
        e.u32(v.umask);
        e.u64(self.members.len() as u64);
        for &(pid, start) in &self.members {
            e.i32(pid);
            e.u64(start);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let (root, cwd) = (d.bytes(), d.bytes());
        let outside = d.bool();
        // (Its bytes are there either way.)
        let bytes = d.bytes();
        let cwd_outside = outside.then_some(bytes);
        let (root_mount, cwd_mount) = (d.u32(), d.u32());
        let (root_pin, cwd_pin) = (crate::fs::ProcPin::load(d), crate::fs::ProcPin::load(d));
        let view = View {
            root,
            cwd,
            cwd_outside,
            root_mount,
            cwd_mount,
            root_pin,
            cwd_pin,
            umask: d.u32(),
        };
        let n = d.u64();
        let members = (0..n).map(|_| (d.i32(), d.u64())).collect();
        Shared { view, members }
    }

    fn valid(&self) -> bool {
        !self.view.root.is_empty()
    }
}

/// The record this process shares its view through, if it shares it.
static RECORD: Mutex<Option<Arc<Record<Shared>>>> = Mutex::new(None);
/// Whether [`RECORD`] holds one (the cheap check each call makes).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The record's generation the kernel's view was last brought to.
static SEEN: AtomicU64 = AtomicU64::new(0);
/// The record's generation the published view was last brought to.
static SEEN_PUBLISHED: AtomicU64 = AtomicU64::new(0);

fn record() -> Option<Arc<Record<Shared>>> {
    RECORD.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set(r: Option<Arc<Record<Shared>>>) {
    let mut g = RECORD.lock().unwrap_or_else(|e| e.into_inner());
    ACTIVE.store(r.is_some(), Ordering::Release);
    let at = r.as_ref().map_or(0, |r| r.generation());
    *g = r;
    SEEN.store(at, Ordering::Release);
    SEEN_PUBLISHED.store(at, Ordering::Release);
    drop(g);
    crate::threadfs::publish_held();
}

/// This process, as the record lists it.
fn me() -> (i32, u64) {
    let pid = crate::host::pid();
    (pid.get(), crate::procreg::start_time(pid).unwrap_or(0))
}

/// Whether this process shares its view with others.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// The record's name, while this process holds it: the shared state
/// [`crate::shared::collect`] keeps for it.
pub fn dir() -> Option<Vec<u8>> {
    active().then(record).flatten().map(|r| r.dir().to_vec())
}

/// Before the host `fork` of a `clone` with `CLONE_FS`: the record the
/// child shares this view through, made from `view` if this process
/// shares it with none yet.
pub(crate) fn for_fork(view: View) -> Result<(), i32> {
    if active() {
        return Ok(());
    }
    let r = Record::fresh("fs", Shared { view, members: vec![me()] })?;
    set(Some(Arc::new(r)));
    Ok(())
}

/// In a fork child, as it starts: a member of its parent's record if it
/// was made with `CLONE_FS` (`shares`), else a view of its own.
pub(crate) fn forked_child(shares: bool) {
    if !active() {
        return;
    }
    if !shares {
        set(None);
        return;
    }
    if let Some(r) = record() {
        let me = me();
        let _ = r.update(|s| {
            s.members.retain(|m| *m != me && alive_kept(*m));
            s.members.push(me);
            Ok(())
        });
    }
    crate::threadfs::publish_held();
}

/// The process's view changed to `view` (by `chdir`, `fchdir`, `chroot`,
/// `pivot_root` or `umask`): the processes that share it have it too.
pub(crate) fn changed(view: View) {
    let Some(r) = active().then(record).flatten() else { return };
    // (The next call takes the record's view again: this one, or a
    // later one another process wrote meanwhile.)
    let _ = r.update_maybe(|s| {
        let differs = s.view != view;
        s.view = view;
        Ok(((), differs))
    });
}

/// Whether another process changed the view since this one took it: the
/// calls run on the kernel lock's shared side, which cannot take it, are
/// then run holding it ([`crate::Kernel::dispatch_shared`]).
pub fn pending() -> bool {
    active() && record().is_some_and(|r| r.generation() != SEEN.load(Ordering::Acquire))
}

/// The view another process changed it to, for the kernel's view, if one
/// did since this process last took it (under the kernel lock, as a call
/// starts).
pub(crate) fn take() -> Option<View> {
    let r = active().then(record).flatten()?;
    let now = r.generation();
    if SEEN.swap(now, Ordering::AcqRel) == now {
        return None;
    }
    SEEN_PUBLISHED.store(now, Ordering::Release);
    Some(r.get().view.clone())
}

/// [`take`], for the view the calls made without the kernel lock resolve
/// paths in: the kernel's own takes it as its next locked call starts.
pub(crate) fn take_published() -> Option<View> {
    let r = active().then(record).flatten()?;
    let now = r.generation();
    if SEEN_PUBLISHED.swap(now, Ordering::AcqRel) == now {
        return None;
    }
    Some(r.get().view.clone())
}

/// This process no longer shares its view (`unshare(CLONE_FS)`, or
/// `CLONE_NEWNS`, alone in the process): it keeps it as it is.
pub(crate) fn leave() {
    let Some(r) = active().then(record).flatten() else { return };
    let me = me();
    let _ = r.update(|s| {
        s.members.retain(|m| *m != me);
        Ok(())
    });
    set(None);
}

/// Whether another live process shares this one's view: `setns` into a
/// mount or user namespace is then refused (`EINVAL`), as on Linux.
pub(crate) fn shared_with_others() -> bool {
    let Some(r) = active().then(record).flatten() else { return false };
    let me = me();
    r.get().members.iter().any(|&m| m != me && alive_kept(m))
}

/// Whether the fork under way shares the view with its child
/// (`CLONE_FS`): for the state a VM child is handed, which starts afresh
/// ([`save_for_fork`]). Set and cleared under the kernel lock.
static FORK_SHARES: AtomicBool = AtomicBool::new(false);

/// The fork under way shares the view with its child, or no longer does
/// (it is over).
pub(crate) fn fork_shares(on: bool) {
    FORK_SHARES.store(on, Ordering::SeqCst);
}

/// Write the record the child of the fork under way shares the view
/// through, if it does, into the state a VM child is handed.
pub(crate) fn save_for_fork(e: &mut Enc) {
    let r = FORK_SHARES.load(Ordering::SeqCst).then(record).flatten();
    crate::shared::save_opt(e, &r);
}

/// What [`save_for_fork`] wrote, in the VM child as it starts: a member of
/// its parent's record, or a view of its own.
pub(crate) fn load_for_fork(d: &mut Dec) {
    let r = crate::shared::load_opt::<Shared>(d).ok().flatten();
    let shares = r.is_some();
    set(r);
    forked_child(shares);
}

/// A VM fork child's record is written ([`load_for_fork`] ran before it
/// was): the record of the view it shares is among what it holds.
pub fn record_written() {
    if active() {
        crate::threadfs::publish_held();
    }
}

/// Write the record this process shares its view through, if any, into
/// the exec state: the sharing outlasts `execve`.
pub(crate) fn save(e: &mut Enc) {
    crate::shared::save_opt(e, &active().then(record).flatten());
}

/// What [`save`] wrote, in the process the exec started. The view itself
/// comes with the exec state; the record's is taken at the first call.
pub(crate) fn load(d: &mut Dec) {
    let r = crate::shared::load_opt::<Shared>(d).ok().flatten();
    let some = r.is_some();
    set(r);
    if some {
        SEEN.store(0, Ordering::Release);
        SEEN_PUBLISHED.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_view_reads_back_as_written() {
        let s = Shared {
            view: View {
                root: b"/proc/7/fdinfo".to_vec(),
                cwd: b"/".to_vec(),
                cwd_outside: Some(b"/srv".to_vec()),
                root_mount: 3,
                cwd_mount: 4,
                root_pin: Some(crate::fs::ProcPin { dir: b"/proc/7".to_vec(), host: (70, 71) }),
                cwd_pin: None,
                umask: 0o027,
            },
            members: vec![(10, 11), (12, 13)],
        };
        let mut e = Enc::new();
        s.encode(&mut e);
        let bytes = e.into_bytes();
        let back = Shared::decode(&mut Dec::new(&bytes));
        assert_eq!(back.view, s.view);
        assert_eq!(back.members, s.members);
        assert!(back.valid());
        assert!(!Shared::default().valid());
    }
}
